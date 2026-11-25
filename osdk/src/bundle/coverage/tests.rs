// SPDX-License-Identifier: MPL-2.0

use super::{CoverageDump, Monitor, export_profile, read_dump};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tempfile::{TempDir, tempdir};

const MOCK_IO_TIMEOUT: Duration = Duration::from_secs(2);
const MOCK_JOIN_TIMEOUT: Duration = Duration::from_secs(3);
const PROFILE_SIZE: usize = 32;
const PROFILE_ADDRESS: u64 = 0x1234;

fn serial_log(directory: &TempDir, contents: &str) -> PathBuf {
    let path = directory.path().join("serial.log");
    fs::write(&path, contents).unwrap();
    path
}

#[test]
fn read_dump_accepts_complete_success_and_failure_records() {
    let directory = tempdir().unwrap();
    let path = serial_log(
        &directory,
        "#### Coverage: 0x1000 16 success\n#### Coverage: 0x2000 32 failure\n",
    );

    assert_eq!(
        read_dump(&path).unwrap(),
        Some(CoverageDump {
            address: 0x2000,
            size: 32,
            success: false
        })
    );
    fs::write(&path, "#### Coverage: 0x1000 16 success\n").unwrap();
    assert_eq!(
        read_dump(&path).unwrap(),
        Some(CoverageDump {
            address: 0x1000,
            size: 16,
            success: true
        })
    );
}

#[test]
fn read_dump_ignores_incomplete_records_and_files_without_marker() {
    let directory = tempdir().unwrap();
    let path = serial_log(&directory, "console output without a coverage record\n");
    assert_eq!(read_dump(&path).unwrap(), None);

    fs::write(&path, "#### Coverage: 0x1000 16 success").unwrap();
    assert_eq!(read_dump(&path).unwrap(), None);

    fs::write(
        &path,
        "#### Coverage: 0x1000 16 success\n#### Coverage: 0x2000 32 failure",
    )
    .unwrap();
    assert_eq!(
        read_dump(&path).unwrap(),
        Some(CoverageDump {
            address: 0x1000,
            size: 16,
            success: true
        })
    );
}

#[test]
fn read_dump_recovers_a_valid_record_after_invalid_utf8_background() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("serial.log");
    let mut bytes = b"\xff\xfe background output\n".to_vec();
    bytes.extend_from_slice(b"#### Coverage: 0x3000 24 success\n");
    fs::write(&path, bytes).unwrap();

    assert_eq!(
        read_dump(&path).unwrap(),
        Some(CoverageDump {
            address: 0x3000,
            size: 24,
            success: true
        })
    );
}

#[test]
fn read_dump_rejects_invalid_fields_addresses_lengths_and_statuses() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("serial.log");
    let invalid_records = [
        "#### Coverage: 0x1000 16 success extra\n",
        "#### Coverage: 0x1000 success\n",
        "#### Coverage: invalid 16 success\n",
        "#### Coverage: 0x0 16 success\n",
        "#### Coverage: 0xfffffffffffffff8 16 success\n",
        "#### Coverage: 0x1000 15 success\n",
        "#### Coverage: 0x1000 18446744073709551616 success\n",
        "#### Coverage: 0x1000 nope success\n",
        "#### Coverage: 0x1000 16 maybe\n",
    ];

    for record in invalid_records {
        fs::write(&path, record).unwrap();
        let error = read_dump(&path).unwrap_err();
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidData,
            "record: {record:?}"
        );
    }
}

fn spawn_mock<F>(stream: UnixStream, handler: F) -> JoinHandle<()>
where
    F: FnOnce(BufReader<UnixStream>, UnixStream) + Send + 'static,
{
    stream.set_read_timeout(Some(MOCK_IO_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(MOCK_IO_TIMEOUT)).unwrap();
    let reader = BufReader::new(stream.try_clone().unwrap());
    thread::spawn(move || handler(reader, stream))
}

fn join_mock(server: JoinHandle<()>) {
    let deadline = Instant::now() + MOCK_JOIN_TIMEOUT;
    while !server.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(server.is_finished(), "mock QMP server exceeded its timeout");
    server.join().expect("mock QMP server panicked");
}

fn take_error<T>(result: io::Result<T>) -> io::Error {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn assert_commands(actual: &[String], expected: &[&str]) {
    let actual: Vec<_> = actual.iter().map(String::as_str).collect();
    assert_eq!(actual, expected.to_vec());
}

fn send_json(stream: &mut UnixStream, value: Value) {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).unwrap();
}

fn read_json(reader: &mut BufReader<UnixStream>) -> Value {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).expect("read QMP request");
    assert_ne!(bytes, 0, "client disconnected before sending a QMP request");
    serde_json::from_str(&line).expect("valid JSON QMP request")
}

fn send_greeting(stream: &mut UnixStream) {
    send_json(
        stream,
        json!({
            "QMP": {
                "version": {
                    "qemu": { "major": 8, "minor": 2, "micro": 2 },
                    "package": "test"
                },
                "capabilities": []
            }
        }),
    );
}

fn request_id(request: &Value) -> Value {
    request.get("id").cloned().expect("QMP request has an id")
}

fn respond(stream: &mut UnixStream, id: Value, result: Value) {
    send_json(stream, json!({ "return": result, "id": id }));
}

fn respond_error(stream: &mut UnixStream, id: Value) {
    send_json(
        stream,
        json!({
            "error": { "class": "GenericError", "desc": "mock command failed" },
            "id": id
        }),
    );
}

fn finish_capabilities(reader: &mut BufReader<UnixStream>, writer: &mut UnixStream) {
    let request = read_json(reader);
    assert_eq!(request["execute"], "qmp_capabilities");
    assert_eq!(request["id"].as_u64(), Some(0));
    respond(writer, request_id(&request), json!({}));
}

#[test]
fn monitor_handshakes_skips_events_and_returns_the_matching_response() {
    let (client, server_stream) = UnixStream::pair().unwrap();
    let server = spawn_mock(server_stream, |mut reader, mut writer| {
        send_greeting(&mut writer);
        finish_capabilities(&mut reader, &mut writer);

        let request = read_json(&mut reader);
        assert_eq!(request["execute"], "query-status");
        assert_eq!(request["id"].as_u64(), Some(1));
        send_json(
            &mut writer,
            json!({ "event": "STOP", "data": {}, "timestamp": {} }),
        );
        respond(
            &mut writer,
            request_id(&request),
            json!({ "running": false }),
        );
    });

    let mut monitor = Monitor::new(client).unwrap();
    let status = monitor.execute("query-status", json!({})).unwrap();
    assert_eq!(status, json!({ "running": false }));
    join_mock(server);
}

#[test]
fn monitor_parses_a_response_fragmented_across_read_timeout() {
    let (client, server_stream) = UnixStream::pair().unwrap();
    let server = spawn_mock(server_stream, |mut reader, mut writer| {
        send_greeting(&mut writer);
        finish_capabilities(&mut reader, &mut writer);

        let request = read_json(&mut reader);
        assert_eq!(request["execute"], "query-status");
        let mut response = serde_json::to_vec(&json!({
            "return": { "running": false },
            "id": request_id(&request)
        }))
        .unwrap();
        response.push(b'\n');
        let split = 6;
        writer.write_all(&response[..split]).unwrap();
        thread::sleep(Duration::from_millis(150));
        writer.write_all(&response[split..]).unwrap();
    });

    let mut monitor = Monitor::new(client).unwrap();
    let status = monitor.execute("query-status", json!({})).unwrap();
    assert_eq!(status, json!({ "running": false }));
    join_mock(server);
}

#[test]
fn monitor_rejects_wrong_response_ids_and_missing_return_values() {
    for wrong_id in [false, true] {
        let (client, server_stream) = UnixStream::pair().unwrap();
        let server = spawn_mock(server_stream, move |mut reader, mut writer| {
            send_greeting(&mut writer);
            finish_capabilities(&mut reader, &mut writer);
            let request = read_json(&mut reader);
            assert_eq!(request["execute"], "query-status");
            let id = request_id(&request);
            if wrong_id {
                send_json(
                    &mut writer,
                    json!({ "id": id.as_u64().unwrap() + 1, "return": {} }),
                );
            } else {
                send_json(&mut writer, json!({ "id": id }));
            }
        });

        let mut monitor = Monitor::new(client).unwrap();
        let error = monitor.execute("query-status", json!({})).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        join_mock(server);
    }
}

#[test]
fn monitor_rejects_qmp_error_responses() {
    let (client, server_stream) = UnixStream::pair().unwrap();
    let server = spawn_mock(server_stream, |mut reader, mut writer| {
        send_greeting(&mut writer);
        finish_capabilities(&mut reader, &mut writer);
        let request = read_json(&mut reader);
        assert_eq!(request["execute"], "query-status");
        respond_error(&mut writer, request_id(&request));
    });

    let mut monitor = Monitor::new(client).unwrap();
    let error = monitor.execute("query-status", json!({})).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(error.to_string().contains("QMP query-status"));
    join_mock(server);
}

#[test]
fn monitor_rejects_disconnect_during_handshake() {
    let (client, server_stream) = UnixStream::pair().unwrap();
    let server = spawn_mock(server_stream, |mut reader, mut writer| {
        send_greeting(&mut writer);
        let request = read_json(&mut reader);
        assert_eq!(request["execute"], "qmp_capabilities");
    });

    let error = take_error(Monitor::new(client));
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    join_mock(server);
}

#[test]
fn monitor_rejects_a_malformed_qmp_greeting() {
    let (client, server_stream) = UnixStream::pair().unwrap();
    let server = spawn_mock(server_stream, |_reader, mut writer| {
        send_json(&mut writer, json!({ "not_qmp": {} }));
    });

    let error = take_error(Monitor::new(client));
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    join_mock(server);
}

#[derive(Clone, Copy, Debug)]
enum ExportFault {
    None,
    StopError,
    StillRunning,
    NoFile,
    ShortFile,
    LongFile,
    BadMagic,
    HmpQmpError,
    HmpMessageError,
}

fn valid_profile(size: usize) -> Vec<u8> {
    let mut bytes = vec![0x5a; size];
    bytes[..8].copy_from_slice(&0xff6c70726f667281u64.to_le_bytes());
    bytes
}

fn memsave_target(request: &Value, directory: &Path) -> PathBuf {
    let command = request["arguments"]["command-line"]
        .as_str()
        .expect("HMP command line");
    let fields: Vec<_> = command.split_whitespace().collect();
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0], "memsave");
    let expected_address = format!("0x{PROFILE_ADDRESS:x}");
    assert_eq!(fields[1], expected_address.as_str());
    let expected_size = PROFILE_SIZE.to_string();
    assert_eq!(fields[2], expected_size.as_str());
    assert_eq!(
        Path::new(fields[3]).file_name().unwrap().to_str().unwrap(),
        fields[3]
    );
    assert!(!fields[3].contains('/'));
    directory.join(fields[3])
}

fn export_with_mock(fault: ExportFault, output: &Path) -> (io::Result<()>, Vec<String>) {
    let (client, server_stream) = UnixStream::pair().unwrap();
    let directory = output.parent().unwrap().to_path_buf();
    let commands = Arc::new(Mutex::new(Vec::new()));
    let server_commands = Arc::clone(&commands);
    let server = spawn_mock(server_stream, move |mut reader, mut writer| {
        send_greeting(&mut writer);
        loop {
            let request = read_json(&mut reader);
            let command = request["execute"].as_str().expect("QMP command").to_owned();
            server_commands.lock().unwrap().push(command.clone());
            let id = request_id(&request);
            match command.as_str() {
                "qmp_capabilities" => respond(&mut writer, id, json!({})),
                "stop" if matches!(fault, ExportFault::StopError) => {
                    respond_error(&mut writer, id);
                    return;
                }
                "stop" => respond(&mut writer, id, json!({})),
                "query-status" => {
                    let running = matches!(fault, ExportFault::StillRunning);
                    respond(&mut writer, id, json!({ "running": running }));
                    if running {
                        return;
                    }
                }
                "human-monitor-command" => {
                    let target = memsave_target(&request, &directory);
                    match fault {
                        ExportFault::HmpQmpError => {
                            respond_error(&mut writer, id);
                            return;
                        }
                        ExportFault::HmpMessageError => {
                            respond(&mut writer, id, json!("memsave failed"));
                            return;
                        }
                        ExportFault::NoFile => {}
                        ExportFault::ShortFile => {
                            fs::write(&target, valid_profile(PROFILE_SIZE - 1)).unwrap();
                        }
                        ExportFault::LongFile => {
                            fs::write(&target, valid_profile(PROFILE_SIZE + 1)).unwrap();
                        }
                        ExportFault::BadMagic => {
                            fs::write(&target, vec![0x33; PROFILE_SIZE]).unwrap();
                        }
                        ExportFault::None => {
                            fs::write(&target, valid_profile(PROFILE_SIZE)).unwrap();
                        }
                        ExportFault::StopError | ExportFault::StillRunning => {
                            panic!("unexpected HMP command after failed stop")
                        }
                    }
                    respond(&mut writer, id, json!(""));
                    return;
                }
                other => panic!("unexpected QMP command: {other}"),
            }
        }
    });

    let dump = CoverageDump {
        address: PROFILE_ADDRESS,
        size: PROFILE_SIZE as u64,
        success: true,
    };
    let result =
        Monitor::new(client).and_then(|mut monitor| export_profile(&mut monitor, &dump, output));
    join_mock(server);
    let commands = commands.lock().unwrap().clone();
    (result, commands)
}

fn assert_export_failure(fault: ExportFault) -> Vec<String> {
    let directory = tempdir().unwrap();
    let output = directory.path().join("coverage.profraw");
    let (result, commands) = export_with_mock(fault, &output);
    assert!(result.is_err(), "fault {fault:?} unexpectedly succeeded");
    assert!(!output.exists(), "fault {fault:?} left a published profile");
    assert_eq!(
        fs::read_dir(directory.path()).unwrap().count(),
        0,
        "fault {fault:?} left a temporary file"
    );
    commands
}

#[test]
fn export_profile_publishes_only_a_complete_valid_llvm_profile() {
    let directory = tempdir().unwrap();
    let output = directory.path().join("coverage.profraw");
    let (result, commands) = export_with_mock(ExportFault::None, &output);

    assert!(result.is_ok(), "export failed: {result:?}");
    assert_eq!(fs::read(&output).unwrap(), valid_profile(PROFILE_SIZE));
    assert_commands(
        &commands,
        &[
            "qmp_capabilities",
            "stop",
            "query-status",
            "human-monitor-command",
        ],
    );
    let entries: Vec<_> = fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(entries, vec![output]);
}

#[test]
fn export_profile_requires_stop_confirmation_before_memsave() {
    let stop_commands = assert_export_failure(ExportFault::StopError);
    assert_commands(&stop_commands, &["qmp_capabilities", "stop"]);

    let status_commands = assert_export_failure(ExportFault::StillRunning);
    assert_commands(
        &status_commands,
        &["qmp_capabilities", "stop", "query-status"],
    );
}

#[test]
fn export_profile_rejects_missing_short_and_bad_magic_dumps() {
    for fault in [
        ExportFault::NoFile,
        ExportFault::ShortFile,
        ExportFault::LongFile,
        ExportFault::BadMagic,
    ] {
        let commands = assert_export_failure(fault);
        assert_commands(
            &commands,
            &[
                "qmp_capabilities",
                "stop",
                "query-status",
                "human-monitor-command",
            ],
        );
    }
}

#[test]
fn export_profile_rejects_qmp_and_hmp_errors() {
    for fault in [ExportFault::HmpQmpError, ExportFault::HmpMessageError] {
        let commands = assert_export_failure(fault);
        assert_commands(
            &commands,
            &[
                "qmp_capabilities",
                "stop",
                "query-status",
                "human-monitor-command",
            ],
        );
    }
}
