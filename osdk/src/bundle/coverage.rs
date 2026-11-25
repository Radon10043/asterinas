// SPDX-License-Identifier: MPL-2.0

//! Collects an LLVM profile while the guest keeps its coverage buffer alive.

use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use tempfile::NamedTempFile;

use super::{QemuExit, connect_to_qemu_monitor};
use crate::{
    daemon::{DaemonSupervisor, SignalGuard},
    error::Errno,
    error_msg,
};

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const COVERAGE_PREFIX: &str = "#### Coverage: ";

pub(super) fn run(
    command: &mut Command,
    work_dir: &Path,
    log_path: &Path,
    signal: &SignalGuard,
    daemons: &mut DaemonSupervisor<'_>,
) -> QemuExit {
    let output = work_dir.join("coverage.profraw");
    let prepare_fn = || -> io::Result<()> {
        // Both inputs must belong to this run, even when the working directory is reused.
        File::create(log_path)?;
        match fs::remove_file(&output) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    };
    if let Err(error) = prepare_fn() {
        error_msg!("Cannot prepare coverage output: {error}");
        daemons.abort(None, Errno::RunBundle);
    }
    let socket = match NamedTempFile::new() {
        Ok(file) => file.into_temp_path(),
        Err(error) => {
            error_msg!("Cannot create QMP socket path: {error}");
            daemons.abort(None, Errno::RunBundle);
        }
    };
    command
        .arg("-qmp")
        .arg(format!("unix:{},server,nowait", socket.display()));
    info!("Running QEMU: {command:#?}");
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            error_msg!("Cannot start QEMU: {error}");
            drop(socket);
            daemons.abort(None, Errno::ExecuteCommand);
        }
    };
    let stream = match connect_to_qemu_monitor(&socket, &mut child, signal) {
        Ok(stream) => stream,
        Err(errno) => {
            drop(socket);
            daemons.abort(Some(&mut child), errno);
        }
    };
    let result = (|| -> io::Result<QemuExit> {
        let mut monitor = Monitor::new(stream)?;
        let dump = loop {
            if signal.received_signal().is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "coverage collection interrupted",
                ));
            }
            daemons
                .reap_exited_daemons()
                .map_err(|_| io::Error::other("a supervised daemon failed"))?;
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::other(format!(
                    "QEMU exited before coverage export: {status}"
                )));
            }
            if let Some(dump) = read_dump(log_path)? {
                break dump;
            }
            thread::sleep(POLL_INTERVAL);
        };
        export_profile(&mut monitor, &dump, &output)?;
        monitor.execute("quit", json!({}))?;
        let status = daemons
            .wait_for_qemu(&mut child)
            .map_err(|_| io::Error::other("failed to wait for QEMU"))?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "QEMU failed after coverage export: {status}"
            )));
        }
        Ok(if dump.success {
            QemuExit::Success
        } else {
            QemuExit::Failed
        })
    })();
    match result {
        Ok(exit) => {
            daemons.stop_all();
            exit
        }
        Err(error) => {
            error_msg!("Coverage collection failed: {error}");
            let errno = if error.kind() == io::ErrorKind::Interrupted {
                Errno::Interrupted
            } else {
                Errno::RunBundle
            };
            drop(socket);
            daemons.abort(Some(&mut child), errno);
        }
    }
}

#[derive(Debug, PartialEq)]
struct CoverageDump {
    address: u64,
    size: u64,
    success: bool,
}

/// Reads only complete records, since QEMU may still be writing the serial log.
fn read_dump(path: &Path) -> io::Result<Option<CoverageDump>> {
    let bytes = fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    for line in text.split_inclusive('\n').rev() {
        if !line.ends_with('\n') {
            continue;
        }
        let Some(record) = line.trim_end().strip_prefix(COVERAGE_PREFIX) else {
            continue;
        };
        let fields: Vec<_> = record.split_whitespace().collect();
        let invalid_fn = || io::Error::new(io::ErrorKind::InvalidData, "invalid coverage record");
        if fields.len() != 3 {
            return Err(invalid_fn());
        }
        let address = fields[0]
            .strip_prefix("0x")
            .and_then(|value| u64::from_str_radix(value, 16).ok())
            .ok_or_else(invalid_fn)?;
        let size = fields[1].parse::<u64>().map_err(|_| invalid_fn())?;
        let success = match fields[2] {
            "success" => true,
            "failure" => false,
            _ => return Err(invalid_fn()),
        };
        if address == 0 || size < 16 || address.checked_add(size).is_none() {
            return Err(invalid_fn());
        }
        return Ok(Some(CoverageDump {
            address,
            size,
            success,
        }));
    }
    Ok(None)
}

struct Monitor {
    reader: BufReader<UnixStream>,
    next_id: u64,
}

impl Monitor {
    fn new(stream: UnixStream) -> io::Result<Self> {
        stream.set_read_timeout(Some(POLL_INTERVAL))?;
        stream.set_write_timeout(Some(COMMAND_TIMEOUT))?;
        let mut monitor = Self {
            reader: BufReader::new(stream),
            next_id: 0,
        };
        let greeting = monitor.receive(Instant::now() + COMMAND_TIMEOUT)?;
        if !greeting.get("QMP").is_some_and(Value::is_object) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing QMP greeting",
            ));
        }
        monitor.execute("qmp_capabilities", json!({}))?;
        Ok(monitor)
    }

    fn receive(&mut self, deadline: Instant) -> io::Result<Value> {
        let mut bytes = Vec::new();
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "QMP response timed out",
                ));
            }
            match self.reader.read_until(b'\n', &mut bytes) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "QMP disconnected",
                    ));
                }
                Ok(_) if bytes.ends_with(b"\n") => {
                    return serde_json::from_slice(&bytes)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn execute(&mut self, command: &str, arguments: Value) -> io::Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let mut request = serde_json::to_vec(&json!({
            "execute": command, "arguments": arguments, "id": id
        }))?;
        request.push(b'\n');
        self.reader.get_mut().write_all(&request)?;
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            let response = self.receive(deadline)?;
            if response.get("event").is_some() {
                continue;
            }
            if response.get("id").and_then(Value::as_u64) != Some(id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected QMP response ID",
                ));
            }
            if let Some(error) = response.get("error") {
                return Err(io::Error::other(format!("QMP {command}: {error}")));
            }
            return response
                .get("return")
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing QMP result"));
        }
    }
}

/// Publishes the profile only after QEMU has completed the exact memory dump.
fn export_profile(monitor: &mut Monitor, dump: &CoverageDump, output: &Path) -> io::Result<()> {
    monitor.execute("stop", json!({}))?;
    let status = monitor.execute("query-status", json!({}))?;
    if status.get("running").and_then(Value::as_bool) != Some(false) {
        return Err(io::Error::other("QEMU did not stop for coverage export"));
    }
    let mut profile = NamedTempFile::new_in(output.parent().unwrap())?;
    // QEMU runs in the output directory. The generated filename needs no HMP escaping.
    let name = profile.path().file_name().unwrap().to_str().unwrap();
    let result = monitor.execute(
        "human-monitor-command",
        json!({
            "command-line": format!("memsave 0x{:x} {} {}", dump.address, dump.size, name)
        }),
    )?;
    if result
        .as_str()
        .is_none_or(|message| !message.trim().is_empty())
    {
        return Err(io::Error::other(format!(
            "QEMU memory export failed: {result}"
        )));
    }
    if profile.as_file().metadata()?.len() != dump.size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "coverage file size differs from guest record",
        ));
    }
    let mut magic = [0u8; 8];
    profile.read_exact(&mut magic)?;
    // LLVM raw profiles encode the target pointer width in the magic value.
    let raw64 = 0xff6c70726f667281u64;
    let raw32 = 0xff6c70726f665281u64;
    if ![
        raw64.to_le_bytes(),
        raw64.to_be_bytes(),
        raw32.to_le_bytes(),
        raw32.to_be_bytes(),
    ]
    .contains(&magic)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid LLVM raw profile magic",
        ));
    }
    profile.persist(output).map_err(|error| error.error)?;
    info!("Coverage data saved to {}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests;
