// SPDX-License-Identifier: MPL-2.0

//! Test the `run` command

use crate::util::is_tdx_enabled;

mod basic {
    use std::path::PathBuf;

    use tempfile::tempdir;

    use crate::util::*;

    #[test]
    fn new_kernel_and_run() {
        const KERNEL_NAME: &str = "myos";

        // Use a per-test temporary directory to avoid cross-run collisions.
        let work_dir = tempdir().unwrap();

        // Run `cargo osdk new --kernel KERNEL_NAME` in the workspace directory
        let mut cmd_new = cargo_osdk(["new", "--kernel", KERNEL_NAME]);
        cmd_new.current_dir(&work_dir);
        cmd_new.ok().expect("create kernel fails");

        // Run `cargo osdk run` in the created kernel directory
        let os_dir = PathBuf::from(work_dir.path()).join(KERNEL_NAME);
        edit_config_files(&os_dir);
        let mut cmd_run = cargo_osdk(["run"]);
        cmd_run.current_dir(&os_dir);
        let output = cmd_run.ok().unwrap();
        assert_eq!(output.status.code().unwrap(), 0);
    }
}

const WORKSPACE: &str = "/tmp/kernel_test_workspace/run_command";

mod workspace {
    use crate::util::*;
    use std::{
        fs::{create_dir_all, remove_dir_all},
        path::Path,
    };

    fn create_kernel_in_workspace(workspace: &str, kernel_name: &str) {
        let os_dir = Path::new(workspace).join(kernel_name);
        if os_dir.exists() {
            remove_dir_all(&os_dir).unwrap();
        }
        let mut cargo_osdk_new = cargo_osdk(["new", "--kernel", kernel_name]);
        cargo_osdk_new.current_dir(workspace);
        cargo_osdk_new
            .ok()
            .expect("Failed to create kernel project");
        edit_config_files(&os_dir);
    }

    fn prepare_workspace(workspace: &str) {
        if !Path::new(workspace).exists() {
            create_dir_all(workspace).unwrap();
        }
    }
    #[derive(Debug)]
    pub struct WorkSpace {
        pub workspace: String,
        pub kernel_name: String,
    }
    impl WorkSpace {
        pub fn new(workspace: &str, kernel_name: &str) -> Self {
            prepare_workspace(workspace);
            create_kernel_in_workspace(workspace, kernel_name);
            Self {
                workspace: workspace.to_string(),
                kernel_name: kernel_name.to_string(),
            }
        }

        pub fn os_dir(&self) -> String {
            Path::new(&self.workspace)
                .join(self.kernel_name.clone())
                .to_string_lossy()
                .to_string()
        }
    }
    impl Drop for WorkSpace {
        fn drop(&mut self) {
            remove_dir_all(self.os_dir()).unwrap();
        }
    }
}

mod coverage_feature {
    use super::*;
    use crate::util::{cargo_osdk, depends_on_coverage};
    use std::{
        env, fs,
        path::{Path, PathBuf},
        process::{Command, Output},
    };

    const PROFILE_SENTINEL: &[u8] = b"stale coverage profile sentinel";

    fn coverage_workspace(kernel_name: &str) -> workspace::WorkSpace {
        let workspace = workspace::WorkSpace::new(WORKSPACE, kernel_name);
        let os_dir = PathBuf::from(workspace.os_dir());
        depends_on_coverage(os_dir.join("Cargo.toml"), os_dir.join("OSDK.toml"));
        workspace
    }

    fn profile_path(workspace: &workspace::WorkSpace) -> PathBuf {
        PathBuf::from(workspace.os_dir()).join("coverage.profraw")
    }

    fn run_coverage(workspace: &workspace::WorkSpace) -> Output {
        let mut command = cargo_osdk(["run", "--coverage"]);
        command.current_dir(workspace.os_dir());
        command
            .output()
            .expect("Failed to wait for QEMU coverage instance")
    }

    fn assert_command_success(output: &Output, action: &str) {
        assert!(
            output.status.success(),
            "{action} exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn llvm_profdata() -> PathBuf {
        let executable = if let Some(path) = env::var_os("LLVM_PROFDATA") {
            PathBuf::from(path)
        } else {
            let output = Command::new("rustc")
                .args(["--print", "sysroot"])
                .output()
                .expect("Failed to run rustc --print sysroot");
            assert_command_success(&output, "rustc --print sysroot");
            let sysroot = String::from_utf8_lossy(&output.stdout);

            let host_output = Command::new("rustc")
                .arg("-vV")
                .output()
                .expect("Failed to run rustc -vV");
            assert_command_success(&host_output, "rustc -vV");
            let host_info = String::from_utf8_lossy(&host_output.stdout);
            let host = host_info
                .lines()
                .find_map(|line| line.strip_prefix("host: "))
                .expect("rustc -vV did not report the host triple");

            Path::new(sysroot.trim())
                .join("lib")
                .join("rustlib")
                .join(host)
                .join("bin/llvm-profdata")
        };

        let version = Command::new(&executable)
            .arg("--version")
            .output()
            .unwrap_or_else(|error| {
                panic!(
                    "Failed to run llvm-profdata at {}: {error}",
                    executable.display()
                )
            });
        assert_command_success(&version, "llvm-profdata --version");
        executable
    }

    fn has_nonzero_execution_count(summary: &str) -> bool {
        summary.lines().any(|line| {
            ["Function count:", "Block counts:"].iter().any(|marker| {
                line.split_once(*marker).is_some_and(|(_, counts)| {
                    counts
                        .split(|character: char| !character.is_ascii_digit())
                        .filter_map(|value| value.parse::<u64>().ok())
                        .any(|count| count > 0)
                })
            })
        })
    }

    fn assert_profile_updated_and_readable(profile: &Path) {
        let contents = fs::read(profile).unwrap_or_else(|error| {
            panic!(
                "Failed to read generated coverage profile {}: {error}",
                profile.display()
            )
        });
        assert!(!contents.is_empty(), "Coverage profile is empty");
        assert_ne!(
            contents, PROFILE_SENTINEL,
            "Coverage profile still contains only the stale sentinel"
        );

        let llvm_profdata = llvm_profdata();
        let merged_profile = profile.with_extension("profdata");
        let merge = Command::new(&llvm_profdata)
            .arg("merge")
            .arg("-sparse")
            .arg(profile)
            .arg("-o")
            .arg(&merged_profile)
            .output()
            .unwrap_or_else(|error| {
                panic!(
                    "Failed to run llvm-profdata merge for {}: {error}",
                    profile.display()
                )
            });
        assert_command_success(&merge, "llvm-profdata merge");
        assert!(
            fs::metadata(&merged_profile).unwrap().len() > 0,
            "llvm-profdata merge produced an empty profile"
        );

        let show = Command::new(&llvm_profdata)
            .args(["show", "--all-functions", "--counts"])
            .arg(&merged_profile)
            .output()
            .unwrap_or_else(|error| {
                panic!(
                    "Failed to run llvm-profdata show for {}: {error}",
                    merged_profile.display()
                )
            });
        assert_command_success(&show, "llvm-profdata show");
        let summary = String::from_utf8_lossy(&show.stdout);
        assert!(
            has_nonzero_execution_count(&summary),
            "llvm-profdata show reported no nonzero execution count\nstdout:\n{summary}\nstderr:\n{}",
            String::from_utf8_lossy(&show.stderr)
        );
    }

    fn run_with_stale_profile(workspace: &workspace::WorkSpace) -> (Output, PathBuf) {
        let profile = profile_path(workspace);
        fs::write(&profile, PROFILE_SENTINEL).unwrap();
        (run_coverage(workspace), profile)
    }

    fn replace_generated_kernel_with_failure(os_dir: &Path) {
        let source_path = os_dir.join("src/lib.rs");
        let source = fs::read_to_string(&source_path).unwrap();
        let success_line = "    println!(\"Hello world from guest kernel!\");";
        assert_eq!(
            source.matches(success_line).count(),
            1,
            "Expected the generated kernel template's Hello world body"
        );
        let failure_line = "    ostd::power::poweroff(ostd::power::ExitCode::Failure);";
        fs::write(&source_path, source.replacen(success_line, failure_line, 1)).unwrap();
    }

    #[test]
    fn basic_coverage() {
        // Test skipped because TDX is enabled.
        if is_tdx_enabled() {
            return;
        }

        let workspace = coverage_workspace("basic_coverage");
        let (output, coverage_file) = run_with_stale_profile(&workspace);
        assert_command_success(&output, "cargo osdk run --coverage");
        assert_profile_updated_and_readable(&coverage_file);
    }

    #[test]
    fn failure_exit_still_exports_coverage() {
        // Test skipped because TDX is enabled.
        if is_tdx_enabled() {
            return;
        }

        let workspace = coverage_workspace("failure_exit_coverage");
        let os_dir = PathBuf::from(workspace.os_dir());
        replace_generated_kernel_with_failure(&os_dir);

        let (output, coverage_file) = run_with_stale_profile(&workspace);
        assert!(
            output.status.code() == Some(1),
            "Expected a nonzero exit for guest ExitCode::Failure, got {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_profile_updated_and_readable(&coverage_file);
    }
}

mod qemu_gdb_feature {
    use super::*;
    use crate::util::cargo_osdk;
    use assert_cmd::Command;
    use std::{path::Path, thread::sleep};

    #[test]
    fn basic_debug() {
        // Test skipped because TDX is enabled.
        if is_tdx_enabled() {
            return;
        }
        let workspace = workspace::WorkSpace::new(WORKSPACE, "basic_debug");
        let unix_socket = {
            let path = Path::new(&workspace.os_dir()).join("qemu-gdb-sock");
            path.to_string_lossy().to_string()
        };

        let mut instance = cargo_osdk([
            "run",
            "--gdb-server",
            format!("addr={},wait-client", unix_socket.as_str()).as_str(),
        ]);
        instance.current_dir(workspace.os_dir());

        let sock = unix_socket.clone();
        let _gdb = std::thread::spawn(move || {
            gdb_continue_via_unix_sock(&sock);
        });

        let output = instance
            .output()
            .expect("Failed to wait for QEMU GDB instance");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(stdout.contains("Hello world from guest kernel!"));
    }

    fn gdb_continue_via_unix_sock(socket: &str) {
        let sock_file = Path::new(&socket);
        while !sock_file.exists() {
            sleep(std::time::Duration::from_secs(1));
        }
        gdb_continue_via(socket);
    }

    fn gdb_continue_via(addr: &str) {
        let mut gdb = Command::new("gdb");
        gdb.args(["-ex", format!("target remote {}", addr).as_str()]);
        gdb.write_stdin("\n")
            .write_stdin("quit\n")
            .write_stdin("y\n");
        gdb.assert().success();
    }
    mod vsc {
        use super::*;

        #[test]
        fn vsc_launch_file() {
            // Test skipped because TDX is enabled.
            if is_tdx_enabled() {
                return;
            }
            let kernel_name = "vsc_launch_file";
            let workspace = workspace::WorkSpace::new(WORKSPACE, kernel_name);
            let addr = ":50001";

            let mut instance = cargo_osdk([
                "run",
                "--gdb-server",
                format!("wait-client,vscode,addr={}", addr).as_str(),
            ]);
            instance.current_dir(workspace.os_dir());

            let dir = workspace.os_dir();
            let bin_file_path = Path::new(&workspace.os_dir())
                .join("target")
                .join("osdk")
                .join(kernel_name)
                .join(format!("{}-osdk-bin", kernel_name));
            let _gdb = std::thread::spawn(move || {
                while !bin_file_path.exists() {
                    sleep(std::time::Duration::from_secs(1));
                }
                assert!(
                    check_launch_file_existence(&dir),
                    "VSCode launch config file is not found during debugging session"
                );
                gdb_continue_via(addr);
            });

            let output = instance
                .output()
                .expect("Failed to wait for QEMU GDB instance");
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            assert!(stdout.contains("Hello world from guest kernel!"));
            assert!(
                !check_launch_file_existence(&workspace.workspace),
                "VSCode launch config file should be removed after debugging session"
            );
        }

        fn check_launch_file_existence(workspace: &str) -> bool {
            let launch_file = Path::new(workspace).join(".vscode/launch.json");
            launch_file.exists()
        }
    }
}
