# cargo osdk run

## Overview

`cargo osdk run` runs the kernel with QEMU:

```bash
cargo osdk run [OPTIONS]
```

Most options are shared with [cargo osdk build](build.md).

## Debugging

`--gdb-server` accepts a comma-separated list of settings:

- `addr=ADDR`: TCP address or UNIX socket path
  (default: `.osdk-gdb-socket`).
- `wait-client`: wait for the debugger before starting the guest.
- `vscode`: create a VSCode launch configuration for
  [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb).
  This setting requires a TCP address.

For a UNIX socket:

```bash
cargo osdk run --gdb-server addr=.debug
```

For TCP:

```bash
cargo osdk run --gdb-server addr=:1234
```

To wait for VSCode:

```bash
cargo osdk run --gdb-server wait-client,vscode,addr=:1234
```

See [cargo osdk debug](debug.md) for connecting a debugger.

## LLVM coverage

`--coverage` enables compiler profiling and exports `coverage.profraw`
into the OSDK working directory. Configure `qemu.log_file` in `OSDK.toml`
and write serial output to that same file. For example, with the standard
`mux` chardev, set `log_file = "qemu.log"` in the existing `[qemu]`
section and add `logfile=qemu.log` to its `-chardev stdio,...` argument.

```bash
cargo osdk run --coverage
llvm-profdata merge -sparse coverage.profraw -o coverage.profdata
llvm-profdata show --all-functions --counts coverage.profdata
```

Use `llvm-profdata` from the compiler's matching LLVM toolchain.

At poweroff, the guest captures an immutable profile and reports its address,
size and success/failure status. It then waits while OSDK pauses QEMU through
QMP and exports the buffer. OSDK checks the monitor response, exact file size
and LLVM raw-profile header before publishing the file and terminating QEMU.
A guest failure still produces a profile and returns a nonzero command status.

Each run clears the previous profile and serial log before launching QEMU.
Missing records, a disconnected monitor, rejected memory exports, truncated
files and invalid profile headers cause command failure. A successful QEMU
process exit alone does not indicate a successful export.
