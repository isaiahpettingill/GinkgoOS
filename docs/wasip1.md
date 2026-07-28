# WASIp1 command runtime

GinkgoOS runs installed WebAssembly commands through a dedicated ring-3 `wasmi` process. The kernel still loads only native Ginkgo ELF files. The terminal verifies an installed module against `applications/installed.gki`, starts the signed `/system/wasm-runtime.elf`, and passes the module as an attenuated read-only startup handle.

## Package metadata

GKP packages and the installed GKI registry store an executable format separately from the application kind:

| Value | Format | Generation suffix |
| ---: | --- | --- |
| `0` | Native Ginkgo ELF | `.elf` |
| `1` | WebAssembly command | `.wasm` |

Value `0` preserves compatibility with existing packages and registries, where this field was reserved and had to be zero. WebAssembly is currently valid only with `AppKind::Command`; graphical WebAssembly packages are rejected.

A host-side packager should set:

```rust
PackageInput {
    kind: AppKind::Command,
    format: ExecutableFormat::Wasm,
    // ...
}
```

After installation, enter the package's app ID in the terminal exactly as for a native command. Arguments are passed to the WASIp1 module and `_start` is called. Foreground commands return their process exit status. Background commands use the terminal's existing job controls. A direct path ending in `.wasm`, such as `/user/tool.wasm`, uses the same runtime without package installation.

## Supported ABI

The runtime accepts core WebAssembly modules with a WASIp1 command `_start` export. It registers the same capability-safe functions under the current `wasi_snapshot_preview1` namespace and the older `wasi_unstable` namespace used by early WASI toolchains.

Implemented calls:

- `args_get`, `args_sizes_get`
- `environ_get`, `environ_sizes_get` with an empty environment
- `proc_exit`
- `fd_write` for stdout and stderr through the terminal console protocol
- nonblocking `fd_read` for stdin; it returns `EAGAIN` when no terminal input is queued
- one capability-scoped preopened directory on descriptor 3, named `/`
- `path_open`, `path_filestat_get`, `path_create_directory`, `path_remove_directory`, `path_unlink_file`, and `path_rename`
- `fd_close`, `fd_fdstat_get`, `fd_fdstat_set_flags`, and attenuating `fd_fdstat_set_rights`
- `fd_prestat_get` and `fd_prestat_dir_name`
- file `fd_read`, `fd_write`, `fd_pread`, `fd_pwrite`, `fd_seek`, and `fd_tell`
- `fd_filestat_get`, `fd_filestat_set_size`, `fd_readdir`, `fd_advise`, `fd_sync`, and `fd_datasync`
- monotonic `clock_res_get` and `clock_time_get`
- `poll_oneoff` for monotonic deadlines, terminal readiness, and regular files
- capability-backed `random_get`
- `sched_yield`

The terminal receives a separate random-source capability and duplicates read-only authority into each WASM runtime. The runtime never turns a guest integer into a native handle.

The environment is empty. Built-in tools and directly executed modules receive `/user` as the preopened `/`; installed modules receive only their own `appdata/<app-id>` directory. Guest paths must be relative and cannot contain `..`, backslashes, NUL bytes, or empty components.

The current runtime does not provide realtime or process CPU clocks, file timestamp mutation, hard links, symbolic links, socket calls, signals, threads, guaranteed file allocation, or atomic `O_CREAT | O_EXCL`. Unsupported imports fail module instantiation with a named missing-import error. `fd_filestat_get` reports the known file type and current size but leaves unavailable device, inode, and timestamp fields at zero.

## Limits and isolation

Each invocation runs in its own normal-class Ginkgo process. Untrusted and direct-path modules use these additional guest limits:

- module bytes: 64 MiB
- linear memory: 256 MiB
- memories: 1
- tables: 1
- table elements: 65,536
- instances: 1
- Wasm value stack: 65,536 values
- Wasm call depth: 1,024
- execution fuel: 500,000,000 units
- memory64, multi-memory, custom page sizes, tail calls, and SIMD: disabled or unavailable in the pinned build

An installed WASM generation may be explicitly marked with `trust <app-id>`. Trusted launches disable fuel and the wasmi store memory/table/instance limiter, but retain kernel scheduling, private-page, virtual-memory, VMA, channel-traffic, module-byte, stack, descriptor, and capability limits. `untrust <app-id>` restores interpreter limits for future launches. Updates revoke trust, and direct paths always remain constrained.

Every guest-memory pointer and length is bounds checked before host access. A malformed module, invalid pointer, trap, missing import, or exhausted fuel terminates only the runtime process and reports an error through the terminal channel. Process teardown reclaims the interpreter, module, guest memory, and startup handles.

## Building a Rust command

Install a Rust toolchain that provides the `wasm32-wasip1` target, then build a normal command crate:

```sh
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
```

Inspect imports before packaging:

```sh
wasm-tools print target/wasm32-wasip1/release/example.wasm
```

The module must import only the calls listed above. Rust and C WASIp1 command runtimes that depend on arguments, terminal I/O, monotonic polling, random data, and capability-scoped files now fit this profile. Programs that require sockets, realtime clocks, links, signals, threads, or timestamp mutation still need a smaller build or compatibility shim.

GinkgoOS also bundles the official WABT 1.0.41 WASI tools. Run `wat2wasm`, `wasm2wat`, `wasm-validate`, and the other WABT command names directly in the terminal. See `/system/docs/webassembly.md` in GinkgoOS or `docs/webassembly-development.md` in the source tree.

## Ginkgo-specific imports

WASIp1 compatibility and GinkgoOS platform functions are separate interfaces. Standard calls remain under `wasi_snapshot_preview1`. Windowing, protected surfaces, input, audio, channels, shared memory, process launch, and other native services will use a versioned `ginkgo_v1` namespace.

`ginkgo_v1` is not registered yet. Graphical WASM packages remain unsupported until that namespace has a capability-safe guest handle table, pointer validation, event delivery, package capability declarations, and SDK bindings. Modules must not import native x86-64 syscall numbers because WebAssembly pointers address guest linear memory rather than native process memory.

## Version policy

The interpreter is pinned to `wasmi 0.46` with default features disabled and B-tree collections enabled for `no_std`. GKP and GKI remain wire version 1 because the executable-format field reuses a required-zero reserved word. Unknown format values are rejected. New incompatible runtime or package metadata will require a new wire or import namespace version rather than changing existing values in place.
