# WebAssembly and native application development

This manual is installed globally as `/system/docs/webassembly.md` and is also kept in the source tree at `docs/webassembly-development.md`.

## WABT tools

GinkgoOS includes the official WABT 1.0.41 WASI release under `/system/bin`. Enter these names directly in the terminal:

- `wat2wasm` — compile WebAssembly text (`.wat`) to a binary module.
- `wasm2wat` — convert a binary module to text.
- `wasm-validate` — validate a binary module.
- `wasm-objdump` — print section, symbol, relocation, and disassembly details.
- `wasm-strip` — remove names and debugging sections.
- `wasm-decompile` — produce decompiler-style text.
- `wasm-stats` — print instruction and section statistics.
- `wasm-interp` — run a module with WABT's interpreter.
- `spectest-interp` — run spec-test scripts.
- `wast2json` — convert a spec-test script to JSON and modules.
- `wat-desugar` — normalize WebAssembly text syntax.
- `wasm2c` — translate a module to C source.

The tools see the Ginkgo `/user` directory as WASI preopen `/`. Paths passed to WABT are relative to `/user`, even though WABT displays them with conventional WASI syntax.

Example:

```text
wat2wasm "hello.wat", "-o", "hello.wasm"
wasm-validate "hello.wasm"
wasm-objdump "-x", "hello.wasm"
wasm2wat "hello.wasm", "-o", "hello-roundtrip.wat"
```

The Ginkgo shell separates arguments with commas. Use `launch "wat2wasm", ...` to run a tool in a new terminal.

WABT compiles WebAssembly text and transforms existing modules. It is not a C, C++, or Rust compiler. Build those languages for `wasm32-wasip1` with their normal cross compiler, then use WABT to inspect or transform the output.

## Packaging a module

Create and install a command package:

```text
package "hello.wasm", "hello.gkp", "examples.hello", "Hello", "1.0.0"
install "hello.gkp"
examples.hello "first argument"
```

Use `unpackage "hello.gkp", "hello-package"` to create an editable `package.gkm`, executable, and `assets/` tree. Rebuild it with `package "hello-package", "hello-updated.gkp"`.

## WASIp1 guest interface

A Ginkgo WebAssembly command exports `_start` and imports standard functions from `wasi_snapshot_preview1`.

Currently supported:

- arguments and an empty environment;
- `proc_exit`;
- terminal `fd_read`/`fd_write` on descriptors 0, 1, and 2;
- one capability-scoped preopened directory on descriptor 3, named `/`;
- `path_open`, `path_filestat_get`, directory creation/removal, file unlink, and rename;
- `fd_close`, descriptor status/flag access, and guest-local rights attenuation;
- `fd_prestat_get`, `fd_prestat_dir_name`, and `fd_readdir`;
- file read/write, positional read/write, seek/tell, stat, truncate, sync, datasync, and advice;
- monotonic clock time/resolution, `poll_oneoff`, `random_get`, and `sched_yield`;
- retained terminal input across short reads;
- bounded execution fuel, memory, tables, call depth, descriptors, polling subscriptions, I/O vectors, and module bytes.

Installed modules receive only their own application-data directory as `/`. Built-in tools and directly executed modules receive `/user`. Guest paths cannot be absolute and cannot contain `..`, backslashes, NUL bytes, or empty components.

Realtime and process CPU clocks, file timestamp mutation, links and symlinks, sockets, signals, threads, guaranteed file allocation, and atomic create-exclusive opens are not yet available. `fd_filestat_get` cannot report exact open-handle identity or timestamps because GinkgoOS does not yet expose rich metadata by open handle. Unsupported imports fail instantiation instead of receiving ambient authority.

## Ginkgo-specific WebAssembly imports

The current interpreter does not expose a `ginkgo_v1` guest import namespace yet. WebAssembly modules cannot currently create windows or call raw Ginkgo handles directly. Do not import native x86-64 syscall numbers from a Wasm module: guest pointers refer to linear memory and are not native process pointers.

Graphical WebAssembly support will require versioned host functions that validate every guest pointer and map opaque guest handles to delegated Ginkgo capabilities. Until that ABI exists, package WebAssembly modules as `command`, not `graphical`.

## Native ELF startup

A registry-launched native application enters an `extern "C"` function with six integer arguments. The commonly used arguments are:

1. desktop/window channel handle;
2. filesystem capability;
3. optional startup or terminal channel;
4. random-source capability, or system-power capability for the terminal;
5. interactive scheduling authority;
6. reserved.

Use `ginkgo_runtime::entry!` or `entry6!` to define `_start`. Convert raw handle values only after checking that they fit `u32` and produce a valid `ginkgo_userspace::Handle`.

A process created with `process_create` instead receives the versioned `GKSP` startup block containing NUL-terminated arguments, opaque configuration bytes, and transferred child-local handles.

## Creating a native window

Native graphical apps use `ginkgo_userspace::WindowTransport` and `ginkgo_window::WindowClient` rather than sending raw messages.

```rust
let transport = WindowTransport::new(desktop_handle)?;
let mut window = WindowClient::new(transport);
let request = window.create_window(WindowOptions {
    title: String::from("Example"),
    preferred_size: Size::new(640, 480),
    minimum_size: Some(Size::new(320, 240)),
    ..WindowOptions::default()
})?;
```

`create_window` returns a request ID. Keep polling `window.poll_event()` until `Event::WindowCreated` and `Event::Configured` arrive. Configuration supplies a protected multi-buffer surface generation. A request may return `ShouldWait`; yield and retry rather than spinning forever.

Handle these events:

- `Configured` — dimensions, pixel format, stride, generation, and new protected buffers changed.
- `Redraw` — repaint the requested damaged region.
- `Keyboard` and `Pointer` — input for this window.
- `BufferReleased` — a previously presented buffer became reusable; the client state machine consumes this internally.
- `CloseRequested` — destroy the window and exit cleanly.
- `FocusChanged` — keyboard focus changed.
- `RequestFailed` — a request did not complete.

## Drawing and presenting

Acquire a frame only when one is available:

```rust
if let Some(mut frame) = window.acquire_frame()? {
    let mut pixels = frame.pixel_surface()?;
    pixels.clear(Rgb::new(24, 24, 28));
    pixels.fill_rect(20, 20, 200, 80, Rgb::new(70, 120, 220));
    pixels.draw_text(32, 48, 1, "Hello", Rgb::new(255, 255, 255));
    frame.present(vec![Rect::new(0, 0, 640, 480)])?;
}
```

The exact drawing helpers come from `ginkgo_graphics::PixelSurface`. The frame's pixel format and stride come from the active configuration; do not assume tightly packed rows. Present damage is surface-local and half-open. An empty damage list means the complete surface.

Do not reuse a presented buffer until the matching release event has been processed. Do not cache a surface across `Configured` generations. Dropping an unpresented frame returns its slot to the local pool.

## Native filesystem, process, and IPC functions

The `ginkgo-userspace` crate exposes typed syscall wrappers. Important groups include:

- Files: `filesystem_open`, `filesystem_read`, `filesystem_write`, `filesystem_stat`, `filesystem_get_metadata`, `filesystem_read_directory2`, `filesystem_sync`, and path mutation calls.
- Processes: `process_create`, `process_create_with_policy`, `process_get_info`, `process_wait`, `process_terminate`, and `process_exit`.
- IPC: `channel_create`, `channel_read`, `channel_write`, `wait_many`, and rights-attenuating `HandleDisposition` transfers.
- Memory: anonymous mappings, file mappings, shared memory creation/mapping, protection, and unmapping.
- Runtime: `monotonic_time_ns`, `random_fill` with a delegated random-source handle, and `process_yield`.

Every operation requires a handle with the needed rights. Handles are generation-protected capabilities, not file-descriptor integers that can be manufactured. Move or duplicate handles only through `HandleDisposition`, request a subset of source rights, and close owned handles exactly once.

Channel reads and writes are nonblocking. `Status::ShouldWait` means wait for `READABLE` or `WRITABLE` through `wait_many`, or yield and retry in a bounded UI loop. `Status::PeerClosed` is a normal lifecycle event.

## Further source references

- `crates/ginkgo-userspace/src/lib.rs` — native syscall wrappers.
- `crates/ginkgo-window/src/client.rs` — window state machine.
- `crates/ginkgo-window/src/protocol.rs` — window wire types and limits.
- `crates/ginkgo-graphics/src/lib.rs` — pixel drawing.
- `userspace/ginkgo-minimal-client/src/main.rs` — small native graphical example.
- `userspace/ginkgo-wasm-runtime/src/main.rs` — WASIp1 host implementation and limits.
- `docs/packages.md` — package editing, installation, and removal.
