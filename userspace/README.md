# GinkgoOS userspace workspace

This is the production, nested `x86_64-unknown-none` workspace. It is intentionally independent of the kernel's root Cargo workspace.

## Packages

- `ginkgo-runtime`: shared `no_std` talc static heap, panic/exit handling, `_start` entry macro, linker script, and build-script helper.
- `ginkgo-desktop-service`: production window-policy service using `ginkgo_desktop::Desktop`, the broker runtime protocol, per-app channels, and protected two-buffer surface pools.
- `ginkgo-minimal-client`: production syscall-backed `WindowTransport`/`WindowClient` demo with a centered “Hello World” surface and `F11` fullscreen toggling.
- `ginkgo-file-navigator`: keyboard-controlled persistent root-directory browser using the stable filesystem syscall wrappers; Up/Down selects, Enter previews, Backspace returns, and Delete removes non-system files.
- `ginkgo-terminal`: terminal emulator and bounded Rhai shell. Keyboard input and graphical child output use framed Ginkgo channel messages rather than file descriptors. Scripts can perform root file I/O, launch and inspect headless ELF jobs through process capabilities, manage bounded GKP installations, source another script, and request registry-governed graphical launches.
- `validator`: host-only copy of the existing validation harness pattern which imports the kernel ELF parser directly.

## Build and validate

Normal root Makefile builds compile all four production ELFs before the kernel and pass their paths into the kernel build for embedding as `/desktop.elf`, `/file-navigator.elf`, `/minimal-client.elf`, and `/terminal.elf` alongside `/programs.gkr`. To build or validate them directly, run from `userspace/`:

```sh
cargo build --release --target x86_64-unknown-none -p ginkgo-desktop-service -p ginkgo-file-navigator -p ginkgo-minimal-client -p ginkgo-terminal
cargo run --manifest-path validator/Cargo.toml --target x86_64-pc-windows-msvc -- \
  target/x86_64-unknown-none/release/ginkgo-desktop-service \
  target/x86_64-unknown-none/release/ginkgo-file-navigator \
  target/x86_64-unknown-none/release/ginkgo-minimal-client \
  target/x86_64-unknown-none/release/ginkgo-terminal
```

The terminal itself cannot use Rust's host test harness because it is a `no_std`, `no_main` GinkgoOS binary tied to the userspace syscall ABI. Pure GKP parser, bounds, unsafe-path, canonical registry, atomic mutation, and protected-ID behavior is covered by the `ginkgo-app-package` host tests:

```sh
cargo test -p ginkgo-app-package --features host --target x86_64-pc-windows-msvc
```

Artifacts:

- `target/x86_64-unknown-none/release/ginkgo-desktop-service`
- `target/x86_64-unknown-none/release/ginkgo-minimal-client`
- `target/x86_64-unknown-none/release/ginkgo-file-navigator`
- `target/x86_64-unknown-none/release/ginkgo-terminal`

## Runtime integration

The kernel boots `ginkgo-desktop-service` with only one bootstrap channel and the output dimensions. It launches each registered app with its attenuated per-app desktop channel; registry entries explicitly marked for filesystem access also receive a non-transferable filesystem-root capability. The service and kernel broker then provision protected shared-memory surfaces and client/manager capabilities. The boot registry exposes `Files`, `Terminal`, and `Ginkgo Demo` while keeping the desktop service hidden. The terminal alone receives launch authority; the kernel still resolves every request through the registry and applies the target entry's capability flags.

## Terminal shell

The prompt evaluates Rhai directly. Useful examples:

```rhai
print("hello from Rhai");
list_files() // compatibility: root entry names
mkdir("documents")
write_file("documents/notes.txt", "persistent text")
append_file("documents/notes.txt", "\nmore")
read_file("documents/notes.txt")
file_size("documents/notes.txt")
metadata("documents/notes.txt")
list_directory("documents")
rename_path("documents/notes.txt", "documents/archive.txt", false)
remove_file("documents/archive.txt")
rmdir("documents")
filesystem_info()
sync_filesystem()
syscall("yield")

// Direct ELF execution is headless and receives no transferred startup handles.
let job = spawn_elf("hello.elf", ["--verbose"]);
process_status(job)
wait_process(job)
terminate_process(job)
close_process(job)
exec_elf("one-shot.elf", ["input.txt"])

install_package("paint.gkp")
list_installed()
uninstall_app("tools.paint")

// Graphical applications continue through registry and desktop policy.
run("minimal-client")
```

Enter `source "script.rhai"` to evaluate another script by a relative path.

### Filesystem functions

All terminal filesystem paths are relative to the explicit filesystem-root capability supplied at startup. Nested relative paths are accepted; absolute paths, `.` and `..` components, backslashes, and ambient kernel current-working-directory state are not used. Operations that enumerate a path open and close a directory capability beneath that root.

- `mkdir(path)` creates one directory at `path`; parent directories must already exist.
- `rmdir(path)` removes an empty directory.
- `rename_path(source, destination, replace)` atomically renames or moves a file or directory beneath the same root. If `replace` is `false`, an existing destination causes failure; if it is `true`, a compatible destination may be replaced.
- `sync_filesystem()` flushes pending filesystem data and metadata.
- `filesystem_info()` returns capacity and limit fields (`total_bytes`, `free_bytes`, `available_bytes`, `block_size`, `max_name_length`, `max_path_depth`, and `read_only`) or an error string.
- `metadata(path)` returns `kind`, stable `identity`, numeric `mode`, `size`, and a `time` map containing `created_ns` and `modified_ns`, or an error string.
- `list_directory(path)` returns up to 256 rich entry maps with `name` plus the same kind, identity, mode, size, and time fields. It reports an error and returns an empty array on failure.
- `list_files()` remains the compatibility form and returns up to 256 root entry names.

Filesystem counters, identities, sizes, and nanosecond timestamps are Rhai integers when they fit; values beyond the signed integer range are returned as decimal strings instead of being truncated.

### Process jobs

`spawn_elf(path, args)` opens `path` with `READ | EXECUTE`, constructs bounded NUL-terminated UTF-8 arguments with `path` as `argv[0]`, creates the process with no ambient startup-handle dispositions or configuration, closes the executable file handle, and returns a positive terminal-local job ID. It reports an error and returns `-1` if validation or creation fails. At most 32 arguments including `argv[0]`, 16 KiB of startup bytes, and 32 retained jobs are accepted.

The headless job table is separate from graphical children and retains each process capability until `close_process(job_id)` or terminal shutdown. `process_status` and the infinite-wait `wait_process` return a map on success or an error string. The map's `state` is `running`, `exited`, `faulted`, or `terminated`; normal exits include `exit_code`, while faults include `fault`, `fault_code`, and `fault_address` (the code and address are fixed-width hexadecimal strings). `terminate_process` requests termination but retains the job handle. `exec_elf` is the synchronous convenience form: it launches headlessly, waits indefinitely, closes its process handle, and returns the same status map/error-string shape.

Direct execution intentionally does not create a window or bypass graphical launch policy. `run(app_id)` remains the graphical path: it creates a fresh bidirectional console channel and transfers the child endpoint through the desktop broker, which resolves the registry ID and applies entry capabilities. Console-aware graphical children receive the endpoint as startup argument 3 (`rdx`), and the terminal polls its independently retained endpoint for `Output`, `Error`, and `Exit` messages.

### Package installation

`install_package(path)` accepts a bounded GKP file (currently capped at 1 MiB to fit the terminal's 2 MiB static heap), validates it with `ginkgo-app-package`, and installs or updates its registry entry. `desktop`, `files`, `terminal`, and `minimal-client` are protected system IDs and cannot be installed, updated, or removed. `list_installed()` returns maps containing `app_id`, `display_name`, `version`, `kind`, immutable executable filename, executable `sha256`, and package `package_sha256`. `uninstall_app(app_id)` publishes the registry removal before deleting the executable generation.

Executables are written under immutable generation filenames derived from the app ID and the actual SHA-256 of the ELF. The installed registry is `installed-apps.gki`; publication first writes and verifies `installed-apps.gki.new`, then publishes the canonical snapshot. Updates retain the old executable until publication succeeds. On failure, the terminal restores the prior registry when possible and removes newly created executable/seed files only when rollback confirms they are unreferenced; the old executable is never removed by a failed publication.

Package storage retains its existing flat generation layout for compatibility with the canonical registry validation used by #8. Executables keep immutable generation filenames derived from the app ID and ELF digest, while seed assets use deterministic app-owned backing names of the form `<app-id>-seed-<SHA-256-of-virtual-path>.dat`; existing backing files are preserved so updates do not overwrite application data. Moving these to `applications/<app-id>/versions/` and `appdata/<app-id>/` requires a coordinated registry-format migration rather than a terminal-only path change.

The service implements channel handling, protected two-buffer pools, server decorations, focus, fullscreen, pointer/keyboard routing, and compositor placements. Resize is generation-staged: the old frame remains displayed until the first new-generation present succeeds. Presented slots return to the client only through matching `BufferReleased` events. The compositor assembles a complete scene in RAM and publishes it with packed framebuffer writes before completing a presentation.

All userspace and kernel channel queues are bounded. The service retains queued payloads and transferred surface handles after `ShouldWait`, retries after yielding, and limits work per scheduler turn. The minimal client treats empty reads and full writes as transient, submits one steady “Hello World” frame for each configuration, and does not repaint continuously after `BufferReleased`. The kernel does not auto-launch it; apps start only through an explicit launcher action.

`META+N` toggles the registry launcher. Integrated pane bindings are `META+Left/Right` (focus), `META+Q` (close the focused application), `META+A/S` (move left/right), `META+=/-` (width by 5%), and `META+L/C/R` (left/center/right alignment). Columns scroll horizontally, so additional live applications may be off-screen and remain reachable with the focus bindings. Remaining hotkey work is tracked in #5.
