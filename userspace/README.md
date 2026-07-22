# GinkgoOS userspace workspace

This is the production, nested `x86_64-unknown-none` workspace. It is intentionally independent of the kernel's root Cargo workspace.

## Packages

- `ginkgo-runtime`: shared `no_std` talc static heap, panic/exit handling, `_start` entry macro, linker script, and build-script helper.
- `ginkgo-desktop-service`: production window-policy service using `ginkgo_desktop::Desktop`, the broker runtime protocol, per-app channels, and protected two-buffer surface pools.
- `ginkgo-minimal-client`: production syscall-backed `WindowTransport`/`WindowClient` demo with a centered “Hello World” surface and `F11` fullscreen toggling.
- `ginkgo-file-navigator`: keyboard-controlled persistent root-directory browser using the stable filesystem syscall wrappers; Up/Down selects, Enter previews, Backspace returns, and Delete removes non-system files.
- `ginkgo-terminal`: terminal emulator and bounded Rhai shell. Keyboard input and shell/child output use framed Ginkgo channel messages rather than file descriptors. Scripts can perform root file I/O, yield through the safe syscall facade, source another script, and request registry-governed program launches.
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
list_files()
read_file("notes.txt")
write_file("notes.txt", "persistent text")
append_file("notes.txt", "\nmore")
file_size("notes.txt")
remove_file("notes.txt")
syscall("yield")
run("minimal-client")
```

Enter `source "script.rhai"` to evaluate another root-level script. Ginkgo does not yet expose nested directories. `run` creates a fresh bidirectional console channel and transfers the child endpoint through the desktop broker; console-aware children receive it as startup argument 3 (`rdx`). The terminal polls the retained endpoint for `Output`, `Error`, and `Exit` protocol messages.

The service implements channel handling, protected two-buffer pools, server decorations, focus, fullscreen, pointer/keyboard routing, and compositor placements. Resize is generation-staged: the old frame remains displayed until the first new-generation present succeeds. Presented slots return to the client only through matching `BufferReleased` events. The compositor assembles a complete scene in RAM and publishes it with packed framebuffer writes before completing a presentation.

All userspace and kernel channel queues are bounded. The service retains queued payloads and transferred surface handles after `ShouldWait`, retries after yielding, and limits work per scheduler turn. The minimal client treats empty reads and full writes as transient, submits one steady “Hello World” frame for each configuration, and does not repaint continuously after `BufferReleased`. The kernel does not auto-launch it; apps start only through an explicit launcher action.

`META+N` toggles the registry launcher. Integrated pane bindings are `META+Left/Right` (focus), `META+Q` (close the focused application), `META+A/S` (move left/right), `META+=/-` (width by 5%), and `META+L/C/R` (left/center/right alignment). Columns scroll horizontally, so additional live applications may be off-screen and remain reachable with the focus bindings. Remaining hotkey work is tracked in #5.
