# GinkgoOS userspace workspace

This is the production, nested `x86_64-unknown-none` workspace. It is intentionally independent of the kernel's root Cargo workspace.

## Packages

- `ginkgo-runtime`: shared `no_std` talc static heap, panic/exit handling, `_start` entry macro, linker script, and build-script helper.
- `ginkgo-desktop-service`: production window-policy service using `ginkgo_desktop::Desktop`, the broker runtime protocol, per-app channels, and protected two-buffer surface pools.
- `ginkgo-minimal-client`: production syscall-backed `WindowTransport`/`WindowClient` demo with a centered “Hello World” surface and `F11` fullscreen toggling.
- `validator`: host-only copy of the existing validation harness pattern which imports the kernel ELF parser directly.

## Build and validate

Normal root Makefile builds compile both production ELFs before the kernel and pass their paths into the kernel build for embedding as `/desktop.elf` and `/minimal-client.elf` alongside `/programs.gkr`. To build or validate them directly, run from `userspace/`:

```sh
cargo build --release --target x86_64-unknown-none -p ginkgo-desktop-service -p ginkgo-minimal-client
cargo run --manifest-path validator/Cargo.toml --target x86_64-pc-windows-msvc -- \
  target/x86_64-unknown-none/release/ginkgo-desktop-service \
  target/x86_64-unknown-none/release/ginkgo-minimal-client
```

Artifacts:

- `target/x86_64-unknown-none/release/ginkgo-desktop-service`
- `target/x86_64-unknown-none/release/ginkgo-minimal-client`

## Runtime integration

The kernel boots `ginkgo-desktop-service` with only one bootstrap channel and the output dimensions. It launches each registered app with only its attenuated per-app desktop channel; the service and kernel broker then provision protected shared-memory surfaces and client/manager capabilities. The boot registry exposes `Ginkgo Demo` while keeping the desktop service hidden.

The service implements channel handling, protected two-buffer pools, server decorations, focus, fullscreen, pointer/keyboard routing, and compositor placements. Resize is generation-staged: the old frame remains displayed until the first new-generation present succeeds. Presented slots return to the client only through matching `BufferReleased` events. The compositor assembles a complete scene in RAM and publishes it with packed framebuffer writes before completing a presentation.

All userspace and kernel channel queues are bounded. The service retains queued payloads and transferred surface handles after `ShouldWait`, retries after yielding, and limits work per scheduler turn. The minimal client treats empty reads and full writes as transient, submits one steady “Hello World” frame for each configuration, and does not repaint continuously after `BufferReleased`. The kernel does not auto-launch it; apps start only through an explicit launcher action.

`META+N` toggles the registry launcher. Integrated pane bindings are `META+Left/Right` (focus), `META+A/S` (move left/right), `META+=/-` (width by 5%), and `META+L/C/R` (left/center/right alignment); broader hotkey work is tracked in #5. The userspace filesystem ABI and filesystem-backed search are tracked in #4.
