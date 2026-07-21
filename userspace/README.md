# GinkgoOS userspace workspace

This is the production, nested `x86_64-unknown-none` workspace. It is intentionally independent of the kernel's root Cargo workspace.

## Packages

- `ginkgo-runtime`: shared `no_std` talc static heap, panic/exit handling, `_start` entry macro, linker script, and build-script helper.
- `ginkgo-desktop-service`: window-policy service using `ginkgo_desktop::Desktop`, the broker runtime protocol, and per-client window channels.
- `ginkgo-minimal-client`: syscall-backed `WindowTransport`/`WindowClient` demo with deterministic checker rendering, two initial in-flight frames, post-release frames, and F11 fullscreen toggling.
- `validator`: host-only copy of the existing validation harness pattern which imports the kernel ELF parser directly.

## Build and validate

Run from `userspace/`:

```sh
cargo build --release --target x86_64-unknown-none -p ginkgo-desktop-service -p ginkgo-minimal-client
cargo run --manifest-path validator/Cargo.toml --target x86_64-pc-windows-msvc -- \
  target/x86_64-unknown-none/release/ginkgo-desktop-service \
  target/x86_64-unknown-none/release/ginkgo-minimal-client
```

Artifacts:

- `target/x86_64-unknown-none/release/ginkgo-desktop-service`
- `target/x86_64-unknown-none/release/ginkgo-minimal-client`

## Runtime constraints

All userspace and kernel channel queues are bounded. The desktop service retains queued payloads and transferred surface handles when a write returns `ShouldWait`, retries after yielding, and limits work per scheduler turn. The minimal client similarly treats empty reads and full-channel writes as transient.

The service expects the bootstrap peer to speak `ginkgo_desktop::RuntimePacket` version 1 and to provision client/surface handles with the rights required by that protocol. The current kernel integration must install these ELF artifacts and provide the broker side of that protocol before the binaries can be exercised end to end.
