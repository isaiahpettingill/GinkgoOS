# GinkgoOS security model

GinkgoOS is a single-user, capability-oriented hobby OS aimed at emulation and retrocomputing. Its policy is intentionally closer to KolibriOS's compact, application-centric environment than to Unix: a process receives explicit object handles at launch, and there is no ambient root user, inherited file-descriptor namespace, UID/GID permission lattice, or global random device.

## Threat model

The kernel protects itself and mutually distrustful ring-3 applications from malformed executable files, invalid pointers, capability forgery, unauthorized object operations, writable executable mappings, and bounded resource-exhaustion attempts. Signed system metadata protects executable and launcher policy bytes stored on an untrusted or accidentally corrupted system disk.

The current model does **not** protect against a malicious bootloader, firmware, kernel image, physical attacker, DMA-capable device, compromised signing key, hardware fault, cold-boot attack, or side channels between applications. Disk contents and user data are not encrypted. The system is presently single-core and does not claim SMP-safe revocation or TLB shootdown.

## Trusted computing base

The trusted computing base is:

- the Limine boot path, firmware, and loaded GinkgoOS kernel image;
- the kernel's Rust code, small x86-64 assembly entry/fixup paths, allocator, drivers, RedoxFS adapter, and embedded public trust key;
- the signed system manifest and the registry policy it authenticates;
- the desktop service for window/input policy, but not for kernel isolation;
- compiler, linker, build script, and release-signing environment.

Applications, filesystem bytes read after boot, IPC payloads, ELF metadata, device input, and syscall addresses are untrusted.

## Executable and update trust

The build emits an Ed25519-signed `GKTM` manifest covering each trusted system path, exact length, and SHA-256 digest. After files are refreshed on the system volume, the kernel verifies the manifest signature with its compiled-in public key and verifies each registry/executable byte string before parsing or loading it. A missing, malformed, unsigned, length-mismatched, or digest-mismatched artifact is rejected.

Local development uses the documented deterministic development key. Official or redistributed builds must set `GINKGO_TRUST_SIGNING_KEY_HEX` to a protected 32-byte Ed25519 seed in the release environment and must not publish that seed. Rotating the release key requires a new kernel carrying the new public key. Future online updates must be staged, completely verified under the same manifest policy, and switched atomically; rollback counters are not yet implemented, so signed rollback remains an unsupported threat.

Registry signatures identify approved application bytes and launch policy. They do not create ambient identity. Installation and launch remain explicit capability-mediated operations. Persistent principals should be introduced only if a future service needs durable policy that cannot be represented by attenuated handles (for example, separate encrypted profiles).

## Entropy and random capabilities

Boot requires RDSEED or RDRAND to return 256 bits successfully. Those words seed a kernel ChaCha20 generator after SHA-256 mixing with timing and boot context. Timing values receive no entropy credit. If hardware seeding fails, secure userspace startup fails closed rather than silently exposing predictable output.

A process can request at most 4096 bytes per call and only through a non-transferable, read-only `RandomSource` handle supplied by the trusted launcher. Applications never execute hardware random instructions directly through the Ginkgo API.

## Memory and CPU policy

- NX is required and enabled; every userspace mapping enforces W^X.
- SMAP is enabled when CPUID advertises it. User copies arm one CPU-local page-fault fixup and use `STAC`/`CLAC`; a bad pointer returns `InvalidAddress` instead of panicking the kernel. Other kernel faults still fail stop.
- `ET_EXEC` remains fixed for compatibility. Static position-independent `ET_DYN` images receive a randomized 2 MiB-aligned load bias. Stack and automatic shared-memory regions use independent randomized inputs and preserve guard pages. Dynamic linking and runtime relocation records are not supported.
- Each process is limited to 256 handles. Private pages, created and mapped shared memory, reserved virtual bytes, VMA count, and executable source/image size are derived from validated usable physical RAM with checked floors and ceilings. Outbound channel traffic remains bounded. Accounting is conservative and lifetime-based where resources can outlive one syscall.
- At most 32 processes may be live. Process creation remains available only through explicit launch authority and signed registry entries.
- Each runnable process receives at most a 10 ms uninterrupted quantum per round. Total CPU time is accounted without terminating legitimate long-running emulators.
- Channel message size, attached-handle count, queue depth, ELF size/pages, registry entries, filesystem I/O, waits, and debug writes have independent bounds.

## CPU and debug-state audit

GinkgoOS requires x86-64, SYSCALL, NX, x87, FXSAVE, SSE, and SSE2. On XSAVE-capable CPUs it enables and preserves x87/SSE/AVX state (including AVX2's YMM state) in bounded 64-byte-aligned per-process areas; legacy CPUs retain FXSAVE switching. Current system images use an SSE2 baseline without masking newer hardware features. User FS/GS bases are reset/not exposed, and debug-register state is not available to applications. IRET state is revalidated on every return. Kernel pages are supervisor-only and userspace cannot request executable shared memory.

No universal speculative-execution mitigation is enabled yet. The kernel does not currently schedule mutually hostile secrets across SMT siblings because SMP is unsupported, but it also does not claim protection from Spectre-class, MDS, L1TF, Retbleed, or vendor-specific transient-execution attacks. Before SMP or secret-bearing multi-user services, initialization must inventory vendor/model/microcode capabilities and apply the appropriate `IA32_SPEC_CTRL`, predictor-barrier, SMT, and buffer-clearing policy without pretending one sequence is portable to all supported CPUs.

## Reporting

Security-sensitive defects can be filed in the project issue tracker. Do not include private signing seeds, personal disk images, or other secrets in a public report.
