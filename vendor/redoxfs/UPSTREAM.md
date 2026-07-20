# RedoxFS adaptation provenance

- Upstream: https://github.com/redox-os/redoxfs
- Commit: `99bc185bf8ad8bd6f4d2562c424d800c2a3d310b`
- Upstream version: 0.9.1
- License: MIT (`LICENSE`)

## GinkgoOS changes

- Reduced the package to the filesystem library core; upstream CLI and mount binaries are not built.
- Fixed missing `alloc::vec::Vec` imports in the upstream `no_std` configuration.
- Exposed deterministic, unencrypted formatting for the host seed-image build.
- Removed encryption-only dependencies and reject encrypted images because AES code generation is incompatible with the kernel code model used by GinkgoOS.
- Added a GinkgoOS memory-backed `Disk` implementation in `src/fs.rs`; the core RedoxFS format and transaction implementation remain upstream-derived.
