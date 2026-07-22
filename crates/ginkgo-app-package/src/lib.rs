#![no_std]

//! Bounded package and installed-application registry formats for GinkgoOS.
//!
//! Ginkgo packages (`.gkp`) deliberately use a small, deterministic binary format
//! instead of ZIP. ZIP has multiple directory representations, duplicate-name and
//! path-normalization ambiguities, optional compression and encryption methods, data
//! descriptors, and large implementation surface. An installer running with storage
//! authority should not have to reconcile those choices. GKP has one canonical field
//! order, no compression, fixed little-endian integers, explicit limits, and rejects
//! unknown flags, duplicate assets, unsafe paths, truncation, and trailing bytes.
//!
//! A package contains validated installer metadata, one ELF byte string, and optional
//! seed-data records. Seed paths are normalized relative names intended to be copied
//! beneath an application-owned data directory; they can never name an absolute or
//! parent path. Parsing borrows the input and performs no allocation. Its version 1
//! little-endian layout is:
//!
//! ```text
//! GKP header (24 bytes):
//!   magic "GKP\\0" | format_version u16 | flags u16 | app_kind u16
//!   asset_count u16 | app_id_len u16 | display_name_len u16 | app_version_len u16
//!   reserved u16 | executable_len u32
//! app_id | display_name | app_version | executable
//! repeated asset_count times:
//!   path_len u16 | flags u16 | data_len u32 | relative_path | data
//! ```
//!
//! The installed registry (`.gki`) is a separate mutable snapshot. It stores entries
//! in app-ID order and records an immutable executable generation name derived from
//! the app ID and executable digest, along with its exact length and package-digest
//! provenance. Registry mutation is performed on an owned in-memory snapshot and
//! validates an entire operation before changing it, allowing the caller to persist
//! the resulting encoded snapshot atomically. Its version 1 little-endian layout is:
//!
//! ```text
//! GKI header (12 bytes): magic "GKI\\0" | format_version u16 | flags u16 | count u32
//! each entry (fixed header followed by strings):
//!   app_id_len u16 | display_name_len u16 | app_version_len u16 | filename_len u16
//!   app_kind u16 | flags u16 | provenance_kind u16 | reserved u16
//!   executable_len u64 | executable_digest [u8; 32] | package_digest [u8; 32]
//!   app_id | display_name | app_version | generation_filename
//! ```

extern crate alloc;

mod package;
mod registry;
mod sha256;
mod validation;

#[cfg(feature = "host")]
pub use package::{encode_package, AssetInput, EncodeError, PackageInput};
pub use package::{
    AppKind, Asset, Assets, Field, Package, PackageError, PACKAGE_HEADER_SIZE, PACKAGE_MAGIC,
    PACKAGE_VERSION,
};
pub use registry::{
    generation_filename, ExecutableGeneration, InstalledApp, InstalledRegistry, MutationError,
    Provenance, RegistryError, REGISTRY_MAGIC, REGISTRY_VERSION,
};
pub use sha256::{sha256, Sha256};
pub use validation::{
    MAX_APP_ID_LEN, MAX_ASSET_COUNT, MAX_ASSET_DATA_LEN, MAX_ASSET_PATH_LEN, MAX_DISPLAY_NAME_LEN,
    MAX_EXECUTABLE_LEN, MAX_GENERATION_FILENAME_LEN, MAX_INSTALLED_APPS, MAX_PACKAGE_LEN,
    MAX_REGISTRY_LEN, MAX_TOTAL_ASSET_DATA_LEN, MAX_VERSION_LEN,
};

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn encoded_package(
        app_id: &str,
        display_name: &str,
        version: &str,
        executable: &[u8],
        assets: &[(&str, &[u8])],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PACKAGE_MAGIC);
        bytes.extend_from_slice(&PACKAGE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(AppKind::Graphical as u16).to_le_bytes());
        bytes.extend_from_slice(&(assets.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(app_id.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(display_name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(version.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(executable.len() as u32).to_le_bytes());
        bytes.extend_from_slice(app_id.as_bytes());
        bytes.extend_from_slice(display_name.as_bytes());
        bytes.extend_from_slice(version.as_bytes());
        bytes.extend_from_slice(executable);
        for (path, data) in assets {
            bytes.extend_from_slice(&(path.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(path.as_bytes());
            bytes.extend_from_slice(data);
        }
        bytes
    }

    fn package(app_id: &str, version: &str, executable: &[u8]) -> Vec<u8> {
        encoded_package(app_id, "Example App", version, executable, &[])
    }

    #[test]
    fn parses_package_and_assets() {
        let bytes = encoded_package(
            "tools.paint",
            "Paint",
            "1.2.0",
            b"ELF",
            &[("examples/flower.gkg", b"seed"), ("palette.txt", b"rgb")],
        );
        let parsed = Package::parse(&bytes).unwrap();
        assert_eq!(parsed.app_id, "tools.paint");
        assert_eq!(parsed.kind, AppKind::Graphical);
        assert_eq!(parsed.executable, b"ELF");
        assert_eq!(
            parsed.assets().map(|asset| asset.path).collect::<Vec<_>>(),
            ["examples/flower.gkg", "palette.txt"]
        );
    }

    #[cfg(feature = "host")]
    #[test]
    fn host_encoder_is_canonical() {
        let assets = [AssetInput {
            path: "defaults/config.txt",
            data: b"dark=true",
        }];
        let input = PackageInput {
            app_id: "tools.editor",
            display_name: "Editor",
            version: "2.0.1",
            kind: AppKind::Command,
            executable: b"elf bytes",
            assets: &assets,
        };
        let first = encode_package(&input).unwrap();
        let second = encode_package(&input).unwrap();
        assert_eq!(first, second);
        let parsed = Package::parse(&first).unwrap();
        assert_eq!(parsed.kind, AppKind::Command);
        assert_eq!(parsed.assets().next().unwrap().data, b"dark=true");
    }

    #[test]
    fn rejects_unsafe_and_duplicate_asset_names() {
        for path in [
            "../secret",
            "/absolute",
            "a//b",
            "a/./b",
            "a/../b",
            "a\\b",
            "C:evil",
        ] {
            let bytes = encoded_package("safe.app", "Safe", "1.0.0", b"elf", &[(path, b"x")]);
            assert!(matches!(
                Package::parse(&bytes),
                Err(PackageError::InvalidAssetPath { index: 0 })
            ));
        }
        let bytes = encoded_package(
            "safe.app",
            "Safe",
            "1.0.0",
            b"elf",
            &[("same.txt", b"one"), ("same.txt", b"two")],
        );
        assert!(matches!(
            Package::parse(&bytes),
            Err(PackageError::DuplicateAsset {
                first_index: 0,
                duplicate_index: 1
            })
        ));
    }

    #[test]
    fn rejects_unknown_flags_counts_sizes_and_boundaries() {
        let valid = package("safe.app", "1.0.0", b"elf");

        let mut unknown_header = valid.clone();
        unknown_header[6] = 1;
        assert!(matches!(
            Package::parse(&unknown_header),
            Err(PackageError::UnknownHeaderFlags(1))
        ));

        let mut too_many_assets = valid.clone();
        too_many_assets[10..12].copy_from_slice(&((MAX_ASSET_COUNT + 1) as u16).to_le_bytes());
        assert!(matches!(
            Package::parse(&too_many_assets),
            Err(PackageError::TooManyAssets { .. })
        ));

        let mut oversized_executable = valid.clone();
        oversized_executable[20..24]
            .copy_from_slice(&((MAX_EXECUTABLE_LEN + 1) as u32).to_le_bytes());
        assert!(matches!(
            Package::parse(&oversized_executable),
            Err(PackageError::ExecutableTooLarge { .. })
        ));

        for length in 0..valid.len() {
            assert!(
                Package::parse(&valid[..length]).is_err(),
                "accepted {length} bytes"
            );
        }
        let mut trailing = valid;
        trailing.push(0);
        assert_eq!(Package::parse(&trailing), Err(PackageError::TrailingData));

        let mut unknown_asset =
            encoded_package("safe.app", "Safe", "1.0.0", b"elf", &[("seed.txt", b"x")]);
        let asset_header =
            PACKAGE_HEADER_SIZE + "safe.app".len() + "Safe".len() + "1.0.0".len() + 3;
        unknown_asset[asset_header + 2] = 1;
        assert!(matches!(
            Package::parse(&unknown_asset),
            Err(PackageError::UnknownAssetFlags { index: 0, bits: 1 })
        ));
    }

    fn generation(app_id: &str, byte: u8, length: usize) -> ExecutableGeneration {
        ExecutableGeneration::new(app_id, [byte; 32], length as u64).unwrap()
    }

    #[test]
    fn registry_install_update_uninstall_round_trip() {
        let alpha_bytes = package("alpha.app", "1.0.0", b"alpha");
        let zeta_bytes = package("zeta.app", "1.0.0", b"zeta");
        let alpha = Package::parse(&alpha_bytes).unwrap();
        let zeta = Package::parse(&zeta_bytes).unwrap();
        let mut registry = InstalledRegistry::new();
        registry
            .install(
                &zeta,
                generation(zeta.app_id, 2, 4),
                Provenance {
                    package_digest: [12; 32],
                },
                &[],
            )
            .unwrap();
        registry
            .install(
                &alpha,
                generation(alpha.app_id, 1, 5),
                Provenance {
                    package_digest: [11; 32],
                },
                &[],
            )
            .unwrap();
        assert_eq!(
            registry
                .entries()
                .iter()
                .map(|entry| entry.app_id.as_str())
                .collect::<Vec<_>>(),
            ["alpha.app", "zeta.app"]
        );

        let encoded = registry.encode();
        assert_eq!(InstalledRegistry::parse(&encoded).unwrap(), registry);
        assert_eq!(registry.encode(), encoded);

        let update_bytes = package("alpha.app", "2.0.0", b"new-alpha");
        let update = Package::parse(&update_bytes).unwrap();
        registry
            .update(
                &update,
                generation(update.app_id, 3, 9),
                Provenance {
                    package_digest: [13; 32],
                },
                &[],
            )
            .unwrap();
        let installed = registry.get("alpha.app").unwrap();
        assert_eq!(installed.version, "2.0.0");
        assert_eq!(installed.executable.digest, [3; 32]);
        assert_eq!(installed.provenance.package_digest, [13; 32]);

        let removed = registry.remove("alpha.app", &[]).unwrap();
        assert_eq!(removed.app_id, "alpha.app");
        assert!(registry.get("alpha.app").is_none());
    }

    #[test]
    fn failed_registry_operations_are_atomic_and_reserve_system_ids() {
        let bytes = package("user.app", "1.0.0", b"elf");
        let parsed = Package::parse(&bytes).unwrap();
        let mut registry = InstalledRegistry::new();
        registry
            .install(
                &parsed,
                generation(parsed.app_id, 1, 3),
                Provenance {
                    package_digest: [2; 32],
                },
                &["desktop"],
            )
            .unwrap();

        let before = registry.encode();
        assert_eq!(
            registry.install(
                &parsed,
                generation(parsed.app_id, 1, 3),
                Provenance {
                    package_digest: [2; 32]
                },
                &[]
            ),
            Err(MutationError::AlreadyInstalled)
        );
        assert_eq!(registry.encode(), before);

        assert!(matches!(
            registry.update(
                &parsed,
                generation(parsed.app_id, 9, 99),
                Provenance {
                    package_digest: [3; 32]
                },
                &[]
            ),
            Err(MutationError::ExecutableLengthMismatch { .. })
        ));
        assert_eq!(registry.encode(), before);

        assert_eq!(
            registry.remove("missing.app", &[]),
            Err(MutationError::NotInstalled)
        );
        assert_eq!(registry.encode(), before);

        let system_bytes = package("desktop", "1.0.0", b"elf");
        let system = Package::parse(&system_bytes).unwrap();
        assert_eq!(
            registry.install(
                &system,
                generation(system.app_id, 4, 3),
                Provenance {
                    package_digest: [5; 32]
                },
                &["desktop"]
            ),
            Err(MutationError::ReservedSystemId)
        );
        assert_eq!(
            registry.remove("desktop", &["desktop"]),
            Err(MutationError::ReservedSystemId)
        );
        assert_eq!(registry.encode(), before);
    }

    #[test]
    fn registry_parser_rejects_unknown_flags_truncation_and_trailing_data() {
        let bytes = package("user.app", "1.0.0", b"elf");
        let parsed = Package::parse(&bytes).unwrap();
        let mut registry = InstalledRegistry::new();
        registry
            .install(
                &parsed,
                generation(parsed.app_id, 1, 3),
                Provenance {
                    package_digest: [2; 32],
                },
                &[],
            )
            .unwrap();
        let encoded = registry.encode();

        let mut flags = encoded.clone();
        flags[6] = 1;
        assert_eq!(
            InstalledRegistry::parse(&flags),
            Err(RegistryError::UnknownHeaderFlags(1))
        );
        for length in 0..encoded.len() {
            assert!(InstalledRegistry::parse(&encoded[..length]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            InstalledRegistry::parse(&trailing),
            Err(RegistryError::TrailingData)
        );
    }
}
