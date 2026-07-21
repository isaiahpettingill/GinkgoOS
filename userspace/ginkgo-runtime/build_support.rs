use std::{env, path::PathBuf};

/// Configures one userspace binary to use the shared fixed-address ELF layout.
pub fn configure_binary(binary_name: &str) {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let linker_script = manifest.join("../ginkgo-runtime/linker.ld");
    println!("cargo:rerun-if-changed={}", linker_script.display());
    println!(
        "cargo:rustc-link-arg-bin={binary_name}=-T{}",
        linker_script.display()
    );
}
