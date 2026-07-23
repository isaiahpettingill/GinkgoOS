#[path = "../ginkgo-runtime/build_support.rs"]
mod build_support;

fn main() {
    println!("cargo:rerun-if-env-changed=GINKGO_TEXT_EDITOR_SMOKE");
    build_support::configure_binary("ginkgo-text-editor");
}
