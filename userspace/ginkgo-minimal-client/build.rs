#[path = "../ginkgo-runtime/build_support.rs"]
mod build_support;

fn main() {
    build_support::configure_binary("ginkgo-minimal-client");
}
