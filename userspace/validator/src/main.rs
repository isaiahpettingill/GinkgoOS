#![allow(dead_code)]

#[path = "../../../crates/ginkgo-kernel/src/elf.rs"]
mod elf;

use std::{env, fs, process};

const USER_STACK_TOP: u64 = 0x0000_7fff_ffff_f000;
const USER_STACK_SIZE: u64 = 64 * 1024;
const PAGE_SIZE: u64 = 4096;
const USER_STACK_GUARD_START: u64 = USER_STACK_TOP - USER_STACK_SIZE - PAGE_SIZE;

fn main() {
    let paths: Vec<_> = env::args_os().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: validate-ginkgo-userspace-elf <path>...");
        process::exit(2);
    }

    let mut rejected = false;
    for path in paths {
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("{}: read failed: {error}", path.to_string_lossy());
                rejected = true;
                continue;
            }
        };
        match elf::parse(&bytes) {
            Ok(image) => {
                let overlaps_stack = image
                    .overlaps_reserved_range(
                        USER_STACK_GUARD_START,
                        USER_STACK_TOP - USER_STACK_GUARD_START,
                    )
                    .expect("kernel stack range is valid");
                if overlaps_stack {
                    eprintln!("{}: rejected: overlaps user stack or guard", path.to_string_lossy());
                    rejected = true;
                } else {
                    println!(
                        "{}: accepted: entry={:#x}, load_segments={}, load_pages={}, bytes={}",
                        path.to_string_lossy(),
                        image.entry(),
                        image.segment_count(),
                        image.total_load_pages(),
                        bytes.len()
                    );
                }
            }
            Err(error) => {
                eprintln!("{}: rejected: {error:?}", path.to_string_lossy());
                rejected = true;
            }
        }
    }

    if rejected {
        process::exit(1);
    }
}
