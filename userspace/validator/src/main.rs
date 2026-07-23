#![allow(dead_code)]

#[path = "../../../crates/ginkgo-kernel/src/elf.rs"]
mod elf;

use std::{env, fs, process};

const USER_STACK_TOP: u64 = 0x0000_7fff_ffff_f000;
const USER_STACK_MAX_SIZE: u64 = 8 * 1024 * 1024;
const PAGE_SIZE: u64 = 4096;
const STACK_ASLR_ALIGNMENT: u64 = 2 * 1024 * 1024;
const STACK_ASLR_SLOTS: u64 = 1024;
const STACK_ASLR_MAX_DISPLACEMENT: u64 = checked_mul(STACK_ASLR_SLOTS - 1, STACK_ASLR_ALIGNMENT);
const RANDOMIZED_STACK_UNION_START: u64 = checked_sub(
    checked_sub(USER_STACK_TOP, STACK_ASLR_MAX_DISPLACEMENT),
    checked_add(USER_STACK_MAX_SIZE, PAGE_SIZE),
);
const RANDOMIZED_STACK_UNION_LENGTH: u64 =
    checked_sub(USER_STACK_TOP, RANDOMIZED_STACK_UNION_START);

const fn checked_add(left: u64, right: u64) -> u64 {
    match left.checked_add(right) {
        Some(value) => value,
        None => panic!("validator stack policy addition overflow"),
    }
}

const fn checked_sub(left: u64, right: u64) -> u64 {
    match left.checked_sub(right) {
        Some(value) => value,
        None => panic!("validator stack policy subtraction underflow"),
    }
}

const fn checked_mul(left: u64, right: u64) -> u64 {
    match left.checked_mul(right) {
        Some(value) => value,
        None => panic!("validator stack policy multiplication overflow"),
    }
}

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
                        RANDOMIZED_STACK_UNION_START,
                        RANDOMIZED_STACK_UNION_LENGTH,
                    )
                    .expect("kernel stack range is valid");
                if overlaps_stack {
                    eprintln!(
                        "{}: rejected: overlaps a randomized user stack reservation or guard",
                        path.to_string_lossy()
                    );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn randomized_stack_union_contains_every_slot_reservation_and_guard() {
        assert!(USER_STACK_MAX_SIZE + PAGE_SIZE >= STACK_ASLR_ALIGNMENT);
        for slot in 0..STACK_ASLR_SLOTS {
            let displacement = checked_mul(slot, STACK_ASLR_ALIGNMENT);
            let stack_top = checked_sub(USER_STACK_TOP, displacement);
            let reservation_start =
                checked_sub(stack_top, checked_add(USER_STACK_MAX_SIZE, PAGE_SIZE));
            assert!(RANDOMIZED_STACK_UNION_START <= reservation_start);
            assert!(stack_top <= USER_STACK_TOP);
        }
    }

    #[test]
    fn randomized_stack_union_endpoints_match_extreme_slots() {
        let lowest_top = checked_sub(USER_STACK_TOP, STACK_ASLR_MAX_DISPLACEMENT);
        assert_eq!(
            RANDOMIZED_STACK_UNION_START,
            checked_sub(lowest_top, checked_add(USER_STACK_MAX_SIZE, PAGE_SIZE))
        );
        assert_eq!(
            checked_add(RANDOMIZED_STACK_UNION_START, RANDOMIZED_STACK_UNION_LENGTH),
            USER_STACK_TOP
        );
    }
}
