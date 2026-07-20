//! Tiny freestanding memory routines that LLVM may emit calls to.

use core::{cmp::Ordering, ffi::c_int, ptr};

#[no_mangle]
pub unsafe extern "C" fn memset(destination: *mut u8, value: c_int, count: usize) -> *mut u8 {
    for offset in 0..count {
        ptr::write_volatile(destination.add(offset), value as u8);
    }
    destination
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(
    destination: *mut u8,
    source: *const u8,
    count: usize,
) -> *mut u8 {
    memmove(destination, source, count)
}

#[no_mangle]
pub unsafe extern "C" fn memmove(
    destination: *mut u8,
    source: *const u8,
    count: usize,
) -> *mut u8 {
    match (destination as usize).cmp(&(source as usize)) {
        Ordering::Less => {
            for offset in 0..count {
                ptr::write_volatile(destination.add(offset), ptr::read_volatile(source.add(offset)));
            }
        }
        Ordering::Greater => {
            for offset in (0..count).rev() {
                ptr::write_volatile(destination.add(offset), ptr::read_volatile(source.add(offset)));
            }
        }
        Ordering::Equal => {}
    }
    destination
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, count: usize) -> c_int {
    for offset in 0..count {
        let left_byte = ptr::read_volatile(left.add(offset));
        let right_byte = ptr::read_volatile(right.add(offset));
        if left_byte != right_byte {
            return c_int::from(left_byte) - c_int::from(right_byte);
        }
    }
    0
}
