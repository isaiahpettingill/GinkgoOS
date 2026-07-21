//! Tiny freestanding memory routines that LLVM may emit calls to.

use core::{
    cmp::Ordering,
    ffi::{c_int, c_void},
    ptr,
};

#[no_mangle]
pub unsafe extern "C" fn memset(
    destination: *mut c_void,
    value: c_int,
    count: usize,
) -> *mut c_void {
    let bytes = destination.cast::<u8>();
    for offset in 0..count {
        ptr::write_volatile(bytes.add(offset), value as u8);
    }
    destination
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    memmove(destination, source, count)
}

#[no_mangle]
pub unsafe extern "C" fn memmove(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    let destination_bytes = destination.cast::<u8>();
    let source_bytes = source.cast::<u8>();
    match (destination as usize).cmp(&(source as usize)) {
        Ordering::Less => {
            for offset in 0..count {
                ptr::write_volatile(
                    destination_bytes.add(offset),
                    ptr::read_volatile(source_bytes.add(offset)),
                );
            }
        }
        Ordering::Greater => {
            for offset in (0..count).rev() {
                ptr::write_volatile(
                    destination_bytes.add(offset),
                    ptr::read_volatile(source_bytes.add(offset)),
                );
            }
        }
        Ordering::Equal => {}
    }
    destination
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(left: *const c_void, right: *const c_void, count: usize) -> c_int {
    let left = left.cast::<u8>();
    let right = right.cast::<u8>();
    for offset in 0..count {
        let left_byte = ptr::read_volatile(left.add(offset));
        let right_byte = ptr::read_volatile(right.add(offset));
        if left_byte != right_byte {
            return c_int::from(left_byte) - c_int::from(right_byte);
        }
    }
    0
}
