//! C ABI for crypto, codec, tunnels, and single-peer client endpoints. See `include/covert.h`.
//!
//! # Safety
//! All non-null pointers must be aligned, valid for their documented size and
//! lifetime, and have the indicated type. Handles must originate here and be
//! freed exactly once. Calls involving a handle must be externally serialized.
//! Output locations must be writable and must not alias inputs or each other.
//! Never pass a live output buffer/handle as an output slot: free it first.
//! Null byte pointers are allowed only with zero length; null PSKs mean no PSK.
//! Panics are caught, but do not protect against invalid pointers or aborts.
#![allow(clippy::missing_safety_doc)]

use crate::crypto::Key;
use crate::{Error, Result};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
};

pub const OK: i32 = 0;
pub const EMPTY: i32 = 1;
pub const INVALID: i32 = -1;
pub const FAILED: i32 = -2;
pub const PANIC: i32 = -3;

#[repr(C)]
pub struct Buffer {
    pub data: *mut u8,
    pub len: usize,
}

fn guard(f: impl FnOnce() -> Result) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => OK,
        Ok(Err(Error::Empty)) => EMPTY,
        Ok(Err(Error::InvalidArgument(_))) => INVALID,
        Ok(Err(_)) => FAILED,
        Err(_) => PANIC,
    }
}
unsafe fn get<'a, T>(p: *const T) -> Result<&'a T> {
    unsafe { p.as_ref() }.ok_or(Error::InvalidArgument("invalid FFI argument"))
}
unsafe fn get_mut<'a, T>(p: *mut T) -> Result<&'a mut T> {
    unsafe { p.as_mut() }.ok_or(Error::InvalidArgument("invalid FFI argument"))
}
unsafe fn bytes<'a>(p: *const u8, n: usize) -> Result<&'a [u8]> {
    if n == 0 {
        return Ok(&[]);
    }
    if p.is_null() || n > isize::MAX as usize {
        return Err(Error::InvalidArgument("invalid FFI argument"));
    }
    Ok(unsafe { slice::from_raw_parts(p, n) })
}
unsafe fn key(p: *const u8) -> Result<Key> {
    Ok(unsafe { bytes(p, 32)? }.try_into().unwrap())
}
unsafe fn psk(p: *const u8) -> Result<Option<Key>> {
    if p.is_null() {
        Ok(None)
    } else {
        Ok(Some(unsafe { key(p)? }))
    }
}
fn output(out: &mut Buffer, data: Vec<u8>) {
    let data = data.into_boxed_slice();
    out.len = data.len();
    out.data = Box::into_raw(data).cast::<u8>();
}
macro_rules! free_handle {
    ($name:ident, $ty:ty) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(p: *mut $ty) -> i32 {
            guard(|| {
                if !p.is_null() {
                    unsafe {
                        drop(Box::from_raw(p));
                    }
                }
                Ok(())
            })
        }
    };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn covert_buffer_free(p: *mut Buffer) -> i32 {
    guard(|| {
        let p = unsafe { get_mut(p)? };
        if !p.data.is_null() {
            unsafe {
                drop(Box::from_raw(ptr::slice_from_raw_parts_mut(p.data, p.len)));
            }
        }
        p.data = ptr::null_mut();
        p.len = 0;
        Ok(())
    })
}

mod codec;
mod config;
mod crypto;
mod endpoint;
mod tunnel;
pub use codec::*;
pub use config::*;
pub use crypto::*;
pub use endpoint::*;
pub use tunnel::*;

/// Increment for incompatible changes to the public C ABI.
#[unsafe(no_mangle)]
pub extern "C" fn covert_abi_version() -> u32 {
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_errors_preserve_the_c_status_contract() {
        assert_eq!(guard(|| Ok(())), OK);
        assert_eq!(guard(|| Err(Error::Empty)), EMPTY);
        assert_eq!(guard(|| Err(Error::InvalidArgument("bad input"))), INVALID);
        assert_eq!(guard(|| Err(Error::MalformedDatagram)), FAILED);
        assert_eq!(
            guard(|| Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into())),
            FAILED
        );
        assert_eq!(guard(|| panic!("caught at C boundary")), PANIC);
    }
}
