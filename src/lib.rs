#![allow(unsafe_op_in_unsafe_fn)]

use std::{
    collections::HashMap,
    ffi::{CString, c_void},
};

#[repr(C)]
pub enum QueueType {
    None,
}

#[repr(C)]
pub struct Pair {
    name: CString,
    value: CString,
}

struct Queue {}

/// # Safety
/// * `params` is well defined pointer to an array of `params_len` items of [`Pair`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn new_queue(params: *const Pair, params_len: i32) -> *mut c_void {
    assert!(params_len > 0, "params_len must be positive");

    let params = unsafe { std::slice::from_raw_parts(params, params_len as usize) };
    let _param_map = params
        .iter()
        .map(|p| {
            p.name
                .to_str()
                .and_then(|k| p.value.to_str().map(|v| (k, v)))
        })
        .collect::<Result<HashMap<&str, &str>, _>>()
        .expect("params contain a non UTF-8 string");

    let queue = Box::new(Queue {});
    Box::into_raw(queue).cast()
}

pub extern "C" fn push_queue(_queue: *mut c_void) {}

/// # Safety
/// * `queue` is the queue created by the `new_queue` function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_queue(queue: *mut c_void) {
    let queue = Box::from_raw(queue.cast::<Queue>());
    drop(queue)
}
