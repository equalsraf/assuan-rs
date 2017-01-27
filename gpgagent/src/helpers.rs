use std::ffi;
use std::ptr::null_mut;

extern crate libc;

#[cfg(unix)]
pub fn get_ttyname() -> Option<String> {
    let ptr = unsafe { libc::ttyname(0) };
    if ptr == null_mut() {
        return None;
    }

    let c_str = unsafe { ffi::CStr::from_ptr(ptr) };
    c_str.to_str()
        .ok()
        .map(|v| v.to_owned())
}

#[cfg(unix)]
pub fn getuid() -> libc::uid_t {
    unsafe { libc::getuid() }
}
