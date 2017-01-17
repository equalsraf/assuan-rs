use std::ffi;

extern crate libc;

#[cfg(unix)]
pub fn get_ttyname() -> Option<String> {
    let c_str = unsafe { 
        ffi::CStr::from_ptr(libc::ttyname(0)) 
    };
    c_str.to_str()
        .ok()
        .map(|v| v.to_owned())
}

#[cfg(unix)]
pub fn getuid() -> libc::uid_t {
    unsafe { libc::getuid() }
}
