// macOS-specific batch message syscalls (sendmsg_x/recvmsg_x)
//
// These are private Apple APIs that allow sending/receiving multiple messages
// in a single syscall, similar to Linux's sendmmsg/recvmmsg.
//
// Reference: https://github.com/nirs/vmnet-helper/blob/main/socket_x.h

#![allow(dead_code)]
#![allow(non_camel_case_types)]

#[cfg(target_os = "macos")]
pub mod macos {
    use libc::{c_int, c_uint, c_void, iovec, socklen_t};

    /// Extended message header for batch operations.
    /// Similar to msghdr but includes msg_datalen for output.
    #[repr(C)]
    pub struct msghdr_x {
        pub msg_name: *mut c_void,
        pub msg_namelen: socklen_t,
        pub msg_iov: *mut iovec,
        pub msg_iovlen: c_int,
        pub msg_control: *mut c_void,
        pub msg_controllen: socklen_t,
        pub msg_flags: c_int,
        pub msg_datalen: usize, // out: bytes transferred for this message
    }

    impl Default for msghdr_x {
        fn default() -> Self {
            Self {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: std::ptr::null_mut(),
                msg_iovlen: 0,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
                msg_datalen: 0,
            }
        }
    }

    unsafe extern "C" {
        /// Send multiple datagrams in a single syscall.
        ///
        /// # Arguments
        /// * `s` - Socket file descriptor
        /// * `msgp` - Pointer to array of msghdr_x structures
        /// * `cnt` - Number of messages to send
        /// * `flags` - Only MSG_DONTWAIT is supported
        ///
        /// # Constraints
        /// For each msghdr_x: msg_name, msg_namelen, msg_control, msg_controllen,
        /// msg_flags, and msg_datalen must all be zero on input.
        ///
        /// # Returns
        /// Number of datagrams sent, or -1 on error.
        /// Each msghdr_x.msg_datalen is set to bytes sent for that message.
        pub fn sendmsg_x(s: c_int, msgp: *const msghdr_x, cnt: c_uint, flags: c_int) -> isize;

        /// Receive multiple datagrams in a single syscall.
        ///
        /// # Arguments
        /// * `s` - Socket file descriptor
        /// * `msgp` - Pointer to array of msghdr_x structures
        /// * `cnt` - Maximum number of messages to receive
        /// * `flags` - Only MSG_DONTWAIT is supported
        ///
        /// # Constraints
        /// For each msghdr_x: msg_flags must be zero on input.
        ///
        /// # Returns
        /// Number of datagrams received (may be less than cnt), or -1 on error.
        /// Each msghdr_x.msg_datalen is set to bytes received for that message.
        pub fn recvmsg_x(s: c_int, msgp: *mut msghdr_x, cnt: c_uint, flags: c_int) -> isize;
    }
}

#[cfg(target_os = "macos")]
pub use macos::*;
