// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(unix)]
pub use vmm_sys_util::{errno, tempdir, tempfile, terminal};
#[cfg(target_os = "linux")]
pub use vmm_sys_util::{eventfd, ioctl};

pub mod byte_order;
#[cfg(unix)]
pub mod fd;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::epoll;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::epoll;
#[cfg(target_os = "macos")]
pub use macos::eventfd;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::epoll;
#[cfg(target_os = "windows")]
pub use windows::eventfd;
pub mod pollable_channel;
#[cfg(target_arch = "x86_64")]
pub mod rand;
#[cfg(target_os = "linux")]
pub mod signal;
pub mod sized_vec;
pub mod sm;
pub mod syscall;
pub mod time;
pub mod worker_message;
