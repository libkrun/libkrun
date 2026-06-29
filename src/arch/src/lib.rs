// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements platform specific functionality.
//! Supported platforms: x86_64 and aarch64.

use std::result;

#[derive(Default)]
pub struct ArchMemoryInfo {
    #[cfg(target_arch = "x86_64")]
    pub ram_below_gap: u64,
    #[cfg(target_arch = "x86_64")]
    pub ram_above_gap: u64,
    #[cfg(target_arch = "aarch64")]
    pub ram_start_addr: u64,
    pub ram_last_addr: u64,
    pub shm_start_addr: u64,
    pub guest_last_addr: u64,
    pub page_size: usize,
    #[cfg(target_arch = "aarch64")]
    pub fdt_addr: u64,
    pub initrd_addr: u64,
    pub firmware_addr: u64,
    #[cfg(target_os = "macos")]
    pub ipa_size: u32,
}

/// Module for aarch64 related functionality.
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    Error, MMIO_MEM_START, arch_memory_regions, configure_system, layout::CMDLINE_MAX_SIZE,
    layout::IRQ_BASE, layout::IRQ_MAX, layout::RESET_VECTOR,
};

/// Module for riscv64 related functionality.
#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[cfg(target_arch = "riscv64")]
pub use riscv64::{
    Error, MMIO_MEM_START, arch_memory_regions, configure_system, layout::CMDLINE_MAX_SIZE,
    layout::IRQ_BASE, layout::IRQ_MAX, layout::RESET_VECTOR,
};

/// Module for x86_64 related functionality.
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use crate::x86_64::{
    Error, arch_memory_regions, configure_system, layout::CMDLINE_MAX_SIZE, layout::FIRMWARE_SIZE,
    layout::FIRMWARE_START, layout::IRQ_BASE, layout::IRQ_MAX, layout::MMIO_MEM_START,
    layout::RESET_VECTOR,
};

/// Type for returning public functions outcome.
pub type Result<T> = result::Result<T, Error>;

/// Type for passing information about the initrd in the guest memory.
pub struct InitrdConfig {
    /// Load address of initrd in guest memory
    pub address: vm_memory::GuestAddress,
    /// Size of initrd in guest memory
    pub size: usize,
}

/// Default (smallest) memory page size for the supported architectures.
pub const PAGE_SIZE: usize = 4096;
