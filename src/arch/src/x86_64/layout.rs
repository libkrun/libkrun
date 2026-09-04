// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Magic addresses externally used to lay out x86_64 VMs.

/// Initial stack for the boot CPU.
pub const BOOT_STACK_POINTER: u64 = 0x8ff0;

/// Kernel command line start address.
pub const CMDLINE_START: u64 = 0x20000;
/// Kernel command line start address maximum size.
pub const CMDLINE_MAX_SIZE: usize = 0x10000;
/// Kernel command line static size on SEV.
pub const CMDLINE_SEV_SIZE: usize = 0x200;
/// Initrd start address on SEV.
pub const INITRD_SEV_START: u64 = 0xa00000;

/// Start of the high memory.
pub const HIMEM_START: u64 = 0x0010_0000; //1 MB.

// The I/O APIC has 24 pins (0-23). ISA IRQs 0-4 are reserved for
// legacy devices, leaving GSIs 5-23 for virtio-mmio devices.
/// First usable IRQ ID for virtio device interrupts on x86_64.
pub const IRQ_BASE: u32 = 5;
/// Last usable IRQ ID for virtio device interrupts on x86_64.
pub const IRQ_MAX: u32 = 23;

/// Address for the TSS setup.
pub const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;

/// Address of the hvm_start_info struct used in PVH boot.
/// Mutually exclusive with SNP_CPUID_START (TEE only).
pub const PVH_INFO_START: u64 = 0x6000;

/// Starting address of array of modules of hvm_modlist_entry type.
/// Used to enable initrd support using the PVH boot ABI.
pub const MODLIST_START: u64 = 0x6040;

/// Address of memory map table used in PVH boot. Can overlap
/// with the zero page address since they are mutually exclusive.
pub const MEMMAP_START: u64 = 0x7000;

/// Location of RSDP pointer in x86 machines.
pub const RSDP_ADDR: u64 = 0x000e_0000;

/// The 'zero page', a.k.a linux kernel bootparams.
pub const ZERO_PAGE_START: u64 = 0x7000;

/// SNP: space for the initial LIDT
pub const SNP_LIDT_START: u64 = 0x0;
/// SNP: Secrets page.
pub const SNP_SECRETS_START: u64 = 0x5000;
/// SNP: CPUID page
pub const SNP_CPUID_START: u64 = 0x6000;
/// SNP: FW stack and initial page tables
pub const SNP_FWDATA_START: u64 = 0x8000;
pub const SNP_FWDATA_SIZE: usize = 0x7000;

// Where BIOS/VGA magic would live on a real PC.
pub const EBDA_START: u64 = 0x9fc00;

/// Where the PC register will point after a reset.
#[cfg(not(feature = "tdx"))]
pub const RESET_VECTOR: u64 = 0xfff0;
#[cfg(feature = "tdx")]
pub const RESET_VECTOR: u64 = 0xffff_fff0;
pub const RESET_VECTOR_SEV_AP: u64 = 0xfff3;

/// Address of the AP idle trampoline (`cli; hlt; jmp` loop) used during
/// SMP boot on WHP. APs park here in real mode until the BSP sends
/// INIT + SIPI through the emulated local APIC.
#[cfg(target_os = "windows")]
pub const AP_TRAMPOLINE_START: u64 = 0x1000;

/// The address to load the firmware, if present.
pub const FIRMWARE_START: u64 = 0xffff_0000;

/// The size of the firmware.
pub const FIRMWARE_SIZE: u64 = 65536;

/// The start of the memory area reserved for MMIO devices.
pub const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
pub const MEM_32BIT_GAP_SIZE: u64 = 768 << 20;
pub const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;
