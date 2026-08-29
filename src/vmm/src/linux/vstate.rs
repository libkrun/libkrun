// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#[cfg(target_arch = "aarch64")]
use arch::ArchMemoryInfo;
use crossbeam_channel::{Receiver, Sender, TryRecvError, unbounded};
use libc::{c_int, c_void, siginfo_t};
use std::cell::Cell;
use std::fmt::{Display, Formatter};
use std::io;
use std::ops::Range;

// x86_64: the kvmclock ioctl below; aarch64: duplicating the vGIC device fd
// for the snapshot path.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use std::os::fd::AsRawFd;
#[cfg(target_arch = "aarch64")]
use std::os::fd::FromRawFd;
use std::os::unix::io::RawFd;

#[cfg(target_arch = "x86_64")]
use std::env;
use std::result;
#[cfg(not(test))]
use std::sync::Barrier;
use std::sync::atomic::{Ordering, fence};
use std::thread;
#[cfg(target_arch = "x86_64")]
use std::time::Duration;

use super::super::{FC_EXIT_CODE_GENERIC_ERROR, FC_EXIT_CODE_OK};

#[cfg(feature = "amd-sev")]
use super::tee::amdsnp::{AmdSnp, Error as SnpError};

#[cfg(feature = "tdx")]
use super::tee::inteltdx::{Error as TdxError, IntelTdx};

#[cfg(feature = "tee")]
use kbs_types::Tee;

#[cfg(feature = "tee")]
use crate::resources::TeeConfig;
use crate::vmm_config::machine_config::CpuFeaturesTemplate;
#[cfg(target_arch = "x86_64")]
use cpuid::{VmSpec, c3, filter_cpuid, t2};
#[cfg(not(feature = "tee"))]
use kvm_bindings::kvm_userspace_memory_region;
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{
    CpuId, KVM_CLOCK_TSC_STABLE, KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE,
    KVM_MAX_CPUID_ENTRIES, MsrList, Msrs, kvm_clock_data, kvm_debugregs, kvm_irqchip,
    kvm_lapic_state, kvm_mp_state, kvm_pit_state2, kvm_regs, kvm_sregs, kvm_vcpu_events, kvm_xcrs,
    kvm_xsave,
};
use kvm_bindings::{KVM_API_VERSION, KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN};
#[cfg(feature = "tee")]
use kvm_bindings::{KVM_CAP_EXIT_HYPERCALL, KVM_MEMORY_EXIT_FLAG_PRIVATE, kvm_enable_cap};
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{
    KVM_CLOCK_HOST_TSC, KVM_CLOCK_REALTIME, KVM_VCPU_TSC_CTRL, KVM_VCPU_TSC_OFFSET, KVMIO,
    kvm_device_attr,
};
#[cfg(all(feature = "tee", target_arch = "x86_64"))]
use kvm_bindings::{
    KVM_MEM_GUEST_MEMFD, KVM_MEMORY_ATTRIBUTE_PRIVATE, kvm_create_guest_memfd,
    kvm_memory_attributes, kvm_userspace_memory_region2,
};
#[cfg(target_arch = "aarch64")]
use kvm_bindings::{KVM_REG_SIZE_MASK, KVM_REG_SIZE_SHIFT, RegList, kvm_mp_state};
use kvm_ioctls::{Cap::*, *};
use utils::eventfd::EventFd;
use utils::signal::{Killable, register_signal_handler, sigrtmin};
use utils::sm::StateMachine;
#[cfg(feature = "tee")]
use utils::worker_message::{MemoryProperties, WorkerMessage};
use vm_memory::{
    Address, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion,
    GuestRegionMmap,
};
#[cfg(target_arch = "x86_64")]
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};

#[cfg(target_arch = "x86_64")]
vmm_sys_util::ioctl_iow_nr!(KVM_GET_VCPU_DEVICE_ATTR, KVMIO, 0xe2, kvm_device_attr);
#[cfg(target_arch = "x86_64")]
vmm_sys_util::ioctl_iow_nr!(KVM_SET_VCPU_DEVICE_ATTR, KVMIO, 0xe1, kvm_device_attr);

#[cfg(feature = "amd-sev")]
use super::tee::amdsnp::launch as snp;

/// Signal number (SIGRTMIN) used to kick Vcpus.
pub(crate) const VCPU_RTSIG_OFFSET: i32 = 0;

#[cfg(target_arch = "x86_64")]
const KVM_KVMCLOCK_CTRL: libc::c_ulong = 0xAEAD;

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug)]
pub enum Error {
    #[cfg(target_arch = "x86_64")]
    /// A call to cpuid instruction failed.
    CpuId(cpuid::Error),
    /// Unable to create a KVM guest_memfd.
    CreateGuestMemfd(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the floating point related registers
    FPUConfiguration(arch::x86_64::regs::Error),
    /// Invalid guest memory configuration.
    GuestMemoryMmap(GuestMemoryError),
    #[cfg(target_arch = "x86_64")]
    /// Retrieving supported guest MSRs fails.
    GuestMSRs(arch::x86_64::msr::Error),
    /// Hyperthreading flag is not initialized.
    HTNotInitialized,
    /// Unable to enable KVM hypercall exits.
    #[cfg(feature = "tee")]
    HypercallExitEnable(kvm_ioctls::Error),
    /// Cannot configure the IRQ.
    Irq(kvm_ioctls::Error),
    /// Cannot open /dev/kvm (KVM unavailable, or inaccessible to this process).
    KvmOpen(kvm_ioctls::Error),
    /// The host kernel reports an invalid KVM API version.
    KvmApiVersion(i32),
    /// Cannot initialize the KVM context due to missing capabilities.
    KvmCap(kvm_ioctls::Cap),
    #[cfg(feature = "amd-sev")]
    /// Cannot read the CPUID entries from KVM.
    KvmCpuId(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Cannot set the local interruption due to bad configuration.
    LocalIntConfiguration(arch::x86_64::interrupts::Error),
    #[cfg(feature = "tee")]
    /// Missing TEE config
    MissingTeeConfig,
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the MSR registers
    MSRSConfiguration(arch::x86_64::msr::Error),
    /// The number of configured slots is bigger than the maximum reported by KVM.
    NotEnoughMemorySlots,
    #[cfg(target_arch = "aarch64")]
    /// Error configuring the general purpose aarch64 registers.
    REGSConfiguration(arch::aarch64::regs::Error),
    #[cfg(target_arch = "riscv64")]
    /// Error configuring the general purpose riscv64 registers.
    REGSConfiguration(arch::riscv64::regs::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the general purpose registers
    REGSConfiguration(arch::x86_64::regs::Error),
    /// Cannot set memory region attributes.
    SetMemoryAttributes(kvm_ioctls::Error),
    /// Cannot set the memory regions.
    SetUserMemoryRegion(kvm_ioctls::Error),
    /// Error creating memory map for SHM region.
    ShmMmap(io::Error),
    #[cfg(feature = "amd-sev")]
    /// Error initializing the Secure Virtualization Backend (SNP).
    SnpSecVirtInit(SnpError),
    #[cfg(feature = "amd-sev")]
    /// Error preparing the VM for Secure Virtualization (SNP).
    SnpSecVirtPrepare(SnpError),
    #[cfg(feature = "amd-sev")]
    /// Error attesting the Secure VM (SNP).
    SnpSecVirtAttest(SnpError),
    #[cfg(feature = "tdx")]
    /// Error preparing the VM for Trust Domain Extensions (TDX)
    TdxSecVirtPrepare(TdxError),
    #[cfg(feature = "tdx")]
    /// Error initializing vCPU for Trust Domain Extensions (TDX)
    TdxSecVirtInitVcpu,
    #[cfg(feature = "tee")]
    /// The TEE specified is not supported.
    InvalidTee,
    /// Failed to signal Vcpu.
    SignalVcpu(utils::errno::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the special registers
    SREGSConfiguration(arch::x86_64::regs::Error),
    #[cfg(target_arch = "aarch64")]
    /// Error doing Vcpu Init on Arm.
    VcpuArmInit(kvm_ioctls::Error),
    #[cfg(target_arch = "aarch64")]
    /// Error getting the Vcpu preferred target on Arm.
    VcpuArmPreferredTarget(kvm_ioctls::Error),
    /// vCPU count is not initialized.
    VcpuCountNotInitialized,
    /// Cannot open the VCPU file descriptor.
    VcpuFd(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu debug regs.
    VcpuGetDebugRegs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu lapic.
    VcpuGetLapic(kvm_ioctls::Error),
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    /// Failed to get KVM vcpu mp state.
    VcpuGetMpState(kvm_ioctls::Error),
    #[cfg(target_arch = "aarch64")]
    /// Failed to enumerate the KVM vcpu register list.
    VcpuGetRegList(kvm_ioctls::Error),
    #[cfg(target_arch = "aarch64")]
    /// Failed to get a KVM vcpu register (reg id, error).
    VcpuGetOneReg(u64, kvm_ioctls::Error),
    #[cfg(target_arch = "aarch64")]
    /// Failed to set a KVM vcpu register (reg id, error).
    VcpuSetOneReg(u64, kvm_ioctls::Error),
    #[cfg(target_arch = "aarch64")]
    /// Failed to capture or restore the in-kernel vGIC state.
    VmGicState(String),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu msrs.
    VcpuGetMsrs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu regs.
    VcpuGetRegs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu sregs.
    VcpuGetSregs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu event.
    VcpuGetVcpuEvents(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu xcrs.
    VcpuGetXcrs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu xsave.
    VcpuGetXsave(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get the virtual TSC frequency.
    VcpuGetTscKhz(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get the virtual TSC offset used for live migration.
    VcpuGetTscOffset(io::Error),
    /// Cannot run the VCPUs.
    VcpuRun(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu cpuid.
    VcpuSetCpuid(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu debug regs.
    VcpuSetDebugRegs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu lapic.
    VcpuSetLapic(kvm_ioctls::Error),
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    /// Failed to set KVM vcpu mp state.
    VcpuSetMpState(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu msrs.
    VcpuSetMsrs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// KVM accepted only a prefix of the checkpoint's MSR state.
    VcpuSetMsrsIncomplete { expected: usize, actual: usize },
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu regs.
    VcpuSetRegs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu sregs.
    VcpuSetSregs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu event.
    VcpuSetVcpuEvents(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu xcrs.
    VcpuSetXcrs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu xsave.
    VcpuSetXsave(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to restore the source virtual TSC frequency.
    VcpuSetTscKhz(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to restore the rebased virtual TSC offset.
    VcpuSetTscOffset(io::Error),
    #[cfg(target_arch = "x86_64")]
    /// Host KVM did not expose the clock data needed for portable migration.
    VmClockMigration(String),
    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(io::Error),
    /// Cannot cleanly initialize vcpu TLS.
    VcpuTlsInit,
    /// Vcpu not present in TLS.
    VcpuTlsNotPresent,
    /// Unexpected KVM_RUN exit reason
    VcpuUnhandledKvmExit,
    /// Failed to notify KVM that vCPU time was paused.
    VcpuKvmClockCtrl(io::Error),
    /// Unsupported KVM_EXIT_HYPERCALL.
    #[cfg(feature = "tee")]
    VcpuUnsupportedHypercall,
    /// Cannot open the VM file descriptor.
    VmFd(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vm pit state.
    VmGetPit2(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vm clock.
    VmGetClock(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vm irqchip.
    VmGetIrqChip(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vm pit state.
    VmSetPit2(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vm clock.
    VmSetClock(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vm irqchip.
    VmSetIrqChip(kvm_ioctls::Error),
    /// Cannot configure the microvm.
    VmSetup(kvm_ioctls::Error),
    /// Failed to enable split IRQCHIP in vm
    VmSplitIrqchip(kvm_ioctls::Error),
    /// Failed to set vm APIC bus clock rate (in nanoseconds)
    VmApicBusClockRate(kvm_ioctls::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            #[cfg(target_arch = "x86_64")]
            CpuId(e) => write!(f, "Cpuid error: {e:?}"),
            CreateGuestMemfd(e) => write!(f, "Unable to create KVM guest_memfd: {e:?}"),
            GuestMemoryMmap(e) => write!(f, "Guest memory error: {e:?}"),
            #[cfg(target_arch = "x86_64")]
            GuestMSRs(e) => write!(f, "Retrieving supported guest MSRs fails: {e:?}"),
            HTNotInitialized => write!(f, "Hyperthreading flag is not initialized"),
            #[cfg(feature = "tee")]
            HypercallExitEnable(e) => write!(f, "Unable to enable KVM hypercall exits: {e}"),
            KvmOpen(e) => write!(
                f,
                "Cannot open /dev/kvm: {e} (KVM unavailable, or inaccessible to \
                 this process — check the kvm module is loaded and /dev/kvm's \
                 group/permissions grant access)"
            ),
            KvmApiVersion(v) => {
                write!(f, "The host kernel reports an invalid KVM API version: {v}")
            }
            KvmCap(cap) => write!(f, "Missing KVM capabilities: {cap:?}"),
            #[cfg(feature = "amd-sev")]
            KvmCpuId(e) => write!(f, "Cannot read CPUID entries from KVM: {e}"),
            VcpuCountNotInitialized => write!(f, "vCPU count is not initialized"),
            VmFd(e) => write!(f, "Cannot open the VM file descriptor: {e}"),
            VcpuFd(e) => write!(f, "Cannot open the VCPU file descriptor: {e}"),
            VmSetup(e) => write!(f, "Cannot configure the microvm: {e}"),
            VmSplitIrqchip(e) => write!(f, "Failed to enable split IRQCHIP: {e}"),
            VmApicBusClockRate(e) => write!(
                f,
                "Failed to set vm APIC bus clock rate (in nanoseconds): {e}"
            ),
            VcpuRun(e) => write!(f, "Cannot run the VCPUs: {e}"),
            NotEnoughMemorySlots => write!(
                f,
                "The number of configured slots is bigger than the maximum reported by KVM"
            ),
            #[cfg(target_arch = "x86_64")]
            LocalIntConfiguration(e) => write!(
                f,
                "Cannot set the local interruption due to bad configuration: {e:?}"
            ),
            SetMemoryAttributes(e) => write!(f, "Cannot set memory region attributes: {e}"),
            SetUserMemoryRegion(e) => write!(f, "Cannot set the memory regions: {e}"),
            ShmMmap(e) => write!(f, "Error creating memory map for SHM region: {e}"),
            #[cfg(feature = "amd-sev")]
            SnpSecVirtInit(e) => write!(
                f,
                "Error initializing the Secure Virtualization Backend (SEV): {e:?}"
            ),

            #[cfg(feature = "amd-sev")]
            SnpSecVirtPrepare(e) => write!(
                f,
                "Error preparing the VM for Secure Virtualization (SNP): {e:?}"
            ),

            #[cfg(feature = "amd-sev")]
            SnpSecVirtAttest(e) => write!(f, "Error attesting the Secure VM (SNP): {e:?}"),

            SignalVcpu(e) => write!(f, "Failed to signal Vcpu: {e}"),
            #[cfg(feature = "tdx")]
            TdxSecVirtPrepare(e) => write!(
                f,
                "Error preparing the VM for Trust Domain Extensions (TDX): {e:?}"
            ),
            #[cfg(feature = "tdx")]
            TdxSecVirtInitVcpu => write!(
                f,
                "Error initializing vCPU for Trust Domain Extensions (TDX)"
            ),
            #[cfg(feature = "tee")]
            MissingTeeConfig => write!(f, "Missing TEE configuration"),
            #[cfg(target_arch = "x86_64")]
            MSRSConfiguration(e) => write!(f, "Error configuring the MSR registers: {e:?}"),
            #[cfg(target_arch = "aarch64")]
            REGSConfiguration(e) => write!(
                f,
                "Error configuring the general purpose aarch64 registers: {e:?}"
            ),
            #[cfg(target_arch = "riscv64")]
            REGSConfiguration(e) => write!(
                f,
                "Error configuring the general purpose riscv64 registers: {e:?}"
            ),
            #[cfg(target_arch = "x86_64")]
            REGSConfiguration(e) => {
                write!(f, "Error configuring the general purpose registers: {e:?}")
            }
            #[cfg(target_arch = "x86_64")]
            SREGSConfiguration(e) => write!(f, "Error configuring the special registers: {e:?}"),
            #[cfg(target_arch = "x86_64")]
            FPUConfiguration(e) => write!(
                f,
                "Error configuring the floating point related registers: {e:?}"
            ),
            Irq(e) => write!(f, "Cannot configure the IRQ: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuGetDebugRegs(e) => write!(f, "Failed to get KVM vcpu debug regs: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuGetLapic(e) => write!(f, "Failed to get KVM vcpu lapic: {e}"),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            VcpuGetMpState(e) => write!(f, "Failed to get KVM vcpu mp state: {e}"),
            #[cfg(target_arch = "aarch64")]
            VcpuGetRegList(e) => write!(f, "Failed to get KVM vcpu register list: {e}"),
            #[cfg(target_arch = "aarch64")]
            VcpuGetOneReg(id, e) => write!(f, "Failed to get KVM vcpu register {id:#x}: {e}"),
            #[cfg(target_arch = "aarch64")]
            VcpuSetOneReg(id, e) => write!(f, "Failed to set KVM vcpu register {id:#x}: {e}"),
            #[cfg(target_arch = "aarch64")]
            VmGicState(e) => write!(f, "vGIC state transfer failed: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuGetMsrs(e) => write!(f, "Failed to get KVM vcpu msrs: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuGetRegs(e) => write!(f, "Failed to get KVM vcpu regs: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuGetSregs(e) => write!(f, "Failed to get KVM vcpu sregs: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuGetVcpuEvents(e) => write!(f, "Failed to get KVM vcpu event: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuGetXcrs(e) => write!(f, "Failed to get KVM vcpu xcrs: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuGetXsave(e) => write!(f, "Failed to get KVM vcpu xsave: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuGetTscKhz(e) => write!(f, "Failed to get KVM vcpu TSC frequency: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuGetTscOffset(e) => write!(f, "Failed to get KVM vcpu TSC offset: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetCpuid(e) => write!(f, "Failed to set KVM vcpu cpuid: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetDebugRegs(e) => write!(f, "Failed to set KVM vcpu debug regs: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetLapic(e) => write!(f, "Failed to set KVM vcpu lapic: {e}"),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            VcpuSetMpState(e) => write!(f, "Failed to set KVM vcpu mp state: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetMsrs(e) => write!(f, "Failed to set KVM vcpu msrs: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetMsrsIncomplete { expected, actual } => write!(
                f,
                "KVM restored only {actual} of {expected} checkpoint MSRs"
            ),
            #[cfg(target_arch = "x86_64")]
            VcpuSetRegs(e) => write!(f, "Failed to set KVM vcpu regs: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetSregs(e) => write!(f, "Failed to set KVM vcpu sregs: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetVcpuEvents(e) => write!(f, "Failed to set KVM vcpu event: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetXcrs(e) => write!(f, "Failed to set KVM vcpu xcrs: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetXsave(e) => write!(f, "Failed to set KVM vcpu xsave: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetTscKhz(e) => write!(f, "Failed to set KVM vcpu TSC frequency: {e}"),
            #[cfg(target_arch = "x86_64")]
            VcpuSetTscOffset(e) => write!(f, "Failed to set KVM vcpu TSC offset: {e}"),
            #[cfg(target_arch = "x86_64")]
            VmClockMigration(e) => write!(f, "KVM live-migration clock state is unavailable: {e}"),
            VcpuSpawn(e) => write!(f, "Cannot spawn a new vCPU thread: {e}"),
            VcpuTlsInit => write!(f, "Cannot clean init vcpu TLS"),
            VcpuTlsNotPresent => write!(f, "Vcpu not present in TLS"),
            VcpuUnhandledKvmExit => write!(f, "Unexpected KVM_RUN exit reason"),
            VcpuKvmClockCtrl(e) => write!(f, "Failed to adjust KVM vCPU clock: {e}"),
            #[cfg(feature = "tee")]
            VcpuUnsupportedHypercall => write!(f, "Unsupported KVM_EXIT_HYPERCALL"),
            #[cfg(target_arch = "x86_64")]
            VmGetPit2(e) => write!(f, "Failed to get KVM vm pit state: {e}"),
            #[cfg(target_arch = "x86_64")]
            VmGetClock(e) => write!(f, "Failed to get KVM vm clock: {e}"),
            #[cfg(target_arch = "x86_64")]
            VmGetIrqChip(e) => write!(f, "Failed to get KVM vm irqchip: {e}"),
            #[cfg(target_arch = "x86_64")]
            VmSetPit2(e) => write!(f, "Failed to set KVM vm pit state: {e}"),
            #[cfg(target_arch = "x86_64")]
            VmSetClock(e) => write!(f, "Failed to set KVM vm clock: {e}"),
            #[cfg(target_arch = "x86_64")]
            VmSetIrqChip(e) => write!(f, "Failed to set KVM vm irqchip: {e}"),
            #[cfg(target_arch = "aarch64")]
            VcpuArmPreferredTarget(e) => {
                write!(f, "Error getting the Vcpu preferred target on Arm: {e}")
            }
            #[cfg(target_arch = "aarch64")]
            VcpuArmInit(e) => write!(f, "Error doing Vcpu Init on Arm: {e}"),

            #[cfg(feature = "tee")]
            InvalidTee => write!(f, "TEE selected is not currently supported"),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

#[cfg(feature = "tee")]
#[derive(Debug)]
pub struct MeasuredRegion {
    pub guest_addr: u64,
    pub host_addr: u64,
    pub size: usize,
}

/// Describes a KVM context that gets attached to the microVM.
/// It gives access to the functionality of the KVM wrapper as
/// long as every required KVM capability is present on the host.
pub struct KvmContext {
    kvm: Kvm,
    max_memslots: usize,
}

impl KvmContext {
    pub fn new() -> Result<Self> {
        // Propagate rather than `.expect()`: a /dev/kvm open failure is recoverable
        // (KVM absent, or no access after a privilege drop), and unwinding it here
        // aborts the VMM — which, under seccomp, dies silently instead of surfacing
        // the error `KvmContext::new` is typed to return.
        let kvm = Kvm::new().map_err(Error::KvmOpen)?;

        // Check that KVM has the correct version.
        if kvm.get_api_version() != KVM_API_VERSION as i32 {
            return Err(Error::KvmApiVersion(kvm.get_api_version()));
        }

        // A list of KVM capabilities we want to check.
        #[cfg(target_arch = "x86_64")]
        let capabilities = [Irqchip, Ioeventfd, Irqfd, UserMemory, SetTssAddr];

        #[cfg(target_arch = "aarch64")]
        let capabilities = [Irqchip, Ioeventfd, Irqfd, UserMemory, ArmPsci02];

        #[cfg(target_arch = "riscv64")]
        let capabilities = [Irqchip, Ioeventfd, Irqfd, UserMemory];

        // Check that all desired capabilities are supported.
        match capabilities
            .iter()
            .find(|&capability| !kvm.check_extension(*capability))
        {
            None => {
                let max_memslots = kvm.get_nr_memslots();
                Ok(KvmContext { kvm, max_memslots })
            }

            Some(c) => Err(Error::KvmCap(*c)),
        }
    }

    pub fn fd(&self) -> &Kvm {
        &self.kvm
    }

    /// Get the maximum number of memory slots reported by this KVM context.
    pub fn max_memslots(&self) -> usize {
        self.max_memslots
    }
}

/// A wrapper around creating and using a VM.
pub struct Vm {
    fd: VmFd,
    next_mem_slot: u32,

    // X86 specific fields.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    supported_cpuid: CpuId,
    #[cfg(target_arch = "x86_64")]
    supported_msrs: MsrList,

    #[cfg(feature = "amd-sev")]
    tee: Option<AmdSnp>,

    #[cfg(feature = "tdx")]
    tdx: Option<IntelTdx>,

    #[cfg(feature = "tee")]
    pub tee_config: Tee,

    pub guest_memfds: Vec<(Range<u64>, RawFd)>,

    /// Handle onto the in-kernel vGICv3 for checkpoint/restore (registered by
    /// the builder after the GIC device and vCPUs exist). `None` on GICv2
    /// hosts, where snapshots degrade to a warning (fork clones would not
    /// receive device IRQs).
    #[cfg(target_arch = "aarch64")]
    vgic: Option<VgicSnapshotHandle>,
}

/// The pieces needed to capture/restore the in-kernel vGIC state: a dup of
/// the GIC `DeviceFd` (attribute ioctls) plus the per-CPU addressing the
/// device's flavor uses — GICv3 addresses per-CPU state by MPIDR affinity,
/// GICv2 by vCPU index.
#[cfg(target_arch = "aarch64")]
pub struct VgicSnapshotHandle {
    fd: DeviceFd,
    flavor: VgicFlavor,
}

/// Which in-kernel GIC the snapshot handle drives, with its per-CPU keys.
#[cfg(target_arch = "aarch64")]
pub enum VgicFlavor {
    V3 { mpidrs: Vec<u64> },
    V2 { vcpu_count: u64 },
}

impl Vm {
    /// Constructs a new `Vm` using the given `Kvm` instance.
    #[cfg(not(feature = "tee"))]
    pub fn new(kvm: &Kvm) -> Result<Self> {
        //create fd for interacting with kvm-vm specific functions
        let vm_fd = kvm.create_vm().map_err(Error::VmFd)?;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let supported_cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::VmFd)?;
        #[cfg(target_arch = "x86_64")]
        let supported_msrs =
            arch::x86_64::msr::supported_guest_msrs(kvm).map_err(Error::GuestMSRs)?;

        Ok(Vm {
            fd: vm_fd,
            next_mem_slot: 0,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            supported_cpuid,
            #[cfg(target_arch = "x86_64")]
            supported_msrs,
            guest_memfds: Vec::new(),
            #[cfg(target_arch = "aarch64")]
            vgic: None,
        })
    }

    /// Register the in-kernel vGICv3 for checkpoint/restore. Called by the
    /// builder once the GIC device and the (configured) vCPUs exist; without
    /// a registered vGIC, `save_state` refuses the checkpoint.
    #[cfg(target_arch = "aarch64")]
    pub fn register_vgic(&mut self, gic_fd: &DeviceFd, mpidrs: Vec<u64>) {
        self.register_vgic_flavor(gic_fd, VgicFlavor::V3 { mpidrs });
    }

    /// Register the in-kernel vGICv2 for checkpoint/restore (the GICv3-less
    /// fallback). Per-CPU state is addressed by vCPU index, not MPIDR.
    #[cfg(target_arch = "aarch64")]
    pub fn register_vgic_v2(&mut self, gic_fd: &DeviceFd, vcpu_count: u64) {
        self.register_vgic_flavor(gic_fd, VgicFlavor::V2 { vcpu_count });
    }

    #[cfg(target_arch = "aarch64")]
    fn register_vgic_flavor(&mut self, gic_fd: &DeviceFd, flavor: VgicFlavor) {
        // Dup so the handle stays valid independent of the device object's
        // lifetime inside the IRQ-chip container.
        let fd = unsafe { libc::dup(gic_fd.as_raw_fd()) };
        if fd < 0 {
            warn!(
                "could not dup the vGIC device fd ({}); snapshots will not carry GIC state",
                io::Error::last_os_error()
            );
            return;
        }
        self.vgic = Some(VgicSnapshotHandle {
            fd: unsafe { DeviceFd::from_raw_fd(fd) },
            flavor,
        });
    }

    #[cfg(feature = "amd-sev")]
    pub fn new(kvm: &Kvm, tee_config: &TeeConfig) -> Result<Self> {
        //create fd for interacting with kvm-vm specific functions
        let vm_fd = kvm
            .create_vm_with_type(4 /* KVM_X86_SNP_VM */)
            .map_err(Error::VmFd)?;

        let supported_cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::VmFd)?;

        let supported_msrs =
            arch::x86_64::msr::supported_guest_msrs(kvm).map_err(Error::GuestMSRs)?;

        let cap = kvm_enable_cap {
            cap: KVM_CAP_EXIT_HYPERCALL,
            flags: 0,
            args: [1 << 12 /* KVM_HC_MAP_GPA_RANGE */, 0, 0, 0],
            ..Default::default()
        };

        vm_fd.enable_cap(&cap).map_err(Error::HypercallExitEnable)?;

        let tee = match tee_config.tee {
            Tee::Snp => Some(AmdSnp::new().map_err(Error::SnpSecVirtInit)?),
            _ => return Err(Error::InvalidTee),
        };

        Ok(Vm {
            fd: vm_fd,
            next_mem_slot: 0,
            supported_cpuid,
            supported_msrs,
            tee,
            tee_config: tee_config.tee,
            guest_memfds: Vec::new(),
        })
    }

    #[cfg(feature = "tdx")]
    pub fn new(
        kvm: &Kvm,
        tee_config: &TeeConfig,
        _sender: crossbeam_channel::Sender<WorkerMessage>,
    ) -> Result<Self> {
        // create fd for interacting with kvm-vm specific functions
        let vm_fd = kvm
            .create_vm_with_type(tdx::launch::KVM_X86_TDX_VM)
            .map_err(Error::VmFd)?;

        let supported_cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::VmFd)?;

        let supported_msrs =
            arch::x86_64::msr::supported_guest_msrs(kvm).map_err(Error::GuestMSRs)?;

        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_EXIT_HYPERCALL,
            flags: 0,
            args: [1 << 12 /* KVM_HC_MAP_GPA_RANGE */, 0, 0, 0],
            ..Default::default()
        };
        vm_fd.enable_cap(&cap).map_err(Error::HypercallExitEnable)?;

        cap.cap = kvm_bindings::KVM_CAP_SPLIT_IRQCHIP;
        cap.args[0] = 24;
        vm_fd.enable_cap(&cap).map_err(Error::VmSplitIrqchip)?;

        cap.cap = 237; // KVM_CAP_X86_APIC_BUS_CYCLES_NS
        cap.args[0] = 40;
        vm_fd.enable_cap(&cap).map_err(Error::VmApicBusClockRate)?;

        Ok(Vm {
            fd: vm_fd,
            next_mem_slot: 0,
            supported_cpuid,
            supported_msrs,
            tdx: Some(IntelTdx::new()),
            tee_config: tee_config.tee,
            guest_memfds: Vec::new(),
        })
    }

    /// Returns a ref to the supported `CpuId` for this Vm.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn supported_cpuid(&self) -> &CpuId {
        &self.supported_cpuid
    }

    /// Returns a ref to the supported `MsrList` for this Vm.
    #[cfg(target_arch = "x86_64")]
    pub fn supported_msrs(&self) -> &MsrList {
        &self.supported_msrs
    }

    /// Initializes the guest memory.
    pub fn memory_init(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        kvm_max_memslots: usize,
    ) -> Result<()> {
        if guest_mem.num_regions() > kvm_max_memslots {
            return Err(Error::NotEnoughMemorySlots);
        }

        for region in guest_mem.iter() {
            self.memory_region_set(guest_mem, region)?;
        }

        #[cfg(target_arch = "x86_64")]
        self.fd
            .set_tss_address(arch::x86_64::layout::KVM_TSS_ADDRESS as usize)
            .map_err(Error::VmSetup)?;

        Ok(())
    }

    pub fn guest_memfd_get(&self, gpa: u64) -> Option<(RawFd, u64)> {
        for (range, rawfd) in self.guest_memfds.iter() {
            if range.contains(&gpa) {
                return Some((*rawfd, range.start));
            }
        }
        None
    }

    // GuestMemfd is generally intended for either of two purposes:
    // * sharing the memory with out-of-process components, and conversely,
    // * hiding the memory completely from the VMM process (Confidential Computing).
    //
    // We only use it for the second use case currently, so don't even try to use it
    // outside of TEE builds. Software-protected VMs are only available on x86_64 and
    // are marked with strongly-worded warnings about them being for development only,
    // as of late 2025. Also, on other architectures like aarch64, guest_memfd in
    // general is unstable for now, so don't try to use it without a reason.

    #[cfg(not(feature = "tee"))]
    fn create_guest_physical_memory_slot(
        &mut self,
        host_addr: u64,
        start: u64,
        region: &GuestRegionMmap,
    ) -> Result<()> {
        let memory_region = kvm_userspace_memory_region {
            slot: self.next_mem_slot,
            guest_phys_addr: start,
            memory_size: region.len(),
            userspace_addr: host_addr,
            flags: 0,
        };

        // Safe because we mapped the memory region and ensured regions do not overlap.
        unsafe {
            self.fd
                .set_user_memory_region(memory_region)
                .map_err(Error::SetUserMemoryRegion)?;
        };

        Ok(())
    }

    #[cfg(all(feature = "tee", target_arch = "x86_64"))]
    fn create_guest_physical_memory_slot(
        &mut self,
        host_addr: u64,
        start: u64,
        region: &GuestRegionMmap,
    ) -> Result<()> {
        let end = start + region.len();

        if !self.fd.check_extension(GuestMemfd) {
            return Err(Error::KvmCap(GuestMemfd));
        }

        // GuestMemfd is only used for confidential-memory setups in TEE builds.
        let guest_memfd = self
            .fd
            .create_guest_memfd(kvm_create_guest_memfd {
                size: region.size() as u64,
                flags: 0,
                reserved: [0; 6],
            })
            .map_err(Error::CreateGuestMemfd)?;

        let memory_region = kvm_userspace_memory_region2 {
            slot: self.next_mem_slot,
            flags: KVM_MEM_GUEST_MEMFD,
            guest_phys_addr: start,
            memory_size: region.len(),
            userspace_addr: host_addr,
            guest_memfd_offset: 0,
            guest_memfd: guest_memfd as u32,
            pad1: 0,
            pad2: [0; 14],
        };

        // Safe because we mapped the memory region and ensured regions do not overlap.
        unsafe {
            self.fd
                .set_user_memory_region2(memory_region)
                .map_err(Error::SetUserMemoryRegion)?;
        };

        let attr = kvm_memory_attributes {
            address: start,
            size: region.len(),
            attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE as u64,
            flags: 0,
        };

        self.fd
            .set_memory_attributes(attr)
            .map_err(Error::SetMemoryAttributes)?;

        self.guest_memfds.push((Range { start, end }, guest_memfd));

        Ok(())
    }

    #[cfg(all(feature = "tee", not(target_arch = "x86_64")))]
    fn create_guest_physical_memory_slot(
        &mut self,
        _host_addr: u64,
        _start: u64,
        _region: &GuestRegionMmap,
    ) -> Result<()> {
        // TEE support should be rejected during VM setup on non-x86_64 targets.
        // Do not silently fall back to the non-TEE path here, because that would
        // ignore an invalid TEE configuration and create a normal VM instead.
        Err(Error::InvalidTee)
    }

    fn memory_region_set(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        region: &GuestRegionMmap,
    ) -> Result<()> {
        let host_addr = guest_mem.get_host_address(region.start_addr()).unwrap() as u64;
        let start = region.start_addr().raw_value();

        self.create_guest_physical_memory_slot(host_addr, start, region)?;

        self.next_mem_slot += 1;

        Ok(())
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_secure_virt_prepare(&self) -> Result<tdx::launch::Launcher> {
        match &self.tdx {
            Some(t) => t
                .vm_prepare(&self.fd, self.supported_cpuid.clone())
                .map_err(Error::TdxSecVirtPrepare),
            None => Err(Error::InvalidTee),
        }
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_secure_virt_init_vcpus(&self, launcher: &mut tdx::launch::Launcher) -> Result<()> {
        match &self.tdx {
            Some(_) => {
                launcher.init_vcpus(0).unwrap();
                Ok(())
            }
            None => Err(Error::InvalidTee),
        }
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_secure_virt_prepare_memory(
        &self,
        launcher: &mut tdx::launch::Launcher,
        regions: &Vec<crate::vstate::MeasuredRegion>,
    ) -> Result<()> {
        match &self.tdx {
            Some(t) => t
                .configure_td_memory(launcher, regions)
                .map_err(Error::TdxSecVirtPrepare),
            None => Err(Error::InvalidTee),
        }
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_secure_virt_finalize_vm(&self, launcher: tdx::launch::Launcher) -> Result<()> {
        match &self.tdx {
            Some(t) => t.finalize_vm(launcher).map_err(Error::TdxSecVirtPrepare),
            None => Err(Error::InvalidTee),
        }
    }

    #[cfg(feature = "amd-sev")]
    pub fn snp_secure_virt_prepare(
        &self,
        guest_mem: &GuestMemoryMmap,
    ) -> Result<snp::Launcher<snp::Started, RawFd, RawFd>> {
        match &self.tee {
            Some(s) => s
                .vm_prepare(&self.fd, guest_mem)
                .map_err(Error::SnpSecVirtPrepare),
            None => Err(Error::InvalidTee),
        }
    }

    #[cfg(feature = "amd-sev")]
    pub fn snp_secure_virt_measure(
        &self,
        cpuid: CpuId,
        guest_mem: &GuestMemoryMmap,
        measured_regions: Vec<MeasuredRegion>,
        launcher: snp::Launcher<snp::Started, RawFd, RawFd>,
    ) -> Result<()> {
        match &self.tee {
            Some(s) => s
                .vm_measure(cpuid, guest_mem, measured_regions, launcher)
                .map_err(Error::SnpSecVirtAttest),
            None => Err(Error::InvalidTee),
        }
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    pub fn fd(&self) -> &VmFd {
        &self.fd
    }

    pub fn adjust_clock_after_pause(&self, paused_ns: u64) -> Result<()> {
        if paused_ns == 0 {
            return Ok(());
        }

        #[cfg(target_arch = "x86_64")]
        {
            let mut clock = self.fd.get_clock().map_err(Error::VmGetClock)?;
            clock.clock = clock.clock.saturating_sub(paused_ns);
            clock.flags &= !KVM_CLOCK_TSC_STABLE;
            self.fd.set_clock(&clock).map_err(Error::VmSetClock)?;
        }

        Ok(())
    }

    #[allow(unused)]
    #[cfg(target_arch = "x86_64")]
    /// Saves and returns the Kvm Vm state.
    pub fn save_state(&self) -> Result<VmState> {
        let pitstate = self.fd.get_pit2().map_err(Error::VmGetPit2)?;

        let realtime_before = host_realtime_ns()?;
        let mut clock = self.fd.get_clock().map_err(Error::VmGetClock)?;
        let realtime_after = host_realtime_ns()?;
        if clock.flags & KVM_CLOCK_REALTIME == 0 {
            // KVM only publishes its atomic realtime sample while its master
            // clock is active. KVM_SET_CLOCK can temporarily disable that
            // mode, so a restored VM may otherwise become impossible to save
            // again. The VM is paused here; bracket KVM_GET_CLOCK with two
            // CLOCK_REALTIME reads and use their bounded midpoint.
            clock.realtime = bounded_realtime_midpoint(realtime_before, realtime_after)?;
            clock.flags |= KVM_CLOCK_REALTIME;
        }
        // This bit is not accepted in SET_CLOCK, clear it.
        clock.flags &= !KVM_CLOCK_TSC_STABLE;

        let mut pic_master = kvm_irqchip {
            chip_id: KVM_IRQCHIP_PIC_MASTER,
            ..Default::default()
        };
        self.fd
            .get_irqchip(&mut pic_master)
            .map_err(Error::VmGetIrqChip)?;

        let mut pic_slave = kvm_irqchip {
            chip_id: KVM_IRQCHIP_PIC_SLAVE,
            ..Default::default()
        };
        self.fd
            .get_irqchip(&mut pic_slave)
            .map_err(Error::VmGetIrqChip)?;

        let mut ioapic = kvm_irqchip {
            chip_id: KVM_IRQCHIP_IOAPIC,
            ..Default::default()
        };
        self.fd
            .get_irqchip(&mut ioapic)
            .map_err(Error::VmGetIrqChip)?;

        Ok(VmState {
            pitstate,
            clock,
            pic_master,
            pic_slave,
            ioapic,
        })
    }

    #[cfg(target_arch = "x86_64")]
    /// Refuse a portable checkpoint unless it carries the realtime anchor that
    /// KVM_SET_CLOCK needs to advance guest time while the VM is stopped.
    /// HOST_TSC enables the exact offset fast path but is optional: older KVM
    /// implementations and VMs restored with KVM_SET_CLOCK may omit it, in
    /// which case restore writes the saved absolute guest TSC instead.
    pub fn validate_migration_clock(
        &self,
        state: &VmState,
        vcpu_states: &[VcpuState],
    ) -> Result<()> {
        if !vcpu_states
            .iter()
            .any(|state| state.tsc_migration.is_some())
        {
            return Ok(());
        }
        validate_migration_clock_realtime(&state.clock, "source")
    }

    #[cfg(target_arch = "x86_64")]
    /// Rebase every saved vCPU TSC offset after the source kvmclock was applied
    /// to this destination VM. This is the KVM live-migration relationship:
    ///
    /// `ofs_dst = ofs_src - (guest_src - guest_dst) * freq + (tsc_src - tsc_dst)`
    ///
    /// where guest clock values are nanoseconds and `freq` is in kHz.
    pub fn rebase_vcpu_tsc(&self, source: &VmState, vcpu_states: &mut [VcpuState]) -> Result<()> {
        if !vcpu_states
            .iter()
            .any(|state| state.tsc_migration.is_some())
        {
            return Ok(());
        }

        validate_migration_clock_realtime(&source.clock, "source")?;
        let destination = self.fd.get_clock().map_err(Error::VmGetClock)?;
        let has_full_samples = source.clock.flags & KVM_CLOCK_HOST_TSC != 0
            && destination.flags & KVM_CLOCK_HOST_TSC != 0;

        for state in vcpu_states {
            if let Some(tsc) = &mut state.tsc_migration {
                if has_full_samples {
                    tsc.offset = rebased_tsc_offset(
                        tsc.offset,
                        tsc.khz,
                        source.clock.clock,
                        destination.clock,
                        source.clock.host_tsc,
                        destination.host_tsc,
                    );
                    tsc.apply_offset = true;
                } else {
                    let guest_delta_ns =
                        i128::from(destination.clock) - i128::from(source.clock.clock);
                    let tsc_entry = state
                        .msrs
                        .as_mut_slice()
                        .iter_mut()
                        .find(|entry| entry.index == 0x10)
                        .ok_or_else(|| {
                            Error::VmClockMigration(
                                "portable vCPU state is missing IA32_TSC".to_string(),
                            )
                        })?;
                    tsc_entry.data = advance_tsc(tsc_entry.data, guest_delta_ns, tsc.khz);
                    tsc.apply_offset = false;
                }
            }
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    /// Restore clock/TSC state for a same-host checkpoint or fork. Older and
    /// nested KVM implementations can provide a usable `KVM_GET_CLOCK` value
    /// while advertising neither `KVM_CLOCK_REALTIME` nor
    /// `KVM_CLOCK_HOST_TSC`. That is insufficient for portable migration, but
    /// it is sufficient on the same host: install the captured kvmclock, then
    /// advance the saved IA32_TSC by the observed guest-clock delta and let
    /// KVM derive its local TSC offset from the MSR write.
    pub fn rebase_vcpu_tsc_same_host(
        &self,
        source: &VmState,
        vcpu_states: &mut [VcpuState],
    ) -> Result<()> {
        if !vcpu_states
            .iter()
            .any(|state| state.tsc_migration.is_some())
        {
            return Ok(());
        }

        let destination = self.fd.get_clock().map_err(Error::VmGetClock)?;
        let has_full_samples = source.clock.flags & KVM_CLOCK_HOST_TSC != 0
            && destination.flags & KVM_CLOCK_HOST_TSC != 0;

        for state in vcpu_states {
            let Some(tsc) = &mut state.tsc_migration else {
                continue;
            };
            if has_full_samples {
                tsc.offset = rebased_tsc_offset(
                    tsc.offset,
                    tsc.khz,
                    source.clock.clock,
                    destination.clock,
                    source.clock.host_tsc,
                    destination.host_tsc,
                );
                tsc.apply_offset = true;
                continue;
            }

            let guest_delta_ns = i128::from(destination.clock) - i128::from(source.clock.clock);
            let tsc_entry = state
                .msrs
                .as_mut_slice()
                .iter_mut()
                .find(|entry| entry.index == 0x10)
                .ok_or_else(|| {
                    Error::VmClockMigration("same-host vCPU state is missing IA32_TSC".to_string())
                })?;
            tsc_entry.data = advance_tsc(tsc_entry.data, guest_delta_ns, tsc.khz);
            tsc.apply_offset = false;
        }
        Ok(())
    }

    #[allow(unused)]
    #[cfg(target_arch = "x86_64")]
    /// Restores the Kvm Vm state.
    pub fn restore_state(&self, state: &VmState) -> Result<()> {
        self.fd
            .set_pit2(&state.pitstate)
            .map_err(Error::VmSetPit2)?;
        self.fd.set_clock(&state.clock).map_err(Error::VmSetClock)?;
        self.fd
            .set_irqchip(&state.pic_master)
            .map_err(Error::VmSetIrqChip)?;
        self.fd
            .set_irqchip(&state.pic_slave)
            .map_err(Error::VmSetIrqChip)?;
        self.fd
            .set_irqchip(&state.ioapic)
            .map_err(Error::VmSetIrqChip)?;
        Ok(())
    }

    /// Saves the VM-level KVM state. On aarch64 that is the in-kernel vGICv3
    /// (KVM's arm equivalent of the x86 irqchip/PIT/clock capture): the
    /// distributor, per-CPU redistributor, and CPU-interface registers, read
    /// through the GIC device fd. Requires the vCPUs to be paused. Empty (with
    /// a warning) when no vGICv3 was registered — an in-place pause/resume
    /// does not need it, but a fork clone restored from such a checkpoint
    /// would never receive device IRQs.
    #[cfg(target_arch = "aarch64")]
    pub fn save_state(&self) -> Result<VmState> {
        match &self.vgic {
            Some(handle) => vgic::save(handle).map_err(Error::VmGicState),
            // Refuse rather than warn: an empty GIC blob produces a clone whose
            // freshly-created GIC has every interrupt masked, so the restored
            // guest is deaf — vsock kicks never interrupt it and the agent can
            // never answer (verified on a GICv2 QEMU host: the clone boots,
            // accepts socket connects, and times out readiness). Failing the
            // checkpoint here lets the fork roll back and the golden resume.
            None => Err(Error::VmGicState(
                "snapshot/fork requires an in-kernel vGIC handle; none was registered".to_string(),
            )),
        }
    }

    /// Restores VM-level state: replay the captured vGICv3 registers onto the
    /// clone's freshly-initialized GIC (`GICD_CTLR` written last so delivery
    /// only enables once the rest of the state is in place). No-op if empty.
    #[cfg(target_arch = "aarch64")]
    pub fn restore_state(&self, state: &VmState) -> Result<()> {
        if state.is_empty() {
            return Ok(());
        }
        match &self.vgic {
            Some(handle) => vgic::restore(handle, state).map_err(Error::VmGicState),
            None => {
                warn!("checkpoint carries GIC state but no vGIC is registered; skipping");
                Ok(())
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn validate_migration_clock_realtime(clock: &kvm_clock_data, host: &str) -> Result<()> {
    if clock.flags & KVM_CLOCK_REALTIME == 0 {
        return Err(Error::VmClockMigration(format!(
            "{host} KVM clock flags {:#x} do not include KVM_CLOCK_REALTIME",
            clock.flags
        )));
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn host_realtime_ns() -> Result<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            Error::VmClockMigration(format!(
                "host CLOCK_REALTIME precedes the Unix epoch: {error}"
            ))
        })?;
    u64::try_from(elapsed.as_nanos()).map_err(|_| {
        Error::VmClockMigration("host CLOCK_REALTIME does not fit in nanoseconds".to_string())
    })
}

#[cfg(target_arch = "x86_64")]
fn bounded_realtime_midpoint(before: u64, after: u64) -> Result<u64> {
    const MAX_SAMPLE_WINDOW_NS: u64 = 100_000_000;

    let window = after.checked_sub(before).ok_or_else(|| {
        Error::VmClockMigration(
            "host CLOCK_REALTIME moved backwards while sampling KVM clock; retry capture"
                .to_string(),
        )
    })?;
    if window > MAX_SAMPLE_WINDOW_NS {
        return Err(Error::VmClockMigration(format!(
            "host clock sampling took {window} ns; retry capture"
        )));
    }
    Ok(before + window / 2)
}

#[cfg(target_arch = "x86_64")]
fn rebased_tsc_offset(
    source_offset: u64,
    khz: u32,
    source_guest_ns: u64,
    destination_guest_ns: u64,
    source_host_tsc: u64,
    destination_host_tsc: u64,
) -> u64 {
    let guest_delta_ns = i128::from(source_guest_ns) - i128::from(destination_guest_ns);
    let guest_delta_ticks = guest_delta_ns * i128::from(khz) / 1_000_000;
    let guest_delta_ticks_mod = guest_delta_ticks.rem_euclid(1_i128 << 64) as u64;
    source_offset
        .wrapping_sub(guest_delta_ticks_mod)
        .wrapping_add(source_host_tsc.wrapping_sub(destination_host_tsc))
}

#[cfg(target_arch = "x86_64")]
fn advance_tsc(source_tsc: u64, guest_delta_ns: i128, khz: u32) -> u64 {
    let delta_ticks = guest_delta_ns * i128::from(khz) / 1_000_000;
    source_tsc.wrapping_add(delta_ticks.rem_euclid(1_i128 << 64) as u64)
}

#[cfg(target_arch = "x86_64")]
fn portable_msr_should_serialize(index: u32) -> bool {
    // PortableV1 masks MPX and Debug Store/LBR in CPUID. Their corresponding
    // MSRs are nevertheless present in KVM_GET_MSR_INDEX_LIST on some bare
    // metal hosts and absent from nested or newer KVM implementations. They
    // are not guest-visible under this CPU contract and must not leak into the
    // checkpoint's required restore state.
    !matches!(index, 0x0d90 | 0x01d9..=0x01de)
}

#[allow(unused)]
#[cfg(target_arch = "x86_64")]
/// Structure holding VM kvm state.
pub struct VmState {
    pitstate: kvm_pit_state2,
    clock: kvm_clock_data,
    pic_master: kvm_irqchip,
    pic_slave: kvm_irqchip,
    ioapic: kvm_irqchip,
}

/// VM-level state for an aarch64 checkpoint: the in-kernel vGICv3 registers.
/// Distributor entries are keyed by register byte offset; redistributor and
/// CPU-interface entries are keyed by the full KVM device-attribute id
/// (CPU affinity in bits 63:32, register offset/id in bits 31:0), so restore
/// is a direct replay.
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Debug, Default)]
pub struct VmState {
    dist_regs: Vec<(u32, u32)>,
    redist_regs: Vec<(u64, u32)>,
    icc_regs: Vec<(u64, u64)>,
    /// GICv2 distributor registers, keyed by the full device-attribute id
    /// (vCPU index in the cpuid field for banked SGI/PPI ranges, register byte
    /// offset in the low bits). Populated only for checkpoints taken on a
    /// GICv2 host; disjoint from the v3 fields above.
    gicv2_dist: Vec<(u64, u32)>,
    /// GICv2 CPU-interface (`GICC_*`) registers, keyed the same way.
    gicv2_cpu: Vec<(u64, u32)>,
}

/// In-kernel vGICv3 state transfer via `KVM_{GET,SET}_DEVICE_ATTR`, the KVM
/// device-attribute API (Documentation/virt/kvm/devices/arm-vgic-v3.rst).
/// Distributor registers are addressed by byte offset with 32-bit accesses
/// (64-bit registers such as `GICD_IROUTERn` read as two halves); per-CPU
/// state is addressed by packing the CPU's MPIDR affinity into attr[63:32].
#[cfg(target_arch = "aarch64")]
mod vgic {
    use super::{VgicSnapshotHandle, VmState};
    use kvm_bindings::{
        KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS, KVM_DEV_ARM_VGIC_GRP_CTRL,
        KVM_DEV_ARM_VGIC_GRP_DIST_REGS, KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
        KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES, kvm_device_attr,
    };
    use kvm_ioctls::DeviceFd;

    // Only the set-variants (IS*) of the enable/pending/active banks are
    // walked: KVM's uaccess semantics make an IS* write install the value and
    // an IC* write CLEAR the bits in the value — replaying a saved IC* mask
    // after its IS* twin would wipe the state just restored.
    const GICD_CTLR: u32 = 0x0000;
    const GICD_TYPER: u32 = 0x0004;
    const GICD_STATUSR: u32 = 0x0010;
    const GICD_IGROUPR: u32 = 0x0080;
    const GICD_ISENABLER: u32 = 0x0100;
    const GICD_ISPENDR: u32 = 0x0200;
    const GICD_ISACTIVER: u32 = 0x0300;
    const GICD_IPRIORITYR: u32 = 0x0400;
    const GICD_ICFGR: u32 = 0x0c00;
    const GICD_IROUTER: u32 = 0x6000;

    /// Redistributor offsets: RD_base frame, then the SGI_base frame at
    /// +0x10000 (per-CPU banked SGI/PPI configuration).
    const SGI_BASE: u32 = 0x10000;
    const REDIST_OFFSETS: [u32; 21] = [
        0x0000,           // GICR_CTLR
        0x0010,           // GICR_STATUSR
        0x0014,           // GICR_WAKER
        0x0070,           // GICR_PROPBASER (lo)
        0x0074,           // GICR_PROPBASER (hi)
        0x0078,           // GICR_PENDBASER (lo)
        0x007c,           // GICR_PENDBASER (hi)
        SGI_BASE + 0x080, // GICR_IGROUPR0
        SGI_BASE + 0x100, // GICR_ISENABLER0
        SGI_BASE + 0x200, // GICR_ISPENDR0
        SGI_BASE + 0x300, // GICR_ISACTIVER0
        SGI_BASE + 0x400, // GICR_IPRIORITYR0..7
        SGI_BASE + 0x404,
        SGI_BASE + 0x408,
        SGI_BASE + 0x40c,
        SGI_BASE + 0x410,
        SGI_BASE + 0x414,
        SGI_BASE + 0x418,
        SGI_BASE + 0x41c,
        SGI_BASE + 0xc00, // GICR_ICFGR0
        SGI_BASE + 0xc04, // GICR_ICFGR1
    ];

    /// CPU-interface sysreg id in the `KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS`
    /// encoding: op0 in bits 15:14, op1 13:11, CRn 10:7, CRm 6:3, op2 2:0.
    const fn icc(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
        (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
    }
    /// Restore replays in array order, so control/config registers come before
    /// masks and active-priority state.
    const ICC_REGS: [u64; 15] = [
        icc(3, 0, 12, 12, 5), // ICC_SRE_EL1
        icc(3, 0, 12, 12, 4), // ICC_CTLR_EL1
        icc(3, 0, 12, 12, 6), // ICC_IGRPEN0_EL1
        icc(3, 0, 12, 12, 7), // ICC_IGRPEN1_EL1
        icc(3, 0, 4, 6, 0),   // ICC_PMR_EL1
        icc(3, 0, 12, 8, 3),  // ICC_BPR0_EL1
        icc(3, 0, 12, 12, 3), // ICC_BPR1_EL1
        icc(3, 0, 12, 8, 4),  // ICC_AP0R0_EL1
        icc(3, 0, 12, 8, 5),  // ICC_AP0R1_EL1
        icc(3, 0, 12, 8, 6),  // ICC_AP0R2_EL1
        icc(3, 0, 12, 8, 7),  // ICC_AP0R3_EL1
        icc(3, 0, 12, 9, 0),  // ICC_AP1R0_EL1
        icc(3, 0, 12, 9, 1),  // ICC_AP1R1_EL1
        icc(3, 0, 12, 9, 2),  // ICC_AP1R2_EL1
        icc(3, 0, 12, 9, 3),  // ICC_AP1R3_EL1
    ];

    /// Whether `reg` is one of `ICC_AP0R1..3_EL1` / `ICC_AP1R1..3_EL1` — the
    /// higher active-priority registers that only exist with >5 (>6)
    /// implemented priority bits.
    const fn is_higher_aprn(reg: u64) -> bool {
        let crm = (reg >> 3) & 0xf;
        let op2 = reg & 0x7;
        (crm == 8 && op2 >= 5) || (crm == 9 && op2 >= 1 && op2 <= 3)
    }

    /// Pack a vCPU's MPIDR affinity fields into the device-attribute id's
    /// CPU-affinity field (bits 63:32): Aff3 (MPIDR bits 39:32) moves down to
    /// bits 31:24 next to Aff2..Aff0.
    fn affinity(mpidr: u64) -> u64 {
        (((mpidr & 0xff_0000_0000) >> 8) | (mpidr & 0x00ff_ffff)) << 32
    }

    fn get_reg<T: Copy + Default>(fd: &DeviceFd, group: u32, attr: u64) -> Result<T, String> {
        let mut val = T::default();
        let mut dev_attr = kvm_device_attr {
            group,
            attr,
            addr: &mut val as *mut T as u64,
            flags: 0,
        };
        // Safety: `dev_attr.addr` points at `val`, which lives until after the
        // ioctl returns and is exactly the size the attribute group writes.
        unsafe { fd.get_device_attr(&mut dev_attr) }
            .map_err(|e| format!("get GIC reg group={group} attr={attr:#x}: {e}"))?;
        Ok(val)
    }

    fn set_reg<T: Copy>(fd: &DeviceFd, group: u32, attr: u64, val: T) -> Result<(), String> {
        let dev_attr = kvm_device_attr {
            group,
            attr,
            addr: &val as *const T as u64,
            flags: 0,
        };
        fd.set_device_attr(&dev_attr)
            .map_err(|e| format!("set GIC reg group={group} attr={attr:#x}: {e}"))
    }

    fn has_reg(fd: &DeviceFd, group: u32, attr: u64) -> bool {
        let dev_attr = kvm_device_attr {
            group,
            attr,
            addr: 0,
            flags: 0,
        };
        fd.has_device_attr(&dev_attr).is_ok()
    }

    /// Distributor register offsets for `nr_irqs` interrupt IDs. SGIs/PPIs
    /// (IDs 0..31) are banked in the redistributor, so distributor per-IRQ
    /// ranges start at ID 32.
    fn dist_offsets(nr_irqs: u32) -> Vec<u32> {
        let mut offsets = vec![GICD_CTLR, GICD_STATUSR];
        for base in [GICD_IGROUPR, GICD_ISENABLER, GICD_ISPENDR, GICD_ISACTIVER] {
            for irq in (32..nr_irqs).step_by(32) {
                offsets.push(base + (irq / 32) * 4); // one bit per IRQ
            }
        }
        for irq in (32..nr_irqs).step_by(4) {
            offsets.push(GICD_IPRIORITYR + irq); // one byte per IRQ
        }
        for irq in (32..nr_irqs).step_by(16) {
            offsets.push(GICD_ICFGR + (irq / 16) * 4); // two bits per IRQ
        }
        for irq in 32..nr_irqs {
            // 64-bit affinity routing, accessed as two 32-bit halves.
            offsets.push(GICD_IROUTER + irq * 8);
            offsets.push(GICD_IROUTER + irq * 8 + 4);
        }
        offsets
    }

    pub(super) fn save(handle: &VgicSnapshotHandle) -> Result<VmState, String> {
        match &handle.flavor {
            super::VgicFlavor::V3 { mpidrs } => save_v3(&handle.fd, mpidrs),
            super::VgicFlavor::V2 { vcpu_count } => save_v2(&handle.fd, *vcpu_count),
        }
    }

    pub(super) fn restore(handle: &VgicSnapshotHandle, state: &VmState) -> Result<(), String> {
        // A checkpoint taken under one GIC flavor cannot replay onto the
        // other: the register namespaces are disjoint (v3 redistributor/sysreg
        // attrs vs v2 cpuid-banked distributor/GICC attrs), so a mismatch means
        // the checkpoint moved to a host with different interrupt hardware.
        let has_v3 = !state.dist_regs.is_empty()
            || !state.redist_regs.is_empty()
            || !state.icc_regs.is_empty();
        let has_v2 = !state.gicv2_dist.is_empty() || !state.gicv2_cpu.is_empty();
        match &handle.flavor {
            super::VgicFlavor::V3 { .. } if has_v2 => Err(
                "checkpoint was captured on a GICv2 host but this host uses a GICv3".to_string(),
            ),
            super::VgicFlavor::V2 { .. } if has_v3 => Err(
                "checkpoint was captured on a GICv3 host but this host uses a GICv2".to_string(),
            ),
            super::VgicFlavor::V3 { .. } => restore_v3(&handle.fd, state),
            super::VgicFlavor::V2 { .. } => restore_v2(&handle.fd, state),
        }
    }

    fn save_v3(fd: &DeviceFd, mpidrs: &[u64]) -> Result<VmState, String> {
        // Flush LPI pending state into guest RAM first. Without an ITS there
        // are no LPIs and some kernels reject the request — best-effort.
        let flush = kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES),
            addr: 0,
            flags: 0,
        };
        if let Err(e) = fd.set_device_attr(&flush) {
            debug!("vGIC SAVE_PENDING_TABLES not applied (no LPIs in use?): {e}");
        }

        // Size the register walk from the distributor's own view.
        let typer: u32 = get_reg(fd, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, GICD_TYPER as u64)?;
        let nr_irqs = 32 * ((typer & 0x1f) + 1);

        let mut dist_regs = Vec::new();
        for offset in dist_offsets(nr_irqs) {
            let val: u32 = get_reg(fd, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, offset as u64)?;
            dist_regs.push((offset, val));
        }

        let mut redist_regs = Vec::new();
        let mut icc_regs = Vec::new();
        for &mpidr in mpidrs {
            let aff = affinity(mpidr);
            for offset in REDIST_OFFSETS {
                let attr = aff | offset as u64;
                let val: u32 = get_reg(fd, KVM_DEV_ARM_VGIC_GRP_REDIST_REGS, attr)?;
                redist_regs.push((attr, val));
            }
            for reg in ICC_REGS {
                let attr = aff | reg;
                if !has_reg(fd, KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS, attr) {
                    continue;
                }
                match get_reg::<u64>(fd, KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS, attr) {
                    Ok(val) => icc_regs.push((attr, val)),
                    // The kernel lists AP<n>R1..3 as attributes but rejects
                    // access when the implemented priority bits don't
                    // materialize them — absent state, nothing to save.
                    Err(_) if is_higher_aprn(reg) => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(VmState {
            dist_regs,
            redist_regs,
            icc_regs,
            ..VmState::default()
        })
    }

    fn restore_v3(fd: &DeviceFd, state: &VmState) -> Result<(), String> {
        // Everything except GICD_CTLR first, so the distributor only starts
        // delivering once pending/enable/routing state is fully in place.
        let mut ctlr = None;
        for &(offset, val) in &state.dist_regs {
            if offset == GICD_CTLR {
                ctlr = Some(val);
                continue;
            }
            set_reg(fd, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, offset as u64, val)?;
        }
        for &(attr, val) in &state.redist_regs {
            set_reg(fd, KVM_DEV_ARM_VGIC_GRP_REDIST_REGS, attr, val)?;
        }
        for &(attr, val) in &state.icc_regs {
            set_reg(fd, KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS, attr, val)?;
        }
        if let Some(val) = ctlr {
            set_reg(fd, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, GICD_CTLR as u64, val)?;
        }
        Ok(())
    }

    // ---- GICv2 -------------------------------------------------------------
    //
    // v2's device-attribute API (Documentation/virt/kvm/devices/arm-vgic.rst)
    // shares KVM_DEV_ARM_VGIC_GRP_DIST_REGS with v3 but addresses per-CPU
    // (banked SGI/PPI) state by packing the vCPU INDEX into the attr's cpuid
    // field (bits 39:32) — there are no redistributors. The CPU interface is
    // the memory-mapped GICC frame, exposed through its own attribute group.
    // Like v3, only the set-variants (IS*) of enable/pending/active are
    // walked: KVM's uaccess write handlers keep set/clear semantics, so
    // replaying a saved IS* mask onto a reset (all-clear) GIC installs
    // exactly the saved bits.

    /// `KVM_DEV_ARM_VGIC_GRP_CPU_REGS`: the GICC frame's registers. Fixed
    /// UAPI value (arch/arm64/include/uapi/asm/kvm.h); spelled locally because
    /// kvm-bindings' generated name set varies by version.
    const KVM_DEV_ARM_VGIC_GRP_CPU_REGS: u32 = 2;
    /// v2 cpuid field: the vCPU index lives in attr bits 39:32.
    const VGIC_V2_CPUID_SHIFT: u64 = 32;

    /// Banked (per-CPU) distributor offsets covering SGIs/PPIs (INTIDs 0..31).
    /// Ordered so restore replays configuration before enables/pending/active.
    /// GICD_ICFGR0 (SGIs, always edge) and GICD_ITARGETSR0..7 (read-as-cpuid)
    /// are read-only and deliberately absent.
    const V2_BANKED_DIST_OFFSETS: [u32; 12] = [
        GICD_IGROUPR,    // IGROUPR0
        GICD_ICFGR + 4,  // ICFGR1 (PPIs)
        GICD_IPRIORITYR, // IPRIORITYR0..7
        GICD_IPRIORITYR + 4,
        GICD_IPRIORITYR + 8,
        GICD_IPRIORITYR + 12,
        GICD_IPRIORITYR + 16,
        GICD_IPRIORITYR + 20,
        GICD_IPRIORITYR + 24,
        GICD_ISENABLER, // ISENABLER0
        GICD_ISPENDR,   // ISPENDR0
        GICD_ISACTIVER, // ISACTIVER0
    ];

    /// GICv2 SPI target registers: one byte per INTID from GICD_ITARGETSR8
    /// (INTID 32) upward — v2's routing, in place of v3's GICD_IROUTERn.
    const GICD_ITARGETSR: u32 = 0x0800;

    /// GICC registers, in restore order: masks/priorities/config first,
    /// GICC_CTLR last so the interface only re-enables once its state stands.
    const V2_CPU_OFFSETS: [u32; 8] = [
        0x04, // GICC_PMR
        0x08, // GICC_BPR
        0x1c, // GICC_ABPR
        0xd0, // GICC_APR0
        0xd4, // GICC_APR1
        0xd8, // GICC_APR2
        0xdc, // GICC_APR3
        0x00, // GICC_CTLR (last)
    ];

    /// Shared (SPI) distributor offsets for `nr_irqs` INTIDs, configuration
    /// before set-state, matching the banked ordering above.
    fn v2_shared_dist_offsets(nr_irqs: u32) -> Vec<u32> {
        // No GICD_STATUSR here: that offset is GICv3-only (reserved on v2,
        // where the kernel's uaccess would reject it).
        let mut offsets = Vec::new();
        for irq in (32..nr_irqs).step_by(32) {
            offsets.push(GICD_IGROUPR + (irq / 32) * 4);
        }
        for irq in (32..nr_irqs).step_by(16) {
            offsets.push(GICD_ICFGR + (irq / 16) * 4);
        }
        for irq in (32..nr_irqs).step_by(4) {
            offsets.push(GICD_IPRIORITYR + irq);
        }
        for irq in (32..nr_irqs).step_by(4) {
            offsets.push(GICD_ITARGETSR + irq);
        }
        for base in [GICD_ISENABLER, GICD_ISPENDR, GICD_ISACTIVER] {
            for irq in (32..nr_irqs).step_by(32) {
                offsets.push(base + (irq / 32) * 4);
            }
        }
        offsets
    }

    fn save_v2(fd: &DeviceFd, vcpu_count: u64) -> Result<VmState, String> {
        let typer: u32 = get_reg(fd, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, GICD_TYPER as u64)?;
        let nr_irqs = 32 * ((typer & 0x1f) + 1);

        let mut gicv2_dist = Vec::new();
        // Banked SGI/PPI state per vCPU, then the shared SPI ranges (cpuid 0
        // in the attr — shared registers ignore it), then GICD_CTLR, which
        // restore replays last.
        for cpu in 0..vcpu_count {
            let aff = cpu << VGIC_V2_CPUID_SHIFT;
            for offset in V2_BANKED_DIST_OFFSETS {
                let attr = aff | offset as u64;
                let val: u32 = get_reg(fd, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, attr)?;
                gicv2_dist.push((attr, val));
            }
        }
        for offset in v2_shared_dist_offsets(nr_irqs) {
            let val: u32 = get_reg(fd, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, offset as u64)?;
            gicv2_dist.push((offset as u64, val));
        }
        let ctlr: u32 = get_reg(fd, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, GICD_CTLR as u64)?;
        gicv2_dist.push((GICD_CTLR as u64, ctlr));

        let mut gicv2_cpu = Vec::new();
        for cpu in 0..vcpu_count {
            let aff = cpu << VGIC_V2_CPUID_SHIFT;
            for offset in V2_CPU_OFFSETS {
                let attr = aff | offset as u64;
                let val: u32 = get_reg(fd, KVM_DEV_ARM_VGIC_GRP_CPU_REGS, attr)?;
                gicv2_cpu.push((attr, val));
            }
        }

        Ok(VmState {
            gicv2_dist,
            gicv2_cpu,
            ..VmState::default()
        })
    }

    fn restore_v2(fd: &DeviceFd, state: &VmState) -> Result<(), String> {
        // Everything except GICD_CTLR first (save appended it last, but keep
        // the guard explicit), so delivery only enables once routing, config,
        // and pending state are fully in place; the GICC frames follow, each
        // ending with its own GICC_CTLR per the saved ordering.
        let mut ctlr = None;
        for &(attr, val) in &state.gicv2_dist {
            if attr == GICD_CTLR as u64 {
                ctlr = Some(val);
                continue;
            }
            set_reg(fd, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, attr, val)?;
        }
        for &(attr, val) in &state.gicv2_cpu {
            set_reg(fd, KVM_DEV_ARM_VGIC_GRP_CPU_REGS, attr, val)?;
        }
        if let Some(val) = ctlr {
            set_reg(fd, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, GICD_CTLR as u64, val)?;
        }
        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
impl VmState {
    /// Whether the checkpoint carries no GIC state at all.
    fn is_empty(&self) -> bool {
        self.dist_regs.is_empty()
            && self.redist_regs.is_empty()
            && self.icc_regs.is_empty()
            && self.gicv2_dist.is_empty()
            && self.gicv2_cpu.is_empty()
    }

    /// Serialize to a byte blob (mirrors the x86 `VmState::serialize`
    /// signature so the cross-platform `VmCheckpoint` can call it uniformly).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.dist_regs.len() as u32).to_le_bytes());
        for &(offset, val) in &self.dist_regs {
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        out.extend_from_slice(&(self.redist_regs.len() as u32).to_le_bytes());
        for &(attr, val) in &self.redist_regs {
            out.extend_from_slice(&attr.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        out.extend_from_slice(&(self.icc_regs.len() as u32).to_le_bytes());
        for &(attr, val) in &self.icc_regs {
            out.extend_from_slice(&attr.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        // GICv2 sections, appended after the v3 ones so blobs written before
        // GICv2 support existed still deserialize (absent trailing sections
        // read back as empty).
        out.extend_from_slice(&(self.gicv2_dist.len() as u32).to_le_bytes());
        for &(attr, val) in &self.gicv2_dist {
            out.extend_from_slice(&attr.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        out.extend_from_slice(&(self.gicv2_cpu.len() as u32).to_le_bytes());
        for &(attr, val) in &self.gicv2_cpu {
            out.extend_from_slice(&attr.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        out
    }

    /// Reconstruct from a blob produced by [`Self::serialize`].
    pub fn deserialize(bytes: &[u8]) -> std::result::Result<VmState, String> {
        let err = || "aarch64 VmState blob truncated".to_string();
        let mut pos = 0usize;
        let take = |pos: &mut usize, n: usize| -> std::result::Result<&[u8], String> {
            let s = bytes.get(*pos..*pos + n).ok_or_else(err)?;
            *pos += n;
            Ok(s)
        };
        let count = |pos: &mut usize| -> std::result::Result<usize, String> {
            Ok(u32::from_le_bytes(take(pos, 4)?.try_into().unwrap()) as usize)
        };
        let n = count(&mut pos)?;
        let mut dist_regs = Vec::with_capacity(n);
        for _ in 0..n {
            let offset = u32::from_le_bytes(take(&mut pos, 4)?.try_into().unwrap());
            let val = u32::from_le_bytes(take(&mut pos, 4)?.try_into().unwrap());
            dist_regs.push((offset, val));
        }
        let n = count(&mut pos)?;
        let mut redist_regs = Vec::with_capacity(n);
        for _ in 0..n {
            let attr = u64::from_le_bytes(take(&mut pos, 8)?.try_into().unwrap());
            let val = u32::from_le_bytes(take(&mut pos, 4)?.try_into().unwrap());
            redist_regs.push((attr, val));
        }
        let n = count(&mut pos)?;
        let mut icc_regs = Vec::with_capacity(n);
        for _ in 0..n {
            let attr = u64::from_le_bytes(take(&mut pos, 8)?.try_into().unwrap());
            let val = u64::from_le_bytes(take(&mut pos, 8)?.try_into().unwrap());
            icc_regs.push((attr, val));
        }
        // Trailing GICv2 sections: absent in blobs written before GICv2
        // support, so exhausted-bytes here means empty, not truncation.
        let mut gicv2_dist = Vec::new();
        let mut gicv2_cpu = Vec::new();
        if pos < bytes.len() {
            let n = count(&mut pos)?;
            gicv2_dist.reserve(n);
            for _ in 0..n {
                let attr = u64::from_le_bytes(take(&mut pos, 8)?.try_into().unwrap());
                let val = u32::from_le_bytes(take(&mut pos, 4)?.try_into().unwrap());
                gicv2_dist.push((attr, val));
            }
            let n = count(&mut pos)?;
            gicv2_cpu.reserve(n);
            for _ in 0..n {
                let attr = u64::from_le_bytes(take(&mut pos, 8)?.try_into().unwrap());
                let val = u32::from_le_bytes(take(&mut pos, 4)?.try_into().unwrap());
                gicv2_cpu.push((attr, val));
            }
        }
        Ok(VmState {
            dist_regs,
            redist_regs,
            icc_regs,
            gicv2_dist,
            gicv2_cpu,
        })
    }
}

/// Encapsulates configuration parameters for the guest vCPUS.
#[derive(Debug, Eq, PartialEq)]
pub struct VcpuConfig {
    /// Number of guest VCPUs.
    pub vcpu_count: u8,
    /// Enable hyperthreading in the CPUID configuration.
    pub ht_enabled: bool,
    /// CPUID template to use.
    pub cpu_template: Option<CpuFeaturesTemplate>,
    /// Enable nested virtualization in the CPUID configuration.
    pub nested_enabled: bool,
}

// Using this for easier explicit type-casting to help IDEs interpret the code.
type VcpuCell = Cell<Option<*mut Vcpu>>;

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    fd: VcpuFd,
    id: u8,
    mmio_bus: Option<devices::Bus>,
    #[allow(dead_code)]
    #[cfg_attr(all(test, target_arch = "aarch64"), allow(unused))]
    exit_evt: EventFd,

    #[cfg(target_arch = "x86_64")]
    io_bus: devices::Bus,
    #[cfg(target_arch = "x86_64")]
    cpuid: CpuId,
    #[cfg(target_arch = "x86_64")]
    msr_list: MsrList,
    #[cfg(target_arch = "x86_64")]
    kernel_enomem_workaround: bool,
    #[cfg(target_arch = "x86_64")]
    kernel_first_run_delay: bool,
    #[cfg(target_arch = "x86_64")]
    kernel_enomem_retries: u8,
    #[cfg(target_arch = "x86_64")]
    portable_cpu: bool,

    #[cfg(target_arch = "aarch64")]
    mpidr: u64,
    /// The guest virtual counter (`CNTVCT`) captured when this vCPU paused,
    /// written back at resume so guest time freezes across the pause. `None`
    /// for a vCPU that entered the paused state without running first (a fork
    /// clone's initial state — its counter comes from the checkpoint restore).
    #[cfg(target_arch = "aarch64")]
    paused_cntvct: Option<u64>,

    // The receiving end of events channel owned by the vcpu side.
    event_receiver: Receiver<VcpuEvent>,
    // The transmitting end of the events channel which will be given to the handler.
    event_sender: Option<Sender<VcpuEvent>>,
    // The receiving end of the responses channel which will be given to the handler.
    response_receiver: Option<Receiver<VcpuResponse>>,
    // The transmitting end of the responses channel owned by the vcpu side.
    response_sender: Sender<VcpuResponse>,

    #[cfg(feature = "tee")]
    pm_sender: Sender<WorkerMessage>,
}

impl Vcpu {
    thread_local!(static TLS_VCPU_PTR: VcpuCell = const { Cell::new(None) });

    /// Associates `self` with the current thread.
    ///
    /// It is a prerequisite to successfully run `init_thread_local_data()` before using
    /// `run_on_thread_local()` on the current thread.
    /// This function will return an error if there already is a `Vcpu` present in the TLS.
    fn init_thread_local_data(&mut self) -> Result<()> {
        Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| {
            if cell.get().is_some() {
                return Err(Error::VcpuTlsInit);
            }
            cell.set(Some(self as *mut Vcpu));
            Ok(())
        })
    }

    /// Deassociates `self` from the current thread.
    ///
    /// Should be called if the current `self` had called `init_thread_local_data()` and
    /// now needs to move to a different thread.
    ///
    /// Fails if `self` was not previously associated with the current thread.
    fn reset_thread_local_data(&mut self) -> Result<()> {
        // Best-effort to clean up TLS. If the `Vcpu` was moved to another thread
        // _before_ running this, then there is nothing we can do.
        Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| {
            if let Some(vcpu_ptr) = cell.get()
                && std::ptr::eq(vcpu_ptr, self)
            {
                Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| cell.take());
                return Ok(());
            }
            Err(Error::VcpuTlsNotPresent)
        })
    }

    /// Runs `func` for the `Vcpu` associated with the current thread.
    ///
    /// It requires that `init_thread_local_data()` was run on this thread.
    ///
    /// Fails if there is no `Vcpu` associated with the current thread.
    ///
    /// # Safety
    ///
    /// This is marked unsafe as it allows temporary aliasing through
    /// dereferencing from pointer an already borrowed `Vcpu`.
    unsafe fn run_on_thread_local<F>(func: F) -> Result<()>
    where
        F: FnOnce(&mut Vcpu),
    {
        unsafe {
            Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| {
                if let Some(vcpu_ptr) = cell.get() {
                    // Dereferencing here is safe since `TLS_VCPU_PTR` is populated/non-empty,
                    // and it is being cleared on `Vcpu::drop` so there is no dangling pointer.
                    let vcpu_ref: &mut Vcpu = &mut *vcpu_ptr;
                    func(vcpu_ref);
                    Ok(())
                } else {
                    Err(Error::VcpuTlsNotPresent)
                }
            })
        }
    }

    /// Registers a signal handler which makes use of TLS and kvm immediate exit to
    /// kick the vcpu running on the current thread, if there is one.
    pub fn register_kick_signal_handler() {
        extern "C" fn handle_signal(_: c_int, _: *mut siginfo_t, _: *mut c_void) {
            // This is safe because it's temporarily aliasing the `Vcpu` object, but we are
            // only reading `vcpu.fd` which does not change for the lifetime of the `Vcpu`.
            unsafe {
                let _ = Vcpu::run_on_thread_local(|vcpu: &mut Vcpu| {
                    vcpu.fd.set_kvm_immediate_exit(1);
                    fence(Ordering::Release);
                });
            }
        }

        register_signal_handler(sigrtmin() + VCPU_RTSIG_OFFSET, handle_signal)
            .expect("Failed to register vcpu signal handler");
    }

    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm_fd` - The kvm `VmFd` for the virtual machine this vcpu will get attached to.
    /// * `cpuid` - The `CpuId` listing the supported capabilities of this vcpu.
    /// * `msr_list` - The `MsrList` listing the supported MSRs for this vcpu.
    /// * `io_bus` - The io-bus used to access port-io devices.
    /// * `exit_evt` - An `EventFd` that will be written into when this vcpu exits.
    #[cfg(target_arch = "x86_64")]
    pub fn new_x86_64(
        id: u8,
        vm_fd: &VmFd,
        cpuid: CpuId,
        msr_list: MsrList,
        io_bus: devices::Bus,
        exit_evt: EventFd,
        #[cfg(feature = "tee")] pm_sender: Sender<WorkerMessage>,
    ) -> Result<Self> {
        let kvm_vcpu = vm_fd.create_vcpu(id as u64).map_err(Error::VcpuFd)?;
        let (event_sender, event_receiver) = unbounded();
        let (response_sender, response_receiver) = unbounded();

        let kernel_enomem_workaround = if env::var_os("KRUN_ENOMEM_WORKAROUND").is_some() {
            debug!("Enabling ENOMEM workaround");
            true
        } else {
            false
        };
        let kernel_first_run_delay = if env::var_os("KRUN_FIRST_RUN_DELAY").is_some() {
            debug!("Delaying the first KVM_RUN");
            true
        } else {
            false
        };
        // KVM_RUN should not return ENOMEM, but affected host kernels can do so
        // transiently. Bound the workaround so a real persistent failure is
        // still surfaced instead of leaving a vCPU in an infinite retry loop.
        let kernel_enomem_retries = if env::var_os("KRUN_ENOMEM_RETRY").is_some() {
            debug!("Enabling bounded KVM_RUN ENOMEM retries");
            20
        } else {
            0
        };

        // Initially the cpuid per vCPU is the one supported by this VM.
        Ok(Vcpu {
            fd: kvm_vcpu,
            id,
            mmio_bus: None,
            exit_evt,
            io_bus,
            cpuid,
            msr_list,
            kernel_enomem_workaround,
            kernel_first_run_delay,
            kernel_enomem_retries,
            portable_cpu: false,
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
            #[cfg(feature = "tee")]
            pm_sender,
        })
    }

    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm_fd` - The kvm `VmFd` for the virtual machine this vcpu will get attached to.
    /// * `exit_evt` - An `EventFd` that will be written into when this vcpu exits.
    /// * `create_ts` - A timestamp used by the vcpu to calculate its lifetime.
    #[cfg(target_arch = "aarch64")]
    pub fn new_aarch64(id: u8, vm_fd: &VmFd, exit_evt: EventFd) -> Result<Self> {
        let kvm_vcpu = vm_fd.create_vcpu(id as u64).map_err(Error::VcpuFd)?;
        let (event_sender, event_receiver) = unbounded();
        let (response_sender, response_receiver) = unbounded();

        Ok(Vcpu {
            fd: kvm_vcpu,
            id,
            mmio_bus: None,
            exit_evt,
            mpidr: 0,
            paused_cntvct: None,
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
        })
    }

    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm_fd` - The kvm `VmFd` for the virtual machine this vcpu will get attached to.
    /// * `exit_evt` - An `EventFd` that will be written into when this vcpu exits.
    /// * `create_ts` - A timestamp used by the vcpu to calculate its lifetime.
    #[cfg(target_arch = "riscv64")]
    pub fn new_riscv64(id: u8, vm_fd: &VmFd, exit_evt: EventFd) -> Result<Self> {
        let kvm_vcpu = vm_fd.create_vcpu(id as u64).map_err(Error::VcpuFd)?;
        let (event_sender, event_receiver) = unbounded();
        let (response_sender, response_receiver) = unbounded();

        Ok(Vcpu {
            fd: kvm_vcpu,
            id,
            mmio_bus: None,
            exit_evt,
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
        })
    }

    /// Returns the cpu index as seen by the guest OS.
    pub fn cpu_index(&self) -> u8 {
        self.id
    }

    /// Gets the MPIDR register value.
    #[cfg(target_arch = "aarch64")]
    pub fn get_mpidr(&self) -> u64 {
        self.mpidr
    }

    /// Sets a MMIO bus for this vcpu.
    pub fn set_mmio_bus(&mut self, mmio_bus: devices::Bus) {
        self.mmio_bus = Some(mmio_bus);
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(unused_variables)]
    /// Configures a x86_64 specific vcpu and should be called once per vcpu.
    ///
    /// # Arguments
    ///
    /// * `machine_config` - The machine configuration of this microvm needed for the CPUID configuration.
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_start_addr` - Offset from `guest_mem` at which the kernel starts.
    pub fn configure_x86_64(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        kernel_start_addr: GuestAddress,
        vcpu_config: &VcpuConfig,
        kernel_boot: bool,
        pvh: bool,
    ) -> Result<()> {
        let cpuid_vm_spec = VmSpec::new(
            self.id,
            vcpu_config.vcpu_count,
            vcpu_config.ht_enabled,
            vcpu_config.nested_enabled,
        )
        .map_err(Error::CpuId)?;

        filter_cpuid(&mut self.cpuid, &cpuid_vm_spec).map_err(|e| {
            error!("Failure in configuring CPUID for vcpu {}: {:?}", self.id, e);
            Error::CpuId(e)
        })?;

        if let Some(template) = vcpu_config.cpu_template {
            match template {
                CpuFeaturesTemplate::T2 => {
                    t2::set_cpuid_entries(&mut self.cpuid, &cpuid_vm_spec).map_err(Error::CpuId)?
                }
                CpuFeaturesTemplate::C3 => {
                    c3::set_cpuid_entries(&mut self.cpuid, &cpuid_vm_spec).map_err(Error::CpuId)?
                }
                // The existing T2 mask is a conservative Haswell-era Intel
                // contract: it removes host-specific extended state (MPX,
                // AVX-512, PKU, and XSAVE extensions) that cannot safely cross
                // CPU generations in a live checkpoint while retaining the
                // broadly available AVX2 baseline.
                CpuFeaturesTemplate::PortableV1 => {
                    t2::set_cpuid_entries(&mut self.cpuid, &cpuid_vm_spec).map_err(Error::CpuId)?
                }
            }
            self.portable_cpu = template == CpuFeaturesTemplate::PortableV1;
        }

        self.fd
            .set_cpuid2(&self.cpuid)
            .map_err(Error::VcpuSetCpuid)?;

        if kernel_boot {
            arch::x86_64::msr::setup_msrs(&self.fd).map_err(Error::MSRSConfiguration)?;
            arch::x86_64::regs::setup_regs(&self.fd, kernel_start_addr.raw_value(), self.id, pvh)
                .map_err(Error::REGSConfiguration)?;
            arch::x86_64::regs::setup_fpu(&self.fd).map_err(Error::FPUConfiguration)?;
            arch::x86_64::regs::setup_sregs(guest_mem, &self.fd, self.id, pvh)
                .map_err(Error::SREGSConfiguration)?;
            arch::x86_64::interrupts::set_lint(&self.fd).map_err(Error::LocalIntConfiguration)?;
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Configures an aarch64 specific vcpu.
    ///
    /// # Arguments
    ///
    /// * `vm_fd` - The kvm `VmFd` for this microvm.
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_load_addr` - Offset from `guest_mem` at which the kernel is loaded.
    pub fn configure_aarch64(
        &mut self,
        vm_fd: &VmFd,
        mem_info: &ArchMemoryInfo,
        kernel_load_addr: GuestAddress,
    ) -> Result<()> {
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();

        // This reads back the kernel's preferred target type.
        vm_fd
            .get_preferred_target(&mut kvi)
            .map_err(Error::VcpuArmPreferredTarget)?;
        // We already checked that the capability is supported.
        kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
        // Non-boot cpus are powered off initially.
        if self.id > 0 {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }

        if vm_fd.check_extension(kvm_ioctls::Cap::ArmPtrAuthAddress) {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PTRAUTH_ADDRESS;
        }
        if vm_fd.check_extension(kvm_ioctls::Cap::ArmPtrAuthGeneric) {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PTRAUTH_GENERIC;
        }

        self.fd.vcpu_init(&kvi).map_err(Error::VcpuArmInit)?;
        arch::aarch64::regs::setup_regs(&self.fd, self.id, kernel_load_addr.raw_value(), mem_info)
            .map_err(Error::REGSConfiguration)?;

        self.mpidr = arch::aarch64::regs::read_mpidr(&self.fd).map_err(Error::REGSConfiguration)?;

        Ok(())
    }

    #[cfg(target_arch = "riscv64")]
    /// Configures an riscv64 specific vcpu.
    ///
    /// # Arguments
    ///
    /// * `vm_fd` - The kvm `VmFd` for this microvm.
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_load_addr` - Offset from `guest_mem` at which the kernel is loaded.
    pub fn configure_riscv64(
        &mut self,
        _vm_fd: &VmFd,
        guest_mem: &GuestMemoryMmap,
        kernel_load_addr: GuestAddress,
    ) -> Result<()> {
        arch::riscv64::regs::setup_regs(&self.fd, self.id, kernel_load_addr.raw_value(), guest_mem)
            .map_err(Error::REGSConfiguration)?;
        Ok(())
    }

    /// Moves the vcpu to its own thread and constructs a VcpuHandle.
    /// The handle can be used to control the remote vcpu.
    pub fn start_threaded(mut self) -> Result<VcpuHandle> {
        let event_sender = self.event_sender.take().unwrap();
        let response_receiver = self.response_receiver.take().unwrap();
        let (init_tls_sender, init_tls_receiver) = unbounded();
        let vcpu_thread = thread::Builder::new()
            .name(format!("fc_vcpu {}", self.cpu_index()))
            .spawn(move || {
                self.init_thread_local_data()
                    .expect("Cannot cleanly initialize vcpu TLS.");

                init_tls_sender
                    .send(true)
                    .expect("Cannot notify vcpu TLS initialization.");

                self.run();
            })
            .map_err(Error::VcpuSpawn)?;

        init_tls_receiver
            .recv()
            .expect("Error waiting for TLS initialization.");

        Ok(VcpuHandle::new(
            event_sender,
            response_receiver,
            vcpu_thread,
        ))
    }

    #[allow(unused)]
    #[cfg(target_arch = "x86_64")]
    fn save_state(&self) -> Result<VcpuState> {
        /*
         * Ordering requirements:
         *
         * KVM_GET_MP_STATE calls kvm_apic_accept_events(), which might modify
         * vCPU/LAPIC state. As such, it must be done before most everything
         * else, otherwise we cannot restore everything and expect it to work.
         *
         * KVM_GET_VCPU_EVENTS/KVM_SET_VCPU_EVENTS is unsafe if other vCPUs are
         * still running.
         *
         * KVM_GET_LAPIC may change state of LAPIC before returning it.
         *
         * GET_VCPU_EVENTS should probably be last to save. The code looks as
         * it might as well be affected by internal state modifications of the
         * GET ioctls.
         *
         * SREGS saves/restores a pending interrupt, similar to what
         * VCPU_EVENTS also does.
         *
         * GET_MSRS requires a pre-populated data structure to do something
         * meaningful. For SET_MSRS it will then contain good data.
         */

        // Build the list of MSRs we want to save.
        let msr_indices = self
            .msr_list
            .as_slice()
            .iter()
            .copied()
            .filter(|index| !self.portable_cpu || portable_msr_should_serialize(*index))
            .collect::<Vec<_>>();
        let num_msrs = msr_indices.len();
        let mut msrs = Msrs::new(num_msrs).unwrap();
        {
            let msr_entries = msrs.as_mut_slice();
            assert_eq!(msr_indices.len(), msr_entries.len());
            for (pos, index) in msr_indices.iter().enumerate() {
                msr_entries[pos].index = *index;
            }
        }
        let mp_state = self.fd.get_mp_state().map_err(Error::VcpuGetMpState)?;
        let regs = self.fd.get_regs().map_err(Error::VcpuGetRegs)?;
        let sregs = self.fd.get_sregs().map_err(Error::VcpuGetSregs)?;
        let xsave = self.fd.get_xsave().map_err(Error::VcpuGetXsave)?;
        let tsc_migration = if self.portable_cpu {
            Some(TscMigrationState {
                khz: self.fd.get_tsc_khz().map_err(Error::VcpuGetTscKhz)?,
                offset: self.get_tsc_offset()?,
                apply_offset: true,
            })
        } else {
            None
        };
        let xcrs = self.fd.get_xcrs().map_err(Error::VcpuGetXcrs)?;
        let debug_regs = self.fd.get_debug_regs().map_err(Error::VcpuGetDebugRegs)?;
        let lapic = self.fd.get_lapic().map_err(Error::VcpuGetLapic)?;
        let nmsrs = self.fd.get_msrs(&mut msrs).map_err(Error::VcpuGetMsrs)?;
        assert_eq!(nmsrs, num_msrs);
        let vcpu_events = self
            .fd
            .get_vcpu_events()
            .map_err(Error::VcpuGetVcpuEvents)?;
        Ok(VcpuState {
            cpuid: self.cpuid.clone(),
            msrs,
            debug_regs,
            lapic,
            mp_state,
            regs,
            sregs,
            vcpu_events,
            xcrs,
            xsave,
            tsc_migration,
        })
    }

    #[allow(unused)]
    #[cfg(target_arch = "x86_64")]
    fn restore_state(&self, state: VcpuState) -> Result<()> {
        /*
         * Ordering requirements:
         *
         * KVM_GET_VCPU_EVENTS/KVM_SET_VCPU_EVENTS is unsafe if other vCPUs are
         * still running.
         *
         * Some SET ioctls (like set_mp_state) depend on kvm_vcpu_is_bsp(), so
         * if we ever change the BSP, we have to do that before restoring anything.
         * The same seems to be true for CPUID stuff.
         *
         * SREGS saves/restores a pending interrupt, similar to what
         * VCPU_EVENTS also does.
         *
         * SET_REGS clears pending exceptions unconditionally, thus, it must be
         * done before SET_VCPU_EVENTS, which restores it.
         *
         * SET_LAPIC must come after SET_SREGS, because the latter restores
         * the apic base msr.
         *
         * SET_LAPIC must come before SET_MSRS, because the TSC deadline MSR
         * only restores successfully, when the LAPIC is correctly configured.
         */
        // Guest clock conversion state was initialized against the source
        // virtual TSC rate. Program that same rate before restoring TSC/MSRs;
        // otherwise a cross-host resume can make guest timers stall or jump.
        if let Some(tsc) = state.tsc_migration {
            self.fd.set_tsc_khz(tsc.khz).map_err(Error::VcpuSetTscKhz)?;
        }
        self.fd
            .set_cpuid2(&state.cpuid)
            .map_err(Error::VcpuSetCpuid)?;
        self.fd
            .set_mp_state(state.mp_state)
            .map_err(Error::VcpuSetMpState)?;
        self.fd.set_regs(&state.regs).map_err(Error::VcpuSetRegs)?;
        self.fd
            .set_sregs(&state.sregs)
            .map_err(Error::VcpuSetSregs)?;
        unsafe {
            self.fd
                .set_xsave(&state.xsave)
                .map_err(Error::VcpuSetXsave)?;
        }
        self.fd.set_xcrs(&state.xcrs).map_err(Error::VcpuSetXcrs)?;
        self.fd
            .set_debug_regs(&state.debug_regs)
            .map_err(Error::VcpuSetDebugRegs)?;
        self.fd
            .set_lapic(&state.lapic)
            .map_err(Error::VcpuSetLapic)?;
        let expected_msrs = state.msrs.as_slice().len();
        let restored_msrs = self.fd.set_msrs(&state.msrs).map_err(Error::VcpuSetMsrs)?;
        if restored_msrs != expected_msrs {
            return Err(Error::VcpuSetMsrsIncomplete {
                expected: expected_msrs,
                actual: restored_msrs,
            });
        }
        // SET_MSRS includes IA32_TSC and therefore changes KVM's offset. Apply
        // the migration-corrected offset afterwards so the guest's TSC and
        // kvmclock retain their source relationship on the destination host.
        if let Some(tsc) = state.tsc_migration
            && tsc.apply_offset
        {
            self.set_tsc_offset(tsc.offset)?;
        }
        self.fd
            .set_vcpu_events(&state.vcpu_events)
            .map_err(Error::VcpuSetVcpuEvents)?;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn get_tsc_offset(&self) -> Result<u64> {
        let mut offset = 0_u64;
        let mut attr = kvm_device_attr {
            group: KVM_VCPU_TSC_CTRL,
            attr: u64::from(KVM_VCPU_TSC_OFFSET),
            addr: (&mut offset as *mut u64) as u64,
            flags: 0,
        };
        let result = unsafe { ioctl_with_mut_ref(&self.fd, KVM_GET_VCPU_DEVICE_ATTR(), &mut attr) };
        if result < 0 {
            return Err(Error::VcpuGetTscOffset(io::Error::last_os_error()));
        }
        Ok(offset)
    }

    #[cfg(target_arch = "x86_64")]
    fn set_tsc_offset(&self, offset: u64) -> Result<()> {
        let attr = kvm_device_attr {
            group: KVM_VCPU_TSC_CTRL,
            attr: u64::from(KVM_VCPU_TSC_OFFSET),
            addr: (&offset as *const u64) as u64,
            flags: 0,
        };
        let result = unsafe { ioctl_with_ref(&self.fd, KVM_SET_VCPU_DEVICE_ATTR(), &attr) };
        if result < 0 {
            return Err(Error::VcpuSetTscOffset(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Capture the full aarch64 vCPU state: the MP (power) state plus every
    /// register KVM enumerates via `KVM_GET_REG_LIST` — core registers, FP/SIMD,
    /// system registers, the generic timer (`CNTVCT`/`CNTV_CTL`/`CNTV_CVAL`,
    /// so the clone's virtual counter resumes from the checkpoint), and the
    /// PSCI firmware registers. The in-kernel GIC's CPU-interface state is
    /// deliberately absent from the list; it travels in `VmState`.
    #[cfg(target_arch = "aarch64")]
    fn save_state(&self) -> Result<VcpuState> {
        let mp_state = self.fd.get_mp_state().map_err(Error::VcpuGetMpState)?;
        // 500 is the kvm-bindings `RegList` capacity ceiling and comfortably
        // above the ~260-450 registers current kernels list for a non-SVE
        // vCPU (SVE is never enabled at vcpu_init). A larger kernel list
        // surfaces as E2BIG from the ioctl below rather than truncation.
        let mut reg_list = RegList::new(500)
            .map_err(|_| Error::VcpuGetRegList(kvm_ioctls::Error::new(libc::ENOMEM)))?;
        self.fd
            .get_reg_list(&mut reg_list)
            .map_err(Error::VcpuGetRegList)?;
        let mut regs = Vec::with_capacity(reg_list.as_slice().len());
        for &id in reg_list.as_slice() {
            let size = reg_size_bytes(id);
            if size > 16 {
                // Only SVE state is wider than 128 bits and it is never
                // enabled; skip rather than silently truncate.
                warn!("skipping oversized vCPU register {id:#x} ({size} bytes) in checkpoint");
                continue;
            }
            let mut data = [0u8; 16];
            self.fd
                .get_one_reg(id, &mut data[..size])
                .map_err(|e| Error::VcpuGetOneReg(id, e))?;
            regs.push((id, u128::from_le_bytes(data)));
        }
        Ok(VcpuState { mp_state, regs })
    }

    /// Restore aarch64 vCPU state captured by [`Self::save_state`] onto this
    /// freshly-initialized (never-run) vCPU. Writing the saved `CNTVCT` value
    /// back makes KVM derive the clone's virtual-counter offset, giving the
    /// guest a continuous timeline across the fork.
    #[cfg(target_arch = "aarch64")]
    fn restore_state(&self, state: VcpuState) -> Result<()> {
        self.fd
            .set_mp_state(state.mp_state)
            .map_err(Error::VcpuSetMpState)?;
        for &(id, val) in &state.regs {
            let size = reg_size_bytes(id);
            self.fd
                .set_one_reg(id, &val.to_le_bytes()[..size])
                .map_err(|e| Error::VcpuSetOneReg(id, e))?;
        }
        Ok(())
    }

    /// Runs the vCPU in KVM context and handles the kvm exit reason.
    ///
    /// Returns error or enum specifying whether emulation was handled or interrupted.
    fn run_emulation(&mut self) -> Result<VcpuEmulation> {
        // Work around a kernel bug that can return ENOMEM when the first
        // KVM_RUN follows vCPU creation too closely. Delaying only the first
        // entry avoids taxing every subsequent guest exit.
        // https://github.com/containers/libkrun/issues/314
        #[cfg(target_arch = "x86_64")]
        if self.kernel_first_run_delay {
            self.kernel_first_run_delay = false;
            thread::sleep(Duration::from_millis(5));
        }

        // Preserve the legacy opt-in workaround for callers that need a delay
        // before every KVM entry.
        #[cfg(target_arch = "x86_64")]
        if self.kernel_enomem_workaround {
            thread::sleep(Duration::from_millis(5));
        }

        match self.fd.run() {
            Ok(run) => match run {
                #[cfg(feature = "tee")]
                VcpuExit::Hypercall(hypercall) => {
                    if hypercall.nr != 12
                    /* KVM_HC_MAP_GPA_RANGE */
                    {
                        return Err(Error::VcpuUnsupportedHypercall);
                    }

                    let gpa = hypercall.args[0];
                    let size = hypercall.args[1] * 0x1000; /* TARGET_PAGE_SIZE */
                    let attributes = hypercall.args[2];

                    let private = !matches!(attributes, 0);

                    let mem_properties = MemoryProperties { gpa, size, private };

                    let (response_sender, response_receiver) = unbounded();
                    self.pm_sender
                        .send(WorkerMessage::ConvertMemory(
                            response_sender.clone(),
                            mem_properties,
                        ))
                        .unwrap();
                    if !response_receiver.recv().unwrap() {
                        error!(
                            "Unable to convert memory with properties: gpa: 0x{gpa:x} size: 0x{size:x} to_private: {private}"
                        );
                        return Err(Error::VcpuUnhandledKvmExit);
                    }
                    Ok(VcpuEmulation::Handled)
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoIn(addr, data) => {
                    self.io_bus.read(0, u64::from(addr), data);
                    Ok(VcpuEmulation::Handled)
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoOut(addr, data) => {
                    self.io_bus.write(0, u64::from(addr), data);
                    Ok(VcpuEmulation::Handled)
                }
                #[cfg(feature = "tee")]
                VcpuExit::MemoryFault { gpa, size, flags } => {
                    if flags & !kvm_bindings::KVM_MEMORY_EXIT_FLAG_PRIVATE as u64 != 0 {
                        println!("KVM_EXIT_MEMORY_FAULT: Unknown flag {flags}");
                        Err(Error::VcpuUnhandledKvmExit)
                    } else {
                        let private = (flags & (KVM_MEMORY_EXIT_FLAG_PRIVATE as u64)) != 0;
                        let mem_properties = MemoryProperties { gpa, size, private };
                        let (response_sender, response_receiver) = unbounded();
                        self.pm_sender
                            .send(WorkerMessage::ConvertMemory(
                                response_sender.clone(),
                                mem_properties,
                            ))
                            .unwrap();
                        if !response_receiver.recv().unwrap() {
                            error!(
                                "Unable to convert memory with properties: gpa: 0x{gpa:x} size: 0x{size:x} to_private: {private}"
                            );
                            return Err(Error::VcpuUnhandledKvmExit);
                        }
                        Ok(VcpuEmulation::Handled)
                    }
                }
                VcpuExit::MmioRead(addr, data) => {
                    if std::env::var_os("SMOLVM_TRACE_MMIO").is_some() {
                        eprintln!("[mmio] R {addr:#x} len={}", data.len());
                    }
                    if let Some(ref mmio_bus) = self.mmio_bus {
                        mmio_bus.read(0, addr, data);
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if std::env::var_os("SMOLVM_TRACE_MMIO").is_some() {
                        eprintln!("[mmio] W {addr:#x} len={}", data.len());
                    }
                    if let Some(ref mmio_bus) = self.mmio_bus {
                        mmio_bus.write(0, addr, data);
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::Hlt => {
                    info!("Received KVM_EXIT_HLT signal");
                    Ok(VcpuEmulation::Stopped)
                }
                VcpuExit::Shutdown => {
                    info!("Received KVM_EXIT_SHUTDOWN signal");
                    Ok(VcpuEmulation::Stopped)
                }
                // Documentation specifies that below kvm exits are considered
                // errors.
                VcpuExit::FailEntry(reason, vcpu) => {
                    error!("Received KVM_EXIT_FAIL_ENTRY signal: reason={reason}, vcpu={vcpu}");
                    Err(Error::VcpuUnhandledKvmExit)
                }
                VcpuExit::InternalError => {
                    error!("Received KVM_EXIT_INTERNAL_ERROR signal");
                    Err(Error::VcpuUnhandledKvmExit)
                }
                VcpuExit::SystemEvent(event, _reason) => {
                    match event {
                        KVM_SYSTEM_EVENT_SHUTDOWN => info!("Received KVM_SYSTEM_EVENT_SHUTDOWN"),
                        KVM_SYSTEM_EVENT_RESET => info!("Received KVM_SYSTEM_EVENT_RESET"),
                        _ => error!("Received an unexpected System Event: {event}"),
                    }
                    Ok(VcpuEmulation::Stopped)
                }
                r => {
                    // TODO: Are we sure we want to finish running a vcpu upon
                    // receiving a vm exit that is not necessarily an error?
                    error!("Unexpected exit reason on vcpu run: {r:?}");
                    Err(Error::VcpuUnhandledKvmExit)
                }
            },
            // The unwrap on raw_os_error can only fail if we have a logic
            // error in our code in which case it is better to panic.
            Err(ref e) => {
                match e.errno() {
                    libc::EAGAIN => Ok(VcpuEmulation::Handled),
                    libc::EINTR => {
                        self.fd.set_kvm_immediate_exit(0);
                        // Notify that this KVM_RUN was interrupted.
                        Ok(VcpuEmulation::Interrupted)
                    }
                    #[cfg(target_arch = "x86_64")]
                    libc::ENOMEM if self.kernel_enomem_retries > 0 => {
                        self.kernel_enomem_retries -= 1;
                        debug!(
                            "Retrying KVM_RUN after ENOMEM ({} retries remain)",
                            self.kernel_enomem_retries
                        );
                        thread::sleep(Duration::from_millis(5));
                        Ok(VcpuEmulation::Handled)
                    }
                    _ => {
                        #[cfg(target_arch = "x86_64")]
                        if e.errno() == libc::ENOMEM {
                            eprintln!(
                                "ERROR KVM_RUN repeatedly returned ENOMEM after the bounded retry window"
                            );
                        }
                        error!("Failure during vcpu run: {e}");
                        Err(Error::VcpuUnhandledKvmExit)
                    }
                }
            }
        }
    }

    /// Main loop of the vCPU thread.
    ///
    /// Runs the vCPU in KVM context in a loop. Handles KVM_EXITs then goes back in.
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    pub fn run(&mut self) {
        // Start running the machine state in the `Paused` state.
        StateMachine::run(self, Self::paused);
    }

    // aarch64 freezes guest time via the paused_cntvct capture/write-back in
    // the pause/resume handlers instead; only x86_64 still takes this path.
    #[cfg(target_arch = "x86_64")]
    fn adjust_guest_clock_after_pause(&self, paused_ns: u64) -> Result<()> {
        if paused_ns == 0 {
            return Ok(());
        }

        #[cfg(target_arch = "x86_64")]
        {
            let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_KVMCLOCK_CTRL) };
            if ret < 0 {
                return Err(Error::VcpuKvmClockCtrl(io::Error::last_os_error()));
            }
        }

        Ok(())
    }

    // This is the main loop of the `Running` state.
    fn running(&mut self) -> StateMachine<Self> {
        // This loop is here just for optimizing the emulation path.
        // No point in ticking the state machine if there are no external events.
        loop {
            match self.run_emulation() {
                // Emulation ran successfully, continue.
                Ok(VcpuEmulation::Handled) => (),
                // Emulation was interrupted, check external events.
                Ok(VcpuEmulation::Interrupted) => break,
                // If the guest was rebooted or halted:
                // - vCPU0 will always exit out of `KVM_RUN` with KVM_EXIT_SHUTDOWN or
                //   KVM_EXIT_HLT.
                // - the other vCPUs won't ever exit out of `KVM_RUN`, but they won't consume CPU.
                // Moreover if we allow the vCPU0 thread to finish execution, this might generate a
                // seccomp failure because musl calls `sigprocmask` as part of `pthread_exit`.
                // So we pause vCPU0 and send a signal to the emulation thread to stop the VMM.
                Ok(VcpuEmulation::Stopped) => return self.exit(FC_EXIT_CODE_OK),
                // Emulation errors lead to vCPU exit.
                Err(_) => return self.exit(FC_EXIT_CODE_GENERIC_ERROR),
            }
        }

        // By default don't change state.
        let mut state = StateMachine::next(Self::running);

        // Break this emulation loop on any transition request/external event.
        match self.event_receiver.try_recv() {
            // Running ---- Pause ----> Paused
            Ok(VcpuEvent::Pause) => {
                // Capture the guest's virtual counter so resume can freeze
                // guest time across the pause. Best-effort: a capture failure
                // only costs freeze semantics (the guest sees time jump),
                // never the pause itself.
                #[cfg(target_arch = "aarch64")]
                {
                    self.paused_cntvct =
                        match arch::aarch64::regs::read_virtual_timer_count(&self.fd) {
                            Ok(cnt) => Some(cnt),
                            Err(e) => {
                                warn!("could not capture the virtual counter at pause: {e:?}");
                                None
                            }
                        };
                }
                self.response_sender
                    .send(VcpuResponse::Paused)
                    .expect("failed to send pause status");

                // Move to 'paused' state.
                state = StateMachine::next(Self::paused);
            }
            Ok(VcpuEvent::Resume { .. }) => {
                self.response_sender
                    .send(VcpuResponse::Resumed)
                    .expect("failed to send resume status");
            }
            // Save/restore are only valid while paused; the orchestrator always
            // pauses first, so receiving one here is a protocol error — ignore
            // it rather than capturing mid-instruction state.
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            Ok(VcpuEvent::SaveState | VcpuEvent::RestoreState(_)) => {
                error!("ignoring vcpu SaveState/RestoreState received while running");
            }
            // Unhandled exit of the other end.
            Err(TryRecvError::Disconnected) => {
                // Move to 'exited' state.
                state = self.exit(FC_EXIT_CODE_GENERIC_ERROR);
            }
            // All other events or lack thereof have no effect on current 'running' state.
            Err(TryRecvError::Empty) => (),
        }

        state
    }

    // This is the main loop of the `Paused` state.
    fn paused(&mut self) -> StateMachine<Self> {
        match self.event_receiver.recv() {
            // Paused ---- Resume ----> Running
            Ok(VcpuEvent::Resume { paused_ns }) => {
                // x86_64: a failed kvmclock adjustment leaves the guest clock
                // undefined, so treat it as fatal as before. aarch64: writing
                // the pause-time counter back is freeze-semantics best-effort —
                // a failure means the guest sees the paused wall time elapse,
                // which is strictly better than killing the vCPU (a fork
                // rollback resumes through here; a fatal exit here is what
                // turned one failed fork into a dead golden on arm KVM hosts).
                #[cfg(target_arch = "x86_64")]
                if let Err(e) = self.adjust_guest_clock_after_pause(paused_ns) {
                    error!("failed to adjust guest clock after pause: {e}");
                    return self.exit(FC_EXIT_CODE_GENERIC_ERROR);
                }
                #[cfg(target_arch = "aarch64")]
                {
                    let _ = paused_ns;
                    if let Some(cnt) = self.paused_cntvct.take()
                        && let Err(e) =
                            arch::aarch64::regs::write_virtual_timer_count(&self.fd, cnt)
                    {
                        warn!("could not restore the virtual counter at resume: {e:?}");
                    }
                }
                self.response_sender
                    .send(VcpuResponse::Resumed)
                    .expect("failed to send resume status");
                // Move to 'running' state.
                StateMachine::next(Self::running)
            }
            // Checkpoint: capture full vCPU register state while paused (the
            // only safe point — KVM_GET_VCPU_EVENTS is unsafe while other vCPUs
            // run). Stays paused afterwards.
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            Ok(VcpuEvent::SaveState) => match self.save_state() {
                Ok(state) => {
                    self.response_sender
                        .send(VcpuResponse::SavedState(Box::new(state)))
                        .expect("failed to send saved vcpu state");
                    StateMachine::next(Self::paused)
                }
                Err(e) => {
                    error!("failed to capture vcpu state: {e:?}");
                    self.exit(FC_EXIT_CODE_GENERIC_ERROR)
                }
            },
            // Restore: load captured register state onto the paused vCPU.
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            Ok(VcpuEvent::RestoreState(state)) => {
                if let Err(e) = self.restore_state(*state) {
                    let message = e.to_string();
                    error!("failed to restore vcpu state: {message}");
                    let _ = self
                        .response_sender
                        .send(VcpuResponse::RestoreFailed(message));
                    return self.exit(FC_EXIT_CODE_GENERIC_ERROR);
                }
                self.response_sender
                    .send(VcpuResponse::RestoredState)
                    .expect("failed to send restored vcpu ack");
                StateMachine::next(Self::paused)
            }
            // All other events have no effect on current 'paused' state.
            Ok(_) => StateMachine::next(Self::paused),
            // Unhandled exit of the other end.
            Err(_) => {
                // Move to 'exited' state.
                self.exit(FC_EXIT_CODE_GENERIC_ERROR)
            }
        }
    }

    #[cfg(not(test))]
    // Transition to the exited state.
    fn exit(&mut self, exit_code: u8) -> StateMachine<Self> {
        // Restore may already have returned an error and dropped the receiver;
        // exiting must not turn that original error into a secondary panic.
        if self
            .response_sender
            .send(VcpuResponse::Exited(exit_code))
            .is_err()
        {
            debug!("vCPU response receiver closed before Exited status");
        }

        if let Err(e) = self.exit_evt.write(1) {
            error!("Failed signaling vcpu exit event: {e}");
        }

        // State machine reached its end.
        StateMachine::next(Self::exited)
    }

    #[cfg(not(test))]
    // This is the main loop of the `Exited` state.
    fn exited(&mut self) -> StateMachine<Self> {
        // Wait indefinitely.
        // The VMM thread will kill the entire process.
        let barrier = Barrier::new(2);
        barrier.wait();

        StateMachine::finish()
    }

    #[cfg(feature = "tdx")]
    pub fn tdx_secure_virt_prepare(&self, launcher: &mut tdx::launch::Launcher) {
        use std::os::fd::AsRawFd;
        launcher.add_vcpu_fd(self.fd.as_raw_fd());
    }

    #[cfg(test)]
    // In tests the main/vmm thread exits without 'exit()'ing the whole process.
    // All channels get closed on the other side while this Vcpu thread is still running.
    // This Vcpu thread should just do a clean finish without reporting back to the main thread.
    fn exit(&mut self, _: u8) -> StateMachine<Self> {
        // State machine reached its end.
        StateMachine::finish()
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        let _ = self.reset_thread_local_data();
    }
}

#[cfg(target_arch = "x86_64")]
impl std::fmt::Debug for VcpuState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // The fields are raw KVM bindings (registers, MSRs, XSAVE) — bulky and
        // uninformative to dump; a marker keeps `VcpuResponse: Debug` cheap.
        f.write_str("VcpuState { .. }")
    }
}

#[cfg(target_arch = "x86_64")]
/// Structure holding VCPU kvm state.
pub struct VcpuState {
    cpuid: CpuId,
    msrs: Msrs,
    debug_regs: kvm_debugregs,
    lapic: kvm_lapic_state,
    mp_state: kvm_mp_state,
    regs: kvm_regs,
    sregs: kvm_sregs,
    vcpu_events: kvm_vcpu_events,
    xcrs: kvm_xcrs,
    xsave: kvm_xsave,
    tsc_migration: Option<TscMigrationState>,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
struct TscMigrationState {
    khz: u32,
    offset: u64,
    apply_offset: bool,
}

// --- Binary (de)serialization for checkpoint-to-file ---------------------------
//
// `VcpuState`/`VmState` are made of raw KVM bindings — plain `#[repr(C)]` POD
// structs plus two FAM-backed wrappers (`CpuId`, `Msrs`). kvm-bindings does not
// derive serde on them, so we encode them directly: POD fields as their raw
// bytes, FAM wrappers as a `u32` entry count followed by the entry bytes. This
// is the file format used by the control-socket CHECKPOINT/RESTORE path. No
// cross-version compatibility is promised — the snapshot manifest carries a
// format version and these blobs are only read back by the same build.

#[cfg(target_arch = "x86_64")]
fn ser_pod<T>(out: &mut Vec<u8>, v: &T) {
    // Safety: `T` is a `#[repr(C)]` POD KVM struct; reading its bytes is sound.
    let bytes =
        unsafe { std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>()) };
    out.extend_from_slice(bytes);
}

#[cfg(target_arch = "x86_64")]
fn de_pod<T>(inp: &[u8], pos: &mut usize) -> std::result::Result<T, String> {
    let sz = std::mem::size_of::<T>();
    if *pos + sz > inp.len() {
        return Err(format!(
            "snapshot truncated: need {sz} bytes at offset {pos}, have {}",
            inp.len()
        ));
    }
    // Safety: bounds checked above; `read_unaligned` tolerates any alignment.
    let v = unsafe { std::ptr::read_unaligned(inp[*pos..].as_ptr() as *const T) };
    *pos += sz;
    Ok(v)
}

#[cfg(target_arch = "x86_64")]
fn ser_fam<T>(out: &mut Vec<u8>, entries: &[T]) {
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        ser_pod(out, e);
    }
}

#[cfg(target_arch = "x86_64")]
fn de_fam<T>(inp: &[u8], pos: &mut usize) -> std::result::Result<Vec<T>, String> {
    let count = de_pod::<u32>(inp, pos)? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(de_pod::<T>(inp, pos)?);
    }
    Ok(entries)
}

#[cfg(target_arch = "x86_64")]
impl VcpuState {
    /// Serialize the full vCPU register state to a self-describing byte blob.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ser_fam(&mut out, self.cpuid.as_slice());
        ser_fam(&mut out, self.msrs.as_slice());
        match self.tsc_migration {
            Some(tsc) => {
                out.push(1);
                ser_pod(&mut out, &tsc.khz);
                ser_pod(&mut out, &tsc.offset);
            }
            None => out.push(0),
        }
        ser_pod(&mut out, &self.debug_regs);
        ser_pod(&mut out, &self.lapic);
        ser_pod(&mut out, &self.mp_state);
        ser_pod(&mut out, &self.regs);
        ser_pod(&mut out, &self.sregs);
        ser_pod(&mut out, &self.vcpu_events);
        ser_pod(&mut out, &self.xcrs);
        ser_pod(&mut out, &self.xsave);
        out
    }

    /// Reconstruct a [`VcpuState`] from a blob produced by [`Self::serialize`].
    pub fn deserialize(bytes: &[u8]) -> std::result::Result<VcpuState, String> {
        let mut pos = 0usize;
        let cpuid_entries: Vec<kvm_bindings::kvm_cpuid_entry2> = de_fam(bytes, &mut pos)?;
        let msr_entries: Vec<kvm_bindings::kvm_msr_entry> = de_fam(bytes, &mut pos)?;
        let cpuid =
            CpuId::from_entries(&cpuid_entries).map_err(|e| format!("rebuild CpuId: {e:?}"))?;
        let msrs = Msrs::from_entries(&msr_entries).map_err(|e| format!("rebuild Msrs: {e:?}"))?;
        let has_tsc_migration: u8 = de_pod(bytes, &mut pos)?;
        let tsc_migration = match has_tsc_migration {
            0 => None,
            1 => Some(TscMigrationState {
                khz: de_pod(bytes, &mut pos)?,
                offset: de_pod(bytes, &mut pos)?,
                apply_offset: true,
            }),
            marker => {
                return Err(format!("invalid vCPU TSC migration-state marker {marker}"));
            }
        };
        let state = VcpuState {
            cpuid,
            msrs,
            tsc_migration,
            debug_regs: de_pod(bytes, &mut pos)?,
            lapic: de_pod(bytes, &mut pos)?,
            mp_state: de_pod(bytes, &mut pos)?,
            regs: de_pod(bytes, &mut pos)?,
            sregs: de_pod(bytes, &mut pos)?,
            vcpu_events: de_pod(bytes, &mut pos)?,
            xcrs: de_pod(bytes, &mut pos)?,
            xsave: de_pod(bytes, &mut pos)?,
        };
        Ok(state)
    }
}

#[cfg(target_arch = "x86_64")]
impl VmState {
    /// Serialize the VM-level KVM state (PIT, clock, PIC/IOAPIC) to a byte blob.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ser_pod(&mut out, &self.pitstate);
        ser_pod(&mut out, &self.clock);
        ser_pod(&mut out, &self.pic_master);
        ser_pod(&mut out, &self.pic_slave);
        ser_pod(&mut out, &self.ioapic);
        out
    }

    /// Reconstruct a [`VmState`] from a blob produced by [`Self::serialize`].
    pub fn deserialize(bytes: &[u8]) -> std::result::Result<VmState, String> {
        let mut pos = 0usize;
        Ok(VmState {
            pitstate: de_pod(bytes, &mut pos)?,
            clock: de_pod(bytes, &mut pos)?,
            pic_master: de_pod(bytes, &mut pos)?,
            pic_slave: de_pod(bytes, &mut pos)?,
            ioapic: de_pod(bytes, &mut pos)?,
        })
    }
}

/// Byte width of a KVM register, encoded in bits 52+ of its id.
#[cfg(target_arch = "aarch64")]
fn reg_size_bytes(id: u64) -> usize {
    1usize << ((id & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT)
}

/// Full aarch64 vCPU state for a checkpoint: the MP (power) state plus every
/// `KVM_GET_REG_LIST`-enumerated register as an (id, value) pair. Values are
/// stored as `u128` (the widest non-SVE register); each register's true width
/// is derived from its id on the way back in.
#[cfg(target_arch = "aarch64")]
#[derive(Debug)]
pub struct VcpuState {
    mp_state: kvm_mp_state,
    regs: Vec<(u64, u128)>,
}

#[cfg(target_arch = "aarch64")]
impl VcpuState {
    /// Serialize the full vCPU register state to a self-describing byte blob
    /// (mirrors the x86 signature for the cross-platform `VmCheckpoint`).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.regs.len() * 24);
        out.extend_from_slice(&self.mp_state.mp_state.to_le_bytes());
        out.extend_from_slice(&(self.regs.len() as u32).to_le_bytes());
        for &(id, val) in &self.regs {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        out
    }

    /// Reconstruct a [`VcpuState`] from a blob produced by [`Self::serialize`].
    pub fn deserialize(bytes: &[u8]) -> std::result::Result<VcpuState, String> {
        let err = || "aarch64 VcpuState blob truncated".to_string();
        let mut pos = 0usize;
        let take = |pos: &mut usize, n: usize| -> std::result::Result<&[u8], String> {
            let s = bytes.get(*pos..*pos + n).ok_or_else(err)?;
            *pos += n;
            Ok(s)
        };
        let mp = u32::from_le_bytes(take(&mut pos, 4)?.try_into().unwrap());
        let n = u32::from_le_bytes(take(&mut pos, 4)?.try_into().unwrap()) as usize;
        let mut regs = Vec::with_capacity(n);
        for _ in 0..n {
            let id = u64::from_le_bytes(take(&mut pos, 8)?.try_into().unwrap());
            let val = u128::from_le_bytes(take(&mut pos, 16)?.try_into().unwrap());
            regs.push((id, val));
        }
        Ok(VcpuState {
            mp_state: kvm_mp_state { mp_state: mp },
            regs,
        })
    }
}

// Allow currently unused Pause and Exit events. These will be used by the vmm later on.
#[allow(unused)]
#[derive(Debug)]
/// List of events that the Vcpu can receive.
pub enum VcpuEvent {
    /// Pause the Vcpu.
    Pause,
    /// Event that should resume the Vcpu.
    Resume { paused_ns: u64 },
    /// Capture the full vCPU register state into a [`VcpuState`] (vCPU must be
    /// paused). The vCPU replies with [`VcpuResponse::SavedState`].
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    SaveState,
    /// Restore a previously-captured [`VcpuState`] onto the (paused) vCPU. The
    /// vCPU replies with [`VcpuResponse::RestoredState`].
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    RestoreState(Box<VcpuState>),
}

#[derive(Debug)]
/// List of responses that the Vcpu reports.
pub enum VcpuResponse {
    /// Vcpu is paused.
    Paused,
    /// Vcpu is resumed.
    Resumed,
    /// Vcpu is stopped.
    Exited(u8),
    /// Captured vCPU register state, in reply to [`VcpuEvent::SaveState`].
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    SavedState(Box<VcpuState>),
    /// Acknowledges a [`VcpuEvent::RestoreState`].
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    RestoredState,
    /// The vCPU rejected checkpoint state and cannot safely resume.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    RestoreFailed(String),
}

/// Wrapper over Vcpu that hides the underlying interactions with the Vcpu thread.
pub struct VcpuHandle {
    event_sender: Sender<VcpuEvent>,
    response_receiver: Receiver<VcpuResponse>,
    // Rust JoinHandles have to be wrapped in Option if you ever plan on 'join()'ing them.
    // We want to be able to join these threads in tests.
    vcpu_thread: Option<thread::JoinHandle<()>>,
}

impl VcpuHandle {
    pub fn new(
        event_sender: Sender<VcpuEvent>,
        response_receiver: Receiver<VcpuResponse>,
        vcpu_thread: thread::JoinHandle<()>,
    ) -> Self {
        Self {
            event_sender,
            response_receiver,
            vcpu_thread: Some(vcpu_thread),
        }
    }

    pub fn send_event(&self, event: VcpuEvent) -> Result<()> {
        // Use expect() to crash if the other thread closed this channel.
        self.event_sender
            .send(event)
            .expect("event sender channel closed on vcpu end.");
        // Kick the vcpu so it picks up the message.
        self.vcpu_thread
            .as_ref()
            // Safe to unwrap since constructor make this 'Some'.
            .unwrap()
            .kill(sigrtmin() + VCPU_RTSIG_OFFSET)
            .map_err(Error::SignalVcpu)?;
        Ok(())
    }

    pub fn response_receiver(&self) -> &Receiver<VcpuResponse> {
        &self.response_receiver
    }
}

enum VcpuEmulation {
    Handled,
    Interrupted,
    Stopped,
}

#[cfg(test)]
mod tests {
    use crossbeam_channel::unbounded;
    use std::sync::{Arc, Barrier};

    use super::*;
    #[cfg(target_arch = "aarch64")]
    use crate::builder::Payload;
    #[cfg(target_arch = "aarch64")]
    use crate::builder::create_guest_memory;
    #[cfg(target_arch = "aarch64")]
    use crate::resources::VmResources;
    use devices;
    #[cfg(target_arch = "x86_64")]
    use devices::legacy::KvmIoapic;

    use utils::signal::validate_signal_num;

    // In tests we need to close any pending Vcpu threads on test completion.
    impl Drop for VcpuHandle {
        fn drop(&mut self) {
            // Make sure the Vcpu is out of KVM_RUN.
            self.send_event(VcpuEvent::Pause).unwrap();
            // Close the original channel so that the Vcpu thread errors and goes to exit state.
            let (event_sender, _event_receiver) = unbounded();
            self.event_sender = event_sender;
            // Wait for the Vcpu thread to finish execution
            self.vcpu_thread.take().unwrap().join().unwrap();
        }
    }

    // Auxiliary function being used throughout the tests.
    fn setup_vcpu(mem_size: usize) -> (Vm, Vcpu, GuestMemoryMmap) {
        let kvm = KvmContext::new().unwrap();
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), mem_size)]).unwrap();
        let mut vm = Vm::new(kvm.fd()).expect("Cannot create new vm");
        #[cfg(target_arch = "x86_64")]
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();
        assert!(vm.memory_init(&gm, kvm.max_memslots()).is_ok());

        let exit_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();

        let vcpu;
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            vcpu = Vcpu::new_x86_64(
                1,
                vm.fd(),
                vm.supported_cpuid().clone(),
                vm.supported_msrs().clone(),
                devices::Bus::new(),
                exit_evt,
            )
            .unwrap();
        }
        #[cfg(target_arch = "aarch64")]
        {
            vcpu = Vcpu::new_aarch64(1, vm.fd(), exit_evt).unwrap();
        }

        (vm, vcpu, gm)
    }

    #[test]
    fn test_set_mmio_bus() {
        let (_, mut vcpu, _) = setup_vcpu(0x1000);
        assert!(vcpu.mmio_bus.is_none());
        vcpu.set_mmio_bus(devices::Bus::new());
        assert!(vcpu.mmio_bus.is_some());
    }

    #[ignore]
    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_get_supported_cpuid() {
        let kvm = KvmContext::new().unwrap();
        let vm = Vm::new(kvm.fd()).expect("Cannot create new vm");
        let cpuid = kvm
            .kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .expect("Cannot get supported cpuid");
        assert_eq!(vm.supported_cpuid().as_slice(), cpuid.as_slice());
    }

    #[test]
    fn test_vm_memory_init() {
        let mut kvm_context = KvmContext::new().unwrap();
        let mut vm = Vm::new(kvm_context.fd()).expect("Cannot create new vm");

        // Create valid memory region and test that the initialization is successful.
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        assert!(vm.memory_init(&gm, kvm_context.max_memslots()).is_ok());

        // Set the maximum number of memory slots to 1 in KvmContext to check the error
        // path of memory_init. Create 2 non-overlapping memory slots.
        kvm_context.max_memslots = 1;
        let gm = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0x0), 0x1000),
            (GuestAddress(0x1001), 0x2000),
        ])
        .unwrap();
        assert!(vm.memory_init(&gm, kvm_context.max_memslots()).is_err());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_configure_vcpu() {
        let (_vm, mut vcpu, vm_mem) = setup_vcpu(0x10000);

        let mut vcpu_config = VcpuConfig {
            vcpu_count: 1,
            ht_enabled: false,
            cpu_template: None,
            nested_enabled: false,
        };

        assert!(
            vcpu.configure_x86_64(&vm_mem, GuestAddress(0), &vcpu_config, true, false)
                .is_ok()
        );

        // PortableV1 must select the state contract used by checkpoint capture.
        vcpu_config.cpu_template = Some(CpuFeaturesTemplate::PortableV1);
        assert!(
            vcpu.configure_x86_64(&vm_mem, GuestAddress(0), &vcpu_config, true, false)
                .is_ok()
        );
        assert!(vcpu.portable_cpu);

        // Test configure while using the T2 template.
        vcpu_config.cpu_template = Some(CpuFeaturesTemplate::T2);
        assert!(
            vcpu.configure_x86_64(&vm_mem, GuestAddress(0), &vcpu_config, true, false)
                .is_ok()
        );

        // Test configure while using the C3 template.
        vcpu_config.cpu_template = Some(CpuFeaturesTemplate::C3);
        assert!(
            vcpu.configure_x86_64(&vm_mem, GuestAddress(0), &vcpu_config, true, false)
                .is_ok()
        );
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_configure_vcpu() {
        let kvm = KvmContext::new().unwrap();
        let vm_resources = VmResources::default();
        let (guest_memory, arch_memory_info, _shm_manager, _payload_config) =
            create_guest_memory(128, &vm_resources, &Payload::Empty).unwrap();
        let mut vm = Vm::new(kvm.fd()).expect("new vm failed");
        assert!(vm.memory_init(&guest_memory, kvm.max_memslots()).is_ok());

        // Try it for when vcpu id is 0.
        let mut vcpu = Vcpu::new_aarch64(
            0,
            vm.fd(),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();

        assert!(
            vcpu.configure_aarch64(vm.fd(), &arch_memory_info, GuestAddress(0))
                .is_ok()
        );

        // Try it for when vcpu id is NOT 0.
        let mut vcpu = Vcpu::new_aarch64(
            1,
            vm.fd(),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();

        assert!(
            vcpu.configure_aarch64(vm.fd(), &arch_memory_info, GuestAddress(0))
                .is_ok()
        );
    }

    #[test]
    fn test_vcpu_tls() {
        let (_, mut vcpu, _) = setup_vcpu(0x1000);

        // Running on the TLS vcpu should fail before we actually initialize it.
        unsafe {
            assert!(Vcpu::run_on_thread_local(|_| ()).is_err());
        }

        // Initialize vcpu TLS.
        vcpu.init_thread_local_data().unwrap();

        // Validate TLS vcpu is the local vcpu by changing the `id` then validating against
        // the one in TLS.
        vcpu.id = 12;
        unsafe {
            assert!(Vcpu::run_on_thread_local(|v| assert_eq!(v.id, 12)).is_ok());
        }

        // Reset vcpu TLS.
        assert!(vcpu.reset_thread_local_data().is_ok());

        // Running on the TLS vcpu after TLS reset should fail.
        unsafe {
            assert!(Vcpu::run_on_thread_local(|_| ()).is_err());
        }

        // Second reset should return error.
        assert!(vcpu.reset_thread_local_data().is_err());
    }

    #[test]
    fn test_invalid_tls() {
        let (_, mut vcpu, _) = setup_vcpu(0x1000);
        // Initialize vcpu TLS.
        vcpu.init_thread_local_data().unwrap();
        // Trying to initialize non-empty TLS should error.
        vcpu.init_thread_local_data().unwrap_err();
    }

    #[test]
    fn test_vcpu_kick() {
        Vcpu::register_kick_signal_handler();
        let (vm, mut vcpu, _mem) = setup_vcpu(0x1000);

        let mut kvm_run =
            KvmRunWrapper::mmap_from_fd(&vcpu.fd, vm.fd.run_size()).expect("cannot mmap kvm-run");
        let success = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let vcpu_success = success.clone();
        let barrier = Arc::new(Barrier::new(2));
        let vcpu_barrier = barrier.clone();
        // Start Vcpu thread which will be kicked with a signal.
        let handle = std::thread::Builder::new()
            .name("test_vcpu_kick".to_string())
            .spawn(move || {
                vcpu.init_thread_local_data().unwrap();
                // Notify TLS was populated.
                vcpu_barrier.wait();
                // Loop for max 1 second to check if the signal handler has run.
                for _ in 0..10 {
                    if kvm_run.as_mut_ref().immediate_exit == 1 {
                        // Signal handler has run and set immediate_exit to 1.
                        vcpu_success.store(true, Ordering::Release);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            })
            .expect("cannot start thread");

        // Wait for the vcpu to initialize its TLS.
        barrier.wait();
        // Kick the Vcpu using the custom signal.
        handle
            .kill(sigrtmin() + VCPU_RTSIG_OFFSET)
            .expect("failed to signal thread");
        handle.join().expect("failed to join thread");
        // Verify that the Vcpu saw its kvm immediate-exit as set.
        assert!(success.load(Ordering::Acquire));
    }

    #[test]
    fn test_vcpu_rtsig_offset() {
        assert!(validate_signal_num(sigrtmin() + VCPU_RTSIG_OFFSET).is_ok());
    }

    // Checkpoint/restore: a freshly-started vCPU thread sits in the Paused
    // state, so we can drive SaveState/RestoreState over the event channel.
    // This exercises the real KVM GET ioctls (save_state) and SET ioctls
    // (restore_state) end-to-end through the new channel protocol.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_vcpu_save_restore_state_roundtrip() {
        Vcpu::register_kick_signal_handler();
        let (_vm, vcpu, _mem) = setup_vcpu(0x1000);
        let handle = vcpu.start_threaded().expect("failed to start vcpu thread");

        handle
            .send_event(VcpuEvent::SaveState)
            .expect("failed to send SaveState");
        let state = match handle
            .response_receiver()
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("no response to SaveState")
        {
            VcpuResponse::SavedState(state) => state,
            other => panic!("expected SavedState, got {other:?}"),
        };

        // Round-trip the captured state through the binary snapshot format and
        // restore the *deserialized* copy, proving the file encoding is faithful
        // and that the result is a KVM-acceptable register state.
        let blob = state.serialize();
        assert!(!blob.is_empty(), "serialized vcpu state must be non-empty");
        let restored = VcpuState::deserialize(&blob).expect("failed to deserialize vcpu state");

        handle
            .send_event(VcpuEvent::RestoreState(Box::new(restored)))
            .expect("failed to send RestoreState");
        match handle
            .response_receiver()
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("no response to RestoreState")
        {
            VcpuResponse::RestoredState => {}
            other => panic!("expected RestoredState, got {other:?}"),
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_rebased_tsc_offset_preserves_epoch() {
        let source_offset = 10_000_u64;
        let khz = 2_400_000_u32;
        let source_guest_ns = 5_000_000_000_u64;
        let destination_guest_ns = 5_250_000_000_u64;
        let source_host_tsc = 20_000_000_000_u64;
        let destination_host_tsc = 31_000_000_000_u64;

        let destination_offset = rebased_tsc_offset(
            source_offset,
            khz,
            source_guest_ns,
            destination_guest_ns,
            source_host_tsc,
            destination_host_tsc,
        );

        let source_epoch = source_offset
            .wrapping_add(source_host_tsc)
            .wrapping_sub(source_guest_ns.wrapping_mul(u64::from(khz)) / 1_000_000);
        let destination_epoch = destination_offset
            .wrapping_add(destination_host_tsc)
            .wrapping_sub(destination_guest_ns.wrapping_mul(u64::from(khz)) / 1_000_000);
        assert_eq!(destination_epoch, source_epoch);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_rebased_tsc_offset_is_unchanged_for_same_clock_sample() {
        assert_eq!(rebased_tsc_offset(42, 3_000_000, 100, 100, 200, 200), 42);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_advance_tsc_uses_guest_frequency() {
        assert_eq!(advance_tsc(100, 250_000_000, 2_400_000), 600_000_100);
        assert_eq!(advance_tsc(600_000_100, -250_000_000, 2_400_000), 100);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_portable_clock_allows_absolute_tsc_fallback() {
        let realtime_only = kvm_clock_data {
            flags: KVM_CLOCK_REALTIME,
            ..Default::default()
        };
        assert!(validate_migration_clock_realtime(&realtime_only, "source").is_ok());

        let missing_realtime = kvm_clock_data::default();
        assert!(validate_migration_clock_realtime(&missing_realtime, "source").is_err());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_realtime_midpoint_is_bounded() {
        assert_eq!(bounded_realtime_midpoint(1_000, 1_100).unwrap(), 1_050);
        assert!(bounded_realtime_midpoint(1_100, 1_000).is_err());
        assert!(bounded_realtime_midpoint(0, 100_000_001).is_err());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_portable_msr_filter_matches_masked_cpu_features() {
        assert!(!portable_msr_should_serialize(0x0d90));
        for index in 0x01d9..=0x01de {
            assert!(!portable_msr_should_serialize(index));
        }
        assert!(portable_msr_should_serialize(0x10));
        assert!(portable_msr_should_serialize(0x4b56_4d01));
    }
}
