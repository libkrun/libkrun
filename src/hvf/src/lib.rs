// Copyright 2021 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

#[allow(non_camel_case_types)]
#[allow(improper_ctypes)]
#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[allow(deref_nullptr)]
pub mod bindings;

#[macro_use]
extern crate log;

use bindings::*;

#[cfg(target_arch = "aarch64")]
use std::arch::asm;

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::time::Duration;

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use arch::aarch64::sysreg::{SYSREG_MASK, sys_reg_name};
use log::debug;

unsafe extern "C" {
    pub fn mach_absolute_time() -> u64;
}

const HV_EXIT_REASON_CANCELED: hv_exit_reason_t = 0;
const HV_EXIT_REASON_EXCEPTION: hv_exit_reason_t = 1;
const HV_EXIT_REASON_VTIMER_ACTIVATED: hv_exit_reason_t = 2;

const TMR_CTL_ENABLE: u64 = 1 << 0;
const TMR_CTL_IMASK: u64 = 1 << 1;
const TMR_CTL_ISTATUS: u64 = 1 << 2;

const PSR_MODE_EL1H: u64 = 0x0000_0005;
const PSR_MODE_EL2H: u64 = 0x0000_0009;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;
const PSTATE_EL1_FAULT_BITS_64: u64 = PSR_MODE_EL1H | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;
const PSTATE_EL2_FAULT_BITS_64: u64 = PSR_MODE_EL2H | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;

const HCR_TLOR: u64 = 1 << 35;
const HCR_RW: u64 = 1 << 31;
const HCR_TSW: u64 = 1 << 22;
const HCR_TACR: u64 = 1 << 21;
const HCR_TIDCP: u64 = 1 << 20;
const HCR_TSC: u64 = 1 << 19;
const HCR_TID3: u64 = 1 << 18;
const HCR_TWE: u64 = 1 << 14;
const HCR_TWI: u64 = 1 << 13;
const HCR_BSU_IS: u64 = 1 << 10;
const HCR_FB: u64 = 1 << 9;
const HCR_AMO: u64 = 1 << 5;
const HCR_IMO: u64 = 1 << 4;
const HCR_FMO: u64 = 1 << 3;
const HCR_PTW: u64 = 1 << 2;
const HCR_SWIO: u64 = 1 << 1;
const HCR_VM: u64 = 1 << 0;
// Use the same bits as KVM uses in vcpu reset.
const HCR_EL2_BITS: u64 = HCR_TSC
    | HCR_TSW
    | HCR_TWE
    | HCR_TWI
    | HCR_VM
    | HCR_BSU_IS
    | HCR_FB
    | HCR_TACR
    | HCR_AMO
    | HCR_SWIO
    | HCR_TIDCP
    | HCR_RW
    | HCR_TLOR
    | HCR_FMO
    | HCR_IMO
    | HCR_PTW
    | HCR_TID3;

const CNTHCTL_EL0VCTEN: u64 = 1 << 1;
const CNTHCTL_EL0PCTEN: u64 = 1 << 0;
// Trap accesses to both virtual and physical counter registers.
const CNTHCTL_EL2_BITS: u64 = CNTHCTL_EL0VCTEN | CNTHCTL_EL0PCTEN;

const AA64PFR0_EL1_EL2EN: u64 = 1 << 8;
const AA64PFR0_EL1_GIC3EN: u64 = 1 << 24;
const AA64PFR1_EL1_SMEMASK: u64 = 3 << 24;

const EC_WFX_TRAP: u64 = 0x1;
const EC_AA64_HVC: u64 = 0x16;
const EC_AA64_SMC: u64 = 0x17;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
const EC_SYSTEMREGISTERTRAP: u64 = 0x18;
const EC_DATAABORT: u64 = 0x24;
const EC_AA64_BKPT: u64 = 0x3c;

#[derive(Debug)]
pub enum Error {
    EnableEL2,
    FindSymbol(libloading::Error),
    MemoryMap,
    MemoryUnmap,
    NestedCheck,
    VcpuCreate,
    VcpuInitialRegisters,
    VcpuReadRegister,
    VcpuReadSystemRegister,
    VcpuRequestExit,
    VcpuRun,
    VcpuSetPendingIrq,
    VcpuSetRegister,
    VcpuSetSystemRegister(u16, u64),
    VcpuSetVtimerMask,
    VcpuGetVtimerOffset,
    VcpuSetVtimerOffset,
    VmCreate,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            EnableEL2 => write!(f, "Error enabling EL2 mode in HVF"),
            FindSymbol(err) => write!(f, "Couldn't find symbol in HVF library: {err}"),
            MemoryMap => write!(f, "Error registering memory region in HVF"),
            MemoryUnmap => write!(f, "Error unregistering memory region in HVF"),
            NestedCheck => write!(
                f,
                "Nested virtualization was requested but it's not support in this system"
            ),
            VcpuCreate => write!(f, "Error creating HVF vCPU instance"),
            VcpuInitialRegisters => write!(f, "Error setting up initial HVF vCPU registers"),
            VcpuReadRegister => write!(f, "Error reading HVF vCPU register"),
            VcpuReadSystemRegister => write!(f, "Error reading HVF vCPU system register"),
            VcpuRequestExit => write!(f, "Error requesting HVF vCPU exit"),
            VcpuRun => write!(f, "Error running HVF vCPU"),
            VcpuSetPendingIrq => write!(f, "Error setting HVF vCPU pending irq"),
            VcpuSetRegister => write!(f, "Error setting HVF vCPU register"),
            VcpuSetSystemRegister(reg, val) => write!(
                f,
                "Error setting HVF vCPU system register 0x{reg:#x} to 0x{val:#x}"
            ),
            VcpuSetVtimerMask => write!(f, "Error setting HVF vCPU vtimer mask"),
            VcpuGetVtimerOffset => write!(f, "Error getting HVF vCPU vtimer offset"),
            VcpuSetVtimerOffset => write!(f, "Error setting HVF vCPU vtimer offset"),
            VmCreate => write!(f, "Error creating HVF VM instance"),
        }
    }
}

pub enum InterruptType {
    Irq,
    Fiq,
}

pub trait Vcpus {
    fn set_vtimer_irq(&self, vcpuid: u64);
    fn should_wait(&self, vcpuid: u64) -> bool;
    fn has_pending_irq(&self, vcpuid: u64) -> bool;
    fn get_pending_irq(&self, vcpuid: u64) -> u32;
    fn handle_sysreg_read(&self, vcpuid: u64, reg: u32) -> Option<u64>;
    fn handle_sysreg_write(&self, vcpuid: u64, reg: u32, val: u64) -> bool;
}

pub fn vcpu_request_exit(vcpuid: u64) -> Result<(), Error> {
    let mut vcpu: u64 = vcpuid;
    let ret = unsafe { hv_vcpus_exit(&mut vcpu, 1) };

    if ret != HV_SUCCESS {
        Err(Error::VcpuRequestExit)
    } else {
        Ok(())
    }
}

pub fn vcpu_set_pending_irq(
    vcpuid: u64,
    irq_type: InterruptType,
    pending: bool,
) -> Result<(), Error> {
    let _type = match irq_type {
        InterruptType::Irq => hv_interrupt_type_t_HV_INTERRUPT_TYPE_IRQ,
        InterruptType::Fiq => hv_interrupt_type_t_HV_INTERRUPT_TYPE_FIQ,
    };

    let ret = unsafe { hv_vcpu_set_pending_interrupt(vcpuid, _type, pending) };

    if ret != HV_SUCCESS {
        Err(Error::VcpuSetPendingIrq)
    } else {
        Ok(())
    }
}

pub fn vcpu_set_vtimer_mask(vcpuid: u64, masked: bool) -> Result<(), Error> {
    let ret = unsafe { hv_vcpu_set_vtimer_mask(vcpuid, masked) };

    if ret != HV_SUCCESS {
        Err(Error::VcpuSetVtimerMask)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub fn vcpu_adjust_vtimer_offset(vcpuid: u64, delta_ns: u64) -> Result<(), Error> {
    if delta_ns == 0 {
        return Ok(());
    }

    // hv_vcpu_get/set_vtimer_offset works with CNTVOFF_EL2 in raw counter ticks.
    // Read the host timer frequency to convert nanoseconds to ticks.
    // virtual_counter = physical_counter - offset, so adding delta_ticks compensates
    // for the physical counter advancing during pause (freeze semantics).
    // CNTFRQ_EL0 is an AArch64 system register; the `mrs` only assembles on
    // aarch64. The `hvf` crate is an unconditional dependency and is compiled on
    // non-arm64 hosts too (where this fn is never called — those hosts use KVM),
    // so gate the asm to keep the build portable.
    let cntfrq: u64;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) cntfrq)
    };
    #[cfg(not(target_arch = "aarch64"))]
    {
        cntfrq = 0;
    }

    let mut offset = 0_u64;
    let ret = unsafe { hv_vcpu_get_vtimer_offset(vcpuid, &mut offset) };
    if ret != HV_SUCCESS {
        return Err(Error::VcpuGetVtimerOffset);
    }

    let delta_ticks = ((delta_ns as u128) * (cntfrq as u128) / 1_000_000_000)
        .try_into()
        .unwrap_or(u64::MAX);
    let new_offset = offset.saturating_add(delta_ticks);
    let ret = unsafe { hv_vcpu_set_vtimer_offset(vcpuid, new_offset) };
    if ret != HV_SUCCESS {
        Err(Error::VcpuSetVtimerOffset)
    } else {
        Ok(())
    }
}

/// Captured aarch64 vCPU register state for HVF checkpoint/restore — the macOS
/// analogue of KVM's `VcpuState`. Holds the general-purpose registers, program
/// state, NEON/FP registers, and the writable EL1 system registers that define
/// guest execution + MMU state. Read-only ID registers, EL2 (VMM-managed)
/// state, and debug breakpoints are intentionally excluded. The virtual-timer
/// *offset* (`CNTVOFF`) IS captured (see [`HvfVcpuState::vtimer_offset`]): an
/// in-process pause/resume keeps the live vCPU's offset and only nudges it via
/// [`vcpu_adjust_vtimer_offset`], but a cross-process fork builds a fresh
/// `hv_vcpu` with an unrelated default offset, so the absolute offset must be
/// restored or the guest clock jumps on resume.
#[derive(Clone, Debug)]
pub struct HvfVcpuState {
    /// X0..X30.
    pub gp: [u64; 31],
    /// Program counter.
    pub pc: u64,
    /// Processor state (CPSR/PSTATE).
    pub cpsr: u64,
    /// FP control register.
    pub fpcr: u64,
    /// FP status register.
    pub fpsr: u64,
    /// NEON/FP registers Q0..Q31 (128-bit each).
    pub simd: [u128; 32],
    /// Writable EL1 system registers as (hv_sys_reg_t, value) pairs.
    pub sys: Vec<(u16, u64)>,
    /// This vCPU's GIC redistributor registers (SGI/PPI group/enable/priority/
    /// config/pending/active) as (hv_gic_redistributor_reg_t, value) pairs.
    pub gic_redist: Vec<(u32, u64)>,
    /// This vCPU's GIC CPU-interface (ICC) registers (PMR/BPR/CTLR/SRE/IGRPEN…)
    /// as (hv_gic_icc_reg_t, value) pairs. Without these the restored vCPU's
    /// interrupt interface is in reset state and the guest is never woken from
    /// WFI by a device IRQ.
    pub gic_icc: Vec<(u32, u64)>,
    /// Virtual-timer offset (`CNTVOFF`, raw counter ticks): `virtual_counter =
    /// physical_counter - offset`. Captured so a cross-process fork clone — whose
    /// vCPU is a fresh `hv_vcpu` with an unrelated default offset — restores the
    /// guest's virtual counter to continue from the snapshot. The offset is
    /// relative to the host physical counter, which is a single hardware counter
    /// shared across all processes, so applying the golden's offset to the clone
    /// makes the guest clock continue seamlessly (golden time + real fork
    /// elapsed). Without it the guest `CLOCK_MONOTONIC` jumps on resume and
    /// time-based guest code (e.g. the agent's deadline loops) wedges, so the
    /// guest accepts vsock connections at the kernel level but never replies.
    pub vtimer_offset: u64,
}

/// GIC redistributor registers captured per-vCPU (offsets == `hv_gic_redistributor_reg_t`).
/// Config (group/priority/cfg) is restored before enable/pending/active state.
#[cfg(target_arch = "aarch64")]
const GIC_REDIST_REGS: &[u32] = &[
    65664, // GICR_IGROUPR0
    66560, 66564, 66568, 66572, 66576, 66580, 66584, 66588, // GICR_IPRIORITYR0..7
    68608, 68612, // GICR_ICFGR0..1
    65792, // GICR_ISENABLER0
    66048, // GICR_ISPENDR0
    66304, // GICR_ISACTIVER0
];

/// Runtime-resolved GIC register accessors. The Hypervisor framework does not
/// export the `hv_gic_*` symbols for static linking on this platform (arm64
/// chained fixups would fail to bind them at dylib load → SIGKILL), so — like
/// [`crate::HvfGicV3`] — they are looked up via `dlsym` at runtime.
#[cfg(target_arch = "aarch64")]
struct GicRegBindings {
    get_dist: libloading::Symbol<'static, unsafe extern "C" fn(u16, *mut u64) -> hv_return_t>,
    set_dist: libloading::Symbol<'static, unsafe extern "C" fn(u16, u64) -> hv_return_t>,
    get_redist:
        libloading::Symbol<'static, unsafe extern "C" fn(u64, u32, *mut u64) -> hv_return_t>,
    set_redist: libloading::Symbol<'static, unsafe extern "C" fn(u64, u32, u64) -> hv_return_t>,
    get_icc: libloading::Symbol<'static, unsafe extern "C" fn(u64, u16, *mut u64) -> hv_return_t>,
    set_icc: libloading::Symbol<'static, unsafe extern "C" fn(u64, u16, u64) -> hv_return_t>,
}

#[cfg(target_arch = "aarch64")]
static GIC_REGS: LazyLock<GicRegBindings> = LazyLock::new(|| unsafe {
    GicRegBindings {
        get_dist: HVF
            .get(b"hv_gic_get_distributor_reg")
            .expect("hv_gic_get_distributor_reg"),
        set_dist: HVF
            .get(b"hv_gic_set_distributor_reg")
            .expect("hv_gic_set_distributor_reg"),
        get_redist: HVF
            .get(b"hv_gic_get_redistributor_reg")
            .expect("hv_gic_get_redistributor_reg"),
        set_redist: HVF
            .get(b"hv_gic_set_redistributor_reg")
            .expect("hv_gic_set_redistributor_reg"),
        get_icc: HVF.get(b"hv_gic_get_icc_reg").expect("hv_gic_get_icc_reg"),
        set_icc: HVF.get(b"hv_gic_set_icc_reg").expect("hv_gic_set_icc_reg"),
    }
});

/// GIC CPU-interface (ICC) registers captured per-vCPU (values == `hv_gic_icc_reg_t`).
/// SRE first (enables sysreg access), group-enables last.
#[cfg(target_arch = "aarch64")]
const GIC_ICC_REGS: &[u32] = &[
    50789, // ICC_SRE_EL1   (first)
    49712, // ICC_PMR_EL1
    50755, // ICC_BPR0_EL1
    50787, // ICC_BPR1_EL1
    50756, // ICC_AP0R0_EL1
    50760, // ICC_AP1R0_EL1
    50788, // ICC_CTLR_EL1
    50790, // ICC_IGRPEN0_EL1 (enable LAST)
    50791, // ICC_IGRPEN1_EL1 (enable LAST)
];

impl HvfVcpuState {
    /// Serialize to a self-describing little-endian byte blob for cross-process
    /// fork / on-disk checkpoint. No cross-version compatibility promised.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for &g in &self.gp {
            out.extend_from_slice(&g.to_le_bytes());
        }
        out.extend_from_slice(&self.pc.to_le_bytes());
        out.extend_from_slice(&self.cpsr.to_le_bytes());
        out.extend_from_slice(&self.fpcr.to_le_bytes());
        out.extend_from_slice(&self.fpsr.to_le_bytes());
        for &q in &self.simd {
            out.extend_from_slice(&q.to_le_bytes());
        }
        out.extend_from_slice(&(self.sys.len() as u32).to_le_bytes());
        for &(reg, val) in &self.sys {
            out.extend_from_slice(&reg.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        out.extend_from_slice(&(self.gic_redist.len() as u32).to_le_bytes());
        for &(reg, val) in &self.gic_redist {
            out.extend_from_slice(&reg.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        out.extend_from_slice(&(self.gic_icc.len() as u32).to_le_bytes());
        for &(reg, val) in &self.gic_icc {
            out.extend_from_slice(&reg.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        out.extend_from_slice(&self.vtimer_offset.to_le_bytes());
        out
    }

    /// Reconstruct from a blob produced by [`Self::serialize`].
    pub fn deserialize(bytes: &[u8]) -> std::result::Result<HvfVcpuState, String> {
        let mut pos = 0usize;
        let take = |b: &[u8], pos: &mut usize, n: usize| -> std::result::Result<Vec<u8>, String> {
            if *pos + n > b.len() {
                return Err("HvfVcpuState blob truncated".to_string());
            }
            let s = b[*pos..*pos + n].to_vec();
            *pos += n;
            Ok(s)
        };
        let u64_at = |b: &[u8], pos: &mut usize| -> std::result::Result<u64, String> {
            Ok(u64::from_le_bytes(take(b, pos, 8)?.try_into().unwrap()))
        };
        let mut gp = [0u64; 31];
        for slot in gp.iter_mut() {
            *slot = u64_at(bytes, &mut pos)?;
        }
        let pc = u64_at(bytes, &mut pos)?;
        let cpsr = u64_at(bytes, &mut pos)?;
        let fpcr = u64_at(bytes, &mut pos)?;
        let fpsr = u64_at(bytes, &mut pos)?;
        let mut simd = [0u128; 32];
        for slot in simd.iter_mut() {
            *slot = u128::from_le_bytes(take(bytes, &mut pos, 16)?.try_into().unwrap());
        }
        let n = u32::from_le_bytes(take(bytes, &mut pos, 4)?.try_into().unwrap()) as usize;
        let mut sys = Vec::with_capacity(n);
        for _ in 0..n {
            let reg = u16::from_le_bytes(take(bytes, &mut pos, 2)?.try_into().unwrap());
            let val = u64_at(bytes, &mut pos)?;
            sys.push((reg, val));
        }
        let read_u32_pairs =
            |bytes: &[u8], pos: &mut usize| -> std::result::Result<Vec<(u32, u64)>, String> {
                let n = u32::from_le_bytes(take(bytes, pos, 4)?.try_into().unwrap()) as usize;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let reg = u32::from_le_bytes(take(bytes, pos, 4)?.try_into().unwrap());
                    let val = u64::from_le_bytes(take(bytes, pos, 8)?.try_into().unwrap());
                    v.push((reg, val));
                }
                Ok(v)
            };
        let gic_redist = read_u32_pairs(bytes, &mut pos)?;
        let gic_icc = read_u32_pairs(bytes, &mut pos)?;
        // Trailing field; tolerate older blobs that predate it (default 0 → no
        // offset, the prior behavior).
        let vtimer_offset = if pos < bytes.len() {
            u64_at(bytes, &mut pos)?
        } else {
            0
        };
        Ok(HvfVcpuState {
            gp,
            pc,
            cpsr,
            fpcr,
            fpsr,
            simd,
            sys,
            gic_redist,
            gic_icc,
            vtimer_offset,
        })
    }
}

/// The writable EL1 system registers captured/restored for a faithful guest
/// state snapshot (MMU config, exception state, thread pointers, etc.).
#[cfg(target_arch = "aarch64")]
const SNAPSHOT_SYS_REGS: &[u16] = &[
    hv_sys_reg_t_HV_SYS_REG_SP_EL0,
    hv_sys_reg_t_HV_SYS_REG_SP_EL1,
    hv_sys_reg_t_HV_SYS_REG_ELR_EL1,
    hv_sys_reg_t_HV_SYS_REG_SPSR_EL1,
    hv_sys_reg_t_HV_SYS_REG_SCTLR_EL1,
    hv_sys_reg_t_HV_SYS_REG_TCR_EL1,
    hv_sys_reg_t_HV_SYS_REG_TTBR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_TTBR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_MAIR_EL1,
    hv_sys_reg_t_HV_SYS_REG_AMAIR_EL1,
    hv_sys_reg_t_HV_SYS_REG_VBAR_EL1,
    hv_sys_reg_t_HV_SYS_REG_CONTEXTIDR_EL1,
    hv_sys_reg_t_HV_SYS_REG_TPIDR_EL0,
    hv_sys_reg_t_HV_SYS_REG_TPIDR_EL1,
    hv_sys_reg_t_HV_SYS_REG_TPIDRRO_EL0,
    hv_sys_reg_t_HV_SYS_REG_CPACR_EL1,
    hv_sys_reg_t_HV_SYS_REG_AFSR0_EL1,
    hv_sys_reg_t_HV_SYS_REG_AFSR1_EL1,
    hv_sys_reg_t_HV_SYS_REG_ESR_EL1,
    hv_sys_reg_t_HV_SYS_REG_FAR_EL1,
    hv_sys_reg_t_HV_SYS_REG_PAR_EL1,
    hv_sys_reg_t_HV_SYS_REG_CSSELR_EL1,
    hv_sys_reg_t_HV_SYS_REG_ACTLR_EL1,
    hv_sys_reg_t_HV_SYS_REG_MDSCR_EL1,
    // Virtual-timer compare + control + EL1 timer access. A cross-process fork
    // builds a fresh vCPU whose timer registers are at reset, so the guest's
    // per-CPU scheduler tick (armed via CNTV_CVAL_EL0 + CNTV_CTL_EL0) would never
    // fire after resume — the guest services device IRQs but never schedules
    // userspace, so the agent accepts vsock connections at the kernel level but
    // never runs to reply. Restored alongside CNTVOFF (see vtimer_offset) so the
    // armed deadline lines up with the continued virtual counter. CVAL before
    // CTL so the compare is set before the timer is (re-)enabled.
    hv_sys_reg_t_HV_SYS_REG_CNTKCTL_EL1,
    hv_sys_reg_t_HV_SYS_REG_CNTV_CVAL_EL0,
    hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0,
    // Pointer-authentication keys (per-boot/per-task secrets). The guest signs
    // return addresses with these and authenticates them with AUTIASP/AUTIBSP;
    // if a restored clone has different keys, the first authentication faults
    // (FPAC) and the kernel panics ("Attempted to kill the idle task"). They
    // must be captured + restored so signed pointers remain valid.
    hv_sys_reg_t_HV_SYS_REG_APIAKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APIAKEYHI_EL1,
    hv_sys_reg_t_HV_SYS_REG_APIBKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APIBKEYHI_EL1,
    hv_sys_reg_t_HV_SYS_REG_APDAKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APDAKEYHI_EL1,
    hv_sys_reg_t_HV_SYS_REG_APDBKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APDBKEYHI_EL1,
    hv_sys_reg_t_HV_SYS_REG_APGAKEYLO_EL1,
    hv_sys_reg_t_HV_SYS_REG_APGAKEYHI_EL1,
];

/// Capture the full register state of a (paused) HVF vCPU by its id. The macOS
/// adapter mirroring KVM's `Vcpu::save_state`; see [`HvfVcpuState`].
#[cfg(target_arch = "aarch64")]
pub fn vcpu_save_state(vcpuid: u64) -> Result<HvfVcpuState, Error> {
    let mut gp = [0u64; 31];
    for (i, slot) in gp.iter_mut().enumerate() {
        let mut v = 0u64;
        let ret = unsafe { hv_vcpu_get_reg(vcpuid, hv_reg_t_HV_REG_X0 + i as u32, &mut v) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuReadRegister);
        }
        *slot = v;
    }
    let read_reg = |reg: u32| -> Result<u64, Error> {
        let mut v = 0u64;
        let ret = unsafe { hv_vcpu_get_reg(vcpuid, reg, &mut v) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuReadRegister)
        } else {
            Ok(v)
        }
    };
    let pc = read_reg(hv_reg_t_HV_REG_PC)?;
    let cpsr = read_reg(hv_reg_t_HV_REG_CPSR)?;
    let fpcr = read_reg(hv_reg_t_HV_REG_FPCR)?;
    let fpsr = read_reg(hv_reg_t_HV_REG_FPSR)?;

    let mut simd = [0u128; 32];
    for (i, slot) in simd.iter_mut().enumerate() {
        let mut v: hv_simd_fp_uchar16_t = 0;
        let ret = unsafe {
            hv_vcpu_get_simd_fp_reg(
                vcpuid,
                hv_simd_fp_reg_t_HV_SIMD_FP_REG_Q0 + i as u32,
                &mut v,
            )
        };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuReadRegister);
        }
        *slot = v;
    }

    let mut sys = Vec::with_capacity(SNAPSHOT_SYS_REGS.len());
    for &reg in SNAPSHOT_SYS_REGS {
        let mut v = 0u64;
        let ret = unsafe { hv_vcpu_get_sys_reg(vcpuid, reg, &mut v) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuReadSystemRegister);
        }
        sys.push((reg, v));
    }

    // Per-vCPU GIC state: redistributor (SGI/PPI) + CPU interface (ICC). Must be
    // read on the owning vCPU thread (this fn runs there via the SaveState event).
    let mut gic_redist = Vec::with_capacity(GIC_REDIST_REGS.len());
    for &reg in GIC_REDIST_REGS {
        let mut v = 0u64;
        let ret = unsafe { (GIC_REGS.get_redist)(vcpuid, reg, &mut v) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuReadSystemRegister);
        }
        gic_redist.push((reg, v));
    }
    let mut gic_icc = Vec::with_capacity(GIC_ICC_REGS.len());
    for &reg in GIC_ICC_REGS {
        let mut v = 0u64;
        let ret = unsafe { (GIC_REGS.get_icc)(vcpuid, reg as u16, &mut v) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuReadSystemRegister);
        }
        gic_icc.push((reg, v));
    }

    // Virtual-timer offset (CNTVOFF). Restored absolutely on a fork clone so the
    // guest's virtual counter continues from the snapshot (see HvfVcpuState).
    let mut vtimer_offset = 0u64;
    let ret = unsafe { hv_vcpu_get_vtimer_offset(vcpuid, &mut vtimer_offset) };
    if ret != HV_SUCCESS {
        return Err(Error::VcpuGetVtimerOffset);
    }

    Ok(HvfVcpuState {
        gp,
        pc,
        cpsr,
        fpcr,
        fpsr,
        simd,
        sys,
        gic_redist,
        gic_icc,
        vtimer_offset,
    })
}

/// Restore previously-captured register state onto a (paused) HVF vCPU by its
/// id. The macOS adapter mirroring KVM's `Vcpu::restore_state`.
#[cfg(target_arch = "aarch64")]
pub fn vcpu_restore_state(vcpuid: u64, state: &HvfVcpuState) -> Result<(), Error> {
    // System registers first (MMU/exception config), then GP/PC/PSTATE/SIMD.
    for &(reg, val) in &state.sys {
        let ret = unsafe { hv_vcpu_set_sys_reg(vcpuid, reg, val) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuSetSystemRegister(reg, val));
        }
    }
    let write_reg = |reg: u32, val: u64| -> Result<(), Error> {
        let ret = unsafe { hv_vcpu_set_reg(vcpuid, reg, val) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuSetRegister)
        } else {
            Ok(())
        }
    };
    for (i, &v) in state.gp.iter().enumerate() {
        write_reg(hv_reg_t_HV_REG_X0 + i as u32, v)?;
    }
    write_reg(hv_reg_t_HV_REG_PC, state.pc)?;
    write_reg(hv_reg_t_HV_REG_CPSR, state.cpsr)?;
    write_reg(hv_reg_t_HV_REG_FPCR, state.fpcr)?;
    write_reg(hv_reg_t_HV_REG_FPSR, state.fpsr)?;
    for (i, &v) in state.simd.iter().enumerate() {
        let ret = unsafe {
            hv_vcpu_set_simd_fp_reg(vcpuid, hv_simd_fp_reg_t_HV_SIMD_FP_REG_Q0 + i as u32, v)
        };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuSetRegister);
        }
    }
    // Per-vCPU GIC state. The captured order is config-before-enable (redist
    // ISENABLER0 last; ICC SRE first, IGRPEN last), so replay in order.
    for &(reg, val) in &state.gic_redist {
        let ret = unsafe { (GIC_REGS.set_redist)(vcpuid, reg, val) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuSetSystemRegister(0, val));
        }
    }
    for &(reg, val) in &state.gic_icc {
        let ret = unsafe { (GIC_REGS.set_icc)(vcpuid, reg as u16, val) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuSetSystemRegister(0, val));
        }
    }
    // Restore the virtual-timer offset so the clone's guest virtual counter
    // continues from the snapshot. Set absolutely (not via
    // `vcpu_adjust_vtimer_offset`, which only nudges an existing offset by a delta
    // and is a no-op on the delta==0 fork path) — a fresh fork clone's `hv_vcpu`
    // has an unrelated default offset, so without this the guest clock jumps on
    // resume and time-based guest code hangs. See [`HvfVcpuState::vtimer_offset`].
    let ret = unsafe { hv_vcpu_set_vtimer_offset(vcpuid, state.vtimer_offset) };
    if ret != HV_SUCCESS {
        return Err(Error::VcpuSetVtimerOffset);
    }
    Ok(())
}

/// Capture the global GIC distributor state (interrupt group/priority/config,
/// SPI routing, enable, pending, and active bits) for fork. Returns
/// (reg-offset, value) pairs;
/// `gic_restore_distributor` replays them with `GICD_CTLR` written last. The
/// distributor is global (not per-vCPU), so this may run on any thread.
#[cfg(target_arch = "aarch64")]
pub fn gic_save_distributor() -> Result<Vec<(u32, u64)>, Error> {
    // Read GICD_TYPER (offset 4) to learn how many interrupt lines the GIC
    // actually implements; reading per-IRQ registers beyond that range faults
    // HVF. ITLinesNumber (bits [4:0]) ⇒ num_irqs = 32*(ITLinesNumber+1).
    let mut typer = 0u64;
    let ret = unsafe { (GIC_REGS.get_dist)(4, &mut typer) };
    if ret != HV_SUCCESS {
        return Err(Error::VcpuReadSystemRegister);
    }
    let num_irqs = 32 * (((typer & 0x1f) as u32) + 1);

    let mut regs = Vec::new();
    for reg in gic_distributor_regs(num_irqs) {
        let mut v = 0u64;
        let ret = unsafe { (GIC_REGS.get_dist)(reg as u16, &mut v) };
        // Skip registers the GIC rejects rather than aborting the whole save.
        if ret == HV_SUCCESS {
            regs.push((reg, v));
        }
    }
    Ok(regs)
}

/// Restore distributor state captured by [`gic_save_distributor`]. Writes all
/// config/routing/enable registers first, then `GICD_CTLR` (offset 0) last so
/// the distributor is only enabled once its configuration is in place.
#[cfg(target_arch = "aarch64")]
pub fn gic_restore_distributor(regs: &[(u32, u64)]) -> Result<(), Error> {
    for &(reg, val) in regs.iter().filter(|(r, _)| *r != 0) {
        let ret = unsafe { (GIC_REGS.set_dist)(reg as u16, val) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuSetSystemRegister(0, val));
        }
    }
    if let Some(&(_, ctlr)) = regs.iter().find(|(r, _)| *r == 0) {
        let ret = unsafe { (GIC_REGS.set_dist)(0, ctlr) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuSetSystemRegister(0, ctlr));
        }
    }
    Ok(())
}

/// GIC distributor register offsets to snapshot (offset == `hv_gic_distributor_reg_t`),
/// bounded to the `num_irqs` the GIC implements (per-IRQ ranges past that fault):
/// GICD_CTLR, IGROUPR, IPRIORITYR, ICFGR, IROUTER (64-bit SPI routing, SPIs 32+),
/// ISENABLER, ISPENDR, and ISACTIVER. The set variants are replayed onto a reset
/// GIC so the saved state is installed exactly; this is required when a vCPU is
/// checkpointed inside an interrupt handler and later resumes by writing EOIR.
/// Read-only (TYPER/PIDR2) and clear registers (IC*) are excluded.
#[cfg(target_arch = "aarch64")]
fn gic_distributor_regs(num_irqs: u32) -> Vec<u32> {
    let n32 = num_irqs / 32; // 1 bit per IRQ  (IGROUPR / ISENABLER)
    let n4 = num_irqs / 4; //   8 bits per IRQ (IPRIORITYR)
    let n16 = num_irqs / 16; //  2 bits per IRQ (ICFGR)
    let mut regs = vec![0u32]; // GICD_CTLR
    regs.extend((0..n32).map(|i| 0x80 + i * 4)); // IGROUPR
    regs.extend((0..n4).map(|i| 0x400 + i * 4)); // IPRIORITYR
    regs.extend((0..n16).map(|i| 0xC00 + i * 4)); // ICFGR
    regs.extend((32..num_irqs).map(|i| 0x6000 + i * 8)); // IROUTER (SPIs only, 64-bit)
    regs.extend((0..n32).map(|i| 0x100 + i * 4)); // ISENABLER
    regs.extend((0..n32).map(|i| 0x200 + i * 4)); // ISPENDR
    regs.extend((0..n32).map(|i| 0x300 + i * 4)); // ISACTIVER
    regs
}

#[cfg(all(test, target_arch = "aarch64"))]
mod gic_snapshot_tests {
    use super::gic_distributor_regs;

    #[test]
    fn distributor_snapshot_includes_pending_and_active_state() {
        let regs = gic_distributor_regs(96);

        for offset in [0x200, 0x204, 0x208, 0x300, 0x304, 0x308] {
            assert!(regs.contains(&offset), "missing GIC register 0x{offset:x}");
        }
        assert!(
            regs.iter().position(|reg| *reg == 0x108).unwrap()
                < regs.iter().position(|reg| *reg == 0x200).unwrap()
        );
        assert!(
            regs.iter().position(|reg| *reg == 0x208).unwrap()
                < regs.iter().position(|reg| *reg == 0x300).unwrap()
        );
    }
}

/// Checks if Nested Virtualization is supported on the current system. Only
/// M3 or newer chips on macOS 15+ will satisfy the requirements.
pub fn check_nested_virt() -> Result<bool, Error> {
    type GetEL2Supported =
        libloading::Symbol<'static, unsafe extern "C" fn(*mut bool) -> hv_return_t>;

    let get_el2_supported: Result<GetEL2Supported, libloading::Error> =
        unsafe { HVF.get(b"hv_vm_config_get_el2_supported") };
    if get_el2_supported.is_err() {
        info!("cannot find hv_vm_config_get_el2_supported symbol");
        return Ok(false);
    }

    let mut el2_supported: bool = false;
    let ret = unsafe { (get_el2_supported.unwrap())(&mut el2_supported) };
    if ret != HV_SUCCESS {
        error!("hv_vm_config_get_el2_supported failed: {ret:?}");
        return Err(Error::NestedCheck);
    }

    Ok(el2_supported)
}

pub struct HvfVm {}

static HVF: LazyLock<libloading::Library> = LazyLock::new(|| unsafe {
    libloading::Library::new(
        "/System/Library/Frameworks/Hypervisor.framework/Versions/A/Hypervisor",
    )
    .unwrap()
});

impl HvfVm {
    pub fn new(nested_enabled: bool) -> Result<Self, Error> {
        let config = unsafe { hv_vm_config_create() };
        if nested_enabled {
            let set_el2_enabled: libloading::Symbol<
                'static,
                unsafe extern "C" fn(hv_vm_config_t, bool) -> hv_return_t,
            > = unsafe {
                HVF.get(b"hv_vm_config_set_el2_enabled")
                    .map_err(Error::FindSymbol)?
            };

            let ret = unsafe { (set_el2_enabled)(config, true) };
            if ret != HV_SUCCESS {
                return Err(Error::EnableEL2);
            }
        }

        let ret = unsafe { hv_vm_create(config) };

        if ret != HV_SUCCESS {
            Err(Error::VmCreate)
        } else {
            Ok(Self {})
        }
    }

    pub fn map_memory(
        &self,
        host_start_addr: u64,
        guest_start_addr: u64,
        size: u64,
    ) -> Result<(), Error> {
        let ret = unsafe {
            hv_vm_map(
                host_start_addr as *mut core::ffi::c_void,
                guest_start_addr,
                size.try_into().unwrap(),
                (HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC).into(),
            )
        };
        if ret != HV_SUCCESS {
            Err(Error::MemoryMap)
        } else {
            Ok(())
        }
    }

    pub fn unmap_memory(&self, guest_start_addr: u64, size: u64) -> Result<(), Error> {
        let ret = unsafe { hv_vm_unmap(guest_start_addr, size.try_into().unwrap()) };
        if ret != HV_SUCCESS {
            Err(Error::MemoryUnmap)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub enum VcpuExit<'a> {
    Breakpoint,
    Canceled,
    CpuOn(u64, u64, u64),
    HypervisorCall,
    MmioRead(u64, &'a mut [u8]),
    MmioWrite(u64, &'a [u8]),
    PsciHandled,
    SecureMonitorCall,
    Shutdown,
    SystemRegister,
    VtimerActivated,
    WaitForEvent,
    WaitForEventExpired,
    WaitForEventTimeout(Duration),
}

// ---- balloon free-page reclaim ------------------------------------------
//
// Guest RAM mapped into the VM with hv_vm_map is pinned by the hypervisor:
// no madvise variant releases it while the stage-2 mapping exists. To honor
// virtio-balloon free-page reports we unmap the reported range from stage-2,
// madvise the host mapping (which can now actually purge), and lazily remap
// zero-filled pages when the guest faults on the range again. The reporting
// protocol guarantees the guest does not access a reported range until the
// report is acked and makes no assumption about its contents afterwards, so
// zero-fill on refault is conformant.
//
// Safety gates: opt-in via SMOLVM_BALLOON_RECLAIM=1 and hard-disabled for
// forkable VMs (SMOLVM_FORKABLE=1), whose file-backed CoW RAM must never be
// hole-punched or unmapped underneath clones.

struct ReclaimEntry {
    host: u64,
    len: u64,
}

static RECLAIMED: OnceLock<Mutex<BTreeMap<u64, ReclaimEntry>>> = OnceLock::new();

fn reclaimed_map() -> &'static Mutex<BTreeMap<u64, ReclaimEntry>> {
    RECLAIMED.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Balloon reclaim is opt-in and never coexists with forkable (CoW-shared)
/// guest RAM.
pub fn balloon_reclaim_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("SMOLVM_BALLOON_RECLAIM").is_some_and(|v| v == "1")
            && std::env::var_os("SMOLVM_FORKABLE").is_none_or(|v| v != "1")
    })
}

fn host_page_size() -> u64 {
    static PS: OnceLock<u64> = OnceLock::new();
    *PS.get_or_init(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 })
}

/// Release a balloon-reported guest range: drop its stage-2 mapping so the
/// host pages stop being hypervisor-pinned, then let the host purge them.
/// Called from the balloon device thread; must complete before the report is
/// acked to the guest. Ranges are shrunk inward to host-page alignment (the
/// guest reports in multiples of at least 4 MiB, so edge loss is negligible).
pub fn balloon_reclaim_range(gpa: u64, host_addr: u64, len: u64) {
    let ps = host_page_size();
    let start = (gpa + ps - 1) & !(ps - 1);
    let end = (gpa + len) & !(ps - 1);
    if end <= start {
        return;
    }
    let host = host_addr + (start - gpa);
    let alen = end - start;

    // The lock is held across unmap/insert so a concurrent vCPU refault of a
    // neighboring entry serializes with us.
    let mut map = reclaimed_map().lock().unwrap();
    // Entries are disjoint; refuse a report overlapping an outstanding entry
    // (double hv_vm_unmap would fail and split bookkeeping).
    if map
        .range(..end)
        .next_back()
        .is_some_and(|(&prev_start, prev)| prev_start + prev.len > start)
    {
        return;
    }
    let ret = unsafe { hv_vm_unmap(start, alen as usize) };
    if ret != HV_SUCCESS {
        error!("balloon reclaim: hv_vm_unmap(0x{start:x}, {alen}) failed: {ret:x}");
        return;
    }
    // With the stage-2 mapping gone nothing pins the pages; REUSABLE drops
    // them from phys_footprint immediately and permits eager reclaim.
    // (The crate also compiles on non-macOS hosts where the constant does
    // not exist; reclaim is only ever activated on macOS.)
    #[cfg(target_os = "macos")]
    let advice = libc::MADV_FREE_REUSABLE;
    #[cfg(not(target_os = "macos"))]
    let advice = libc::MADV_DONTNEED;
    unsafe { libc::madvise(host as *mut libc::c_void, alen as usize, advice) };
    map.insert(start, ReclaimEntry { host, len: alen });
}

/// If `pa` falls inside a reclaimed range, remap the whole range and return
/// true so the vCPU retries the faulting instruction. Also covers stage-1
/// page-table walks that land in reclaimed memory (s1ptw aborts report the
/// walked PA the same way).
fn balloon_remap_if_reclaimed(pa: u64) -> bool {
    let mut map = reclaimed_map().lock().unwrap();
    let (&gpa, entry) = match map.range(..=pa).next_back() {
        Some(e) => e,
        None => return false,
    };
    if pa >= gpa + entry.len {
        return false;
    }
    let ret = unsafe {
        hv_vm_map(
            entry.host as *mut core::ffi::c_void,
            gpa,
            entry.len as usize,
            (HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC).into(),
        )
    };
    if ret != HV_SUCCESS {
        // Falling through to MMIO dispatch would corrupt the guest; this is
        // unrecoverable state, surface it loudly.
        panic!(
            "balloon refault: hv_vm_map(0x{gpa:x}, {}) failed: {ret:x}",
            entry.len
        );
    }
    map.remove(&gpa);
    true
}

struct MmioRead {
    addr: u64,
    len: usize,
    srt: u32,
}

pub struct HvfVcpu<'a> {
    vcpuid: hv_vcpu_t,
    vcpu_exit: &'a hv_vcpu_exit_t,
    cntfrq: u64,
    mmio_buf: [u8; 8],
    pending_mmio_read: Option<MmioRead>,
    pending_advance_pc: bool,
    vtimer_masked: bool,
    nested_enabled: bool,
}

impl HvfVcpu<'_> {
    pub fn new(mpidr: u64, nested_enabled: bool) -> Result<Self, Error> {
        let mut vcpuid: hv_vcpu_t = 0;
        let vcpu_exit_ptr: *mut hv_vcpu_exit_t = std::ptr::null_mut();

        #[cfg(target_arch = "aarch64")]
        let cntfrq = {
            let cntfrq: u64;
            unsafe { asm!("mrs {}, cntfrq_el0", out(reg) cntfrq) };
            cntfrq
        };
        #[cfg(target_arch = "x86_64")]
        let cntfrq = 0u64;
        #[cfg(target_arch = "riscv64")]
        let cntfrq = 0u64;

        let ret = unsafe {
            hv_vcpu_create(
                &mut vcpuid,
                &vcpu_exit_ptr as *const _ as *mut *mut _,
                std::ptr::null_mut(),
            )
        };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuCreate);
        }

        // We write vcpuid to Aff1 as otherwise it won't match the redistributor ID
        // when using HVF in-kernel GICv3.
        let ret = unsafe { hv_vcpu_set_sys_reg(vcpuid, hv_sys_reg_t_HV_SYS_REG_MPIDR_EL1, mpidr) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuCreate);
        }

        let vcpu_exit: &hv_vcpu_exit_t = unsafe { vcpu_exit_ptr.as_mut().unwrap() };

        Ok(Self {
            vcpuid,
            vcpu_exit,
            cntfrq,
            mmio_buf: [0; 8],
            pending_mmio_read: None,
            pending_advance_pc: false,
            vtimer_masked: false,
            nested_enabled,
        })
    }

    pub fn set_initial_state(&self, entry_addr: u64, fdt_addr: u64) -> Result<(), Error> {
        if self.nested_enabled {
            let ret = unsafe {
                hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_CPSR, PSTATE_EL2_FAULT_BITS_64)
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }

            let ret = unsafe {
                hv_vcpu_set_sys_reg(self.vcpuid, hv_sys_reg_t_HV_SYS_REG_HCR_EL2, HCR_EL2_BITS)
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }

            let ret = unsafe {
                hv_vcpu_set_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_CNTHCTL_EL2,
                    CNTHCTL_EL2_BITS,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }

            // Enable EL2 and GICv3 in ID_AA64PFR0_EL1
            let val: u64 = 0;
            let ret = unsafe {
                hv_vcpu_get_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR0_EL1,
                    &val as *const _ as *mut _,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }
            let ret = unsafe {
                hv_vcpu_set_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR0_EL1,
                    val | AA64PFR0_EL1_EL2EN | AA64PFR0_EL1_GIC3EN,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }

            // If SME is enabled in ID_AA64PFR1_EL1 in the VM, the guest will
            // break after enabling the MMU. Mask it out.
            let val: u64 = 0;
            let ret = unsafe {
                hv_vcpu_get_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR1_EL1,
                    &val as *const _ as *mut _,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }
            let ret = unsafe {
                hv_vcpu_set_sys_reg(
                    self.vcpuid,
                    hv_sys_reg_t_HV_SYS_REG_ID_AA64PFR1_EL1,
                    val & !AA64PFR1_EL1_SMEMASK,
                )
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }
        } else {
            let ret = unsafe {
                hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_CPSR, PSTATE_EL1_FAULT_BITS_64)
            };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuInitialRegisters);
            }
        }

        let ret = unsafe { hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_PC, entry_addr) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuInitialRegisters);
        }

        let ret = unsafe { hv_vcpu_set_reg(self.vcpuid, hv_reg_t_HV_REG_X0, fdt_addr) };
        if ret != HV_SUCCESS {
            return Err(Error::VcpuInitialRegisters);
        }

        Ok(())
    }

    pub fn id(&self) -> u64 {
        self.vcpuid
    }

    fn read_reg(&self, reg: u32) -> Result<u64, Error> {
        let val: u64 = 0;
        let ret = unsafe { hv_vcpu_get_reg(self.vcpuid, reg, &val as *const _ as *mut _) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuReadRegister)
        } else {
            Ok(val)
        }
    }

    pub fn write_reg(&self, rt: u32, val: u64) -> Result<(), Error> {
        let ret = unsafe { hv_vcpu_set_reg(self.vcpuid, rt, val) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuSetRegister)
        } else {
            Ok(())
        }
    }

    fn read_sys_reg(&self, reg: u16) -> Result<u64, Error> {
        let val: u64 = 0;
        let ret = unsafe { hv_vcpu_get_sys_reg(self.vcpuid, reg, &val as *const _ as *mut _) };
        if ret != HV_SUCCESS {
            Err(Error::VcpuReadSystemRegister)
        } else {
            Ok(val)
        }
    }

    fn hvf_sync_vtimer(&mut self, vcpu_list: Arc<dyn Vcpus>) {
        if !self.vtimer_masked {
            return;
        }

        let ctl = self
            .read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0)
            .unwrap();
        let irq_state = (ctl & (TMR_CTL_ENABLE | TMR_CTL_IMASK | TMR_CTL_ISTATUS))
            == (TMR_CTL_ENABLE | TMR_CTL_ISTATUS);
        vcpu_list.set_vtimer_irq(self.vcpuid);
        if !irq_state {
            vcpu_set_vtimer_mask(self.vcpuid, false).unwrap();
            self.vtimer_masked = false;
        }
    }

    fn handle_psci_request(&self) -> Result<VcpuExit<'_>, Error> {
        match self.read_reg(hv_reg_t_HV_REG_X0)? {
            0x8400_0000 /* QEMU_PSCI_0_2_FN_PSCI_VERSION */ => {
                self.write_reg(hv_reg_t_HV_REG_X0, 2)?;
                Ok(VcpuExit::PsciHandled)
            },
            0x8400_0006 /* QEMU_PSCI_0_2_FN_MIGRATE_INFO_TYPE */ => {
                self.write_reg(hv_reg_t_HV_REG_X0, 2)?;
                Ok(VcpuExit::PsciHandled)
            },
            0x8400_0008 /* QEMU_PSCI_0_2_FN_SYSTEM_OFF */ => {
                Ok(VcpuExit::Shutdown)
            },
            0x8400_0009 /* QEMU_PSCI_0_2_FN_SYSTEM_RESET */ => {
                Ok(VcpuExit::Shutdown)
            },
            0xc400_0003 /* QEMU_PSCI_0_2_FN64_CPU_ON */ => {
                let mpidr = self.read_reg(hv_reg_t_HV_REG_X1)?;
                let entry = self.read_reg(hv_reg_t_HV_REG_X2)?;
                let context_id = self.read_reg(hv_reg_t_HV_REG_X3)?;
                self.write_reg(hv_reg_t_HV_REG_X0, 0)?;
                Ok(VcpuExit::CpuOn(mpidr, entry, context_id))
            }
            val => panic!("Unexpected val={val}")
        }
    }

    pub fn run(&mut self, vcpu_list: Arc<dyn Vcpus>) -> Result<VcpuExit<'_>, Error> {
        let pending_irq = vcpu_list.has_pending_irq(self.vcpuid);

        if let Some(mmio_read) = self.pending_mmio_read.take()
            && mmio_read.srt < 31
        {
            let val = match mmio_read.len {
                1 => u8::from_le_bytes(self.mmio_buf[0..1].try_into().unwrap()) as u64,
                2 => u16::from_le_bytes(self.mmio_buf[0..2].try_into().unwrap()) as u64,
                4 => u32::from_le_bytes(self.mmio_buf[0..4].try_into().unwrap()) as u64,
                8 => u64::from_le_bytes(self.mmio_buf[0..8].try_into().unwrap()),
                _ => panic!(
                    "unsupported mmio pa={} len={}",
                    mmio_read.addr, mmio_read.len
                ),
            };

            self.write_reg(mmio_read.srt, val)?;
        }

        if self.pending_advance_pc {
            let pc = self.read_reg(hv_reg_t_HV_REG_PC)?;
            self.write_reg(hv_reg_t_HV_REG_PC, pc + 4)?;
            self.pending_advance_pc = false;
        }

        if pending_irq {
            vcpu_set_pending_irq(self.vcpuid, InterruptType::Irq, true)?;
        }

        // Loop only for balloon refaults: a data abort in a reclaimed RAM
        // range remaps the range and retries the instruction without leaving
        // the vCPU thread (PC untouched). Every other exit returns.
        loop {
            let ret = unsafe { hv_vcpu_run(self.vcpuid) };
            if ret != HV_SUCCESS {
                return Err(Error::VcpuRun);
            }

            match self.vcpu_exit.reason {
                HV_EXIT_REASON_EXCEPTION => { /* This is the main one, handle below. */ }
                HV_EXIT_REASON_VTIMER_ACTIVATED => {
                    self.vtimer_masked = true;
                    return Ok(VcpuExit::VtimerActivated);
                }
                HV_EXIT_REASON_CANCELED => return Ok(VcpuExit::Canceled),
                _ => {
                    let pc = self.read_reg(hv_reg_t_HV_REG_PC)?;
                    panic!(
                        "unexpected exit reason: vcpuid={} 0x{:x} at pc=0x{:x}",
                        self.id(),
                        self.vcpu_exit.reason,
                        pc
                    );
                }
            }

            self.hvf_sync_vtimer(vcpu_list.clone());

            let syndrome = self.vcpu_exit.exception.syndrome;
            let ec = (syndrome >> 26) & 0x3f;
            return match ec {
                EC_AA64_BKPT => {
                    debug!("vcpu[{}]: BRK exit", self.vcpuid);
                    Ok(VcpuExit::Breakpoint)
                }
                EC_DATAABORT => {
                    let isv: bool = (syndrome & (1 << 24)) != 0;
                    let iswrite: bool = ((syndrome >> 6) & 1) != 0;
                    let s1ptw: bool = ((syndrome >> 7) & 1) != 0;
                    let sas: u32 = ((syndrome >> 22) & 3) as u32;
                    let len: usize = (1 << sas) as usize;
                    let srt: u32 = ((syndrome >> 16) & 0x1f) as u32;
                    let cm: u32 = ((syndrome >> 8) & 0x1) as u32;

                    debug!(
                        "EC_DATAABORT {} {} {} {} {} {} {} {}",
                        syndrome, isv as u8, iswrite as u8, s1ptw as u8, sas, len, srt, cm
                    );

                    let pa = self.vcpu_exit.exception.physical_address;

                    // A fault inside a balloon-reclaimed RAM range is not MMIO:
                    // remap it and retry the instruction (PC not advanced). This
                    // must precede MMIO classification — RAM addresses are never
                    // valid MMIO and misdispatching them would corrupt the guest.
                    if balloon_reclaim_enabled() && balloon_remap_if_reclaimed(pa) {
                        continue;
                    }

                    self.pending_advance_pc = true;

                    if iswrite {
                        let val = if srt < 31 {
                            self.read_reg(hv_reg_t_HV_REG_X0 + srt)?
                        } else {
                            0
                        };

                        match len {
                            1 => self.mmio_buf[0..1].copy_from_slice(&(val as u8).to_le_bytes()),
                            4 => self.mmio_buf[0..4].copy_from_slice(&(val as u32).to_le_bytes()),
                            8 => self.mmio_buf[0..8].copy_from_slice(&val.to_le_bytes()),
                            _ => panic!("unsupported mmio len={len}"),
                        };

                        Ok(VcpuExit::MmioWrite(pa, &self.mmio_buf[0..len]))
                    } else {
                        self.pending_mmio_read = Some(MmioRead { addr: pa, srt, len });
                        Ok(VcpuExit::MmioRead(pa, &mut self.mmio_buf[0..len]))
                    }
                }
                #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
                EC_SYSTEMREGISTERTRAP => {
                    let isread: bool = (syndrome & 1) != 0;
                    let rt: u32 = ((syndrome >> 5) & 0x1f) as u32;
                    let reg: u32 = syndrome as u32 & SYSREG_MASK;
                    debug!(
                        "EC_SYSTEMREGISTERTRAP isread={}, syndrome={}, rt={}, reg={}, reg_name={}",
                        isread as u32,
                        syndrome,
                        rt,
                        reg,
                        sys_reg_name(reg).unwrap_or("unknown sysreg")
                    );

                    self.pending_advance_pc = true;

                    if isread {
                        assert!(rt < 32);

                        // See https://developer.arm.com/documentation/dui0801/l/Overview-of-AArch64-state/Registers-in-AArch64-state
                        if rt == 31 {
                            return Ok(VcpuExit::SystemRegister);
                        }

                        match vcpu_list.handle_sysreg_read(self.vcpuid, reg) {
                            Some(val) => {
                                self.write_reg(rt, val)?;
                                Ok(VcpuExit::SystemRegister)
                            }
                            None => panic!(
                                "UNKNOWN rt={}, reg={} name={}",
                                rt,
                                reg,
                                sys_reg_name(reg).unwrap_or("unknown sysreg")
                            ),
                        }
                    } else {
                        assert!(rt < 32);

                        // See https://developer.arm.com/documentation/dui0801/l/Overview-of-AArch64-state/Registers-in-AArch64-state
                        let val = if rt == 31 { 0u64 } else { self.read_reg(rt)? };

                        if vcpu_list.handle_sysreg_write(self.vcpuid, reg, val) {
                            Ok(VcpuExit::SystemRegister)
                        } else {
                            panic!(
                                "unexpected write: {} name={}",
                                reg,
                                sys_reg_name(reg).unwrap_or("unknown sysreg")
                            );
                        }
                    }
                }
                EC_WFX_TRAP => {
                    let ctl = self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CTL_EL0)?;

                    self.pending_advance_pc = true;
                    if ((ctl & 1) == 0) || (ctl & 2) != 0 {
                        return Ok(VcpuExit::WaitForEvent);
                    }

                    // Also CNTV_CVAL & CNTV_CVAL_EL0
                    let cval = self.read_sys_reg(hv_sys_reg_t_HV_SYS_REG_CNTV_CVAL_EL0)?;
                    let now = unsafe { mach_absolute_time() };
                    if now > cval {
                        return Ok(VcpuExit::WaitForEventExpired);
                    }

                    let timeout =
                        Duration::from_nanos((cval - now) * (1_000_000_000 / self.cntfrq));
                    Ok(VcpuExit::WaitForEventTimeout(timeout))
                }
                EC_AA64_HVC => self.handle_psci_request(),
                EC_AA64_SMC => {
                    self.pending_advance_pc = true;
                    self.handle_psci_request()
                }
                _ => panic!("unexpected exception: 0x{ec:x}"),
            };
        }
    }
}
