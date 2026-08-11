// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use std::mem::{self, MaybeUninit};
use std::sync::Arc;

use log::{debug, error};
use windows_sys::Win32::Foundation::S_OK;
use windows_sys::Win32::System::Hypervisor::{
    WHV_CAPABILITY, WHV_EMULATOR_CALLBACKS, WHV_EMULATOR_STATUS, WHV_MEMORY_ACCESS_CONTEXT,
    WHV_PARTITION_HANDLE, WHV_PARTITION_PROPERTY, WHV_PARTITION_PROPERTY_CODE,
    WHV_PROCESSOR_FEATURES_BANKS, WHV_REGISTER_NAME, WHV_REGISTER_VALUE, WHV_RUN_VP_EXIT_CONTEXT,
    WHV_VP_EXIT_CONTEXT, WHV_X64_CPUID_RESULT, WHV_X64_IO_PORT_ACCESS_CONTEXT,
    WHvCancelRunVirtualProcessor, WHvCapabilityCodeHypervisorPresent,
    WHvCapabilityCodeProcessorFeaturesBanks, WHvCreatePartition, WHvCreateVirtualProcessor,
    WHvDeletePartition, WHvDeleteVirtualProcessor, WHvEmulatorCreateEmulator,
    WHvEmulatorDestroyEmulator, WHvEmulatorTryIoEmulation, WHvEmulatorTryMmioEmulation,
    WHvGetCapability, WHvGetVirtualProcessorRegisters, WHvMapGpaRange, WHvMapGpaRangeFlagExecute,
    WHvMapGpaRangeFlagRead, WHvMapGpaRangeFlagWrite, WHvPartitionPropertyCodeCpuidResultList,
    WHvPartitionPropertyCodeExtendedVmExits, WHvPartitionPropertyCodeLocalApicEmulationMode,
    WHvPartitionPropertyCodeProcessorCount, WHvPartitionPropertyCodeProcessorFeaturesBanks,
    WHvPartitionPropertyCodeSyntheticProcessorFeaturesBanks,
    WHvPartitionPropertyCodeX64MsrExitBitmap, WHvRequestInterrupt, WHvRunVirtualProcessor,
    WHvRunVpExitReasonCanceled, WHvRunVpExitReasonInvalidVpRegisterValue,
    WHvRunVpExitReasonMemoryAccess, WHvRunVpExitReasonUnrecoverableException,
    WHvRunVpExitReasonUnsupportedFeature, WHvRunVpExitReasonX64Cpuid, WHvRunVpExitReasonX64Halt,
    WHvRunVpExitReasonX64InterruptWindow, WHvRunVpExitReasonX64IoPortAccess,
    WHvRunVpExitReasonX64MsrAccess, WHvSetPartitionProperty, WHvSetVirtualProcessorRegisters,
    WHvSetupPartition, WHvX64LocalApicEmulationModeXApic,
    WHvX64RegisterDeliverabilityNotifications, WHvX64RegisterRax, WHvX64RegisterRbx,
    WHvX64RegisterRcx, WHvX64RegisterRdx, WHvX64RegisterRflags, WHvX64RegisterRip,
    WHvX64RegisterRsp,
};
use windows_sys::Win32::System::Hypervisor::{
    WHV_EMULATOR_IO_ACCESS_INFO, WHV_EMULATOR_MEMORY_ACCESS_INFO, WHV_TRANSLATE_GVA_FLAGS,
    WHV_TRANSLATE_GVA_RESULT, WHV_TRANSLATE_GVA_RESULT_CODE, WHvTranslateGva,
};
// Register names + state APIs used for checkpoint/restore (snapshot & fork).
use windows_sys::Win32::System::Hypervisor::{
    WHvGetVirtualProcessorInterruptControllerState, WHvGetVirtualProcessorXsaveState,
    WHvSetVirtualProcessorInterruptControllerState, WHvSetVirtualProcessorXsaveState,
    WHvX64RegisterApicBase, WHvX64RegisterCr0, WHvX64RegisterCr2, WHvX64RegisterCr3,
    WHvX64RegisterCr4, WHvX64RegisterCr8, WHvX64RegisterCs, WHvX64RegisterCstar, WHvX64RegisterDr0,
    WHvX64RegisterDr1, WHvX64RegisterDr2, WHvX64RegisterDr3, WHvX64RegisterDr6, WHvX64RegisterDr7,
    WHvX64RegisterDs, WHvX64RegisterEfer, WHvX64RegisterEs, WHvX64RegisterFs, WHvX64RegisterGdtr,
    WHvX64RegisterGs, WHvX64RegisterIdtr, WHvX64RegisterKernelGsBase, WHvX64RegisterLdtr,
    WHvX64RegisterLstar, WHvX64RegisterPat, WHvX64RegisterR8, WHvX64RegisterR9, WHvX64RegisterR10,
    WHvX64RegisterR11, WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14, WHvX64RegisterR15,
    WHvX64RegisterRbp, WHvX64RegisterRdi, WHvX64RegisterRsi, WHvX64RegisterSfmask,
    WHvX64RegisterSs, WHvX64RegisterStar, WHvX64RegisterSysenterCs, WHvX64RegisterSysenterEip,
    WHvX64RegisterSysenterEsp, WHvX64RegisterTr, WHvX64RegisterTsc, WHvX64RegisterTscAux,
    WHvX64RegisterXCr0,
};
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows_sys::core::HRESULT;

#[derive(Debug)]
pub enum Error {
    CheckCapability(i32),
    HypervisorNotPresent,
    CreatePartition(i32),
    SetPartitionProperty(i32),
    SetupPartition(i32),
    DeletePartition(i32),
    MapGpaRange(i32),
    RequestInterrupt(i32),
    CreateVirtualProcessor(i32),
    DeleteVirtualProcessor(i32),
    RunVirtualProcessor(i32),
    GetRegisters(i32),
    SetRegisters(i32),
    MemoryAlignment,
    CreateEmulator(i32),
    DestroyEmulator(i32),
    IoEmulation(i32),
    MmioEmulation(i32),
    EmulationFailed(u32),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use Error::*;
        match self {
            CheckCapability(hr) => write!(f, "WHvGetCapability failed: HRESULT 0x{hr:08x}"),
            HypervisorNotPresent => write!(f, "WHP hypervisor is not present on this system"),
            CreatePartition(hr) => write!(f, "WHvCreatePartition failed: HRESULT 0x{hr:08x}"),
            SetPartitionProperty(hr) => {
                write!(f, "WHvSetPartitionProperty failed: HRESULT 0x{hr:08x}")
            }
            SetupPartition(hr) => write!(f, "WHvSetupPartition failed: HRESULT 0x{hr:08x}"),
            DeletePartition(hr) => write!(f, "WHvDeletePartition failed: HRESULT 0x{hr:08x}"),
            MapGpaRange(hr) => write!(f, "WHvMapGpaRange failed: HRESULT 0x{hr:08x}"),
            RequestInterrupt(hr) => write!(f, "WHvRequestInterrupt failed: HRESULT 0x{hr:08x}"),
            CreateVirtualProcessor(hr) => {
                write!(f, "WHvCreateVirtualProcessor failed: HRESULT 0x{hr:08x}")
            }
            DeleteVirtualProcessor(hr) => {
                write!(f, "WHvDeleteVirtualProcessor failed: HRESULT 0x{hr:08x}")
            }
            RunVirtualProcessor(hr) => {
                write!(f, "WHvRunVirtualProcessor failed: HRESULT 0x{hr:08x}")
            }
            GetRegisters(hr) => {
                write!(
                    f,
                    "WHvGetVirtualProcessorRegisters failed: HRESULT 0x{hr:08x}"
                )
            }
            SetRegisters(hr) => {
                write!(
                    f,
                    "WHvSetVirtualProcessorRegisters failed: HRESULT 0x{hr:08x}"
                )
            }
            MemoryAlignment => write!(f, "WHP memory mapping must be 4KB aligned"),
            CreateEmulator(hr) => {
                write!(f, "WHvEmulatorCreateEmulator failed: HRESULT 0x{hr:08x}")
            }
            DestroyEmulator(hr) => {
                write!(f, "WHvEmulatorDestroyEmulator failed: HRESULT 0x{hr:08x}")
            }
            IoEmulation(hr) => {
                write!(f, "WHvEmulatorTryIoEmulation failed: HRESULT 0x{hr:08x}")
            }
            MmioEmulation(hr) => {
                write!(f, "WHvEmulatorTryMmioEmulation failed: HRESULT 0x{hr:08x}")
            }
            EmulationFailed(status) => {
                let reason = match *status {
                    s if s & (1 << 1) != 0 => "internal emulation failure",
                    s if s & (1 << 2) != 0 => "I/O port callback failed",
                    s if s & (1 << 3) != 0 => "memory callback failed",
                    s if s & (1 << 4) != 0 => "translate GVA page callback failed",
                    s if s & (1 << 5) != 0 => "translated GPA page is not aligned",
                    s if s & (1 << 6) != 0 => "get VP registers callback failed",
                    s if s & (1 << 7) != 0 => "set VP registers callback failed",
                    s if s & (1 << 8) != 0 => "interrupt caused intercept",
                    s if s & (1 << 9) != 0 => "guest cannot be faulted",
                    _ => "unknown",
                };
                write!(
                    f,
                    "Instruction emulation failed: {reason} (status 0x{status:08x})"
                )
            }
        }
    }
}

/// Verifies that the Windows Hypervisor Platform is available.
pub fn check_hypervisor() -> Result<(), Error> {
    let mut capability = MaybeUninit::<WHV_CAPABILITY>::uninit();
    let mut written_size: u32 = 0;

    unsafe {
        let hr = WHvGetCapability(
            WHvCapabilityCodeHypervisorPresent,
            capability.as_mut_ptr().cast(),
            mem::size_of::<WHV_CAPABILITY>() as u32,
            &mut written_size,
        );

        if hr != S_OK {
            return Err(Error::CheckCapability(hr));
        }

        if capability.assume_init().HypervisorPresent == 0 {
            return Err(Error::HypervisorNotPresent);
        }
    }

    debug!("WHP hypervisor is present");
    Ok(())
}

fn get_processor_features_banks() -> Result<WHV_PROCESSOR_FEATURES_BANKS, Error> {
    let mut capability = MaybeUninit::<WHV_CAPABILITY>::uninit();
    let mut written_size: u32 = 0;

    unsafe {
        let hr = WHvGetCapability(
            WHvCapabilityCodeProcessorFeaturesBanks,
            capability.as_mut_ptr().cast(),
            mem::size_of::<WHV_CAPABILITY>() as u32,
            &mut written_size,
        );

        if hr != S_OK {
            return Err(Error::CheckCapability(hr));
        }

        Ok(capability.assume_init().ProcessorFeaturesBanks)
    }
}

/// Parsed CPUID exit context returned by [`WhpVcpu::cpuid_exit_info`].
#[derive(Debug, Clone)]
pub struct CpuidExitInfo {
    pub leaf: u64,
    pub subleaf: u64,
    pub default_eax: u64,
    pub default_ebx: u64,
    pub default_ecx: u64,
    pub default_edx: u64,
}

/// Parsed MSR exit context returned by [`WhpVcpu::msr_exit_info`].
#[derive(Debug, Clone)]
pub struct MsrExitInfo {
    pub msr_number: u32,
    pub is_write: bool,
    pub rax: u64,
    pub rdx: u64,
}

/// Parsed IO-port exit context returned by [`WhpVcpu::io_port_exit_info`].
#[derive(Debug, Clone)]
pub struct IoPortExitInfo {
    pub port: u16,
    pub is_write: bool,
    /// Access width in bytes (1, 2 or 4).
    pub size: u8,
    /// Current RAX (the source data for an `out`).
    pub rax: u64,
}

pub struct WhpVm {
    handle: WHV_PARTITION_HANDLE,
}

#[repr(C)]
struct WhvInterruptControl {
    type_and_flags: u64,
    destination: u32,
    vector: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum InterruptType {
    Fixed = 0,
    LowestPriority = 1,
    Nmi = 4,
    Init = 5,
    Sipi = 6,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum InterruptDestinationMode {
    Physical = 0,
    Logical = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum InterruptTriggerMode {
    Edge = 0,
    Level = 1,
}

#[derive(Debug, Clone)]
pub struct InterruptRequest {
    pub interrupt_type: InterruptType,
    pub destination_mode: InterruptDestinationMode,
    pub trigger_mode: InterruptTriggerMode,
    pub destination: u32,
    pub vector: u32,
}

impl WhpVm {
    /// Creates a new WHP partition.
    /// WHP has a create → configure → finalize model
    /// WHvCreatePartition — allocates the partition object but it's not yet usable.
    /// WHvSetPartitionProperty — sets properties like processor count, APIC emulation mode, etc.
    ///                           These properties can only be set before finalization.
    /// WHvSetupPartition — finalizes the partition. After this call, configuration is locked and you can start creating vCPUs.
    ///                     You cannot change the config (like processor count) after this call.
    pub fn new(vcpu_count: u32) -> Result<Self, Error> {
        let handle = unsafe {
            let mut h: WHV_PARTITION_HANDLE = 0;
            let hr = WHvCreatePartition(&mut h);
            if hr != S_OK {
                return Err(Error::CreatePartition(hr));
            }
            h
        };

        let tsc_freq_hz = Self::detect_tsc_frequency();

        if let Err(e) = Self::configure_partition(handle, vcpu_count, tsc_freq_hz) {
            let _ = unsafe { WHvDeletePartition(handle) };
            return Err(e);
        }

        debug!("WHP partition created with {vcpu_count} vCPU(s)");
        Ok(WhpVm { handle })
    }

    fn configure_partition(
        handle: WHV_PARTITION_HANDLE,
        vcpu_count: u32,
        tsc_freq_hz: u64,
    ) -> Result<(), Error> {
        Self::set_property(handle, WHvPartitionPropertyCodeProcessorCount, |p| {
            p.ProcessorCount = vcpu_count;
        })?;

        Self::set_property(
            handle,
            WHvPartitionPropertyCodeLocalApicEmulationMode,
            |p| {
                p.LocalApicEmulationMode = WHvX64LocalApicEmulationModeXApic;
            },
        )?;

        // Enable MSR exits (bit 1)
        // https://github.com/google/crosvm/blob/main/hypervisor/src/whpx/whpx_sys/WinHvPlatformDefs.h#L74
        Self::set_property(handle, WHvPartitionPropertyCodeExtendedVmExits, |p| {
            p.ExtendedVmExits.AsUINT64 = 0b10; // bit 1 = X64MsrExit
        })?;

        // Configure how MSRs are handled
        // We just set the bit 0 (UnhandledMsrs) so that any MSR read/write does not automatically fail
        // but it triggers an exit that we can handle
        Self::set_property_optional(handle, WHvPartitionPropertyCodeX64MsrExitBitmap, |p| {
            p.X64MsrExitBitmap.AsUINT64 = 0b01; // bit 0 = UnhandledMsrs
        })?;

        // Set invariant TSC support
        // First we need to retrieve the processor features banks and re-set them with the invariant TSC support
        // otherwise they get lost.
        //
        // The ProcessorFeaturesBanks capability/property is a later WHP addition
        // and is unknown to older Windows (e.g. Windows 10 1909), where the
        // capability query returns WHV_E_UNKNOWN_CAPABILITY. Treat it as
        // best-effort: on failure fall back to a zeroed banks struct (BanksCount
        // 0) so every `BanksCount >= 2` guard below — here and in the CPUID
        // invariant-TSC leaf — simply skips.
        let processor_features_banks = get_processor_features_banks().unwrap_or_else(|e| {
            log::warn!("processor features banks unavailable ({e}); skipping invariant-TSC setup");
            unsafe { MaybeUninit::<WHV_PROCESSOR_FEATURES_BANKS>::zeroed().assume_init() }
        });
        if processor_features_banks.BanksCount >= 2 {
            let result = Self::set_property_optional(
                handle,
                WHvPartitionPropertyCodeProcessorFeaturesBanks,
                |p| {
                    p.ProcessorFeaturesBanks = processor_features_banks;

                    unsafe {
                        p.ProcessorFeaturesBanks.Anonymous.AsUINT64[1] |= 0x2; // TscInvariantSupport
                    }
                },
            );

            // Some Windows 10 WHP builds expose ProcessorFeaturesBanks but
            // reject attempts to set the capability-derived value after the
            // invariant-TSC bit is added. Invariant TSC is also advertised via
            // CPUID below, so this optional refinement can be skipped safely.
            const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;
            match result {
                Err(Error::SetPartitionProperty(hr)) if hr == E_INVALIDARG => {
                    log::warn!(
                        "processor features banks rejected by this WHP host; \
                         skipping invariant-TSC partition property"
                    );
                }
                other => other?,
            }
        }

        // This unlocks the MSRs you are advertising in CPUID.
        Self::set_property_optional(
            handle,
            WHvPartitionPropertyCodeSyntheticProcessorFeaturesBanks,
            |p| {
                p.SyntheticProcessorFeaturesBanks.BanksCount = 1;
                // We use bitwise OR on the AsUINT64 array of the union for safety/clarity.
                // Bit 0: HypervisorPresent
                // Bit 1: Hv1 (Report support for Hv1: CPUID leaves 0x40000000 - 0x40000006)
                // Bit 2: AccessVpRunTimeReg
                // Bit 3: AccessPartitionReferenceCounter
                // Bit 7: Hypercalls
                // Bit 8: AccessVpIndex
                // Bit 9: AccessPartitionReferenceTsc
                // Bit 11: AccessFrequencyRegs
                unsafe {
                    p.SyntheticProcessorFeaturesBanks.Anonymous.AsUINT64[0] = 0xB8F;
                }
            },
        )?;

        let mut cpuid_results: Vec<WHV_X64_CPUID_RESULT> = Vec::new();

        // WHP does NOT expose Hyper-V CPUID to the guest automatically;
        // we must provide 0x40000000+ via CpuidResultList.
        // More info on Hypervisor Top Level Functional Specification
        // https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs

        // 0x40000000 — Hypervisor signature: "Microsoft Hv"
        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x40000000,
            Reserved: [0; 3],
            Eax: 0x40000006,
            Ebx: 0x7263694D, // "Micr"
            Ecx: 0x666F736F, // "osof"
            Edx: 0x76482074, // "t Hv"
        });
        // 0x40000001 — Interface identification: "Hv#1"
        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x40000001,
            Reserved: [0; 3],
            Eax: 0x31237648, // "Hv#1"
            Ebx: 0,
            Ecx: 0,
            Edx: 0,
        });
        // 0x40000002 — Version (minimal)
        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x40000002,
            Reserved: [0; 3],
            Eax: 0x3839,  // build number
            Ebx: 0xa0000, // version
            Ecx: 0,
            Edx: 0,
        });
        // 0x40000003 — Feature identification (Hyper-V TLFS §2.4)
        const ACCESS_VP_RUNTIME: u32 = 1 << 0;
        const ACCESS_REF_COUNTER: u32 = 1 << 1;
        const ACCESS_HYPERCALLS: u32 = 1 << 5;
        const ACCESS_VP_INDEX: u32 = 1 << 6;
        const ACCESS_REF_TSC: u32 = 1 << 9;
        const ACCESS_FREQ_REGS: u32 = 1 << 11;
        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x40000003,
            Reserved: [0; 3],
            Eax: ACCESS_VP_RUNTIME
                | ACCESS_REF_COUNTER
                | ACCESS_HYPERCALLS
                | ACCESS_VP_INDEX
                | ACCESS_REF_TSC
                | ACCESS_FREQ_REGS,
            Ebx: 0,
            Ecx: 0,
            Edx: 0,
        });
        // 0x40000004 — Recommendations
        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x40000004,
            Reserved: [0; 3],
            Eax: 1 << 5, // RelaxedTiming
            Ebx: 0,
            Ecx: 0,
            Edx: 0,
        });
        // 0x40000005 — Implementation limits
        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x40000005,
            Reserved: [0; 3],
            Eax: 64, // max virtual processors
            Ebx: 0,
            Ecx: 0,
            Edx: 0,
        });
        // 0x40000006: Hardware Features
        const HV_MSR_BITMAPS: u32 = 1 << 1;
        const HV_SLAT: u32 = 1 << 3;
        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x40000006,
            Reserved: [0; 3],
            Eax: HV_MSR_BITMAPS | HV_SLAT,
            Ebx: 0,
            Ecx: 0,
            Edx: 0,
        });

        // Advertise an invariant TSC to the guest (CPUID 0x80000007, EDX bit 8).
        // WHP only runs on hardware whose TSC is invariant, so this is always
        // true. It must NOT be gated on the ProcessorFeaturesBanks property
        // (which is unavailable on older Windows, e.g. 1909): without the
        // invariant-TSC bit the guest cannot use the TSC as a stable clock
        // source and early timekeeping/clocksource setup can fail, crashing the
        // boot before userspace.
        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x80000007,
            Reserved: [0; 3],
            Eax: 0,
            Ebx: 0,
            Ecx: 0,
            Edx: 0x100, // bit 8 (Invariant TSC / nonstop_tsc)
        });

        // Standard Intel CPUID leaves (Intel's SDM Vol. 2A)
        if tsc_freq_hz > 0 {
            debug!("Providing TSC frequency to guest: {} Hz", tsc_freq_hz);

            // CPUID 0x15 — TSC / Core Crystal Clock (Intel SDM)
            // Formula: TSC Frequency = ECX (Crystal Hz) * EBX/EAX (Ratio)
            //
            // We use a 1 kHz crystal (ECX=1000, EAX=1) rather than a 1 Hz crystal.
            // This prevents a 32-bit overflow in EBX for CPUs clocked above 4.29 GHz,
            // while maintaining high precision (millisecond-level).
            // Max representable frequency: 1000 * (2^32 - 1) ≈ 4.29 THz.
            let crystal_khz: u32 = 1_000;
            let ebx_val = (tsc_freq_hz / crystal_khz as u64) as u32;

            cpuid_results.push(WHV_X64_CPUID_RESULT {
                Function: 0x15,
                Reserved: [0; 3],
                Eax: 1,
                Ebx: ebx_val,
                Ecx: crystal_khz,
                Edx: 0,
            });
        }

        let hr = unsafe {
            WHvSetPartitionProperty(
                handle,
                WHvPartitionPropertyCodeCpuidResultList,
                cpuid_results.as_ptr() as *const _,
                (cpuid_results.len() * mem::size_of::<WHV_X64_CPUID_RESULT>()) as u32,
            )
        };
        if hr != S_OK {
            return Err(Error::SetPartitionProperty(hr));
        }

        let hr = unsafe { WHvSetupPartition(handle) };
        if hr != S_OK {
            Err(Error::SetupPartition(hr))
        } else {
            Ok(())
        }
    }

    fn set_property(
        handle: WHV_PARTITION_HANDLE,
        code: WHV_PARTITION_PROPERTY_CODE,
        configure: impl FnOnce(&mut WHV_PARTITION_PROPERTY),
    ) -> Result<(), Error> {
        let mut prop = unsafe { MaybeUninit::<WHV_PARTITION_PROPERTY>::zeroed().assume_init() };
        configure(&mut prop);
        let hr = unsafe {
            WHvSetPartitionProperty(
                handle,
                code,
                &prop as *const _ as *const _,
                mem::size_of::<WHV_PARTITION_PROPERTY>() as u32,
            )
        };
        if hr != S_OK {
            log::error!("WHvSetPartitionProperty(code={code}) failed: HRESULT 0x{hr:08x}");
            Err(Error::SetPartitionProperty(hr))
        } else {
            Ok(())
        }
    }

    /// Like [`Self::set_property`], but tolerates the property being unknown to
    /// the host (`WHV_E_UNKNOWN_PROPERTY`, 0x80370302). Several partition
    /// properties (the MSR-exit bitmap, the processor/synthetic feature banks)
    /// were added to the Windows Hypervisor Platform after the first release and
    /// are rejected on older Windows (e.g. Windows 10 1909). They are refinements
    /// on top of capabilities already negotiated through other properties, so a
    /// host that does not recognize them can still run the guest — log and skip.
    fn set_property_optional(
        handle: WHV_PARTITION_HANDLE,
        code: WHV_PARTITION_PROPERTY_CODE,
        configure: impl FnOnce(&mut WHV_PARTITION_PROPERTY),
    ) -> Result<(), Error> {
        const WHV_E_UNKNOWN_PROPERTY: i32 = 0x8037_0302u32 as i32;
        match Self::set_property(handle, code, configure) {
            Err(Error::SetPartitionProperty(hr)) if hr == WHV_E_UNKNOWN_PROPERTY => {
                log::warn!(
                    "WHvSetPartitionProperty(code={code}) not supported on this host \
                     (0x{WHV_E_UNKNOWN_PROPERTY:08x}); continuing without it"
                );
                Ok(())
            }
            other => other,
        }
    }

    /// Detect the host TSC frequency in Hz.
    /// Tries CPUID 0x15, then 0x16 (Intel), then falls back to measuring
    /// via RDTSC over a short sleep (works on AMD and all other x86_64).
    #[allow(unused_unsafe)]
    fn detect_tsc_frequency() -> u64 {
        unsafe {
            // Leaf 0 returns the maximum supported standard leaf in EAX.
            // leaves 0x15 and 0x16 may not be supported (like in non-Intel hardware (like AMD)
            // or when using nested virtualization), so it's better to check first.
            let max_leaf = core::arch::x86_64::__cpuid(0x0).eax;

            if max_leaf >= 0x15 {
                let cpuid15 = core::arch::x86_64::__cpuid(0x15);
                if cpuid15.eax != 0 && cpuid15.ebx != 0 && cpuid15.ecx != 0 {
                    let freq = (cpuid15.ecx as u64 * cpuid15.ebx as u64) / cpuid15.eax as u64;
                    debug!("TSC frequency from CPUID 0x15: {} Hz", freq);
                    return freq;
                }
            }

            if max_leaf >= 0x16 {
                let cpuid16 = core::arch::x86_64::__cpuid(0x16);
                if cpuid16.eax != 0 {
                    let freq = cpuid16.eax as u64 * 1_000_000;
                    debug!("TSC frequency from CPUID 0x16: {} Hz", freq);
                    return freq;
                }
            }
        }

        debug!("CPUID 0x15/0x16 unavailable, measuring TSC frequency via QPC");

        // If CPUID 0x15/0x16 is unavailable, we try to measure the CPU's TSC frequency by using the
        // Windows High-Resolution Performance Counter (QPC)
        // We takes a snapshot of both the QPC and the TSC, waits for exactly 10 milliseconds,
        // and then takes another snapshot of both. By comparing how many TSC ticks occurred during those 10 ms
        // of QPC ticks, we can accurately calculate the TSC ticks per second (Hz).

        let mut qpc_freq = 0;
        let mut start_qpc = 0;
        let mut end_qpc = 0;

        unsafe {
            // No need to check the result, it will always succeed
            // https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency#return-value
            let _ = QueryPerformanceFrequency(&mut qpc_freq);
            // Take a snapshot of the current QPC tick count
            // No need to check the result, it will always succeed.
            // https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter#return-value
            let _ = QueryPerformanceCounter(&mut start_qpc);
        }

        // Take a snapshot of the CPU's TSC
        let start_tsc = unsafe { core::arch::x86_64::_rdtsc() };

        // Calculate how many QPC ticks equal 10 milliseconds and loop over it.
        // If we used `std::thread::sleep(10ms)` instead, the OS might put this thread
        // to sleep for 15ms or 20ms, ruining our highly sensitive calibration interval.
        let target_qpc = start_qpc + (qpc_freq / 100);
        loop {
            unsafe {
                // No need to check the result, it will always succeed.
                let _ = QueryPerformanceCounter(&mut end_qpc);
            }
            if end_qpc >= target_qpc {
                break;
            }
        }

        // Take a snapshot of the CPU's TSC after 10ms
        let end_tsc = unsafe { core::arch::x86_64::_rdtsc() };
        // Calculate the actual elapsed QPC ticks
        let qpc_elapsed = end_qpc - start_qpc;

        if qpc_elapsed > 0 {
            let tsc_elapsed = end_tsc.wrapping_sub(start_tsc);
            // Calculate utilizing u128 to prevent overflow before dividing
            let freq = (tsc_elapsed as u128 * qpc_freq as u128 / qpc_elapsed as u128) as u64;
            debug!(
                "TSC frequency measured: {} Hz ({} MHz)",
                freq,
                freq / 1_000_000
            );
            return freq;
        }

        error!("Could not determine TSC frequency");
        0
    }

    /// Maps a host memory region into the guest physical address space.
    ///
    /// # Safety
    ///
    /// `host_start_addr` must point to a valid, writable memory region of at least `size` bytes
    /// that remains live for the lifetime of this partition.
    pub unsafe fn map_memory(
        &self,
        host_start_addr: *mut c_void,
        guest_start_addr: u64,
        size: u64,
    ) -> Result<(), Error> {
        // WHP requires 4KB alignment
        if (host_start_addr as usize | guest_start_addr as usize | size as usize) & 0xFFF != 0 {
            return Err(Error::MemoryAlignment);
        }

        let hr = unsafe {
            WHvMapGpaRange(
                self.handle,
                host_start_addr as *const _,
                guest_start_addr,
                size,
                WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute,
            )
        };
        if hr != S_OK {
            Err(Error::MapGpaRange(hr))
        } else {
            Ok(())
        }
    }

    /// Injects an interrupt into a virtual processor's local APIC.
    /// http://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvrequestinterrupt
    pub fn request_interrupt(&self, req: &InterruptRequest) -> Result<(), Error> {
        let ctrl = WhvInterruptControl {
            type_and_flags: (req.interrupt_type as u64)
                | ((req.destination_mode as u64) << 8)
                | ((req.trigger_mode as u64) << 12),
            destination: req.destination,
            vector: req.vector,
        };

        let hr = unsafe {
            WHvRequestInterrupt(
                self.handle,
                &ctrl as *const _ as *const _,
                mem::size_of::<WhvInterruptControl>() as u32,
            )
        };
        if hr != S_OK {
            Err(Error::RequestInterrupt(hr))
        } else {
            Ok(())
        }
    }

    /// Fire a fixed, edge-triggered interrupt to APIC ID with the given vector.
    pub fn request_fixed_interrupt(&self, vector: u32, apic_id: u32) {
        let result = self.request_interrupt(&InterruptRequest {
            interrupt_type: InterruptType::Fixed,
            destination_mode: InterruptDestinationMode::Physical,
            trigger_mode: InterruptTriggerMode::Edge,
            destination: apic_id,
            vector,
        });
        if result.is_err() {
            error!("inject_vector(0x{vector:02x}) failed: {result:?}");
        }
    }

    /// Cancel a running `WHvRunVirtualProcessor` call so the vCPU thread
    /// exits with `Canceled`. Required after `request_interrupt`/`request_fixed_interrupt` to wake a
    /// vCPU that is blocked in HLT.
    pub fn cancel_vcpu(&self, vp_index: u32) {
        let hr = unsafe { WHvCancelRunVirtualProcessor(self.handle, vp_index, 0) };
        if hr != S_OK {
            error!("WHvCancelRunVirtualProcessor({vp_index}) failed: HRESULT 0x{hr:08x}");
        }
    }

    pub fn partition_handle(&self) -> WHV_PARTITION_HANDLE {
        self.handle
    }
}

impl Drop for WhpVm {
    fn drop(&mut self) {
        let hr = unsafe { WHvDeletePartition(self.handle) };
        if hr != S_OK {
            error!("WHvDeletePartition failed: HRESULT 0x{hr:08x}");
        }
    }
}

unsafe impl Send for WhpVm {}
unsafe impl Sync for WhpVm {}

/// Wraps a `WHV_EMULATOR_HANDLE` (one per vCPU).
///
/// The Windows Hypervisor Platform provides a built-in x86 instruction emulator.
/// When the guest OS tries to read or write to a virtual device (via MMIO or Port I/O),
/// the physical CPU exits to the hypervisor. However, the hypervisor only knows *where*
/// the guest tried to access, not *how* (e.g., was it a 1-byte read or a 4-byte write?).
///
/// We pass the raw VM exit context into this emulator, and it decodes the x86
/// instruction, calls our provided callback functions to perform the actual I/O,
/// updates the guest registers with the result, and advances the instruction pointer.
pub struct WhpEmulator {
    handle: *mut c_void,
}

impl WhpEmulator {
    /// The `callbacks` struct contains function pointers to VMM's I/O
    /// and memory handling routines. When the emulator decodes an instruction
    /// that reads/writes memory, it will call these pointers to get or set the data.
    pub fn new(callbacks: WHV_EMULATOR_CALLBACKS) -> Result<Self, Error> {
        let mut handle: *mut c_void = std::ptr::null_mut();
        let hr = unsafe { WHvEmulatorCreateEmulator(&callbacks, &mut handle) };
        if hr != S_OK {
            Err(Error::CreateEmulator(hr))
        } else {
            Ok(WhpEmulator { handle })
        }
    }

    fn check_emulation_result(
        hr: i32,
        status: WHV_EMULATOR_STATUS,
        hresult_err: fn(i32) -> Error,
    ) -> Result<(), Error> {
        if hr != S_OK {
            return Err(hresult_err(hr));
        }
        // Check the emulator status bitfield.
        // According to Microsoft docs, Bit 0 (EmulationSuccessful) must be 1.
        let bits = unsafe { status.AsUINT32 };
        if bits & 1 == 0 {
            return Err(Error::EmulationFailed(bits));
        }
        Ok(())
    }

    /// Attempts to emulate an x86 Port I/O (PIO) instruction (e.g., `IN`, `OUT`).
    ///
    /// It is called when `WHvRunVirtualProcessor` returns `WHvRunVpExitReasonX64IoPortAccess`.
    ///
    /// * `context`: An opaque pointer that WHP will pass directly into your callbacks.
    ///   This points to the Bus so the callback can route the I/O to the correct device.
    /// * `vp_context`: The state of the vCPU's registers at the time of the exit.
    /// * `io_context`: The details of the I/O port exit (port number, access size, etc.).
    ///
    /// # Safety
    ///
    /// All three pointers must be valid and non-null for the duration of the call.
    // https://learn.microsoft.com/en-us/virtualization/api/hypervisor-instruction-emulator/funcs/whvemulatortryemulation
    pub unsafe fn try_io_emulation(
        &self,
        context: *const c_void,
        vp_context: *const WHV_VP_EXIT_CONTEXT,
        io_context: *const WHV_X64_IO_PORT_ACCESS_CONTEXT,
    ) -> Result<(), Error> {
        unsafe {
            let mut status: WHV_EMULATOR_STATUS = mem::zeroed();
            let hr = WHvEmulatorTryIoEmulation(
                self.handle,
                context,
                vp_context,
                io_context,
                &mut status,
            );
            Self::check_emulation_result(hr, status, Error::IoEmulation)
        }
    }

    /// Attempts to emulate an x86 Memory-Mapped I/O (MMIO) instruction (e.g., `MOV eax, [mem]`).
    ///
    /// It is called when `WHvRunVirtualProcessor` returns `WHvRunVpExitReasonMemoryAccess`
    /// *and* the memory address belongs to a virtual device.
    ///
    /// # Safety
    ///
    /// All three pointers must be valid and non-null for the duration of the call.
    pub unsafe fn try_mmio_emulation(
        &self,
        context: *const c_void,
        vp_context: *const WHV_VP_EXIT_CONTEXT,
        mmio_context: *const WHV_MEMORY_ACCESS_CONTEXT,
    ) -> Result<(), Error> {
        unsafe {
            let mut status: WHV_EMULATOR_STATUS = mem::zeroed();
            let hr = WHvEmulatorTryMmioEmulation(
                self.handle,
                context,
                vp_context,
                mmio_context,
                &mut status,
            );
            Self::check_emulation_result(hr, status, Error::MmioEmulation)
        }
    }

    /// Creates an emulator wired with default callbacks: memory accesses are
    /// routed through the handler passed to [`Self::emulate_mmio`], and
    /// register/translation queries are forwarded to the partition. This is the
    /// constructor the VMM should use for MMIO instruction emulation.
    pub fn with_mmio_callbacks() -> Result<Self, Error> {
        let callbacks = WHV_EMULATOR_CALLBACKS {
            Size: mem::size_of::<WHV_EMULATOR_CALLBACKS>() as u32,
            Reserved: 0,
            WHvEmulatorIoPortCallback: Some(emu_io_cb),
            WHvEmulatorMemoryCallback: Some(emu_memory_cb),
            WHvEmulatorGetVirtualProcessorRegisters: Some(emu_get_regs_cb),
            WHvEmulatorSetVirtualProcessorRegisters: Some(emu_set_regs_cb),
            WHvEmulatorTranslateGvaPage: Some(emu_translate_cb),
        };
        Self::new(callbacks)
    }

    /// Emulates the faulting MMIO instruction for `vcpu`, routing the device-side
    /// memory access through `mem` (`(gpa, data, is_write)`; for writes `data`
    /// holds the bytes to store, for reads the handler fills `data`). The
    /// emulator advances RIP and updates the vCPU registers itself via the
    /// register callbacks.
    ///
    /// # Safety
    /// Call only after a `MemoryAccess` exit on `vcpu`; the emulator created with
    /// [`Self::with_mmio_callbacks`].
    pub unsafe fn emulate_mmio(
        &self,
        vcpu: &WhpVcpu,
        mem: &mut dyn FnMut(u64, &mut [u8], bool),
    ) -> Result<(), Error> {
        let mut ctx = MmioEmuCtx {
            partition: vcpu.partition_handle(),
            vp_index: vcpu.index(),
            mem,
        };
        unsafe {
            self.try_mmio_emulation(
                &mut ctx as *mut MmioEmuCtx as *const c_void,
                vcpu.vp_exit_context(),
                vcpu.memory_access_context(),
            )
        }
    }
}

/// Opaque context handed to the WHP emulator callbacks; lives on the stack for
/// the duration of a single [`WhpEmulator::emulate_mmio`] call.
struct MmioEmuCtx<'a> {
    partition: WHV_PARTITION_HANDLE,
    vp_index: u32,
    mem: &'a mut dyn FnMut(u64, &mut [u8], bool),
}

/// Memory-access callback: route the emulator's device-side access to `mem`.
unsafe extern "system" fn emu_memory_cb(
    context: *const c_void,
    access: *mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
) -> HRESULT {
    let ctx = unsafe { &mut *(context as *mut MmioEmuCtx) };
    let access = unsafe { &mut *access };
    let size = (access.AccessSize as usize).min(8);
    let is_write = access.Direction != 0; // 0 = read, 1 = write
    let mut buf = access.Data;
    (ctx.mem)(access.GpaAddress, &mut buf[..size], is_write);
    if !is_write {
        access.Data[..size].copy_from_slice(&buf[..size]);
    }
    S_OK
}

/// PIO callback: string-IO to ports during MMIO emulation isn't produced by
/// virtio-mmio devices. TODO(whp-host): route to the PIO bus if ever needed.
unsafe extern "system" fn emu_io_cb(
    _context: *const c_void,
    _access: *mut WHV_EMULATOR_IO_ACCESS_INFO,
) -> HRESULT {
    S_OK
}

/// Register-read callback: forward to the partition.
unsafe extern "system" fn emu_get_regs_cb(
    context: *const c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *mut WHV_REGISTER_VALUE,
) -> HRESULT {
    let ctx = unsafe { &*(context as *const MmioEmuCtx) };
    unsafe { WHvGetVirtualProcessorRegisters(ctx.partition, ctx.vp_index, names, count, values) }
}

/// Register-write callback: forward to the partition.
unsafe extern "system" fn emu_set_regs_cb(
    context: *const c_void,
    names: *const WHV_REGISTER_NAME,
    count: u32,
    values: *const WHV_REGISTER_VALUE,
) -> HRESULT {
    let ctx = unsafe { &*(context as *const MmioEmuCtx) };
    unsafe { WHvSetVirtualProcessorRegisters(ctx.partition, ctx.vp_index, names, count, values) }
}

/// GVA->GPA translation callback: forward to `WHvTranslateGva`.
unsafe extern "system" fn emu_translate_cb(
    context: *const c_void,
    gva: u64,
    flags: WHV_TRANSLATE_GVA_FLAGS,
    result_code: *mut WHV_TRANSLATE_GVA_RESULT_CODE,
    gpa: *mut u64,
) -> HRESULT {
    let ctx = unsafe { &*(context as *const MmioEmuCtx) };
    let mut result: WHV_TRANSLATE_GVA_RESULT = unsafe { mem::zeroed() };
    let mut out_gpa: u64 = 0;
    let hr = unsafe {
        WHvTranslateGva(
            ctx.partition,
            ctx.vp_index,
            gva,
            flags,
            &mut result,
            &mut out_gpa,
        )
    };
    if hr == S_OK {
        unsafe {
            *result_code = result.ResultCode;
            *gpa = out_gpa;
        }
    }
    hr
}

impl Drop for WhpEmulator {
    fn drop(&mut self) {
        let hr = unsafe { WHvEmulatorDestroyEmulator(self.handle) };
        if hr != S_OK {
            error!("WHvEmulatorDestroyEmulator failed: HRESULT 0x{hr:08x}");
        }
    }
}

unsafe impl Send for WhpEmulator {}

#[derive(Debug)]
pub enum VcpuExitReason {
    IoPortAccess,
    MemoryAccess,
    Halt,
    Canceled,
    CpuidAccess,
    MsrAccess,
    InterruptWindow,
    UnrecoverableException,
    InvalidVpRegisterValue,
    UnsupportedFeature,
    Unknown(u32),
}

pub struct WhpVcpu {
    vm: Arc<WhpVm>,
    index: u32,
    exit_context: WHV_RUN_VP_EXIT_CONTEXT,
}

impl WhpVcpu {
    /// Creates a new virtual processor within the given partition.
    pub fn new(vm: Arc<WhpVm>, index: u32) -> Result<Self, Error> {
        let hr = unsafe { WHvCreateVirtualProcessor(vm.partition_handle(), index, 0) };
        if hr != S_OK {
            return Err(Error::CreateVirtualProcessor(hr));
        }

        debug!("Created WHP vCPU {index}");
        Ok(WhpVcpu {
            vm,
            index,
            exit_context: unsafe { mem::zeroed() },
        })
    }

    /// Runs the virtual processor until a VM exit occurs.
    ///
    /// The raw exit context is stored internally and can be accessed via
    /// [`vp_exit_context`], [`io_port_access_context`], and
    /// [`memory_access_context`] for passing to the instruction emulator.
    pub fn run(&mut self) -> Result<VcpuExitReason, Error> {
        let hr = unsafe {
            WHvRunVirtualProcessor(
                self.vm.partition_handle(),
                self.index,
                &mut self.exit_context as *mut _ as *mut _,
                mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
            )
        };
        if hr != S_OK {
            return Err(Error::RunVirtualProcessor(hr));
        }

        Ok(Self::decode_reason(&self.exit_context))
    }

    pub fn vp_exit_context(&self) -> *const WHV_VP_EXIT_CONTEXT {
        &self.exit_context.VpContext
    }

    pub fn io_port_access_context(&self) -> *const WHV_X64_IO_PORT_ACCESS_CONTEXT {
        unsafe { &self.exit_context.Anonymous.IoPortAccess }
    }

    pub fn memory_access_context(&self) -> *const WHV_MEMORY_ACCESS_CONTEXT {
        unsafe { &self.exit_context.Anonymous.MemoryAccess }
    }

    /// Returns parsed CPUID exit info. Only valid after a `CpuidAccess` exit.
    pub fn cpuid_exit_info(&self) -> CpuidExitInfo {
        let ctx = unsafe { &self.exit_context.Anonymous.CpuidAccess };
        CpuidExitInfo {
            leaf: ctx.Rax,
            subleaf: ctx.Rcx,
            default_eax: ctx.DefaultResultRax,
            default_ebx: ctx.DefaultResultRbx,
            default_ecx: ctx.DefaultResultRcx,
            default_edx: ctx.DefaultResultRdx,
        }
    }

    /// Returns parsed MSR exit info. Only valid after an `MsrAccess` exit.
    pub fn msr_exit_info(&self) -> MsrExitInfo {
        let ctx = unsafe { &self.exit_context.Anonymous.MsrAccess };
        MsrExitInfo {
            msr_number: ctx.MsrNumber,
            is_write: unsafe { ctx.AccessInfo.Anonymous._bitfield } & 1 != 0,
            rax: ctx.Rax,
            rdx: ctx.Rdx,
        }
    }

    /// Returns parsed IO-port exit info. Only valid after an `IoPortAccess` exit.
    ///
    /// The `WHV_X64_IO_PORT_ACCESS_INFO` bitfield packs `IsWrite` in bit 0 and the
    /// access size in bytes (1/2/4) in bits 1-3.
    pub fn io_port_exit_info(&self) -> IoPortExitInfo {
        let ctx = unsafe { &self.exit_context.Anonymous.IoPortAccess };
        let bits = unsafe { ctx.AccessInfo.Anonymous._bitfield };
        IoPortExitInfo {
            port: ctx.PortNumber,
            is_write: bits & 1 != 0,
            size: ((bits >> 1) & 0x7) as u8,
            rax: ctx.Rax,
        }
    }

    /// Writes the result of an IO-port `in` into RAX (preserving bytes outside the
    /// access width) and advances RIP past the instruction.
    pub fn complete_io_in(&self, rax: u64) -> Result<(), Error> {
        let new_rip = self.exit_context.VpContext.Rip + self.instruction_length() as u64;
        self.set_registers64([(WHvX64RegisterRax, rax), (WHvX64RegisterRip, new_rip)])
    }

    /// RIP at the time of the VM exit.
    pub fn exit_rip(&self) -> u64 {
        self.exit_context.VpContext.Rip
    }

    /// Instruction length from the exit context (lower 4 bits of the packed byte).
    pub fn instruction_length(&self) -> u8 {
        self.exit_context.VpContext._bitfield & 0x0F
    }

    /// Advances RIP past the faulting instruction using the instruction length
    /// from the exit context.
    pub fn advance_rip(&self) -> Result<(), Error> {
        let new_rip = self.exit_context.VpContext.Rip + self.instruction_length() as u64;
        self.set_registers64([(WHvX64RegisterRip, new_rip)])
    }

    /// Sets RAX, RBX, RCX, RDX and advances RIP in a single register write.
    /// Used by CPUID exit handling.
    pub fn complete_cpuid(&self, eax: u64, ebx: u64, ecx: u64, edx: u64) -> Result<(), Error> {
        let new_rip = self.exit_context.VpContext.Rip + self.instruction_length() as u64;

        self.set_registers64([
            (WHvX64RegisterRax, eax),
            (WHvX64RegisterRbx, ebx),
            (WHvX64RegisterRcx, ecx),
            (WHvX64RegisterRdx, edx),
            (WHvX64RegisterRip, new_rip),
        ])
    }

    /// Sets RAX and RDX (MSR read result) then advances RIP.
    pub fn complete_msr_read(&self, rax: u64, rdx: u64) -> Result<(), Error> {
        let new_rip = self.exit_context.VpContext.Rip + self.instruction_length() as u64;

        self.set_registers64([
            (WHvX64RegisterRax, rax),
            (WHvX64RegisterRdx, rdx),
            (WHvX64RegisterRip, new_rip),
        ])
    }

    /// Helper to get multiple registers at once.
    /// Returns a stack-allocated array of results.
    pub fn get_registers<const N: usize>(
        &self,
        names: [WHV_REGISTER_NAME; N],
    ) -> Result<[WHV_REGISTER_VALUE; N], Error> {
        // Create a zeroed array on the stack to hold the results
        let mut values: [WHV_REGISTER_VALUE; N] = unsafe { mem::zeroed() };

        let hr = unsafe {
            WHvGetVirtualProcessorRegisters(
                self.vm.partition_handle(),
                self.index,
                names.as_ptr(),
                N as u32,
                values.as_mut_ptr(),
            )
        };

        if hr != S_OK {
            Err(Error::GetRegisters(hr))
        } else {
            // Return the array directly!
            Ok(values)
        }
    }

    pub fn get_registers64<const N: usize>(
        &self,
        names: [WHV_REGISTER_NAME; N],
    ) -> Result<[u64; N], Error> {
        let values = self.get_registers(names)?;
        Ok(values.map(|v| unsafe { v.Reg64 }))
    }

    /// Returns true if the guest currently has interrupts enabled (RFLAGS.IF).
    /// Used to tell an idle `HLT` (waiting for an interrupt, so the vCPU should
    /// keep running) from a dead `HLT` with interrupts masked (shutdown).
    pub fn interrupts_enabled(&self) -> Result<bool, Error> {
        let [rflags] = self.get_registers64([WHvX64RegisterRflags])?;
        Ok(rflags & (1 << 9) != 0)
    }

    /// A short dump of the architectural state most useful for diagnosing a
    /// fault: instruction pointer, stack pointer and flags.
    pub fn debug_state(&self) -> String {
        match self.get_registers64([WHvX64RegisterRip, WHvX64RegisterRsp, WHvX64RegisterRflags]) {
            Ok([rip, rsp, rflags]) => {
                format!("rip={rip:#x} rsp={rsp:#x} rflags={rflags:#x}")
            }
            Err(e) => format!("<failed to read registers: {e}>"),
        }
    }

    fn set_whp_registers(
        &self,
        names: &[WHV_REGISTER_NAME],
        values: &[WHV_REGISTER_VALUE],
    ) -> Result<(), Error> {
        assert_eq!(names.len(), values.len());
        let count = names.len() as u32;

        let hr = unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm.partition_handle(),
                self.index,
                names.as_ptr(),
                count,
                values.as_ptr(),
            )
        };
        if hr != S_OK {
            Err(Error::SetRegisters(hr))
        } else {
            Ok(())
        }
    }

    pub fn set_registers<const N: usize>(
        &self,
        pairs: [(WHV_REGISTER_NAME, WHV_REGISTER_VALUE); N],
    ) -> Result<(), Error> {
        let mut names: [WHV_REGISTER_NAME; N] = unsafe { mem::zeroed() };
        let mut values: [WHV_REGISTER_VALUE; N] = unsafe { mem::zeroed() };

        for i in 0..N {
            names[i] = pairs[i].0;
            values[i] = pairs[i].1;
        }

        self.set_whp_registers(&names, &values)
    }

    pub fn set_registers64<const N: usize>(
        &self,
        pairs: [(WHV_REGISTER_NAME, u64); N],
    ) -> Result<(), Error> {
        let mut names: [WHV_REGISTER_NAME; N] = unsafe { mem::zeroed() };
        let mut values: [WHV_REGISTER_VALUE; N] = unsafe { mem::zeroed() };

        for i in 0..N {
            names[i] = pairs[i].0;
            values[i].Reg64 = pairs[i].1;
        }

        self.set_whp_registers(&names, &values)
    }

    pub fn vm(&self) -> &Arc<WhpVm> {
        &self.vm
    }

    pub fn partition_handle(&self) -> WHV_PARTITION_HANDLE {
        self.vm.partition_handle()
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    /// Clear the deliverability-notification request so WHP stops exiting
    /// on every STI instruction. Called after an InterruptWindow exit.
    /// https://github.com/google/crosvm/blob/main/hypervisor/src/whpx/whpx_sys/WinHvPlatformDefs.h#L773
    pub fn clear_interrupt_window(&self) -> Result<(), Error> {
        let [notifications] = self.get_registers64([WHvX64RegisterDeliverabilityNotifications])?;
        if notifications & 0x2 != 0 {
            // Clear Bit 1 (InterruptNotification) while preserving NMI and Priority bits
            self.set_registers64([(
                WHvX64RegisterDeliverabilityNotifications,
                notifications & !0x2,
            )])?;
        }
        Ok(())
    }

    #[allow(non_upper_case_globals)]
    fn decode_reason(ctx: &WHV_RUN_VP_EXIT_CONTEXT) -> VcpuExitReason {
        match ctx.ExitReason {
            WHvRunVpExitReasonX64IoPortAccess => VcpuExitReason::IoPortAccess,
            WHvRunVpExitReasonMemoryAccess => VcpuExitReason::MemoryAccess,
            WHvRunVpExitReasonX64Halt => VcpuExitReason::Halt,
            WHvRunVpExitReasonCanceled => VcpuExitReason::Canceled,
            WHvRunVpExitReasonX64Cpuid => VcpuExitReason::CpuidAccess,
            WHvRunVpExitReasonX64MsrAccess => VcpuExitReason::MsrAccess,
            WHvRunVpExitReasonX64InterruptWindow => VcpuExitReason::InterruptWindow,
            WHvRunVpExitReasonUnrecoverableException => VcpuExitReason::UnrecoverableException,
            WHvRunVpExitReasonInvalidVpRegisterValue => VcpuExitReason::InvalidVpRegisterValue,
            WHvRunVpExitReasonUnsupportedFeature => VcpuExitReason::UnsupportedFeature,
            _ => VcpuExitReason::Unknown(ctx.ExitReason as u32),
        }
    }
}

/// Ordered register set captured and restored for checkpoint/fork. The saved
/// blob records each register's name alongside its value, so restore writes back
/// exactly what was captured (and a host that lacks a newer register simply omits
/// it). The LAPIC is intentionally excluded here — it is captured separately via
/// the interrupt-controller state blob — and the x87/SSE/AVX register file is
/// covered by the XSAVE blob rather than the individual `Fp*`/`Xmm*` registers.
const CHECKPOINT_REGS: &[WHV_REGISTER_NAME] = &[
    // General-purpose registers.
    WHvX64RegisterRax,
    WHvX64RegisterRcx,
    WHvX64RegisterRdx,
    WHvX64RegisterRbx,
    WHvX64RegisterRsp,
    WHvX64RegisterRbp,
    WHvX64RegisterRsi,
    WHvX64RegisterRdi,
    WHvX64RegisterR8,
    WHvX64RegisterR9,
    WHvX64RegisterR10,
    WHvX64RegisterR11,
    WHvX64RegisterR12,
    WHvX64RegisterR13,
    WHvX64RegisterR14,
    WHvX64RegisterR15,
    WHvX64RegisterRip,
    WHvX64RegisterRflags,
    // Segment registers (selector + cached descriptor).
    WHvX64RegisterEs,
    WHvX64RegisterCs,
    WHvX64RegisterSs,
    WHvX64RegisterDs,
    WHvX64RegisterFs,
    WHvX64RegisterGs,
    WHvX64RegisterLdtr,
    WHvX64RegisterTr,
    // Descriptor tables.
    WHvX64RegisterIdtr,
    WHvX64RegisterGdtr,
    // Control registers.
    WHvX64RegisterCr0,
    WHvX64RegisterCr2,
    WHvX64RegisterCr3,
    WHvX64RegisterCr4,
    WHvX64RegisterCr8,
    WHvX64RegisterXCr0,
    // Debug registers.
    WHvX64RegisterDr0,
    WHvX64RegisterDr1,
    WHvX64RegisterDr2,
    WHvX64RegisterDr3,
    WHvX64RegisterDr6,
    WHvX64RegisterDr7,
    // MSRs exposed through the register namespace.
    WHvX64RegisterEfer,
    WHvX64RegisterKernelGsBase,
    WHvX64RegisterApicBase,
    WHvX64RegisterPat,
    WHvX64RegisterSysenterCs,
    WHvX64RegisterSysenterEip,
    WHvX64RegisterSysenterEsp,
    WHvX64RegisterStar,
    WHvX64RegisterLstar,
    WHvX64RegisterCstar,
    WHvX64RegisterSfmask,
    WHvX64RegisterTsc,
    WHvX64RegisterTscAux,
];

/// Full architectural state of a WHP virtual processor, captured for
/// checkpoint/restore (snapshot and fork). Holds the saved register
/// name/value pairs plus the opaque LAPIC and XSAVE blobs. Serializes to a
/// flat byte buffer via [`WhpVcpuState::to_bytes`] / [`WhpVcpuState::from_bytes`].
#[derive(Clone, Debug, Default)]
pub struct WhpVcpuState {
    reg_names: Vec<WHV_REGISTER_NAME>,
    reg_values: Vec<[u8; 16]>,
    lapic: Vec<u8>,
    xsave: Vec<u8>,
}

impl WhpVcpuState {
    /// Serializes the captured state to a flat, self-describing byte buffer:
    /// `[n_regs u32]( [name i32][value 16B] )* [lapic_len u32][lapic] [xsave_len u32][xsave]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.reg_names.len() * 20 + self.lapic.len() + 16);
        out.extend_from_slice(&(self.reg_names.len() as u32).to_le_bytes());
        for (name, value) in self.reg_names.iter().zip(self.reg_values.iter()) {
            out.extend_from_slice(&name.to_le_bytes());
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&(self.lapic.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.lapic);
        out.extend_from_slice(&(self.xsave.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.xsave);
        out
    }

    /// Reconstructs the state from a buffer produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<WhpVcpuState, String> {
        let mut cur = bytes;
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
            if cur.len() < n {
                return Err("WhpVcpuState: truncated buffer".to_string());
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }
        fn take_u32(cur: &mut &[u8]) -> Result<u32, String> {
            Ok(u32::from_le_bytes(take(cur, 4)?.try_into().unwrap()))
        }

        let n_regs = take_u32(&mut cur)? as usize;
        // Clamp the pre-allocation to the known register count: the per-iteration
        // `take` below bounds the actual reads, but a corrupt/oversized count must
        // not trigger a multi-GB up-front allocation.
        let mut reg_names = Vec::with_capacity(n_regs.min(CHECKPOINT_REGS.len()));
        let mut reg_values = Vec::with_capacity(n_regs.min(CHECKPOINT_REGS.len()));
        for _ in 0..n_regs {
            let name = i32::from_le_bytes(take(&mut cur, 4)?.try_into().unwrap());
            let value: [u8; 16] = take(&mut cur, 16)?.try_into().unwrap();
            reg_names.push(name as WHV_REGISTER_NAME);
            reg_values.push(value);
        }
        let lapic_len = take_u32(&mut cur)? as usize;
        let lapic = take(&mut cur, lapic_len)?.to_vec();
        let xsave_len = take_u32(&mut cur)? as usize;
        let xsave = take(&mut cur, xsave_len)?.to_vec();
        Ok(WhpVcpuState {
            reg_names,
            reg_values,
            lapic,
            xsave,
        })
    }
}

/// Converts a raw 16-byte register value to a `WHV_REGISTER_VALUE`.
fn bytes_to_reg_value(bytes: &[u8; 16]) -> WHV_REGISTER_VALUE {
    // SAFETY: `WHV_REGISTER_VALUE` is a 16-byte POD union (`Reg128` is its widest
    // member); any 16-byte pattern is a valid bit-image of it.
    unsafe { *(bytes.as_ptr() as *const WHV_REGISTER_VALUE) }
}

/// Converts a `WHV_REGISTER_VALUE` to its raw 16-byte image.
fn reg_value_to_bytes(value: &WHV_REGISTER_VALUE) -> [u8; 16] {
    // SAFETY: `WHV_REGISTER_VALUE` is 16 bytes; reading it as bytes is always valid.
    unsafe { *(value as *const WHV_REGISTER_VALUE as *const [u8; 16]) }
}

impl WhpVcpu {
    /// Captures the full architectural state of this virtual processor for
    /// checkpoint/restore. The vCPU must be quiescent (paused at a VM exit).
    ///
    /// Registers are read in one batch when the host accepts the whole list;
    /// otherwise it falls back to reading each register individually and keeping
    /// only the ones the host knows (older Windows lacks some newer register
    /// names). The LAPIC and XSAVE areas are best-effort: a host that does not
    /// expose them yields an empty blob, which restore then skips.
    pub fn save_state(&self) -> Result<WhpVcpuState, Error> {
        let part = self.vm.partition_handle();
        let n = CHECKPOINT_REGS.len();

        let mut reg_names: Vec<WHV_REGISTER_NAME>;
        let mut reg_values: Vec<[u8; 16]>;

        let mut batch: Vec<WHV_REGISTER_VALUE> = vec![unsafe { mem::zeroed() }; n];
        let hr = unsafe {
            WHvGetVirtualProcessorRegisters(
                part,
                self.index,
                CHECKPOINT_REGS.as_ptr(),
                n as u32,
                batch.as_mut_ptr(),
            )
        };
        if hr == S_OK {
            reg_names = CHECKPOINT_REGS.to_vec();
            reg_values = batch.iter().map(reg_value_to_bytes).collect();
        } else {
            // Per-register fallback: keep only registers the host recognizes.
            reg_names = Vec::with_capacity(n);
            reg_values = Vec::with_capacity(n);
            for &name in CHECKPOINT_REGS {
                let mut value: WHV_REGISTER_VALUE = unsafe { mem::zeroed() };
                let hr = unsafe {
                    WHvGetVirtualProcessorRegisters(part, self.index, &name, 1, &mut value)
                };
                if hr == S_OK {
                    reg_names.push(name);
                    reg_values.push(reg_value_to_bytes(&value));
                }
            }
            if reg_names.is_empty() {
                return Err(Error::GetRegisters(hr));
            }
        }

        let lapic = self.get_state_blob(|buf, len, written| unsafe {
            WHvGetVirtualProcessorInterruptControllerState(
                part,
                self.index,
                buf as *mut c_void,
                len,
                written,
            )
        });
        let xsave = self.get_state_blob(|buf, len, written| unsafe {
            WHvGetVirtualProcessorXsaveState(part, self.index, buf as *mut c_void, len, written)
        });

        Ok(WhpVcpuState {
            reg_names,
            reg_values,
            lapic,
            xsave,
        })
    }

    /// Restores architectural state previously captured by [`Self::save_state`].
    /// The vCPU must be quiescent. Registers are written first (batch with a
    /// per-register fallback), then the XSAVE area, then the LAPIC state so the
    /// interrupt-controller view wins over CR8/APIC-base.
    pub fn restore_state(&self, state: &WhpVcpuState) -> Result<(), Error> {
        let part = self.vm.partition_handle();
        let values: Vec<WHV_REGISTER_VALUE> =
            state.reg_values.iter().map(bytes_to_reg_value).collect();

        let hr = unsafe {
            WHvSetVirtualProcessorRegisters(
                part,
                self.index,
                state.reg_names.as_ptr(),
                state.reg_names.len() as u32,
                values.as_ptr(),
            )
        };
        if hr != S_OK {
            // Per-register fallback: set each individually so one register the
            // host doesn't recognize doesn't abort the whole restore. Tolerate a
            // rejected non-core register (log it), but a rejected core register
            // (RIP/RSP/RFLAGS/CR0/CR3/CR4/EFER) means the clone would resume into
            // a fault, so surface that as an error.
            const CORE: &[WHV_REGISTER_NAME] = &[
                WHvX64RegisterRip,
                WHvX64RegisterRsp,
                WHvX64RegisterRflags,
                WHvX64RegisterCr0,
                WHvX64RegisterCr3,
                WHvX64RegisterCr4,
                WHvX64RegisterEfer,
            ];
            for (name, value) in state.reg_names.iter().zip(values.iter()) {
                let hr =
                    unsafe { WHvSetVirtualProcessorRegisters(part, self.index, name, 1, value) };
                if hr != S_OK {
                    if CORE.contains(name) {
                        error!("restoring core vCPU register {name} failed: HRESULT 0x{hr:08x}");
                        return Err(Error::SetRegisters(hr));
                    }
                    debug!("restoring vCPU register {name} failed (ignored): HRESULT 0x{hr:08x}");
                }
            }
        }

        if !state.xsave.is_empty() {
            let hr = unsafe {
                WHvSetVirtualProcessorXsaveState(
                    part,
                    self.index,
                    state.xsave.as_ptr() as *const c_void,
                    state.xsave.len() as u32,
                )
            };
            if hr != S_OK {
                error!("WHvSetVirtualProcessorXsaveState failed: HRESULT 0x{hr:08x}");
            }
        }

        if !state.lapic.is_empty() {
            let hr = unsafe {
                WHvSetVirtualProcessorInterruptControllerState(
                    part,
                    self.index,
                    state.lapic.as_ptr() as *const c_void,
                    state.lapic.len() as u32,
                )
            };
            if hr != S_OK {
                error!("WHvSetVirtualProcessorInterruptControllerState failed: HRESULT 0x{hr:08x}");
            }
        }

        Ok(())
    }

    /// Reads a variable-length WHP state blob (LAPIC or XSAVE) into a right-sized
    /// `Vec`. Returns an empty vec if the host does not support the query.
    fn get_state_blob(&self, get: impl Fn(*mut u8, u32, *mut u32) -> HRESULT) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let mut written: u32 = 0;
        let hr = get(buf.as_mut_ptr(), buf.len() as u32, &mut written);
        if hr != S_OK {
            return Vec::new();
        }
        buf.truncate(written as usize);
        buf
    }
}

impl Drop for WhpVcpu {
    fn drop(&mut self) {
        let hr = unsafe { WHvDeleteVirtualProcessor(self.vm.partition_handle(), self.index) };
        if hr != S_OK {
            error!(
                "WHvDeleteVirtualProcessor({}) failed: HRESULT 0x{hr:08x}",
                self.index
            );
        }
    }
}
