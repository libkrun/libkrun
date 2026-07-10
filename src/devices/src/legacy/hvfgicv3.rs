// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::LazyLock;

use crate::Error as DeviceError;
use crate::bus::BusDevice;
use crate::legacy::gic::GICDevice;
use crate::legacy::irqchip::IrqChipT;

use std::os::raw::c_void;

use hvf::Error;
use hvf::bindings::{
    HV_SUCCESS, hv_gic_config_t, hv_gic_icc_reg_t, hv_gic_icc_reg_t_HV_GIC_ICC_REG_AP0R0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_AP1R0_EL1, hv_gic_icc_reg_t_HV_GIC_ICC_REG_BPR0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_BPR1_EL1, hv_gic_icc_reg_t_HV_GIC_ICC_REG_CTLR_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_IGRPEN0_EL1, hv_gic_icc_reg_t_HV_GIC_ICC_REG_IGRPEN1_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_PMR_EL1, hv_gic_icc_reg_t_HV_GIC_ICC_REG_SRE_EL1,
    hv_gic_state_t, hv_ipa_t, hv_return_t, hv_vcpu_t, os_release,
};
use utils::eventfd::EventFd;

// Device trees specific constants
const ARCH_GIC_V3_MAINT_IRQ: u32 = 9;

/// Per-vCPU GIC CPU-interface (ICC) registers captured for snapshot. These are
/// the writable interface controls (group enables, priority mask, binary point,
/// active-priority); RPR is read-only and the nested EL2 SRE is excluded.
const SAVED_ICC: &[hv_gic_icc_reg_t] = &[
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_SRE_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_CTLR_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_PMR_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_BPR0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_BPR1_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_IGRPEN0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_IGRPEN1_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_AP0R0_EL1,
    hv_gic_icc_reg_t_HV_GIC_ICC_REG_AP1R0_EL1,
];

pub struct HvfGicBindings {
    hv_gic_create:
        libloading::Symbol<'static, unsafe extern "C" fn(hv_gic_config_t) -> hv_return_t>,
    hv_gic_config_create: libloading::Symbol<'static, unsafe extern "C" fn() -> hv_gic_config_t>,
    hv_gic_config_set_distributor_base:
        libloading::Symbol<'static, unsafe extern "C" fn(hv_gic_config_t, hv_ipa_t) -> hv_return_t>,
    hv_gic_config_set_redistributor_base:
        libloading::Symbol<'static, unsafe extern "C" fn(hv_gic_config_t, hv_ipa_t) -> hv_return_t>,
    hv_gic_get_distributor_size:
        libloading::Symbol<'static, unsafe extern "C" fn(*mut usize) -> hv_return_t>,
    hv_gic_get_redistributor_size:
        libloading::Symbol<'static, unsafe extern "C" fn(*mut usize) -> hv_return_t>,
    hv_gic_set_spi: libloading::Symbol<'static, unsafe extern "C" fn(u32, bool) -> hv_return_t>,
    // Snapshot save-side symbols (restore-side lands with M2).
    hv_gic_state_create: libloading::Symbol<'static, unsafe extern "C" fn() -> hv_gic_state_t>,
    hv_gic_state_get_size: libloading::Symbol<
        'static,
        unsafe extern "C" fn(hv_gic_state_t, *mut usize) -> hv_return_t,
    >,
    hv_gic_state_get_data: libloading::Symbol<
        'static,
        unsafe extern "C" fn(hv_gic_state_t, *mut c_void) -> hv_return_t,
    >,
    hv_gic_get_icc_reg: libloading::Symbol<
        'static,
        unsafe extern "C" fn(hv_vcpu_t, hv_gic_icc_reg_t, *mut u64) -> hv_return_t,
    >,
}

pub struct HvfGicV3 {
    bindings: HvfGicBindings,

    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,
}

static HVF: LazyLock<libloading::Library> = LazyLock::new(|| unsafe {
    libloading::Library::new(
        "/System/Library/Frameworks/Hypervisor.framework/Versions/A/Hypervisor",
    )
    .unwrap()
});

impl HvfGicV3 {
    pub fn new(vcpu_count: u64) -> Result<Self, Error> {
        let bindings = unsafe {
            HvfGicBindings {
                hv_gic_create: HVF.get(b"hv_gic_create").map_err(Error::FindSymbol)?,
                hv_gic_config_create: HVF
                    .get(b"hv_gic_config_create")
                    .map_err(Error::FindSymbol)?,
                hv_gic_config_set_distributor_base: HVF
                    .get(b"hv_gic_config_set_distributor_base")
                    .map_err(Error::FindSymbol)?,
                hv_gic_config_set_redistributor_base: HVF
                    .get(b"hv_gic_config_set_redistributor_base")
                    .map_err(Error::FindSymbol)?,
                hv_gic_get_distributor_size: HVF
                    .get(b"hv_gic_get_distributor_size")
                    .map_err(Error::FindSymbol)?,
                hv_gic_get_redistributor_size: HVF
                    .get(b"hv_gic_get_redistributor_size")
                    .map_err(Error::FindSymbol)?,
                hv_gic_set_spi: HVF.get(b"hv_gic_set_spi").map_err(Error::FindSymbol)?,
                hv_gic_state_create: HVF.get(b"hv_gic_state_create").map_err(Error::FindSymbol)?,
                hv_gic_state_get_size: HVF
                    .get(b"hv_gic_state_get_size")
                    .map_err(Error::FindSymbol)?,
                hv_gic_state_get_data: HVF
                    .get(b"hv_gic_state_get_data")
                    .map_err(Error::FindSymbol)?,
                hv_gic_get_icc_reg: HVF.get(b"hv_gic_get_icc_reg").map_err(Error::FindSymbol)?,
            }
        };

        let mut dist_size: usize = 0;
        let ret = unsafe { (bindings.hv_gic_get_distributor_size)(&mut dist_size) };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }
        let dist_size = dist_size as u64;

        let mut redist_size: usize = 0;
        let ret = unsafe { (bindings.hv_gic_get_redistributor_size)(&mut redist_size) };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        let redists_size = redist_size as u64 * vcpu_count;
        let dist_addr = arch::MMIO_MEM_START - dist_size - redists_size;
        let redists_addr = arch::MMIO_MEM_START - redists_size;

        let gic_config = unsafe { (bindings.hv_gic_config_create)() };
        let ret = unsafe { (bindings.hv_gic_config_set_distributor_base)(gic_config, dist_addr) };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        let ret = unsafe {
            (bindings.hv_gic_config_set_redistributor_base)(
                gic_config,
                arch::MMIO_MEM_START - redists_size,
            )
        };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        let ret = unsafe { (bindings.hv_gic_create)(gic_config) };
        if ret != HV_SUCCESS {
            return Err(Error::VmCreate);
        }

        Ok(Self {
            bindings,
            properties: [dist_addr, dist_size, redists_addr, redists_size],
            vcpu_count,
        })
    }
}

impl IrqChipT for HvfGicV3 {
    fn get_mmio_addr(&self) -> u64 {
        0
    }

    fn get_mmio_size(&self) -> u64 {
        0
    }

    fn set_irq(
        &self,
        irq_line: Option<u32>,
        _interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        if let Some(irq_line) = irq_line {
            let ret = unsafe { (self.bindings.hv_gic_set_spi)(irq_line, true) };
            if ret != HV_SUCCESS {
                Err(DeviceError::FailedSignalingUsedQueue(
                    std::io::Error::other("HVF returned error when setting SPI"),
                ))
            } else {
                Ok(())
            }
        } else {
            Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::InvalidData,
                "IRQ not line configured",
            )))
        }
    }

    fn save_gic_state(&self) -> Result<Vec<u8>, DeviceError> {
        // Mirrors ignition's gic.rs: create state, query size, copy out,
        // os_release on every path. The state object is the only thing freed
        // here; os_release is a libSystem symbol, always present.
        let gic_err = || DeviceError::Snapshot("hv_gic_state save failed".into());
        unsafe {
            let state = (self.bindings.hv_gic_state_create)();
            if state.is_null() {
                return Err(gic_err());
            }
            let result = (|| {
                let mut size: usize = 0;
                if (self.bindings.hv_gic_state_get_size)(state, &mut size) != HV_SUCCESS {
                    return Err(gic_err());
                }
                let mut buf = vec![0u8; size];
                if (self.bindings.hv_gic_state_get_data)(state, buf.as_mut_ptr() as *mut c_void)
                    != HV_SUCCESS
                {
                    return Err(gic_err());
                }
                Ok(buf)
            })();
            os_release(state as *mut c_void);
            result
        }
    }

    fn save_vcpu_icc(&self, vcpuid: u64) -> Result<Vec<(u32, u64)>, DeviceError> {
        SAVED_ICC
            .iter()
            .map(|&reg| {
                let mut val: u64 = 0;
                let ret = unsafe { (self.bindings.hv_gic_get_icc_reg)(vcpuid, reg, &mut val) };
                if ret != HV_SUCCESS {
                    Err(DeviceError::Snapshot("hv_gic_get_icc_reg failed".into()))
                } else {
                    Ok((reg as u32, val))
                }
            })
            .collect()
    }
}

impl BusDevice for HvfGicV3 {
    fn read(&mut self, _vcpuid: u64, _offset: u64, _data: &mut [u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }
}

impl GICDevice for HvfGicV3 {
    fn device_properties(&self) -> Vec<u64> {
        self.properties.to_vec()
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn fdt_compatibility(&self) -> String {
        "arm,gic-v3".to_string()
    }

    fn fdt_maint_irq(&self) -> u32 {
        ARCH_GIC_V3_MAINT_IRQ
    }

    fn version(&self) -> u32 {
        7
    }
}
