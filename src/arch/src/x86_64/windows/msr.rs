// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::x86_64::msr::{MTRR_ENABLE, MTRR_MEM_TYPE_WB};

use super::super::msr::Error;
use windows_sys::Win32::System::Hypervisor::{
    WHV_REGISTER_NAME, WHvX64RegisterCstar, WHvX64RegisterLstar, WHvX64RegisterMsrMtrrDefType,
    WHvX64RegisterSfmask, WHvX64RegisterStar, WHvX64RegisterSysenterCs, WHvX64RegisterSysenterEip,
    WHvX64RegisterSysenterEsp, WHvX64RegisterTsc,
};

type Result<T> = std::result::Result<T, Error>;

const REGISTERS: [(WHV_REGISTER_NAME, u64); 9] = [
    (WHvX64RegisterSysenterCs, 0x0),
    (WHvX64RegisterSysenterEsp, 0x0),
    (WHvX64RegisterSysenterEip, 0x0),
    // x86_64 specific MSRs
    (WHvX64RegisterStar, 0x0),
    (WHvX64RegisterCstar, 0x0),
    (WHvX64RegisterSfmask, 0x0),
    (WHvX64RegisterLstar, 0x0),
    (WHvX64RegisterTsc, 0x0),
    (WHvX64RegisterMsrMtrrDefType, MTRR_ENABLE | MTRR_MEM_TYPE_WB),
];

/// Configure MSRs via the WHP API.
pub fn setup_msrs(vcpu: &whp::WhpVcpu) -> Result<()> {
    vcpu.set_registers64(REGISTERS).map_err(Error::SetMsrsWhp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_msrs_on_real_vcpu() {
        if whp::check_hypervisor().is_err() {
            eprintln!("WHP hypervisor not available, skipping");
            return;
        }
        let vm =
            std::sync::Arc::new(whp::WhpVm::new(1, false).expect("failed to create WHP partition"));
        let vcpu = whp::WhpVcpu::new(vm, 0).expect("failed to create vCPU");
        setup_msrs(&vcpu).expect("setup_msrs failed");
        let actual = vcpu
            .get_registers64(REGISTERS.map(|(name, _)| name))
            .expect("failed to read register back");

        assert_eq!(
            actual,
            REGISTERS.map(|(_, value)| value),
            "mismatch for msrs values"
        );
    }
}
