// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "linux")]
pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=-1 panic_print=0 nomodule console=hvc0 \
                                          rootfstype=virtiofs rw quiet no-kvmapf";
#[cfg(target_os = "macos")]
pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=-1 panic_print=0 nomodule console=hvc0 \
                                          rootfstype=virtiofs rw quiet no-kvmapf";
// WHP (Windows Hypervisor Platform) differs from KVM in that it provides
// no in-kernel PIT, PIC, or IOAPIC emulation. All three are emulated in
// userspace. This makes interrupt delivery inherently less precise than KVM,
// so we add the no_timer_check flag to skip the timer check to avoid panics.
#[cfg(target_os = "windows")]
pub const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=-1 panic_print=0 nomodule console=hvc0 \
                                          rootfstype=virtiofs rw quiet no_timer_check";

/// Strongly typed data structure used to configure the boot source of the
/// microvm.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct KernelCmdlineConfig {
    pub prolog: Option<String>,
    pub krun_env: Option<String>,
    pub epilog: Option<String>,
}
