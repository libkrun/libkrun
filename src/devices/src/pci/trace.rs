// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0
//
// Targeted virtio-pci bringup tracing. Filter with:
//   RUST_LOG=krun_devices::virtio::pci=debug ...

use utils::byte_order;

use super::PciBdf;

pub(crate) fn ecam_access(bdf: &PciBdf, offset: u16, write: bool, data: &[u8], found: bool) {
    if !found {
        return;
    }

    match offset {
        0 if !write && data.len() >= 4 => {
            let value = byte_order::read_le_u32(data);
            log::debug!(
                target: "krun_devices::virtio::pci",
                "{bdf}: config read vendor/device -> {value:#010x}"
            );
        }
        4 if write && data.len() >= 2 => {
            let cmd = byte_order::read_le_u16(data);
            log::debug!(
                target: "krun_devices::virtio::pci",
                "{bdf}: config write command -> {cmd:#06x}"
            );
        }
        4 if !write && data.len() >= 2 => {
            let cmd = byte_order::read_le_u16(data);
            log::debug!(
                target: "krun_devices::virtio::pci",
                "{bdf}: config read command -> {cmd:#06x}"
            );
        }
        0x10..=0x24 if write => {
            log::debug!(
                target: "krun_devices::virtio::pci",
                "{bdf}: config write BAR offset {offset:#x} data={data:02x?}"
            );
        }
        _ => {}
    }
}

pub(crate) fn msix_enable(bdf: &PciBdf, enabled: bool, masked: bool) {
    log::debug!(
        target: "krun_devices::virtio::pci",
        "{bdf}: MSI-X enable={enabled} function_mask={masked}"
    );
}

pub(crate) fn msix_vector(bdf: &PciBdf, vector: usize, addr_lo: u32, addr_hi: u32, data: u32) {
    log::debug!(
        target: "krun_devices::virtio::pci",
        "{bdf}: MSI-X vector {vector} addr={addr_hi:#010x}:{addr_lo:#010x} data={data:#010x}"
    );
}

pub(crate) fn msix_route_update(bdf: &PciBdf, gsi: u32) {
    log::debug!(
        target: "krun_devices::virtio::pci",
        "{bdf}: KVM MSI route updated for GSI {gsi}"
    );
}
