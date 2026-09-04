// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

mod config;
mod ecam;
mod msix;
mod trace;

pub use self::config::{
    BarPrefetchable, Bars, PciCapability, PciCapabilityId, PciClassCode, PciConfiguration,
};
pub use self::ecam::{PciBdf, PciBus, PciDevice, PciEcam};
pub use self::msix::{
    MsixCap, MsixConfig, MsixRouteContext, MsixVector, x86_default_irqchip_routes,
};

pub const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
pub const VIRTIO_PCI_DEVICE_ID_BASE: u16 = 0x1040;
