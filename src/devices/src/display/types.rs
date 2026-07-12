// Copyright 2026, Red Hat Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Common display types for EDID generation.

use virtio_bindings::virtio_gpu::VIRTIO_GPU_MAX_SCANOUTS;

pub const MAX_DISPLAYS: usize = VIRTIO_GPU_MAX_SCANOUTS as usize;

use super::edid::EdidInfo;

#[derive(Debug, Clone)]
pub struct EdidParams {
    pub refresh_rate: u32,
    pub physical_size: PhysicalSize,
    pub manufacturer: [u8; 3],
    pub display_name: String,
}

impl Default for EdidParams {
    fn default() -> Self {
        EdidParams {
            refresh_rate: 60,
            physical_size: PhysicalSize::Dpi(300),
            manufacturer: *b"RHT",
            display_name: "krun-display".to_string(),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum PhysicalSize {
    Dpi(u32),
    DimensionsMillimeters(u16, u16),
}

/// User-configured display (monitor) properties.
/// Distinct from the scanout (guest framebuffer), which may be smaller.
#[derive(Clone, Debug)]
pub struct DisplayInfo {
    pub width: u32,
    pub height: u32,
    pub edid: DisplayInfoEdid,
}

#[derive(Debug, Clone)]
pub enum DisplayInfoEdid {
    Generated(EdidParams),
    Provided(Box<[u8]>),
}

impl DisplayInfo {
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            edid: DisplayInfoEdid::Generated(EdidParams::default()),
        }
    }

    pub fn edid_bytes(&self) -> Box<[u8]> {
        match &self.edid {
            DisplayInfoEdid::Provided(edid_bytes) => edid_bytes.clone(),
            DisplayInfoEdid::Generated(edid_params) => {
                let edid_info = EdidInfo::new(self.width, self.height, edid_params);
                edid_info.bytes()
            }
        }
    }
}
