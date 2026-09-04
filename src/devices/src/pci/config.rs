// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use utils::byte_order;

const NUM_CONFIGURATION_REGISTERS: usize = 1024;
const STATUS_REG: usize = 1;
const STATUS_REG_CAPABILITIES_USED_MASK: u32 = 0x0010_0000;
const CAPABILITY_LIST_HEAD_OFFSET: u8 = 0x34;
const FIRST_CAPABILITY_OFFSET: u8 = 0x40;
const CAPABILITY_MAX_OFFSET: u16 = 192;

pub const NUM_BAR_REGS: u8 = 6;

#[derive(Debug, Default, Clone, Copy)]
pub struct Bar {
    pub encoded_addr: u32,
    pub encoded_size: u32,
}

impl Bar {
    pub fn used(&self) -> bool {
        !(self.encoded_addr == 0 && self.encoded_size == 0)
    }

    pub fn is_64bit(&self) -> bool {
        (self.encoded_addr & 0b100) == 0b100
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum BarPrefetchable {
    No = 0,
    Yes = 1,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Bars {
    pub bars: [Bar; NUM_BAR_REGS as usize],
}

impl Bars {
    pub fn set_bar_64(&mut self, bar_idx: u8, addr: u64, size: u64, prefetchable: BarPrefetchable) {
        assert_ne!(size, 0);
        assert!(size.is_power_of_two());
        assert!(addr & 0b1111 == 0);
        assert!(bar_idx < NUM_BAR_REGS - 1);

        let (size_lo, size_hi) = encode_64_bits_bar_size(size);
        let addr_lo = (addr & 0xffff_fff0) as u32;
        let addr_hi = (addr >> 32) as u32;
        let prefetchable = (prefetchable as u32) << 3;
        let is_64_bit = 0b100;

        self.bars[bar_idx as usize].encoded_addr = addr_lo | prefetchable | is_64_bit;
        self.bars[bar_idx as usize].encoded_size = size_lo;
        self.bars[(bar_idx + 1) as usize].encoded_addr = addr_hi;
        self.bars[(bar_idx + 1) as usize].encoded_size = size_hi;
    }

    pub fn get_bar_addr(&self, bar_idx: u8) -> u64 {
        assert!(self.bar_idx_valid(bar_idx));
        let bar = &self.bars[bar_idx as usize];
        if bar.is_64bit() {
            let lo = (bar.encoded_addr & !0xf) as u64;
            let hi = self.bars[(bar_idx + 1) as usize].encoded_addr as u64;
            lo | (hi << 32)
        } else {
            (bar.encoded_addr & !0xf) as u64
        }
    }

    pub fn get_bar_size(&self, bar_idx: u8) -> u64 {
        assert!(self.bar_idx_valid(bar_idx));
        let bar = &self.bars[bar_idx as usize];
        if bar.is_64bit() {
            decode_64_bits_bar_size(
                bar.encoded_size,
                self.bars[(bar_idx + 1) as usize].encoded_size,
            )
        } else {
            decode_32_bits_bar_size(bar.encoded_size)
        }
    }

    pub fn bar_idx_valid(&self, bar_idx: u8) -> bool {
        bar_idx < NUM_BAR_REGS
    }
}

fn decode_32_bits_bar_size(encoded: u32) -> u64 {
    if encoded == 0 {
        0
    } else {
        (!encoded).wrapping_add(1) as u64
    }
}

fn encode_64_bits_bar_size(size: u64) -> (u32, u32) {
    let encoded = (!size).wrapping_add(1);
    (encoded as u32, (encoded >> 32) as u32)
}

fn decode_64_bits_bar_size(lo: u32, hi: u32) -> u64 {
    let encoded = (u64::from(hi) << 32) | u64::from(lo);
    if encoded == 0 {
        0
    } else {
        (!encoded).wrapping_add(1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciCapabilityId {
    MsiX = 0x11,
    VendorSpecific = 0x09,
}

pub trait PciCapability {
    fn bytes(&self) -> &[u8];
    fn id(&self) -> PciCapabilityId;
}

#[derive(Debug, Clone, Copy)]
pub enum PciClassCode {
    UnassignedClass = 0xff,
    MassStorageController = 0x01,
    NetworkController = 0x02,
}

pub struct PciConfiguration {
    registers: [u32; NUM_CONFIGURATION_REGISTERS],
    writable_bits: [u32; NUM_CONFIGURATION_REGISTERS],
    bars: Bars,
    bar_probing: [bool; NUM_BAR_REGS as usize],
    capabilities: Vec<Box<dyn PciCapability + Send>>,
    msix_cap_offset: Option<u16>,
    next_capability_offset: u16,
    /// Offset of the last capability's "next" pointer byte, or the capability
    /// list head at 0x34 when no capabilities have been added yet.
    last_capability_next_ptr: u16,
}

impl PciConfiguration {
    pub fn new_type0(
        vendor_id: u16,
        device_id: u16,
        revision_id: u8,
        class_code: PciClassCode,
        subclass: u8,
        subsystem_vendor_id: u16,
        subsystem_id: u16,
    ) -> Self {
        let mut registers = [0u32; NUM_CONFIGURATION_REGISTERS];
        let mut writable_bits = [0u32; NUM_CONFIGURATION_REGISTERS];

        registers[0] = u32::from(vendor_id) | (u32::from(device_id) << 16);
        writable_bits[0] = 0;

        registers[1] = STATUS_REG_CAPABILITIES_USED_MASK;
        writable_bits[1] = 0x0000_ffff;

        registers[2] = u32::from(revision_id)
            | (u32::from(subclass) << 16)
            | (u32::from(class_code as u8) << 24);
        writable_bits[2] = 0;

        registers[3] = 0;
        writable_bits[3] = 0x0000_00ff;

        for slot in &mut writable_bits[4..10] {
            *slot = 0xffff_ffff;
        }

        registers[11] = u32::from(subsystem_vendor_id) | (u32::from(subsystem_id) << 16);

        // Interrupt Pin = INTA so guests without MSI can still use legacy INTx.
        registers[15] = 0x0000_0100;
        writable_bits[15] = 0x0000_00ff;

        Self {
            registers,
            writable_bits,
            bars: Bars::default(),
            bar_probing: [false; NUM_BAR_REGS as usize],
            capabilities: Vec::new(),
            msix_cap_offset: None,
            next_capability_offset: FIRST_CAPABILITY_OFFSET as u16,
            last_capability_next_ptr: CAPABILITY_LIST_HEAD_OFFSET as u16,
        }
    }

    pub fn bars(&self) -> &Bars {
        &self.bars
    }

    pub fn bars_mut(&mut self) -> &mut Bars {
        &mut self.bars
    }

    fn write_config_byte_raw(&mut self, offset: u16, value: u8) {
        let reg_idx = (offset / 4) as usize;
        let shift = ((offset % 4) * 8) as u32;
        if reg_idx >= NUM_CONFIGURATION_REGISTERS {
            return;
        }
        let reg = &mut self.registers[reg_idx];
        *reg = (*reg & !(0xff << shift)) | (u32::from(value) << shift);
    }

    /// Appends `cap` (body only; ID/next header is written here).
    pub fn add_capability(&mut self, cap: Box<dyn PciCapability + Send>) -> Option<u16> {
        let cap_bytes = cap.bytes();
        let body_len = cap_bytes.len();
        let total_len = 2 + body_len;
        let offset = self.next_capability_offset;
        if offset as usize + total_len > CAPABILITY_MAX_OFFSET as usize {
            return None;
        }

        self.write_config_byte_raw(self.last_capability_next_ptr, offset as u8);
        self.write_config_byte_raw(offset, cap.id() as u8);
        self.write_config_byte_raw(offset + 1, 0);

        for (i, byte) in cap_bytes.iter().enumerate() {
            self.write_config_byte_raw(offset + 2 + i as u16, *byte);
        }

        if cap.id() == PciCapabilityId::MsiX {
            self.msix_cap_offset = Some(offset);
            // Message Control enable/mask bits are writable by the guest.
            let msg_ctl_reg = ((offset + 2) / 4) as usize;
            self.writable_bits[msg_ctl_reg] |= 0xffff_0000;
        }

        self.capabilities.push(cap);
        self.last_capability_next_ptr = offset + 1;
        self.next_capability_offset = ((offset as usize + total_len + 3) & !3) as u16;
        self.registers[STATUS_REG] |= STATUS_REG_CAPABILITIES_USED_MASK;

        Some(offset)
    }

    fn bar_register_value(&self, reg_idx: usize) -> u32 {
        let bar_idx = (reg_idx - 4) as u8;
        let bar = &self.bars.bars[bar_idx as usize];
        if !bar.used() {
            return 0;
        }
        if self.bar_probing[bar_idx as usize] {
            return bar.encoded_size;
        }
        bar.encoded_addr
    }

    pub fn msix_cap_offset(&self) -> Option<u16> {
        self.msix_cap_offset
    }

    pub fn write_config_register(&mut self, reg_idx: usize, offset: u8, data: &[u8]) {
        if reg_idx >= NUM_CONFIGURATION_REGISTERS {
            return;
        }

        let mut reg = self.registers[reg_idx];
        let writable = self.writable_bits[reg_idx];

        for (i, byte) in data.iter().enumerate() {
            let shift = (offset as usize + i) * 8;
            if shift >= 32 {
                break;
            }
            let mask = (writable >> shift) & 0xff;
            reg = (reg & !(mask << shift)) | (u32::from(*byte) & mask) << shift;
        }
        self.registers[reg_idx] = reg;

        if (4..10).contains(&reg_idx) {
            let bar_idx = (reg_idx - 4) as u8;
            if data.iter().all(|&b| b == 0xff) {
                self.bar_probing[bar_idx as usize] = true;
            } else if self.bars.bars[bar_idx as usize].used() {
                self.bar_probing[bar_idx as usize] = false;
            } else {
                self.bars.bars[bar_idx as usize].encoded_addr = self.registers[reg_idx];
            }
        }
    }

    pub fn read_config_register(&self, reg_idx: usize, offset: u8, data: &mut [u8]) {
        if reg_idx >= NUM_CONFIGURATION_REGISTERS {
            data.fill(0xff);
            return;
        }

        let reg = if (4..10).contains(&reg_idx) {
            self.bar_register_value(reg_idx)
        } else {
            self.registers[reg_idx]
        };
        for (i, byte) in data.iter_mut().enumerate() {
            let shift = (offset as usize + i) * 8;
            if shift >= 32 {
                break;
            }
            *byte = ((reg >> shift) & 0xff) as u8;
        }
    }

    pub fn read_config_byte(&self, offset: u16) -> u8 {
        let reg_idx = (offset / 4) as usize;
        let byte_off = (offset % 4) as usize;
        let mut data = [0u8];
        self.read_config_register(reg_idx, byte_off as u8, &mut data);
        data[0]
    }

    pub fn write_config_byte(&mut self, offset: u16, value: u8) {
        let reg_idx = (offset / 4) as usize;
        let byte_off = (offset % 4) as usize;
        self.write_config_register(reg_idx, byte_off as u8, &[value]);
    }

    pub fn read_config_word(&self, offset: u16) -> u16 {
        let mut data = [0u8; 2];
        let reg_idx = (offset / 4) as usize;
        let byte_off = (offset % 4) as usize;
        self.read_config_register(reg_idx, byte_off as u8, &mut data);
        byte_order::read_le_u16(&data)
    }

    pub fn write_config_word(&mut self, offset: u16, value: u16) {
        let reg_idx = (offset / 4) as usize;
        let byte_off = (offset % 4) as usize;
        let mut data = [0u8; 2];
        byte_order::write_le_u16(&mut data, value);
        self.write_config_register(reg_idx, byte_off as u8, &data);
    }

    pub fn command_memory_space_enabled(&self) -> bool {
        self.read_config_word(0x04) & 0x0002 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_read_returns_programmed_address() {
        let mut config = PciConfiguration::new_type0(
            0x1af4,
            0x1049,
            1,
            PciClassCode::UnassignedClass,
            0xff,
            0x1af4,
            0x1049,
        );
        config
            .bars_mut()
            .set_bar_64(0, 0xd000_0000, 0x80_000, BarPrefetchable::No);

        let mut data = [0u8; 4];
        config.read_config_register(4, 0, &mut data);
        assert_eq!(byte_order::read_le_u32(&data), 0xd000_0004);

        config.read_config_register(5, 0, &mut data);
        assert_eq!(byte_order::read_le_u32(&data), 0);
    }

    #[test]
    fn bar_size_probe_returns_correct_64bit_mask() {
        let mut config = PciConfiguration::new_type0(
            0x1af4,
            0x1049,
            1,
            PciClassCode::UnassignedClass,
            0xff,
            0x1af4,
            0x9,
        );
        config
            .bars_mut()
            .set_bar_64(0, 0xd000_0000, 0x80_000, BarPrefetchable::No);

        // Size probe: write all-ones to both halves of the 64-bit BAR.
        config.write_config_register(4, 0, &[0xff, 0xff, 0xff, 0xff]);
        let mut data = [0u8; 4];
        config.read_config_register(4, 0, &mut data);
        assert_eq!(byte_order::read_le_u32(&data), 0xfff8_0000);

        config.write_config_register(5, 0, &[0xff, 0xff, 0xff, 0xff]);
        config.read_config_register(5, 0, &mut data);
        assert_eq!(byte_order::read_le_u32(&data), 0xffff_ffff);
    }
}
