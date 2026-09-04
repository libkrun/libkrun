// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::result;

use acpi_tables::Aml;
use acpi_tables::aml::{
    AddressSpace, AddressSpaceCacheable, Device, EISAName, IO, Interrupt, Memory32Fixed, Name,
    Path, ResourceTemplate, Scope,
};
use acpi_tables::fadt::{FADTBuilder, Flags};
use acpi_tables::madt::{
    EnabledStatus, IoApic, LocalInterruptController, MADT, ProcessorLocalApic,
};
use acpi_tables::rsdp::Rsdp;
use acpi_tables::sdt::Sdt;
use acpi_tables::xsdt::XSDT;
use vm_memory::Bytes;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, Permissions};
use zerocopy::IntoBytes;

use crate::x86_64::layout::{HIMEM_START, PCI_ECAM_START, PCI_MMIO_END, PCI_MMIO_START, RSDP_ADDR};

/// Standard local APIC physical base address.
const LOCAL_APIC_DEFAULT_PHYS_BASE: u32 = 0xfee0_0000;
/// Standard I/O APIC physical base address.
const IO_APIC_DEFAULT_PHYS_BASE: u32 = 0xfec0_0000;
/// With APIC/xAPIC, there are only 255 APIC IDs available, and the I/O APIC
/// occupies one, so at most 254 CPUs can be represented in the MADT.
const MAX_SUPPORTED_CPUS: u32 = 254;

/// Builds a 36-byte ACPI 2.0+ RSDP pointing at the given XSDT address.
fn build_rsdp(xsdt_addr: u64) -> Vec<u8> {
    Rsdp::new(*b"LIBKRN", xsdt_addr).as_bytes().to_vec()
}

fn build_dsdt(virtio_mmio_devices: &[(u64, u32)], virtio_pci: bool) -> Vec<u8> {
    let mut aml_body = Vec::new();

    // (io_base, irq, acpi_device_name) — PC/AT standard COM port assignments
    const COM_PORTS: [(u16, u32, &str); 4] = [
        (0x3F8, 4, "COM1"),
        (0x2F8, 3, "COM2"),
        (0x3E8, 4, "COM3"),
        (0x2E8, 3, "COM4"),
    ];
    for (i, &(io_base, irq, name)) in COM_PORTS.iter().enumerate() {
        let hid = Name::new(Path::new("_HID"), &EISAName::new("PNP0501"));
        let uid = Name::new(Path::new("_UID"), &(i as u32));
        let io_res = IO::new(io_base, io_base, 0x08, 0x08);
        let irq_res = Interrupt::new(true, true, false, false, irq);
        let crs = Name::new(
            Path::new("_CRS"),
            &ResourceTemplate::new(vec![&io_res, &irq_res]),
        );
        Device::new(Path::new(name), vec![&hid, &uid, &crs]).to_aml_bytes(&mut aml_body);
    }

    {
        let hid = Name::new(Path::new("_HID"), &EISAName::new("PNP0303"));
        let uid = Name::new(Path::new("_UID"), &0u32);
        let io_data = IO::new(0x0060, 0x0060, 0x01, 0x01);
        let io_cmd = IO::new(0x0064, 0x0064, 0x01, 0x01);
        let irq_res = Interrupt::new(true, true, false, false, 1);
        let crs = Name::new(
            Path::new("_CRS"),
            &ResourceTemplate::new(vec![&io_data, &io_cmd, &irq_res]),
        );
        Device::new(Path::new("KBD0"), vec![&hid, &uid, &crs]).to_aml_bytes(&mut aml_body);
    }

    if !virtio_pci {
        for (i, &(mmio_base, irq)) in virtio_mmio_devices.iter().enumerate() {
            let name = format!("VR{i:02X}");
            let hid = Name::new(Path::new("_HID"), &"LNRO0005");
            let uid = Name::new(Path::new("_UID"), &(i as u32));
            let mem = Memory32Fixed::new(true, mmio_base as u32, 0x1000);
            let irq_res = Interrupt::new(true, false, false, false, irq);
            let crs = Name::new(
                Path::new("_CRS"),
                &ResourceTemplate::new(vec![&mem, &irq_res]),
            );
            Device::new(Path::new(&name), vec![&hid, &uid, &crs]).to_aml_bytes(&mut aml_body);
        }
    }

    if virtio_pci {
        let bus_number = AddressSpace::<u16>::new_bus_number(0, 0xff);
        let io_low = AddressSpace::<u16>::new_io(0x0000, 0x0cf7, None);
        let io_high = AddressSpace::<u16>::new_io(0x0d00, 0xffff, None);
        let pci_mmio = AddressSpace::<u32>::new_memory(
            AddressSpaceCacheable::NotCacheable,
            true,
            PCI_MMIO_START as u32,
            PCI_MMIO_END as u32,
            None,
        );
        let hid = Name::new(Path::new("_HID"), &EISAName::new("PNP0A08"));
        // PNP0A03 keeps legacy PCI enumeration working alongside PCIe PNP0A08.
        let cid = Name::new(Path::new("_CID"), &EISAName::new("PNP0A03"));
        let adr = Name::new(Path::new("_ADR"), &0u32);
        let seg = Name::new(Path::new("_SEG"), &0u32);
        let bbn = Name::new(Path::new("_BBN"), &0u32);
        let uid = Name::new(Path::new("_UID"), &0u32);
        let cca = Name::new(Path::new("_CCA"), &1u32);
        let crs = Name::new(
            Path::new("_CRS"),
            &ResourceTemplate::new(vec![&bus_number, &io_low, &io_high, &pci_mmio]),
        );
        Device::new(
            Path::new("PCI0"),
            vec![&hid, &cid, &adr, &seg, &bbn, &uid, &cca, &crs],
        )
        .to_aml_bytes(&mut aml_body);
    }

    let scope_bytes = Scope::raw(Path::new("\\_SB_"), aml_body);

    let mut dsdt = Sdt::new(*b"DSDT", 36, 2, *b"LIBKRN", *b"KRUNDSDT", 1);
    dsdt.append_slice(&scope_bytes);
    dsdt.as_slice().to_vec()
}

/// Builds a minimal ACPI 6.x FADT pointing at the given DSDT address.
/// HW_REDUCED_ACPI is set: all devices are described in the DSDT via
/// extended interrupt descriptors, so no legacy PIC or PM hardware is
/// needed.
fn build_fadt(dsdt_addr: u64) -> Vec<u8> {
    let fadt = FADTBuilder::new(*b"LIBKRN", *b"KRUNFADT", 1)
        .dsdt_64(dsdt_addr)
        .flag(Flags::HwReducedAcpi)
        .finalize();
    let mut bytes = Vec::new();
    fadt.to_aml_bytes(&mut bytes);
    bytes
}

/// Builds an ACPI 6.x MADT with one Processor Local APIC entry per vCPU
/// and one I/O APIC entry.
fn build_madt(num_cpus: u8) -> Vec<u8> {
    let mut madt = MADT::new(
        *b"LIBKRN",
        *b"KRUNAPIC",
        1,
        LocalInterruptController::Address(LOCAL_APIC_DEFAULT_PHYS_BASE),
    );

    for cpu_id in 0..num_cpus {
        madt.add_structure(ProcessorLocalApic::new(
            cpu_id,
            cpu_id,
            EnabledStatus::Enabled,
        ));
    }

    madt.add_structure(IoApic::new(num_cpus + 1, IO_APIC_DEFAULT_PHYS_BASE, 0));

    let mut bytes = Vec::new();
    madt.to_aml_bytes(&mut bytes);

    bytes
}

/// Builds an ACPI 2.0+ XSDT with entries for the given 64-bit table addresses.
fn build_xsdt(entry_addrs: &[u64]) -> Vec<u8> {
    let mut xsdt = XSDT::new(*b"LIBKRN", *b"KRUNXSDT", 1);
    for addr in entry_addrs {
        xsdt.add_entry(*addr);
    }
    let mut bytes = Vec::new();
    xsdt.to_aml_bytes(&mut bytes);
    bytes
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// The reserved ACPI window (RSDP_ADDR..HIMEM_START) is too small to
    /// hold the generated tables.
    NotEnoughMemory,
    /// Failed to write a table into guest memory.
    WriteFailed,
    /// `num_cpus` exceeds what a single MADT I/O APIC entry ID (`num_cpus + 1`, a u8) can represent.
    TooManyCpus,
}

pub type Result<T> = result::Result<T, Error>;

/// Builds an MCFG table describing the PCI ECAM region.
fn build_mcfg(ecam_base: u64) -> Vec<u8> {
    const MCFG_LEN: u32 = 60;

    let mut mcfg = vec![0u8; MCFG_LEN as usize];
    mcfg[0..4].copy_from_slice(b"MCFG");
    mcfg[4..8].copy_from_slice(&MCFG_LEN.to_le_bytes());
    mcfg[8] = 1;
    mcfg[10..16].copy_from_slice(b"LIBKRN");
    mcfg[16..24].copy_from_slice(b"KRUNMCFG");
    mcfg[24..28].copy_from_slice(&1u32.to_le_bytes());
    mcfg[44..52].copy_from_slice(&ecam_base.to_le_bytes());
    mcfg[54] = 0;
    mcfg[55] = 255;

    let sum: u8 = mcfg.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    mcfg[9] = mcfg[9].wrapping_sub(sum);
    mcfg
}

/// Builds and writes RSDP, XSDT, FADT, DSDT, and MADT into guest memory
/// starting at `RSDP_ADDR`. Must be called for every payload type, including TEE.
pub fn setup_acpi(
    mem: &GuestMemoryMmap,
    num_cpus: u8,
    virtio_mmio_devices: &[(u64, u32)],
    virtio_pci: bool,
) -> Result<()> {
    if u32::from(num_cpus) > MAX_SUPPORTED_CPUS {
        return Err(Error::TooManyCpus);
    }

    let dsdt = build_dsdt(virtio_mmio_devices, virtio_pci);
    let madt = build_madt(num_cpus);
    let mcfg = if virtio_pci {
        Some(build_mcfg(PCI_ECAM_START))
    } else {
        None
    };

    const RSDP_SIZE: u64 = 36;
    let xsdt_entry_count = if virtio_pci { 3 } else { 2 };
    let xsdt_size = 36 + xsdt_entry_count * 8;
    let fadt_size_placeholder = build_fadt(0).len() as u64;

    let rsdp_addr = RSDP_ADDR;
    let xsdt_addr = rsdp_addr + RSDP_SIZE;
    let fadt_addr = xsdt_addr + xsdt_size as u64;
    let dsdt_addr = fadt_addr + fadt_size_placeholder;
    let madt_addr = dsdt_addr + dsdt.len() as u64;
    let mcfg_addr = madt_addr + madt.len() as u64;

    let fadt = build_fadt(dsdt_addr);
    let xsdt_entries: Vec<u64> = if virtio_pci {
        vec![fadt_addr, madt_addr, mcfg_addr]
    } else {
        vec![fadt_addr, madt_addr]
    };
    let xsdt = build_xsdt(&xsdt_entries);
    let rsdp = build_rsdp(xsdt_addr);

    let mut total_size = rsdp.len() as u64
        + xsdt.len() as u64
        + fadt.len() as u64
        + dsdt.len() as u64
        + madt.len() as u64;
    if let Some(ref mcfg_table) = mcfg {
        total_size += mcfg_table.len() as u64;
    }
    if rsdp_addr + total_size > HIMEM_START
        || !mem.check_range(GuestAddress(rsdp_addr), total_size as usize, Permissions::Write)
    {
        return Err(Error::NotEnoughMemory);
    }

    mem.write_slice(&rsdp, GuestAddress(rsdp_addr))
        .map_err(|_| Error::WriteFailed)?;
    mem.write_slice(&xsdt, GuestAddress(xsdt_addr))
        .map_err(|_| Error::WriteFailed)?;
    mem.write_slice(&fadt, GuestAddress(fadt_addr))
        .map_err(|_| Error::WriteFailed)?;
    mem.write_slice(&dsdt, GuestAddress(dsdt_addr))
        .map_err(|_| Error::WriteFailed)?;
    mem.write_slice(&madt, GuestAddress(madt_addr))
        .map_err(|_| Error::WriteFailed)?;
    if let Some(ref mcfg_table) = mcfg {
        mem.write_slice(mcfg_table, GuestAddress(mcfg_addr))
            .map_err(|_| Error::WriteFailed)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn madt_has_one_lapic_entry_per_cpu() {
        let num_cpus = 4u8;
        let bytes = build_madt(num_cpus);
        assert_eq!(&bytes[0..4], b"APIC");

        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        // Fixed MADT header is 44 bytes (36-byte SDT header + 4 + 4), per ACPI 6.x.
        let mut offset = 44usize;
        let mut lapic_count = 0;
        let mut ioapic_count = 0;
        while offset < bytes.len() {
            let entry_type = bytes[offset];
            let entry_len = bytes[offset + 1] as usize;
            match entry_type {
                0 => lapic_count += 1,
                1 => ioapic_count += 1,
                t => panic!("unexpected MADT entry type {t}"),
            }
            offset += entry_len;
        }
        assert_eq!(lapic_count, num_cpus as usize);
        assert_eq!(ioapic_count, 1);
    }

    #[test]
    fn rsdp_checksums_are_valid() {
        let bytes = build_rsdp(crate::x86_64::layout::RSDP_ADDR);
        assert_eq!(bytes.len(), 36);

        // First 20 bytes (ACPI 1.0-compatible region) must sum to 0.
        let sum1: u8 = bytes[0..20].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum1, 0);

        // Full 36-byte structure must also sum to 0.
        let sum2: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum2, 0);

        assert_eq!(&bytes[0..8], b"RSD PTR ");
    }

    #[test]
    fn dsdt_contains_device_nodes() {
        let devices = vec![(0xd000_0000u64, 5u32), (0xd000_1000, 6)];
        let bytes = build_dsdt(&devices, false);

        assert_eq!(&bytes[..4], b"DSDT");

        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        let length = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert!(length > 36);

        assert!(bytes.len() > 100);
    }

    #[test]
    fn dsdt_pci_host_bridge_describes_pci_bus() {
        let pci = build_dsdt(&[], true);
        let mmio = build_dsdt(&[], false);

        let sum: u8 = pci.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);
        assert!(pci.len() > mmio.len());
    }

    #[test]
    fn dsdt_empty_devices() {
        let bytes = build_dsdt(&[], false);

        assert_eq!(&bytes[..4], b"DSDT");
        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        // Even with no virtio devices, ISA devices are still present
        let length = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert!(length > 36);
    }

    #[test]
    fn fadt_has_hw_reduced_flag() {
        let bytes = build_fadt(0x000e_1100);

        // FADT flags field is at byte offset 112 (per ACPI 6.x spec)
        let flags = u32::from_le_bytes(bytes[112..116].try_into().unwrap());
        // HW_REDUCED_ACPI is bit 20
        assert_ne!(flags & (1 << 20), 0, "HW_REDUCED_ACPI must be set");
    }

    #[test]
    fn fadt_layout_and_checksum() {
        let bytes = build_fadt(0x000e_1100);
        assert_eq!(&bytes[0..4], b"FACP");
        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        // x_dsdt field is at byte offset 140, little-endian u64 (ACPI 6.x FADT layout).
        let x_dsdt = u64::from_le_bytes(bytes[140..148].try_into().unwrap());
        assert_eq!(x_dsdt, 0x000e_1100);
    }

    #[test]
    fn xsdt_lists_all_entry_addresses() {
        let entries = [0x000e_2000u64, 0x000e_3000u64];
        let bytes = build_xsdt(&entries);
        assert_eq!(&bytes[0..4], b"XSDT");

        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        let header_size = 36; // fixed ACPI SDT header size
        for (i, expected) in entries.iter().enumerate() {
            let off = header_size + i * 8;
            let got = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            assert_eq!(got, *expected);
        }
    }

    #[test]
    fn mcfg_layout_and_checksum() {
        use crate::x86_64::layout::PCI_ECAM_START;

        let bytes = build_mcfg(PCI_ECAM_START);
        assert_eq!(&bytes[0..4], b"MCFG");
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 60);
        assert_eq!(&bytes[10..16], b"LIBKRN");

        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        let ecam_base = u64::from_le_bytes(bytes[44..52].try_into().unwrap());
        assert_eq!(ecam_base, PCI_ECAM_START);
        assert_eq!(bytes[54], 0);
        assert_eq!(bytes[55], 255);
    }

    #[test]
    fn setup_acpi_with_virtio_pci_fits_in_reserved_window() {
        let window_size = (HIMEM_START - RSDP_ADDR) as usize;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(RSDP_ADDR), window_size)]).unwrap();

        setup_acpi(&mem, 4, &[], true).unwrap();
    }

    #[test]
    fn setup_acpi_fits_in_reserved_window() {
        let window_size = (HIMEM_START - RSDP_ADDR) as usize;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(RSDP_ADDR), window_size)]).unwrap();

        setup_acpi(&mem, 4, &[], false).unwrap();

        let rsdp: [u8; 8] = {
            let mut buf = [0u8; 8];
            mem.read_slice(&mut buf, GuestAddress(RSDP_ADDR)).unwrap();
            buf
        };
        assert_eq!(&rsdp, b"RSD PTR ");
    }

    #[test]
    fn setup_acpi_fails_if_window_too_small() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(RSDP_ADDR), 8)]).unwrap();
        assert!(setup_acpi(&mem, 4, &[], false).is_err());
    }

    #[test]
    fn setup_acpi_fails_if_too_many_cpus() {
        let window_size = (HIMEM_START - RSDP_ADDR) as usize;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(RSDP_ADDR), window_size)]).unwrap();

        assert_eq!(setup_acpi(&mem, 255, &[], false), Err(Error::TooManyCpus));
    }
}
