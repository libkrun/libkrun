// Copyright 2025 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Debug;
use std::{io, result};

use crate::DeviceType;
use crate::legacy::IrqChip;
use crate::legacy::aia::AIADevice;
use arch::riscv64::get_fdt_addr;
use arch::riscv64::layout::IRQ_BASE;
use arch::{ArchMemoryInfo, InitrdConfig};
use vm_fdt::{Error as FdtError, FdtWriter};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};

const AIA_APLIC_PHANDLE: u32 = 1;
const AIA_IMSIC_PHANDLE: u32 = 2;
const CPU_INTC_BASE_PHANDLE: u32 = 3;
const CPU_BASE_PHANDLE: u32 = 256 + CPU_INTC_BASE_PHANDLE;
// Read the documentation specified when appending the root node to the FDT.
const ADDRESS_CELLS: u32 = 0x2;
const SIZE_CELLS: u32 = 0x2;

// From https://elixir.bootlin.com/linux/v6.10/source/include/dt-bindings/interrupt-controller/irq.h#L14
const _IRQ_TYPE_EDGE_RISING: u32 = 1;
const IRQ_TYPE_LEVEL_HI: u32 = 4;

const S_MODE_EXT_IRQ: u32 = 9;

/// Trait for devices to be added to the Flattened Device Tree.
pub trait DeviceInfoForFDT {
    /// Returns the address where this device will be loaded.
    fn addr(&self) -> u64;
    /// Returns the associated interrupt for this device.
    fn irq(&self) -> u32;
    /// Returns the amount of memory that needs to be reserved for this device.
    fn length(&self) -> u64;
}

/// Errors thrown while configuring the Flattened Device Tree for aarch64.
#[derive(Debug)]
pub enum Error {
    /// Creating FDT failed.
    CreateFDT(FdtError),
    /// Failure in calling syscall for terminating this FDT.
    FinishFDTReserveMap(io::Error),
    /// Failure in writing FDT in memory.
    WriteFDTToMemory(GuestMemoryError),
}
type Result<T> = result::Result<T, Error>;

impl From<FdtError> for Error {
    fn from(item: FdtError) -> Self {
        Error::CreateFDT(item)
    }
}

/// Creates the flattened device tree for this riscv64 VM.
#[allow(clippy::too_many_arguments)]
pub fn create_fdt<T: DeviceInfoForFDT + Clone + Debug>(
    guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
    num_vcpu: u32,
    timebase_frequency: u32,
    cmdline: &str,
    device_info: &HashMap<(DeviceType, String), T>,
    aia_device: &IrqChip,
    initrd: &Option<InitrdConfig>,
    riscv_isa_info: &Option<arch::riscv64::linux::kvm::RiscvIsaInfo>,
) -> Result<Vec<u8>> {
    // Allocate stuff necessary for the holding the blob.
    let mut fdt = FdtWriter::new()?;

    // For an explanation why these nodes were introduced in the blob take a look at
    // https://github.com/torvalds/linux/blob/master/Documentation/devicetree/booting-without-of.txt#L845
    // Look for "Required nodes and properties".

    // Header or the root node as per above mentioned documentation.
    let root_node = fdt.begin_node("")?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    // For info on #address-cells and size-cells resort to Table 3.1 Root Node
    // Properties
    fdt.property_u32("#address-cells", ADDRESS_CELLS)?;
    fdt.property_u32("#size-cells", SIZE_CELLS)?;
    create_cpu_nodes(&mut fdt, num_vcpu, timebase_frequency, riscv_isa_info)?;
    create_memory_node(&mut fdt, guest_mem, arch_memory_info)?;
    create_chosen_node(&mut fdt, cmdline, initrd)?;
    create_aia_node(&mut fdt, aia_device)?;
    create_devices_node(&mut fdt, device_info)?;

    // End Header node.
    fdt.end_node(root_node)?;

    // Allocate another buffer so we can format and then write fdt to guest.
    let fdt_final = fdt.finish()?;

    // Write FDT to memory.
    let fdt_address = GuestAddress(get_fdt_addr(guest_mem));
    guest_mem
        .write_slice(fdt_final.as_slice(), fdt_address)
        .map_err(Error::WriteFDTToMemory)?;
    Ok(fdt_final)
}

// Following are the auxiliary function for creating the different nodes that we append to our FDT.
fn create_cpu_nodes(
    fdt: &mut FdtWriter,
    num_cpus: u32,
    timebase_frequency: u32,
    riscv_isa_info: &Option<arch::riscv64::linux::kvm::RiscvIsaInfo>,
) -> Result<()> {
    // See https://elixir.bootlin.com/linux/v6.10/source/Documentation/devicetree/bindings/riscv/cpus.yaml
    let cpus = fdt.begin_node("cpus")?;
    // As per documentation, on RISC-V 64-bit systems value should be set to 1.
    fdt.property_u32("#address-cells", 0x01)?;
    fdt.property_u32("#size-cells", 0x0)?;
    fdt.property_u32("timebase-frequency", timebase_frequency)?;

    for cpu_index in 0..num_cpus {
        let cpu = fdt.begin_node(&format!("cpu@{cpu_index:x}"))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "riscv")?;
        fdt.property_string("mmu-type", "sv48")?;

        // "riscv,isa" is deprecated by the kernel in favor of the
        // "riscv,isa-base" + "riscv,isa-extensions" pair; we only emit the
        // modern properties.
        //
        // "riscv,isa-base" identifies the base ISA and is always "rv64i" on
        // riscv64 (see Documentation/devicetree/bindings/riscv/extensions.yaml).
        fdt.property_string("riscv,isa-base", "rv64i")?;

        // "riscv,isa-extensions" is a devicetree stringlist: each extension
        // name must be its own NUL-terminated string. property_string_list()
        // concatenates each entry with its own trailing NUL. Use the
        // detected extensions if available, otherwise fall back to
        // `arch::riscv64::linux::kvm::DEFAULT_ISA_EXTENSIONS` so the CPU
        // node remains valid and matches the same fallback used by the
        // detection code itself when it cannot probe anything.
        let ext_list: Vec<String> = match riscv_isa_info {
            Some(isa_info) if !isa_info.extensions.is_empty() => {
                isa_info.extensions.iter().cloned().collect()
            }
            _ => arch::riscv64::linux::kvm::DEFAULT_ISA_EXTENSIONS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };

        // Only emit a cache block size property alongside the extension it
        // belongs to: the devicetree bindings document these as dependent
        // on the matching Z extension being listed in
        // "riscv,isa-extensions", and the guest kernel sizes real `cbo.*`
        // cache-maintenance instructions off these values, so they must
        // not be advertised for an extension we did not detect.
        let has_ext = |name: &str| ext_list.iter().any(|e| e == name);
        if let Some(isa_info) = riscv_isa_info {
            if has_ext("zicbom") {
                if let Some(size) = isa_info.zicbom_block_size {
                    fdt.property_u32("riscv,cbom-block-size", size)?;
                }
            }
            if has_ext("zicboz") {
                if let Some(size) = isa_info.zicboz_block_size {
                    fdt.property_u32("riscv,cboz-block-size", size)?;
                }
            }
            if has_ext("zicbop") {
                if let Some(size) = isa_info.zicbop_block_size {
                    fdt.property_u32("riscv,cbop-block-size", size)?;
                }
            }
        }

        fdt.property_string_list("riscv,isa-extensions", ext_list)?;

        fdt.property_string("status", "okay")?;
        fdt.property_u32("reg", cpu_index)?;
        fdt.property_u32("phandle", CPU_BASE_PHANDLE + cpu_index)?;

        // interrupt controller node
        let intc_node = fdt.begin_node("interrupt-controller")?;
        fdt.property_string("compatible", "riscv,cpu-intc")?;
        fdt.property_u32("#interrupt-cells", 1u32)?;
        fdt.property_null("interrupt-controller")?;
        fdt.property_u32("phandle", CPU_INTC_BASE_PHANDLE + cpu_index)?;
        fdt.end_node(intc_node)?;

        fdt.end_node(cpu)?;
    }
    fdt.end_node(cpus)?;
    Ok(())
}

fn create_memory_node(
    fdt: &mut FdtWriter,
    _guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
) -> Result<()> {
    let mem_size = arch_memory_info.ram_last_addr - arch::riscv64::layout::DRAM_MEM_START;
    // See https://github.com/torvalds/linux/blob/master/Documentation/devicetree/booting-without-of.txt#L960
    // for an explanation of this.
    let mem_reg_prop = [arch::riscv64::layout::DRAM_MEM_START, mem_size];

    let mem_node = fdt.begin_node("memory")?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", &mem_reg_prop)?;
    fdt.end_node(mem_node)?;
    Ok(())
}

fn create_chosen_node(
    fdt: &mut FdtWriter,
    cmdline: &str,
    initrd: &Option<InitrdConfig>,
) -> Result<()> {
    let chosen_node = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", cmdline)?;

    if let Some(initrd_config) = initrd {
        fdt.property_u64("linux,initrd-start", initrd_config.address.raw_value())?;
        fdt.property_u64(
            "linux,initrd-end",
            initrd_config.address.raw_value() + initrd_config.size as u64,
        )?;
    }

    fdt.end_node(chosen_node)?;

    Ok(())
}

fn create_aia_node(fdt: &mut FdtWriter, aia_device: &IrqChip) -> Result<()> {
    // IMSIC
    if aia_device.lock().unwrap().msi_compatible() {
        use arch::riscv64::layout::IMSIC_START;
        let imsic_name = format!("imsics@{IMSIC_START:x}");
        let imsic_node = fdt.begin_node(&imsic_name)?;

        fdt.property_string(
            "compatible",
            aia_device.lock().unwrap().imsic_compatibility(),
        )?;
        let imsic_reg_prop = aia_device.lock().unwrap().imsic_properties();
        fdt.property_array_u32("reg", &imsic_reg_prop)?;
        fdt.property_u32("#interrupt-cells", 0u32)?;
        fdt.property_null("interrupt-controller")?;
        fdt.property_null("msi-controller")?;
        // TODO complete num-ids
        fdt.property_u32("riscv,num-ids", 2047u32)?;
        fdt.property_u32("phandle", AIA_IMSIC_PHANDLE)?;

        let mut irq_cells = Vec::new();
        let num_cpus = aia_device.lock().unwrap().vcpu_count();
        for i in 0..num_cpus {
            irq_cells.push(CPU_INTC_BASE_PHANDLE + i);
            irq_cells.push(S_MODE_EXT_IRQ);
        }
        fdt.property_array_u32("interrupts-extended", &irq_cells)?;

        fdt.end_node(imsic_node)?;
    }

    // APLIC
    use arch::riscv64::layout::APLIC_START;
    let aplic_name = format!("aplic@{APLIC_START:x}");
    let aplic_node = fdt.begin_node(&aplic_name)?;

    fdt.property_string(
        "compatible",
        aia_device.lock().unwrap().aplic_compatibility(),
    )?;
    let reg_cells = aia_device.lock().unwrap().aplic_properties();
    fdt.property_array_u32("reg", &reg_cells)?;
    fdt.property_u32("#interrupt-cells", 2u32)?;
    fdt.property_null("interrupt-controller")?;
    fdt.property_u32("riscv,num-sources", 96u32)?;
    fdt.property_u32("phandle", AIA_APLIC_PHANDLE)?;
    fdt.property_u32("msi-parent", AIA_IMSIC_PHANDLE)?;

    fdt.end_node(aplic_node)?;

    Ok(())
}

fn create_virtio_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let device_reg_prop = [dev_info.addr(), dev_info.length()];
    #[cfg(target_os = "linux")]
    let irq = [dev_info.irq() - IRQ_BASE, IRQ_TYPE_LEVEL_HI];

    let virtio_node = fdt.begin_node(&format!("virtio_mmio@{:x}", dev_info.addr()))?;
    fdt.property_string("compatible", "virtio,mmio")?;
    fdt.property_array_u64("reg", &device_reg_prop)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.property_u32("interrupt-parent", AIA_APLIC_PHANDLE)?;
    fdt.end_node(virtio_node)?;

    Ok(())
}

fn create_serial_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let serial_reg_prop = [dev_info.addr(), dev_info.length()];
    let irq = [dev_info.irq() - IRQ_BASE, IRQ_TYPE_LEVEL_HI];

    let serial_node = fdt.begin_node(&format!("serial@{:x}", dev_info.addr()))?;
    fdt.property_string("compatible", "ns16550a")?;
    fdt.property_array_u64("reg", &serial_reg_prop)?;
    fdt.property_u32("clock-frequency", 3686400)?;
    fdt.property_u32("interrupt-parent", AIA_APLIC_PHANDLE)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.end_node(serial_node)?;

    Ok(())
}

fn create_rtc_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let rtc_reg_prop = [dev_info.addr(), dev_info.length()];
    let irq = [dev_info.irq(), IRQ_TYPE_LEVEL_HI];

    let rtc_node = fdt.begin_node(&format!("rtc@{:x}", dev_info.addr()))?;
    fdt.property_string("compatible", "google,goldfish-rtc")?;
    fdt.property_array_u64("reg", &rtc_reg_prop)?;
    fdt.property_u32("interrupt-parent", AIA_APLIC_PHANDLE)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.end_node(rtc_node)?;

    Ok(())
}

fn create_devices_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &HashMap<(DeviceType, String), T>,
) -> Result<()> {
    // Create one temp Vec to store all virtio devices
    let mut ordered_virtio_device: Vec<&T> = Vec::new();

    for ((device_type, _device_id), info) in dev_info {
        match device_type {
            DeviceType::Serial => create_serial_node(fdt, info)?,
            DeviceType::RTC => create_rtc_node(fdt, info)?,
            DeviceType::Virtio(_) => {
                ordered_virtio_device.push(info);
            }
        }
    }

    // Sort out virtio devices by address from low to high and insert them into fdt table.
    ordered_virtio_device.sort_by_key(|a| a.addr());
    for ordered_device_info in ordered_virtio_device.drain(..) {
        create_virtio_node(fdt, ordered_device_info)?;
    }

    Ok(())
}
