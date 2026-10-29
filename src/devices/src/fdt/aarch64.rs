// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::fmt::Debug;
use std::{io, result};

use crate::DeviceType;
use crate::legacy::IrqChip;
use crate::legacy::gic::GICDevice;
use arch::aarch64::layout::{GTIMER_HYP, GTIMER_PHYS, GTIMER_SEC, GTIMER_VIRT};
use arch::{ArchMemoryInfo, InitrdConfig};
use vm_fdt::{Error as FdtError, FdtWriter};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};

// This is a value for uniquely identifying the FDT node declaring the interrupt controller.
const GIC_PHANDLE: u32 = 1;
// This is a value for uniquely identifying the FDT node containing the clock definition.
const CLOCK_PHANDLE: u32 = 2;
// This is a value for uniquely identifying the FDT node containing the gpio controller.
const GPIO_PHANDLE: u32 = 4;
// Read the documentation specified when appending the root node to the FDT.
const ADDRESS_CELLS: u32 = 0x2;
const SIZE_CELLS: u32 = 0x2;

// System restart
const KEY_RESTART: u32 = 0x198;

// NUMA distances, as per the Linux kernel's include/linux/numa.h.
const LOCAL_DISTANCE: u32 = 10;
const REMOTE_DISTANCE: u32 = 20;
// The distances between the NUMA nodes of RAM (0) and locked guest memory (1), as
// (from, to, distance) triples.
#[rustfmt::skip]
const DISTANCE_MATRIX: [u32; 12] = [
    0, 0, LOCAL_DISTANCE,
    0, 1, REMOTE_DISTANCE,
    1, 0, REMOTE_DISTANCE,
    1, 1, LOCAL_DISTANCE,
];

// As per kvm tool and
// https://www.kernel.org/doc/Documentation/devicetree/bindings/interrupt-controller/arm%2Cgic.txt
// Look for "The 1st cell..."
const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;
const GIC_FDT_IRQ_TYPE_PPI: u32 = 1;

// From https://elixir.bootlin.com/linux/v4.9.62/source/include/dt-bindings/interrupt-controller/irq.h#L17
const IRQ_TYPE_EDGE_RISING: u32 = 1;
const IRQ_TYPE_LEVEL_HI: u32 = 4;

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

/// Creates the flattened device tree for this aarch64 microVM.
pub fn create_fdt<T: DeviceInfoForFDT + Clone + Debug>(
    guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
    vcpu_mpidr: Vec<u64>,
    cmdline: &str,
    device_info: &HashMap<(DeviceType, String), T>,
    gic_device: &IrqChip,
    initrd: &Option<InitrdConfig>,
) -> Result<Vec<u8>> {
    // Alocate stuff necessary for the holding the blob.
    let mut fdt = FdtWriter::new()?;

    // For an explanation why these nodes were introduced in the blob take a look at
    // https://github.com/torvalds/linux/blob/master/Documentation/devicetree/booting-without-of.txt#L845
    // Look for "Required nodes and properties".

    // Header or the root node as per above mentioned documentation.
    let root_node = fdt.begin_node("")?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    // For info on #address-cells and size-cells read "Note about cells and address representation"
    // from the above mentioned txt file.
    fdt.property_u32("#address-cells", ADDRESS_CELLS)?;
    fdt.property_u32("#size-cells", SIZE_CELLS)?;
    // This is not mandatory but we use it to point the root node to the node
    // containing description of the interrupt controller for this VM.
    fdt.property_u32("interrupt-parent", GIC_PHANDLE)?;
    // With locked guest memory, RAM is NUMA node 0, which has all the CPUs, and the locked
    // memory is node 1, which has none. Without it, there is no NUMA information.
    let numa = arch_memory_info.locked_range().is_some();
    create_cpu_nodes(&mut fdt, &vcpu_mpidr, numa)?;
    create_memory_node(&mut fdt, guest_mem, arch_memory_info)?;
    create_chosen_node(&mut fdt, cmdline, initrd, device_info)?;
    create_gic_node(&mut fdt, gic_device)?;
    create_timer_node(&mut fdt)?;
    create_clock_node(&mut fdt)?;
    create_psci_node(&mut fdt)?;
    create_devices_node(&mut fdt, device_info)?;

    // End Header node.
    fdt.end_node(root_node)?;

    // Allocate another buffer so we can format and then write fdt to guest.
    let fdt_final = fdt.finish()?;

    // Write FDT to memory.
    let fdt_address = GuestAddress(arch_memory_info.fdt_addr);
    guest_mem
        .write_slice(fdt_final.as_slice(), fdt_address)
        .map_err(Error::WriteFDTToMemory)?;
    Ok(fdt_final)
}

// Auxiliary functions for writing u32/u64 numbers in big endian order.
fn to_be32(input: u32) -> [u8; 4] {
    u32::to_be_bytes(input)
}

fn to_be64(input: u64) -> [u8; 8] {
    u64::to_be_bytes(input)
}

// Helper functions for generating a properly formatted byte vector using 32-bit/64-bit cells.
fn generate_prop32(cells: &[u32]) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::new();
    for &e in cells {
        ret.extend(to_be32(e).iter());
    }
    ret
}

fn generate_prop64(cells: &[u64]) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::new();
    for &e in cells {
        ret.extend(to_be64(e).iter());
    }
    ret
}

// Following are the auxiliary function for creating the different nodes that we append to our FDT.
fn create_cpu_nodes(fdt: &mut FdtWriter, vcpu_mpidr: &[u64], numa: bool) -> Result<()> {
    // See https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/arm/cpus.yaml.
    let cpu_node = fdt.begin_node("cpus")?;
    // As per documentation, on ARM v8 64-bit systems value should be set to 2.
    fdt.property_u32("#address-cells", 0x02)?;
    fdt.property_u32("#size-cells", 0x0)?;
    let num_cpus = vcpu_mpidr.len();

    for (index, mpidr) in vcpu_mpidr.iter().enumerate() {
        let cpu_name = format!("cpu@{index:x}");
        let cpu_name_node = fdt.begin_node(&cpu_name)?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        if num_cpus > 1 {
            // This is required on armv8 64-bit. See aforementioned documentation.
            fdt.property_string("enable-method", "psci")?;
        }
        // Set the field to first 24 bits of the MPIDR - Multiprocessor Affinity Register.
        // See http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0488c/BABHBJCI.html.
        fdt.property_u64("reg", mpidr & 0x7FFFFF)?;
        if numa {
            fdt.property_u32("numa-node-id", 0)?;
        }
        fdt.end_node(cpu_name_node)?;
    }
    fdt.end_node(cpu_node)?;
    Ok(())
}

fn create_memory_node(
    fdt: &mut FdtWriter,
    _guest_mem: &GuestMemoryMmap,
    arch_memory_info: &ArchMemoryInfo,
) -> Result<()> {
    let mem_size = arch_memory_info.ram_last_addr - arch_memory_info.ram_start_addr;
    // See https://github.com/torvalds/linux/blob/master/Documentation/devicetree/booting-without-of.txt#L960
    // for an explanation of this.
    let mem_reg_prop = generate_prop64(&[arch_memory_info.ram_start_addr, mem_size]);

    let mem_node = fdt.begin_node(&format!("memory@{:x}", arch_memory_info.ram_start_addr))?;
    fdt.property_string("device_type", "memory")?;
    fdt.property("reg", &mem_reg_prop)?;
    let Some(locked) = arch_memory_info.locked_range() else {
        fdt.end_node(mem_node)?;
        return Ok(());
    };
    // See https://www.kernel.org/doc/Documentation/devicetree/bindings/numa.txt.
    fdt.property_u32("numa-node-id", 0)?;
    fdt.end_node(mem_node)?;

    let locked_reg_prop = generate_prop64(&[locked.start, locked.end - locked.start]);
    let locked_node = fdt.begin_node(&format!("memory@{:x}", locked.start))?;
    fdt.property_string("device_type", "memory")?;
    fdt.property("reg", &locked_reg_prop)?;
    fdt.property_u32("numa-node-id", 1)?;
    fdt.end_node(locked_node)?;

    let distance_map_node = fdt.begin_node("distance-map")?;
    fdt.property_string("compatible", "numa-distance-map-v1")?;
    fdt.property_array_u32("distance-matrix", &DISTANCE_MATRIX)?;
    fdt.end_node(distance_map_node)?;
    Ok(())
}

fn create_chosen_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    cmdline: &str,
    initrd: &Option<InitrdConfig>,
    dev_info: &HashMap<(DeviceType, String), T>,
) -> Result<()> {
    let chosen_node = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", cmdline)?;

    // If we have a legacy serial device, tell the guest this is the default console.
    // Clever guests will still switch to a better console (like virtio-console) if
    // it becomes available later, and this gives us a good fallback.
    for ((device_type, _device_id), info) in dev_info {
        if device_type == &DeviceType::Serial {
            fdt.property_string("stdout-path", &format!("/uart@{:x}", info.addr()))?;
        }
    }

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

fn create_gic_node(fdt: &mut FdtWriter, gic_device: &IrqChip) -> Result<()> {
    let gic_device = gic_device.lock().unwrap();
    let gic_reg_prop = generate_prop64(&gic_device.device_properties());

    let intc_node = fdt.begin_node("intc")?;
    fdt.property_string("compatible", &gic_device.fdt_compatibility())?;
    fdt.property_null("interrupt-controller")?;
    // "interrupt-cells" field specifies the number of cells needed to encode an
    // interrupt source. The type shall be a <u32> and the value shall be 3 if no PPI affinity description
    // is required.
    fdt.property_u32("#interrupt-cells", 3)?;
    fdt.property("reg", &gic_reg_prop)?;
    fdt.property_u32("phandle", GIC_PHANDLE)?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_null("ranges")?;
    let gic_intr = [
        GIC_FDT_IRQ_TYPE_PPI,
        gic_device.fdt_maint_irq(),
        IRQ_TYPE_LEVEL_HI,
    ];
    let gic_intr_prop = generate_prop32(&gic_intr);

    fdt.property("interrupts", &gic_intr_prop)?;
    fdt.end_node(intc_node)?;

    Ok(())
}

fn create_clock_node(fdt: &mut FdtWriter) -> Result<()> {
    // The Advanced Peripheral Bus (APB) is part of the Advanced Microcontroller Bus Architecture
    // (AMBA) protocol family. It defines a low-cost interface that is optimized for minimal power
    // consumption and reduced interface complexity.
    // PCLK is the clock source and this node defines exactly the clock for the APB.
    let node = fdt.begin_node("apb-pclk")?;
    fdt.property_string("compatible", "fixed-clock")?;
    fdt.property_u32("#clock-cells", 0x0)?;
    fdt.property_u32("clock-frequency", 24000000)?;
    fdt.property_string("clock-output-names", "clk24mhz")?;
    fdt.property_u32("phandle", CLOCK_PHANDLE)?;
    fdt.end_node(node)?;

    Ok(())
}

fn create_timer_node(fdt: &mut FdtWriter) -> Result<()> {
    // See
    // https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/interrupt-controller/arch_timer.txt
    // These are fixed interrupt numbers for the timer device.
    let irqs = [GTIMER_SEC, GTIMER_HYP, GTIMER_VIRT, GTIMER_PHYS];
    let compatible = "arm,armv8-timer";

    let mut timer_reg_cells: Vec<u32> = Vec::new();
    for &irq in irqs.iter() {
        timer_reg_cells.push(GIC_FDT_IRQ_TYPE_PPI);
        timer_reg_cells.push(irq);
        timer_reg_cells.push(IRQ_TYPE_LEVEL_HI);
    }
    let timer_reg_prop = generate_prop32(timer_reg_cells.as_slice());

    let node = fdt.begin_node("timer")?;
    fdt.property_string("compatible", compatible)?;
    fdt.property_null("always-on")?;
    fdt.property("interrupts", &timer_reg_prop)?;
    fdt.end_node(node)?;

    Ok(())
}

fn create_psci_node(fdt: &mut FdtWriter) -> Result<()> {
    let compatible = "arm,psci-0.2";
    let node = fdt.begin_node("psci")?;
    fdt.property_string("compatible", compatible)?;
    // Two methods available: hvc and smc.
    // As per documentation, PSCI calls between a guest and hypervisor may use the HVC conduit instead of SMC.
    // So, since we are using kvm, we need to use hvc.
    #[cfg(target_os = "linux")]
    fdt.property_string("method", "hvc")?;
    #[cfg(target_os = "macos")]
    fdt.property_string("method", "smc")?;
    fdt.end_node(node)?;

    Ok(())
}

fn create_virtio_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let device_reg_prop = generate_prop64(&[dev_info.addr(), dev_info.length()]);
    #[cfg(target_os = "linux")]
    let irq = generate_prop32(&[GIC_FDT_IRQ_TYPE_SPI, dev_info.irq(), IRQ_TYPE_EDGE_RISING]);
    #[cfg(target_os = "macos")]
    let irq = generate_prop32(&[
        GIC_FDT_IRQ_TYPE_SPI,
        dev_info.irq() - 32,
        IRQ_TYPE_EDGE_RISING,
    ]);

    let virtio_node = fdt.begin_node(&format!("virtio_mmio@{:x}", dev_info.addr()))?;
    fdt.property_string("compatible", "virtio,mmio")?;
    fdt.property("reg", &device_reg_prop)?;
    fdt.property("interrupts", &irq)?;
    fdt.property_u32("interrupt-parent", GIC_PHANDLE)?;
    fdt.end_node(virtio_node)?;

    Ok(())
}

fn create_serial_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let serial_reg_prop = generate_prop64(&[dev_info.addr(), dev_info.length()]);
    #[cfg(target_os = "linux")]
    let irq = generate_prop32(&[GIC_FDT_IRQ_TYPE_SPI, dev_info.irq(), IRQ_TYPE_EDGE_RISING]);
    #[cfg(target_os = "macos")]
    let irq = generate_prop32(&[
        GIC_FDT_IRQ_TYPE_SPI,
        dev_info.irq() - 32,
        IRQ_TYPE_EDGE_RISING,
    ]);

    let node = fdt.begin_node(&format!("uart@{:x}", dev_info.addr()))?;
    fdt.property_string("compatible", "arm,pl011")?;
    fdt.property_string("status", "okay")?;
    fdt.property("reg", &serial_reg_prop)?;
    fdt.property_u32("clocks", CLOCK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.property("interrupts", &irq)?;
    fdt.end_node(node)?;

    Ok(())
}

fn create_rtc_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let compatible = b"arm,pl031\0arm,primecell\0";
    let rtc_reg_prop = generate_prop64(&[dev_info.addr(), dev_info.length()]);
    #[cfg(target_os = "linux")]
    let irq = generate_prop32(&[GIC_FDT_IRQ_TYPE_SPI, dev_info.irq(), IRQ_TYPE_LEVEL_HI]);
    #[cfg(target_os = "macos")]
    let irq = generate_prop32(&[GIC_FDT_IRQ_TYPE_SPI, dev_info.irq() - 32, IRQ_TYPE_LEVEL_HI]);
    let rtc_node = fdt.begin_node(&format!("rtc@{:x}", dev_info.addr()))?;
    fdt.property("compatible", compatible)?;
    fdt.property("reg", &rtc_reg_prop)?;
    fdt.property("interrupts", &irq)?;
    fdt.property_u32("clocks", CLOCK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.end_node(rtc_node)?;

    Ok(())
}

fn create_gpio_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<()> {
    let compatible = b"arm,pl061\0arm,primecell\0";

    let gpio_reg_prop = generate_prop64(&[dev_info.addr(), dev_info.length()]);
    let irq = generate_prop32(&[
        GIC_FDT_IRQ_TYPE_SPI,
        dev_info.irq() - 32,
        IRQ_TYPE_EDGE_RISING,
    ]);

    let gpio_node = fdt.begin_node(&format!("pl061@{:x}", dev_info.addr()))?;
    fdt.property("compatible", compatible)?;

    fdt.property("reg", &gpio_reg_prop)?;
    fdt.property("interrupts", &irq)?;
    fdt.property_null("gpio-controller")?;
    fdt.property_u32("#gpio-cells", 2)?;
    fdt.property_u32("clocks", CLOCK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.property_u32("phandle", GPIO_PHANDLE)?;
    fdt.end_node(gpio_node)?;

    // gpio-keys node
    let gpio_keys_node = fdt.begin_node("gpio-keys")?;
    fdt.property_string("compatible", "gpio-keys")?;
    fdt.property_u32("#size-cells", 0)?;
    fdt.property_u32("#address-cells", 1)?;
    let gpio_keys_poweroff_node = fdt.begin_node("button@1")?;
    fdt.property_string("label", "GPIO Key Poweroff")?;
    fdt.property_u32("linux,code", KEY_RESTART)?;
    let gpios = [GPIO_PHANDLE, 3, 0];
    fdt.property_array_u32("gpios", &gpios)?;
    fdt.end_node(gpio_keys_poweroff_node)?;
    fdt.end_node(gpio_keys_node)?;

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
            DeviceType::Gpio => create_gpio_node(fdt, info)?,
            DeviceType::RTC => create_rtc_node(fdt, info)?,
            DeviceType::Serial => create_serial_node(fdt, info)?,
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::legacy::DummyIrqChip;

    const MIB: u64 = 1 << 20;

    #[derive(Clone, Debug)]
    struct TestDeviceInfo {
        addr: u64,
        irq: u32,
    }

    impl DeviceInfoForFDT for TestDeviceInfo {
        fn addr(&self) -> u64 {
            self.addr
        }
        fn irq(&self) -> u32 {
            self.irq
        }
        fn length(&self) -> u64 {
            0x1000
        }
    }

    /// The memory layout of an EFI boot with 1 GiB of RAM, with `locked_size` bytes of locked
    /// guest memory.
    fn memory_info(locked_size: u64) -> ArchMemoryInfo {
        let locked = locked_size != 0;
        ArchMemoryInfo {
            ram_start_addr: 0x4000_0000,
            ram_last_addr: 0x8000_0000,
            shm_start_addr: if locked { 0x1_0000_0000 } else { 0xc000_0000 },
            fdt_addr: 0x4000_0000,
            locked_start_addr: 0xc000_0000,
            locked_size,
            ..Default::default()
        }
    }

    /// The FDT of a VM with two vCPUs, a serial port and three virtio devices. There is only one
    /// device that isn't a virtio device, as their order would depend on the order of a HashMap.
    fn fdt(locked_size: u64) -> Vec<u8> {
        let info = memory_info(locked_size);
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(info.fdt_addr), 2 * MIB as usize)])
            .unwrap();
        let mut devices = HashMap::new();
        devices.insert(
            (DeviceType::Serial, "serial".to_string()),
            TestDeviceInfo {
                addr: 0x0a00_0000,
                irq: 33,
            },
        );
        for i in 0..3 {
            devices.insert(
                (DeviceType::Virtio(i + 1), format!("virtio{i}")),
                TestDeviceInfo {
                    addr: 0x0a00_1000 + u64::from(i) * 0x1000,
                    irq: 34 + i,
                },
            );
        }
        let intc: IrqChip = DummyIrqChip::new().into();
        let initrd = Some(InitrdConfig {
            address: GuestAddress(0x7000_0000),
            size: 0x10_0000,
        });
        create_fdt(
            &mem,
            &info,
            vec![0, 0x100],
            "console=hvc0 root=/dev/vda",
            &devices,
            &intc,
            &initrd,
        )
        .unwrap()
    }

    /// The properties of each node of a flattened device tree, by the path of the node.
    type Tree = BTreeMap<String, BTreeMap<String, Vec<u8>>>;

    fn parse(dtb: &[u8]) -> Tree {
        const FDT_BEGIN_NODE: u32 = 1;
        const FDT_END_NODE: u32 = 2;
        const FDT_PROP: u32 = 3;
        const FDT_NOP: u32 = 4;
        const FDT_END: u32 = 9;
        let be32 = |offset: usize| u32::from_be_bytes(dtb[offset..offset + 4].try_into().unwrap());
        let string = |offset: usize| {
            let len = dtb[offset..].iter().position(|&b| b == 0).unwrap();
            String::from_utf8(dtb[offset..offset + len].to_vec()).unwrap()
        };
        let align = |offset: usize| (offset + 3) & !3;

        assert_eq!(be32(0), 0xd00d_feed);
        let strings = be32(12) as usize;
        let mut offset = be32(8) as usize;
        let mut tree = Tree::new();
        let mut path = Vec::new();
        loop {
            let token = be32(offset);
            offset += 4;
            match token {
                FDT_BEGIN_NODE => {
                    let name = string(offset);
                    offset = align(offset + name.len() + 1);
                    path.push(name);
                    assert!(tree.insert(path.join("/"), BTreeMap::new()).is_none());
                }
                FDT_END_NODE => {
                    path.pop().unwrap();
                }
                FDT_PROP => {
                    let len = be32(offset) as usize;
                    let name = string(strings + be32(offset + 4) as usize);
                    let value = dtb[offset + 8..offset + 8 + len].to_vec();
                    offset = align(offset + 8 + len);
                    let node = tree.get_mut(&path.join("/")).unwrap();
                    assert!(node.insert(name, value).is_none());
                }
                FDT_NOP => {}
                FDT_END => break,
                _ => panic!("unexpected token {token:#x} at {offset:#x}"),
            }
        }
        assert!(path.is_empty());
        tree
    }

    fn cells32(value: &[u8]) -> Vec<u32> {
        value
            .chunks(4)
            .map(|cell| u32::from_be_bytes(cell.try_into().unwrap()))
            .collect()
    }

    fn cells64(value: &[u8]) -> Vec<u64> {
        value
            .chunks(8)
            .map(|cell| u64::from_be_bytes(cell.try_into().unwrap()))
            .collect()
    }

    /// The nodes whose device_type is "memory".
    fn memory_nodes(tree: &Tree) -> BTreeMap<&str, &BTreeMap<String, Vec<u8>>> {
        tree.iter()
            .filter(|(_, props)| {
                props.get("device_type").map(Vec::as_slice) == Some(&b"memory\0"[..])
            })
            .map(|(path, props)| (path.as_str(), props))
            .collect()
    }

    #[test]
    fn test_fdt_without_locked_memory_has_no_numa_information() {
        let tree = parse(&fdt(0));
        let memory = memory_nodes(&tree);
        assert_eq!(
            memory.keys().copied().collect::<Vec<_>>(),
            ["/memory@40000000"]
        );
        assert_eq!(
            cells64(&memory["/memory@40000000"]["reg"]),
            [0x4000_0000, 0x4000_0000]
        );
        assert!(!tree.contains_key("/distance-map"));
        for (path, props) in &tree {
            assert!(!props.contains_key("numa-node-id"), "{path}");
        }
    }

    #[test]
    fn test_fdt_with_locked_memory_has_a_numa_node_without_cpus() {
        let tree = parse(&fdt(256 * MIB));

        let memory = memory_nodes(&tree);
        assert_eq!(
            memory.keys().copied().collect::<Vec<_>>(),
            ["/memory@40000000", "/memory@c0000000"]
        );
        let ram = memory["/memory@40000000"];
        assert_eq!(cells64(&ram["reg"]), [0x4000_0000, 0x4000_0000]);
        assert_eq!(cells32(&ram["numa-node-id"]), [0]);
        let locked = memory["/memory@c0000000"];
        assert_eq!(cells64(&locked["reg"]), [0xc000_0000, 256 * MIB]);
        assert_eq!(cells32(&locked["numa-node-id"]), [1]);

        let cpus: Vec<_> = tree
            .iter()
            .filter(|(path, _)| path.starts_with("/cpus/cpu@"))
            .collect();
        assert_eq!(cpus.len(), 2);
        for (path, props) in cpus {
            assert_eq!(cells32(&props["numa-node-id"]), [0], "{path}");
        }

        let distance_map = &tree["/distance-map"];
        assert_eq!(distance_map["compatible"], b"numa-distance-map-v1\0");
        assert_eq!(
            cells32(&distance_map["distance-matrix"]),
            [0, 0, 10, 0, 1, 20, 1, 0, 20, 1, 1, 10]
        );
    }

    #[test]
    fn test_fdt_with_locked_memory_changes_nothing_else() {
        let without = parse(&fdt(0));
        let mut with = parse(&fdt(256 * MIB));
        with.remove("/memory@c0000000").unwrap();
        with.remove("/distance-map").unwrap();
        for props in with.values_mut() {
            props.remove("numa-node-id");
        }
        assert_eq!(with, without);
    }
}
