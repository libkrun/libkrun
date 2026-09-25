// SPDX-License-Identifier: Apache-2.0

//! PCI configuration and BAR access routing.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::sync::{Arc, Mutex};

use crate::bus::BusDevice;

pub const PCI_CONVENTIONAL_CONFIG_SPACE_SIZE: usize = 256;
pub const PCI_EXTENDED_CONFIG_SPACE_SIZE: u64 = 1 << 12;
pub(crate) const PCI_UNIMPLEMENTED_READ_BYTE: u8 = u8::MAX;

pub const CONFIG_MECHANISM_1_ADDRESS: u64 = 0xcf8;
pub const CONFIG_MECHANISM_1_SIZE: u64 = 8;

const CONFIG_ADDRESS_ENABLE_BIT: u32 = 1 << 31;
const CONFIG_ADDRESS_BUS_SHIFT: u32 = 16;
const CONFIG_ADDRESS_DEVICE_SHIFT: u32 = 11;
const CONFIG_ADDRESS_FUNCTION_SHIFT: u32 = 8;
const CONFIG_ADDRESS_REGISTER_MASK: u32 = 0xfc;
const PCI_DEVICE_NUMBER_BITS: u32 = 5;
const PCI_FUNCTION_NUMBER_BITS: u32 = 3;
const PCI_DEVICE_NUMBER_MASK: u32 = (1 << PCI_DEVICE_NUMBER_BITS) - 1;
const PCI_FUNCTION_NUMBER_MASK: u32 = (1 << PCI_FUNCTION_NUMBER_BITS) - 1;

const CONFIG_MECHANISM_1_ADDRESS_PORT_SIZE: u64 = std::mem::size_of::<u32>() as u64;
pub(crate) const CONFIG_MECHANISM_1_DATA_PORT_OFFSET: u64 = CONFIG_MECHANISM_1_ADDRESS_PORT_SIZE;
#[cfg(test)]
pub(crate) const CONFIG_MECHANISM_1_ADDRESS_PORT_OFFSET: u64 = 0;

const ECAM_BUS_SHIFT: u32 = 20;
const ECAM_DEVICE_SHIFT: u32 = 15;
const ECAM_FUNCTION_SHIFT: u32 = 12;
const ECAM_REGISTER_OFFSET_MASK: u64 = PCI_EXTENDED_CONFIG_SPACE_SIZE - 1;
const PCI_FUNCTIONS_PER_BUS: u64 = (1 << PCI_DEVICE_NUMBER_BITS) * (1 << PCI_FUNCTION_NUMBER_BITS);
pub const ECAM_SIZE_BUS0: u64 = PCI_EXTENDED_CONFIG_SPACE_SIZE * PCI_FUNCTIONS_PER_BUS;

pub type SharedPciRoot = Arc<Mutex<PciRoot>>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    #[cfg(test)]
    pub(crate) const fn config_mechanism_1_selector(self, register_offset: u16) -> u32 {
        CONFIG_ADDRESS_ENABLE_BIT
            | ((self.bus as u32) << CONFIG_ADDRESS_BUS_SHIFT)
            | ((self.device as u32) << CONFIG_ADDRESS_DEVICE_SHIFT)
            | ((self.function as u32) << CONFIG_ADDRESS_FUNCTION_SHIFT)
            | ((register_offset as u32) & CONFIG_ADDRESS_REGISTER_MASK)
    }

    #[cfg(test)]
    pub(crate) const fn ecam_offset(self, register_offset: u16) -> u64 {
        ((self.bus as u64) << ECAM_BUS_SHIFT)
            | ((self.device as u64) << ECAM_DEVICE_SHIFT)
            | ((self.function as u64) << ECAM_FUNCTION_SHIFT)
            | ((register_offset as u64) & ECAM_REGISTER_OFFSET_MASK)
    }
}

pub trait PciFunction: Send {
    fn read_config(&mut self, offset: u16, data: &mut [u8]);
    fn write_config(&mut self, offset: u16, data: &[u8]);
    fn read_bar(&mut self, address: u64, data: &mut [u8]) -> PciBarAccess;
    fn write_bar(&mut self, address: u64, data: &[u8]) -> PciBarAccess;
}

/// Whether a PCI function claimed an access to its BAR window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciBarAccess {
    /// The function consumed the access; device semantics may still ignore a write.
    Handled,
    /// The function does not decode this address, so the root may try another function.
    Unhandled,
}

pub trait PciIntxLine: Send + Sync {
    fn set_level(&self, asserted: bool) -> io::Result<()>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum PciRootError {
    DuplicateFunction(PciAddress),
}

impl Display for PciRootError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateFunction(address) => write!(
                f,
                "PCI function {:02x}:{:02x}.{} is already registered",
                address.bus, address.device, address.function
            ),
        }
    }
}

impl std::error::Error for PciRootError {}

#[derive(Default)]
pub struct PciRoot {
    functions: BTreeMap<PciAddress, Arc<Mutex<dyn PciFunction>>>,
}

impl PciRoot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn shared() -> SharedPciRoot {
        Arc::new(Mutex::new(Self::new()))
    }

    pub fn insert(
        &mut self,
        address: PciAddress,
        function: Arc<Mutex<dyn PciFunction>>,
    ) -> Result<(), PciRootError> {
        if self.functions.contains_key(&address) {
            return Err(PciRootError::DuplicateFunction(address));
        }
        self.functions.insert(address, function);
        Ok(())
    }

    fn read_config(&mut self, address: PciAddress, offset: u16, data: &mut [u8]) {
        match self.functions.get(&address) {
            Some(function) => function
                .lock()
                .expect("Poisoned PCI function lock")
                .read_config(offset, data),
            None => data.fill(PCI_UNIMPLEMENTED_READ_BYTE),
        }
    }

    fn write_config(&mut self, address: PciAddress, offset: u16, data: &[u8]) {
        if let Some(function) = self.functions.get(&address) {
            function
                .lock()
                .expect("Poisoned PCI function lock")
                .write_config(offset, data);
        }
    }

    fn read_bar(&mut self, address: u64, data: &mut [u8]) {
        for function in self.functions.values() {
            if function
                .lock()
                .expect("Poisoned PCI function lock")
                .read_bar(address, data)
                == PciBarAccess::Handled
            {
                return;
            }
        }
        data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
    }

    fn write_bar(&mut self, address: u64, data: &[u8]) {
        for function in self.functions.values() {
            if function
                .lock()
                .expect("Poisoned PCI function lock")
                .write_bar(address, data)
                == PciBarAccess::Handled
            {
                return;
            }
        }
    }
}

pub struct ConfigMechanism1 {
    root: SharedPciRoot,
    address: u32,
}

impl ConfigMechanism1 {
    pub fn new(root: SharedPciRoot) -> Self {
        Self { root, address: 0 }
    }

    fn config_address(&self, data_offset: u64) -> Option<(PciAddress, u16)> {
        if self.address & CONFIG_ADDRESS_ENABLE_BIT == 0 {
            return None;
        }

        Some((
            PciAddress::new(
                (self.address >> CONFIG_ADDRESS_BUS_SHIFT) as u8,
                ((self.address >> CONFIG_ADDRESS_DEVICE_SHIFT) & PCI_DEVICE_NUMBER_MASK) as u8,
                ((self.address >> CONFIG_ADDRESS_FUNCTION_SHIFT) & PCI_FUNCTION_NUMBER_MASK) as u8,
            ),
            ((self.address & CONFIG_ADDRESS_REGISTER_MASK) + data_offset as u32) as u16,
        ))
    }
}

impl BusDevice for ConfigMechanism1 {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if offset + data.len() as u64 > CONFIG_MECHANISM_1_SIZE {
            return;
        }

        if offset < CONFIG_MECHANISM_1_ADDRESS_PORT_SIZE {
            if offset + data.len() as u64 > CONFIG_MECHANISM_1_ADDRESS_PORT_SIZE {
                return;
            }
            let address = self.address.to_le_bytes();
            let start = offset as usize;
            let end = start + data.len();
            let Some(source) = address.get(start..end) else {
                return;
            };
            data.copy_from_slice(source);
            return;
        }

        let Some((address, config_offset)) =
            self.config_address(offset - CONFIG_MECHANISM_1_DATA_PORT_OFFSET)
        else {
            data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
            return;
        };
        self.root
            .lock()
            .expect("Poisoned PCI root lock")
            .read_config(address, config_offset, data);
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if offset + data.len() as u64 > CONFIG_MECHANISM_1_SIZE {
            return;
        }

        if offset < CONFIG_MECHANISM_1_ADDRESS_PORT_SIZE {
            if offset + data.len() as u64 > CONFIG_MECHANISM_1_ADDRESS_PORT_SIZE {
                return;
            }
            let mut address = self.address.to_le_bytes();
            let start = offset as usize;
            let end = start + data.len();
            let Some(destination) = address.get_mut(start..end) else {
                return;
            };
            destination.copy_from_slice(data);
            self.address = u32::from_le_bytes(address);
            return;
        }

        let Some((address, config_offset)) =
            self.config_address(offset - CONFIG_MECHANISM_1_DATA_PORT_OFFSET)
        else {
            return;
        };
        self.root
            .lock()
            .expect("Poisoned PCI root lock")
            .write_config(address, config_offset, data);
    }
}

pub struct Ecam {
    root: SharedPciRoot,
}

impl Ecam {
    pub fn new(root: SharedPciRoot) -> Self {
        Self { root }
    }

    fn decode(offset: u64) -> PciAddress {
        PciAddress::new(
            (offset >> ECAM_BUS_SHIFT) as u8,
            ((offset >> ECAM_DEVICE_SHIFT) & u64::from(PCI_DEVICE_NUMBER_MASK)) as u8,
            ((offset >> ECAM_FUNCTION_SHIFT) & u64::from(PCI_FUNCTION_NUMBER_MASK)) as u8,
        )
    }
}

impl BusDevice for Ecam {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        let address = Self::decode(offset);
        if address.bus != 0 {
            data.fill(PCI_UNIMPLEMENTED_READ_BYTE);
            return;
        }

        self.root
            .lock()
            .expect("Poisoned PCI root lock")
            .read_config(address, (offset & ECAM_REGISTER_OFFSET_MASK) as u16, data);
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        let address = Self::decode(offset);
        if address.bus != 0 {
            return;
        }

        self.root
            .lock()
            .expect("Poisoned PCI root lock")
            .write_config(address, (offset & ECAM_REGISTER_OFFSET_MASK) as u16, data);
    }
}

pub struct BarWindow {
    root: SharedPciRoot,
    base: u64,
}

impl BarWindow {
    pub fn new(root: SharedPciRoot, base: u64) -> Self {
        Self { root, base }
    }
}

impl BusDevice for BarWindow {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        self.root
            .lock()
            .expect("Poisoned PCI root lock")
            .read_bar(self.base + offset, data);
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        self.root
            .lock()
            .expect("Poisoned PCI root lock")
            .write_bar(self.base + offset, data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PCI_ADDRESS: PciAddress = PciAddress {
        bus: 0,
        device: 1,
        function: 0,
    };
    const ABSENT_PCI_ADDRESS: PciAddress = PciAddress {
        bus: 0,
        device: 0,
        function: 0,
    };
    const TEST_BAR_BASE: u64 = 0x1000;
    const TEST_BAR_ACCESS_OFFSET: u64 = 4;
    const TEST_REGISTER_OFFSET: u16 = 0;

    struct DummyFunction {
        config: [u8; PCI_CONVENTIONAL_CONFIG_SPACE_SIZE],
        bar_base: u64,
        bar: [u8; 16],
    }

    impl DummyFunction {
        fn new() -> Self {
            Self {
                config: [0; PCI_CONVENTIONAL_CONFIG_SPACE_SIZE],
                bar_base: TEST_BAR_BASE,
                bar: [0; 16],
            }
        }
    }

    impl PciFunction for DummyFunction {
        fn read_config(&mut self, offset: u16, data: &mut [u8]) {
            let start = usize::from(offset);
            let end = start + data.len();
            let source = self
                .config
                .get(start..end)
                .expect("test PCI config read is in bounds");
            data.copy_from_slice(source);
        }

        fn write_config(&mut self, offset: u16, data: &[u8]) {
            let start = usize::from(offset);
            let end = start + data.len();
            let destination = self
                .config
                .get_mut(start..end)
                .expect("test PCI config write is in bounds");
            destination.copy_from_slice(data);
        }

        fn read_bar(&mut self, address: u64, data: &mut [u8]) -> PciBarAccess {
            let Some(offset) = address.checked_sub(self.bar_base) else {
                return PciBarAccess::Unhandled;
            };
            let start = offset as usize;
            let Some(end) = start.checked_add(data.len()) else {
                return PciBarAccess::Unhandled;
            };
            let Some(source) = self.bar.get(start..end) else {
                return PciBarAccess::Unhandled;
            };
            data.copy_from_slice(source);
            PciBarAccess::Handled
        }

        fn write_bar(&mut self, address: u64, data: &[u8]) -> PciBarAccess {
            let Some(offset) = address.checked_sub(self.bar_base) else {
                return PciBarAccess::Unhandled;
            };
            let start = offset as usize;
            let Some(end) = start.checked_add(data.len()) else {
                return PciBarAccess::Unhandled;
            };
            let Some(destination) = self.bar.get_mut(start..end) else {
                return PciBarAccess::Unhandled;
            };
            destination.copy_from_slice(data);
            PciBarAccess::Handled
        }
    }

    fn test_root() -> SharedPciRoot {
        let root = PciRoot::shared();
        root.lock()
            .unwrap()
            .insert(TEST_PCI_ADDRESS, Arc::new(Mutex::new(DummyFunction::new())))
            .unwrap();
        root
    }

    #[test]
    fn config_mechanism_1_reads_and_writes_config_space() {
        let root = test_root();
        let mut config = ConfigMechanism1::new(root);
        let selector = TEST_PCI_ADDRESS.config_mechanism_1_selector(TEST_REGISTER_OFFSET);
        config.write(
            0,
            CONFIG_MECHANISM_1_ADDRESS_PORT_OFFSET,
            &selector.to_le_bytes(),
        );
        config.write(0, CONFIG_MECHANISM_1_DATA_PORT_OFFSET, &[0x34, 0x12]);

        let mut value = [0; 2];
        config.read(0, CONFIG_MECHANISM_1_DATA_PORT_OFFSET, &mut value);
        assert_eq!(value, [0x34, 0x12]);
    }

    #[test]
    fn ecam_decodes_bus_device_function_and_register() {
        let root = test_root();
        let mut ecam = Ecam::new(root);
        let offset = TEST_PCI_ADDRESS.ecam_offset(TEST_REGISTER_OFFSET);
        ecam.write(0, offset, &[0xab]);

        let mut value = [0; 1];
        ecam.read(0, offset, &mut value);
        assert_eq!(value, [0xab]);
    }

    #[test]
    fn bar_window_routes_accesses_to_current_function_bar() {
        let root = test_root();
        let mut bars = BarWindow::new(root, TEST_BAR_BASE);
        bars.write(0, TEST_BAR_ACCESS_OFFSET, &[1, 2, 3, 4]);

        let mut value = [0; 4];
        bars.read(0, TEST_BAR_ACCESS_OFFSET, &mut value);
        assert_eq!(value, [1, 2, 3, 4]);
    }

    #[test]
    fn config_mechanism_1_returns_all_ones_for_missing_functions() {
        let root = PciRoot::shared();
        let mut config = ConfigMechanism1::new(root);
        let absent_function = ABSENT_PCI_ADDRESS.config_mechanism_1_selector(TEST_REGISTER_OFFSET);
        config.write(
            0,
            CONFIG_MECHANISM_1_ADDRESS_PORT_OFFSET,
            &absent_function.to_le_bytes(),
        );

        let mut value = [0; 4];
        config.read(0, CONFIG_MECHANISM_1_DATA_PORT_OFFSET, &mut value);
        assert_eq!(
            value,
            [PCI_UNIMPLEMENTED_READ_BYTE; std::mem::size_of::<u32>()]
        );
    }
}
