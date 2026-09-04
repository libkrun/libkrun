//! Common IOAPIC register emulation, shared across hypervisor backends.
//!
//! The generic [`Ioapic<B>`] struct handles all MMIO register reads/writes
//! (ioregsel, iowin, redirection table). Backend-specific interrupt
//! injection is delegated through the [`IoApicBackend`] trait.

use std::sync::Mutex;

use utils::eventfd::EventFd;

use crate::Error as DeviceError;
use crate::bus::BusDevice;
use crate::legacy::irqchip::IrqChipT;

const IOAPIC_BASE: u32 = 0xfec0_0000;
pub(super) const IOAPIC_NUM_PINS: usize = 24;

const IO_REG_SEL: u64 = 0x00;
const IO_WIN: u64 = 0x10;
const IO_EOI: u64 = 0x40;

const IO_APIC_ID: u8 = 0x00;
const IO_APIC_VER: u8 = 0x01;
const IO_APIC_ARB: u8 = 0x02;

pub(super) const IOAPIC_LVT_DELIV_MODE_SHIFT: u64 = 8;
pub(super) const IOAPIC_LVT_DEST_MODE_SHIFT: u64 = 11;
const IOAPIC_LVT_DELIV_STATUS_SHIFT: u64 = 12;
const IOAPIC_LVT_REMOTE_IRR_SHIFT: u64 = 14;
pub(super) const IOAPIC_LVT_TRIGGER_MODE_SHIFT: u64 = 15;
pub(super) const IOAPIC_LVT_MASKED_SHIFT: u64 = 16;

pub(super) const IOAPIC_TRIGGER_EDGE: u64 = 0;
const IOAPIC_VER_ENTRIES_SHIFT: u64 = 16;
const IOAPIC_ID_SHIFT: u64 = 24;

pub(super) const IOAPIC_LVT_REMOTE_IRR: u64 = 1 << IOAPIC_LVT_REMOTE_IRR_SHIFT;
pub(super) const IOAPIC_LVT_TRIGGER_MODE: u64 = 1 << IOAPIC_LVT_TRIGGER_MODE_SHIFT;
const IOAPIC_LVT_DELIV_STATUS: u64 = 1 << IOAPIC_LVT_DELIV_STATUS_SHIFT;

const IOAPIC_RO_BITS: u64 = IOAPIC_LVT_REMOTE_IRR | IOAPIC_LVT_DELIV_STATUS;
const IOAPIC_RW_BITS: u64 = !IOAPIC_RO_BITS;

pub(super) const IOAPIC_DM_MASK: u64 = 0x7;
const IOAPIC_ID_MASK: u64 = 0xf;
pub(super) const IOAPIC_VECTOR_MASK: u64 = 0xff;

pub(super) const IOAPIC_DM_EXTINT: u64 = 0x7;
const IOAPIC_REG_REDTBL_BASE: u64 = 0x10;

pub struct IoApicRegs {
    id: u8,
    ioregsel: u8,
    pub(super) irr: u32,
    pub(super) ioredtbl: [u64; IOAPIC_NUM_PINS],
    version: u8,
}

impl IoApicRegs {
    fn new() -> Self {
        Self {
            id: 0,
            ioregsel: 0,
            irr: 0,
            ioredtbl: [1 << IOAPIC_LVT_MASKED_SHIFT; IOAPIC_NUM_PINS],
            version: 0x20,
        }
    }

    fn fix_edge_remote_irr(&mut self, index: usize) {
        if self.ioredtbl[index] & IOAPIC_LVT_TRIGGER_MODE == IOAPIC_TRIGGER_EDGE {
            self.ioredtbl[index] &= !IOAPIC_LVT_REMOTE_IRR;
        }
    }
}

// Implemented per hypervisor to handle interrupt injection and routing.
pub trait IoApicBackend: Send + 'static {
    /// Called after the guest updates a redirection table entry.
    fn on_entry_changed(&mut self, regs: &mut IoApicRegs, index: usize);

    /// Called when a guest EOI clears Remote-IRR for `index`.
    /// Backends should re-deliver if the pin is still asserted (IRR set).
    fn on_eoi(&mut self, regs: &mut IoApicRegs);

    /// Called from `IrqChipT::set_irq` to assert an interrupt line.
    fn set_irq(
        &mut self,
        irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
        regs: &mut IoApicRegs,
    ) -> Result<(), DeviceError>;
}

struct IoapicInner<B: IoApicBackend> {
    regs: IoApicRegs,
    backend: B,
}

pub struct Ioapic<B: IoApicBackend> {
    inner: Mutex<IoapicInner<B>>,
}

impl<B: IoApicBackend> Ioapic<B> {
    pub(super) fn from_backend(backend: B) -> Self {
        Self {
            inner: Mutex::new(IoapicInner {
                regs: IoApicRegs::new(),
                backend,
            }),
        }
    }
}

impl<B: IoApicBackend> IrqChipT for Ioapic<B> {
    fn get_mmio_addr(&self) -> u64 {
        IOAPIC_BASE as u64
    }

    fn get_mmio_size(&self) -> u64 {
        0x1000
    }

    fn set_irq(
        &self,
        irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        let mut inner = self.inner.lock().unwrap();
        let IoapicInner { regs, backend } = &mut *inner;
        backend.set_irq(irq_line, interrupt_evt, regs)
    }
}

impl<B: IoApicBackend> BusDevice for Ioapic<B> {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        let mut inner = self.inner.lock().unwrap();
        let IoapicInner { regs, .. } = &mut *inner;

        let val = match offset {
            IO_REG_SEL => {
                debug!("ioapic: read: ioregsel");
                regs.ioregsel as u32
            }
            IO_WIN => {
                // the data needs to be 32-bits in size
                if data.len() != 4 {
                    error!("ioapic: bad read size {}", data.len());
                    return;
                }

                match regs.ioregsel {
                    IO_APIC_ID | IO_APIC_ARB => {
                        debug!("ioapic: read: IOAPIC ID");
                        ((regs.id as u64) << IOAPIC_ID_SHIFT) as u32
                    }
                    IO_APIC_VER => {
                        debug!("ioapic: read: IOAPIC version");
                        regs.version as u32
                            | ((IOAPIC_NUM_PINS as u32 - 1) << IOAPIC_VER_ENTRIES_SHIFT)
                    }
                    _ => {
                        let index = (regs.ioregsel as u64 - IOAPIC_REG_REDTBL_BASE) >> 1;
                        debug!("ioapic: read: ioredtbl register {index}");
                        let mut val = 0u32;

                        // we can only read from this register in 32-bit chunks.
                        // Therefore, we need to check if we are reading the
                        // upper 32 bits or the lower
                        if index < IOAPIC_NUM_PINS as u64 {
                            if regs.ioregsel & 1 > 0 {
                                // read upper 32 bits
                                val = (regs.ioredtbl[index as usize] >> 32) as u32;
                            } else {
                                // read lower 32 bits
                                val = (regs.ioredtbl[index as usize] & 0xffff_ffffu64) as u32;
                            }
                        }
                        val
                    }
                }
            }
            _ => unreachable!(),
        };

        // turn the value into native endian byte order and put that value into `data`
        let out_arr = val.to_ne_bytes();
        for i in 0..4 {
            if i < data.len() {
                data[i] = out_arr[i];
            }
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        // data needs to be 32-bits in size
        if data.len() != 4 {
            error!("ioapic: bad write size {}", data.len());
            return;
        }

        // convert data into a u32 int with native endianness
        let arr = [data[0], data[1], data[2], data[3]];
        let val = u32::from_ne_bytes(arr);

        let mut inner = self.inner.lock().unwrap();
        let IoapicInner { regs, backend } = &mut *inner;

        match offset {
            IO_REG_SEL => {
                debug!("ioapic: write: ioregsel");
                regs.ioregsel = val as u8
            }
            IO_WIN => {
                match regs.ioregsel {
                    IO_APIC_ID => {
                        debug!("ioapic: write: IOAPIC ID");
                        regs.id = ((val >> IOAPIC_ID_SHIFT) & (IOAPIC_ID_MASK as u32)) as u8
                    }
                    // NOTE: these are read-only registers, so they should never be written to
                    IO_APIC_VER | IO_APIC_ARB => debug!("ioapic: write: IOAPIC VERSION"),
                    _ => {
                        if regs.ioregsel < (IO_WIN as u8) {
                            debug!("invalid write; ignore");
                            return;
                        }

                        let index = (regs.ioregsel as u64 - IOAPIC_REG_REDTBL_BASE) >> 1;
                        debug!("ioapic: write: ioredtbl register {index}");
                        if index >= IOAPIC_NUM_PINS as u64 {
                            warn!("ioapic: write: virq out of pin range {index}");
                            return;
                        }

                        let ro_bits = regs.ioredtbl[index as usize] & IOAPIC_RO_BITS;
                        // check if we are writing to the upper 32-bits of the
                        // register or the lower 32-bits
                        if regs.ioregsel & 1 > 0 {
                            regs.ioredtbl[index as usize] &= 0xffff_ffff;
                            regs.ioredtbl[index as usize] |= (val as u64) << 32;
                        } else {
                            regs.ioredtbl[index as usize] &= !0xffff_ffff;
                            regs.ioredtbl[index as usize] |= val as u64;
                        }

                        // restore RO bits
                        regs.ioredtbl[index as usize] &= IOAPIC_RW_BITS;
                        regs.ioredtbl[index as usize] |= ro_bits;

                        // if the trigger mode is EDGE, clear IRR bit
                        regs.fix_edge_remote_irr(index as usize);
                        backend.on_entry_changed(regs, index as usize);
                    }
                }
            }
            IO_EOI => {
                let vector = (val as u64 & IOAPIC_VECTOR_MASK) as u8;
                let mut cleared = false;
                for i in 0..IOAPIC_NUM_PINS {
                    let entry = regs.ioredtbl[i];
                    if (entry & IOAPIC_VECTOR_MASK) as u8 == vector
                        && entry & IOAPIC_LVT_REMOTE_IRR != 0
                    {
                        regs.ioredtbl[i] &= !IOAPIC_LVT_REMOTE_IRR;
                        cleared = true;
                    }
                }
                if cleared {
                    backend.on_eoi(regs);
                }
            }
            _ => unreachable!(),
        }
    }
}
