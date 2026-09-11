use crossbeam_channel::unbounded;
#[cfg(not(feature = "tdx"))]
use kvm_bindings::{KVM_CAP_SPLIT_IRQCHIP, kvm_enable_cap};
use kvm_bindings::{
    KVM_IRQ_ROUTING_MSI, KvmIrqRouting, kvm_irq_routing_entry, kvm_irq_routing_entry__bindgen_ty_1,
    kvm_irq_routing_msi,
};

use kvm_ioctls::{Error, VmFd};

use utils::eventfd::EventFd;
use utils::worker_message::WorkerMessage;

use crate::Error as DeviceError;

use super::ioapic::{
    IOAPIC_DM_EXTINT, IOAPIC_DM_MASK, IOAPIC_LVT_DELIV_MODE_SHIFT, IOAPIC_LVT_DEST_MODE_SHIFT,
    IOAPIC_LVT_MASKED_SHIFT, IOAPIC_LVT_REMOTE_IRR, IOAPIC_LVT_TRIGGER_MODE_SHIFT, IOAPIC_NUM_PINS,
    IOAPIC_TRIGGER_EDGE, IOAPIC_VECTOR_MASK, IoApicBackend, IoApicRegs, Ioapic,
};

const APIC_DEFAULT_ADDRESS: u32 = 0xfee0_0000;

const MSI_DATA_VECTOR_SHIFT: u64 = 0;
const MSI_ADDR_DEST_MODE_SHIFT: u64 = 2;
const MSI_ADDR_DEST_IDX_SHIFT: u64 = 4;
const MSI_DATA_DELIVERY_MODE_SHIFT: u64 = 8;
const MSI_DATA_TRIGGER_SHIFT: u64 = 15;

const IOAPIC_LVT_DEST_IDX_SHIFT: u64 = 48;

/// 63:56 Destination Field (RW)
/// 55:17 Reserved
/// 16 Interrupt Mask (RW)
/// 15 Trigger Mode (RW)
/// 14 Remote IRR (RO)
/// 13 Interrupt Input Pin Polarity (INTPOL) (RW)
/// 12 Delivery Status (DELIVS) (RO)
/// 11 Destination Mode (DESTMOD) (RW)
/// 10:8 Delivery Mode (DELMOD) (RW)
/// 7:0 Interrupt Vector (INTVEC) (RW)
type RedirectionTableEntry = u64;

#[derive(Debug, Default)]
struct IoApicEntryInfo {
    masked: u8,
    trig_mode: u8,
    _dest_idx: u16,
    _dest_mode: u8,
    _delivery_mode: u8,
    _vector: u8,

    addr: u32,
    data: u32,
}

#[derive(Default)]
struct MsiMessage {
    address: u64,
    data: u64,
}

#[derive(Debug)]
pub struct IoApicKvmBackend {
    irq_eoi: [i32; IOAPIC_NUM_PINS],
    irq_routes: Vec<kvm_irq_routing_entry>,
    irq_sender: crossbeam_channel::Sender<WorkerMessage>,
}

impl IoApicKvmBackend {
    fn add_msi_route(&mut self, virq: usize) {
        let msg = MsiMessage::default();
        let kroute = kvm_irq_routing_entry {
            gsi: virq as u32,
            type_: KVM_IRQ_ROUTING_MSI,
            flags: 0,
            u: kvm_irq_routing_entry__bindgen_ty_1 {
                msi: kvm_irq_routing_msi {
                    address_lo: msg.address as u32,
                    address_hi: (msg.address >> 32) as u32,
                    data: msg.data as u32,
                    ..Default::default()
                },
            },
            ..Default::default()
        };

        // 4095 is the max irq number for kvm (MAX_IRQ_ROUTES - 1)
        if self.irq_routes.len() < 4095 {
            self.irq_routes.push(kroute);
        } else {
            error!("ioapic: not enough space for irq");
        }
    }

    fn parse_entry(&self, entry: &RedirectionTableEntry) -> IoApicEntryInfo {
        let vector = (entry & IOAPIC_VECTOR_MASK) as u8;
        let dest_idx = ((entry >> IOAPIC_LVT_DEST_IDX_SHIFT) & 0xffff) as u16;
        let delivery_mode = ((entry >> IOAPIC_LVT_DELIV_MODE_SHIFT) & IOAPIC_DM_MASK) as u8;
        let trig_mode = ((entry >> IOAPIC_LVT_TRIGGER_MODE_SHIFT) & 1) as u8;
        let dest_mode = ((entry >> IOAPIC_LVT_DEST_MODE_SHIFT) & 1) as u8;

        if delivery_mode as u64 == IOAPIC_DM_EXTINT {
            panic!("ioapic: libkrun does not have PIC support");
        }

        IoApicEntryInfo {
            masked: ((entry >> IOAPIC_LVT_MASKED_SHIFT) & 1) as u8,
            trig_mode,
            _dest_idx: dest_idx,
            _dest_mode: dest_mode,
            _delivery_mode: delivery_mode,
            _vector: vector,

            addr: ((APIC_DEFAULT_ADDRESS as u64)
                | ((dest_idx as u64) << MSI_ADDR_DEST_IDX_SHIFT)
                | ((dest_mode as u64) << MSI_ADDR_DEST_MODE_SHIFT)) as u32,
            data: (((vector as u64) << MSI_DATA_VECTOR_SHIFT)
                | ((trig_mode as u64) << MSI_DATA_TRIGGER_SHIFT)
                | ((delivery_mode as u64) << MSI_DATA_DELIVERY_MODE_SHIFT))
                as u32,
        }
    }

    fn update_msi_route(&mut self, virq: usize, msg: &MsiMessage) {
        let kroute = kvm_irq_routing_entry {
            gsi: virq as u32,
            type_: KVM_IRQ_ROUTING_MSI,
            flags: 0,
            u: kvm_irq_routing_entry__bindgen_ty_1 {
                msi: kvm_irq_routing_msi {
                    address_lo: msg.address as u32,
                    address_hi: (msg.address >> 32) as u32,
                    data: msg.data as u32,
                    ..Default::default()
                },
            },
            ..Default::default()
        };

        for entry in self.irq_routes.iter_mut() {
            if entry.gsi == kroute.gsi {
                *entry = kroute;
            }
        }
    }

    fn update_routes(&mut self, regs: &IoApicRegs) {
        for i in 0..IOAPIC_NUM_PINS {
            let info = self.parse_entry(&regs.ioredtbl[i]);

            if info.masked == 0 {
                let msg = MsiMessage {
                    address: info.addr as u64,
                    data: info.data as u64,
                };

                self.update_msi_route(i, &msg);
            }
        }

        let (response_sender, response_receiver) = unbounded();
        self.irq_sender
            .send(WorkerMessage::GsiRoute(
                response_sender.clone(),
                self.irq_routes.clone(),
            ))
            .unwrap();
        if !response_receiver.recv().unwrap() {
            error!("unable to set GSI Routes for IO APIC");
        }
    }

    fn service(&mut self, regs: &mut IoApicRegs) {
        for i in 0..IOAPIC_NUM_PINS {
            let mask = 1 << i;

            if regs.irr & mask > 0 {
                let mut coalesce = 0;

                let entry = regs.ioredtbl[i];
                let info = self.parse_entry(&entry);
                if info.masked == 0 {
                    if info.trig_mode as u64 == IOAPIC_TRIGGER_EDGE {
                        regs.irr &= !mask;
                    } else {
                        coalesce = regs.ioredtbl[i] & IOAPIC_LVT_REMOTE_IRR;
                        regs.ioredtbl[i] |= IOAPIC_LVT_REMOTE_IRR;
                    }

                    if coalesce > 0 {
                        continue;
                    }

                    let (response_sender, response_receiver) = unbounded();
                    if info.trig_mode as u64 == IOAPIC_TRIGGER_EDGE {
                        self.irq_sender
                            .send(WorkerMessage::IrqLine(
                                response_sender.clone(),
                                i as u32,
                                true,
                            ))
                            .unwrap();
                        if !response_receiver.recv().unwrap() {
                            error!(
                                "unable to set IRQ LINE for IRQ {} with active set to {}",
                                i, true
                            );
                        }

                        self.irq_sender
                            .send(WorkerMessage::IrqLine(
                                response_sender.clone(),
                                i as u32,
                                false,
                            ))
                            .unwrap();
                        if !response_receiver.recv().unwrap() {
                            error!(
                                "unable to set IRQ LINE for IRQ {} with active set to {}",
                                i, false
                            );
                        }
                    } else {
                        self.irq_sender
                            .send(WorkerMessage::IrqLine(
                                response_sender.clone(),
                                i as u32,
                                true,
                            ))
                            .unwrap();
                        if !response_receiver.recv().unwrap() {
                            error!(
                                "unable to set IRQ LINE for IRQ {} with active set to {}",
                                i, true
                            );
                        }
                    }
                }
            }
        }
    }
}

impl IoApicBackend for IoApicKvmBackend {
    fn on_entry_changed(&mut self, regs: &mut IoApicRegs, index: usize) {
        self.irq_eoi[index] = 0;
        self.update_routes(regs);
        self.service(regs);
    }

    fn on_eoi(&mut self, regs: &mut IoApicRegs) {
        self.service(regs);
    }

    fn set_irq(
        &mut self,
        _irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
        _regs: &mut IoApicRegs,
    ) -> Result<(), DeviceError> {
        if let Some(interrupt_evt) = interrupt_evt {
            if let Err(e) = interrupt_evt.write(1) {
                error!("Failed to signal used queue: {e:?}");
                return Err(DeviceError::FailedSignalingUsedQueue(e));
            }
        } else {
            error!("EventFd not set up for irq line");
            return Err(DeviceError::FailedSignalingUsedQueue(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "EventFd not set up for irq line",
            )));
        }
        Ok(())
    }
}

pub type IoApic = Ioapic<IoApicKvmBackend>;

impl Ioapic<IoApicKvmBackend> {
    pub fn new(
        vm: &VmFd,
        _irq_sender: crossbeam_channel::Sender<WorkerMessage>,
    ) -> Result<Self, Error> {
        #[cfg(not(feature = "tdx"))]
        {
            let mut cap = kvm_enable_cap {
                cap: KVM_CAP_SPLIT_IRQCHIP,
                ..Default::default()
            };
            cap.args[0] = 24;
            vm.enable_cap(&cap)?;
        }

        let mut backend = IoApicKvmBackend {
            irq_eoi: [0; IOAPIC_NUM_PINS],
            irq_routes: Vec::with_capacity(IOAPIC_NUM_PINS),
            irq_sender: _irq_sender,
        };

        (0..IOAPIC_NUM_PINS).for_each(|i| backend.add_msi_route(i));

        let mut routing = KvmIrqRouting::new(backend.irq_routes.len()).unwrap();
        let routing_entries = routing.as_mut_slice();
        routing_entries.copy_from_slice(backend.irq_routes.as_slice());
        vm.set_gsi_routing(&routing)?;

        Ok(Ioapic::from_backend(backend))
    }
}
