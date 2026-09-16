// Copyright 2026 The libkrun Authors
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use crossbeam_channel::Sender;
use kvm_bindings::{
    KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI, KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER,
    KVM_IRQCHIP_PIC_SLAVE, kvm_irq_routing_entry, kvm_irq_routing_entry__bindgen_ty_1,
    kvm_irq_routing_irqchip, kvm_irq_routing_msi,
};
use utils::byte_order;
use utils::eventfd::EventFd;
use utils::worker_message::WorkerMessage;

use super::PciBdf;
use super::config::PciCapability;
use super::config::PciCapabilityId;
use super::trace;

const MSIX_ENABLE_BIT: u8 = 15;
const FUNCTION_MASK_BIT: u8 = 14;

#[derive(Debug, Clone)]
pub struct MsixTableEntry {
    pub msg_addr_lo: u32,
    pub msg_addr_hi: u32,
    pub msg_data: u32,
    pub vector_ctl: u32,
}

impl Default for MsixTableEntry {
    fn default() -> Self {
        // PCI: per-vector Mask bit resets to 1.
        Self {
            msg_addr_lo: 0,
            msg_addr_hi: 0,
            msg_data: 0,
            vector_ctl: 1,
        }
    }
}

impl MsixTableEntry {
    pub fn masked(&self) -> bool {
        self.vector_ctl & 0x1 == 0x1
    }
}

/// MSI-X capability body without the 2-byte PCI capability header.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct MsixCap {
    msg_ctl: u16,
    table: u32,
    pba: u32,
}

impl MsixCap {
    pub fn new(
        table_bir: u8,
        table_size: u16,
        table_offset: u32,
        pba_bir: u8,
        pba_offset: u32,
    ) -> Self {
        assert!(table_size > 0);
        Self {
            // Table Size is N-1; Enable and Function Mask start cleared.
            msg_ctl: table_size - 1,
            table: (table_offset & 0xffff_fff8) | u32::from(table_bir & 0x7),
            pba: (pba_offset & 0xffff_fff8) | u32::from(pba_bir & 0x7),
        }
    }
}

impl PciCapability for MsixCap {
    fn bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                (self as *const Self).cast::<u8>(),
                std::mem::size_of::<Self>(),
            )
        }
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::MsiX
    }
}

pub struct MsixVector {
    pub eventfd: EventFd,
    pub gsi: u32,
}

/// Shared KVM GSI routing table for all PCI devices on a VM.
#[derive(Clone)]
pub struct MsixRouteContext {
    routes: Arc<Mutex<Vec<kvm_irq_routing_entry>>>,
    sender: Sender<WorkerMessage>,
    /// When true, every GSI routing update includes KVM's default PIC/IOAPIC
    /// routes (required for in-kernel irqchip). When false (split irqchip),
    /// the userspace IOAPIC owns those GSIs instead.
    preserve_irqchip_routes: bool,
}

/// KVM default PIC/IOAPIC GSI routes for in-kernel irqchip (x86).
///
/// `KVM_SET_GSI_ROUTING` replaces the entire routing table. With
/// `KVM_CREATE_IRQCHIP`, KVM installs these defaults at creation time; any
/// later userspace routing update must include them or legacy IRQs break
/// (and MSI-X setup in the guest can fail as a result).
pub fn x86_default_irqchip_routes() -> Vec<kvm_irq_routing_entry> {
    let mut routes = Vec::with_capacity(40);
    let push_irqchip = |routes: &mut Vec<_>, gsi: u32, irqchip: u32, pin: u32| {
        routes.push(kvm_irq_routing_entry {
            gsi,
            type_: KVM_IRQ_ROUTING_IRQCHIP,
            flags: 0,
            u: kvm_irq_routing_entry__bindgen_ty_1 {
                irqchip: kvm_irq_routing_irqchip { irqchip, pin },
            },
            ..Default::default()
        });
    };
    for irq in 0..8u32 {
        push_irqchip(&mut routes, irq, KVM_IRQCHIP_PIC_MASTER, irq);
        push_irqchip(&mut routes, irq, KVM_IRQCHIP_IOAPIC, irq);
    }
    for irq in 8..16u32 {
        push_irqchip(&mut routes, irq, KVM_IRQCHIP_PIC_SLAVE, irq - 8);
        push_irqchip(&mut routes, irq, KVM_IRQCHIP_IOAPIC, irq);
    }
    for irq in 16..24u32 {
        push_irqchip(&mut routes, irq, KVM_IRQCHIP_IOAPIC, irq);
    }
    routes
}

impl MsixRouteContext {
    pub fn new(
        routes: Arc<Mutex<Vec<kvm_irq_routing_entry>>>,
        sender: Sender<WorkerMessage>,
        preserve_irqchip_routes: bool,
    ) -> Self {
        Self {
            routes,
            sender,
            preserve_irqchip_routes,
        }
    }

    pub fn push_routes(&self, msi_routes: &[kvm_irq_routing_entry]) {
        let routes = if self.preserve_irqchip_routes {
            let mut routes = x86_default_irqchip_routes();
            routes.extend_from_slice(msi_routes);
            routes
        } else {
            msi_routes.to_vec()
        };
        let n = routes.len();
        let (reply_tx, reply_rx) = crossbeam_channel::bounded(1);
        if self
            .sender
            .send(WorkerMessage::GsiRoute(reply_tx, routes))
            .is_err()
        {
            log::error!("failed to send GSI routing update ({n} entries)");
            return;
        }
        match reply_rx.recv() {
            Ok(true) => {}
            Ok(false) => log::error!("GSI routing update rejected by KVM ({n} entries)"),
            Err(_) => log::error!("GSI routing update reply channel closed ({n} entries)"),
        }
    }
}

pub struct MsixConfig {
    pub table_entries: Vec<MsixTableEntry>,
    pub pba_entries: Vec<u64>,
    pub vectors: Vec<MsixVector>,
    pub sbdf: PciBdf,
    pub masked: bool,
    pub enabled: bool,
    pub table_offset: u32,
    pub pba_offset: u32,
    route_ctx: Option<MsixRouteContext>,
}

impl MsixConfig {
    pub fn new(
        vectors: Vec<MsixVector>,
        sbdf: PciBdf,
        table_offset: u32,
        pba_offset: u32,
        route_ctx: Option<MsixRouteContext>,
    ) -> Self {
        let num_vectors = vectors.len();
        Self {
            table_entries: vec![MsixTableEntry::default(); num_vectors],
            pba_entries: vec![0; num_vectors.div_ceil(64)],
            vectors,
            sbdf,
            // Function Mask resets to 0; per-vector Mask resets to 1 (see Default).
            masked: false,
            enabled: false,
            table_offset,
            pba_offset,
            route_ctx,
        }
    }

    fn sync_route(&self, vector_idx: usize) {
        let Some(ctx) = &self.route_ctx else {
            return;
        };
        if vector_idx >= self.vectors.len() {
            return;
        }
        let gsi = self.vectors[vector_idx].gsi;
        let entry = &self.table_entries[vector_idx];
        let mut routes = ctx.routes.lock().unwrap();
        for route in routes.iter_mut() {
            if route.gsi == gsi {
                // Assign the whole MSI union; field-by-field writes can miss a Copy temporary.
                route.u.msi = kvm_irq_routing_msi {
                    address_lo: entry.msg_addr_lo,
                    address_hi: entry.msg_addr_hi,
                    data: entry.msg_data,
                    ..Default::default()
                };
                break;
            }
        }
        let snapshot = routes.clone();
        drop(routes);
        trace::msix_route_update(&self.sbdf, gsi);
        ctx.push_routes(&snapshot);
    }

    pub fn num_vectors(&self) -> usize {
        self.vectors.len()
    }

    pub fn write_table(&mut self, offset: u64, data: &[u8]) {
        let entry_idx = (offset / 16) as usize;
        let field_offset = (offset % 16) as usize;
        if entry_idx >= self.table_entries.len() || data.len() < 4 {
            return;
        }
        let value = byte_order::read_le_u32(data);
        let entry = &mut self.table_entries[entry_idx];
        match field_offset {
            0 => entry.msg_addr_lo = value,
            4 => entry.msg_addr_hi = value,
            8 => entry.msg_data = value,
            12 => {
                entry.vector_ctl = value;
                return;
            }
            _ => return,
        }
        trace::msix_vector(
            &self.sbdf,
            entry_idx,
            entry.msg_addr_lo,
            entry.msg_addr_hi,
            entry.msg_data,
        );
        self.sync_route(entry_idx);
    }

    pub fn read_table(&self, offset: u64, data: &mut [u8]) {
        let entry_idx = (offset / 16) as usize;
        let field_offset = (offset % 16) as usize;
        if entry_idx >= self.table_entries.len() {
            data.fill(0);
            return;
        }
        let entry = &self.table_entries[entry_idx];
        let value = match field_offset {
            0 => entry.msg_addr_lo,
            4 => entry.msg_addr_hi,
            8 => entry.msg_data,
            12 => entry.vector_ctl,
            _ => 0,
        };
        if data.len() >= 4 {
            byte_order::write_le_u32(data, value);
        }
    }

    pub fn write_pba(&mut self, offset: u64, data: &[u8]) {
        let entry_idx = (offset / 8) as usize;
        if entry_idx >= self.pba_entries.len() {
            return;
        }
        if data.len() >= 8 {
            self.pba_entries[entry_idx] = byte_order::read_le_u64(data);
        } else if data.len() >= 4 {
            let lo = byte_order::read_le_u32(data);
            self.pba_entries[entry_idx] =
                (self.pba_entries[entry_idx] & 0xffff_ffff_0000_0000) | u64::from(lo);
        }
    }

    pub fn read_pba(&self, offset: u64, data: &mut [u8]) {
        let entry_idx = (offset / 8) as usize;
        if entry_idx >= self.pba_entries.len() {
            data.fill(0);
            return;
        }
        if data.len() >= 8 {
            byte_order::write_le_u64(data, self.pba_entries[entry_idx]);
        } else if data.len() >= 4 {
            byte_order::write_le_u32(data, self.pba_entries[entry_idx] as u32);
        }
    }

    pub fn set_msix_enable(&mut self, value: u16) {
        self.enabled = value & (1 << MSIX_ENABLE_BIT) != 0;
        self.masked = value & (1 << FUNCTION_MASK_BIT) != 0;
        trace::msix_enable(&self.sbdf, self.enabled, self.masked);
    }

    pub fn msix_enable_value(&self) -> u16 {
        let mut value = (self.table_entries.len().saturating_sub(1) as u16) & 0x7ff;
        if self.enabled {
            value |= 1 << MSIX_ENABLE_BIT;
        }
        if self.masked {
            value |= 1 << FUNCTION_MASK_BIT;
        }
        value
    }

    pub fn trigger_vector(&self, vector: usize) -> std::io::Result<()> {
        if vector < self.vectors.len()
            && self.enabled
            && !self.masked
            && !self.table_entries[vector].masked()
        {
            self.vectors[vector].eventfd.write(1)
        } else {
            Ok(())
        }
    }

    pub fn push_routes(&self, routes: &mut Vec<kvm_irq_routing_entry>) {
        for (idx, vector) in self.vectors.iter().enumerate() {
            let entry = &self.table_entries[idx];
            routes.push(kvm_irq_routing_entry {
                gsi: vector.gsi,
                type_: KVM_IRQ_ROUTING_MSI,
                flags: 0,
                u: kvm_irq_routing_entry__bindgen_ty_1 {
                    msi: kvm_irq_routing_msi {
                        address_lo: entry.msg_addr_lo,
                        address_hi: entry.msg_addr_hi,
                        data: entry.msg_data,
                        ..Default::default()
                    },
                },
                ..Default::default()
            });
        }
    }

    pub fn register_irqfds(&self, vm: &kvm_ioctls::VmFd) -> Result<(), kvm_ioctls::Error> {
        for vector in &self.vectors {
            vm.register_irqfd(&vector.eventfd, vector.gsi)?;
        }
        Ok(())
    }
}
