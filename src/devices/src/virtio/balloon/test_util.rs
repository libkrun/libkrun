//! A balloon device whose free page reporting queue the tests fill the way a guest does.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use vm_memory::{GuestAddress, GuestMemoryMmap};

use super::defs::NUM_QUEUES;
use super::device::{Balloon, FRQ_INDEX};
use crate::legacy::DummyIrqChip;
use crate::virtio::queue::tests::VirtQueue;
use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::virtio::{DeviceQueue, InterruptTransport, Queue, VirtioDevice, VIRTIO_MMIO_INT_VRING};

pub(super) struct TestDevice<'a> {
    pub(super) balloon: Balloon,
    pub(super) frq: VirtQueue<'a>,
    interrupt: InterruptTransport,
}

impl<'a> TestDevice<'a> {
    /// Attaches and activates a balloon whose free page reporting queue is at the start of `mem`.
    pub(super) fn new(mem: &'a GuestMemoryMmap) -> Self {
        let mut balloon = Balloon::new().unwrap();

        let frq = VirtQueue::new(GuestAddress(0), mem, 16);
        let queues = (0..NUM_QUEUES)
            .map(|i| {
                let queue = if i == FRQ_INDEX {
                    frq.create_queue()
                } else {
                    Queue::new(16)
                };
                DeviceQueue::new(queue, Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()))
            })
            .collect();
        let interrupt =
            InterruptTransport::new(DummyIrqChip::new().into(), "balloon".into()).unwrap();
        balloon
            .activate(mem.clone(), interrupt.clone(), queues)
            .unwrap();

        Self {
            balloon,
            frq,
            interrupt,
        }
    }

    /// Puts a report of free pages in the queue, as the guest does.
    pub(super) fn report(&self, ranges: &[(u64, u32)]) {
        for (i, &(addr, len)) in ranges.iter().enumerate() {
            let next = i + 1 < ranges.len();
            let flags = VIRTQ_DESC_F_WRITE | if next { VIRTQ_DESC_F_NEXT } else { 0 };
            self.frq.dtable[i].set(addr, len, flags, i as u16 + 1);
        }
        let idx = self.frq.avail.idx.get();
        self.frq.avail.ring[usize::from(idx) % self.frq.dtable.len()].set(0);
        self.frq.avail.idx.set(idx + 1);
    }

    /// Notifies the device about the reports in the queue, as the guest does.
    pub(super) fn notify(&mut self) {
        self.balloon.queues.as_ref().unwrap()[FRQ_INDEX]
            .event
            .write(1)
            .unwrap();
        self.balloon
            .handle_frq_event(&EpollEvent::new(EventSet::IN, 0));
    }

    pub(super) fn used(&self) -> u16 {
        self.frq.used.idx.get()
    }

    /// The number of reports that the guest made available and the device didn't take yet.
    pub(super) fn pending(&self, mem: &GuestMemoryMmap) -> u16 {
        self.balloon.queues.as_ref().unwrap()[FRQ_INDEX]
            .queue
            .len(mem)
    }

    pub(super) fn signaled(&self) -> bool {
        self.interrupt.status().load(Ordering::SeqCst) & VIRTIO_MMIO_INT_VRING as usize != 0
    }
}
