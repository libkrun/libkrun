use std::ops::Range;
use std::os::fd::{AsRawFd, RawFd};
use std::thread;

use crossbeam_channel::{Receiver, Sender, unbounded};
use utils::epoll::{EpollEvent, EventSet};
use utils::pollable_channel::{PollableChannelReciever, PollableChannelSender, pollable_channel};
use utils::worker_message::WorkerMessage;
use vm_memory::GuestAddress;

use super::device::{Balloon, FRQ_INDEX};
use super::{BalloonError, Result};
use crate::virtio::DeviceState;

/// Smaller or unaligned reports are only madvise()d, so that the guest can't make the VMM split
/// the stage-2 mapping of its RAM into small pieces. Linux reports 2 MiB blocks by default.
const RECLAIM_ALIGN: u64 = 2 << 20;

/// Has the VMM replace the pages of free page reports, which gives them back to the host.
///
/// A thread waits for the VMM worker, which may be busy, and a report is added to the used ring
/// only once its pages are mapped into the guest again. The guest doesn't touch reported pages
/// before that, so it never finds them unmapped.
#[derive(Default)]
pub(super) struct FreePageReclaim {
    enabled: bool,
    reclaimer: Option<Reclaimer>,
}

struct Reclaimer {
    reports: Sender<Report>,
    done: PollableChannelReciever<u16>,
}

struct Report {
    head: u16,
    ranges: Vec<Range<u64>>,
}

impl FreePageReclaim {
    /// Whether a range of a report is to be reclaimed rather than madvise()d.
    pub(super) fn reclaims(&self, addr: GuestAddress, len: u32) -> bool {
        self.reclaimer.is_some() && reclaimable(addr, len)
    }

    /// Has the VMM reclaim the ranges of the report `head`. Returns false if there are none, in
    /// which case the report can be completed right away.
    pub(super) fn submit(&self, head: u16, ranges: Vec<Range<u64>>) -> bool {
        match &self.reclaimer {
            Some(reclaimer) if !ranges.is_empty() => {
                reclaimer.reports.send(Report { head, ranges }).unwrap();
                true
            }
            _ => false,
        }
    }

    pub(super) fn done_fd(&self) -> Option<RawFd> {
        self.reclaimer.as_ref().map(|r| r.done.as_raw_fd())
    }
}

impl Reclaimer {
    fn new(map_sender: Sender<WorkerMessage>) -> Result<Self> {
        let (done_sender, done) = pollable_channel().map_err(BalloonError::EventFd)?;
        let (reports, report_receiver) = unbounded();
        thread::Builder::new()
            .name("balloon reclaim".into())
            .spawn(move || reclaim(report_receiver, map_sender, done_sender))
            .map_err(BalloonError::ReclaimThread)?;
        Ok(Self { reports, done })
    }
}

fn reclaim(
    reports: Receiver<Report>,
    map_sender: Sender<WorkerMessage>,
    done: PollableChannelSender<u16>,
) {
    for report in reports {
        for range in report.ranges {
            let (reply_sender, reply) = unbounded();
            map_sender
                .send(WorkerMessage::ReclaimMemory(
                    reply_sender,
                    range.start,
                    range.end - range.start,
                ))
                .unwrap();
            // Pages that the VMM couldn't replace are left as they were, which only costs memory.
            reply.recv().unwrap();
        }
        done.send(report.head).unwrap();
    }
}

fn reclaimable(addr: GuestAddress, len: u32) -> bool {
    let len = u64::from(len);
    len != 0 && addr.0.is_multiple_of(RECLAIM_ALIGN) && len.is_multiple_of(RECLAIM_ALIGN)
}

impl Balloon {
    /// Set whether free page reports are given back to the host by having the VMM replace the
    /// reported pages, instead of madvise()ing them, which doesn't release pages that the guest
    /// has written to. Must be called before [`Balloon::set_map_sender`].
    pub fn set_free_page_reclaim(&mut self, enabled: bool) {
        self.reclaim.enabled = enabled;
    }

    /// Set the channel to the VMM worker, and start free page reclaim if it's enabled.
    pub fn set_map_sender(&mut self, map_sender: Sender<WorkerMessage>) -> Result<()> {
        if self.reclaim.enabled {
            self.reclaim.reclaimer = Some(Reclaimer::new(map_sender)?);
        }
        Ok(())
    }

    pub(super) fn handle_reclaim_done_event(&mut self, event: &EpollEvent) {
        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("balloon: reclaim done unexpected event {event_set:?}");
            return;
        }

        let DeviceState::Activated(ref mem, _) = self.device_state else {
            unreachable!()
        };
        let queue = &mut self
            .queues
            .as_mut()
            .expect("queues should exist when activated")[FRQ_INDEX]
            .queue;
        let reclaimer = self
            .reclaim
            .reclaimer
            .as_ref()
            .expect("reclaimer should exist when its event fires");
        let mut have_used = false;
        while let Ok(Some(head)) = reclaimer.done.try_recv() {
            have_used = true;
            if let Err(e) = queue.add_used(mem, head, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }
        if have_used {
            self.device_state.signal_used_queue();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    use utils::eventfd::{EFD_NONBLOCK, EventFd};
    use vm_memory::GuestMemoryMmap;

    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::virtio::{
        DeviceQueue, InterruptTransport, Queue, VIRTIO_MMIO_INT_VRING, VirtioDevice,
    };

    const TIMEOUT: Duration = Duration::from_secs(5);

    struct TestDevice<'a> {
        balloon: Balloon,
        frq: VirtQueue<'a>,
        interrupt: InterruptTransport,
        worker: Receiver<WorkerMessage>,
    }

    impl<'a> TestDevice<'a> {
        /// Attaches and activates a balloon, calling set_free_page_reclaim() unless `reclaim` is
        /// None.
        fn new(mem: &'a GuestMemoryMmap, reclaim: Option<bool>) -> Self {
            let mut balloon = Balloon::new().unwrap();
            if let Some(enabled) = reclaim {
                balloon.set_free_page_reclaim(enabled);
            }
            let (map_sender, worker) = unbounded();
            balloon.set_map_sender(map_sender).unwrap();

            let frq = VirtQueue::new(GuestAddress(0), mem, 16);
            let queues = (0..super::super::defs::NUM_QUEUES)
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
                worker,
            }
        }

        /// Puts a report of free pages in the queue, as the guest does.
        fn report(&self, ranges: &[(u64, u32)]) {
            for (i, &(addr, len)) in ranges.iter().enumerate() {
                let next = i + 1 < ranges.len();
                let flags = VIRTQ_DESC_F_WRITE | if next { VIRTQ_DESC_F_NEXT } else { 0 };
                self.frq.dtable[i].set(addr, len, flags, i as u16 + 1);
            }
            let idx = self.frq.avail.idx.get();
            self.frq.avail.ring[usize::from(idx) % self.frq.dtable.len()].set(0);
            self.frq.avail.idx.set(idx + 1);
        }

        fn used(&self) -> u16 {
            self.frq.used.idx.get()
        }

        fn signaled(&self) -> bool {
            self.interrupt.status() & VIRTIO_MMIO_INT_VRING as usize != 0
        }

        fn handle_reclaim_done(&mut self) {
            let fd = self.balloon.reclaim.done_fd().unwrap();
            self.balloon
                .handle_reclaim_done_event(&EpollEvent::new(EventSet::IN, fd as u64));
        }
    }

    fn guest_memory() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 16 << 20)]).unwrap()
    }

    #[test]
    fn test_reclaimable() {
        assert!(reclaimable(GuestAddress(0x8000_0000), 2 << 20));
        assert!(reclaimable(GuestAddress(0x8020_0000), 4 << 20));
        assert!(!reclaimable(GuestAddress(0x8000_0000), 0));
        assert!(!reclaimable(GuestAddress(0x8000_0000), 1 << 20));
        assert!(!reclaimable(GuestAddress(0x8000_0000), 3 << 20));
        assert!(!reclaimable(GuestAddress(0x8010_0000), 2 << 20));
    }

    #[test]
    fn test_report_done_after_vmm_replies() {
        let (map_sender, map_receiver) = unbounded();
        let reclaimer = Reclaimer::new(map_sender).unwrap();
        reclaimer
            .reports
            .send(Report {
                head: 7,
                ranges: vec![0x8000_0000..0x8020_0000, 0x8040_0000..0x8080_0000],
            })
            .unwrap();

        for expected in [(0x8000_0000, 2 << 20), (0x8040_0000, 4 << 20)] {
            let WorkerMessage::ReclaimMemory(reply_sender, guest_addr, len) =
                map_receiver.recv().unwrap()
            else {
                panic!("unexpected worker message");
            };
            assert_eq!((guest_addr, len), expected);
            assert_eq!(reclaimer.done.try_recv().unwrap(), None);
            reply_sender.send(true).unwrap();
        }

        let deadline = Instant::now() + TIMEOUT;
        let head = loop {
            if let Some(head) = reclaimer.done.try_recv().unwrap() {
                break head;
            }
            assert!(Instant::now() < deadline, "report not done");
            sleep(Duration::from_millis(1));
        };
        assert_eq!(head, 7);
    }

    #[test]
    fn test_reports_released_right_away_without_reclaim() {
        let mem = guest_memory();
        for reclaim in [None, Some(false)] {
            let mut dev = TestDevice::new(&mem, reclaim);
            dev.report(&[(0x40_0000, 2 << 20)]);
            assert!(dev.balloon.process_frq());
            assert_eq!(dev.used(), 1);
            assert!(dev.worker.try_recv().is_err());
            assert_eq!(dev.balloon.reclaim.done_fd(), None);
        }
    }

    #[test]
    fn test_small_reports_released_right_away() {
        let mem = guest_memory();
        let mut dev = TestDevice::new(&mem, Some(true));
        dev.report(&[(0x40_0000, 1 << 20), (0x80_1000, 2 << 20)]);
        assert!(dev.balloon.process_frq());
        assert_eq!(dev.used(), 1);
        assert!(dev.worker.try_recv().is_err());
    }

    #[test]
    fn test_report_used_once_vmm_reclaimed_it() {
        let mem = guest_memory();
        let mut dev = TestDevice::new(&mem, Some(true));
        // The second range is too small to be reclaimed, and is only madvise()d.
        dev.report(&[(0x40_0000, 2 << 20), (0x80_0000, 0x1000)]);
        assert!(!dev.balloon.process_frq());

        let WorkerMessage::ReclaimMemory(reply_sender, guest_addr, len) =
            dev.worker.recv_timeout(TIMEOUT).unwrap()
        else {
            panic!("unexpected worker message");
        };
        assert_eq!((guest_addr, len), (0x40_0000, 2 << 20));

        // The guest mustn't get the pages back before they are mapped again.
        dev.handle_reclaim_done();
        assert_eq!(dev.used(), 0);
        assert!(!dev.signaled());

        reply_sender.send(true).unwrap();
        let deadline = Instant::now() + TIMEOUT;
        while dev.used() == 0 {
            assert!(Instant::now() < deadline, "report not used");
            sleep(Duration::from_millis(1));
            dev.handle_reclaim_done();
        }
        assert_eq!(dev.used(), 1);
        assert_eq!(dev.frq.used.ring[0].get().id, 0);
        assert!(dev.signaled());
        assert!(dev.worker.try_recv().is_err());
    }
}
