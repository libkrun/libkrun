use std::ops::Range;
use std::os::fd::{AsRawFd, RawFd};
use std::thread;

use crossbeam_channel::{unbounded, Receiver, Sender};
use utils::epoll::{EpollEvent, EventSet};
use utils::pollable_channel::{pollable_channel, PollableChannelReciever, PollableChannelSender};
use utils::worker_message::WorkerMessage;
use vm_memory::GuestAddress;

use super::defs::QUEUE_SIZE;
use super::device::{Balloon, FRQ_INDEX};
use super::{BalloonError, FreePageReportingMode, Result};
use crate::virtio::DeviceState;

/// Smaller or unaligned reports are only madvise()d, so that the guest can't make the VMM split
/// the stage-2 mapping of its RAM into small pieces. Linux reports 2 MiB blocks by default.
const RECLAIM_ALIGN: u64 = 2 << 20;

/// The most reports that the device takes from the queue while earlier ones are still being
/// reclaimed; the others stay in the queue until some are done, so the guest can't make the host
/// hold an arbitrary number of them. A report keeps its descriptors until it's used, so a guest
/// that follows the virtio spec never has more of them in flight than the size of the queue.
/// Only a broken or malicious guest could exceed that, by making a head available again while
/// it's still in flight; such a report is counted like any other, and completing it twice only
/// confuses that guest.
const MAX_IN_FLIGHT: usize = QUEUE_SIZE as usize;

/// Has the VMM replace the pages of free page reports, which gives them back to the host.
///
/// A thread waits for the VMM worker, which may be busy, and a report is added to the used ring
/// only once its pages are mapped into the guest again. The guest doesn't touch reported pages
/// before that, so it never finds them unmapped.
#[derive(Default)]
pub(super) struct FreePageReclaim {
    mode: FreePageReportingMode,
    reclaimer: Option<Reclaimer>,
}

struct Reclaimer {
    reports: Sender<Report>,
    done: PollableChannelReciever<u16>,
    /// Reports sent to the thread that aren't done yet.
    in_flight: usize,
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

    /// Whether another report can be taken from the queue.
    pub(super) fn can_take_report(&self) -> bool {
        self.reclaimer
            .as_ref()
            .is_none_or(|reclaimer| reclaimer.in_flight < MAX_IN_FLIGHT)
    }

    /// Has the VMM reclaim the ranges of the report `head`. Returns false if there are none, in
    /// which case the report can be completed right away.
    pub(super) fn submit(&mut self, head: u16, ranges: Vec<Range<u64>>) -> bool {
        match &mut self.reclaimer {
            Some(reclaimer) if !ranges.is_empty() => {
                reclaimer.reports.send(Report { head, ranges }).unwrap();
                reclaimer.in_flight += 1;
                true
            }
            _ => false,
        }
    }

    /// Returns the head of a report whose ranges have been reclaimed, if there is one.
    fn take_done(&mut self) -> Option<u16> {
        let reclaimer = self.reclaimer.as_mut()?;
        let head = reclaimer.done.try_recv().ok().flatten()?;
        reclaimer.in_flight -= 1;
        Some(head)
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
        Ok(Self {
            reports,
            done,
            in_flight: 0,
        })
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
    /// Set how the pages of free page reports are given back to the host. Must be called before
    /// [`Balloon::set_map_sender`].
    pub fn set_free_page_reporting_mode(&mut self, mode: FreePageReportingMode) {
        self.reclaim.mode = mode;
    }

    /// Set the channel to the VMM worker, and start reclaiming reported pages through it in
    /// [`FreePageReportingMode::Replace`].
    pub fn set_map_sender(&mut self, map_sender: Sender<WorkerMessage>) -> Result<()> {
        if self.reclaim.mode == FreePageReportingMode::Replace {
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
        let mut have_used = false;
        while let Some(head) = self.reclaim.take_done() {
            have_used = true;
            if let Err(e) = queue.add_used(mem, head, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }
        // Reports may have been left in the queue while too many were in flight, and the guest
        // won't notify the device about them again.
        have_used |= self.process_frq();
        if have_used {
            self.device_state.signal_used_queue();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    use utils::eventfd::{EventFd, EFD_NONBLOCK};
    use vm_memory::GuestMemoryMmap;

    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::virtio::{
        DeviceQueue, InterruptTransport, Queue, VirtioDevice, VIRTIO_MMIO_INT_VRING,
    };

    const TIMEOUT: Duration = Duration::from_secs(5);

    struct TestDevice<'a> {
        balloon: Balloon,
        frq: VirtQueue<'a>,
        interrupt: InterruptTransport,
        worker: Receiver<WorkerMessage>,
    }

    impl<'a> TestDevice<'a> {
        /// Attaches and activates a balloon, calling set_free_page_reporting_mode() unless `mode`
        /// is None.
        fn new(mem: &'a GuestMemoryMmap, mode: Option<FreePageReportingMode>) -> Self {
            let mut balloon = Balloon::new().unwrap();
            if let Some(mode) = mode {
                balloon.set_free_page_reporting_mode(mode);
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

        /// The number of reports that the guest made available and the device didn't take yet.
        fn pending(&self, mem: &GuestMemoryMmap) -> u16 {
            self.balloon.queues.as_ref().unwrap()[FRQ_INDEX]
                .queue
                .len(mem)
        }

        fn in_flight(&self) -> usize {
            self.balloon.reclaim.reclaimer.as_ref().unwrap().in_flight
        }

        fn signaled(&self) -> bool {
            self.interrupt.status().load(Ordering::SeqCst) & VIRTIO_MMIO_INT_VRING as usize != 0
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
    fn test_reports_released_right_away_in_default_mode() {
        let mem = guest_memory();
        for mode in [None, Some(FreePageReportingMode::Default)] {
            let mut dev = TestDevice::new(&mem, mode);
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
        let mut dev = TestDevice::new(&mem, Some(FreePageReportingMode::Replace));
        dev.report(&[(0x40_0000, 1 << 20), (0x80_1000, 2 << 20)]);
        assert!(dev.balloon.process_frq());
        assert_eq!(dev.used(), 1);
        assert!(dev.worker.try_recv().is_err());
    }

    #[test]
    fn test_report_used_once_vmm_reclaimed_it() {
        let mem = guest_memory();
        let mut dev = TestDevice::new(&mem, Some(FreePageReportingMode::Replace));
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
        assert_eq!(dev.in_flight(), 0);
    }

    #[test]
    fn test_reports_in_flight_are_limited() {
        let mem = guest_memory();
        let mut dev = TestDevice::new(&mem, Some(FreePageReportingMode::Replace));
        // The guest makes the same head available again and again, without waiting for the
        // device to use it.
        let reports = MAX_IN_FLIGHT + 40;
        for _ in 0..reports {
            dev.report(&[(0x40_0000, 2 << 20)]);
        }

        assert!(!dev.balloon.process_frq());
        assert_eq!(dev.in_flight(), MAX_IN_FLIGHT);
        assert_eq!(usize::from(dev.pending(&mem)), reports - MAX_IN_FLIGHT);
        let reclaimer = dev.balloon.reclaim.reclaimer.as_ref().unwrap();
        assert!(reclaimer.reports.len() <= MAX_IN_FLIGHT);

        // Notifying the device again doesn't make it take more.
        assert!(!dev.balloon.process_frq());
        assert_eq!(dev.in_flight(), MAX_IN_FLIGHT);
        assert_eq!(usize::from(dev.pending(&mem)), reports - MAX_IN_FLIGHT);

        // Reports left in the queue are taken once earlier ones are done.
        for _ in 0..reports {
            let WorkerMessage::ReclaimMemory(reply_sender, _, _) =
                dev.worker.recv_timeout(TIMEOUT).unwrap()
            else {
                panic!("unexpected worker message");
            };
            reply_sender.send(true).unwrap();
            dev.handle_reclaim_done();
            assert!(dev.in_flight() <= MAX_IN_FLIGHT);
        }
        let deadline = Instant::now() + TIMEOUT;
        while usize::from(dev.used()) < reports {
            assert!(Instant::now() < deadline, "reports not used");
            sleep(Duration::from_millis(1));
            dev.handle_reclaim_done();
        }
        assert_eq!(dev.pending(&mem), 0);
        assert_eq!(dev.in_flight(), 0);
        assert!(dev.worker.try_recv().is_err());
        assert!(dev.signaled());
    }
}
