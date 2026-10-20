use std::ops::Range;
use std::os::fd::{AsRawFd, RawFd};
use std::thread;

use crossbeam_channel::{unbounded, Receiver, Sender};
use utils::epoll::{EpollEvent, EventSet};
use utils::pollable_channel::{pollable_channel, PollableChannelReciever, PollableChannelSender};
use utils::worker_message::WorkerMessage;
use vm_memory::GuestAddress;

use super::defs::QUEUE_SIZE;
use super::device::{Balloon, FreeRange, FRQ_INDEX};
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
    fn reclaims(&self, range: &FreeRange) -> bool {
        self.reclaimer.is_some() && reclaimable(range.guest_addr, range.len)
    }

    /// Whether another report can be taken from the queue.
    pub(super) fn can_take_report(&self) -> bool {
        self.reclaimer
            .as_ref()
            .is_none_or(|reclaimer| reclaimer.in_flight < MAX_IN_FLIGHT)
    }

    /// Gives the pages of the report `head` back to the host. Returns true if some of them are
    /// still being reclaimed, in which case the report mustn't be used until
    /// [`FreePageReclaim::take_done`] returns it.
    pub(super) fn release(&mut self, head: u16, ranges: Vec<FreeRange>) -> bool {
        let mut reclaim_ranges = Vec::new();
        for range in ranges {
            if self.reclaims(&range) {
                reclaim_ranges.push(range.guest_addr.0..range.guest_addr.0 + range.len as u64);
                continue;
            }
            // SAFETY: the range is guest memory, whose contents the guest has given up.
            unsafe { libc::madvise(range.host_addr.cast(), range.len, libc::MADV_FREE) };
        }
        self.submit(head, reclaim_ranges)
    }

    /// Has the VMM reclaim the ranges of the report `head`. Returns false if there are none, in
    /// which case the report can be completed right away.
    fn submit(&mut self, head: u16, ranges: Vec<Range<u64>>) -> bool {
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
            if map_sender
                .send(WorkerMessage::ReclaimMemory(
                    reply_sender,
                    range.start,
                    range.end - range.start,
                ))
                .is_err()
            {
                return;
            }
            // Pages that the VMM couldn't replace are left as they were, which only costs memory.
            if reply.recv().is_err() {
                return;
            }
        }
        done.send(report.head).unwrap();
    }
}

fn reclaimable(addr: GuestAddress, len: usize) -> bool {
    let len = len as u64;
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
    use std::ops::{Deref, DerefMut};
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    use vm_memory::{Bytes, GuestMemoryMmap};

    use super::super::test_util;
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

    struct TestDevice<'a> {
        dev: test_util::TestDevice<'a>,
        worker: Receiver<WorkerMessage>,
    }

    impl<'a> Deref for TestDevice<'a> {
        type Target = test_util::TestDevice<'a>;

        fn deref(&self) -> &Self::Target {
            &self.dev
        }
    }

    impl DerefMut for TestDevice<'_> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.dev
        }
    }

    impl<'a> TestDevice<'a> {
        /// Attaches and activates a balloon, calling set_free_page_reporting_mode() unless `mode`
        /// is None.
        fn new(mem: &'a GuestMemoryMmap, mode: Option<FreePageReportingMode>) -> Self {
            let mut dev = test_util::TestDevice::new(mem);
            if let Some(mode) = mode {
                dev.balloon.set_free_page_reporting_mode(mode);
            }
            let (map_sender, worker) = unbounded();
            dev.balloon.set_map_sender(map_sender).unwrap();
            Self { dev, worker }
        }

        fn in_flight(&self) -> usize {
            self.balloon.reclaim.reclaimer.as_ref().unwrap().in_flight
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
    fn test_reclaim_stops_when_vmm_channel_is_closed() {
        let (reports, report_receiver) = unbounded();
        reports
            .send(Report {
                head: 7,
                ranges: vec![0x8000_0000..0x8020_0000, 0x8040_0000..0x8080_0000],
            })
            .unwrap();
        drop(reports);

        let (map_sender, map_receiver) = unbounded();
        drop(map_receiver);
        let (done_sender, done) = pollable_channel().unwrap();

        reclaim(report_receiver, map_sender, done_sender);

        assert_eq!(done.try_recv().unwrap(), None);
    }

    #[test]
    fn test_reclaim_stops_when_vmm_drops_reply() {
        let (reports, report_receiver) = unbounded();
        reports
            .send(Report {
                head: 7,
                ranges: vec![0x8000_0000..0x8020_0000, 0x8040_0000..0x8080_0000],
            })
            .unwrap();
        drop(reports);

        let (map_sender, map_receiver) = unbounded();
        let (done_sender, done) = pollable_channel().unwrap();
        let worker = thread::spawn(move || {
            let message = map_receiver.recv_timeout(TIMEOUT).unwrap();
            assert!(matches!(message, WorkerMessage::ReclaimMemory(..)));
        });

        reclaim(report_receiver, map_sender, done_sender);
        worker.join().unwrap();

        assert_eq!(done.try_recv().unwrap(), None);
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

    /// What the kernel says about the pages of a range that is mapped into this process.
    mod page_query {
        use std::os::raw::c_int;

        const VM_PAGE_QUERY_PAGE_DIRTY: c_int = 0x8;
        const VM_PAGE_QUERY_PAGE_REUSABLE: c_int = 0x800;

        unsafe extern "C" {
            fn mach_task_self() -> libc::mach_port_t;
            fn mach_vm_page_range_query(
                target: libc::mach_port_t,
                address: u64,
                size: u64,
                dispositions: *mut c_int,
                dispositions_count: *mut u64,
            ) -> c_int;
        }

        /// Whether each page of the range is still marked as modified, and whether it's marked
        /// as reusable.
        pub fn pages(addr: *const u8, len: usize) -> Vec<(bool, bool)> {
            // SAFETY: sysconf() has no preconditions.
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
            let mut dispositions = vec![0; len / page_size];
            let mut count = dispositions.len() as u64;
            // SAFETY: the buffer has room for the `count` dispositions of the range.
            let ret = unsafe {
                mach_vm_page_range_query(
                    mach_task_self(),
                    addr as u64,
                    len as u64,
                    dispositions.as_mut_ptr(),
                    &mut count,
                )
            };
            assert_eq!(ret, 0);
            assert_eq!(count as usize, dispositions.len());
            dispositions
                .iter()
                .map(|d| {
                    (
                        d & VM_PAGE_QUERY_PAGE_DIRTY != 0,
                        d & VM_PAGE_QUERY_PAGE_REUSABLE != 0,
                    )
                })
                .collect()
        }
    }

    #[test]
    fn test_default_mode_marks_reported_pages_as_free() {
        // A multiple of the page size of every host.
        const PAGE: usize = 64 << 10;
        const FIRST: usize = 1 << 20;
        const PAGES: usize = 32;
        let mem = guest_memory();
        mem.write_slice(&vec![0xff; PAGES * PAGE], GuestAddress(FIRST as u64))
            .unwrap();
        let host_addr = FreeRange::new(&mem, GuestAddress(FIRST as u64), PAGES * PAGE)
            .unwrap()
            .host_addr;

        let mut dev = TestDevice::new(&mem, None);
        // (first page, pages)
        let released = [(1, 1), (4, 3), (20, 1)];
        let report: Vec<_> = released
            .iter()
            .map(|&(page, pages)| ((FIRST + page * PAGE) as u64, (pages * PAGE) as u32))
            .collect();
        dev.report(&report);
        assert!(dev.balloon.process_frq());

        // MADV_FREE clears the modified state of the pages without marking them as reusable,
        // which MADV_FREE_REUSABLE does. MADV_DONTNEED doesn't touch it.
        let pages = page_query::pages(host_addr, PAGES * PAGE);
        for (block, pages) in pages.chunks(pages.len() / PAGES).enumerate() {
            let is_released = released
                .iter()
                .any(|&(first, blocks)| (first..first + blocks).contains(&block));
            for &(modified, reusable) in pages {
                assert_eq!((modified, reusable), (!is_released, false), "page {block}");
            }
        }
    }

    #[test]
    fn test_ranges_outside_guest_memory_are_not_reclaimed() {
        let mem = guest_memory();
        let mut dev = TestDevice::new(&mem, Some(FreePageReportingMode::Replace));
        // The second range is aligned, and runs past the end of the guest memory.
        dev.report(&[(0x40_0000, 2 << 20), (14 << 20, 4 << 20)]);
        assert!(!dev.balloon.process_frq());

        let WorkerMessage::ReclaimMemory(reply_sender, guest_addr, len) =
            dev.worker.recv_timeout(TIMEOUT).unwrap()
        else {
            panic!("unexpected worker message");
        };
        assert_eq!((guest_addr, len), (0x40_0000, 2 << 20));
        reply_sender.send(true).unwrap();

        let deadline = Instant::now() + TIMEOUT;
        while dev.used() == 0 {
            assert!(Instant::now() < deadline, "report not used");
            sleep(Duration::from_millis(1));
            dev.handle_reclaim_done();
        }
        assert!(dev.worker.try_recv().is_err());
    }
}
