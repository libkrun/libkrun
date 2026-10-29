use std::cmp;
use std::io::Write;
use std::mem::size_of;
use std::ops::Range;
use std::time::{Duration, Instant};

use utils::eventfd::EventFd;
use vm_memory::{ByteValued, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, BalloonError, DeviceQueue, DeviceState, QueueConfig,
    VirtioDevice,
};
use super::{FreePageReclaim, defs, defs::uapi};
use crate::virtio::InterruptTransport;

// Inflate queue.
pub(crate) const IFQ_INDEX: usize = 0;
// Deflate queue.
pub(crate) const DFQ_INDEX: usize = 1;
// Stats queue.
pub(crate) const STQ_INDEX: usize = 2;
// Page-hinting queue.
pub(crate) const PHQ_INDEX: usize = 3;
// Free page reporting queue.
pub(crate) const FRQ_INDEX: usize = 4;

// Supported features.
pub(crate) const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_F_VERSION_1 as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_STATS_VQ as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_FREE_PAGE_HINT as u64)
    | (1 << uapi::VIRTIO_BALLOON_F_REPORTING as u64);

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioBalloonConfig {
    /* Number of pages host wants Guest to give up. */
    num_pages: u32,
    /* Number of pages we've actually got in balloon. */
    actual: u32,
    /* Free page report command id, readonly by guest */
    free_page_report_cmd_id: u32,
    /* Stores PAGE_POISON if page poisoning is in use */
    poison_val: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBalloonConfig {}

/// A range of a free page report that is within a single region of guest memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FreeRange {
    pub(super) guest_addr: GuestAddress,
    /// Where the VMM maps the range.
    pub(super) host_addr: *mut u8,
    pub(super) len: usize,
}

impl FreeRange {
    /// Returns the range of `len` bytes at `guest_addr`, if it's within a single region of
    /// `mem`.
    pub(super) fn new(mem: &GuestMemoryMmap, guest_addr: GuestAddress, len: usize) -> Option<Self> {
        let slice = mem.get_slice(guest_addr, len).ok()?;
        Some(Self {
            guest_addr,
            host_addr: slice.ptr_guard_mut().as_ptr(),
            len,
        })
    }

    pub(super) fn guest_end(&self) -> GuestAddress {
        GuestAddress(self.guest_addr.0 + self.len as u64)
    }
}

/// How often the device logs how much of the free page reports it skipped because they were in
/// locked guest memory, at most.
const LOCKED_SKIPPED_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Splits the `len` bytes at `addr` of a free page report into the parts that aren't in any of
/// the ranges of `locked`, which are sorted and don't overlap, and returns them with the number
/// of bytes that are.
fn trim_locked(locked: &[Range<u64>], addr: u64, len: u64) -> (Vec<(u64, u64)>, u64) {
    // A range that wraps around isn't in guest memory, and process_frq() ignores it.
    let Some(end) = addr.checked_add(len) else {
        return (vec![(addr, len)], 0);
    };
    let mut parts = Vec::new();
    let mut skipped = 0;
    let mut start = addr;
    for range in locked {
        if range.end <= start || range.start >= end {
            continue;
        }
        if range.start > start {
            parts.push((start, range.start - start));
        }
        let skipped_end = range.end.min(end);
        skipped += skipped_end - start.max(range.start);
        start = skipped_end;
    }
    if start < end {
        parts.push((start, end - start));
    }
    (parts, skipped)
}

/// Merges the ranges of a report that are adjacent in the same region of guest memory, so that
/// each run of them is released with a single system call.
pub(super) fn coalesce(mem: &GuestMemoryMmap, mut ranges: Vec<FreeRange>) -> Vec<FreeRange> {
    // Linux fills a report from the free lists of its page allocator, which aren't sorted by
    // address.
    ranges.sort_unstable_by_key(|range| range.guest_addr);
    ranges.dedup_by(|next, prev| {
        if prev.guest_end() != next.guest_addr {
            return false;
        }
        // Two regions can be adjacent in guest memory without being adjacent in the VMM's.
        let Some(merged) = FreeRange::new(mem, prev.guest_addr, prev.len + next.len) else {
            return false;
        };
        *prev = merged;
        true
    });
    ranges
}

pub struct Balloon {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    config: VirtioBalloonConfig,
    pub(super) reclaim: FreePageReclaim,
    /// Guest memory that the VMM locks into host memory, whose free pages aren't given back to
    /// the host.
    locked: Vec<Range<u64>>,
    /// The bytes of free page reports that were skipped because they were in `locked`.
    locked_skipped_bytes: u64,
    /// When the skipped bytes were logged last, and how many there were then.
    locked_skipped_logged: Option<(Instant, u64)>,
}

impl Balloon {
    pub fn new() -> super::Result<Balloon> {
        Ok(Balloon {
            queues: None,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(BalloonError::EventFd)?,
            device_state: DeviceState::Inactive,
            config: VirtioBalloonConfig::default(),
            reclaim: Default::default(),
            locked: Vec::new(),
            locked_skipped_bytes: 0,
            locked_skipped_logged: None,
        })
    }

    pub fn id(&self) -> &str {
        defs::BALLOON_DEV_ID
    }

    /// Set the ranges of guest physical addresses of the guest memory that the VMM locks into
    /// host memory. The device doesn't give the free pages that the guest reports in them back to
    /// the host: madvise() wouldn't release them, or would fail on Linux, and replacing them
    /// would silently unlock them on macOS, where a MAP_FIXED mmap() over locked memory leaves
    /// the new pages unlocked.
    pub fn set_locked_ranges(&mut self, mut ranges: Vec<Range<u64>>) {
        ranges.sort_unstable_by_key(|range| range.start);
        self.locked = ranges;
    }

    /// The bytes of free page reports that the device didn't give back to the host because they
    /// were in locked guest memory.
    pub fn locked_skipped_bytes(&self) -> u64 {
        self.locked_skipped_bytes
    }

    /// Logs the bytes of free page reports that were skipped because they were in locked guest
    /// memory, if that changed, at most every LOCKED_SKIPPED_LOG_INTERVAL.
    fn log_locked_skipped_bytes(&mut self) {
        let skipped = self.locked_skipped_bytes;
        let now = Instant::now();
        let log = match self.locked_skipped_logged {
            None => skipped != 0,
            Some((at, logged)) => {
                skipped != logged && now.duration_since(at) >= LOCKED_SKIPPED_LOG_INTERVAL
            }
        };
        if log {
            info!(
                "balloon: locked_skipped_bytes={skipped}: free page reports in locked guest \
                 memory that weren't given back to the host ({} MiB)",
                skipped >> 20
            );
            self.locked_skipped_logged = Some((now, skipped));
        }
    }

    pub fn process_frq(&mut self) -> bool {
        debug!("balloon: process_frq()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let queues = self
            .queues
            .as_mut()
            .expect("queues should exist when activated");

        // Reports stay in the queue while too many are still being reclaimed.
        if !self.reclaim.can_take_report() {
            return false;
        }

        let mut have_used = false;
        while let Some(head) = queues[FRQ_INDEX].queue.pop(mem) {
            let index = head.index;
            let mut ranges = Vec::new();
            for desc in head.into_iter() {
                // Locked guest memory stays where it is, whichever way the reclaimer would give
                // it back.
                let (parts, skipped) = trim_locked(&self.locked, desc.addr.0, desc.len.into());
                if skipped != 0 {
                    debug!(
                        "balloon: skipping {skipped} bytes in locked guest memory of guest_addr={:?} len={}",
                        desc.addr, desc.len
                    );
                    self.locked_skipped_bytes += skipped;
                }
                for (addr, len) in parts {
                    // The range comes from the guest. Releasing one that runs past the end of
                    // a guest memory region would discard whatever the VMM has mapped after it.
                    let Some(range) = FreeRange::new(mem, GuestAddress(addr), len as usize) else {
                        warn!(
                            "balloon: ignoring free page report outside guest memory: guest_addr={:#x} len={}",
                            addr, len
                        );
                        continue;
                    };
                    debug!(
                        "balloon: should release guest_addr={:?} host_addr={:p} len={}",
                        range.guest_addr, range.host_addr, range.len
                    );
                    ranges.push(range);
                }
            }

            if self.reclaim.release(mem, index, ranges) {
                if !self.reclaim.can_take_report() {
                    break;
                }
                continue;
            }

            have_used = true;
            if let Err(e) = queues[FRQ_INDEX].queue.add_used(mem, index, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        self.log_locked_skipped_bytes();
        have_used
    }
}

impl VirtioDevice for Balloon {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_BALLOON
    }

    fn device_name(&self) -> &str {
        "balloon"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn config_len(&self) -> Option<u32> {
        Some(size_of::<VirtioBalloonConfig>() as u32)
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "balloon: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        self.queues = Some(queues);
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        #[cfg(target_os = "macos")]
        self.reclaim.reset();

        if let Some(queues) = self.queues.take() {
            for queue in queues {
                while queue.event.read().is_ok() {}
            }
        }
        while self.activate_evt.read().is_ok() {}
        self.acked_features = 0;
        self.device_state = DeviceState::Inactive;
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use polly::event_manager::EventManager;
    use utils::eventfd::EFD_NONBLOCK;
    use vm_memory::GuestAddress;

    use super::super::test_util::TestDevice;
    use super::*;
    use crate::virtio::Queue;
    use crate::virtio::device::{InterruptHandler, InterruptType};

    const MIB: u64 = 1 << 20;

    struct TestInterrupt;

    impl InterruptHandler for TestInterrupt {
        fn try_signal(&self, _interrupt: InterruptType) -> Result<(), crate::Error> {
            Ok(())
        }
    }

    fn queue_events() -> Vec<Arc<EventFd>> {
        (0..defs::NUM_QUEUES)
            .map(|_| Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()))
            .collect()
    }

    fn activate(balloon: &mut Balloon, events: &[Arc<EventFd>]) {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 1 << 20)]).unwrap();
        let queues = events
            .iter()
            .zip(&defs::QUEUE_CONFIG)
            .map(|(event, config)| DeviceQueue::new(Queue::new(config.size), event.clone()))
            .collect();
        let interrupt = InterruptTransport::from_handler(Arc::new(TestInterrupt));
        balloon.activate(mem, interrupt, queues).unwrap();
    }

    fn process_event(manager: &mut EventManager) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while manager.run_with_timeout(100).unwrap() == 0 {
            assert!(Instant::now() < deadline, "balloon event was not processed");
        }
    }

    #[test]
    fn test_reset_drains_queue_notifications_and_allows_reactivation() {
        let balloon = Arc::new(Mutex::new(Balloon::new().unwrap()));
        let mut manager = EventManager::new().unwrap();
        manager.add_subscriber(balloon.clone()).unwrap();
        let events = queue_events();
        activate(&mut balloon.lock().unwrap(), &events);
        process_event(&mut manager);

        for event in &events {
            event.write(1).unwrap();
            event.write(1).unwrap();
        }
        assert!(balloon.lock().unwrap().reset());
        assert!(!balloon.lock().unwrap().is_activated());
        assert!(balloon.lock().unwrap().queues.is_none());
        assert_eq!(manager.run_with_timeout(0).unwrap(), 0);

        activate(&mut balloon.lock().unwrap(), &events);
        assert_eq!(manager.run_with_timeout(0).unwrap(), 0);
        events[STQ_INDEX].write(1).unwrap();
        process_event(&mut manager);
        assert_eq!(manager.run_with_timeout(0).unwrap(), 0);
    }

    #[test]
    fn test_reset_before_activation_event_drains_notifications() {
        let balloon = Arc::new(Mutex::new(Balloon::new().unwrap()));
        let mut manager = EventManager::new().unwrap();
        manager.add_subscriber(balloon.clone()).unwrap();
        let events = queue_events();
        activate(&mut balloon.lock().unwrap(), &events);
        events[FRQ_INDEX].write(1).unwrap();
        assert!(balloon.lock().unwrap().reset());
        assert_eq!(manager.run_with_timeout(0).unwrap(), 0);
        assert!(balloon.lock().unwrap().reset());

        activate(&mut balloon.lock().unwrap(), &events);
        process_event(&mut manager);
        assert_eq!(manager.run_with_timeout(0).unwrap(), 0);
        events[STQ_INDEX].write(1).unwrap();
        process_event(&mut manager);
        assert_eq!(manager.run_with_timeout(0).unwrap(), 0);
    }

    #[test]
    fn test_reset_clears_negotiated_features() {
        let mut balloon = Balloon::new().unwrap();
        let version_1 = 1 << uapi::VIRTIO_F_VERSION_1;
        balloon.ack_features_by_page(0, 1 << uapi::VIRTIO_BALLOON_F_REPORTING);
        balloon.ack_features_by_page(1, 1);
        activate(&mut balloon, &queue_events());

        assert!(balloon.reset());
        assert_eq!(balloon.acked_features(), 0);
        balloon.ack_features_by_page(0, 0);
        balloon.ack_features_by_page(1, 1);
        assert_eq!(balloon.acked_features(), version_1);
    }

    #[test]
    fn test_report_is_used_and_signaled() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), (16 * MIB) as usize)]).unwrap();
        let mut dev = TestDevice::new(&mem);
        dev.report(&[(4 * MIB, 2 * MIB as u32)]);
        dev.notify();

        assert_eq!(dev.used(), 1);
        assert_eq!(dev.frq.used.ring[0].get().id, 0);
        assert!(dev.signaled());
        assert_eq!(dev.pending(&mem), 0);
    }

    #[test]
    fn test_report_outside_guest_memory_is_still_used() {
        // A hole of 3 MiB between two regions.
        let mem = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), MIB as usize),
            (GuestAddress(4 * MIB), MIB as usize),
        ])
        .unwrap();
        let mut dev = TestDevice::new(&mem);
        dev.report(&[
            // Past the end of a region, in the hole, from a hole into a region, and way out.
            (MIB - 0x1000, 0x2000),
            (2 * MIB, 0x1000),
            (4 * MIB - 0x1000, 0x2000),
            (u64::MAX - 0x1000, 0x2000),
        ]);
        dev.notify();

        assert_eq!(dev.used(), 1);
        assert!(dev.signaled());
        assert_eq!(dev.pending(&mem), 0);
    }

    fn ranges(mem: &GuestMemoryMmap, ranges: &[(u64, usize)]) -> Vec<FreeRange> {
        ranges
            .iter()
            .map(|&(addr, len)| FreeRange::new(mem, GuestAddress(addr), len).unwrap())
            .collect()
    }

    fn assert_coalesced(reported: &[(u64, usize)], expected: &[(u64, usize)]) {
        // Two regions that are adjacent in guest memory.
        let mem = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), MIB as usize),
            (GuestAddress(MIB), MIB as usize),
        ])
        .unwrap();
        assert_eq!(
            coalesce(&mem, ranges(&mem, reported)),
            ranges(&mem, expected)
        );
    }

    #[test]
    fn test_release_discards_each_run_of_adjacent_ranges_once() {
        // Two regions that are adjacent in guest memory.
        let mem = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), MIB as usize),
            (GuestAddress(MIB), MIB as usize),
        ])
        .unwrap();
        let reported = ranges(
            &mem,
            &[
                (0x4000, 0x1000),
                (MIB, 0x1000),
                (0x1000, 0x1000),
                (0x8000, 0x1000),
                (0x2000, 0x2000),
                (MIB - 0x1000, 0x1000),
            ],
        );

        let mut balloon = Balloon::new().unwrap();
        let mut discarded = Vec::new();
        let in_flight = balloon
            .reclaim
            .release_with(&mem, 0, reported, |range| discarded.push(*range));

        assert!(!in_flight);
        assert_eq!(
            discarded,
            ranges(
                &mem,
                &[
                    (0x1000, 0x4000),
                    (0x8000, 0x1000),
                    (MIB - 0x1000, 0x1000),
                    (MIB, 0x1000)
                ]
            )
        );
    }

    #[test]
    fn test_coalesce_adjacent_ranges() {
        assert_coalesced(
            &[(0x1000, 0x1000), (0x2000, 0x2000), (0x4000, 0x1000)],
            &[(0x1000, 0x4000)],
        );
    }

    #[test]
    fn test_coalesce_unsorted_ranges() {
        assert_coalesced(
            &[(0x4000, 0x1000), (0x1000, 0x1000), (0x2000, 0x2000)],
            &[(0x1000, 0x4000)],
        );
    }

    #[test]
    fn test_coalesce_keeps_ranges_with_gaps_apart() {
        assert_coalesced(
            &[
                (0x1000, 0x1000),
                (0x3000, 0x1000),
                (0x5000, 0x1000),
                (0x6000, 0x1000),
            ],
            &[(0x1000, 0x1000), (0x3000, 0x1000), (0x5000, 0x2000)],
        );
    }

    #[test]
    fn test_coalesce_keeps_overlapping_ranges_apart() {
        // Adding up their lengths would release memory that the guest didn't report.
        assert_coalesced(
            &[(0x1000, 0x2000), (0x2000, 0x2000), (0x2000, 0x2000)],
            &[(0x1000, 0x2000), (0x2000, 0x2000), (0x2000, 0x2000)],
        );
    }

    #[test]
    fn test_coalesce_keeps_regions_apart() {
        assert_coalesced(
            &[
                (MIB - 0x2000, 0x1000),
                (MIB - 0x1000, 0x1000),
                (MIB, 0x1000),
                (MIB + 0x1000, 0x1000),
            ],
            &[(MIB - 0x2000, 0x2000), (MIB, 0x2000)],
        );
    }

    #[test]
    fn test_coalesce_empty_report() {
        assert_coalesced(&[], &[]);
    }

    #[test]
    fn test_coalesce_single_range() {
        assert_coalesced(&[(0x1000, 0x1000)], &[(0x1000, 0x1000)]);
    }

    #[test]
    fn test_trim_locked() {
        let locked = [0x10_0000..0x20_0000, 0x40_0000..0x50_0000];
        let trim = |addr, len| trim_locked(&locked, addr, len);
        // Outside, and right next to a locked range on either side.
        assert_eq!(trim(0x2000, 0x1000), (vec![(0x2000, 0x1000)], 0));
        assert_eq!(trim(0xf_f000, 0x1000), (vec![(0xf_f000, 0x1000)], 0));
        assert_eq!(trim(0x20_0000, 0x1000), (vec![(0x20_0000, 0x1000)], 0));
        // Inside.
        assert_eq!(trim(0x10_0000, 0x10_0000), (vec![], 0x10_0000));
        assert_eq!(trim(0x18_0000, 0x1000), (vec![], 0x1000));
        // Across the start or the end of a locked range.
        assert_eq!(
            trim(0xf_0000, 0x2_0000),
            (vec![(0xf_0000, 0x1_0000)], 0x1_0000)
        );
        assert_eq!(
            trim(0x1f_0000, 0x2_0000),
            (vec![(0x20_0000, 0x1_0000)], 0x1_0000)
        );
        // Around a locked range, and across both.
        assert_eq!(
            trim(0xf_0000, 0x12_0000),
            (vec![(0xf_0000, 0x1_0000), (0x20_0000, 0x1_0000)], 0x10_0000)
        );
        assert_eq!(
            trim(0x1f_0000, 0x32_0000),
            (
                vec![(0x20_0000, 0x20_0000), (0x50_0000, 0x1_0000)],
                0x11_0000
            )
        );
        // Without locked memory, and wrapping around, a range is left as it is.
        assert_eq!(
            trim_locked(&[], 0x10_0000, 0x1000),
            (vec![(0x10_0000, 0x1000)], 0)
        );
        assert_eq!(
            trim(u64::MAX - 0x1000, 0x2000),
            (vec![(u64::MAX - 0x1000, 0x2000)], 0)
        );
    }

    /// RAM, with the free page reporting queue at its start, and locked guest memory in a region
    /// of its own, as in the VMM's layout.
    fn guest_memory_with_locked() -> (GuestMemoryMmap, Range<u64>) {
        let locked = 32 * MIB..36 * MIB;
        let mem = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), (16 * MIB) as usize),
            (
                GuestAddress(locked.start),
                (locked.end - locked.start) as usize,
            ),
        ])
        .unwrap();
        (mem, locked)
    }

    #[test]
    fn test_report_in_locked_memory_is_used_and_counted() {
        let (mem, locked) = guest_memory_with_locked();
        let mut dev = TestDevice::new(&mem);
        dev.balloon.set_locked_ranges(vec![locked.clone()]);
        dev.report(&[(locked.start, 2 * MIB as u32), (4 * MIB, 2 * MIB as u32)]);
        dev.notify();

        assert_eq!(dev.used(), 1);
        assert!(dev.signaled());
        assert_eq!(dev.pending(&mem), 0);
        assert_eq!(dev.balloon.locked_skipped_bytes(), 2 * MIB);

        // Only what is in locked memory counts.
        dev.report(&[(locked.end - MIB, 2 * MIB as u32)]);
        dev.notify();
        assert_eq!(dev.used(), 2);
        assert_eq!(dev.balloon.locked_skipped_bytes(), 3 * MIB);
    }

    #[test]
    fn test_locked_skipped_bytes_are_logged_when_they_change() {
        let (mem, locked) = guest_memory_with_locked();
        let mut dev = TestDevice::new(&mem);
        dev.balloon.set_locked_ranges(vec![locked.clone()]);
        dev.notify();
        assert_eq!(dev.balloon.locked_skipped_logged, None);

        dev.report(&[(locked.start, 2 * MIB as u32)]);
        dev.notify();
        let (at, logged) = dev.balloon.locked_skipped_logged.unwrap();
        assert_eq!(logged, 2 * MIB);

        // Not again before LOCKED_SKIPPED_LOG_INTERVAL.
        dev.report(&[(locked.start, 2 * MIB as u32)]);
        dev.notify();
        assert_eq!(dev.balloon.locked_skipped_logged, Some((at, 2 * MIB)));
        assert_eq!(dev.balloon.locked_skipped_bytes(), 4 * MIB);

        let earlier = at - LOCKED_SKIPPED_LOG_INTERVAL;
        dev.balloon.locked_skipped_logged = Some((earlier, 2 * MIB));
        dev.notify();
        let (at, logged) = dev.balloon.locked_skipped_logged.unwrap();
        assert!(at > earlier);
        assert_eq!(logged, 4 * MIB);
    }
}
