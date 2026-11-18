use std::cmp;
// TryInto is in the 2021 prelude; the explicit import is only needed on Unix.
#[cfg(not(target_os = "windows"))]
use std::convert::TryInto;
use std::io::Write;

use utils::eventfd::EventFd;
use vm_memory::{Address, ByteValued, Bytes, GuestMemory, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, BalloonError, DeviceQueue, DeviceState, Queue, QueueConfig,
    VirtioDevice,
};
use super::{BalloonStats, defs, defs::uapi};
use crate::virtio::InterruptTransport;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::DiscardVirtualMemory;

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
    | (1 << uapi::VIRTIO_BALLOON_F_DEFLATE_ON_OOM as u64)
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

/// Runtime state captured for checkpoint/fork (see `save_state`).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BalloonState {
    pub acked_features: u64,
    pub num_pages: u32,
    pub actual: u32,
    pub queues: Vec<Option<crate::virtio::queue::QueueState>>,
    /// Id of the last free page hinting round. The guest remembers the last
    /// round it ran and ignores a request carrying that id again, so a
    /// restored device must not start counting over. Absent in states saved
    /// before it was recorded.
    #[serde(default)]
    pub free_page_hint_cmd_id: u32,
}

pub struct Balloon {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    config: VirtioBalloonConfig,
    snapshot_quiesced: bool,
    deferred_events: u8,
    deferred_stats_request: bool,
    deferred_target_pages: Option<u32>,
    /// Most recent sample the guest published on the stats queue.
    stats: Option<BalloonStats>,
    /// The guest parks one buffer on the stats queue and only refills it after
    /// the host acks. Holding the index here means a sample is requested when
    /// someone actually reads the stats, rather than in a loop with the guest.
    stats_pending_ack: Option<u16>,
    /// When the parked buffer was last acked, so refreshes stay rate-limited.
    stats_last_request: Option<std::time::Instant>,
    /// When the host last asked for (or released) a balloon target. Free-page
    /// reports right after a reclaim pulse are handed back even where they
    /// would otherwise stay resident (see `release_reported_pages`).
    last_reclaim: Option<std::time::Instant>,
    /// Free page hinting round in progress, see `start_free_page_hint`.
    hint: FreePageHint,
}

/// One free page hinting round. The guest driver allocates every free block it
/// can (4 MiB each on x86), hands them over on the hinting queue and holds them
/// until the device writes `CMD_ID_DONE`. While it holds them nothing in the
/// guest can write to them, so the host discards each block on receipt: the
/// memory reads back as zeros and is no longer resident on the host.
#[derive(Debug, Default)]
struct FreePageHint {
    /// Id of the round the device asked for; 0 when none was ever started.
    cmd_id: u32,
    /// The guest acknowledged `cmd_id` on the queue.
    started: bool,
    /// The guest sent `CMD_ID_STOP`: it has handed over all it could.
    finished: bool,
    /// Bytes discarded in this round.
    bytes: u64,
}

/// The id for the next hinting round: never `CMD_ID_STOP` or `CMD_ID_DONE`,
/// which the guest reads as commands rather than as a new round.
fn next_hint_cmd_id(previous: u32) -> u32 {
    match previous.wrapping_add(1) {
        id if id <= uapi::VIRTIO_BALLOON_CMD_ID_DONE => uapi::VIRTIO_BALLOON_CMD_ID_DONE + 1,
        id => id,
    }
}

/// Progress of the current free page hinting round.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FreePageHintProgress {
    pub finished: bool,
    pub bytes: u64,
}

/// A stats entry is a packed le16 tag followed by a le64 value. `repr(C)` would
/// pad that to 16 bytes, so the fields are read individually.
const STAT_ENTRY_LEN: usize = 10;
/// Upper bound on a stats sample read from the guest: Linux sends one entry
/// per known tag (VIRTIO_BALLOON_S_NR, 16 today), i.e. 160 bytes.
const MAX_STATS_LEN: usize = 4096;

/// Decode the guest's stats buffer. Returns `None` if it holds no complete
/// entry; a trailing partial entry is ignored rather than rejecting the sample.
fn parse_stats_buffer(buf: &[u8]) -> Option<BalloonStats> {
    let mut stats = BalloonStats::default();
    let mut saw_entry = false;

    let (entries, _partial) = buf.as_chunks::<STAT_ENTRY_LEN>();
    for entry in entries {
        let tag = u16::from_le_bytes([entry[0], entry[1]]);
        let value = u64::from_le_bytes(entry[2..STAT_ENTRY_LEN].try_into().unwrap());
        match tag {
            uapi::VIRTIO_BALLOON_S_SWAP_IN => stats.swap_in = value,
            uapi::VIRTIO_BALLOON_S_SWAP_OUT => stats.swap_out = value,
            uapi::VIRTIO_BALLOON_S_MAJFLT => stats.major_faults = value,
            uapi::VIRTIO_BALLOON_S_MINFLT => stats.minor_faults = value,
            uapi::VIRTIO_BALLOON_S_MEMFREE => stats.mem_free = value,
            uapi::VIRTIO_BALLOON_S_MEMTOT => stats.mem_total = value,
            uapi::VIRTIO_BALLOON_S_AVAIL => stats.mem_available = value,
            uapi::VIRTIO_BALLOON_S_CACHES => stats.caches = value,
            // Unknown tags are skipped rather than treated as an error: the set
            // grows with kernel versions, and a newer guest must not invalidate
            // the fields this build does understand.
            _ => {}
        }
        saw_entry = true;
    }

    saw_entry.then_some(stats)
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
            snapshot_quiesced: false,
            deferred_events: 0,
            deferred_stats_request: false,
            deferred_target_pages: None,
            stats: None,
            stats_pending_ack: None,
            stats_last_request: None,
            last_reclaim: None,
            hint: FreePageHint::default(),
        })
    }

    pub fn id(&self) -> &str {
        defs::BALLOON_DEV_ID
    }

    /// Capture runtime state for checkpoint/fork. Both vCPUs and device event
    /// handling must be quiesced so the queues remain at a clean boundary.
    pub fn save_state(&self) -> BalloonState {
        BalloonState {
            acked_features: self.acked_features,
            num_pages: self.config.num_pages,
            actual: self.config.actual,
            queues: match self.queues.as_ref() {
                Some(qs) => qs.iter().map(|q| Some(q.queue.save_state())).collect(),
                None => vec![None; defs::NUM_QUEUES],
            },
            free_page_hint_cmd_id: self.hint.cmd_id,
        }
    }

    /// Restore configuration and any live, quiesced queues. A fresh device
    /// receives its queues later through `restore_and_activate`.
    pub fn restore_state(&mut self, state: &BalloonState) -> Result<(), String> {
        if self.is_activated() && !self.snapshot_quiesced {
            return Err("balloon must be quiesced before restoring live queues".into());
        }
        if let Some(queues) = &mut self.queues {
            if state.queues.len() != queues.len() {
                return Err("balloon checkpoint queue count does not match the device".into());
            }
            // Validate every queue before changing any of the live state.
            let restored = queues
                .iter()
                .zip(&state.queues)
                .map(|(live, saved)| {
                    let saved = saved
                        .as_ref()
                        .ok_or("balloon checkpoint is missing a live queue")?;
                    let mut queue = Queue::new(live.queue.max_size);
                    queue.restore_state(saved)?;
                    if let DeviceState::Activated(mem, _) = &self.device_state
                        && queue.ready
                        && (!queue.is_valid(mem) || queue.len(mem) > queue.actual_size())
                    {
                        return Err(
                            "balloon checkpoint queue does not match restored memory".into()
                        );
                    }
                    Ok(queue)
                })
                .collect::<Result<Vec<_>, String>>()?;
            for (live, restored) in queues.iter_mut().zip(restored) {
                live.queue = restored;
            }
        }
        self.acked_features = state.acked_features;
        self.config.num_pages = state.num_pages;
        self.config.actual = state.actual;
        // Continue after the guest's last hinting round. A state that did not
        // record it may still come from a guest that ran one: starting over
        // would reissue that id, which the guest ignores, and every hint would
        // wait out its timeout having discarded nothing. Start anywhere else.
        self.hint = FreePageHint {
            cmd_id: match state.free_page_hint_cmd_id {
                0 => rand::random(),
                id => id,
            },
            ..FreePageHint::default()
        };
        self.stats = None;
        self.stats_pending_ack = None;
        self.stats_last_request = None;
        self.last_reclaim = None;
        self.deferred_target_pages = None;
        self.deferred_stats_request = false;
        self.deferred_events = 0;
        self.config.free_page_report_cmd_id = uapi::VIRTIO_BALLOON_CMD_ID_DONE;
        if self.is_activated() {
            // Saved available reports need service even if their original
            // eventfd notification was consumed on the discarded timeline.
            self.deferred_events = (1 << defs::NUM_QUEUES) - 1;
            if self.acked_features & (1 << uapi::VIRTIO_BALLOON_F_FREE_PAGE_HINT) != 0 {
                self.finish_free_page_hint();
            }
        }
        Ok(())
    }

    /// Host-side target: ask the guest to inflate the balloon to `pages`
    /// 4 KiB pages (0 fully deflates). Takes effect via a config-change
    /// interrupt; the guest driver in/deflates toward the target and updates
    /// `actual` in config space as it goes.
    pub fn set_target_pages(&mut self, pages: u32) {
        if self.snapshot_quiesced {
            self.deferred_target_pages = Some(pages);
            return;
        }
        if pages > 0 || self.config.num_pages > 0 {
            self.last_reclaim = Some(std::time::Instant::now());
        }
        self.config.num_pages = pages;
        if let DeviceState::Activated(_, ref interrupt) = self.device_state {
            interrupt.signal_config_change();
        }
    }

    /// (target, actual) balloon size in 4 KiB pages, as last written by the
    /// host and guest respectively.
    pub fn pages(&self) -> (u32, u32) {
        (self.config.num_pages, self.config.actual)
    }

    /// Ask the guest to hand over its free memory so the host can discard it.
    ///
    /// Freed guest memory keeps whatever it last held, so without this a
    /// checkpoint hashes, compresses and ships it. Free page reporting misses
    /// most of it: it only covers free blocks of 2 MiB or more and runs on the
    /// guest's own schedule. Poll `free_page_hint_progress`, then call
    /// `finish_free_page_hint` to let the guest reuse the blocks.
    pub fn start_free_page_hint(&mut self) -> Result<u32, &'static str> {
        if self.acked_features & (1 << uapi::VIRTIO_BALLOON_F_FREE_PAGE_HINT) == 0 {
            return Err("the guest did not negotiate free page hinting");
        }
        if self.snapshot_quiesced {
            return Err("the device is quiesced for a snapshot");
        }
        let DeviceState::Activated(_, ref interrupt) = self.device_state else {
            return Err("the device is not active");
        };
        let cmd_id = next_hint_cmd_id(self.hint.cmd_id);
        self.hint = FreePageHint {
            cmd_id,
            ..FreePageHint::default()
        };
        self.config.free_page_report_cmd_id = cmd_id;
        interrupt.signal_config_change();
        Ok(cmd_id)
    }

    pub fn free_page_hint_progress(&self) -> FreePageHintProgress {
        FreePageHintProgress {
            finished: self.hint.finished,
            bytes: self.hint.bytes,
        }
    }

    /// Let the guest free the blocks it is holding for the current round.
    pub fn finish_free_page_hint(&mut self) {
        self.config.free_page_report_cmd_id = uapi::VIRTIO_BALLOON_CMD_ID_DONE;
        if let DeviceState::Activated(_, ref interrupt) = self.device_state {
            interrupt.signal_config_change();
        }
    }

    /// Hinting queue: an out buffer carries a command id (the round's id when
    /// the guest starts, `CMD_ID_STOP` when it is done); an in buffer is one
    /// free block the guest now holds, which the host discards.
    pub(crate) fn process_phq(&mut self) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            DeviceState::Inactive => return false,
        };
        let queues = self
            .queues
            .as_mut()
            .expect("queues should exist when activated");
        let mut have_used = false;

        while let Some(head) = queues[PHQ_INDEX].queue.pop(mem) {
            let index = head.index;
            for desc in head.into_iter() {
                if desc.is_write_only() {
                    // Only discard blocks for the round the host asked for; a
                    // stale round's blocks are acked and left alone.
                    if self.hint.started && !self.hint.finished {
                        clear_hinted_range(mem, desc.addr.0, desc.len as u64);
                        self.hint.bytes += desc.len as u64;
                    }
                } else if desc.len >= 4 {
                    match mem.read_obj::<u32>(desc.addr) {
                        Ok(id) if id == self.hint.cmd_id && self.hint.cmd_id != 0 => {
                            self.hint.started = true;
                        }
                        Ok(uapi::VIRTIO_BALLOON_CMD_ID_STOP) if self.hint.started => {
                            self.hint.finished = true;
                        }
                        Ok(_) => {}
                        Err(e) => error!("balloon: unreadable hint command id: {e:?}"),
                    }
                }
            }
            have_used = true;
            if let Err(e) = queues[PHQ_INDEX].queue.add_used(mem, index, 0) {
                error!("failed to add used elements to the hinting queue: {e:?}");
            }
        }
        have_used
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
        let mut have_used = false;

        // Reclaim can require expensive host mapping changes. Complete one
        // report before yielding to the reactor so socket and control events
        // are not held behind the entire free-memory backlog.
        if let Some(head) = queues[FRQ_INDEX].queue.pop(mem) {
            let index = head.index;
            // A reclaim pulse (inflate then deflate) makes the guest free and
            // re-report its idle memory; give that back whatever the host's
            // memory pressure, for two minutes after the last target change.
            let reclaiming = self
                .last_reclaim
                .is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(120));
            if reclaiming || release_reported_pages() {
                for desc in head.into_iter() {
                    // Must happen before this report is acked via add_used below.
                    release_guest_range(mem, desc.addr.0, desc.len as u64);
                }
            }

            have_used = true;
            if let Err(e) = queues[FRQ_INDEX].queue.add_used(mem, index, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        // The original kick may cover several reports. Keep the remaining
        // work runnable without requiring another guest notification.
        if have_used
            && !queues[FRQ_INDEX].queue.is_empty(mem)
            && let Err(error) = queues[FRQ_INDEX].event.write(1)
        {
            error!("failed to rearm free-page reporting: {error:?}");
        }

        have_used
    }

    /// Stats queue: the guest writes an array of `{ le16 tag, le64 value }`
    /// entries describing its own memory. Parse the newest one and keep the
    /// descriptor index without acking, so the guest does not immediately
    /// refill; `take_stats` acks it to ask for the next sample.
    ///
    /// Returns true if a sample was parsed.
    pub(crate) fn process_stq(&mut self) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            DeviceState::Inactive => return false,
        };
        let queues = self
            .queues
            .as_mut()
            .expect("queues should exist when activated");

        let mut parsed = None;
        while let Some(head) = queues[STQ_INDEX].queue.pop(mem) {
            // A superseded buffer must be returned or the queue stalls; only the
            // newest sample is worth keeping.
            if let Some(stale) = self.stats_pending_ack.replace(head.index)
                && let Err(e) = queues[STQ_INDEX].queue.add_used(mem, stale, 0)
            {
                error!("balloon: failed to release a superseded stats buffer: {e:?}");
            }

            let mut buf = Vec::new();
            for desc in head.into_iter() {
                let at = buf.len();
                // The guest sizes the buffer (up to 4 GiB); a real sample is far smaller.
                buf.resize(at + cmp::min(desc.len as usize, MAX_STATS_LEN - at), 0);
                if let Err(e) = mem.read_slice(&mut buf[at..], desc.addr) {
                    error!("balloon: unreadable stats buffer: {e:?}");
                    buf.truncate(at);
                    break;
                }
            }

            if let Some(stats) = parse_stats_buffer(&buf) {
                parsed = Some(stats);
            }
        }

        match parsed {
            Some(stats) => {
                // Logged at info: this is the only accurate account of the
                // machine's memory, and it is rate-limited to one sample per
                // refresh interval, so it does not flood the console.
                info!(
                    "balloon stats: total={} available={} free={} caches={} in_use={}",
                    stats.mem_total,
                    stats.mem_available,
                    stats.mem_free,
                    stats.caches,
                    stats.in_use()
                );
                self.stats = Some(stats);
                true
            }
            None => false,
        }
    }

    /// Ack the parked stats buffer, which is what makes the guest publish a
    /// fresh sample. Returns true if a request was actually issued.
    fn request_stats_sample(&mut self) -> bool {
        if self.snapshot_quiesced {
            self.deferred_stats_request = true;
            return false;
        }
        let Some(index) = self.stats_pending_ack.take() else {
            return false;
        };
        let DeviceState::Activated(ref mem, _) = self.device_state else {
            // Re-park it: an inactive device has no queue to ack against, and
            // dropping the index would strand the buffer for good.
            self.stats_pending_ack = Some(index);
            return false;
        };
        let queues = self
            .queues
            .as_mut()
            .expect("queues should exist when activated");
        if let Err(e) = queues[STQ_INDEX].queue.add_used(mem, index, 0) {
            error!("balloon: failed to request the next stats sample: {e:?}");
            return false;
        }
        self.stats_last_request = Some(std::time::Instant::now());
        true
    }

    /// Ask for a fresh sample if the last request is old enough, and say whether
    /// the guest needs an interrupt to notice.
    ///
    /// Called from the balloon's other queue handlers rather than a timer: the
    /// guest is reporting memory activity precisely when its memory is moving,
    /// which is when a stale figure would be wrong. Acking on every sample
    /// instead would leave host and guest refilling the queue in a loop.
    pub(crate) fn refresh_stats_if_due(&mut self) -> bool {
        const MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

        if self.stats_pending_ack.is_none() {
            return false;
        }
        if let Some(last) = self.stats_last_request
            && last.elapsed() < MIN_INTERVAL
        {
            return false;
        }
        self.request_stats_sample()
    }

    /// The guest's own account of its memory, and a request for the next one.
    ///
    /// Acking the parked descriptor is what makes the guest publish a fresh
    /// sample, so the value returned here is the state as of the previous
    /// request. Callers needing a current figure should read twice.
    pub fn take_stats(&mut self) -> Option<BalloonStats> {
        self.request_stats_sample();
        self.stats
    }

    /// Inflate queue: the guest surrenders pages as arrays of little-endian
    /// u32 PFNs (4 KiB units). Coalesce consecutive PFNs into runs and release
    /// each run exactly like a free-page report — the guest will not touch
    /// these pages until it deflates them, and deflated pages come back
    /// zero-filled (refault path / fresh anonymous pages), which the driver
    /// tolerates because we do not negotiate MUST_TELL_HOST semantics beyond
    /// the queue itself.
    pub fn process_ifq(&mut self) -> bool {
        debug!("balloon: process_ifq()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            DeviceState::Inactive => unreachable!(),
        };
        let queues = self
            .queues
            .as_mut()
            .expect("queues should exist when activated");
        let mut have_used = false;

        while let Some(head) = queues[IFQ_INDEX].queue.pop(mem) {
            let index = head.index;
            // Release the pages as sorted, coalesced runs: the guest hands
            // them over in allocation order, and on some hosts (Windows) each
            // release call is costly however small the range.
            let mut pfns: Vec<u32> = Vec::new();
            for desc in head.into_iter() {
                let count = desc.len as usize / 4;
                for i in 0..count {
                    match mem.read_obj::<u32>(desc.addr.unchecked_add(i as u64 * 4)) {
                        Ok(v) => pfns.push(v),
                        Err(e) => {
                            error!("balloon: bad inflate pfn buffer: {e:?}");
                            break;
                        }
                    }
                }
            }
            pfns.sort_unstable();
            pfns.dedup();
            let mut run_start: u64 = 0;
            let mut run_len: u64 = 0;
            for pfn in pfns {
                let gpa = u64::from(pfn) << 12;
                if run_len > 0 && gpa == run_start + run_len {
                    run_len += 4096;
                } else {
                    if run_len > 0 {
                        release_guest_range(mem, run_start, run_len);
                    }
                    run_start = gpa;
                    run_len = 4096;
                }
            }
            if run_len > 0 {
                release_guest_range(mem, run_start, run_len);
            }
            have_used = true;
            if let Err(e) = queues[IFQ_INDEX].queue.add_used(mem, index, 0) {
                error!("failed to add used elements to the inflate queue: {e:?}");
            }
        }
        have_used
    }

    /// Deflate queue: the guest reclaims pages from the balloon. Nothing to
    /// release — the pages materialize on access (refault remap on macOS,
    /// fresh anonymous pages on Linux) — so just ack the descriptors.
    pub fn process_dfq(&mut self) -> bool {
        debug!("balloon: process_dfq()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            DeviceState::Inactive => unreachable!(),
        };
        let queues = self
            .queues
            .as_mut()
            .expect("queues should exist when activated");
        let mut have_used = false;

        while let Some(head) = queues[DFQ_INDEX].queue.pop(mem) {
            let index = head.index;
            have_used = true;
            if let Err(e) = queues[DFQ_INDEX].queue.add_used(mem, index, 0) {
                error!("failed to add used elements to the deflate queue: {e:?}");
            }
        }
        have_used
    }
}

/// Call `f(gpa, host, len)` for each part of the guest range `gpa..gpa+len` that
/// lies in one guest memory region, in order. The range comes from the guest
/// (a free-page report, hint or inflate run), and two regions next to each
/// other in guest memory need not be next to each other on the host (x86 maps
/// the kernel image as its own region between two RAM regions), so one host
/// pointer plus the guest's length could run past a region into unrelated host
/// memory. A part outside guest memory ends the walk: it is not ours to touch.
fn for_each_region_part(
    mem: &GuestMemoryMmap,
    gpa: u64,
    len: u64,
    mut f: impl FnMut(u64, *mut u8, u64),
) {
    use vm_memory::{GuestAddress, GuestMemoryRegion};
    let Some(end) = gpa.checked_add(len) else {
        error!("balloon: range overflows guest memory: 0x{gpa:x}+{len}");
        return;
    };
    let mut cur = gpa;
    while cur < end {
        let Some(region) = mem.find_region(GuestAddress(cur)) else {
            error!("balloon: range outside guest memory: 0x{cur:x}..0x{end:x}");
            return;
        };
        let start = region.start_addr().raw_value();
        let region_end = start.saturating_add(region.len());
        let part_end = end.min(region_end);
        let Ok(host) = region.get_host_address(vm_memory::MemoryRegionAddress(cur - start)) else {
            return;
        };
        f(cur, host, part_end - cur);
        cur = part_end;
    }
}

/// Shrink a part to whole host pages. `madvise`, discard and remapping act on
/// whole host pages, which are larger than the guest's 4 KiB on macOS (16 KiB):
/// releasing or zeroing a partial one would take neighbouring guest pages that
/// are still in use with it. `None` when no whole host page is left.
fn whole_host_pages(gpa: u64, host_addr: *mut u8, len: u64) -> Option<(u64, *mut u8, u64)> {
    let page = host_page_size();
    let start = host_addr as u64;
    let aligned_start = start.checked_add(page - 1)? & !(page - 1);
    let aligned_end = (start + len) & !(page - 1);
    if aligned_end <= aligned_start {
        return None;
    }
    let skip = aligned_start - start;
    Some((
        gpa + skip,
        aligned_start as *mut u8,
        aligned_end - aligned_start,
    ))
}

fn host_page_size() -> u64 {
    #[cfg(unix)]
    {
        (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).max(4096) as u64
    }
    #[cfg(not(unix))]
    {
        4096
    }
}

/// Release a guest range surrendered by the balloon (free-page report or
/// inflate): unmap+purge on macOS when reclaim is enabled, otherwise the
/// per-OS madvise/discard fallback. Sub-host-page runs are silently skipped
/// by the reclaim path's inward alignment. Works region by region, see
/// [`for_each_region_part`].
///
/// File-backed RAM this VMM owns (a branchable machine's) keeps a released
/// page alive in the file, so its pages are also removed from the file; see
/// [`super::owned_ram`].
/// Returns whether the whole range now reads back as zeros. On Linux a
/// file-backed range this VMM cannot punch (a checkpoint generation, a restored
/// or branched machine's private view) keeps its contents: `MADV_DONTNEED` only
/// drops the mapping, and the next read faults the file's page back in.
fn release_guest_range(mem: &GuestMemoryMmap, gpa: u64, len: u64) -> bool {
    let mut zeroed = true;
    let mut any = false;
    for_each_region_part(mem, gpa, len, |gpa, host_addr, len| {
        any = true;
        match whole_host_pages(gpa, host_addr, len) {
            Some((gpa, host_addr, whole)) => {
                zeroed &= whole == len && release_region_part(mem, gpa, host_addr, whole);
            }
            None => zeroed = false,
        }
    });
    any && zeroed
}

/// [`release_guest_range`] for a part that lies in one region.
fn release_region_part(mem: &GuestMemoryMmap, gpa: u64, host_addr: *mut u8, len: u64) -> bool {
    use vm_memory::{GuestAddress, GuestMemoryRegion};
    // The backing file and the offset of `gpa` in it, when the region is
    // file-backed.
    let backing = mem.find_region(GuestAddress(gpa)).and_then(|region| {
        let start = region.start_addr().raw_value();
        let file_offset = region.file_offset()?;
        Some((file_offset.file(), file_offset.start() + (gpa - start)))
    });
    #[cfg(target_os = "macos")]
    if hvf::balloon_reclaim_enabled() {
        use std::os::fd::AsRawFd;
        if let Some((file, offset)) = backing {
            let punched = super::owned_ram::with_owned_backing(file, || {
                hvf::balloon_reclaim_range(
                    gpa,
                    host_addr as u64,
                    len,
                    hvf::ReclaimBacking::OwnedFile(file.as_raw_fd(), offset),
                )
            });
            if punched.is_some() {
                return true;
            }
        }
        // Anonymous RAM, or a restored or branched machine's private view of a
        // file: replaced with fresh zero pages, which both releases them and
        // keeps the file's stale contents out of the next capture.
        hvf::balloon_reclaim_range(gpa, host_addr as u64, len, hvf::ReclaimBacking::Unowned);
        return true;
    }
    #[cfg(target_os = "linux")]
    if let Some((file, _)) = backing {
        // MADV_REMOVE frees the pages from the memfd. The kernel refuses it on
        // a private view and on a write-sealed generation, which then fall
        // through to MADV_DONTNEED as before.
        let removed = super::owned_ram::with_owned_backing(file, || unsafe {
            libc::madvise(
                host_addr as *mut libc::c_void,
                len as usize,
                libc::MADV_REMOVE,
            ) == 0
        });
        if removed == Some(true) {
            return true;
        }
    }
    #[cfg(target_os = "linux")]
    let zeroed = backing.is_none();
    #[cfg(not(target_os = "linux"))]
    let zeroed = true;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = (backing, gpa);
    #[cfg(target_os = "linux")]
    let advice = libc::MADV_DONTNEED;
    #[cfg(target_os = "macos")]
    let advice = libc::MADV_FREE_REUSABLE;
    #[cfg(unix)]
    unsafe {
        libc::madvise(host_addr as *mut libc::c_void, len as usize, advice)
    };
    #[cfg(target_os = "windows")]
    unsafe {
        DiscardVirtualMemory(host_addr as *mut core::ffi::c_void, len as usize)
    };
    zeroed
}

/// Replace a hinted part of a file-backed private view, inside one region, with
/// anonymous zero pages. They cost nothing until the guest writes them, a write
/// becomes an ordinary private page that every capture keeps, and the capture
/// writes the untouched rest as holes. Guest RAM is anonymous wherever it is not
/// a file, so this is the same memory the rest of the RAM uses. The guest holds
/// the range until the hinting round ends, so nothing reads or writes it while
/// the mapping changes; KVM follows the new pages through its MMU notifier.
#[cfg(target_os = "linux")]
fn zero_hinted_private_part(gpa: u64, host_addr: *mut u8, len: u64) {
    // Safety: the part lies inside one live guest-memory mapping this VMM owns
    // and stays mapped (MAP_FIXED replaces it in place with the same
    // protection); the guest is not using it while the round holds it.
    let mapped = unsafe {
        libc::mmap(
            host_addr.cast(),
            len as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        debug!(
            "balloon: could not zero hinted range 0x{gpa:x}+{len}: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Make a hinted block read back as zeros, which is what lets a checkpoint
/// skip it, and hand it back to the host where that is cheap. The guest holds
/// the block until the round is done, so nothing races with this. Works region
/// by region, see [`for_each_region_part`].
fn clear_hinted_range(mem: &GuestMemoryMmap, gpa: u64, len: u64) {
    for_each_region_part(mem, gpa, len, |gpa, host_addr, len| {
        if let Some((gpa, host_addr, len)) = whole_host_pages(gpa, host_addr, len) {
            clear_hinted_part(mem, gpa, host_addr, len)
        }
    });
}

/// [`clear_hinted_range`] for a part that lies in one region.
fn clear_hinted_part(mem: &GuestMemoryMmap, gpa: u64, host_addr: *mut u8, len: u64) {
    // Linux's MADV_DONTNEED zeroes anonymous RAM as it releases, and punching
    // RAM this VMM owns clears it from the file. A private view of a file
    // (every machine after its first checkpoint, every restore and branch)
    // keeps the file's contents, so a checkpoint saved that stale memory:
    // 2.4 GB where 0.26 GB was in use. Map fresh zero pages over it instead.
    #[cfg(target_os = "linux")]
    if !release_region_part(mem, gpa, host_addr, len) {
        zero_hinted_private_part(gpa, host_addr, len);
    }

    // With reclaim on, releasing the range already leaves it reading as zeros:
    // an owned RAM file is punched, and anything else (anonymous RAM, or the
    // private file view every restored and branched machine runs on, where
    // MADV_ZERO fails with EPERM) is replaced with fresh anonymous pages.
    // Without reclaim, MADV_FREE_REUSABLE leaves the old contents readable
    // until macOS takes the pages back, so zero them first; MADV_ZERO clears
    // resident pages without faulting in the rest.
    #[cfg(target_os = "macos")]
    {
        if !hvf::balloon_reclaim_enabled()
            && unsafe {
                libc::madvise(
                    host_addr as *mut libc::c_void,
                    len as usize,
                    libc::MADV_ZERO,
                )
            } != 0
        {
            debug!(
                "balloon: MADV_ZERO unavailable: {}",
                std::io::Error::last_os_error()
            );
        }
        release_region_part(mem, gpa, host_addr, len);
    }

    // DiscardVirtualMemory costs about 1.1 s per GiB here, so the hint path
    // does not use it. Follow the free-page-report policy instead: with RAM to
    // spare keep the pages and write zeros (resident, so this is fast); under
    // pressure decommit and recommit, which frees them and leaves zero pages.
    // A file-backed view refuses the decommit and is cleared by writing.
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_DECOMMIT, PAGE_READWRITE, VirtualAlloc, VirtualFree,
        };
        let _ = (mem, gpa);
        let addr = host_addr as *mut core::ffi::c_void;
        let released = release_reported_pages()
            && unsafe {
                VirtualFree(addr, len as usize, MEM_DECOMMIT) != 0
                    && !VirtualAlloc(addr, len as usize, MEM_COMMIT, PAGE_READWRITE).is_null()
            };
        if !released {
            unsafe { std::ptr::write_bytes(host_addr, 0, len as usize) };
        }
    }
}

/// Whether free-page reports should give their pages back to the host now.
///
/// On Windows a discarded page costs the guest ~5 us to fault back in (about
/// 1.4 s per GiB of memory it reuses), against ~0.1 s per GiB when the page was
/// kept. Like Hyper-V's own dynamic memory, keep freed guest memory resident
/// while the host has RAM to spare and hand it back once the host is under
/// pressure; idle reclaim still shrinks a VM that sits idle. Override with
/// `SMOLVM_WHP_RECLAIM=discard` (always) or `keep` (never). Other hosts
/// refault cheaply and always discard.
fn release_reported_pages() -> bool {
    #[cfg(target_os = "windows")]
    {
        match std::env::var("SMOLVM_WHP_RECLAIM").as_deref() {
            Ok("discard") => return true,
            Ok("keep") => return false,
            _ => {}
        }
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        let mut st: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        st.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        // SAFETY: correctly sized and initialized out-struct.
        if unsafe { GlobalMemoryStatusEx(&mut st) } == 0 {
            return true;
        }
        // Discard once a quarter of physical memory or less is available.
        st.ullAvailPhys.saturating_mul(4) <= st.ullTotalPhys
    }
    #[cfg(not(target_os = "windows"))]
    {
        true
    }
}

impl VirtioDevice for Balloon {
    fn quiesce_for_snapshot(&mut self) {
        if self.snapshot_quiesced {
            return;
        }
        // A parked stats descriptor is host-only state. Return it before
        // freezing so a restored device does not lose the outstanding ack.
        if self.request_stats_sample() {
            self.device_state.signal_used_queue();
        }
        self.snapshot_quiesced = true;
    }

    fn rearm_after_snapshot(&mut self) {
        if !self.snapshot_quiesced {
            return;
        }
        self.snapshot_quiesced = false;
        let pending = std::mem::take(&mut self.deferred_events);
        self.notify_pending_queues(pending);
        if let Some(pages) = self.deferred_target_pages.take() {
            self.set_target_pages(pages);
        }
        if std::mem::take(&mut self.deferred_stats_request) && self.request_stats_sample() {
            self.device_state.signal_used_queue();
        }
    }

    fn finish_restore_activation(&mut self) -> Result<(), String> {
        // Eventfd notifications do not survive a portable restore. The saved
        // available ring can still contain reports awaiting acknowledgment.
        self.notify_pending_queues(
            (1 << IFQ_INDEX)
                | (1 << DFQ_INDEX)
                | (1 << STQ_INDEX)
                | (1 << PHQ_INDEX)
                | (1 << FRQ_INDEX),
        );
        // A checkpoint taken while the guest still held hinted blocks must not
        // leave them held forever: tell the driver the round is done, which
        // frees any it holds and is a no-op otherwise.
        if self.acked_features & (1 << uapi::VIRTIO_BALLOON_F_FREE_PAGE_HINT) != 0 {
            self.finish_free_page_hint();
        }
        Ok(())
    }

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
        // The guest driver reports the balloon's current size by writing
        // `actual` (offset 4, 4 bytes LE). Everything else is host-owned.
        if offset == 4 && data.len() == 4 {
            self.config.actual = u32::from_le_bytes(data.try_into().unwrap());
            return;
        }
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
}

impl Balloon {
    pub(crate) fn defer_queue_event(&mut self, index: usize) -> bool {
        if self.snapshot_quiesced {
            self.deferred_events |= 1 << index;
            true
        } else {
            false
        }
    }

    fn notify_pending_queues(&self, pending: u8) {
        if let Some(queues) = &self.queues {
            for (index, queue) in queues.iter().enumerate() {
                if pending & (1 << index) != 0
                    && queue.queue.ready
                    && let Err(error) = queue.event.write(1)
                {
                    error!("balloon: failed to rearm queue {index}: {error}");
                }
            }
        }
    }
}

#[cfg(test)]
mod hint_tests {
    use super::*;

    #[test]
    fn hint_ids_skip_the_command_values() {
        assert_eq!(next_hint_cmd_id(0), 2);
        assert_eq!(next_hint_cmd_id(2), 3);
        assert_eq!(next_hint_cmd_id(u32::MAX), 2);
    }

    /// A restored device continues after the saved round, so its next request
    /// is not the id the guest last ran and ignores.
    #[test]
    fn a_restored_device_continues_after_the_saved_hint_round() {
        let mut source = Balloon::new().unwrap();
        source.hint.cmd_id = 7;
        let state = source.save_state();
        assert_eq!(state.free_page_hint_cmd_id, 7);
        let mut restored = Balloon::new().unwrap();
        restored.restore_state(&state).unwrap();
        assert_eq!(next_hint_cmd_id(restored.hint.cmd_id), 8);
    }

    /// A state saved before the round was recorded loads, and the restored
    /// device does not reissue the first id a fresh device would use, which
    /// is the one a guest that hinted once has already run.
    #[test]
    fn a_state_without_the_hint_round_does_not_start_over() {
        let mut state = serde_json::to_value(Balloon::new().unwrap().save_state()).unwrap();
        state
            .as_object_mut()
            .unwrap()
            .remove("free_page_hint_cmd_id");
        let state: BalloonState = serde_json::from_value(state).unwrap();
        assert_eq!(state.free_page_hint_cmd_id, 0);
        let fresh_first = next_hint_cmd_id(0);
        let collisions = (0..64)
            .filter(|_| {
                let mut restored = Balloon::new().unwrap();
                restored.restore_state(&state).unwrap();
                next_hint_cmd_id(restored.hint.cmd_id) == fresh_first
            })
            .count();
        assert_eq!(collisions, 0);
    }

    #[test]
    fn hinting_needs_the_negotiated_feature() {
        let mut balloon = Balloon::new().unwrap();
        assert!(balloon.start_free_page_hint().is_err());
        balloon.set_acked_features(1 << uapi::VIRTIO_BALLOON_F_FREE_PAGE_HINT);
        // Negotiated but not yet activated.
        assert!(balloon.start_free_page_hint().is_err());
    }
}

#[cfg(test)]
mod stats_tests {
    use super::*;

    /// Build a stats buffer the way the guest lays it out: packed 10-byte
    /// entries, little-endian, with no padding between them.
    fn entries(pairs: &[(u16, u64)]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(pairs.len() * STAT_ENTRY_LEN);
        for (tag, value) in pairs {
            buf.extend_from_slice(&tag.to_le_bytes());
            buf.extend_from_slice(&value.to_le_bytes());
        }
        buf
    }

    #[test]
    fn a_guest_sample_decodes_to_the_values_it_carried() {
        let buf = entries(&[
            (uapi::VIRTIO_BALLOON_S_MEMTOT, 8 * 1024 * 1024 * 1024),
            (uapi::VIRTIO_BALLOON_S_MEMFREE, 512 * 1024 * 1024),
            (uapi::VIRTIO_BALLOON_S_AVAIL, 6 * 1024 * 1024 * 1024),
            (uapi::VIRTIO_BALLOON_S_CACHES, 1024 * 1024 * 1024),
            (uapi::VIRTIO_BALLOON_S_SWAP_IN, 7),
            (uapi::VIRTIO_BALLOON_S_SWAP_OUT, 9),
            (uapi::VIRTIO_BALLOON_S_MAJFLT, 11),
            (uapi::VIRTIO_BALLOON_S_MINFLT, 13),
        ]);

        let stats = parse_stats_buffer(&buf).expect("a full sample parses");
        assert_eq!(stats.mem_total, 8 * 1024 * 1024 * 1024);
        assert_eq!(stats.mem_free, 512 * 1024 * 1024);
        assert_eq!(stats.mem_available, 6 * 1024 * 1024 * 1024);
        assert_eq!(stats.caches, 1024 * 1024 * 1024);
        assert_eq!(stats.swap_in, 7);
        assert_eq!(stats.swap_out, 9);
        assert_eq!(stats.major_faults, 11);
        assert_eq!(stats.minor_faults, 13);
        // 8 GiB total, 6 GiB available -> 2 GiB the guest cannot hand back.
        assert_eq!(stats.in_use(), 2 * 1024 * 1024 * 1024);
    }

    /// Entries are packed, not `repr(C)`-aligned. Reading them on a 16-byte
    /// stride silently shifts every field after the first, which is the bug
    /// this asserts against: parsing the same bytes on the wrong stride would
    /// not see the second tag at all.
    #[test]
    fn entries_are_read_on_a_ten_byte_stride() {
        let buf = entries(&[
            (uapi::VIRTIO_BALLOON_S_MEMTOT, 4096),
            (uapi::VIRTIO_BALLOON_S_AVAIL, 1024),
        ]);
        assert_eq!(buf.len(), 20, "two packed entries are 20 bytes, not 32");

        let stats = parse_stats_buffer(&buf).expect("parses");
        assert_eq!(stats.mem_total, 4096);
        assert_eq!(stats.mem_available, 1024);
    }

    /// A newer guest sends tags this build has never heard of. They must be
    /// skipped, leaving the known fields intact rather than derailing the rest
    /// of the buffer.
    #[test]
    fn an_unknown_tag_does_not_discard_the_rest_of_the_sample() {
        let buf = entries(&[
            (9999, 0xdead_beef),
            (uapi::VIRTIO_BALLOON_S_MEMTOT, 2048),
            (4242, 1),
            (uapi::VIRTIO_BALLOON_S_AVAIL, 512),
        ]);

        let stats = parse_stats_buffer(&buf).expect("known tags still parse");
        assert_eq!(stats.mem_total, 2048);
        assert_eq!(stats.mem_available, 512);
    }

    /// A short buffer carries no complete entry; reporting a zeroed sample as
    /// though it were real would claim the guest has no memory at all.
    #[test]
    fn a_buffer_too_short_for_one_entry_yields_no_sample() {
        assert_eq!(parse_stats_buffer(&[]), None);
        assert_eq!(parse_stats_buffer(&[0u8; STAT_ENTRY_LEN - 1]), None);
    }

    /// A trailing partial entry is dropped, but the complete ones before it
    /// still count.
    #[test]
    fn a_trailing_partial_entry_is_ignored() {
        let mut buf = entries(&[(uapi::VIRTIO_BALLOON_S_MEMTOT, 777)]);
        buf.extend_from_slice(&[0xff; 4]);

        let stats = parse_stats_buffer(&buf).expect("the complete entry parses");
        assert_eq!(stats.mem_total, 777);
    }
}

#[cfg(test)]
mod checkpoint_quiescence_tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::VirtQueue;
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use utils::epoll::{EpollEvent, EventSet};
    #[cfg(windows)]
    use utils::windows::AsRawFd;
    use vm_memory::GuestAddress;

    fn active_balloon(memory: &GuestMemoryMmap) -> (Balloon, Vec<VirtQueue<'_>>) {
        let rings: Vec<_> = (0..defs::NUM_QUEUES)
            .map(|i| VirtQueue::new(GuestAddress(0x1000 + i as u64 * 0x1000), memory, 8))
            .collect();
        let queues: Vec<_> = rings
            .iter()
            .map(|ring| {
                DeviceQueue::new(
                    ring.create_queue(),
                    Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap()),
                )
            })
            .collect();
        let mut balloon = Balloon::new().unwrap();
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(DummyIrqChip::new().into(), "checkpoint test".into())
                    .unwrap(),
                queues,
            )
            .unwrap();
        (balloon, rings)
    }

    #[test]
    fn rewind_rejects_invalid_last_queue_without_changing_earlier_queues() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let (mut balloon, _) = active_balloon(&memory);
        balloon.hint.cmd_id = 7;
        balloon.quiesce_for_snapshot();
        let before = balloon.save_state();
        let mut invalid = before.clone();
        invalid.acked_features = 123;
        invalid.queues[0].as_mut().unwrap().num_added = 7;
        invalid.queues[FRQ_INDEX].as_mut().unwrap().size = 9;
        assert!(balloon.restore_state(&invalid).is_err());
        assert_eq!(balloon.save_state(), before);
    }

    #[test]
    fn rewind_restores_live_queues_and_discards_later_host_bookkeeping() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let (mut balloon, rings) = active_balloon(&memory);
        balloon.hint.cmd_id = 7;
        balloon.quiesce_for_snapshot();
        let checkpoint = balloon.save_state();
        balloon.rearm_after_snapshot();
        rings[FRQ_INDEX].dtable[0].addr.set(0x10000);
        rings[FRQ_INDEX].dtable[0].len.set(4096);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        assert!(balloon.process_frq());
        balloon.quiesce_for_snapshot();
        // The memory image is restored before device state. The live host
        // counter must rewind too, or 0 - 1 appears to be 65,535 new reports.
        rings[FRQ_INDEX].avail.idx.set(0);
        rings[FRQ_INDEX].used.idx.set(0);
        balloon.stats_pending_ack = Some(6);
        balloon.deferred_target_pages = Some(900);
        balloon.hint.finished = true;
        balloon.hint.bytes = 1234;
        balloon.restore_state(&checkpoint).unwrap();
        assert_eq!(balloon.save_state(), checkpoint);
        assert!(balloon.stats_pending_ack.is_none());
        assert!(balloon.deferred_target_pages.is_none());
        assert!(!balloon.hint.finished);
        assert_eq!(balloon.hint.bytes, 0);
        balloon.rearm_after_snapshot();
        assert!(!balloon.process_frq());
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 0);
    }

    #[test]
    fn free_page_reports_yield_between_chains_and_rearm_pending_work() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let (mut balloon, rings) = active_balloon(&memory);
        let event = Arc::clone(&balloon.queues.as_ref().unwrap()[FRQ_INDEX].event);
        for i in 0..3 {
            rings[FRQ_INDEX].dtable[i]
                .addr
                .set(0x10000 + i as u64 * 0x1000);
            rings[FRQ_INDEX].dtable[i].len.set(4096);
            rings[FRQ_INDEX].avail.ring[i].set(i as u16);
        }
        rings[FRQ_INDEX].avail.idx.set(3);
        event.write(1).unwrap();
        for completed in 1..=3 {
            balloon.handle_frq_event(&EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64));
            assert_eq!(
                rings[FRQ_INDEX].used.idx.get(),
                completed,
                "memory reclaim must yield so the reactor can service socket queues"
            );
        }
        assert_eq!(
            event.read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn a_pending_free_page_callback_cannot_advance_a_quiesced_snapshot() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let (mut balloon, rings) = active_balloon(&memory);
        let event = Arc::clone(&balloon.queues.as_ref().unwrap()[FRQ_INDEX].event);
        rings[FRQ_INDEX].dtable[0].addr.set(0x10000);
        rings[FRQ_INDEX].dtable[0].len.set(4096);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        event.write(1).unwrap();

        // The control thread has quiesced devices and saved their indices.
        // The event loop then delivers a notification already pending at pause.
        balloon.quiesce_for_snapshot();
        let boundary = balloon.save_state();
        let used = rings[FRQ_INDEX].used.idx.get();
        balloon.handle_frq_event(&EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64));
        assert_eq!(
            balloon.save_state(),
            boundary,
            "queue metadata moved after quiescence"
        );
        assert_eq!(
            rings[FRQ_INDEX].used.idx.get(),
            used,
            "guest used ring moved after quiescence"
        );
        assert_eq!(
            event.read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "a deferred notification must not leave the event loop spinning"
        );
        balloon.rearm_after_snapshot();
        balloon.handle_frq_event(&EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64));
        assert_eq!(
            rings[FRQ_INDEX].used.idx.get(),
            1,
            "deferred report must complete after resume"
        );
        balloon.rearm_after_snapshot();
        assert_eq!(
            event.read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "rearming twice must not duplicate the notification"
        );
    }

    #[test]
    fn paused_stats_and_target_requests_do_not_change_the_boundary() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let (mut balloon, rings) = active_balloon(&memory);
        // A stats buffer was consumed and parked before the checkpoint.
        balloon.stats_pending_ack = Some(0);
        balloon.quiesce_for_snapshot();
        assert!(balloon.stats_pending_ack.is_none());
        assert_eq!(rings[STQ_INDEX].used.idx.get(), 1);
        let boundary = balloon.save_state();
        balloon.set_target_pages(123);
        balloon.take_stats();
        balloon.quiesce_for_snapshot();
        assert_eq!(balloon.save_state(), boundary);
        balloon.rearm_after_snapshot();
        assert_eq!(balloon.pages().0, 123);
    }

    #[test]
    fn restored_pending_reports_receive_a_fresh_notification() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let (mut balloon, rings) = active_balloon(&memory);
        let event = Arc::clone(&balloon.queues.as_ref().unwrap()[FRQ_INDEX].event);
        rings[FRQ_INDEX].dtable[0].addr.set(0x10000);
        rings[FRQ_INDEX].dtable[0].len.set(4096);
        rings[FRQ_INDEX].avail.ring[0].set(0);
        rings[FRQ_INDEX].avail.idx.set(1);
        balloon.finish_restore_activation().unwrap();
        balloon.handle_frq_event(&EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64));
        assert_eq!(rings[FRQ_INDEX].used.idx.get(), 1);
    }

    #[test]
    fn inactive_balloon_can_be_quiesced_and_rearmed() {
        let mut balloon = Balloon::new().unwrap();
        balloon.quiesce_for_snapshot();
        balloon.set_target_pages(42);
        balloon.take_stats();
        balloon.rearm_after_snapshot();
        assert_eq!(balloon.pages().0, 42);
    }

    #[test]
    fn every_supported_queue_defers_pending_work_until_resume() {
        type QueueHandler = fn(&mut Balloon, &EpollEvent);
        let handlers: [(usize, QueueHandler); 4] = [
            (IFQ_INDEX, Balloon::handle_ifq_event),
            (DFQ_INDEX, Balloon::handle_dfq_event),
            (STQ_INDEX, Balloon::handle_stq_event),
            (FRQ_INDEX, Balloon::handle_frq_event),
        ];
        for (index, handle) in handlers {
            let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
            let (mut balloon, rings) = active_balloon(&memory);
            let event = Arc::clone(&balloon.queues.as_ref().unwrap()[index].event);
            // An inflate PFN points at a separate free page; the other queues
            // only need a readable buffer to exercise their completion path.
            memory.write_obj(0x18u32, GuestAddress(0x10000)).unwrap();
            rings[index].dtable[0].addr.set(0x10000);
            rings[index].dtable[0].len.set(4);
            rings[index].avail.ring[0].set(0);
            rings[index].avail.idx.set(1);
            balloon.quiesce_for_snapshot();
            let boundary = balloon.save_state();
            let notification = EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64);
            // Multiple kicks coalesce while paused, without processing work or
            // leaving an eventfd readable in a busy loop.
            for _ in 0..2 {
                event.write(1).unwrap();
                handle(&mut balloon, &notification);
                assert_eq!(balloon.save_state(), boundary, "queue {index}");
                assert_eq!(rings[index].used.idx.get(), 0, "queue {index}");
                assert_eq!(
                    event.read().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
            balloon.rearm_after_snapshot();
            handle(&mut balloon, &notification);
            if index == STQ_INDEX {
                // Stats park their descriptor until a fresh sample is asked for.
                assert_eq!(balloon.stats_pending_ack, Some(0));
                assert!(balloon.request_stats_sample());
            }
            assert_eq!(rings[index].used.idx.get(), 1, "queue {index}");
        }
    }
}

#[cfg(test)]
mod region_bounds_tests {
    use super::*;
    use vm_memory::{Bytes, GuestAddress};

    // Whole host pages: 16 KiB on macOS, so the tests hold on every host.
    fn page() -> usize {
        host_page_size() as usize
    }

    /// Two guest regions next to each other in guest memory, each its own host
    /// mapping, filled with 0xAA.
    fn two_regions() -> GuestMemoryMmap {
        let mem = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 2 * page()),
            (GuestAddress(2 * page() as u64), 2 * page()),
        ])
        .unwrap();
        mem.write_slice(&vec![0xAA; 4 * page()], GuestAddress(0))
            .unwrap();
        mem
    }

    fn page_byte(mem: &GuestMemoryMmap, n: usize) -> u8 {
        mem.read_obj::<u8>(GuestAddress((n * page()) as u64))
            .unwrap()
    }

    // A range across a region boundary is walked region by region, each part
    // through its own region's host mapping.
    #[test]
    fn a_range_across_regions_is_split_at_the_boundary() {
        let mem = two_regions();
        let mut parts = Vec::new();
        for_each_region_part(&mem, page() as u64, 2 * page() as u64, |gpa, host, len| {
            parts.push((gpa, host as usize, len))
        });
        assert_eq!(parts.len(), 2);
        assert_eq!((parts[0].0, parts[0].2), (page() as u64, page() as u64));
        assert_eq!((parts[1].0, parts[1].2), (2 * page() as u64, page() as u64));
        let second = mem
            .get_host_address(GuestAddress(2 * page() as u64))
            .unwrap() as usize;
        assert_eq!(
            parts[1].1, second,
            "the second part uses its own region's host address"
        );
    }

    // Releasing across the boundary zeroes exactly the requested pages in
    // both regions and nothing next to them.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn releasing_across_regions_zeroes_exactly_the_range() {
        let mem = two_regions();
        clear_hinted_range(&mem, page() as u64, 2 * page() as u64);
        assert_eq!(page_byte(&mem, 0), 0xAA);
        assert_eq!(page_byte(&mem, 1), 0);
        assert_eq!(
            page_byte(&mem, 2),
            0,
            "the part in the second region is cleared"
        );
        assert_eq!(page_byte(&mem, 3), 0xAA);
    }

    // A range that runs past guest memory touches only the guest part, and
    // one wholly outside touches nothing.
    #[test]
    fn a_range_past_guest_memory_stops_at_its_end() {
        let mem = two_regions();
        let mut parts = Vec::new();
        for_each_region_part(&mem, 3 * page() as u64, 1 << 20, |gpa, _, len| {
            parts.push((gpa, len))
        });
        assert_eq!(parts, vec![(3 * page() as u64, page() as u64)]);
        parts.clear();
        for_each_region_part(&mem, 1 << 30, page() as u64, |gpa, _, len| {
            parts.push((gpa, len))
        });
        assert!(parts.is_empty());
        for_each_region_part(&mem, u64::MAX - 1, 4, |gpa, _, len| parts.push((gpa, len)));
        assert!(parts.is_empty(), "an overflowing range is refused");
    }

    // A release smaller than a host page leaves that host page, and the guest
    // pages sharing it, untouched; a whole host page inside it is released.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn partial_host_pages_are_left_alone() {
        let mem = two_regions();
        let quarter = (page() / 4) as u64;
        clear_hinted_range(&mem, quarter, 2 * quarter);
        assert_eq!(page_byte(&mem, 0), 0xAA, "no whole host page in the range");
        assert!(
            !release_guest_range(&mem, quarter, 2 * quarter),
            "nothing is reported zeroed"
        );
        clear_hinted_range(&mem, quarter, page() as u64 + 3 * quarter);
        assert_eq!(page_byte(&mem, 0), 0xAA, "the partial first page is kept");
        assert_eq!(page_byte(&mem, 1), 0, "the whole second page is cleared");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod stats_allocation_tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::VirtQueue;
    use std::sync::Arc;
    use vm_memory::GuestAddress;

    fn max_rss_bytes() -> i64 {
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        usage.ru_maxrss * 1024
    }

    /// The stats buffer length is guest-chosen (up to 4 GiB) and must not size
    /// a host allocation.
    #[test]
    fn an_oversized_stats_descriptor_does_not_size_a_host_allocation() {
        const CLAIMED: u32 = 1 << 30;
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let rings: Vec<_> = (0..defs::NUM_QUEUES)
            .map(|i| VirtQueue::new(GuestAddress(0x1000 + i as u64 * 0x1000), &memory, 8))
            .collect();
        let queues = rings
            .iter()
            .map(|ring| {
                DeviceQueue::new(
                    ring.create_queue(),
                    Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap()),
                )
            })
            .collect();
        let mut balloon = Balloon::new().unwrap();
        balloon
            .activate(
                memory.clone(),
                InterruptTransport::new(DummyIrqChip::new().into(), "stats test".into()).unwrap(),
                queues,
            )
            .unwrap();
        rings[STQ_INDEX].dtable[0].addr.set(0x10000);
        rings[STQ_INDEX].dtable[0].len.set(CLAIMED);
        rings[STQ_INDEX].avail.ring[0].set(0);
        rings[STQ_INDEX].avail.idx.set(1);

        let before = max_rss_bytes();
        balloon.process_stq();
        let grown = max_rss_bytes() - before;
        assert!(
            grown < i64::from(CLAIMED) / 2,
            "process_stq grew the peak RSS by {grown} bytes for a {CLAIMED}-byte claim"
        );
    }
}
