use std::cmp;
use std::io::Write;

use utils::eventfd::EventFd;
use vm_memory::{ByteValued, GuestAddress, GuestMemory, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, BalloonError, DeviceQueue, DeviceState, QueueConfig,
    VirtioDevice,
};
use super::{defs, defs::uapi, FreePageReclaim};
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
}

pub struct Balloon {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    config: VirtioBalloonConfig,
    pub(super) reclaim: FreePageReclaim,
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
        })
    }

    pub fn id(&self) -> &str {
        defs::BALLOON_DEV_ID
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
                // The range comes from the guest. Releasing one that runs past the end of
                // a guest memory region would discard whatever the VMM has mapped after it.
                let Some(range) = FreeRange::new(mem, desc.addr, desc.len as usize) else {
                    warn!(
                        "balloon: ignoring free page report outside guest memory: guest_addr={:?} len={}",
                        desc.addr, desc.len
                    );
                    continue;
                };
                debug!(
                    "balloon: should release guest_addr={:?} host_addr={:p} len={}",
                    range.guest_addr, range.host_addr, range.len
                );
                ranges.push(range);
            }

            if self.reclaim.release(index, ranges) {
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
}

#[cfg(test)]
mod tests {
    use super::super::test_util::TestDevice;
    use super::*;

    const MIB: u64 = 1 << 20;

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
}
