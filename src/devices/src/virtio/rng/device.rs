use rand::{TryRngCore, rngs::OsRng};
use utils::eventfd::EventFd;
use vm_memory::{Bytes, GuestMemory, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, Queue, QueueConfig, RngError,
    VirtioDevice,
};
use super::{defs, defs::uapi};
use crate::virtio::InterruptTransport;

// Request queue.
pub(crate) const REQ_INDEX: usize = 0;

// Supported features.
pub(crate) const AVAIL_FEATURES: u64 = 1 << uapi::VIRTIO_F_VERSION_1 as u64;

// Linux's virtio-rng driver posts small, sub-page buffers.
const MAX_REQUEST_LEN: u32 = 64 * 1024;

pub struct Rng {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    snapshot_quiesced: bool,
    deferred_request: bool,
}

/// Serializable runtime state of an [`Rng`] device for VM checkpoint/fork.
/// The entropy source is the host RNG (recreated per process), so only the
/// negotiated features and the request-queue indices need to be carried —
/// reactivating the device on a clone gives the guest a *fresh* host entropy
/// source, which the kernel credits and reseeds the CRNG from (the practical
/// fork-safety reseed, since the kernel here lacks ACPI/VMGENID).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RngState {
    pub acked_features: u64,
    pub queue: Option<crate::virtio::queue::QueueState>,
}

impl Rng {
    /// Capture runtime state for checkpoint/fork. Both vCPUs and request
    /// processing must be quiesced: a previously queued host event can still
    /// arrive after the guest pauses.
    pub fn save_state(&self) -> RngState {
        RngState {
            acked_features: self.acked_features,
            queue: self
                .queues
                .as_ref()
                .map(|q| q[REQ_INDEX].queue.save_state()),
        }
    }

    /// Restore a fresh entropy device or its live, quiesced request queue.
    pub fn restore_state(&mut self, state: &RngState) -> Result<(), String> {
        if self.is_activated() && !self.snapshot_quiesced {
            return Err("entropy device must be quiesced before restoring its live queue".into());
        }
        if let Some(queues) = &mut self.queues {
            let saved = state
                .queue
                .as_ref()
                .ok_or("entropy checkpoint is missing its live queue")?;
            let mut queue = Queue::new(queues[REQ_INDEX].queue.max_size);
            queue.restore_state(saved)?;
            if let DeviceState::Activated(mem, _) = &self.device_state
                && queue.ready
                && (!queue.is_valid(mem) || queue.len(mem) > queue.actual_size())
            {
                return Err("entropy checkpoint queue does not match restored memory".into());
            }
            queues[REQ_INDEX].queue = queue;
        }
        self.acked_features = state.acked_features;
        self.deferred_request = self.is_activated();
        Ok(())
    }
}

impl Rng {
    pub(crate) fn queue_event(&self, idx: usize) -> &std::sync::Arc<utils::eventfd::EventFd> {
        &self.queues.as_ref().expect("queues should exist")[idx].event
    }

    pub fn new() -> super::Result<Rng> {
        Ok(Rng {
            queues: None,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(RngError::EventFd)?,
            device_state: DeviceState::Inactive,
            snapshot_quiesced: false,
            deferred_request: false,
        })
    }

    pub fn id(&self) -> &str {
        defs::RNG_DEV_ID
    }

    pub fn process_req(&mut self) -> bool {
        debug!("rng: process_req()");
        if self.snapshot_quiesced {
            self.deferred_request = true;
            return false;
        }
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

        while let Some(head) = queues[REQ_INDEX].queue.pop(mem) {
            let index = head.index;
            let mut written = 0;
            for desc in head.into_iter() {
                // The length is guest-chosen (up to 4 GiB) and the device may fill
                // less than offered. Check the range before allocating: rewinding
                // below would retry a bad descriptor forever.
                let len = desc.len.min(MAX_REQUEST_LEN);
                if !mem.check_range(desc.addr, len as usize) {
                    error!("rng: request buffer outside guest memory");
                    break;
                }
                let mut rand_bytes = vec![0u8; len as usize];
                if let Err(e) = OsRng.try_fill_bytes(&mut rand_bytes) {
                    error!("Failed to fill buffer with random data: {e:?}");
                    queues[REQ_INDEX].queue.go_to_previous_position();
                    break;
                }
                if let Err(e) = mem.write_slice(&rand_bytes[..], desc.addr) {
                    error!("Failed to write slice: {e:?}");
                    queues[REQ_INDEX].queue.go_to_previous_position();
                    break;
                }
                written += len;
            }

            have_used = true;
            if let Err(e) = queues[REQ_INDEX].queue.add_used(mem, index, written) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        have_used
    }
}

impl VirtioDevice for Rng {
    fn quiesce_for_snapshot(&mut self) {
        self.snapshot_quiesced = true;
    }

    fn rearm_after_snapshot(&mut self) {
        self.snapshot_quiesced = false;
        if std::mem::take(&mut self.deferred_request) {
            self.notify_pending_request();
        }
    }

    fn finish_restore_activation(&mut self) -> Result<(), String> {
        // Queue indices survive restore; the host eventfd counter does not.
        // Check the restored queue even when no new guest kick arrives.
        self.notify_pending_request();
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
        uapi::VIRTIO_ID_RNG
    }

    fn device_name(&self) -> &str {
        "rng"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, _offset: u64, _data: &mut [u8]) {
        error!("rng: invalid request to read config space");
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "rng: guest driver attempted to write device config (offset={:x}, len={:x})",
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
        self.queues = None;
        self.device_state = DeviceState::Inactive;
        self.snapshot_quiesced = false;
        self.deferred_request = false;
        true
    }
}

impl Rng {
    fn notify_pending_request(&self) {
        if self.is_activated()
            && let Err(error) = self.queue_event(REQ_INDEX).write(1)
        {
            error!("rng: failed to notify pending request: {error}");
        }
    }
}

#[cfg(test)]
mod checkpoint_tests {
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

    #[test]
    fn pending_entropy_request_keeps_the_checkpoint_boundary() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
        let event = Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());
        let mut rng = Rng::new().unwrap();
        rng.activate(
            memory.clone(),
            InterruptTransport::new(DummyIrqChip::new().into(), "checkpoint test".into()).unwrap(),
            vec![DeviceQueue::new(ring.create_queue(), Arc::clone(&event))],
        )
        .unwrap();
        let buffer = GuestAddress(0x10000);
        memory.write_slice(&[0x55; 64], buffer).unwrap();
        ring.dtable[0].addr.set(buffer.0);
        ring.dtable[0].len.set(64);
        ring.dtable[0].flags.set(2);
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        event.write(1).unwrap();

        rng.quiesce_for_snapshot();
        let boundary = rng.save_state();
        let notification = EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64);
        rng.handle_req_event(&notification);
        assert_eq!(
            rng.save_state(),
            boundary,
            "entropy queue advanced after quiescence"
        );
        assert_eq!(ring.used.idx.get(), 0);
        let mut contents = [0; 64];
        memory.read_slice(&mut contents, buffer).unwrap();
        assert_eq!(contents, [0x55; 64]);
        assert_eq!(
            event.read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        event.write(1).unwrap();
        rng.quiesce_for_snapshot();
        rng.handle_req_event(&notification);
        assert_eq!(rng.save_state(), boundary);
        assert_eq!(
            event.read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );

        rng.rearm_after_snapshot();
        rng.handle_req_event(&notification);
        assert_eq!(
            ring.used.idx.get(),
            1,
            "pending entropy request must complete after resume"
        );
        rng.rearm_after_snapshot();
        assert_eq!(
            event.read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn live_entropy_rewind_restores_and_rearms_the_saved_request() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
        let event = Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());
        let mut rng = Rng::new().unwrap();
        rng.activate(
            memory.clone(),
            InterruptTransport::new(DummyIrqChip::new().into(), "rewind test".into()).unwrap(),
            vec![DeviceQueue::new(ring.create_queue(), Arc::clone(&event))],
        )
        .unwrap();
        ring.dtable[0].addr.set(0x10000);
        ring.dtable[0].len.set(64);
        ring.dtable[0].flags.set(2);
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        rng.quiesce_for_snapshot();
        let checkpoint = rng.save_state();
        rng.rearm_after_snapshot();
        assert!(rng.process_req());
        rng.quiesce_for_snapshot();
        ring.used.idx.set(0);
        rng.restore_state(&checkpoint).unwrap();
        assert_eq!(rng.save_state(), checkpoint);
        let mut invalid = checkpoint.clone();
        invalid.acked_features = 123;
        invalid.queue.as_mut().unwrap().size = 9;
        assert!(rng.restore_state(&invalid).is_err());
        assert_eq!(rng.save_state(), checkpoint);
        rng.rearm_after_snapshot();
        rng.handle_req_event(&EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64));
        assert_eq!(ring.used.idx.get(), 1);
        assert!(
            rng.restore_state(&checkpoint).is_err(),
            "live restore requires quiescence"
        );
    }

    #[test]
    fn restored_entropy_request_does_not_need_a_new_guest_kick() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
        let event = Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());
        let mut rng = Rng::new().unwrap();
        rng.activate(
            memory.clone(),
            InterruptTransport::new(DummyIrqChip::new().into(), "restore test".into()).unwrap(),
            vec![DeviceQueue::new(ring.create_queue(), Arc::clone(&event))],
        )
        .unwrap();
        ring.dtable[0].addr.set(0x10000);
        ring.dtable[0].len.set(64);
        ring.dtable[0].flags.set(2);
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        // A fresh device has an empty eventfd despite pending guest work.
        assert_eq!(
            event.read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        rng.finish_restore_activation().unwrap();
        rng.handle_req_event(&EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64));
        assert_eq!(ring.used.idx.get(), 1);
    }

    #[test]
    fn inactive_entropy_device_can_be_quiesced_rearmed_and_reset() {
        let mut rng = Rng::new().unwrap();
        rng.quiesce_for_snapshot();
        assert!(!rng.process_req());
        rng.rearm_after_snapshot();
        rng.rearm_after_snapshot();
        rng.finish_restore_activation().unwrap();
        rng.quiesce_for_snapshot();
        assert!(rng.reset());
        assert!(!rng.snapshot_quiesced);
        assert!(!rng.deferred_request);
    }
}

#[cfg(test)]
mod guest_range_tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::VirtQueue;
    use std::sync::Arc;
    use std::time::Duration;
    use vm_memory::GuestAddress;

    /// A request buffer outside guest memory must complete instead of being
    /// retried forever, and its guest-chosen length must not size an
    /// allocation first.
    #[test]
    fn an_out_of_range_request_completes_once() {
        let (done, finished) = std::sync::mpsc::channel();
        // Run on a thread: the failure mode is process_req never returning.
        std::thread::spawn(move || {
            let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
            let ring = VirtQueue::new(GuestAddress(0x1000), &memory, 8);
            let mut rng = Rng::new().unwrap();
            rng.activate(
                memory.clone(),
                InterruptTransport::new(DummyIrqChip::new().into(), "range test".into()).unwrap(),
                vec![DeviceQueue::new(
                    ring.create_queue(),
                    Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap()),
                )],
            )
            .unwrap();
            ring.dtable[0].addr.set(0x10000);
            ring.dtable[0].len.set(64 << 20);
            ring.dtable[0].flags.set(2);
            ring.avail.ring[0].set(0);
            ring.avail.idx.set(1);
            rng.process_req();
            done.send(ring.used.idx.get()).unwrap();
        });
        assert_eq!(
            finished.recv_timeout(Duration::from_secs(20)),
            Ok(1),
            "process_req did not complete the request"
        );
    }
}
