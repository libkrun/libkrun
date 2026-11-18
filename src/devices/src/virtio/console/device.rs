use std::cmp;
use std::io::Write;
use std::iter::zip;
use std::mem::{size_of, size_of_val};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
#[cfg(target_os = "windows")]
use utils::windows::{AsRawFd, RawFd};

use utils::eventfd::EventFd;
use vm_memory::{ByteValued, Bytes, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, QueueConfig, VirtioDevice,
};
use super::{defs, defs::control_event, defs::uapi};
use crate::virtio::console::console_control::{
    ConsoleControl, VirtioConsoleControl, VirtioConsoleResize,
};
use crate::virtio::console::defs::QUEUE_SIZE;
use crate::virtio::console::port::Port;
use crate::virtio::console::port_queue_mapping::{
    QueueDirection, num_queues, port_id_to_queue_idx,
};
use crate::virtio::queue::QueueState;
use crate::virtio::{InterruptTransport, PortDescription, VmmExitObserver};

pub(crate) const CONTROL_RXQ_INDEX: usize = 2;
pub(crate) const CONTROL_TXQ_INDEX: usize = 3;

pub(crate) const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_CONSOLE_F_SIZE as u64)
    | (1 << uapi::VIRTIO_CONSOLE_F_MULTIPORT as u64)
    | (1 << uapi::VIRTIO_F_VERSION_1 as u64);

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct VirtioConsoleConfig {
    cols: u16,
    rows: u16,
    max_nr_ports: u32,
    emerg_wr: u32,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioConsoleConfig {}

impl VirtioConsoleConfig {
    pub fn new(cols: u16, rows: u16, max_nr_ports: u32) -> Self {
        VirtioConsoleConfig {
            cols,
            rows,
            max_nr_ports,
            emerg_wr: 0u32,
        }
    }
}

pub struct Console {
    pub(crate) device_state: DeviceState,
    pub(crate) control: Arc<ConsoleControl>,
    pub(crate) ports: Vec<Port>,

    queue_config: Vec<QueueConfig>,
    // Queues are stored as Option so individual queues can be taken when ports start.
    pub(crate) queues: Vec<Option<DeviceQueue>>,
    // TODO: move the queue event handling to the correct threads!
    pub(crate) queue_events: Vec<Arc<EventFd>>,

    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,

    pub(crate) activate_evt: EventFd,
    pub(crate) sigwinch_evt: EventFd,

    pub(crate) snapshot_quiesced: bool,
    snapshot_error: Option<String>,
    // Indices in the notification list, not borrowed OS handles (which are
    // pointers on Windows). The list stays fixed while quiesced; reset clears it.
    pub(crate) deferred_events: Vec<usize>,

    config: VirtioConsoleConfig,
}

impl Console {
    pub fn new(ports: Vec<PortDescription>) -> super::Result<Console> {
        assert!(!ports.is_empty(), "Expected at least 1 port");

        let num_queues = num_queues(ports.len());
        let queue_config: Vec<QueueConfig> = (0..num_queues)
            .map(|_| QueueConfig::new(QUEUE_SIZE))
            .collect();

        let ports: Vec<Port> = zip(0u32.., ports)
            .map(|(port_id, description)| Port::new(port_id, description))
            .collect();

        let (cols, rows) = ports[0]
            .terminal()
            .map(|t| t.get_win_size())
            .unwrap_or((0, 0));
        let config = VirtioConsoleConfig::new(cols, rows, ports.len() as u32);

        Ok(Console {
            control: ConsoleControl::new(),
            ports,
            queue_config,
            queues: Vec::new(),
            queue_events: Vec::new(),
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(super::ConsoleError::EventFd)?,
            sigwinch_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(super::ConsoleError::EventFd)?,
            device_state: DeviceState::Inactive,
            snapshot_quiesced: false,
            snapshot_error: None,
            deferred_events: Vec::new(),
            config,
        })
    }

    pub fn id(&self) -> &str {
        defs::CONSOLE_DEV_ID
    }

    pub fn get_sigwinch_fd(&self) -> RawFd {
        self.sigwinch_evt.as_raw_fd()
    }

    pub fn update_console_size(&mut self, port_id: u32, cols: u16, rows: u16) {
        log::debug!("update_console_size {port_id}: {cols} {rows}");
        self.control
            .console_resize(port_id, VirtioConsoleResize { rows, cols });
    }

    pub(crate) fn process_control_rx(&mut self) -> bool {
        log::trace!("process_control_rx");
        let DeviceState::Activated(ref mem, _) = self.device_state else {
            unreachable!()
        };
        let mut raise_irq = false;

        let control_rx = self.queues[CONTROL_RXQ_INDEX]
            .as_mut()
            .expect("control rx queue should exist");

        while let Some(head) = control_rx.queue.pop(mem) {
            if let Some(buf) = self.control.queue_pop() {
                match mem.write(&buf, head.addr) {
                    Ok(n) => {
                        if n != buf.len() {
                            log::error!("process_control_rx: partial write");
                        }
                        raise_irq = true;
                        log::trace!("process_control_rx wrote {n}");
                        if let Err(e) = control_rx.queue.add_used(mem, head.index, n as u32) {
                            error!("failed to add used elements to the queue: {e:?}");
                        }
                    }
                    Err(e) => {
                        log::error!("process_control_rx failed to write: {e}");
                    }
                }
            } else {
                control_rx.queue.undo_pop();
                break;
            }
        }
        raise_irq
    }

    pub(crate) fn process_control_tx(&mut self) -> bool {
        log::trace!("process_control_tx");
        let DeviceState::Activated(ref mem, ref interrupt) = self.device_state else {
            unreachable!()
        };

        let control_tx = self.queues[CONTROL_TXQ_INDEX]
            .as_mut()
            .expect("control tx queue should exist");
        let mut raise_irq = false;

        let mut ports_to_start = Vec::new();

        while let Some(head) = control_tx.queue.pop(mem) {
            raise_irq = true;

            let cmd: VirtioConsoleControl = match mem.read_obj(head.addr) {
                Ok(cmd) => cmd,
                Err(e) => {
                    log::error!(
                        "Failed to read VirtioConsoleControl struct: {e:?}, struct len = {len}, head.len = {head_len}",
                        len = size_of::<VirtioConsoleControl>(),
                        head_len = head.len,
                    );
                    continue;
                }
            };
            if let Err(e) = control_tx
                .queue
                .add_used(mem, head.index, size_of_val(&cmd) as u32)
            {
                error!("failed to add used elements to the queue: {e:?}");
            }

            log::trace!("VirtioConsoleControl cmd: {cmd:?}");
            match cmd.event {
                control_event::VIRTIO_CONSOLE_DEVICE_READY => {
                    log::debug!(
                        "Device is ready: initialization {}",
                        if cmd.value == 1 { "ok" } else { "failed" }
                    );
                    for port_id in 0..self.ports.len() {
                        self.control.port_add(port_id as u32);
                    }
                }
                control_event::VIRTIO_CONSOLE_PORT_READY => {
                    if cmd.value != 1 {
                        log::error!("Port initialization failed: {cmd:?}");
                        continue;
                    }

                    if let Some(term) = self.ports[cmd.id as usize].terminal() {
                        self.control.mark_console_port(mem, cmd.id);
                        self.control.port_open(cmd.id, true);
                        let (cols, rows) = term.get_win_size();
                        self.control
                            .console_resize(cmd.id, VirtioConsoleResize { cols, rows });
                    } else {
                        // We start with all ports open, this makes sense for now,
                        // because underlying file descriptors STDIN, STDOUT, STDERR are always open too
                        self.control.port_open(cmd.id, true)
                    }

                    let name = self.ports[cmd.id as usize].name();
                    log::trace!("Port ready {id}: {name}", id = cmd.id);
                    if !name.is_empty() {
                        self.control.port_name(cmd.id, name)
                    }
                }
                control_event::VIRTIO_CONSOLE_PORT_OPEN => {
                    let opened = match cmd.value {
                        0 => false,
                        1 => true,
                        _ => {
                            log::error!(
                                "Invalid value ({}) for VIRTIO_CONSOLE_PORT_OPEN on port {}",
                                cmd.value,
                                cmd.id
                            );
                            continue;
                        }
                    };

                    if !opened {
                        log::debug!("Guest closed port {}", cmd.id);
                        continue;
                    }

                    ports_to_start.push(cmd.id as usize);
                }
                _ => log::warn!("Unknown console control event {:x}", cmd.event),
            }
        }

        for port_id in ports_to_start {
            // Restore activation may already have restarted this port before
            // a pending guest PORT_OPEN message is consumed.
            if self.ports[port_id].is_active() {
                continue;
            }
            log::trace!("Starting port io for port {port_id}");
            let rx_idx = port_id_to_queue_idx(QueueDirection::Rx, port_id);
            let tx_idx = port_id_to_queue_idx(QueueDirection::Tx, port_id);

            // Take ownership of port queues - they are moved to the port.
            let rx_queue = self.queues[rx_idx]
                .take()
                .expect("port rx queue should exist")
                .queue;
            let tx_queue = self.queues[tx_idx]
                .take()
                .expect("port tx queue should exist")
                .queue;

            self.ports[port_id].start(
                mem.clone(),
                rx_queue,
                tx_queue,
                interrupt.clone(),
                self.control.clone(),
            );
        }

        raise_irq
    }
}

/// Serializable runtime state of a [`Console`] device, for VM checkpoint/fork.
///
/// Composes the per-queue [`QueueState`] with the device-level state that is
/// negotiated/established at run time (acked features, activation). Host-side
/// resources — `EventFd`s, port I/O handles, worker threads, and the
/// `Activated` guest-memory/interrupt — are recreated and re-wired when the
/// device is re-activated on restore, so they are not serialized.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsoleState {
    pub acked_features: u64,
    pub activated: bool,
    /// Per-queue runtime state, indexed like [`Console::queues`]. `None` means
    /// the queue was owned by a port worker thread at snapshot time and was not
    /// captured — a faithful snapshot must first quiesce the port threads so
    /// they release their queues (the device-level drain step).
    pub queues: Vec<Option<QueueState>>,
    /// Control replies accepted by the host but not yet delivered to the guest.
    #[serde(default)]
    pub pending_control: Vec<Vec<u8>>,
}

impl Console {
    /// Capture this console's runtime state for VM checkpoint/fork.
    pub fn save_state(&self) -> ConsoleState {
        ConsoleState {
            acked_features: self.acked_features,
            activated: matches!(self.device_state, DeviceState::Activated(..)),
            pending_control: self.control.snapshot_pending(),
            queues: self
                .queues
                .iter()
                .map(|q| q.as_ref().map(|dq| dq.queue.save_state()))
                .collect(),
        }
    }

    /// Restore runtime state onto a freshly-constructed, not-yet-activated
    /// console. The VMM re-activates the device afterwards (re-supplying guest
    /// memory + interrupt and starting port threads).
    pub fn restore_state(&mut self, state: &ConsoleState) -> Result<(), String> {
        self.acked_features = state.acked_features;
        self.control.restore_pending(&state.pending_control);
        for (slot, snap) in self.queues.iter_mut().zip(state.queues.iter()) {
            if let (Some(dq), Some(qs)) = (slot.as_mut(), snap.as_ref()) {
                dq.queue.restore_state(qs)?;
            }
        }
        Ok(())
    }

    /// Stop every running port worker thread and reclaim its virtqueue back into
    /// `self.queues`, so [`Self::save_state`] captures the queue ring addresses
    /// and indices at a clean checkpoint boundary. Without this, the port
    /// workers own the data queues and `save_state` records them as `None`,
    /// losing the state needed to resume console I/O on a clone.
    pub fn quiesce_ports_for_snapshot(&mut self) {
        for port_id in 0..self.ports.len() {
            if !self.ports[port_id].is_active() {
                continue;
            }
            let reclaimed = self.ports[port_id].shutdown_and_reclaim();
            if reclaimed.rx.is_none() || reclaimed.tx.is_none() {
                self.snapshot_error =
                    Some(format!("console port {port_id} lost a checkpoint queue"));
            }
            if let Some(q) = reclaimed.rx {
                let idx = port_id_to_queue_idx(QueueDirection::Rx, port_id);
                self.queues[idx] = Some(DeviceQueue::new(q, self.queue_events[idx].clone()));
            }
            if let Some(q) = reclaimed.tx {
                let idx = port_id_to_queue_idx(QueueDirection::Tx, port_id);
                self.queues[idx] = Some(DeviceQueue::new(q, self.queue_events[idx].clone()));
            }
        }
    }

    /// (Re)start every port's worker threads from the (restored) virtqueues in
    /// `self.queues`. Used after a checkpoint/restore: the restored guest has
    /// already completed the virtio-console port handshake and will not re-issue
    /// the `PORT_OPEN` control messages that start port workers on a fresh boot,
    /// so the device must restart them itself — otherwise the guest hard-spins
    /// in `__send_to_port` writing console output to a queue nobody drains,
    /// wedging the vCPU (and starving every other device, e.g. vsock).
    pub fn start_ports_after_restore(&mut self) {
        let (mem, interrupt) = match &self.device_state {
            DeviceState::Activated(mem, interrupt) => (mem.clone(), interrupt.clone()),
            _ => return,
        };
        for port_id in 0..self.ports.len() {
            if self.ports[port_id].is_active() {
                continue;
            }
            let rx_idx = port_id_to_queue_idx(QueueDirection::Rx, port_id);
            let tx_idx = port_id_to_queue_idx(QueueDirection::Tx, port_id);
            let (Some(rx_dq), Some(tx_dq)) =
                (self.queues[rx_idx].take(), self.queues[tx_idx].take())
            else {
                log::warn!("console: missing queues to restart port {port_id} after restore");
                continue;
            };
            self.ports[port_id].start(
                mem.clone(),
                rx_dq.queue,
                tx_dq.queue,
                interrupt.clone(),
                self.control.clone(),
            );
        }
    }
}

impl VirtioDevice for Console {
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
        uapi::VIRTIO_ID_CONSOLE
    }

    fn device_name(&self) -> &str {
        "console"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &self.queue_config
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
            "console: guest driver attempted to write device config (offset={:x}, len={:x})",
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
        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt");
            return Err(ActivateError::BadActivate);
        }

        self.queue_events = queues.iter().map(|dq| dq.event.clone()).collect();
        self.queues = queues.into_iter().map(Some).collect();
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        // Shutdown ports and clear queues.
        for port in &mut self.ports {
            port.shutdown();
        }
        self.queues.clear();
        self.queue_events.clear();
        self.device_state = DeviceState::Inactive;
        self.snapshot_quiesced = false;
        self.snapshot_error = None;
        self.deferred_events.clear();
        true
    }

    fn quiesce_for_snapshot(&mut self) {
        if self.snapshot_quiesced {
            return;
        }
        self.snapshot_quiesced = true;
        self.quiesce_ports_for_snapshot();
    }

    fn snapshot_error(&self) -> Option<&str> {
        self.snapshot_error.as_deref()
    }

    fn rearm_after_snapshot(&mut self) {
        if !self.snapshot_quiesced {
            return;
        }
        self.snapshot_quiesced = false;
        self.start_ports_after_restore();
        self.replay_deferred_events();
    }

    fn finish_restore_activation(&mut self) -> Result<(), String> {
        self.start_ports_after_restore();
        if self.is_activated() {
            // Guest queue state survives restore, host eventfd counters do not.
            for event in [
                self.queue_events[CONTROL_RXQ_INDEX].as_ref(),
                self.queue_events[CONTROL_TXQ_INDEX].as_ref(),
                self.control.queue_evt(),
            ] {
                if let Err(error) = event.write(1) {
                    error!("console: failed to notify restored control queue: {error}");
                }
            }
        }
        Ok(())
    }
}

impl VmmExitObserver for Console {
    fn on_vmm_exit(&mut self) {
        self.reset();
        log::trace!("Console on_vmm_exit finished");
    }
}

#[cfg(test)]
mod checkpoint_boundary_tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::VirtQueue;
    use polly::event_manager::{EventManager, Subscriber};
    use utils::epoll::{EpollEvent, EventSet};
    use vm_memory::GuestAddress;

    fn active_console(memory: &GuestMemoryMmap) -> (Console, Vec<VirtQueue<'_>>) {
        let mut console = Console::new(vec![PortDescription {
            name: "checkpoint-test".into(),
            input: None,
            output: None,
            terminal: None,
        }])
        .unwrap();
        let rings: Vec<_> = (0..4)
            .map(|index| VirtQueue::new(GuestAddress(0x1000 + index * 0x1000), memory, 8))
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
        console
            .activate(
                memory.clone(),
                InterruptTransport::new(DummyIrqChip::new().into(), "checkpoint test".into())
                    .unwrap(),
                queues,
            )
            .unwrap();
        (console, rings)
    }

    #[test]
    fn checkpoint_rejects_a_lost_console_worker_queue() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let (mut console, _rings) = active_console(&memory);
        console.ports[0].inject_failed_tx_worker();
        console.quiesce_for_snapshot();
        assert!(console.snapshot_error().unwrap().contains("port 0"));
        console.quiesce_for_snapshot();
        assert!(console.snapshot_error().is_some());
        console.reset();
        assert!(console.snapshot_error().is_none());
    }

    #[test]
    fn pending_control_reply_keeps_the_checkpoint_boundary() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let (mut console, rings) = active_console(&memory);
        let ring = &rings[CONTROL_RXQ_INDEX];
        ring.dtable[0].addr.set(0x10000);
        ring.dtable[0].len.set(64);
        ring.dtable[0].flags.set(2);
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        memory
            .write_slice(&[0x55; 64], GuestAddress(0x10000))
            .unwrap();
        console.control.port_add(0);
        console.quiesce_for_snapshot();
        let boundary = console.save_state();
        let event = EpollEvent::new(EventSet::IN, console.control.queue_evt().as_raw_fd() as u64);
        console.process(&event, &mut EventManager::new().unwrap());
        assert_eq!(
            console.save_state(),
            boundary,
            "console control queue advanced after quiescence"
        );
        assert_eq!(ring.used.idx.get(), 0);
        let mut contents = [0; 64];
        memory
            .read_slice(&mut contents, GuestAddress(0x10000))
            .unwrap();
        assert_eq!(contents, [0x55; 64]);
        assert_eq!(
            console.control.queue_evt().read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        console.rearm_after_snapshot();
        console.process(&event, &mut EventManager::new().unwrap());
        assert_eq!(ring.used.idx.get(), 1);
        assert!(console.control.snapshot_pending().is_empty());
        console.rearm_after_snapshot();
        assert_eq!(
            console.control.queue_evt().read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        console.reset();
    }

    #[test]
    fn restored_reply_waits_for_the_guest_to_supply_a_buffer() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let (mut source, _) = active_console(&memory);
        source.control.port_add(0);
        source.quiesce_for_snapshot();
        let state = source.save_state();
        let encoded = serde_json::to_vec(&state).unwrap();
        let decoded: ConsoleState = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(state, decoded);

        let (mut restored, rings) = active_console(&memory);
        restored.restore_state(&decoded).unwrap();
        restored.finish_restore_activation().unwrap();
        let mut manager = EventManager::new().unwrap();
        let event = EpollEvent::new(
            EventSet::IN,
            restored.control.queue_evt().as_raw_fd() as u64,
        );
        restored.process(&event, &mut manager);
        assert_eq!(restored.control.snapshot_pending(), state.pending_control);
        let ring = &rings[CONTROL_RXQ_INDEX];
        ring.dtable[0].addr.set(0x10000);
        ring.dtable[0].len.set(64);
        ring.dtable[0].flags.set(2);
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        let notification = &restored.queue_events[CONTROL_RXQ_INDEX];
        notification.write(1).unwrap();
        let event = EpollEvent::new(EventSet::IN, notification.as_raw_fd() as u64);
        restored.process(&event, &mut manager);
        assert_eq!(ring.used.idx.get(), 1);
        let mut reply = vec![0; state.pending_control[0].len()];
        memory
            .read_slice(&mut reply, GuestAddress(0x10000))
            .unwrap();
        assert_eq!(reply, state.pending_control[0]);
        assert!(restored.control.snapshot_pending().is_empty());
        assert_eq!(source.control.snapshot_pending(), state.pending_control);
        restored.reset();
        source.reset();
    }

    #[test]
    fn restored_port_open_does_not_start_an_active_port_twice() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let (mut console, rings) = active_console(&memory);
        let ring = &rings[CONTROL_TXQ_INDEX];
        memory
            .write_obj(
                VirtioConsoleControl {
                    id: 0,
                    event: control_event::VIRTIO_CONSOLE_PORT_OPEN,
                    value: 1,
                },
                GuestAddress(0x10000),
            )
            .unwrap();
        ring.dtable[0].addr.set(0x10000);
        ring.dtable[0]
            .len
            .set(size_of::<VirtioConsoleControl>() as u32);
        ring.avail.ring[0].set(0);
        ring.avail.idx.set(1);
        console.finish_restore_activation().unwrap();
        assert!(console.ports[0].is_active());
        let event = EpollEvent::new(
            EventSet::IN,
            console.queue_events[CONTROL_TXQ_INDEX].as_raw_fd() as u64,
        );
        console.process(&event, &mut EventManager::new().unwrap());
        assert_eq!(ring.used.idx.get(), 1);
        assert!(console.ports[0].is_active());
        console.reset();
    }

    #[test]
    fn paused_notifications_replay_to_their_original_events() {
        fn assert_send<T: Send>() {}
        assert_send::<Console>();
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let (mut console, _) = active_console(&memory);
        console.quiesce_for_snapshot();
        let mut manager = EventManager::new().unwrap();
        // Exercise both a guest queue and the host control event at the end of
        // the indexed notification list, in reverse order.
        for control in [true, false] {
            let notification = if control {
                console.control.queue_evt()
            } else {
                console.queue_events[CONTROL_TXQ_INDEX].as_ref()
            };
            notification.write(1).unwrap();
            let event = EpollEvent::new(EventSet::IN, notification.as_raw_fd() as u64);
            console.process(&event, &mut manager);
        }
        assert_eq!(console.deferred_events.len(), 2);
        console.rearm_after_snapshot();
        assert_eq!(console.control.queue_evt().read().unwrap(), 1);
        assert_eq!(console.queue_events[CONTROL_TXQ_INDEX].read().unwrap(), 1);
        assert!(console.deferred_events.is_empty());
        console.reset();
    }

    #[test]
    fn repeated_paused_events_are_drained_and_replayed_once() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let (mut console, _) = active_console(&memory);
        console.quiesce_for_snapshot();
        let boundary = console.save_state();
        let mut manager = EventManager::new().unwrap();
        for _ in 0..3 {
            console.quiesce_for_snapshot();
            console.queue_events[CONTROL_TXQ_INDEX].write(1).unwrap();
            let event = EpollEvent::new(
                EventSet::IN,
                console.queue_events[CONTROL_TXQ_INDEX].as_raw_fd() as u64,
            );
            console.process(&event, &mut manager);
            assert_eq!(console.save_state(), boundary);
            assert_eq!(
                console.queue_events[CONTROL_TXQ_INDEX]
                    .read()
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert_eq!(console.deferred_events.len(), 1);
        }
        console.rearm_after_snapshot();
        assert_eq!(console.queue_events[CONTROL_TXQ_INDEX].read().unwrap(), 1);
        console.rearm_after_snapshot();
        assert_eq!(
            console.queue_events[CONTROL_TXQ_INDEX]
                .read()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        console.reset();
        assert!(!console.snapshot_quiesced);
        assert!(console.deferred_events.is_empty());
    }
}
