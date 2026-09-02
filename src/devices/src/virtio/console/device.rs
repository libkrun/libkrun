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
    ActivateError, ActivateResult, DeviceQueue, DeviceState, PauseError, QueueConfig, VirtioDevice,
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
    // Ports the guest had open at snapshot. A restored guest won't re-send
    // PORT_OPEN, so this is the only record of which to restart.
    open_ports: Vec<bool>,
    // TODO: move the queue event handling to the correct threads!
    pub(crate) queue_events: Vec<Arc<EventFd>>,

    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,

    pub(crate) activate_evt: EventFd,
    pub(crate) sigwinch_evt: EventFd,

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
            open_ports: Vec::new(),
            queue_events: Vec::new(),
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(super::ConsoleError::EventFd)?,
            sigwinch_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(super::ConsoleError::EventFd)?,
            device_state: DeviceState::Inactive,
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

    /// Stop the ports' I/O threads and take their queues back — the threads own
    /// the live indices.
    fn pause(&mut self) -> std::result::Result<Vec<DeviceQueue>, PauseError> {
        if !self.device_state.is_activated() {
            return Ok(Vec::new());
        }
        self.open_ports = self.ports.iter().map(|p| p.is_active()).collect();

        for port_id in 0..self.ports.len() {
            let recovered = self.ports[port_id].shutdown();
            let rx_idx = port_id_to_queue_idx(QueueDirection::Rx, port_id);
            let tx_idx = port_id_to_queue_idx(QueueDirection::Tx, port_id);
            if let Some(queue) = recovered.rx {
                self.queues[rx_idx] =
                    Some(DeviceQueue::new(queue, self.queue_events[rx_idx].clone()));
            }
            if let Some(queue) = recovered.tx {
                self.queues[tx_idx] =
                    Some(DeviceQueue::new(queue, self.queue_events[tx_idx].clone()));
            }
        }

        let mut queues = Vec::with_capacity(self.queues.len());
        for (i, slot) in self.queues.iter_mut().enumerate() {
            let queue = slot.take().ok_or_else(|| {
                PauseError::Failed(format!("virtio_console queue {i} was not recovered"))
            })?;
            queues.push(queue);
        }
        Ok(queues)
    }

    /// One byte per port: whether the guest had it open. Always full width, even
    /// if never activated (then `open_ports` is empty = nothing open).
    fn save_state(&self) -> Vec<u8> {
        (0..self.ports.len())
            .map(|i| self.open_ports.get(i).copied().unwrap_or(false) as u8)
            .collect()
    }

    fn restore_state(&mut self, state: &[u8]) -> std::result::Result<(), crate::Error> {
        if state.len() != self.ports.len() {
            return Err(crate::Error::Snapshot(format!(
                "virtio_console: snapshot has {} ports, config has {}",
                state.len(),
                self.ports.len()
            )));
        }
        self.open_ports = state.iter().map(|&b| b != 0).collect();
        Ok(())
    }

    /// Bring the device back up, restarting only the ports the guest had open —
    /// starting a closed port would consume the queue its later PORT_OPEN needs.
    fn resume(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        // activate signals `activate_evt`, which makes the event loop watch our
        // queue eventfds; without it the guest's kick is never seen.
        self.activate(mem.clone(), interrupt.clone(), queues)?;

        for port_id in 0..self.ports.len() {
            if !self.open_ports.get(port_id).copied().unwrap_or(false) {
                continue;
            }
            let rx_idx = port_id_to_queue_idx(QueueDirection::Rx, port_id);
            let tx_idx = port_id_to_queue_idx(QueueDirection::Tx, port_id);
            let (Some(rx), Some(tx)) = (self.queues[rx_idx].take(), self.queues[tx_idx].take())
            else {
                continue;
            };
            self.ports[port_id].start(
                mem.clone(),
                rx.queue,
                tx.queue,
                interrupt.clone(),
                self.control.clone(),
            );
        }
        Ok(())
    }

    fn reset(&mut self) -> bool {
        // Shutdown ports and clear queues.
        for port in &mut self.ports {
            port.shutdown();
        }
        self.queues.clear();
        self.queue_events.clear();
        self.device_state = DeviceState::Inactive;
        true
    }
}

impl VmmExitObserver for Console {
    fn on_vmm_exit(&mut self) {
        self.reset();
        log::trace!("Console on_vmm_exit finished");
    }
}
