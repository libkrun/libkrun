use std::cmp;
use std::io::Write;
use std::iter::zip;
use std::mem::size_of;
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
use crate::virtio::descriptor_utils::Reader;
use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::virtio::{DescriptorChain, InterruptTransport, PortDescription, VmmExitObserver};

pub(crate) const CONTROL_RXQ_INDEX: usize = 2;
pub(crate) const CONTROL_TXQ_INDEX: usize = 3;

fn read_control_command(
    mem: &GuestMemoryMmap,
    head: DescriptorChain<'_>,
) -> Option<VirtioConsoleControl> {
    let mut descriptor = Some(head.clone());
    let mut descriptor_indices = Vec::new();
    let mut readable_len = 0usize;

    while let Some(current) = descriptor {
        if descriptor_indices.contains(&current.index) {
            log::error!("Console control descriptor chain contains a loop");
            return None;
        }
        descriptor_indices.push(current.index);

        if current.flags & !(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE) != 0 {
            log::error!("Console control transmit chain uses unsupported descriptor flags");
            return None;
        }

        if current.is_write_only() {
            log::error!("Console control transmit chain contains a writable descriptor");
            return None;
        }

        readable_len = match readable_len.checked_add(current.len as usize) {
            Some(len) => len,
            None => {
                log::error!("Console control descriptor length overflow");
                return None;
            }
        };

        let has_next = current.flags & VIRTQ_DESC_F_NEXT != 0;
        descriptor = current.next_descriptor();
        if has_next && descriptor.is_none() {
            log::error!("Malformed console control descriptor chain");
            return None;
        }
    }

    if readable_len != size_of::<VirtioConsoleControl>() {
        log::error!(
            "Invalid console control payload length: expected {}, got {readable_len}",
            size_of::<VirtioConsoleControl>()
        );
        return None;
    }

    let mut reader = match Reader::new(mem, head) {
        Ok(reader) => reader,
        Err(e) => {
            log::error!("Invalid console control descriptor memory: {e}");
            return None;
        }
    };
    match reader.read_obj() {
        Ok(command) => Some(command),
        Err(e) => {
            log::error!("Failed to read console control payload: {e}");
            None
        }
    }
}

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

            let head_index = head.index;
            let cmd = read_control_command(mem, head);
            if let Err(e) = control_tx.queue.add_used(mem, head_index, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }
            let Some(cmd) = cmd else {
                continue;
            };

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
                    let Some(port) = self.ports.get(cmd.id as usize) else {
                        log::warn!("Guest reported unknown console port {} ready", cmd.id);
                        continue;
                    };

                    if cmd.value != 1 {
                        log::error!("Port initialization failed: {cmd:?}");
                        continue;
                    }

                    if let Some(term) = port.terminal() {
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

                    let name = port.name();
                    log::trace!("Port ready {id}: {name}", id = cmd.id);
                    if !name.is_empty() {
                        self.control.port_name(cmd.id, name)
                    }
                }
                control_event::VIRTIO_CONSOLE_PORT_OPEN => {
                    let Some(port_id) =
                        ((cmd.id as usize) < self.ports.len()).then_some(cmd.id as usize)
                    else {
                        log::warn!("Guest reported unknown console port {} open", cmd.id);
                        continue;
                    };

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

                    ports_to_start.push(port_id);
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use utils::eventfd::EventFd;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::console::console_control::Payload;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

    const QUEUE_SIZE: u16 = 8;
    const CONTROL_ADDR: u64 = 0x4000;

    struct ProcessResult {
        console: Console,
        raised_irq: bool,
        used_index: u16,
        used_id: u32,
        used_len: u32,
    }

    fn process_control_chain(
        command: VirtioConsoleControl,
        descriptors: &[(u64, u32, u16, u16)],
    ) -> ProcessResult {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let queues = [0, 0x400, 0x800, 0xc00]
            .map(|start| VirtQueue::new(GuestAddress(start), &mem, QUEUE_SIZE));

        let command_bytes = command.as_slice();
        let mut command_offset = 0;
        for (index, &(addr, len, flags, next)) in descriptors.iter().enumerate() {
            queues[CONTROL_TXQ_INDEX].dtable[index].set(addr, len, flags, next);
            if flags & VIRTQ_DESC_F_WRITE == 0 && command_offset < command_bytes.len() {
                let write_len = usize::min(len as usize, command_bytes.len() - command_offset);
                if mem
                    .write(
                        &command_bytes[command_offset..command_offset + write_len],
                        GuestAddress(addr),
                    )
                    .is_ok()
                {
                    command_offset += write_len;
                }
            }
        }
        queues[CONTROL_TXQ_INDEX].avail.ring[0].set(0);
        queues[CONTROL_TXQ_INDEX].avail.idx.set(1);

        let device_queues = queues
            .iter()
            .map(|queue| {
                DeviceQueue::new(
                    queue.create_queue(),
                    Arc::new(EventFd::new(0).expect("create queue event")),
                )
            })
            .collect();
        let interrupt = InterruptTransport::new(DummyIrqChip::new().into(), "test".into())
            .expect("create interrupt transport");
        let mut console = Console::new(vec![PortDescription {
            name: "test".into(),
            input: None,
            output: None,
            terminal: None,
        }])
        .unwrap();
        console
            .activate(mem.clone(), interrupt, device_queues)
            .unwrap();

        let raised_irq = console.process_control_tx();
        let used_index = queues[CONTROL_TXQ_INDEX].used.idx.get();
        assert!(!console.process_control_tx());
        assert_eq!(queues[CONTROL_TXQ_INDEX].used.idx.get(), used_index);

        let used = queues[CONTROL_TXQ_INDEX].used.ring[0].get();
        ProcessResult {
            console,
            raised_irq,
            used_index,
            used_id: used.id,
            used_len: used.len,
        }
    }

    #[test]
    fn unknown_port_ids_are_completed_without_side_effects() {
        for event in [
            control_event::VIRTIO_CONSOLE_PORT_READY,
            control_event::VIRTIO_CONSOLE_PORT_OPEN,
        ] {
            for id in [1, u32::MAX] {
                let command = VirtioConsoleControl {
                    id,
                    event,
                    value: 1,
                };
                let result = process_control_chain(
                    command,
                    &[(CONTROL_ADDR, size_of::<VirtioConsoleControl>() as u32, 0, 0)],
                );

                assert!(result.raised_irq);
                assert_eq!(result.used_index, 1);
                assert_eq!(result.used_id, 0);
                assert_eq!(result.used_len, 0);
                assert!(result.console.queues.iter().all(Option::is_some));
                assert!(result.console.control.queue_pop().is_none());
            }
        }
    }

    #[test]
    fn valid_control_chains_are_processed() {
        let command = VirtioConsoleControl {
            id: 0,
            event: control_event::VIRTIO_CONSOLE_DEVICE_READY,
            value: 1,
        };
        let chains = [
            ("contiguous", vec![(CONTROL_ADDR, 8, 0, 0)]),
            (
                "split",
                vec![
                    (CONTROL_ADDR, 3, VIRTQ_DESC_F_NEXT, 1),
                    (CONTROL_ADDR + 0x100, 5, 0, 0),
                ],
            ),
        ];

        for (name, chain) in chains {
            let result = process_control_chain(command, &chain);

            assert!(result.raised_irq, "{name}");
            assert_eq!(result.used_index, 1, "{name}");
            assert_eq!(result.used_id, 0, "{name}");
            assert_eq!(result.used_len, 0, "{name}");
            let Some(Payload::ConsoleControl(response)) = result.console.control.queue_pop() else {
                panic!("expected port-add response");
            };
            let response_id = response.id;
            let response_event = response.event;
            assert_eq!(response_id, 0);
            assert_eq!(response_event, control_event::VIRTIO_CONSOLE_PORT_ADD);
            assert!(result.console.control.queue_pop().is_none());
        }
    }

    #[test]
    fn invalid_control_chains_are_completed_without_side_effects() {
        let command = VirtioConsoleControl {
            id: 0,
            event: control_event::VIRTIO_CONSOLE_PORT_READY,
            value: 1,
        };
        let chains = [
            ("short", vec![(CONTROL_ADDR, 7, 0, 0)]),
            ("trailing payload", vec![(CONTROL_ADDR, 9, 0, 0)]),
            ("write only", vec![(CONTROL_ADDR, 8, VIRTQ_DESC_F_WRITE, 0)]),
            (
                "mixed direction",
                vec![
                    (CONTROL_ADDR, 4, VIRTQ_DESC_F_NEXT, 1),
                    (CONTROL_ADDR + 0x100, 4, VIRTQ_DESC_F_WRITE, 0),
                ],
            ),
            ("invalid first range", vec![(0x10000, 8, 0, 0)]),
            (
                "invalid second range",
                vec![(CONTROL_ADDR, 4, VIRTQ_DESC_F_NEXT, 1), (0x10000, 4, 0, 0)],
            ),
            (
                "loop",
                vec![
                    (CONTROL_ADDR, 4, VIRTQ_DESC_F_NEXT, 1),
                    (CONTROL_ADDR + 0x100, 4, VIRTQ_DESC_F_NEXT, 0),
                ],
            ),
            ("oversized length", vec![(CONTROL_ADDR, u32::MAX, 0, 0)]),
            ("unsupported flags", vec![(CONTROL_ADDR, 8, 4, 0)]),
        ];

        for (name, chain) in chains {
            let result = process_control_chain(command, &chain);

            assert!(result.raised_irq, "{name}");
            assert_eq!(result.used_index, 1, "{name}");
            assert_eq!(result.used_id, 0, "{name}");
            assert_eq!(result.used_len, 0, "{name}");
            assert!(result.console.queues.iter().all(Option::is_some), "{name}");
            assert!(result.console.control.queue_pop().is_none(), "{name}");
        }
    }

    #[test]
    fn malformed_control_head_has_no_side_effects() {
        let command = VirtioConsoleControl {
            id: 0,
            event: control_event::VIRTIO_CONSOLE_PORT_READY,
            value: 1,
        };
        let result =
            process_control_chain(command, &[(CONTROL_ADDR, 8, VIRTQ_DESC_F_NEXT, QUEUE_SIZE)]);

        assert!(!result.raised_irq);
        assert_eq!(result.used_index, 0);
        assert!(result.console.queues.iter().all(Option::is_some));
        assert!(result.console.control.queue_pop().is_none());
    }
}
