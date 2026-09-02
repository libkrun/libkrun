use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::{mem, thread};

use vm_memory::GuestMemoryMmap;

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::port_io::{PortInput, PortOutput};
use crate::virtio::console::process_rx::process_rx;
use crate::virtio::console::process_tx::process_tx;
use crate::virtio::port_io::PortTerminalProperties;
use crate::virtio::{InterruptTransport, Queue};

pub struct PortDescription {
    pub name: Cow<'static, str>,
    pub input: Option<Box<dyn PortInput + Send>>,
    pub output: Option<Box<dyn PortOutput + Send>>,
    pub terminal: Option<Box<dyn PortTerminalProperties>>,
}

impl PortDescription {
    pub fn console(
        input: Option<Box<dyn PortInput + Send>>,
        output: Option<Box<dyn PortOutput + Send>>,
        terminal: Box<dyn PortTerminalProperties>,
    ) -> Self {
        Self {
            name: "".into(),
            input,
            output,
            terminal: Some(terminal),
        }
    }

    pub fn output_pipe(
        name: impl Into<Cow<'static, str>>,
        output: Box<dyn PortOutput + Send>,
    ) -> Self {
        Self {
            name: name.into(),
            input: None,
            output: Some(output),
            terminal: None,
        }
    }

    pub fn input_pipe(
        name: impl Into<Cow<'static, str>>,
        input: Box<dyn PortInput + Send>,
    ) -> Self {
        Self {
            name: name.into(),
            input: Some(input),
            output: None,
            terminal: None,
        }
    }
}

enum PortState {
    Inactive,
    Active {
        stopfd: utils::eventfd::EventFd,
        stop: Arc<AtomicBool>,
        rx_thread: Option<JoinHandle<Queue>>,
        tx_thread: Option<JoinHandle<Queue>>,
        // Queues for a direction with no backing fd (an output-only port has no
        // rx thread). Kept, not dropped, so a snapshot recovers every queue.
        idle_rx: Option<Queue>,
        idle_tx: Option<Queue>,
    },
}

pub(crate) struct Port {
    port_id: u32,
    /// Empty if no name given
    name: Cow<'static, str>,
    state: PortState,
    input: Option<Arc<Mutex<Box<dyn PortInput + Send>>>>,
    output: Option<Arc<Mutex<Box<dyn PortOutput + Send>>>>,
    terminal: Option<Box<dyn PortTerminalProperties>>,
}

impl Port {
    pub(crate) fn new(port_id: u32, description: PortDescription) -> Self {
        Self {
            port_id,
            name: description.name,
            state: PortState::Inactive,
            input: description.input.map(|input| Arc::new(Mutex::new(input))),
            output: description
                .output
                .map(|output| Arc::new(Mutex::new(output))),
            terminal: description.terminal,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn terminal(&self) -> Option<&dyn PortTerminalProperties> {
        self.terminal.as_deref()
    }

    /// Whether the port's I/O threads are running (i.e. the guest opened it).
    pub fn is_active(&self) -> bool {
        matches!(self.state, PortState::Active { .. })
    }

    pub fn notify_rx(&self) {
        if let PortState::Active {
            rx_thread: Some(handle),
            ..
        } = &self.state
        {
            handle.thread().unpark()
        }
    }

    pub fn notify_tx(&self) {
        if let PortState::Active {
            tx_thread: Some(handle),
            ..
        } = &self.state
        {
            handle.thread().unpark()
        }
    }

    pub fn start(
        &mut self,
        mem: GuestMemoryMmap,
        rx_queue: Queue,
        tx_queue: Queue,
        interrupt: InterruptTransport,
        control: Arc<ConsoleControl>,
    ) {
        if let PortState::Active { .. } = &mut self.state {
            let _ = self.shutdown();
        };

        let input = self.input.as_ref().cloned();
        let output = self.output.as_ref().cloned();

        let stopfd = utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK)
            .expect("Failed to create EventFd for interrupt_evt");
        let stop = Arc::new(AtomicBool::new(false));

        let mut idle_rx = None;
        let rx_thread = match input {
            Some(input) => {
                let mem = mem.clone();
                let interrupt = interrupt.clone();
                let port_id = self.port_id;
                let stopfd = stopfd.try_clone().unwrap();
                let stop = stop.clone();
                Some(
                    thread::Builder::new()
                        .name("console port".into())
                        .spawn(move || {
                            process_rx(
                                mem, rx_queue, interrupt, input, control, port_id, stopfd, stop,
                            )
                        })
                        .unwrap(),
                )
            }
            None => {
                idle_rx = Some(rx_queue);
                None
            }
        };

        let mut idle_tx = None;
        let tx_thread = match output {
            Some(output) => {
                let stop = stop.clone();
                let stopfd = stopfd.try_clone().unwrap();
                Some(thread::spawn(move || {
                    process_tx(mem, tx_queue, interrupt, output, stopfd, stop)
                }))
            }
            None => {
                idle_tx = Some(tx_queue);
                None
            }
        };

        self.state = PortState::Active {
            stopfd,
            stop,
            rx_thread,
            tx_thread,
            idle_rx,
            idle_tx,
        }
    }

    /// Stops the port's I/O threads and returns the queues they owned (each
    /// `Option` since a port may have only one direction).
    pub fn shutdown(&mut self) -> PortQueues {
        let mut queues = PortQueues::default();
        if let PortState::Active {
            stopfd,
            stop,
            tx_thread,
            rx_thread,
            idle_rx,
            idle_tx,
        } = &mut self.state
        {
            queues.rx = idle_rx.take();
            queues.tx = idle_tx.take();
            // Signal both wakeup paths before joining: the flag for the
            // queue-pop park, and the stopfd for a tx thread blocked on a full
            // output fd. Writing the stopfd after the tx join would deadlock.
            stop.store(true, Ordering::Release);
            stopfd.write(1).unwrap();
            if let Some(tx_thread) = mem::take(tx_thread) {
                tx_thread.thread().unpark();
                match tx_thread.join() {
                    Ok(queue) => queues.tx = Some(queue),
                    Err(e) => log::error!(
                        "Failed to flush tx for port {port_id}, thread panicked: {e:?}",
                        port_id = self.port_id
                    ),
                }
            }
            if let Some(rx_thread) = mem::take(rx_thread) {
                rx_thread.thread().unpark();
                match rx_thread.join() {
                    Ok(queue) => queues.rx = Some(queue),
                    Err(e) => log::error!(
                        "Failed to flush rx for port {port_id}, thread panicked: {e:?}",
                        port_id = self.port_id
                    ),
                }
            }
        };
        self.state = PortState::Inactive;
        queues
    }
}

/// The queues an active port's I/O threads owned, handed back on shutdown.
#[derive(Default)]
pub(crate) struct PortQueues {
    pub rx: Option<Queue>,
    pub tx: Option<Queue>,
}
