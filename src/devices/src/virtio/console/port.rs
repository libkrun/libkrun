use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::{mem, thread};

use vm_memory::GuestMemoryMmap;

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::port_io::{PortInput, PortOutput};
use crate::virtio::console::process_rx::{RxExit, process_rx};
use crate::virtio::console::process_tx::{TxExit, process_tx};
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
    /// Worker threads are running normally.
    Active {
        stopfd: utils::eventfd::EventFd,
        stop: Arc<AtomicBool>,
        pausefd: utils::eventfd::EventFd,
        pause: Arc<AtomicBool>,
        rx_thread: Option<JoinHandle<RxExit>>,
        tx_thread: Option<JoinHandle<TxExit>>,
        // Holds the rx/tx queue directly (instead of via a worker thread) when
        // the port has no input/output configured for that direction, so the
        // queue can still be recovered by `shutdown()`/`pause()` and handed
        // back to the device, rather than being silently dropped.
        idle_rx_queue: Option<Queue>,
        idle_tx_queue: Option<Queue>,
    },
    /// The guest closed the port while the VM keeps running: worker threads
    /// have exited without draining further, and the rx/tx queues are held
    /// here (not handed back to the device) until the guest reopens the
    /// port (`resume()`) or the VM shuts down (`shutdown()`).
    Paused {
        rx_queue: Option<Queue>,
        tx_queue: Option<Queue>,
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
        if !matches!(self.state, PortState::Inactive) {
            self.shutdown();
        };

        self.start_with_queues(mem, rx_queue, tx_queue, interrupt, control);
    }

    fn start_with_queues(
        &mut self,
        mem: GuestMemoryMmap,
        rx_queue: Queue,
        tx_queue: Queue,
        interrupt: InterruptTransport,
        control: Arc<ConsoleControl>,
    ) {
        let input = self.input.as_ref().cloned();
        let output = self.output.as_ref().cloned();

        let stopfd = utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK)
            .expect("Failed to create EventFd for interrupt_evt");
        let stop = Arc::new(AtomicBool::new(false));
        let pausefd = utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK)
            .expect("Failed to create EventFd for pause signaling");
        let pause = Arc::new(AtomicBool::new(false));

        // Ports without input/output never get a worker thread for that
        // direction, so the queue handed to us would otherwise be silently
        // dropped. Stash it directly so `shutdown()`/`pause()` can still
        // hand it back.
        let mut idle_rx_queue = None;
        let rx_thread = match input {
            Some(input) => {
                let mem = mem.clone();
                let interrupt = interrupt.clone();
                let port_id = self.port_id;
                let stopfd_clone = stopfd.try_clone().unwrap();
                let stop = stop.clone();
                let pausefd_clone = pausefd.try_clone().unwrap();
                let pause = pause.clone();
                Some(
                    thread::Builder::new()
                        .name("console port".into())
                        .spawn(move || {
                            process_rx(
                                mem,
                                rx_queue,
                                interrupt,
                                input,
                                control,
                                port_id,
                                stopfd_clone,
                                stop,
                                pausefd_clone,
                                pause,
                            )
                        })
                        .unwrap(),
                )
            }
            None => {
                idle_rx_queue = Some(rx_queue);
                None
            }
        };

        let mut idle_tx_queue = None;
        let tx_thread = match output {
            Some(output) => {
                let stop = stop.clone();
                let pausefd_clone = pausefd.try_clone().unwrap();
                let pause = pause.clone();
                Some(thread::spawn(move || {
                    process_tx(mem, tx_queue, interrupt, output, stop, pausefd_clone, pause)
                }))
            }
            None => {
                idle_tx_queue = Some(tx_queue);
                None
            }
        };

        self.state = PortState::Active {
            stopfd,
            stop,
            pausefd,
            pause,
            rx_thread,
            tx_thread,
            idle_rx_queue,
            idle_tx_queue,
        }
    }

    /// Shuts down the port's worker threads (if active), and returns the
    /// rx/tx queues so the caller (the `Console` device) can hand them back
    /// into its own queue slots, making the port eligible to be `start()`-ed
    /// again if the guest reopens it. Returns `None` for a port that was
    /// already inactive.
    pub fn shutdown(&mut self) -> Option<(Queue, Queue)> {
        match &mut self.state {
            PortState::Inactive => None,
            PortState::Paused { rx_queue, tx_queue } => {
                let queues = match (mem::take(rx_queue), mem::take(tx_queue)) {
                    (Some(rx_queue), Some(tx_queue)) => Some((rx_queue, tx_queue)),
                    _ => None,
                };
                self.state = PortState::Inactive;
                queues
            }
            PortState::Active {
                stopfd,
                stop,
                tx_thread,
                rx_thread,
                idle_rx_queue,
                idle_tx_queue,
                ..
            } => {
                stop.store(true, Ordering::Release);
                // Write stopfd before joining any thread: a worker may be
                // parked in a poll() that watches stopfd (e.g. TX's
                // wait_until_writable), so writing it only has to happen
                // once here, before either join below.
                stopfd.write(1).unwrap();

                let tx_queue = if let Some(tx_thread) = mem::take(tx_thread) {
                    tx_thread.thread().unpark();
                    match tx_thread.join() {
                        Ok(TxExit::Stopped(queue) | TxExit::Paused(queue)) => Some(queue),
                        Err(e) => {
                            log::error!(
                                "Failed to flush tx for port {port_id}, thread panicked: {e:?}",
                                port_id = self.port_id
                            );
                            None
                        }
                    }
                } else {
                    mem::take(idle_tx_queue)
                };

                let rx_queue = if let Some(rx_thread) = mem::take(rx_thread) {
                    rx_thread.thread().unpark();
                    match rx_thread.join() {
                        Ok(RxExit::Stopped(queue) | RxExit::Paused(queue)) => Some(queue),
                        Err(e) => {
                            log::error!(
                                "Failed to flush rx for port {port_id}, thread panicked: {e:?}",
                                port_id = self.port_id
                            );
                            None
                        }
                    }
                } else {
                    mem::take(idle_rx_queue)
                };

                self.state = PortState::Inactive;

                match (rx_queue, tx_queue) {
                    (Some(rx_queue), Some(tx_queue)) => Some((rx_queue, tx_queue)),
                    _ => {
                        log::error!(
                            "Failed to recover rx/tx queue for port {port_id} on shutdown (worker thread panicked); port will stay unusable until the VM restarts",
                            port_id = self.port_id
                        );
                        None
                    }
                }
            }
        }
    }

    /// Pauses the port in response to a guest-initiated close
    /// (`VIRTIO_CONSOLE_PORT_OPEN(0)`) while the VM keeps running. Unlike
    /// `shutdown()`, this does not wait for buffered output to be drained
    /// to a backpressured/non-responsive sink: worker threads are signaled
    /// to stop at their next safe point and are joined promptly, without
    /// blocking on host I/O. The rx/tx queues are kept inside the port
    /// (not handed back to the caller) so a subsequent `resume()` can pick
    /// up with them directly. A no-op if the port is already `Inactive` or
    /// `Paused`.
    pub fn pause(&mut self) {
        let PortState::Active {
            pausefd,
            pause,
            tx_thread,
            rx_thread,
            idle_rx_queue,
            idle_tx_queue,
            ..
        } = &mut self.state
        else {
            return;
        };

        pause.store(true, Ordering::Release);
        // Write pausefd before joining any thread, for the same reason as
        // in `shutdown()`.
        pausefd.write(1).unwrap();

        let tx_queue = if let Some(tx_thread) = mem::take(tx_thread) {
            tx_thread.thread().unpark();
            match tx_thread.join() {
                Ok(TxExit::Stopped(queue) | TxExit::Paused(queue)) => Some(queue),
                Err(e) => {
                    log::error!(
                        "Failed to pause tx for port {port_id}, thread panicked: {e:?}",
                        port_id = self.port_id
                    );
                    None
                }
            }
        } else {
            mem::take(idle_tx_queue)
        };

        let rx_queue = if let Some(rx_thread) = mem::take(rx_thread) {
            rx_thread.thread().unpark();
            match rx_thread.join() {
                Ok(RxExit::Stopped(queue) | RxExit::Paused(queue)) => Some(queue),
                Err(e) => {
                    log::error!(
                        "Failed to pause rx for port {port_id}, thread panicked: {e:?}",
                        port_id = self.port_id
                    );
                    None
                }
            }
        } else {
            mem::take(idle_rx_queue)
        };

        self.state = PortState::Paused { rx_queue, tx_queue };
    }

    /// Returns `true` if the port is currently `Paused` (i.e. the guest
    /// closed it while the VM kept running, and it has not been reopened
    /// or shut down since).
    pub fn is_paused(&self) -> bool {
        matches!(self.state, PortState::Paused { .. })
    }

    /// Resumes a `Paused` port in response to a guest-initiated reopen
    /// (`VIRTIO_CONSOLE_PORT_OPEN(1)`): respawns worker threads using the
    /// queues that were held while paused, picking back up where
    /// processing left off, without needing fresh queues from the caller.
    /// A no-op if the port is not currently `Paused`.
    pub fn resume(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        control: Arc<ConsoleControl>,
    ) {
        let PortState::Paused { rx_queue, tx_queue } = &mut self.state else {
            return;
        };
        let (Some(rx_queue), Some(tx_queue)) = (mem::take(rx_queue), mem::take(tx_queue)) else {
            log::error!(
                "Failed to resume port {port_id}: rx/tx queue missing from paused state",
                port_id = self.port_id
            );
            self.state = PortState::Inactive;
            return;
        };

        self.start_with_queues(mem, rx_queue, tx_queue, interrupt, control);
    }
}
