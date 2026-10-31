use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use devices::legacy::ReadableFd;
use devices::windows_console::ConsoleInputDecoder;
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use utils::windows::{AsRawFd, RawFd};
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::System::Console::{INPUT_RECORD, ReadConsoleInputW};
use windows_sys::Win32::System::Threading::{INFINITE, WaitForMultipleObjects};

struct RxQueue {
    bytes: Mutex<VecDeque<u8>>,
    ready: EventFd,
}

impl RxQueue {
    fn enqueue(&self, bytes: &[u8]) {
        let mut queue = self.bytes.lock().unwrap();
        let was_empty = queue.is_empty();
        queue.extend(bytes);
        if was_empty && let Err(e) = self.ready.write(1) {
            log::error!("failed to signal serial input: {e}");
        }
    }
}

pub struct SerialConsoleInput {
    rx: Arc<RxQueue>,
    stop: EventFd,
    worker: Option<JoinHandle<()>>,
}

impl SerialConsoleInput {
    fn new(input: Option<File>, rx: Arc<RxQueue>) -> io::Result<Self> {
        let stop = EventFd::new(EFD_NONBLOCK)?;
        let worker = input
            .map(|input| {
                let worker_stop = stop.try_clone()?;
                let worker_rx = rx.clone();
                thread::Builder::new()
                    .name("serial console input".into())
                    .spawn(move || console_input_worker(input, worker_rx, worker_stop))
            })
            .transpose()?;
        Ok(Self { rx, stop, worker })
    }
}

impl Read for SerialConsoleInput {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let mut queue = self.rx.bytes.lock().unwrap();
        let count = output.len().min(queue.len());
        for byte in &mut output[..count] {
            *byte = queue.pop_front().unwrap();
        }
        if queue.is_empty() {
            let _ = self.rx.ready.read();
        }
        Ok(count)
    }
}

impl AsRawFd for SerialConsoleInput {
    fn as_raw_fd(&self) -> RawFd {
        self.rx.ready.as_raw_fd()
    }
}

impl ReadableFd for SerialConsoleInput {}

impl Drop for SerialConsoleInput {
    fn drop(&mut self) {
        let _ = self.stop.write(1);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub struct SerialConsoleOutput {
    output: File,
    rx: Arc<RxQueue>,
    query: VecDeque<u8>,
    is_non_interactive: bool,
}

impl Write for SerialConsoleOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.write_all(bytes)?;
        for &byte in bytes {
            self.process_output_byte(byte);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

impl SerialConsoleOutput {
    fn process_output_byte(&mut self, byte: u8) {
        self.query.push_back(byte);
        if self.query.len() > 128 {
            self.query.pop_front();
        }

        if byte != b'n' && byte != b'\\' {
            return;
        }

        let query = self.query.make_contiguous();
        if query.ends_with(b"\x1b[6n") {
            self.query.clear();
            if self.is_non_interactive {
                self.rx.enqueue(b"\x1b[24;80R");
            }
            return;
        }

        if !query.ends_with(b"\x1b\\") {
            return;
        }

        if let Some(start) = query.windows(4).position(|window| window == b"\x1bP+q") {
            let end = query.len().saturating_sub(2);
            if start + 4 <= end {
                let capability = &query[start + 4..end];
                let mut response = b"\x1bP1+r".to_vec();
                response.extend_from_slice(capability);
                response.extend_from_slice(b"=7674313030\x1b\\");
                self.rx.enqueue(&response);
            }
        }
        self.query.clear();
    }
}

pub fn serial_console_bridge(
    input: Option<File>,
    output: File,
    is_non_interactive: bool,
) -> io::Result<(Box<dyn ReadableFd + Send>, Box<dyn Write + Send>)> {
    let rx = Arc::new(RxQueue {
        bytes: Mutex::new(VecDeque::new()),
        ready: EventFd::new(EFD_NONBLOCK)?,
    });
    let input = SerialConsoleInput::new(input, rx.clone())?;
    let output = SerialConsoleOutput {
        output,
        rx,
        query: VecDeque::new(),
        is_non_interactive,
    };
    Ok((Box::new(input), Box::new(output)))
}

fn console_input_worker(input: File, rx: Arc<RxQueue>, stop: EventFd) {
    let handles = [input.as_raw_handle(), stop.as_raw_fd() as RawHandle];
    let mut decoder = ConsoleInputDecoder::default();
    loop {
        let result = unsafe {
            WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), FALSE, INFINITE)
        };
        if result == 1 {
            return;
        }
        if result != 0 {
            log::error!(
                "failed waiting for serial console input: {}",
                io::Error::last_os_error()
            );
            return;
        }

        let mut records: [INPUT_RECORD; 64] = std::array::from_fn(|_| INPUT_RECORD::default());
        let mut record_count = 0;
        if unsafe {
            ReadConsoleInputW(
                input.as_raw_handle(),
                records.as_mut_ptr(),
                records.len() as u32,
                &mut record_count,
            )
        } == 0
        {
            log::error!(
                "failed reading serial console input: {}",
                io::Error::last_os_error()
            );
            return;
        }

        let bytes = decoder.decode(&records[..record_count as usize]);
        if !bytes.is_empty() {
            rx.enqueue(&bytes);
        }
    }
}
