use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use devices::legacy::ReadableFd;
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use utils::windows::{AsRawFd, RawFd};
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::System::Console::{
    INPUT_RECORD, KEY_EVENT, LEFT_ALT_PRESSED, LEFT_CTRL_PRESSED, RIGHT_ALT_PRESSED,
    RIGHT_CTRL_PRESSED, ReadConsoleInputW, SHIFT_PRESSED,
};
use windows_sys::Win32::System::Threading::{INFINITE, WaitForMultipleObjects};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    VK_DELETE, VK_DOWN, VK_END, VK_F1, VK_F2, VK_F3, VK_F4, VK_F5, VK_F6, VK_F7, VK_F8, VK_F9,
    VK_F10, VK_F11, VK_F12, VK_HOME, VK_INSERT, VK_LEFT, VK_NEXT, VK_PRIOR, VK_RIGHT, VK_SPACE,
    VK_TAB, VK_UP,
};

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
    let mut utf16 = Vec::new();
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

        let mut bytes = Vec::new();
        for record in &records[..record_count as usize] {
            if record.EventType != KEY_EVENT as u16 {
                continue;
            }

            let key = unsafe { record.Event.KeyEvent };
            if key.bKeyDown != 0 {
                // it extracts UTF-16 character and encodes it as UTF-8
                let character = unsafe { key.uChar.UnicodeChar };
                if key.wVirtualKeyCode == VK_TAB && key.dwControlKeyState & SHIFT_PRESSED != 0 {
                    append_utf16(&mut bytes, &mut utf16, false, false);
                    append_shift_tab(&mut bytes, key.wRepeatCount);
                } else if character != 0 {
                    let alt_pressed =
                        key.dwControlKeyState & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED) != 0;
                    let alt_gr_pressed = key.dwControlKeyState
                        & (LEFT_CTRL_PRESSED | RIGHT_ALT_PRESSED)
                        == (LEFT_CTRL_PRESSED | RIGHT_ALT_PRESSED);
                    if alt_pressed && !alt_gr_pressed {
                        utf16.extend(std::iter::repeat_n(character, key.wRepeatCount as usize));
                        append_utf16(&mut bytes, &mut utf16, true, true);
                    } else {
                        utf16.extend(std::iter::repeat_n(character, key.wRepeatCount as usize));
                    }
                } else if key.wVirtualKeyCode == VK_SPACE
                    && key.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0
                {
                    append_utf16(&mut bytes, &mut utf16, false, false);
                    bytes.extend(std::iter::repeat_n(0, key.wRepeatCount as usize));
                } else {
                    append_utf16(&mut bytes, &mut utf16, false, false);
                    append_virtual_key(
                        &mut bytes,
                        key.wVirtualKeyCode,
                        key.dwControlKeyState,
                        key.wRepeatCount,
                    );
                }
            }
        }
        append_utf16(&mut bytes, &mut utf16, false, true);
        if !bytes.is_empty() {
            rx.enqueue(&bytes);
        }
    }
}

// This converts UTF-16 text to UTF-8 encoded text, and appends the result to the given buffer
fn append_utf16(bytes: &mut Vec<u8>, utf16: &mut Vec<u16>, escape: bool, retain_trailing: bool) {
    let end =
        utf16.len() - usize::from(retain_trailing && matches!(utf16.last(), Some(0xd800..=0xdbff)));
    for character in char::decode_utf16(utf16.drain(..end)) {
        let character = character.unwrap_or(char::REPLACEMENT_CHARACTER);
        let mut encoded = [0; 4];
        if escape {
            bytes.push(b'\x1b');
        }
        bytes.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
    }
}

// This converts Windows virtual key events (like arrow keys, function keys, and navigation keys)
// into ANSI/xterm escape sequences that Linux/POSIX terminal programs understand and
// appends them to the given buffer.
fn append_virtual_key(bytes: &mut Vec<u8>, key: u16, state: u32, repeat: u16) {
    let modifier = 1
        + u8::from(state & SHIFT_PRESSED != 0)
        + 2 * u8::from(state & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED) != 0)
        + 4 * u8::from(state & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0);

    let (prefix, suffix) = match key {
        VK_UP => (None, b'A'),
        VK_DOWN => (None, b'B'),
        VK_RIGHT => (None, b'C'),
        VK_LEFT => (None, b'D'),
        VK_HOME => (None, b'H'),
        VK_END => (None, b'F'),
        VK_INSERT => (Some(2), b'~'),
        VK_DELETE => (Some(3), b'~'),
        VK_PRIOR => (Some(5), b'~'),
        VK_NEXT => (Some(6), b'~'),
        VK_F1 => (Some(1), b'P'),
        VK_F2 => (Some(1), b'Q'),
        VK_F3 => (Some(1), b'R'),
        VK_F4 => (Some(1), b'S'),
        VK_F5 => (Some(15), b'~'),
        VK_F6 => (Some(17), b'~'),
        VK_F7 => (Some(18), b'~'),
        VK_F8 => (Some(19), b'~'),
        VK_F9 => (Some(20), b'~'),
        VK_F10 => (Some(21), b'~'),
        VK_F11 => (Some(23), b'~'),
        VK_F12 => (Some(24), b'~'),
        _ => return,
    };

    for _ in 0..repeat {
        if modifier == 1 && prefix == Some(1) && (b'P'..=b'S').contains(&suffix) {
            bytes.extend_from_slice(b"\x1bO");
            bytes.push(suffix);
            continue;
        }

        bytes.extend_from_slice(b"\x1b[");
        if let Some(prefix) = prefix {
            if prefix >= 10 {
                bytes.push(b'0' + prefix / 10);
            }
            bytes.push(b'0' + prefix % 10);
        } else if modifier != 1 {
            bytes.push(b'1');
        }
        if modifier != 1 {
            bytes.push(b';');
            bytes.push(b'0' + modifier);
        }
        bytes.push(suffix);
    }
}

fn append_shift_tab(bytes: &mut Vec<u8>, repeat: u16) {
    for _ in 0..repeat {
        bytes.extend_from_slice(b"\x1b[Z");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_virtual_keys_and_modifiers() {
        let mut bytes = Vec::new();

        append_virtual_key(&mut bytes, VK_UP, 0, 1);
        append_virtual_key(&mut bytes, VK_LEFT, LEFT_CTRL_PRESSED, 1);
        append_virtual_key(&mut bytes, VK_F1, 0, 1);
        append_virtual_key(&mut bytes, VK_F5, SHIFT_PRESSED, 2);

        assert_eq!(bytes, b"\x1b[A\x1b[1;5D\x1bOP\x1b[15;2~\x1b[15;2~");
    }

    #[test]
    fn encodes_utf16_as_utf8() {
        let mut bytes = Vec::new();
        let mut utf16 = vec![b'a' as u16, 0xd83d, 0xde00, 0xd800];

        append_utf16(&mut bytes, &mut utf16, false, true);

        assert_eq!(bytes, b"a\xf0\x9f\x98\x80");
        assert_eq!(utf16, [0xd800]);
    }

    #[test]
    fn encodes_alt_surrogate_pair_across_events() {
        let mut bytes = Vec::new();
        let mut utf16 = vec![0xd83d];

        append_utf16(&mut bytes, &mut utf16, true, true);
        assert!(bytes.is_empty());

        utf16.push(0xde00);
        append_utf16(&mut bytes, &mut utf16, true, true);

        assert_eq!(bytes, b"\x1b\xf0\x9f\x98\x80");
    }

    #[test]
    fn encodes_shift_tab() {
        let mut bytes = Vec::new();

        append_shift_tab(&mut bytes, 1);

        assert_eq!(bytes, b"\x1b[Z");
    }
}
