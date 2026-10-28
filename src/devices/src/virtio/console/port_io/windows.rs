use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, ErrorKind, IsTerminal};
use std::mem::MaybeUninit;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, OwnedHandle, RawHandle};
use utils::eventfd::EventFd;
use utils::windows::AsRawFd;
use vm_memory::VolatileSlice;
use windows_sys::Win32::{
    Foundation::FALSE,
    Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType, ReadFile, WriteFile},
    System::{
        Console::{
            CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo, GetNumberOfConsoleInputEvents,
            INPUT_RECORD, ReadConsoleInputW,
        },
        Pipes::PeekNamedPipe,
        Threading::{INFINITE, WaitForMultipleObjects, WaitForSingleObject},
    },
};

use super::{PortInput, PortInputEmpty, PortOutput, PortTerminalProperties};
use crate::windows_console::ConsoleInputDecoder;

pub fn input_to_handle_dup(
    handle: *mut core::ffi::c_void,
) -> io::Result<Box<dyn PortInput + Send>> {
    Ok(Box::new(PortInputHandle {
        handle: dup_handle(handle)?,
        pending: VecDeque::new(),
        decoder: ConsoleInputDecoder::default(),
    }))
}

pub fn term_handle(
    handle: *mut core::ffi::c_void,
) -> io::Result<Box<dyn PortTerminalProperties + Send + Sync>> {
    let handle = dup_handle(handle)?;
    assert!(
        handle.is_terminal(),
        "Expected handle to be a tty, to query the window size!"
    );
    Ok(Box::new(PortTerminalPropertiesHandle(handle)))
}

pub fn input_empty() -> Result<Box<dyn PortInput + Send>, io::Error> {
    Ok(Box::new(PortInputEmpty {}))
}

pub fn output_file(file: File) -> Result<Box<dyn PortOutput + Send>, io::Error> {
    output_to_handle_dup(file.as_raw_handle())
}

pub fn output_to_handle_dup(
    handle: *mut core::ffi::c_void,
) -> Result<Box<dyn PortOutput + Send>, io::Error> {
    // We skip make_non_blocking() on Windows and rely on the background
    // tx_thread to safely execute a blocking write.
    let owned_handle = dup_handle(handle)?;
    Ok(Box::new(PortOutputHandle(owned_handle)))
}

struct PortInputHandle {
    handle: OwnedHandle,
    pending: VecDeque<u8>,
    decoder: ConsoleInputDecoder,
}

impl AsRawHandle for PortInputHandle {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle.as_raw_handle()
    }
}

impl PortInput for PortInputHandle {
    fn read_bytes(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.handle.is_terminal() {
            return self.read_console(buf);
        }

        if unsafe { GetFileType(self.as_raw_handle()) } == FILE_TYPE_PIPE {
            let mut bytes_available = 0;
            if unsafe {
                PeekNamedPipe(
                    self.as_raw_handle(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut bytes_available,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                if error.kind() == ErrorKind::BrokenPipe {
                    return Ok(0);
                }
                return Err(error);
            }
            if bytes_available == 0 {
                return Err(ErrorKind::WouldBlock.into());
            }
        }

        let len = u32::try_from(buf.len()).map_err(|_| {
            io::Error::new(ErrorKind::InvalidInput, "buffer length exceeds u32::MAX")
        })?;
        let mut bytes_read: u32 = 0;
        let ret = unsafe {
            ReadFile(
                self.as_raw_handle(),
                buf.as_mut_ptr(),
                len,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            let err = io::Error::last_os_error();
            if err.kind() == ErrorKind::BrokenPipe {
                return Ok(0);
            }
            return Err(err);
        }

        Ok(bytes_read as usize)
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        if !self.handle.is_terminal() {
            std::thread::sleep(std::time::Duration::from_millis(10));
            return;
        }
        let mut handles = vec![self.as_raw_handle()];
        if let Some(s) = stopfd {
            handles.push(s.as_raw_fd());
        }
        wait_for_handles(&handles);
    }
}

impl PortInputHandle {
    fn read_console(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pending.is_empty() {
            let mut event_count = 0;
            if unsafe { GetNumberOfConsoleInputEvents(self.as_raw_handle(), &mut event_count) } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if event_count == 0 {
                return Err(ErrorKind::WouldBlock.into());
            }

            let mut records = vec![INPUT_RECORD::default(); event_count.min(64) as usize];
            let mut record_count = 0;
            if unsafe {
                ReadConsoleInputW(
                    self.as_raw_handle(),
                    records.as_mut_ptr(),
                    records.len() as u32,
                    &mut record_count,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            self.pending
                .extend(self.decoder.decode(&records[..record_count as usize]));
        }

        if self.pending.is_empty() {
            return Err(ErrorKind::WouldBlock.into());
        }
        let count = buf.len().min(self.pending.len());
        for byte in &mut buf[..count] {
            *byte = self.pending.pop_front().unwrap();
        }
        Ok(count)
    }
}

impl PortInput for PortInputEmpty {
    fn read_bytes(&mut self, _buf: &mut [u8]) -> Result<usize, io::Error> {
        Ok(0)
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        let handles: Vec<_> = stopfd.iter().map(|s| s.as_raw_fd()).collect();
        wait_for_handles(&handles);
    }
}

struct PortOutputHandle(OwnedHandle);

impl AsRawHandle for PortOutputHandle {
    fn as_raw_handle(&self) -> RawHandle {
        self.0.as_raw_handle()
    }
}

impl PortOutput for PortOutputHandle {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> io::Result<usize> {
        let len = u32::try_from(buf.len()).map_err(|_| {
            io::Error::new(ErrorKind::InvalidInput, "buffer length exceeds u32::MAX")
        })?;
        let mut bytes_written: u32 = 0;
        let ret = unsafe {
            WriteFile(
                self.as_raw_handle(),
                buf.ptr_guard().as_ptr(),
                len,
                &mut bytes_written,
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(bytes_written as usize)
        }
    }

    fn wait_until_writable(&self) {
        // Because WriteFile is blocking, `write_volatile` will natively pause the
        // thread until space is available. It will never return io::ErrorKind::WouldBlock.
        // Therefore, `process_tx` will never invoke this function on Windows.
    }
}

struct PortTerminalPropertiesHandle(OwnedHandle);

impl PortTerminalProperties for PortTerminalPropertiesHandle {
    fn get_win_size(&self) -> (u16, u16) {
        let mut info = MaybeUninit::<CONSOLE_SCREEN_BUFFER_INFO>::uninit();
        let ret = unsafe { GetConsoleScreenBufferInfo(self.0.as_raw_handle(), info.as_mut_ptr()) };
        if ret == 0 {
            log::error!(
                "GetConsoleScreenBufferInfo failed: {}",
                io::Error::last_os_error()
            );
            return (0, 0);
        }
        let info = unsafe { info.assume_init() };

        let cols = (info.srWindow.Right - info.srWindow.Left + 1) as u16;
        let rows = (info.srWindow.Bottom - info.srWindow.Top + 1) as u16;
        (cols, rows)
    }
}

fn dup_handle(raw: *mut core::ffi::c_void) -> Result<OwnedHandle, io::Error> {
    let borrowed = unsafe { BorrowedHandle::borrow_raw(raw) };
    borrowed.try_clone_to_owned()
}

/// Block until at least one of the given Windows HANDLEs becomes signaled.
fn wait_for_handles(handles: &[*mut core::ffi::c_void]) {
    match handles.len() {
        0 => std::thread::sleep(std::time::Duration::MAX),
        1 => unsafe {
            WaitForSingleObject(handles[0], INFINITE);
        },
        n => unsafe {
            WaitForMultipleObjects(n as u32, handles.as_ptr(), FALSE, INFINITE);
        },
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::System::Console::{
        COORD, INPUT_RECORD, INPUT_RECORD_0, MOUSE_EVENT, MOUSE_EVENT_RECORD, MOUSE_MOVED,
        WriteConsoleInputW,
    };

    use super::input_to_handle_dup;

    fn write_console_event(
        handle: std::os::windows::io::RawHandle,
        record: INPUT_RECORD,
    ) -> io::Result<()> {
        let mut written = 0;
        if unsafe { WriteConsoleInputW(handle, &record, 1, &mut written) } == 0 {
            return Err(io::Error::last_os_error());
        }
        assert_eq!(written, 1);
        Ok(())
    }

    #[test]
    #[ignore = "requires an interactive Windows console and injects input events"]
    fn non_character_event_does_not_block_console_read() {
        let stdin = io::stdin();
        let handle = stdin.as_raw_handle();
        let mut input = input_to_handle_dup(handle).unwrap();

        write_console_event(
            handle,
            INPUT_RECORD {
                EventType: MOUSE_EVENT as u16,
                Event: INPUT_RECORD_0 {
                    MouseEvent: MOUSE_EVENT_RECORD {
                        dwMousePosition: COORD { X: 0, Y: 0 },
                        dwButtonState: 0,
                        dwControlKeyState: 0,
                        dwEventFlags: MOUSE_MOVED,
                    },
                },
            },
        )
        .unwrap();

        let mut buffer = [0; 16];
        assert_eq!(
            input.read_bytes(&mut buffer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
