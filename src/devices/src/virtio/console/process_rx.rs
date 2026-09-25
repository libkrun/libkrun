#[cfg(not(windows))]
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[cfg(not(windows))]
use vm_memory::GuestMemoryRegion;
#[cfg(windows)]
use vm_memory::bitmap::Bitmap;
use vm_memory::{GuestMemoryBackend, GuestMemoryError, GuestMemoryMmap};

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::port_io::PortInput;
use crate::virtio::{DescriptorChain, InterruptTransport, Queue};

#[allow(clippy::too_many_arguments)]
pub(crate) fn process_rx(
    mem: GuestMemoryMmap,
    mut queue: Queue,
    interrupt: InterruptTransport,
    input: Arc<Mutex<Box<dyn PortInput + Send>>>,
    control: Arc<ConsoleControl>,
    port_id: u32,
    stopfd: utils::eventfd::EventFd,
    stop: Arc<AtomicBool>,
) {
    let mem = &mem;
    let mut eof = false;

    let mut input = input.lock().unwrap();
    loop {
        let Some(head) = pop_head_blocking(&mut queue, mem, &interrupt, &stop) else {
            return;
        };

        let head_index = head.index;
        let mut bytes_read = 0;
        for chain in head.into_iter().writable() {
            match read_to_desc(chain, input.as_mut(), &mut eof) {
                Ok(0) => {
                    break;
                }
                Ok(len) => {
                    bytes_read += len;
                }
                Err(e) => {
                    log::error!("Failed to read: {e:?}")
                }
            }
        }

        if bytes_read != 0 {
            if let Err(e) = queue.add_used(mem, head_index, bytes_read as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }
            #[cfg(target_os = "windows")]
            // On Windows, ReadFile blocks until data arrives rather than returning WouldBlock (0 bytes).
            // Because bytes_read is > 0, execution skips the `else if bytes_read == 0` block below
            // where `interrupt.signal_used_queue()` normally happens, so we must signal the guest here.
            interrupt.signal_used_queue();
        }

        // We signal_used_queue only when we get WouldBlock or EOF
        if eof {
            interrupt.signal_used_queue();
            log::trace!("signaling EOF on port {port_id}");
            control.port_open(port_id, false);
            return;
        } else if bytes_read == 0 {
            queue.undo_pop();
            interrupt.signal_used_queue();
            input.wait_until_readable(Some(&stopfd));
        }

        if stop.load(Ordering::Acquire) {
            return;
        }
    }
}

fn pop_head_blocking<'mem>(
    queue: &mut Queue,
    mem: &'mem GuestMemoryMmap,
    interrupt: &InterruptTransport,
    stop: &AtomicBool,
) -> Option<DescriptorChain<'mem>> {
    loop {
        match queue.pop(mem) {
            Some(descriptor) => break Some(descriptor),
            None => {
                interrupt.signal_used_queue();
                if stop.load(Ordering::Acquire) {
                    break None;
                }
                thread::park();
                log::trace!("rx unparked, queue len {}", queue.len(mem))
            }
        }
    }
}

#[cfg(not(windows))]
fn read_to_desc(
    desc: DescriptorChain,
    input: &mut (dyn PortInput + Send),
    eof: &mut bool,
) -> Result<usize, GuestMemoryError> {
    // TODO: Switch to using `get_slices()` with the next vm-memory
    //       bump.
    #[allow(deprecated)]
    desc.mem
        .try_access(desc.len as usize, desc.addr, |_, len, addr, region| {
            let mut target = region.get_slice(addr, len).unwrap();
            match input.read_volatile(&mut target) {
                Ok(n) => {
                    if n == 0 {
                        *eof = true
                    }
                    Ok(n)
                }
                // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(GuestMemoryError::IOError(e)),
            }
        })
}

#[cfg(windows)]
fn read_to_desc(
    desc: DescriptorChain,
    input: &mut (dyn PortInput + Send),
    eof: &mut bool,
) -> Result<usize, GuestMemoryError> {
    // Read into a temp host buffer first and then copy to guest memory.
    // If we read directly into guest memory, ReadFile would block while holding
    // a reference to it, which deadlocks WHP vCPUs trying to access that same memory.
    let mut host_buf = vec![0; desc.len as usize];
    let bytes_read = input
        .read_bytes(&mut host_buf)
        .map_err(GuestMemoryError::IOError)?;
    if bytes_read == 0 {
        *eof = true;
        return Ok(0);
    }

    let mut copied = 0;
    for slice in desc.mem.get_slices(desc.addr, desc.len as usize) {
        let slice = slice?;
        let count = (bytes_read - copied).min(slice.len());
        let guard = slice.ptr_guard_mut();
        unsafe {
            std::ptr::copy_nonoverlapping(host_buf[copied..].as_ptr(), guard.as_ptr(), count);
        }
        slice.bitmap().mark_dirty(0, count);
        copied += count;
    }
    Ok(copied)
}
