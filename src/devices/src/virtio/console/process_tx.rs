use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{io, thread};

use vm_memory::{GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion};

use crate::virtio::console::port_io::PortOutput;
use crate::virtio::{DescriptorChain, InterruptTransport, Queue};

pub(crate) fn process_tx(
    mem: GuestMemoryMmap,
    mut queue: Queue,
    interrupt: InterruptTransport,
    output: Arc<Mutex<Box<dyn PortOutput + Send>>>,
    stop: Arc<AtomicBool>,
) {
    loop {
        let Some(head) = pop_head_blocking(&mut queue, &mem, &interrupt, &stop) else {
            return;
        };

        let head_index = head.index;
        let mut bytes_written = 0;

        for desc in head.into_iter().readable() {
            let desc_len = desc.len as usize;
            match write_desc_to_output(desc, output.lock().unwrap().as_mut(), &interrupt) {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    assert_eq!(n, desc_len);
                    bytes_written += n;
                }
                Err(e) => {
                    log::error!("Failed to write output: {e}");
                    if matches!(e, GuestMemoryError::IOError(e) if e.kind() == io::ErrorKind::BrokenPipe)
                    {
                        // Errors could conceivably be spurious. Broken
                        // pipe is not and there is no point in attempting
                        // to write more.
                        return;
                    }
                }
            }
        }

        if bytes_written == 0 {
            log::trace!("Tx Add used {bytes_written}");
            queue.undo_pop();
        } else {
            log::trace!("Tx add used {bytes_written}");
            if let Err(e) = queue.add_used(&mem, head_index, bytes_written as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }
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
        // Suppress guest notifications while draining to avoid a TOCTOU race:
        // without suppression, the guest could add a descriptor and send a
        // notification between queue.pop() returning None and thread::park(),
        // and the notification would be lost if the TX thread is stopping.
        queue.disable_notification(mem).unwrap_or_default();

        // Pop one descriptor if available.
        if let Some(descriptor) = queue.pop(mem) {
            return Some(descriptor);
        }

        // Re-enable notifications. enable_notification re-reads avail_idx with
        // a SeqCst fence; if new entries arrived while we had notifications
        // suppressed, it returns Ok(true) and we must drain again.  On Err,
        // treat conservatively as if new entries may have arrived (notifications
        // may not be fully armed), so also retry the drain.
        if !matches!(queue.enable_notification(mem), Ok(false)) {
            continue;
        }

        // Queue is confirmed empty and notifications are armed.  Check stop
        // only after the drain+fence: if stop was set while the guest was
        // writing its final bytes, we still flush them before returning None.
        if stop.load(Ordering::Acquire) {
            return None;
        }

        interrupt.signal_used_queue();
        thread::park();
        log::trace!("tx unparked, queue len {}", queue.len(mem));
    }
}

fn write_desc_to_output(
    desc: DescriptorChain,
    output: &mut (dyn PortOutput + Send),
    interrupt: &InterruptTransport,
) -> Result<usize, GuestMemoryError> {
    // TODO: Switch to using `get_slices()` with the next vm-memory
    //       bump.
    #[allow(deprecated)]
    desc.mem
        .try_access(desc.len as usize, desc.addr, |_, len, addr, region| {
            let src = region.get_slice(addr, len).unwrap();
            loop {
                log::trace!("Tx {src:?}, write_volatile {len} bytes");
                match output.write_volatile(&src) {
                    // try_access seem to handle partial write for us (we will be invoked again with an offset)
                    Ok(n) => break Ok(n),
                    // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        log::trace!("Tx wait for output (would block)");
                        interrupt.signal_used_queue();
                        output.wait_until_writable();
                    }
                    Err(e) => break Err(GuestMemoryError::IOError(e)),
                }
            }
        })
}
