use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use gtk::{gdk::MemoryFormat, glib::Bytes};
use krun_display::{
    DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayBackendNew, MAX_DISPLAYS, Rect,
    ResourceFormat,
};
use log::error;
use std::mem;
use std::sync::mpsc::{SyncSender, sync_channel};
use utils::pollable_channel::PollableChannelSender;

// We try to push the maximum amount of data to the GTK thread. Currently, we want the display thread
// deal with dropping the frames if they are coming too quickly to render. If we set this to a lower
// number could slow down the libkrun thread, by making it wait for the display thread when calling
// DisplayBackendBasicFramebuffer::alloc_frame.
const MAX_DISPLAY_BUFFERS: usize = 4;
const _: () = {
    if MAX_DISPLAY_BUFFERS < 2 {
        panic!("At least 2 buffers are required")
    }
};

#[derive(Debug, Clone)]
pub enum DisplayEvent {
    ConfigureScanout {
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: MemoryFormat,
    },
    DisableScanout {
        scanout_id: u32,
    },
    UpdateScanout {
        scanout_id: u32,
        buffer: Bytes,
        rect: Option<Rect>,
        response_tx: SyncSender<bool>,
    },
}

// Implements libkrun traits (callbacks) to provide a display implementation, by forwarding the
// events to the `DisplayWorker`
pub struct GtkDisplayBackend {
    channel: PollableChannelSender<DisplayEvent>,
    scanouts: [Option<Scanout>; MAX_DISPLAYS],
}

impl DisplayBackendNew<PollableChannelSender<DisplayEvent>> for GtkDisplayBackend {
    fn new(channel: Option<&PollableChannelSender<DisplayEvent>>) -> Self {
        let channel = channel
            .expect("The channel should have been set by GtkDisplayBackend::into_display_backend")
            .clone();

        Self {
            channel,
            scanouts: Default::default(),
        }
    }
}

impl DisplayBackendBasicFramebuffer for GtkDisplayBackend {
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: ResourceFormat,
    ) -> Result<(), DisplayBackendError> {
        let required_buffer_size =
            width as usize * height as usize * ResourceFormat::BYTES_PER_PIXEL;
        if let Some(ref mut scanout) = self.scanouts[scanout_id as usize] {
            scanout.required_buffer_size = required_buffer_size;
        } else {
            let (buffer_tx, buffer_rx) = bounded(MAX_DISPLAY_BUFFERS);

            for _ in 0..MAX_DISPLAY_BUFFERS {
                // We initialize the buffers as empty in case we don't end up using them, the buffers
                // are always resized on `alloc_frame`
                buffer_tx
                    .try_send(Vec::new())
                    .expect("Failed to prefill the channel for buffers");
            }

            self.scanouts[scanout_id as usize] = Some(Scanout {
                required_buffer_size,
                buffer_rx,
                buffer_tx,
                current_buffer: Vec::new(),
            });
        }

        self.channel
            .send(DisplayEvent::ConfigureScanout {
                scanout_id,
                display_width,
                display_height,
                width,
                height,
                format: resource_format_into_gdk(format),
            })
            .unwrap();
        Ok(())
    }

    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayBackendError> {
        self.scanouts[scanout_id as usize] = None;
        self.channel
            .send(DisplayEvent::DisableScanout { scanout_id })
            .unwrap();
        Ok(())
    }

    fn alloc_frame(&mut self, scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError> {
        let Some(scanout) = &mut self.scanouts[scanout_id as usize] else {
            return Err(DisplayBackendError::InvalidScanoutId);
        };

        // We only support one buffer "in-flight"
        if !scanout.current_buffer.is_empty() {
            return Err(DisplayBackendError::OutOfBuffers);
        }

        scanout.current_buffer = scanout.buffer_rx.recv().unwrap();
        scanout
            .current_buffer
            .resize(scanout.required_buffer_size, 0);

        Ok((1, scanout.current_buffer.as_mut()))
    }

    fn present_frame(
        &mut self,
        scanout_id: u32,
        frame_id: u32,
        rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        assert_eq!(frame_id, 1);

        let Some(scanout) = &mut self.scanouts[scanout_id as usize] else {
            return Err(DisplayBackendError::InvalidScanoutId);
        };

        let buffer = scanout.take_buffer();
        let rect = rect.copied();

        // Synchronously wait for frame to be painted
        let (response_tx, response_rx) = sync_channel(0);

        self.channel
            .send(DisplayEvent::UpdateScanout {
                scanout_id,
                buffer,
                rect,
                response_tx,
            })
            .unwrap();

        match response_rx.recv() {
            Ok(true) => Ok(()),
            Ok(false) => Err(DisplayBackendError::InternalError),
            Err(_) => Err(DisplayBackendError::InternalError),
        }
    }
}

fn resource_format_into_gdk(format: ResourceFormat) -> MemoryFormat {
    match format {
        ResourceFormat::BGRA => MemoryFormat::B8g8r8a8,
        ResourceFormat::BGRX => MemoryFormat::B8g8r8x8,
        ResourceFormat::ARGB => MemoryFormat::A8r8g8b8,
        ResourceFormat::XRGB => MemoryFormat::X8r8g8b8,
        ResourceFormat::RGBA => MemoryFormat::R8g8b8a8,
        ResourceFormat::XBGR => MemoryFormat::X8b8g8r8,
        ResourceFormat::ABGR => MemoryFormat::A8b8g8r8,
        ResourceFormat::RGBX => MemoryFormat::R8g8b8x8,
    }
}

struct Scanout {
    buffer_tx: Sender<Vec<u8>>,
    buffer_rx: Receiver<Vec<u8>>,
    required_buffer_size: usize,
    current_buffer: Vec<u8>,
}

impl Scanout {
    fn take_buffer(&mut self) -> Bytes {
        Bytes::from_owned(BufferReturner {
            return_tx: self.buffer_tx.clone(),
            buf: mem::take(&mut self.current_buffer),
        })
    }
}

struct BufferReturner {
    return_tx: Sender<Vec<u8>>,
    buf: Vec<u8>,
}

impl AsRef<[u8]> for BufferReturner {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for BufferReturner {
    fn drop(&mut self) {
        match self.return_tx.try_send(mem::take(&mut self.buf)) {
            Ok(_) => (),
            // We can just drop the buffer if the other party doesn't exist anymore.
            Err(TrySendError::Disconnected(_)) => (),
            Err(TrySendError::Full(_)) => {
                error!(
                    "Either the channel is too small or we have more than MAX_DISPLAY_BUFFERS buffers!?"
                );
            }
        }
    }
}
