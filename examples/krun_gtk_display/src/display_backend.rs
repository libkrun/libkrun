use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use gtk::{gdk::MemoryFormat, glib::Bytes};
use krun_display::{
    DisplayBackend, DisplayBackendBasicFramebuffer, DisplayBackendDmabuf, DisplayBackendError,
    DisplayBackendNew, DisplayBasicFramebufferVtable, DisplayFeatures, DisplayVtable, DmabufExport,
    IntoDisplayBackend, MAX_DISPLAYS, Rect, ResourceFormat,
};
use log::error;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem;
use std::ptr::{from_ref, null, null_mut};
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
    #[cfg(target_os = "linux")]
    ImportDmabuf {
        dmabuf_id: u32,
        dmabuf_export: DmabufExport,
    },
    #[cfg(target_os = "linux")]
    UnrefDmabuf {
        dmabuf_id: u32,
    },
    ConfigureScanout {
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: MemoryFormat,
    },
    #[cfg(target_os = "linux")]
    ConfigureScanoutDmabuf {
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        dmabuf_id: u32,
    },
    DisableScanout {
        scanout_id: u32,
    },
    UpdateScanout {
        scanout_id: u32,
        buffer: Bytes,
        rect: Option<Rect>,
    },
    #[cfg(target_os = "linux")]
    UpdateScanoutDmabuf {
        scanout_id: u32,
        rect: Option<Rect>,
        /// Response channel - signals when texture build completes (not when painted!)
        response_tx: std::sync::mpsc::SyncSender<bool>,
    },
}

// Implements libkrun traits (callbacks) to provide a display implementation, by forwarding the
// events to the `DisplayWorker`
pub struct GtkDisplayBackend {
    channel: PollableChannelSender<DisplayEvent>,
    scanouts: [Option<Scanout>; MAX_DISPLAYS],
    #[cfg(target_os = "linux")]
    next_dmabuf_id: u32,
}

impl DisplayBackendNew<PollableChannelSender<DisplayEvent>> for GtkDisplayBackend {
    fn new(channel: Option<&PollableChannelSender<DisplayEvent>>) -> Self {
        let channel = channel
            .expect("The channel should have been set by GtkDisplayBackend::into_display_backend")
            .clone();

        Self {
            channel,
            scanouts: Default::default(),
            #[cfg(target_os = "linux")]
            next_dmabuf_id: 1,
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
                #[cfg(target_os = "linux")]
                has_dmabuf: false,
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

        self.channel
            .send(DisplayEvent::UpdateScanout {
                scanout_id,
                buffer,
                rect,
            })
            .unwrap();
        Ok(())
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
    #[cfg(target_os = "linux")]
    has_dmabuf: bool,
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

#[cfg(target_os = "linux")]
impl DisplayBackendDmabuf for GtkDisplayBackend {
    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayBackendError> {
        self.scanouts[scanout_id as usize] = None;
        self.channel
            .send(DisplayEvent::DisableScanout { scanout_id })
            .unwrap();
        Ok(())
    }

    fn import_dmabuf(&mut self, dmabuf_export: &DmabufExport) -> Result<u32, DisplayBackendError> {
        let dmabuf_id = self.next_dmabuf_id;
        self.next_dmabuf_id += 1;

        self.channel
            .send(DisplayEvent::ImportDmabuf {
                dmabuf_id,
                dmabuf_export: *dmabuf_export,
            })
            .unwrap();

        Ok(dmabuf_id)
    }

    fn unref_dmabuf(&mut self, dmabuf_id: u32) -> Result<(), DisplayBackendError> {
        self.channel
            .send(DisplayEvent::UnrefDmabuf { dmabuf_id })
            .unwrap();

        Ok(())
    }

    fn configure_scanout_dmabuf(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        dmabuf_id: u32,
        _src_rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        // Create scanout if it doesn't exist (DMABUF-only path)
        if self.scanouts[scanout_id as usize].is_none() {
            let (buffer_tx, buffer_rx) = bounded(MAX_DISPLAY_BUFFERS);

            for _ in 0..MAX_DISPLAY_BUFFERS {
                buffer_tx
                    .try_send(Vec::new())
                    .expect("Failed to prefill the channel for buffers");
            }

            self.scanouts[scanout_id as usize] = Some(Scanout {
                required_buffer_size: 0,
                buffer_rx,
                buffer_tx,
                current_buffer: Vec::new(),
                has_dmabuf: true,
            });
        } else {
            self.scanouts[scanout_id as usize]
                .as_mut()
                .unwrap()
                .has_dmabuf = true;
        }

        self.channel
            .send(DisplayEvent::ConfigureScanoutDmabuf {
                scanout_id,
                display_width,
                display_height,
                dmabuf_id,
            })
            .unwrap();
        Ok(())
    }

    fn present_dmabuf(
        &mut self,
        scanout_id: u32,
        rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        if self.scanouts[scanout_id as usize]
            .as_ref()
            .is_none_or(|scanout| !scanout.has_dmabuf)
        {
            return Err(DisplayBackendError::InvalidScanoutId);
        };

        // Synchronously wait for texture build to complete
        let (response_tx, response_rx) = std::sync::mpsc::sync_channel(0);

        self.channel
            .send(DisplayEvent::UpdateScanoutDmabuf {
                scanout_id,
                rect: rect.copied(),
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

impl IntoDisplayBackend<PollableChannelSender<DisplayEvent>> for GtkDisplayBackend {
    fn into_display_backend(
        userdata: Option<&PollableChannelSender<DisplayEvent>>,
    ) -> DisplayBackend<'_> {
        extern "C" fn create_fn(
            instance: *mut *mut c_void,
            userdata: *const c_void,
            _reserved: *const c_void,
        ) -> i32 {
            unsafe {
                assert_ne!(instance, null_mut());
                let userdata_ref =
                    (userdata as *const PollableChannelSender<DisplayEvent>).as_ref();
                *(instance as *mut *mut GtkDisplayBackend) =
                    Box::into_raw(Box::new(GtkDisplayBackend::new(userdata_ref)));
            }
            0
        }

        extern "C" fn destroy_fn(instance: *mut c_void) -> i32 {
            drop(unsafe { Box::from_raw(instance as *mut GtkDisplayBackend) });
            0
        }

        fn cast_instance(instance: *mut c_void) -> &'static mut GtkDisplayBackend {
            assert_ne!(instance, null_mut());
            unsafe { &mut *(instance as *mut GtkDisplayBackend) }
        }

        unsafe fn ptr_to_option_ref<'a, T>(x: *const T) -> Option<&'a T> {
            unsafe { x.as_ref() }
        }

        fn from_rust_result(result: Result<(), DisplayBackendError>) -> i32 {
            match result {
                Ok(()) => 0,
                Err(e) => e as i32,
            }
        }

        extern "C" fn configure_scanout_fn(
            instance: *mut c_void,
            scanout_id: u32,
            display_width: u32,
            display_height: u32,
            width: u32,
            height: u32,
            format: u32,
        ) -> i32 {
            let Ok(format) = ResourceFormat::try_from(format) else {
                return DisplayBackendError::InvalidParam as i32;
            };

            from_rust_result(cast_instance(instance).configure_scanout(
                scanout_id,
                display_width,
                display_height,
                width,
                height,
                format,
            ))
        }

        extern "C" fn disable_scanout_fn(instance: *mut c_void, scanout_id: u32) -> i32 {
            from_rust_result(DisplayBackendBasicFramebuffer::disable_scanout(
                &mut *cast_instance(instance),
                scanout_id,
            ))
        }

        extern "C" fn alloc_frame_fn(
            instance: *mut c_void,
            scanout_id: u32,
            buffer: *mut *mut u8,
            buffer_size: *mut usize,
        ) -> i32 {
            match cast_instance(instance).alloc_frame(scanout_id) {
                Ok((frame_id, allocated_buffer)) => {
                    unsafe {
                        *buffer_size = allocated_buffer.len();
                        *buffer = allocated_buffer.as_mut_ptr();
                    }
                    frame_id as i32
                }
                Err(e) => e as i32,
            }
        }

        extern "C" fn present_frame_fn(
            instance: *mut c_void,
            scanout_id: u32,
            frame_id: u32,
            rect: *const Rect,
        ) -> i32 {
            let rect = unsafe { ptr_to_option_ref(rect) };
            from_rust_result(cast_instance(instance).present_frame(scanout_id, frame_id, rect))
        }

        #[cfg(target_os = "linux")]
        extern "C" fn import_dmabuf_fn(
            instance: *mut c_void,
            dmabuf_export: *const DmabufExport,
        ) -> i32 {
            let dmabuf = unsafe { ptr_to_option_ref(dmabuf_export) }
                .expect("dmabuf_export must not be null");
            match cast_instance(instance).import_dmabuf(dmabuf) {
                Ok(dmabuf_id) => dmabuf_id as i32,
                Err(e) => e as i32,
            }
        }

        #[cfg(target_os = "linux")]
        extern "C" fn unref_dmabuf_fn(instance: *mut c_void, dmabuf_id: u32) -> i32 {
            from_rust_result(cast_instance(instance).unref_dmabuf(dmabuf_id))
        }

        #[cfg(target_os = "linux")]
        extern "C" fn configure_scanout_dmabuf_fn(
            instance: *mut c_void,
            scanout_id: u32,
            display_width: u32,
            display_height: u32,
            dmabuf_id: u32,
            src_rect: *const Rect,
        ) -> i32 {
            let src_rect = unsafe { ptr_to_option_ref(src_rect) };
            from_rust_result(cast_instance(instance).configure_scanout_dmabuf(
                scanout_id,
                display_width,
                display_height,
                dmabuf_id,
                src_rect,
            ))
        }

        #[cfg(target_os = "linux")]
        extern "C" fn present_dmabuf_fn(
            instance: *mut c_void,
            scanout_id: u32,
            damage_area: *const Rect,
        ) -> i32 {
            let damage_area = unsafe { ptr_to_option_ref(damage_area) };
            from_rust_result(cast_instance(instance).present_dmabuf(scanout_id, damage_area))
        }

        DisplayBackend {
            create_userdata: userdata.map_or(null(), |t| from_ref(t) as *const c_void),
            create_userdata_lifetime: PhantomData,
            #[cfg(target_os = "linux")]
            features: (DisplayFeatures::BASIC_FRAMEBUFFER | DisplayFeatures::DMABUF_CONSUMER)
                .bits(),
            #[cfg(not(target_os = "linux"))]
            features: DisplayFeatures::BASIC_FRAMEBUFFER.bits(),
            create_fn: Some(create_fn),
            vtable: DisplayVtable {
                basic_framebuffer: DisplayBasicFramebufferVtable {
                    destroy: Some(destroy_fn),
                    configure_scanout: Some(configure_scanout_fn),
                    disable_scanout: Some(disable_scanout_fn),
                    alloc_frame: Some(alloc_frame_fn),
                    present_frame: Some(present_frame_fn),
                    #[cfg(target_os = "linux")]
                    import_dmabuf: Some(import_dmabuf_fn),
                    #[cfg(target_os = "linux")]
                    unref_dmabuf: Some(unref_dmabuf_fn),
                    #[cfg(target_os = "linux")]
                    configure_scanout_dmabuf: Some(configure_scanout_dmabuf_fn),
                    #[cfg(target_os = "linux")]
                    present_dmabuf: Some(present_dmabuf_fn),
                    #[cfg(not(target_os = "linux"))]
                    import_dmabuf: None,
                    #[cfg(not(target_os = "linux"))]
                    unref_dmabuf: None,
                    #[cfg(not(target_os = "linux"))]
                    configure_scanout_dmabuf: None,
                    #[cfg(not(target_os = "linux"))]
                    present_dmabuf: None,
                },
            },
        }
    }
}
