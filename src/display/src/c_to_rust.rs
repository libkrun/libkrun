use crate::{
    DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayFeatures, DisplayVtable,
    DmabufExport, Rect, ResourceFormat, header,
};
use log::error;
use static_assertions::assert_not_impl_any;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::{null, null_mut, slice_from_raw_parts_mut};

#[macro_export]
macro_rules! into_rust_result {
    ($expr:expr) => {
        into_rust_result!($expr,
            0 => Ok(()),
            code @ 0.. => {
                log::warn!("{}: Unknown OK result code: {code}", stringify!($expr));
                Ok(())
            }
        )
    };
    ($expr:expr, $($pat:pat $(if $pat_guard:expr)? => $pat_expr:expr),+ ) => {
        match $expr {
            $($pat $(if $pat_guard)? => $pat_expr,)+
            -1 => Err(DisplayBackendError::InternalError),
            -3 => Err(DisplayBackendError::InvalidScanoutId),
            -4 => Err(DisplayBackendError::InvalidParam),
            code @ i32::MIN.. => {
                log::warn!("{}: Unknown error result code: {code}", stringify!($expr));
                Err(DisplayBackendError::InternalError)
            }
        }
    };
}

macro_rules! method_call_fb {
    ($self:ident.$method:ident($($args:expr),*) ) => {
        unsafe {
            $self.vtable.basic_framebuffer.$method
                .ok_or(DisplayBackendError::MethodNotSupported)?( $self.instance, $($args),* )
        }
    };
}

macro_rules! method_call_dmabuf {
    ($self:ident.$method:ident($($args:expr),*) ) => {
        unsafe {
            $self.vtable.basic_framebuffer.$method
                .ok_or(DisplayBackendError::MethodNotSupported)?( $self.instance, $($args),* )
        }
    };
}

pub struct DisplayBackendInstance {
    instance: *mut c_void,
    vtable: DisplayVtable,
    features: DisplayFeatures,
}

// By design the struct is !Send and !Sync to allow for the implementation to safely assume that
// the methods are always called on the GPU worker thread
assert_not_impl_any!(DisplayBackendInstance: Sync, Send);

impl Drop for DisplayBackendInstance {
    fn drop(&mut self) {
        // Try basic_framebuffer destroy first, then dmabuf
        let destroy_fn = if self.features.contains(DisplayFeatures::BASIC_FRAMEBUFFER) {
            unsafe { self.vtable.basic_framebuffer.destroy }
        } else if self.features.contains(DisplayFeatures::DMABUF_CONSUMER) {
            unsafe { self.vtable.dmabuf.destroy }
        } else {
            None
        };

        let Some(destroy_fn) = destroy_fn else {
            return;
        };

        if let Err(e) = into_rust_result!(unsafe { destroy_fn(self.instance) }) {
            error!("Failed to destroy krun_gtk_display instance: {e}");
        }
    }
}

impl DisplayBackendInstance {
    pub fn import_dmabuf(
        &mut self,
        dmabuf_export: &DmabufExport,
    ) -> Result<u32, DisplayBackendError> {
        let dmabuf_id = into_rust_result! {
            method_call_dmabuf! {
                self.import_dmabuf(dmabuf_export as *const _)
            },
            result @ 0.. => Ok(result as u32)
        }?;
        Ok(dmabuf_id)
    }

    pub fn unref_dmabuf(&mut self, dmabuf_id: u32) -> Result<(), DisplayBackendError> {
        into_rust_result! {
            method_call_dmabuf! {
                self.unref_dmabuf(dmabuf_id)
            }
        }
    }

    pub fn configure_scanout_dmabuf(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        dmabuf_id: u32,
        src_rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        into_rust_result! {
            method_call_dmabuf! {
                self.configure_scanout_dmabuf(
                    scanout_id,
                    display_width,
                    display_height,
                    dmabuf_id,
                    src_rect.map(|r| r as *const _).unwrap_or(null())
                )
            }
        }
    }

    pub fn present_dmabuf(
        &mut self,
        scanout_id: u32,
        damage_area: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        into_rust_result! {
            method_call_dmabuf! {
                self.present_dmabuf(scanout_id, damage_area.map(|r| r as *const _).unwrap_or(null()))
            }
        }
    }
}

impl DisplayBackendBasicFramebuffer for DisplayBackendInstance {
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: ResourceFormat,
    ) -> Result<(), DisplayBackendError> {
        into_rust_result!(method_call_fb! {
        self.configure_scanout(
            scanout_id,
            display_width,
            display_height,
            width,
            height,
            format as u32
        )
        })
    }

    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayBackendError> {
        into_rust_result! {
            method_call_fb! {
                self.disable_scanout(scanout_id)
            }
        }
    }

    // Soundness note: this method has to take &mut self in order for the lifetime of the returned
    // slice to be tied to self. This way the returned slice cannot stay borrowed once another method
    // on self is called.
    fn alloc_frame(&mut self, scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError> {
        let mut buffer: *mut u8 = null_mut();
        let mut buffer_len: usize = 0;
        let frame_id = into_rust_result! {
            method_call_fb! {
                self.alloc_frame(scanout_id, &raw mut buffer, &raw mut buffer_len)
            },
            result @ 0.. => Ok(result as u32)
        }?;

        assert_ne!(buffer, null_mut());
        assert_ne!(buffer_len, 0);
        // SAFETY: We have obtained the buffer and buffer_len from the krun_gtk_display impl. Because
        //         the alloc_frame_fn return an error we assume they should be valid.
        let buffer = unsafe {
            slice_from_raw_parts_mut(buffer, buffer_len)
                .as_mut()
                .unwrap()
        };
        Ok((frame_id, buffer))
    }

    fn present_frame(
        &mut self,
        scanout_id: u32,
        frame_id: u32,
        rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        into_rust_result! {
            method_call_fb!{
                self.present_frame(scanout_id, frame_id, rect.map(|r| r as *const _).unwrap_or(null()))
            }
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct DisplayBackend<'userdata> {
    pub features: u64,
    pub create_userdata: *const c_void,
    pub create_userdata_lifetime: PhantomData<&'userdata c_void>,
    pub create_fn: header::krun_display_create_fn,
    pub vtable: DisplayVtable,
}

impl DisplayBackend<'_> {
    /// Create a DisplayBackendInstance, the caller is responsible for only calling this on a
    /// properly constructed DisplayBackend struct.
    pub fn create_instance(&self) -> Result<DisplayBackendInstance, DisplayBackendError> {
        let mut instance = null_mut();
        if let Some(create_fn) = self.create_fn {
            into_rust_result!(unsafe {
                create_fn(&raw mut instance, self.create_userdata, null())
            })?;
        }
        assert!(self.verify());

        Ok(DisplayBackendInstance {
            instance,
            vtable: self.vtable,
            features: DisplayFeatures::from_bits_retain(self.features),
        })
    }

    pub fn verify(&self) -> bool {
        let features = DisplayFeatures::from_bits_retain(self.features);

        // Require at least one display backend type
        if !features.contains(DisplayFeatures::BASIC_FRAMEBUFFER)
            && !features.contains(DisplayFeatures::DMABUF_CONSUMER)
        {
            error!("This version of libkrun requires BASIC_FRAMEBUFFER or DMABUF_CONSUMER feature");
            return false;
        }

        // Check basic framebuffer methods if that feature is set
        if features.contains(DisplayFeatures::BASIC_FRAMEBUFFER) {
            // SAFETY: We have checked the feature flag is enabled, so we should be able to
            // access the union field.
            if unsafe {
                self.vtable.basic_framebuffer.disable_scanout.is_none()
                    || self.vtable.basic_framebuffer.configure_scanout.is_none()
                    || self.vtable.basic_framebuffer.alloc_frame.is_none()
                    || self.vtable.basic_framebuffer.present_frame.is_none()
            } {
                error!("Missing required methods for BASIC_FRAMEBUFFER");
                return false;
            }
        }

        // Check DMABUF methods if that feature is ALSO set
        // DMABUF methods are in the basic_framebuffer vtable as extensions
        if features.contains(DisplayFeatures::DMABUF_CONSUMER)
            && unsafe {
                self.vtable.basic_framebuffer.import_dmabuf.is_none()
                    || self.vtable.basic_framebuffer.unref_dmabuf.is_none()
                    || self
                        .vtable
                        .basic_framebuffer
                        .configure_scanout_dmabuf
                        .is_none()
                    || self.vtable.basic_framebuffer.present_dmabuf.is_none()
            }
        {
            error!("Missing required methods for DMABUF_CONSUMER");
            return false;
        }
        true
    }
}

unsafe impl Send for DisplayBackend<'_> {}
