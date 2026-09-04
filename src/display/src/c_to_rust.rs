use crate::{
    DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayBasicFramebufferVtable,
    DisplayCursorVtable, DisplayFeatures, DisplayVtable, Rect, ResourceFormat, header,
};
use log::{error, warn};
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

macro_rules! method_call {
    ($self:ident.$method:ident($($args:expr),*) ) => {
        unsafe {
            $self.vtable.$method
                .ok_or(DisplayBackendError::MethodNotSupported)?( $self.instance, $($args),* )
        }
    };
}

pub struct DisplayBackendInstance {
    instance: *mut c_void,
    vtable: DisplayBasicFramebufferVtable,
    cursor: DisplayCursorVtable,
}

impl DisplayBackendInstance {
    /// Hand the backend the guest's pointer image; a zero size hides it.
    pub fn set_cursor(
        &mut self,
        scanout_id: u32,
        width: u32,
        height: u32,
        hot_x: u32,
        hot_y: u32,
        bgra: &[u8],
    ) -> Result<(), DisplayBackendError> {
        let Some(set_cursor) = self.cursor.set_cursor else {
            return Err(DisplayBackendError::MethodNotSupported);
        };
        into_rust_result!(unsafe {
            set_cursor(
                self.instance,
                scanout_id,
                width,
                height,
                hot_x,
                hot_y,
                bgra.as_ptr(),
                bgra.len(),
            )
        })
    }

    /// Tell the backend where the pointer hot spot now is.
    pub fn move_cursor(
        &mut self,
        scanout_id: u32,
        x: u32,
        y: u32,
    ) -> Result<(), DisplayBackendError> {
        let Some(move_cursor) = self.cursor.move_cursor else {
            return Err(DisplayBackendError::MethodNotSupported);
        };
        into_rust_result!(unsafe { move_cursor(self.instance, scanout_id, x, y) })
    }
}

// By design the struct is !Send and !Sync to allow for the implementation to safely assume that
// the methods are always called on the GPU worker thread
assert_not_impl_any!(DisplayBackendInstance: Sync, Send);

impl Drop for DisplayBackendInstance {
    fn drop(&mut self) {
        let Some(destroy_fn) = self.vtable.destroy else {
            return;
        };

        if let Err(e) = into_rust_result!(unsafe { destroy_fn(self.instance) }) {
            error!("Failed to destroy krun_gtk_display instance: {e}");
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
        into_rust_result!(method_call! {
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
            method_call! {
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
            method_call! {
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
            method_call!{
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
    /// Only meaningful when `features` carries `CURSOR`; zero otherwise.
    pub cursor: DisplayCursorVtable,
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
            // SAFETY: we have checked the feature flags, so basic_framebuffer should be populated
            vtable: unsafe { self.vtable.basic_framebuffer },
            cursor: if DisplayFeatures::from_bits_retain(self.features)
                .contains(DisplayFeatures::CURSOR)
            {
                self.cursor
            } else {
                DisplayCursorVtable {
                    set_cursor: None,
                    move_cursor: None,
                }
            },
        })
    }

    pub fn verify(&self) -> bool {
        let features = DisplayFeatures::from_bits_retain(self.features);

        // This requirement might change in the future when we add support for alternatives to this
        if !features.contains(DisplayFeatures::BASIC_FRAMEBUFFER) {
            error!("This version of libkrun requires BASIC_FRAMEBUFFER feature");
            return false;
        }

        for feature in features {
            if feature.contains(DisplayFeatures::BASIC_FRAMEBUFFER) {
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
            if feature.contains(DisplayFeatures::CURSOR)
                && (self.cursor.set_cursor.is_none() || self.cursor.move_cursor.is_none())
            {
                error!("Missing required methods for CURSOR");
                return false;
            } else {
                warn!("Unknown display features ({feature:x}) will be ignored")
            }
        }
        true
    }
}

unsafe impl Send for DisplayBackend<'_> {}
