use crate::{DisplayBackend, DisplayBackendError, DmabufExport, Rect, ResourceFormat};
use std::ffi::c_void;
use std::ptr::null_mut;

pub trait DisplayBackendNew<T: Sync> {
    fn new(userdata: Option<&T>) -> Self;
}

pub trait DisplayBackendBasicFramebuffer {
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: ResourceFormat,
    ) -> Result<(), DisplayBackendError>;

    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayBackendError>;

    fn alloc_frame(&mut self, scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError>;

    fn present_frame(
        &mut self,
        scanout_id: u32,
        frame_id: u32,
        rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError>;
}

pub trait DisplayBackendDmabuf {
    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayBackendError>;

    fn import_dmabuf(&mut self, dmabuf_export: &DmabufExport) -> Result<u32, DisplayBackendError>;

    fn unref_dmabuf(&mut self, dmabuf_id: u32) -> Result<(), DisplayBackendError>;

    fn configure_scanout_dmabuf(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        dmabuf_id: u32,
        src_rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError>;

    fn present_dmabuf(
        &mut self,
        scanout_id: u32,
        damage_area: Option<&Rect>,
    ) -> Result<(), DisplayBackendError>;
}

pub trait IntoDisplayBackend<T: Sync> {
    fn into_display_backend(userdata: Option<&T>) -> DisplayBackend<'_>;
}

// Note: Removed blanket impl for DisplayBackendBasicFramebuffer to avoid conflicts.
// Types that need BasicFramebuffer vtable should implement IntoDisplayBackend explicitly.

pub mod dmabuf_backend {
    use super::*;

    pub extern "C" fn create_fn<T: Sync, I: DisplayBackendNew<T>>(
        instance: *mut *mut c_void,
        userdata: *const c_void,
        _reserved: *const c_void,
    ) -> i32 {
        unsafe {
            assert_ne!(
                instance,
                null_mut(),
                "Pointer to location where to create instance cannot be null"
            );
            let userdata_ref = (userdata as *const T).as_ref();
            *(instance as *mut *mut I) = Box::into_raw(Box::new(I::new(userdata_ref)));
        }
        0
    }

    pub extern "C" fn destroy_fn<I>(instance: *mut c_void) -> i32 {
        drop(unsafe { Box::from_raw(instance as *mut I) });
        0
    }

    fn cast_instance<'a, I: DisplayBackendDmabuf>(instance: *mut c_void) -> &'a mut I {
        assert_ne!(instance, null_mut());
        unsafe { &mut *(instance as *mut I) }
    }

    /// # Safety
    /// - `instance` must point to a valid, aligned `I` created by `create_fn`, with no concurrent mutable access.
    /// - `dmabuf_export` must point to a valid, readable `DmabufExport`.
    pub unsafe extern "C" fn import_dmabuf_fn<I: DisplayBackendDmabuf>(
        instance: *mut c_void,
        dmabuf_export: *const DmabufExport,
    ) -> i32 {
        let dmabuf =
            unsafe { ptr_to_option_ref(dmabuf_export) }.expect("dmabuf_export must not be null");
        match cast_instance::<I>(instance).import_dmabuf(dmabuf) {
            Ok(dmabuf_id) => dmabuf_id as i32,
            Err(e) => e as i32,
        }
    }

    pub extern "C" fn unref_dmabuf_fn<I: DisplayBackendDmabuf>(
        instance: *mut c_void,
        dmabuf_id: u32,
    ) -> i32 {
        from_rust_result(cast_instance::<I>(instance).unref_dmabuf(dmabuf_id))
    }

    /// # Safety
    /// - `instance` must point to a valid `I` with no concurrent mutable access.
    /// - `src_rect` must be null or point to a valid, readable `Rect`.
    pub unsafe extern "C" fn configure_scanout_dmabuf_fn<I: DisplayBackendDmabuf>(
        instance: *mut c_void,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        dmabuf_id: u32,
        src_rect: *const Rect,
    ) -> i32 {
        let src_rect = unsafe { ptr_to_option_ref(src_rect) };
        from_rust_result(cast_instance::<I>(instance).configure_scanout_dmabuf(
            scanout_id,
            display_width,
            display_height,
            dmabuf_id,
            src_rect,
        ))
    }

    /// # Safety
    /// - `instance` must point to a valid `I` with no concurrent mutable access.
    /// - `damage_area` must be null or point to a valid, readable `Rect`.
    pub unsafe extern "C" fn present_dmabuf_fn<I: DisplayBackendDmabuf>(
        instance: *mut c_void,
        scanout_id: u32,
        damage_area: *const Rect,
    ) -> i32 {
        let damage_area = unsafe { ptr_to_option_ref(damage_area) };
        from_rust_result(cast_instance::<I>(instance).present_dmabuf(scanout_id, damage_area))
    }

    pub extern "C" fn disable_scanout_dmabuf<I: DisplayBackendDmabuf>(
        instance: *mut c_void,
        scanout_id: u32,
    ) -> i32 {
        from_rust_result(cast_instance::<I>(instance).disable_scanout(scanout_id))
    }
}

unsafe fn ptr_to_option_ref<'a, T>(x: *const T) -> Option<&'a T> {
    if x.is_null() {
        None
    } else {
        // SAFETY: this method is unsafe, up to the caller to be sure
        unsafe { Some(&*x) }
    }
}

fn from_rust_result(result: Result<(), DisplayBackendError>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => e as i32,
    }
}
