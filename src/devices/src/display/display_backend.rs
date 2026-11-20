use krun_display::{
    DisplayBackend, DisplayBackendBasicFramebuffer, DisplayBackendError, DisplayBackendNew,
    DisplayBasicFramebufferVtable, DisplayFeatures, DisplayVtable, IntoDisplayBackend, Rect,
    ResourceFormat,
};
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::{null, null_mut};

pub struct NoopDisplayBackend;

impl DisplayBackendNew<()> for NoopDisplayBackend {
    fn new(_userdata: Option<&()>) -> Self {
        Self
    }
}

impl DisplayBackendBasicFramebuffer for NoopDisplayBackend {
    fn configure_scanout(
        &mut self,
        _scanout_id: u32,
        _display_width: u32,
        _display_height: u32,
        _width: u32,
        _height: u32,
        _format: ResourceFormat,
    ) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn disable_scanout(&mut self, _scanout_id: u32) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn alloc_frame(&mut self, _scanout_id: u32) -> Result<(u32, &mut [u8]), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }

    fn present_frame(
        &mut self,
        _scanout_id: u32,
        _frame_id: u32,
        _rect: Option<&Rect>,
    ) -> Result<(), DisplayBackendError> {
        Err(DisplayBackendError::InvalidScanoutId)
    }
}

impl IntoDisplayBackend<()> for NoopDisplayBackend {
    fn into_display_backend(_userdata: Option<&()>) -> DisplayBackend<'_> {
        extern "C" fn create_fn(
            instance: *mut *mut c_void,
            _userdata: *const c_void,
            _reserved: *const c_void,
        ) -> i32 {
            unsafe {
                assert_ne!(instance, null_mut());
                *(instance as *mut *mut NoopDisplayBackend) =
                    Box::into_raw(Box::new(NoopDisplayBackend));
            }
            0
        }

        extern "C" fn destroy_fn(instance: *mut c_void) -> i32 {
            drop(unsafe { Box::from_raw(instance as *mut NoopDisplayBackend) });
            0
        }

        fn cast_instance(instance: *mut c_void) -> &'static mut NoopDisplayBackend {
            assert_ne!(instance, null_mut());
            unsafe { &mut *(instance as *mut NoopDisplayBackend) }
        }

        unsafe fn ptr_to_option_ref<'a, T>(x: *const T) -> Option<&'a T> {
            if x.is_null() {
                None
            } else {
                unsafe { Some(&*x) }
            }
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
            from_rust_result(cast_instance(instance).disable_scanout(scanout_id))
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

        DisplayBackend {
            create_userdata: null(),
            create_userdata_lifetime: PhantomData,
            features: DisplayFeatures::BASIC_FRAMEBUFFER.bits(),
            create_fn: Some(create_fn),
            vtable: DisplayVtable {
                basic_framebuffer: DisplayBasicFramebufferVtable {
                    destroy: Some(destroy_fn),
                    configure_scanout: Some(configure_scanout_fn),
                    present_frame: Some(present_frame_fn),
                    alloc_frame: Some(alloc_frame_fn),
                    disable_scanout: Some(disable_scanout_fn),
                    import_dmabuf: None,
                    unref_dmabuf: None,
                    configure_scanout_dmabuf: None,
                    present_dmabuf: None,
                },
            },
        }
    }
}
