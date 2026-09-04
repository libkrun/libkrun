mod rust_to_c;
pub use rust_to_c::*;
mod c_to_rust;
pub use c_to_rust::*;

use bitflags::bitflags;
use thiserror::Error;

#[allow(
    non_upper_case_globals,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    unused_variables
)]
mod header {
    include!(concat!(env!("OUT_DIR"), "/display_header.rs"));
}

bitflags! {
    pub struct DisplayFeatures: u64 {
        const BASIC_FRAMEBUFFER = header::KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER as u64;
        const CURSOR = header::KRUN_DISPLAY_FEATURE_CURSOR as u64;
    }
}

pub const MAX_DISPLAYS: usize = 16;

#[derive(Error, Debug)]
#[repr(i32)]
pub enum DisplayBackendError {
    #[error("Backend implementation error")]
    InternalError = header::KRUN_DISPLAY_ERR_INTERNAL,
    #[error("Method not supported")]
    MethodNotSupported = header::KRUN_DISPLAY_ERR_METHOD_UNSUPPORTED,
    #[error("Invalid scanout id")]
    InvalidScanoutId = header::KRUN_DISPLAY_ERR_INVALID_SCANOUT_ID,
    #[error("Invalid parameter")]
    InvalidParam = header::KRUN_DISPLAY_ERR_INVALID_PARAM,
    #[error("Maximum number of buffers has been allocated")]
    OutOfBuffers = header::KRUN_DISPLAY_ERR_OUT_OF_BUFFERS,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ResourceFormat {
    BGRA = header::KRUN_DISPLAY_FORMAT_B8G8R8A8_UNORM,
    BGRX = header::KRUN_DISPLAY_FORMAT_B8G8R8X8_UNORM,
    ARGB = header::KRUN_DISPLAY_FORMAT_A8R8G8B8_UNORM,
    XRGB = header::KRUN_DISPLAY_FORMAT_X8R8G8B8_UNORM,
    RGBA = header::KRUN_DISPLAY_FORMAT_R8G8B8A8_UNORM,
    XBGR = header::KRUN_DISPLAY_FORMAT_X8B8G8R8_UNORM,
    ABGR = header::KRUN_DISPLAY_FORMAT_A8B8G8R8_UNORM,
    RGBX = header::KRUN_DISPLAY_FORMAT_R8G8B8X8_UNORM,
}

impl ResourceFormat {
    pub const BYTES_PER_PIXEL: usize = 4;
}

impl TryFrom<u32> for ResourceFormat {
    type Error = ();

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            header::KRUN_DISPLAY_FORMAT_B8G8R8A8_UNORM => Ok(Self::BGRA),
            header::KRUN_DISPLAY_FORMAT_B8G8R8X8_UNORM => Ok(Self::BGRX),
            header::KRUN_DISPLAY_FORMAT_A8R8G8B8_UNORM => Ok(Self::ARGB),
            header::KRUN_DISPLAY_FORMAT_X8R8G8B8_UNORM => Ok(Self::XRGB),
            header::KRUN_DISPLAY_FORMAT_R8G8B8A8_UNORM => Ok(Self::RGBA),
            header::KRUN_DISPLAY_FORMAT_X8B8G8R8_UNORM => Ok(Self::XBGR),
            header::KRUN_DISPLAY_FORMAT_A8B8G8R8_UNORM => Ok(Self::ABGR),
            header::KRUN_DISPLAY_FORMAT_R8G8B8X8_UNORM => Ok(Self::RGBX),
            _ => Err(()),
        }
    }
}

pub type DisplayVtable = header::krun_display_vtable;
pub type DisplayBasicFramebufferVtable = header::krun_display_basic_framebuffer_vtable;
pub type DisplayCursorVtable = header::krun_display_cursor_vtable;
pub type Rect = header::krun_rect;
