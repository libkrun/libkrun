#![cfg(not(target_os = "windows"))]

mod rust_to_c;

use bitflags::bitflags;
pub use rust_to_c::*;
use std::cmp::max;

mod c_to_rust;
pub use c_to_rust::{
    InputConfigBackend, InputConfigInstance, InputEventProviderBackend, InputEventProviderInstance,
};

use thiserror::Error;

#[allow(
    non_upper_case_globals,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    unused_variables
)]
mod header {
    include!(concat!(env!("OUT_DIR"), "/input_header.rs"));
}

bitflags! {
    pub struct ConfigFeatures: u64 {
        const QUERY = header::KRUN_INPUT_EVENT_PROVIDER_FEATURE_QUEUE as u64;
    }
}

bitflags! {
    pub struct EventProviderFeatures: u64 {
        const QUEUE  = header::KRUN_INPUT_EVENT_PROVIDER_FEATURE_QUEUE as u64;
    }
}

#[derive(Error, Debug)]
#[repr(i32)]
pub enum InputBackendError {
    #[error("Backend implementation error")]
    InternalError = header::KRUN_INPUT_ERR_INTERNAL,
    #[error("Try again later")]
    Again = header::KRUN_INPUT_ERR_EAGAIN,
    #[error("Method not supported")]
    MethodNotSupported = header::KRUN_INPUT_ERR_METHOD_UNSUPPORTED,
    #[error("Invalid parameter")]
    InvalidParam = header::KRUN_INPUT_ERR_INVALID_PARAM,
}

/// Input event types matching Linux input event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum InputEventType {
    Syn = 0x00, // EV_SYN
    Key = 0x01, // EV_KEY
    Rel = 0x02, // EV_REL
    Abs = 0x03, // EV_ABS
    Msc = 0x04, // EV_MSC
    Sw = 0x05,  // EV_SW
    Led = 0x11, // EV_LED
    Snd = 0x12, // EV_SND
    Rep = 0x14, // EV_REP
}

impl TryFrom<u16> for InputEventType {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Syn),
            0x01 => Ok(Self::Key),
            0x02 => Ok(Self::Rel),
            0x03 => Ok(Self::Abs),
            0x04 => Ok(Self::Msc),
            0x05 => Ok(Self::Sw),
            0x11 => Ok(Self::Led),
            0x12 => Ok(Self::Snd),
            0x14 => Ok(Self::Rep),
            _ => Err(()),
        }
    }
}

impl From<InputEventType> for u16 {
    fn from(val: InputEventType) -> Self {
        val as u16
    }
}

pub type InputEvent = header::krun_input_event;
pub type InputDeviceIds = header::krun_input_device_ids;
pub type InputAbsInfo = header::krun_input_absinfo;

/// Writes the specific bits in bitmap, given the indices of the bits
/// Return the "length" of the newly constructed bitmap
pub fn write_bitmap(bitmap: &mut [u8], active_bits: &[u16]) -> u8 {
    let mut max_byte: u8 = 0;
    for idx in active_bits {
        let byte_pos = (idx / 8).try_into().unwrap();
        let additional_bit = 1 << (idx % 8);
        if byte_pos as usize > bitmap.len() {
            panic!("Bit index {idx} out of bounds");
        }
        bitmap[byte_pos as usize] |= additional_bit;
        max_byte = max(max_byte, byte_pos);
    }
    max_byte.checked_add(1).unwrap()
}
