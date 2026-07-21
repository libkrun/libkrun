pub mod devices;
pub mod error;
pub mod logging;
pub mod payload;

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use devices::FsDevice;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use devices::FsOverlay;
pub use devices::{
    AttachContext, AttachDevice, DeviceManager, DeviceRequirements, MmioDeviceManager,
    ResolvedShmRegion,
};
pub use error::{DetailedError, Error};
pub use logging::{LogLevel, LogStyle, LogTarget, init_log};
pub use payload::{KernelFormat, Payload};

// Re-export from the external `devices` (krun-devices) crate.
// Can't use `devices::` here because `pub mod devices` above shadows it.
pub use crate::reexports::TsiFlags;
#[cfg(feature = "net")]
pub use crate::reexports::VirtioNetBackend;
pub use crate::reexports::port_io;

ffier::library_definition!("krun", library_tag = 1,
    primitives_prefix = "krun",
    crate::api::error::Error = 1,
    crate::api::devices::MmioDeviceManager<'_> = 2,
    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    crate::api::devices::FsDevice<'_> = 3,
    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    crate::api::devices::FsOverlay = 6,
    crate::api::payload::Payload = 8,
    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    crate::api::devices::AttachDevice for crate::api::devices::FsDevice,
    trait ffier_builtins::PushStr = 12,
    trait ffier_builtins::Error = 13,
    Error for crate::api::error::Error,
    enum crate::api::payload::KernelFormat,
    enum crate::api::logging::LogLevel,
    enum crate::api::logging::LogStyle,
    enum crate::api::logging::LogTarget,
    fn crate::api::logging::init_log,
);
