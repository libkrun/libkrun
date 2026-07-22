pub mod devices;
pub mod error;
pub mod logging;
pub mod payload;
pub mod vmm_builder;

#[cfg(not(feature = "tee"))]
pub use devices::BalloonDevice;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use devices::FsDevice;
#[cfg(not(feature = "tee"))]
pub use devices::RngDevice;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use devices::FsOverlay;
#[cfg(feature = "blk")]
pub use devices::BlockDevice;
#[cfg(feature = "net")]
pub use devices::NetDevice;
#[cfg(feature = "gpu")]
pub use devices::{DisplayBackend, DisplayInfoBuilder, GpuDevice};
#[cfg(feature = "input")]
pub use devices::InputDevice;
#[cfg(all(feature = "vhost-user", target_os = "linux"))]
pub use devices::VhostUserDevice;
pub use devices::{
    AttachContext, AttachDevice, ConsoleBuilder, ConsoleDevice, DeviceManager, DeviceRequirements,
    MmioDeviceManager, ResolvedShmRegion, VsockDevice,
};
pub use error::{DetailedError, Error};
pub use logging::{LogLevel, LogStyle, LogTarget, init_log};
pub use payload::{KernelFormat, Payload};
pub use vmm_builder::{Vmm, VmmBuilder};

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
    crate::api::devices::ConsoleDevice<'_> = 4,
    crate::api::devices::ConsoleBuilder<'_> = 5,
    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    crate::api::devices::FsOverlay = 6,
    crate::api::payload::Payload = 8,
    crate::api::vmm_builder::VmmBuilder<'_> = 10,
    crate::api::vmm_builder::Vmm<'_> = 11,
    #[cfg(not(feature = "tee"))]
    crate::api::devices::BalloonDevice = 14,
    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    crate::api::devices::AttachDevice for crate::api::devices::FsDevice,
    crate::api::devices::AttachDevice for crate::api::devices::ConsoleDevice,
    #[cfg(not(feature = "tee"))]
    crate::api::devices::RngDevice = 15,
    crate::api::devices::VsockDevice = 16,
    #[cfg(feature = "blk")]
    crate::api::devices::BlockDevice = 17,
    #[cfg(feature = "blk")]
    crate::api::devices::AttachDevice for crate::api::devices::BlockDevice,
    #[cfg(feature = "net")]
    crate::api::devices::NetDevice = 18,
    #[cfg(feature = "net")]
    crate::api::devices::AttachDevice for crate::api::devices::NetDevice,
    #[cfg(feature = "gpu")]
    crate::api::devices::DisplayInfoBuilder = 19,
    #[cfg(all(feature = "vhost-user", target_os = "linux"))]
    crate::api::devices::VhostUserDevice = 20,
    #[cfg(all(feature = "vhost-user", target_os = "linux"))]
    crate::api::devices::AttachDevice for crate::api::devices::VhostUserDevice,
    #[cfg(not(feature = "tee"))]
    crate::api::devices::AttachDevice for crate::api::devices::BalloonDevice,
    #[cfg(not(feature = "tee"))]
    crate::api::devices::AttachDevice for crate::api::devices::RngDevice,
    crate::api::devices::AttachDevice for crate::api::devices::VsockDevice,
    trait ffier_builtins::PushStr = 12,
    trait ffier_builtins::Error = 13,
    Error for crate::api::error::Error,
    enum crate::api::payload::KernelFormat,
    enum crate::api::logging::LogLevel,
    enum crate::api::logging::LogStyle,
    enum crate::api::logging::LogTarget,
    fn crate::api::logging::init_log,
);
