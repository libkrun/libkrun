pub mod device_builders;
pub mod error;
pub mod logging;
pub mod payload;
pub mod vmm_builder;

#[cfg(feature = "ffi")]
pub(crate) use ffier::export_bitflags;

#[cfg(not(feature = "ffi"))]
#[allow(unused_macros)]
macro_rules! export_bitflags {
    ($(#[cfg($($cfg:tt)*)])? bitflags::bitflags! { $($body:tt)* }) => {
        $(#[cfg($($cfg)*)])?
        bitflags::bitflags! { $($body)* }
    };
}
#[cfg(not(feature = "ffi"))]
pub(crate) use export_bitflags;

#[cfg(feature = "aws-nitro")]
pub use crate::NitroConfig;
#[cfg(not(feature = "tee"))]
pub use device_builders::BalloonDevice;
#[cfg(feature = "blk")]
pub use device_builders::BlockDevice;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use device_builders::FsDevice;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use device_builders::FsOverlay;
#[cfg(feature = "input")]
pub use device_builders::InputDevice;
#[cfg(feature = "net")]
pub use device_builders::NetDevice;
#[cfg(feature = "net")]
pub use device_builders::NetFlags;
#[cfg(not(feature = "tee"))]
pub use device_builders::RngDevice;
#[cfg(all(feature = "vhost-user", target_os = "linux"))]
pub use device_builders::VhostUserDevice;
pub use device_builders::{
    AttachContext, AttachDevice, ConsoleBuilder, ConsoleDevice, DeviceManager, DeviceRequirements,
    MmioDeviceManager, ResolvedShmRegion, VsockDevice,
};
#[cfg(feature = "gpu")]
pub use device_builders::{DisplayBackend, DisplayInfoBuilder, GpuDevice, VirglRendererFlags};
#[cfg(feature = "blk")]
pub use devices::virtio::block::{DiskFormat, SyncMode};
pub use error::Error;
pub use logging::{LogLevel, LogOptions, LogStyle, init_log};
pub use payload::{KernelFormat, Payload};
pub use vmm_builder::{Vmm, VmmBuilder, VmmHandle, check_nested_virt};

pub use devices::virtio::TsiFlags;
#[cfg(feature = "net")]
pub use devices::virtio::net::device::VirtioNetBackend;
pub use devices::virtio::port_io;

#[cfg(feature = "ffi")]
ffier::library_definition!("krun", library_tag = 1,
    primitives_prefix = "krun",
    crate::api::error::Error = 1,
    crate::api::device_builders::MmioDeviceManager<'_> = 2,
    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    crate::api::device_builders::FsDevice<'_> = 3,
    crate::api::device_builders::ConsoleDevice<'_> = 4,
    crate::api::device_builders::ConsoleBuilder<'_> = 5,
    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    crate::api::device_builders::FsOverlay = 6,
    crate::api::payload::Payload = 8,
    #[cfg(feature = "aws-nitro")]
    crate::NitroConfig = 9,
    crate::api::vmm_builder::VmmBuilder<'_> = 10,
    crate::api::vmm_builder::Vmm<'_> = 11,
    crate::api::vmm_builder::VmmHandle = 21,
    #[cfg(not(feature = "tee"))]
    crate::api::device_builders::BalloonDevice = 14,
    #[cfg(not(feature = "tee"))]
    crate::api::device_builders::RngDevice = 15,
    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    crate::api::device_builders::AttachDevice for crate::api::device_builders::FsDevice,
    crate::api::device_builders::AttachDevice for crate::api::device_builders::ConsoleDevice,
    crate::api::device_builders::VsockDevice = 16,
    #[cfg(feature = "blk")]
    crate::api::device_builders::BlockDevice = 17,
    #[cfg(feature = "blk")]
    crate::api::device_builders::AttachDevice for crate::api::device_builders::BlockDevice,
    #[cfg(feature = "net")]
    crate::api::device_builders::NetDevice = 18,
    #[cfg(feature = "net")]
    crate::api::device_builders::AttachDevice for crate::api::device_builders::NetDevice,
    #[cfg(feature = "gpu")]
    crate::api::device_builders::DisplayInfoBuilder = 19,
    #[cfg(all(feature = "vhost-user", target_os = "linux"))]
    crate::api::device_builders::VhostUserDevice = 20,
    #[cfg(feature = "gpu")]
    crate::api::device_builders::DisplayBackend = 22,
    #[cfg(feature = "gpu")]
    crate::api::device_builders::GpuDevice = 23,
    #[cfg(feature = "gpu")]
    crate::api::device_builders::AttachDevice for crate::api::device_builders::GpuDevice,
    #[cfg(feature = "input")]
    crate::api::device_builders::InputDevice = 24,
    #[cfg(feature = "input")]
    crate::api::device_builders::AttachDevice for crate::api::device_builders::InputDevice,
    #[cfg(all(feature = "vhost-user", target_os = "linux"))]
    crate::api::device_builders::AttachDevice for crate::api::device_builders::VhostUserDevice,
    #[cfg(not(feature = "tee"))]
    crate::api::device_builders::AttachDevice for crate::api::device_builders::BalloonDevice,
    #[cfg(not(feature = "tee"))]
    crate::api::device_builders::AttachDevice for crate::api::device_builders::RngDevice,
    crate::api::device_builders::AttachDevice for crate::api::device_builders::VsockDevice,
    trait ffier_builtins::PushStr = 12,
    trait ffier_builtins::Error = 13,
    Error for crate::api::error::Error,
    enum crate::api::payload::KernelFormat,
    #[cfg(feature = "blk")]
    enum devices::virtio::block::DiskFormat,
    #[cfg(feature = "blk")]
    enum devices::virtio::block::SyncMode,
    enum crate::api::logging::LogLevel,
    enum crate::api::logging::LogStyle,
    fn crate::api::logging::init_log,
    fn crate::api::vmm_builder::check_nested_virt,
    bitflags crate::api::logging::LogOptions,
    #[cfg(feature = "gpu")]
    bitflags crate::api::device_builders::VirglRendererFlags,
    #[cfg(feature = "net")]
    bitflags crate::api::device_builders::NetFlags,
);
