mod device;
pub mod display;
mod edid;
mod mapping;
mod protocol;
mod virtio_gpu;
mod worker;

use super::descriptor_utils::Error as DescriptorError;

pub use self::defs::uapi::VIRTIO_ID_GPU as TYPE_GPU;
pub use self::device::Gpu;
pub use self::mapping::supports_virgl_renderer_resource_map_fixed;

mod defs {
    pub const GPU_DEV_ID: &str = "virtio_gpu";
    pub const NUM_QUEUES: usize = 2;

    #[allow(dead_code)]
    pub mod uapi {
        use vm_memory::ByteValued;

        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_GPU: u32 = 16;

        pub const VIRTIO_GPU_F_VIRGL: u32 = 0;
        pub const VIRTIO_GPU_F_EDID: u32 = 1;
        pub const VIRTIO_GPU_F_RESOURCE_UUID: u32 = 2;
        pub const VIRTIO_GPU_F_RESOURCE_BLOB: u32 = 3;
        pub const VIRTIO_GPU_F_CONTEXT_INIT: u32 = 4;
        /* The following capabilities are not upstreamed. */
        pub const VIRTIO_GPU_F_RESOURCE_SYNC: u32 = 5;
        pub const VIRTIO_GPU_F_CREATE_GUEST_HANDLE: u32 = 6;

        #[derive(Copy, Clone, Debug, Default)]
        #[repr(C)]
        pub struct virtio_gpu_config {
            pub events_read: u32,
            pub events_clear: u32,
            pub num_scanouts: u32,
            pub num_capsets: u32,
        }
        unsafe impl ByteValued for virtio_gpu_config {}
    }
}

#[derive(Debug)]
pub enum GpuError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
    /// Failed to decode incoming command.
    DecodeCommand(std::io::Error),
    /// Error creating Reader for Queue.
    QueueReader(DescriptorError),
    /// Error creating Writer for Queue.
    QueueWriter(DescriptorError),
    /// Error writting to the Queue.
    WriteDescriptor(std::io::Error),
    /// Error reading Guest Memory,
    GuestMemory,
}

type Result<T> = std::result::Result<T, GpuError>;
