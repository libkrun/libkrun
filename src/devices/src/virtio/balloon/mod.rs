mod device;
mod event_handler;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(test)]
mod test_util;

#[cfg(target_os = "linux")]
use self::linux::FreePageReclaim;
#[cfg(target_os = "macos")]
use self::macos::FreePageReclaim;

pub use self::defs::uapi::VIRTIO_ID_BALLOON as TYPE_BALLOON;
pub use self::device::Balloon;

mod defs {
    use super::super::QueueConfig;

    pub const BALLOON_DEV_ID: &str = "virtio_balloon";
    pub const NUM_QUEUES: usize = 5;
    pub const QUEUE_SIZE: u16 = 256;
    pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

    pub mod uapi {
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_BALLOON: u32 = 5;
        pub const VIRTIO_BALLOON_F_STATS_VQ: u32 = 1;
        pub const VIRTIO_BALLOON_F_FREE_PAGE_HINT: u32 = 3;
        pub const VIRTIO_BALLOON_F_REPORTING: u32 = 5;
    }
}

/// How the balloon gives the pages of free page reports back to the host.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FreePageReportingMode {
    /// madvise() the reported pages on Linux and macOS, and DiscardVirtualMemory() them on
    /// Windows. On macOS, this doesn't release the pages that the guest has written to.
    #[default]
    Default = 0,
    /// On macOS, have the VMM replace the reported pages with fresh memory, which releases them
    /// even if the guest has written to them, at the cost of a few system calls per report.
    /// Other platforms don't implement this, and use [`FreePageReportingMode::Default`].
    Replace = 1,
}

#[derive(Debug)]
pub enum BalloonError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
    /// Failed to start the thread that reclaims reported pages.
    #[cfg(target_os = "macos")]
    ReclaimThread(std::io::Error),
}

type Result<T> = std::result::Result<T, BalloonError>;
