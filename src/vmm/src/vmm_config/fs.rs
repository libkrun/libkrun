#[cfg(not(feature = "aws-nitro"))]
use devices::virtio::fs::virtual_entry::VirtualDirEntry;

#[derive(Clone, Debug)]
pub struct FsDeviceConfig {
    pub fs_id: String,
    /// Host directory to pass through. None means a virtual-only filesystem
    /// (NullFs + AugmentFs, no host directory).
    pub shared_dir: Option<String>,
    pub shm_size: Option<usize>,
    pub read_only: bool,
    /// Serve ownership and mode from the `user.containers.override_stat`
    /// xattr (see the passthrough `Config`).
    pub override_stat: bool,
    /// Let the guest keep a missing name for a second (see the passthrough
    /// `Config::negative_timeout`).
    pub negative_entries: bool,
    /// Serve host directories attached and detached at runtime (see
    /// `devices::virtio::fs::live_fs`) instead of one fixed directory.
    pub live: bool,
    /// The owner a file is served as when it records none of its own (see the
    /// passthrough `Config::default_owner`).
    pub default_owner: Option<(u32, u32)>,
    #[cfg(not(feature = "aws-nitro"))]
    pub virtual_entries: Vec<VirtualDirEntry>,
}
