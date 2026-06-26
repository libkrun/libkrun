#[cfg(not(feature = "aws-nitro"))]
use devices::virtio::fs::passthrough::PermissionSemantics;
#[cfg(not(feature = "aws-nitro"))]
use devices::virtio::fs::virtual_entry::VirtualDirEntry;

#[derive(Clone, Debug)]
pub struct FsDeviceConfig {
    pub fs_id: String,
    /// Host directory to pass through. None means a virtual-only filesystem
    /// (NullFs + AugmentFs, no host directory).
    pub shared_dir: Option<String>,
    pub semantics: PermissionSemantics,
    pub shm_size: Option<usize>,
    pub read_only: bool,
    #[cfg(not(feature = "aws-nitro"))]
    pub virtual_entries: Vec<VirtualDirEntry>,
}
