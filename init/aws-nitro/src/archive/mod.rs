use std::io::{Cursor, Read};

use anyhow::Context;

/// Extract the tarball from the reader (that is, the memory buffer that
/// read the rootfs archive from the hypervisor vsock) and write it to the
/// enclave's filesystem.
pub fn extract(nsm_fd: i32, rootfs_archive: &[u8]) -> anyhow::Result<()> {
    // Measure the rootfs data in NSM PCR 16 before extraction.
    let mut tar = tar::Archive::new(Cursor::new(rootfs_archive));
    for entry in tar.entries().context("unable to read tar entries")? {
        let mut entry = entry.context("unable to read tar entry")?;
        let path = entry.path().context("unable to read entry path")?;

        let ignored_paths = ["rootfs/etc/hostname", "rootfs/etc/hosts"];
        if ignored_paths
            .iter()
            .any(|p| path.to_string_lossy().contains(p))
        {
            continue;
        }

        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .context("unable to read entry data")?;
        if !data.is_empty() {
            super::nsm::pcr_extend_rootfs(nsm_fd, &data)
                .context("unable to extend pcr with rootfs")?;
        }
    }

    // Extract the archive to the root filesystem.
    let mut tar = tar::Archive::new(Cursor::new(rootfs_archive));
    tar.set_preserve_permissions(true);
    tar.set_preserve_ownerships(true);
    tar.unpack("/").context("unable to extract rootfs archive")
}
