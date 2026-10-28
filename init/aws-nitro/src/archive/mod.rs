use std::io::{Cursor, Read};

use anyhow::Context;
use tar::{Archive, GnuExtSparseHeader, GnuSparseHeader};

use crate::nsm;

/// Extract the tarball from the reader (that is, the memory buffer that
/// read the rootfs archive from the hypervisor vsock) and write it to the
/// enclave's filesystem.
pub fn extract(nsm_fd: i32, rootfs_archive: &[u8]) -> anyhow::Result<()> {
    measure_rootfs(rootfs_archive, |data| {
        nsm::pcr_extend_rootfs(nsm_fd, data).context("unable to extend pcr with rootfs")
    })?;

    // Extract the archive to the root filesystem.
    let mut tar = Archive::new(Cursor::new(rootfs_archive));
    tar.set_preserve_permissions(true);
    tar.set_preserve_ownerships(true);
    tar.unpack("/").context("unable to extract rootfs archive")
}

fn measure_rootfs(
    rootfs_archive: &[u8],
    mut extend: impl FnMut(&[u8]) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut tar = Archive::new(Cursor::new(rootfs_archive));
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
        if entry.header().entry_type().is_gnu_sparse() {
            // Libarchive excludes holes and restarts PCR chunking at each stored extent.
            let mut extend_sparse = |spans: &[GnuSparseHeader]| -> anyhow::Result<()> {
                for span in spans {
                    if !span.is_empty() {
                        let offset = span.offset()? as usize;
                        let length = span.length()? as usize;
                        extend(&data[offset..offset + length])?;
                    }
                }
                Ok(())
            };
            let gnu = entry.header().as_gnu().unwrap();
            extend_sparse(&gnu.sparse)?;

            let mut extended = gnu.is_extended();
            let mut sparse_headers = Cursor::new(rootfs_archive);
            sparse_headers.set_position(entry.raw_file_position());
            while extended {
                let mut header = GnuExtSparseHeader::new();
                sparse_headers
                    .read_exact(header.as_mut_bytes())
                    .context("unable to read extended sparse header")?;
                extend_sparse(header.sparse())?;
                extended = header.is_extended();
            }
        } else {
            extend(&data)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tar::{Builder, EntryType, Header};

    fn payloads(archive: &[u8]) -> Vec<Vec<u8>> {
        let mut payloads = Vec::new();
        measure_rootfs(archive, |data| {
            payloads.extend(data.chunks(2048).map(<[u8]>::to_vec));
            Ok(())
        })
        .unwrap();
        payloads
    }

    fn regular_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        for &(path, data) in entries {
            let mut header = Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(data.len() as u64);
            builder.append_data(&mut header, path, data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn sparse_archive(size: u64, extents: &[(u64, &[u8])]) -> Vec<u8> {
        let mut spans = extents.to_vec();
        if spans
            .last()
            .map(|&(offset, data)| offset + data.len() as u64)
            .unwrap_or(0)
            < size
        {
            spans.push((size, &[]));
        }

        let mut header = Header::new_gnu();
        header.set_path("rootfs/file").unwrap();
        header.set_entry_type(EntryType::GNUSparse);
        header.set_mode(0o644);
        header.set_size(spans.iter().map(|&(_, data)| data.len() as u64).sum());
        let gnu = header.as_gnu_mut().unwrap();
        gnu.set_real_size(size);
        let remaining = &spans[spans.len().min(gnu.sparse.len())..];
        gnu.set_is_extended(!remaining.is_empty());
        for (span, &(offset, data)) in gnu.sparse.iter_mut().zip(&spans) {
            span.set_offset(offset);
            span.set_length(data.len() as u64);
        }
        header.set_cksum();
        let mut archive = header.as_bytes().to_vec();

        for (index, group) in remaining.chunks(21).enumerate() {
            let mut header = GnuExtSparseHeader::new();
            header.set_is_extended((index + 1) * 21 < remaining.len());
            for (span, &(offset, data)) in header.sparse_mut().iter_mut().zip(group) {
                span.set_offset(offset);
                span.set_length(data.len() as u64);
            }
            archive.extend_from_slice(header.as_bytes());
        }
        for &(_, data) in &spans {
            archive.extend_from_slice(data);
        }
        archive.resize(archive.len().next_multiple_of(512) + 1024, 0);
        archive
    }

    #[test]
    fn regular_file_keeps_two_kib_chunk_boundaries() {
        let expected = vec![vec![b'A'; 2048], vec![b'B'; 2048], vec![b'C'; 1024]];
        let data = expected.concat();
        assert_eq!(
            payloads(&regular_archive(&[("rootfs/file", &data)])),
            expected
        );
    }

    #[test]
    fn sparse_holes_are_not_measured() {
        let a = vec![b'A'; 3072];
        let b = vec![b'B'; 512];
        let archive = sparse_archive(65536, &[(4096, &a), (32768, &b)]);
        assert_eq!(
            payloads(&archive),
            vec![vec![b'A'; 2048], vec![b'A'; 1024], b]
        );
    }

    #[test]
    fn adjacent_sparse_extents_restart_chunking() {
        let a = vec![b'A'; 3072];
        let b = vec![b'B'; 2048];
        let archive = sparse_archive(5120, &[(0, &a), (3072, &b)]);
        assert_eq!(
            payloads(&archive),
            vec![vec![b'A'; 2048], vec![b'A'; 1024], b]
        );
    }

    #[test]
    fn extended_sparse_headers_measure_all_extents() {
        let expected: Vec<Vec<u8>> = (1..=26).map(|byte| vec![byte; 512]).collect();
        let extents: Vec<(u64, &[u8])> = expected
            .iter()
            .enumerate()
            .map(|(index, data)| ((index as u64 + 1) * 4096, data.as_slice()))
            .collect();
        assert_eq!(payloads(&sparse_archive(131072, &extents)), expected);
    }

    #[test]
    fn empty_files_and_sparse_holes_do_not_extend_pcr() {
        assert!(payloads(&regular_archive(&[("rootfs/empty", &[])])).is_empty());
        assert!(payloads(&sparse_archive(65536, &[])).is_empty());
    }

    #[test]
    fn hostname_and_hosts_are_not_measured() {
        let archive = regular_archive(&[
            ("rootfs/etc/hostname", b"ephemeral hostname"),
            ("rootfs/etc/hosts", b"ephemeral hosts"),
            ("rootfs/file", b"measured"),
        ]);
        assert_eq!(payloads(&archive), vec![b"measured".to_vec()]);
    }
}
