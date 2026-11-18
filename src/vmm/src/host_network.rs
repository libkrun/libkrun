// SPDX-License-Identifier: Apache-2.0

//! Validate the selected kernel, not its filename or packaging version.

use memchr::memmem;
#[cfg(target_arch = "x86_64")]
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use crate::builder::StartMicrovmError;

pub const ABI_VERSION: u32 = devices::virtio::vsock::HOST_NETWORK_ABI_VERSION;
const MARKER: &[u8] = b"KRUN_TSI_HOST_NETWORK_ABI_8\0";
#[cfg(target_arch = "x86_64")]
const CHUNK_SIZE: usize = 64 * 1024;

fn unsupported() -> StartMicrovmError {
    StartMicrovmError::HostNetwork("the loaded kernel does not support host-network ABI 8")
}

pub(crate) fn require_image(image: &[u8]) -> Result<(), StartMicrovmError> {
    if memmem::find(image, MARKER).is_some() {
        Ok(())
    } else {
        Err(unsupported())
    }
}

/// Inspect only loaded guest bytes below the ELF loader's kernel end. This
/// includes load segments preceding the entry point, and excludes debug data
/// or a marker appended to the file without belonging to a load segment.
/// Called before initrd/boot metadata is written and before vCPUs start.
#[cfg(target_arch = "x86_64")]
pub(crate) fn require_loaded(
    memory: &GuestMemoryMmap,
    kernel_end: u64,
) -> Result<(), StartMicrovmError> {
    let mut buffer = vec![0; CHUNK_SIZE + MARKER.len() - 1];
    let mut retained = 0;
    let mut previous_end = None;
    for region in memory.iter() {
        let start = region.start_addr().raw_value();
        if previous_end != Some(start) {
            retained = 0;
        }
        let end = region
            .last_addr()
            .raw_value()
            .saturating_add(1)
            .min(kernel_end);
        let mut address = start;
        while address < end {
            let count = (end - address).min(CHUNK_SIZE as u64) as usize;
            memory
                .read_slice(
                    &mut buffer[retained..retained + count],
                    GuestAddress(address),
                )
                .map_err(|_| unsupported())?;
            let used = retained + count;
            if memmem::find(&buffer[..used], MARKER).is_some() {
                return Ok(());
            }
            retained = used.min(MARKER.len() - 1);
            buffer.copy_within(used - retained..used, 0);
            address += count as u64;
        }
        previous_end = Some(end);
    }
    Err(unsupported())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_different_or_unterminated_abi_is_rejected() {
        for image in [
            &b"old kernel"[..],
            &b"KRUN_TSI_HOST_NETWORK_ABI_1\0"[..],
            &b"KRUN_TSI_HOST_NETWORK_ABI_2\0"[..],
            &b"KRUN_TSI_HOST_NETWORK_ABI_3\0"[..],
            &b"KRUN_TSI_HOST_NETWORK_ABI_4\0"[..],
            &b"KRUN_TSI_HOST_NETWORK_ABI_5\0"[..],
            &b"KRUN_TSI_HOST_NETWORK_ABI_6\0"[..],
            &b"KRUN_TSI_HOST_NETWORK_ABI_7\0"[..],
            &b"KRUN_TSI_HOST_NETWORK_ABI_10\0"[..],
            &MARKER[..MARKER.len() - 1],
        ] {
            assert!(require_image(image).is_err());
        }
        assert!(require_image(MARKER).is_ok());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn loaded_scan_handles_chunk_boundaries_and_excludes_unloaded_bytes() {
        let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), CHUNK_SIZE * 3)]).unwrap();
        let address = GuestAddress((CHUNK_SIZE - 5) as u64);
        memory.write_slice(MARKER, address).unwrap();
        assert!(require_loaded(&memory, CHUNK_SIZE as u64).is_err());
        assert!(require_loaded(&memory, (CHUNK_SIZE * 2) as u64).is_ok());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn loaded_scan_skips_unmapped_gaps() {
        let memory =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096), (GuestAddress(0x20000), 4096)])
                .unwrap();
        memory.write_slice(MARKER, GuestAddress(0x20100)).unwrap();
        assert!(require_loaded(&memory, 0x21000).is_ok());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn loaded_scan_joins_adjacent_regions_but_not_gaps() {
        for second_start in [4096, 8192] {
            let memory = GuestMemoryMmap::from_ranges(&[
                (GuestAddress(0), 4096),
                (GuestAddress(second_start), 4096),
            ])
            .unwrap();
            memory
                .write_slice(&MARKER[..5], GuestAddress(4091))
                .unwrap();
            memory
                .write_slice(&MARKER[5..], GuestAddress(second_start))
                .unwrap();
            assert_eq!(require_loaded(&memory, 12288).is_ok(), second_start == 4096);
        }
    }
}
