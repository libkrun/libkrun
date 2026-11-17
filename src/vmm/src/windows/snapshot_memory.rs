// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Capture reserved device windows without faulting their unused pages in.

use std::io::{self, Write};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    VirtualQuery,
};

const CHUNK: usize = 1024 * 1024;

/// Write committed bytes and zeros for uncommitted reservations in the same
/// dense format used on other platforms. In particular, do not hand reserved
/// addresses to `WriteFile`: kernel I/O cannot invoke our user-mode lazy-memory
/// fault handler, and touching them first would commit the entire DAX window.
///
/// # Safety
/// `source..source + len` must belong to a live guest-memory region. The caller
/// must freeze vCPUs and device workers so its mappings and bytes remain stable.
pub(crate) unsafe fn write_region<W: Write>(
    source: *const u8,
    len: usize,
    output: &mut W,
) -> io::Result<()> {
    let zeros = vec![0_u8; CHUNK.min(len)];
    let mut offset = 0;
    while offset < len {
        // SAFETY: the caller owns the whole address range, including reserved
        // pages; querying it does not dereference the pointer.
        let address = unsafe { source.add(offset) };
        let mut info = MEMORY_BASIC_INFORMATION::default();
        if unsafe { VirtualQuery(address.cast(), &mut info, size_of_val(&info)) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let within = (address as usize)
            .checked_sub(info.BaseAddress as usize)
            .ok_or_else(|| io::Error::other("memory query starts past guest address"))?;
        let count = info
            .RegionSize
            .checked_sub(within)
            .filter(|count| *count > 0)
            .ok_or_else(|| io::Error::other("memory query does not cover guest address"))?
            .min(len - offset);
        match info.State {
            MEM_RESERVE => {
                let mut remaining = count;
                while remaining > 0 {
                    let n = remaining.min(zeros.len());
                    output.write_all(&zeros[..n])?;
                    remaining -= n;
                }
            }
            MEM_COMMIT
                if info.Protect & PAGE_GUARD == 0
                    && matches!(
                        info.Protect & 0xff,
                        PAGE_READONLY
                            | PAGE_READWRITE
                            | PAGE_WRITECOPY
                            | PAGE_EXECUTE_READ
                            | PAGE_EXECUTE_READWRITE
                            | PAGE_EXECUTE_WRITECOPY
                    ) =>
            {
                // SAFETY: VirtualQuery verified readable committed pages;
                // frozen workers cannot change the mapping during the copy.
                let bytes = unsafe { std::slice::from_raw_parts(address, count) };
                for chunk in bytes.chunks(CHUNK) {
                    output.write_all(chunk)?;
                }
            }
            _ => {
                // Only an uncommitted reservation represents implicit zeros.
                // A free, guarded or inaccessible committed range is an error,
                // never silently discarded guest state.
                return Err(io::Error::other(format!(
                    "unreadable guest memory at offset {offset:#x}: state {:#x}, protection {:#x}",
                    info.State, info.Protect
                )));
            }
        }
        offset += count;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Memory::{
        MEM_RELEASE, PAGE_NOACCESS, VirtualAlloc, VirtualFree, VirtualProtect,
    };

    struct Reservation(*mut u8);

    impl Reservation {
        fn new(len: usize) -> Self {
            let ptr = unsafe { VirtualAlloc(std::ptr::null(), len, MEM_RESERVE, PAGE_READWRITE) };
            assert!(!ptr.is_null());
            Self(ptr.cast())
        }

        fn commit(&self, offset: usize, len: usize, value: u8) {
            let ptr =
                unsafe { VirtualAlloc(self.0.add(offset).cast(), len, MEM_COMMIT, PAGE_READWRITE) };
            assert!(!ptr.is_null());
            unsafe { ptr.cast::<u8>().write_bytes(value, len) };
        }

        fn state(&self, offset: usize) -> u32 {
            let mut info = MEMORY_BASIC_INFORMATION::default();
            assert_ne!(
                unsafe { VirtualQuery(self.0.add(offset).cast(), &mut info, size_of_val(&info)) },
                0
            );
            info.State
        }
    }

    impl Drop for Reservation {
        fn drop(&mut self) {
            assert_ne!(unsafe { VirtualFree(self.0.cast(), 0, MEM_RELEASE) }, 0);
        }
    }

    #[test]
    fn reserved_holes_stay_uncommitted_and_committed_bytes_survive() {
        const LEN: usize = 3 * CHUNK;
        let memory = Reservation::new(LEN);
        memory.commit(4096, 4096, 0xa5);
        memory.commit(2 * CHUNK, 4096, 0x5a);
        let mut output = Vec::new();
        unsafe { write_region(memory.0, LEN, &mut output) }.unwrap();
        let mut expected = vec![0; LEN];
        expected[4096..8192].fill(0xa5);
        expected[2 * CHUNK..2 * CHUNK + 4096].fill(0x5a);
        assert_eq!(output, expected);
        for offset in [0, 8192, CHUNK, LEN - 1] {
            assert_eq!(memory.state(offset), MEM_RESERVE);
        }
        assert_eq!(memory.state(4096), MEM_COMMIT);
        // A descriptor can start and end within a VirtualQuery span.
        let mut partial = Vec::new();
        unsafe { write_region(memory.0.add(4097), 8192, &mut partial) }.unwrap();
        assert_eq!(partial, expected[4097..4097 + 8192]);
    }

    #[test]
    fn inaccessible_committed_memory_is_an_error() {
        for protection in [PAGE_NOACCESS, PAGE_READWRITE | PAGE_GUARD] {
            let memory = Reservation::new(4096);
            memory.commit(0, 4096, 0xa5);
            let mut previous = 0;
            assert_ne!(
                unsafe { VirtualProtect(memory.0.cast(), 4096, protection, &mut previous) },
                0
            );
            let error = unsafe { write_region(memory.0, 4096, &mut Vec::new()) }.unwrap_err();
            assert!(error.to_string().contains("unreadable guest memory"));
        }
    }

    #[test]
    fn output_errors_are_propagated_for_reserved_and_committed_memory() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::StorageFull, "disk full"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let memory = Reservation::new(4096);
        for committed in [false, true] {
            if committed {
                memory.commit(0, 4096, 0xa5);
            }
            let error = unsafe { write_region(memory.0, 4096, &mut FailingWriter) }.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        }
    }
}
