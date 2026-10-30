//! Locks guest memory into host memory, so that the host never pages it out or compresses it.

use std::io;

/// Locks the `len` bytes at `addr` into memory, which faults them in.
pub fn lock(addr: *mut u8, len: usize) -> io::Result<()> {
    // SAFETY: mlock() only changes whether the pages can be paged out, not what's in them.
    if unsafe { libc::mlock(addr.cast(), len) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What the tests need to check which memory is locked.
#[cfg(test)]
pub(crate) mod testing {
    #[cfg(target_os = "linux")]
    use std::fs;
    use std::io;

    /// The most that the tests of this crate lock in total, possibly at the same time, as they
    /// run in threads of one process and RLIMIT_MEMLOCK is a limit on the process.
    const TESTS_LOCK_AT_MOST: libc::rlim_t = 8 << 20;

    /// Whether RLIMIT_MEMLOCK lets the tests lock memory. The tests that lock memory must only
    /// be skipped when this is false, so that they can't pass when lock() is broken.
    pub fn limit_allows_locking() -> bool {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid rlimit that getrlimit() fills in.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) },
            0
        );
        limit.rlim_cur == libc::RLIM_INFINITY || limit.rlim_cur >= TESTS_LOCK_AT_MOST
    }

    /// How many of the `len` bytes at `addr` this process has wired with mlock().
    #[cfg(target_os = "macos")]
    pub fn wired_bytes(addr: *const u8, len: usize) -> io::Result<u64> {
        use mach::*;

        let start = addr as u64;
        let end = start + len as u64;
        let mut wired = 0;
        let mut address = start;
        while address < end {
            let mut size = 0;
            let mut depth = 0;
            let mut info = VmRegionSubmapInfo64::default();
            let mut count = VM_REGION_SUBMAP_INFO_COUNT_64;
            // SAFETY: the pointers are to local variables, and `count` is the size of `info` in
            // natural_t's.
            let ret = unsafe {
                mach_vm_region_recurse(
                    mach_task_self(),
                    &mut address,
                    &mut size,
                    &mut depth,
                    (&mut info as *mut VmRegionSubmapInfo64).cast(),
                    &mut count,
                )
            };
            match ret {
                KERN_SUCCESS => {}
                // There are no more entries at or above `address`.
                KERN_INVALID_ADDRESS => break,
                _ => {
                    return Err(io::Error::other(format!(
                        "mach_vm_region_recurse() failed: {ret}"
                    )));
                }
            }
            // `address` is now the start of the entry that contains it, or of the next one.
            if address >= end {
                break;
            }
            if { info.user_wired_count } > 0 {
                wired += (address + size).min(end) - address.max(start);
            }
            address += size;
        }
        Ok(wired)
    }

    #[cfg(target_os = "macos")]
    mod mach {
        /// `vm_region_submap_info_data_64_t` from <mach/vm_region.h>, which packs it to 4 bytes.
        #[repr(C, packed(4))]
        #[derive(Default)]
        pub struct VmRegionSubmapInfo64 {
            pub protection: i32,
            pub max_protection: i32,
            pub inheritance: u32,
            pub offset: u64,
            pub user_tag: u32,
            pub pages_resident: u32,
            pub pages_shared_now_private: u32,
            pub pages_swapped_out: u32,
            pub pages_dirtied: u32,
            pub ref_count: u32,
            pub shadow_depth: u16,
            pub external_pager: u8,
            pub share_mode: u8,
            pub is_submap: i32,
            pub behavior: i32,
            pub object_id: u32,
            pub user_wired_count: u16,
            pub pages_reusable: u32,
            pub object_id_full: u64,
        }

        pub const VM_REGION_SUBMAP_INFO_COUNT_64: u32 =
            (size_of::<VmRegionSubmapInfo64>() / size_of::<u32>()) as u32;
        pub const KERN_SUCCESS: i32 = 0;
        pub const KERN_INVALID_ADDRESS: i32 = 1;

        unsafe extern "C" {
            pub fn mach_task_self() -> libc::mach_port_t;
            pub fn mach_vm_region_recurse(
                target_task: libc::mach_port_t,
                address: *mut u64,
                size: *mut u64,
                nesting_depth: *mut u32,
                info: *mut i32,
                info_count: *mut u32,
            ) -> i32;
        }
    }

    /// How many of the `len` bytes at `addr` this process has locked with mlock().
    #[cfg(target_os = "linux")]
    pub fn wired_bytes(addr: *const u8, len: usize) -> io::Result<u64> {
        let smaps = fs::read_to_string("/proc/self/smaps")?;
        let start = addr as u64;
        Ok(locked_in_smaps(&smaps, start, start + len as u64))
    }

    /// The bytes of the mappings in `smaps` that are between `start` and `end` and locked.
    /// mlock() splits mappings at the ends of the range that it locks, so a mapping is either
    /// locked as a whole or not at all.
    #[cfg(target_os = "linux")]
    pub fn locked_in_smaps(smaps: &str, start: u64, end: u64) -> u64 {
        let mut locked = 0;
        let mut mapping = None;
        for line in smaps.lines() {
            let first = line.split_ascii_whitespace().next().unwrap_or_default();
            if let Some((low, high)) = first.split_once('-')
                && let (Ok(low), Ok(high)) =
                    (u64::from_str_radix(low, 16), u64::from_str_radix(high, 16))
            {
                mapping = Some((low, high));
                continue;
            }
            let (Some(kib), Some((low, high))) = (line.strip_prefix("Locked:"), mapping) else {
                continue;
            };
            let overlap = high.min(end).saturating_sub(low.max(start));
            let kib = kib.trim().trim_end_matches("kB").trim();
            if let Ok(kib) = kib.parse::<u64>() {
                locked += (kib << 10).min(overlap);
            }
        }
        locked
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use super::testing::*;
    use super::*;

    const MIB: usize = 1 << 20;

    /// Anonymous memory that is unmapped when dropped.
    struct Mapping(*mut u8, usize);

    impl Mapping {
        fn new(len: usize) -> Self {
            // SAFETY: a new anonymous mapping doesn't alias anything.
            let addr = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            assert_ne!(addr, libc::MAP_FAILED);
            Self(addr.cast(), len)
        }

        fn at(&self, offset: usize) -> *mut u8 {
            assert!(offset <= self.1);
            // SAFETY: the offset is within the mapping.
            unsafe { self.0.add(offset) }
        }
    }

    impl Drop for Mapping {
        fn drop(&mut self) {
            // SAFETY: the mapping is ours, and nothing refers to it any more.
            unsafe { libc::munmap(self.0.cast(), self.1) };
        }
    }

    #[test]
    fn test_lock_locks_the_range() {
        if !limit_allows_locking() {
            eprintln!("skipping, RLIMIT_MEMLOCK doesn't let this test lock 4 MiB");
            return;
        }
        let mapping = Mapping::new(8 * MIB);
        assert_eq!(wired_bytes(mapping.at(0), 8 * MIB).unwrap(), 0);

        lock(mapping.at(2 * MIB), 4 * MIB).unwrap();
        assert_eq!(wired_bytes(mapping.at(0), 8 * MIB).unwrap(), 4 * MIB as u64);
        assert_eq!(
            wired_bytes(mapping.at(2 * MIB), 4 * MIB).unwrap(),
            4 * MIB as u64
        );
        // Only the part of the range that is locked counts.
        assert_eq!(wired_bytes(mapping.at(0), 3 * MIB).unwrap(), MIB as u64);
        assert_eq!(
            wired_bytes(mapping.at(5 * MIB), 3 * MIB).unwrap(),
            MIB as u64
        );
        assert_eq!(wired_bytes(mapping.at(6 * MIB), 2 * MIB).unwrap(), 0);

        // SAFETY: the range is part of the mapping.
        assert_eq!(
            unsafe { libc::munlock(mapping.at(2 * MIB).cast(), 4 * MIB) },
            0
        );
        assert_eq!(wired_bytes(mapping.at(0), 8 * MIB).unwrap(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_locked_in_smaps() {
        let smaps = "\
00400000-00500000 r-xp 00000000 08:01 1234       /usr/bin/krun
Size:               1024 kB
Locked:                0 kB
7f0000000000-7f0000400000 rw-p 00000000 00:00 0
Size:               4096 kB
Rss:                4096 kB
Locked:             4096 kB
VmFlags: rd wr mr mw me lo ac
7f0000400000-7f0000800000 rw-p 00000000 00:00 0
Size:               4096 kB
Locked:                0 kB
";
        let (locked, unlocked, end) = (0x7f00_0000_0000, 0x7f00_0040_0000, 0x7f00_0080_0000);
        assert_eq!(locked_in_smaps(smaps, locked, end), 4 << 20);
        assert_eq!(locked_in_smaps(smaps, locked, unlocked), 4 << 20);
        assert_eq!(
            locked_in_smaps(smaps, locked + 0x10_0000, unlocked),
            3 << 20
        );
        assert_eq!(locked_in_smaps(smaps, unlocked, end), 0);
        assert_eq!(locked_in_smaps(smaps, 0x40_0000, 0x50_0000), 0);
    }
}
