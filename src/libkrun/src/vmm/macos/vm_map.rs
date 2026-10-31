//! The map entries of this process as `mach_vm_region_recurse()` and `mach_vm_region()` report
//! them, for tests that check how guest memory is mapped.

use std::mem::size_of;

pub struct Entry {
    pub start: u64,
    pub size: u64,
    pub object_id: u32,
    /// Of the entry's range in its VM object.
    pub offset: u64,
    /// The pages of the entry's range that are resident.
    pub resident: u32,
    /// The pages of the entry's VM object that are resident, wherever they are in it.
    pub object_resident: u32,
}

/// `vm_region_submap_info_data_64_t` from <mach/vm_region.h>, which packs it to 4 bytes.
#[repr(C, packed(4))]
#[derive(Default)]
#[allow(dead_code)]
struct SubmapInfo64 {
    protection: i32,
    max_protection: i32,
    inheritance: u32,
    offset: u64,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    ref_count: u32,
    shadow_depth: u16,
    external_pager: u8,
    share_mode: u8,
    is_submap: i32,
    behavior: i32,
    object_id: u32,
    user_wired_count: u16,
    pages_reusable: u32,
    object_id_full: u64,
}

/// `vm_region_top_info_data_t` from <mach/vm_region.h>.
#[repr(C, packed(4))]
#[derive(Default)]
#[allow(dead_code)]
struct TopInfo {
    obj_id: u32,
    ref_count: u32,
    private_pages_resident: u32,
    shared_pages_resident: u32,
    share_mode: u8,
}

const VM_REGION_TOP_INFO: i32 = 12;

unsafe extern "C" {
    fn mach_task_self() -> libc::mach_port_t;
    fn mach_vm_region_recurse(
        target_task: libc::mach_port_t,
        address: *mut u64,
        size: *mut u64,
        nesting_depth: *mut u32,
        info: *mut i32,
        info_count: *mut u32,
    ) -> i32;
    fn mach_vm_region(
        target_task: libc::mach_port_t,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        info_count: *mut u32,
        object_name: *mut libc::mach_port_t,
    ) -> i32;
}

fn count<T>() -> u32 {
    (size_of::<T>() / size_of::<u32>()) as u32
}

/// The map entry that contains `addr`.
pub fn entry(addr: u64) -> Entry {
    let (mut start, mut size, mut depth) = (addr, 0, 0);
    let mut info = SubmapInfo64::default();
    let mut info_count = count::<SubmapInfo64>();
    // SAFETY: the pointers are to locals, and the counts are their sizes in natural_t's.
    let ret = unsafe {
        mach_vm_region_recurse(
            mach_task_self(),
            &mut start,
            &mut size,
            &mut depth,
            (&mut info as *mut SubmapInfo64).cast(),
            &mut info_count,
        )
    };
    assert_eq!(ret, 0, "mach_vm_region_recurse({addr:#x})");
    assert!(start <= addr, "no entry contains {addr:#x}");

    let (mut top_start, mut top_size, mut object_name) = (start, 0, 0);
    let mut top = TopInfo::default();
    let mut top_count = count::<TopInfo>();
    // SAFETY: as above.
    let ret = unsafe {
        mach_vm_region(
            mach_task_self(),
            &mut top_start,
            &mut top_size,
            VM_REGION_TOP_INFO,
            (&mut top as *mut TopInfo).cast(),
            &mut top_count,
            &mut object_name,
        )
    };
    assert_eq!(ret, 0, "mach_vm_region({start:#x})");
    Entry {
        start,
        size,
        object_id: info.object_id,
        offset: info.offset,
        resident: info.pages_resident,
        object_resident: top.private_pages_resident.max(top.shared_pages_resident),
    }
}
