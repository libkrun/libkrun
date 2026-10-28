use vm_memory::GuestMemoryMmap;
use windows_sys::Win32::System::Memory::DiscardVirtualMemory;

use super::device::{FreeRange, coalesce};

/// Gives the pages of free page reports back to the host with DiscardVirtualMemory().
#[derive(Default)]
pub(super) struct FreePageReclaim;

impl FreePageReclaim {
    /// Whether another report can be taken from the queue. Reports are released right away, so
    /// it always can.
    pub(super) fn can_take_report(&self) -> bool {
        true
    }

    /// Gives the pages of a report back to the host. That's done right away, so this returns
    /// false: the report can be used right away.
    pub(super) fn release(
        &mut self,
        mem: &GuestMemoryMmap,
        head: u16,
        ranges: Vec<FreeRange>,
    ) -> bool {
        self.release_with(mem, head, ranges, |range| {
            // SAFETY: the range is guest memory, whose contents the guest has given up.
            unsafe { DiscardVirtualMemory(range.host_addr.cast(), range.len) };
        })
    }

    /// Like [`FreePageReclaim::release`], with `discard` giving back each run of adjacent ranges.
    /// The tests use it to count the calls.
    pub(super) fn release_with(
        &mut self,
        mem: &GuestMemoryMmap,
        _head: u16,
        ranges: Vec<FreeRange>,
        mut discard: impl FnMut(&FreeRange),
    ) -> bool {
        for range in coalesce(mem, ranges) {
            discard(&range);
        }
        false
    }
}
