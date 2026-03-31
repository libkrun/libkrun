// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Batched virtio queue producer/consumer infrastructure.
//!
//! Raw iovecs live in a fixed-capacity ring buffer owned by the batch queue.
//! Each descriptor chain's iovecs occupy a contiguous slice of the ring; when
//! the tail has insufficient room the allocation wraps to physical index 0.
//! Per-chain metadata stores absolute ranges into the ring.  Optional
//! user-transformed state lives in a separate array aligned with the work
//! items.

use std::ops::Range;

use aliased_ioslice::{AliasedIoSlice, AliasedIoSliceMut, AnyIoSlice, RawAliasedIoSlice};

pub mod aliased_ioslice;
mod rx_queue_producer;
mod tx_queue_consumer;

pub use rx_queue_producer::{RxProducerBatch, RxQueueProducer};
pub use tx_queue_consumer::{TxConsumerBatch, TxQueueConsumer};

/// Per-chain state returned by the feed transform and stored alongside each
/// work item.
///
/// `set_iovecs` is called to update cached iovec pointers: once after feed,
/// and again after any `advance` or `truncate` that changes the live window.
/// Implementors like `MsgHdrItem` use this to keep `mmsghdr.msg_iov` in sync.
pub trait WorkItemState: Send {
    fn set_iovecs(&mut self, iovecs: &[RawAliasedIoSlice]);
}

impl WorkItemState for () {
    fn set_iovecs(&mut self, _iovecs: &[RawAliasedIoSlice]) {}
}

/// Optional trait for transformed state that records receive byte counts.
pub trait ReceivedBytes {
    fn received_bytes(&self) -> usize;
}

pub(crate) fn raw_as_io_slices<'a>(iovecs: &'a [RawAliasedIoSlice]) -> &'a [AliasedIoSlice<'a>] {
    // Safety: both wrappers are repr(transparent) over `libc::iovec`.
    unsafe {
        std::slice::from_raw_parts(iovecs.as_ptr() as *const AliasedIoSlice<'a>, iovecs.len())
    }
}

pub(crate) fn raw_as_io_slices_mut<'a>(
    iovecs: &'a mut [RawAliasedIoSlice],
) -> &'a mut [AliasedIoSliceMut<'a>] {
    // Safety: both wrappers are repr(transparent) over `libc::iovec`.
    unsafe {
        std::slice::from_raw_parts_mut(
            iovecs.as_mut_ptr() as *mut AliasedIoSliceMut<'a>,
            iovecs.len(),
        )
    }
}

/// No-allocation sink for transformed iovecs.
///
/// This appends directly into the shared raw-iovec arena instead of collecting
/// a temporary per-chain container first.
///
/// `'iov` is the lifetime of the iovec data (guest memory).  Only iovecs that
/// live at least as long as `'iov` can be pushed, which ties the appender to
/// the descriptor chain iterator that produces the iovecs.
pub struct IovecAppender<'s, 'iov> {
    storage: &'s mut IovecStorage,
    /// Absolute index before any wrap padding from `reserve()`.
    alloc_start: usize,
    /// Absolute index where iovecs are actually pushed (after wrap padding).
    start: usize,
    len: usize,
    reserved: usize,
    total_bytes: usize,
    _marker: std::marker::PhantomData<&'iov ()>,
}

impl<'s, 'iov> IovecAppender<'s, 'iov> {
    pub(crate) fn new(storage: &'s mut IovecStorage) -> Self {
        let pos = storage.end_index();
        Self {
            storage,
            alloc_start: pos,
            start: pos,
            len: 0,
            reserved: 0,
            total_bytes: 0,
            _marker: std::marker::PhantomData,
        }
    }

    /// Reserve `count` contiguous iovec slots in the ring buffer.
    ///
    /// Returns `true` if the reservation succeeded. Returns `false` when the
    /// ring is too full — the caller should return `None` from the transform
    /// so the feed loop can `undo_pop`.
    pub fn reserve(&mut self, count: usize) -> bool {
        assert!(self.reserved == 0, "reserve() called twice");
        let cap = self.storage.buf.len();
        let phys_tail = self.storage.abs_tail % cap;
        if phys_tail + count > cap {
            // wrap to physical 0 — the gap is dead space
            self.storage.abs_tail += cap - phys_tail;
        }
        if self.storage.abs_tail + count - self.storage.abs_head > cap {
            // not enough free slots — undo any wrap padding
            self.storage.abs_tail = self.alloc_start;
            return false;
        }
        self.start = self.storage.abs_tail;
        self.reserved = count;
        true
    }

    /// Append one iovec to the shared arena.
    pub fn push(&mut self, iov: impl AnyIoSlice + 'iov) {
        if iov.is_empty() {
            return;
        }

        assert!(
            self.len < self.reserved,
            "IovecAppender: pushed {} iovecs but only {} were reserved",
            self.len + 1,
            self.reserved,
        );

        let raw = unsafe { RawAliasedIoSlice::from_any(iov) };
        self.total_bytes += raw.len();
        self.storage.push(raw);
        self.len += 1;
    }

    /// Append an iterator of iovecs to the shared arena.
    pub fn extend<I>(&mut self, iovecs: I)
    where
        I: IntoIterator,
        I::Item: AnyIoSlice + 'iov,
    {
        for iov in iovecs {
            self.push(iov);
        }
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub(crate) fn finish(self) -> (usize, Range<usize>, usize) {
        (
            self.alloc_start,
            self.start..self.start + self.len,
            self.total_bytes,
        )
    }
}

/// Fixed-capacity ring buffer for raw iovecs.
///
/// Chains are allocated contiguously: when the tail doesn't have enough room
/// for a chain's iovecs, it wraps to physical index 0.  The gap between the
/// old tail and the buffer end is included in the chain's `allocation` so it
/// is reclaimed when the chain is released.
pub(crate) struct IovecStorage {
    buf: Box<[RawAliasedIoSlice]>,
    /// Monotonically increasing logical head / tail.
    abs_head: usize,
    abs_tail: usize,
}

// Safety: the stored iovecs point into guest memory owned by the surrounding
// queue object.
unsafe impl Send for IovecStorage {}

impl IovecStorage {
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self {
            buf: vec![RawAliasedIoSlice::zeroed(); cap].into_boxed_slice(),
            abs_head: 0,
            abs_tail: 0,
        }
    }

    pub(crate) fn end_index(&self) -> usize {
        self.abs_tail
    }

    pub(crate) fn push(&mut self, iov: RawAliasedIoSlice) {
        let phys = self.abs_tail % self.buf.len();
        self.buf[phys] = iov;
        self.abs_tail += 1;
    }

    pub(crate) fn slice(&self, range: Range<usize>) -> &[RawAliasedIoSlice] {
        if range.is_empty() {
            return &[];
        }
        let cap = self.buf.len();
        let start = range.start % cap;
        let len = range.end - range.start;
        assert!(
            start + len <= cap,
            "slice not contiguous: phys_start={start} len={len} cap={cap} abs_range={range:?} abs_head={} abs_tail={}",
            self.abs_head,
            self.abs_tail,
        );
        &self.buf[start..start + len]
    }

    pub(crate) fn slice_mut(&mut self, range: Range<usize>) -> &mut [RawAliasedIoSlice] {
        if range.is_empty() {
            return &mut [];
        }
        let cap = self.buf.len();
        let start = range.start % cap;
        let len = range.end - range.start;
        assert!(
            start + len <= cap,
            "slice_mut not contiguous: phys_start={start} len={len} cap={cap} abs_range={range:?} abs_head={} abs_tail={}",
            self.abs_head,
            self.abs_tail,
        );
        &mut self.buf[start..start + len]
    }

    pub(crate) fn release_front_len(&mut self, len: usize) {
        self.abs_head += len;
        debug_assert!(self.abs_head <= self.abs_tail);
        if self.abs_head == self.abs_tail {
            self.abs_head = 0;
            self.abs_tail = 0;
        }
    }
}

/// Queue-owned per-chain metadata.
#[derive(Debug, Clone)]
pub(crate) struct WorkItem {
    /// Virtqueue descriptor chain head index, passed back to `add_used` on completion.
    pub(crate) head_index: u16,
    /// Total byte capacity of the transformed iovec window. Used as an upper
    /// bound for `bytes_used` and for computing remaining capacity.
    pub(crate) max_bytes: usize,
    /// Cumulative bytes consumed (TX) or written (RX) so far. For RX this is
    /// the value reported to `add_used`; may be pre-seeded during feed when the
    /// transform writes data (e.g. a vnet header) before I/O begins.
    pub(crate) bytes_used: usize,
    /// Full reservation in the iovec ring, including any dead-space gap from
    /// wrapping. `allocation_len()` is used during release to advance the ring
    /// head by the correct amount.
    pub(crate) allocation: Range<usize>,
    /// Current active iovec window within the ring. Shrinks from the front on
    /// `advance` and from the back on `truncate_bytes`.
    pub(crate) live: Range<usize>,
}

impl WorkItem {
    pub(crate) fn new(
        head_index: u16,
        max_bytes: usize,
        bytes_used: usize,
        allocation: Range<usize>,
        live: Range<usize>,
    ) -> Self {
        Self {
            head_index,
            max_bytes,
            bytes_used,
            allocation,
            live,
        }
    }

    pub(crate) fn raw_slice<'a>(&self, storage: &'a IovecStorage) -> &'a [RawAliasedIoSlice] {
        storage.slice(self.live.clone())
    }

    pub(crate) fn allocation_len(&self) -> usize {
        self.allocation.len()
    }

    pub(crate) fn advance(&mut self, storage: &mut IovecStorage, bytes: usize) {
        if bytes == 0 || self.live.is_empty() {
            return;
        }

        let mut new_start = self.live.start;
        {
            let iovecs = storage.slice_mut(self.live.clone());
            let original_len = iovecs.len();
            let remaining_len = RawAliasedIoSlice::advance_slices(iovecs, bytes).len();
            new_start += original_len - remaining_len;
        }
        self.live.start = new_start;
    }

    pub(crate) fn truncate_bytes(&mut self, storage: &mut IovecStorage, max_bytes: usize) {
        let mut remaining = max_bytes;
        let mut keep = 0;
        let start = self.live.start;

        for iov in storage.slice_mut(self.live.clone()).iter_mut() {
            let len = iov.len();
            if remaining == 0 {
                break;
            }
            if remaining < len {
                iov.shorten(remaining);
                keep += 1;
                remaining = 0;
                break;
            }
            remaining -= len;
            keep += 1;
        }

        if remaining == 0 {
            self.live.end = start + keep;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ioslice(buf: &[u8]) -> AliasedIoSlice<'_> {
        unsafe { AliasedIoSlice::from_raw(buf.as_ptr(), buf.len()) }
    }

    /// Helper: reserve and push N iovecs into storage.
    fn reserve_and_push(
        storage: &mut IovecStorage,
        count: usize,
        iov_len: usize,
    ) -> (usize, Range<usize>) {
        // We need stable pointers, but for testing we only care about ring structure.
        // Use a leaked buffer so pointers stay valid.
        let buf = vec![0u8; iov_len].leak();
        let mut appender = IovecAppender::new(storage);
        assert!(appender.reserve(count));
        for _ in 0..count {
            appender.push(ioslice(buf));
        }
        let (alloc_start, live, _) = appender.finish();
        (alloc_start, live)
    }

    #[test]
    fn reserve_basic() {
        let mut storage = IovecStorage::with_capacity(8);
        let buf = [1u8; 10];

        let mut appender = IovecAppender::new(&mut storage);
        assert!(appender.reserve(3));
        appender.push(ioslice(&buf));
        appender.push(ioslice(&buf));
        appender.push(ioslice(&buf));
        let (alloc_start, live, total) = appender.finish();

        assert_eq!(alloc_start, 0);
        assert_eq!(live, 0..3);
        assert_eq!(total, 30);
        assert_eq!(storage.slice(live).len(), 3);
    }

    #[test]
    fn reserve_wraps_when_tail_near_end() {
        let mut storage = IovecStorage::with_capacity(8);

        // Fill 6 slots (don't release — we need tail to stay at phys 6).
        reserve_and_push(&mut storage, 6, 1);
        // Release only 4 so ring isn't fully drained (head=4, tail=6).
        storage.release_front_len(4);

        // Reserve 4 — doesn't fit at phys 6 (6+4=10>8), should wrap to phys 0.
        let buf = [1u8; 5];
        let mut appender = IovecAppender::new(&mut storage);
        assert!(appender.reserve(4));
        for _ in 0..4 {
            appender.push(ioslice(&buf));
        }
        let (alloc_start, live, _) = appender.finish();

        // alloc_start is pre-wrap position (6), live starts after wrap gap (8)
        assert_eq!(alloc_start, 6);
        assert_eq!(live, 8..12);
        // Physical positions should be 0..4
        assert_eq!(storage.slice(live).len(), 4);
    }

    #[test]
    fn reserve_fails_when_ring_full() {
        let mut storage = IovecStorage::with_capacity(8);

        // Fill 6 slots (not released).
        reserve_and_push(&mut storage, 6, 1);

        // Try to reserve 4 more — only 2 slots free.
        let mut a2 = IovecAppender::new(&mut storage);
        assert!(!a2.reserve(4));

        // But reserving 2 should work.
        let mut a3 = IovecAppender::new(&mut storage);
        assert!(a3.reserve(2));
    }

    #[test]
    fn reserve_fails_when_wrap_still_not_enough() {
        let mut storage = IovecStorage::with_capacity(8);

        // Put 5 in, release 2 from front. head=2, tail=5.
        reserve_and_push(&mut storage, 5, 1);
        storage.release_front_len(2); // head=2, tail=5

        // Try to reserve 5. At phys 5, 5+5=10>8 so wrap to 8.
        // After wrap: tail=8, 8+5-2=11>8. Not enough. Should fail.
        let mut a = IovecAppender::new(&mut storage);
        assert!(!a.reserve(5));

        // Tail should be restored to 5 (no wrap damage).
        assert_eq!(storage.abs_tail, 5);
    }

    #[test]
    #[should_panic(expected = "reserve() called twice")]
    fn reserve_called_twice_panics() {
        let mut storage = IovecStorage::with_capacity(8);
        let mut appender = IovecAppender::new(&mut storage);
        appender.reserve(2);
        appender.reserve(2);
    }

    #[test]
    #[should_panic(expected = "only 2 were reserved")]
    fn push_beyond_reserved_panics() {
        let mut storage = IovecStorage::with_capacity(8);
        let buf = [1u8; 10];

        let mut appender = IovecAppender::new(&mut storage);
        appender.reserve(2);
        appender.push(ioslice(&buf));
        appender.push(ioslice(&buf));
        appender.push(ioslice(&buf)); // 3rd push, only 2 reserved
    }

    #[test]
    fn push_empty_iovec_skipped() {
        let mut storage = IovecStorage::with_capacity(8);
        let buf = [1u8; 10];
        let empty: &[u8] = &[];

        let mut appender = IovecAppender::new(&mut storage);
        appender.reserve(2);
        appender.push(ioslice(&buf));
        appender.push(ioslice(empty)); // skipped, doesn't count
        appender.push(ioslice(&buf));
        let (_, live, total) = appender.finish();

        assert_eq!(live.len(), 2); // only 2 non-empty pushed
        assert_eq!(total, 20);
    }

    #[test]
    fn multiple_chains_contiguous() {
        let mut storage = IovecStorage::with_capacity(8);

        let (_, l1) = reserve_and_push(&mut storage, 3, 10);
        let (_, l2) = reserve_and_push(&mut storage, 2, 20);

        assert_eq!(l1, 0..3);
        assert_eq!(l2, 3..5);
        assert_eq!(storage.slice(l1.clone()).len(), 3);
        assert_eq!(storage.slice(l2.clone()).len(), 2);

        // Release first chain, second still valid.
        storage.release_front_len(l1.len());
        assert_eq!(storage.slice(l2).len(), 2);
    }

    #[test]
    fn release_and_reuse() {
        let mut storage = IovecStorage::with_capacity(4);

        // Fill all 4 slots.
        let (a1, l1) = reserve_and_push(&mut storage, 4, 1);
        assert_eq!(l1, 0..4);

        // Can't reserve any more.
        let mut a = IovecAppender::new(&mut storage);
        assert!(!a.reserve(1));

        // Release all 4 — ring resets to 0.
        storage.release_front_len(l1.end - a1);
        assert_eq!(storage.abs_head, 0);
        assert_eq!(storage.abs_tail, 0);

        // Now we can reserve the full capacity again.
        let (_, l2) = reserve_and_push(&mut storage, 4, 1);
        assert_eq!(l2, 0..4);
        assert_eq!(storage.slice(l2).len(), 4);
    }

    #[test]
    fn slice_contiguity_after_wrap() {
        let mut storage = IovecStorage::with_capacity(8);

        // Fill 6, release 5. head=5, tail=6.
        // (release 5 so there's enough room after the wrap gap)
        reserve_and_push(&mut storage, 6, 1);
        storage.release_front_len(5);

        // Reserve 5 — doesn't fit at phys 6 (6+5=11>8), wraps to phys 0.
        // After wrap: abs_tail=8, check: 8+5-5=8<=8 → OK.
        let (_, live) = reserve_and_push(&mut storage, 5, 1);

        // Live should start at phys 0.
        let phys_start = live.start % 8;
        assert_eq!(phys_start, 0);
        assert_eq!(live.len(), 5);
        // slice should succeed (contiguous at phys 0..5).
        assert_eq!(storage.slice(live).len(), 5);
    }

    #[test]
    fn release_multiple_allocations_spanning_wrap() {
        // cap=8. Chain A at tail end, chain B wraps to phys 0.
        // Release both, then verify full capacity is available.
        let mut storage = IovecStorage::with_capacity(8);

        // Fill 5, release only 3 so ring doesn't drain fully.
        // head=3, tail=5.
        reserve_and_push(&mut storage, 5, 1);
        storage.release_front_len(3);

        // Chain A: 2 iovecs at phys 5..7.
        let (a_alloc, a_live) = reserve_and_push(&mut storage, 2, 10);
        assert_eq!(a_alloc, 5);
        assert_eq!(a_live, 5..7);

        // Chain B: 3 iovecs — wraps. alloc 7..11, live 8..11.
        let (b_alloc, b_live) = reserve_and_push(&mut storage, 3, 20);
        assert_eq!(b_alloc, 7);
        assert_eq!(b_live, 8..11);

        // Verify both slices work.
        assert_eq!(storage.slice(a_live.clone()).len(), 2);
        assert_eq!(storage.slice(b_live.clone()).len(), 3);

        // Release the initial 2 unreleased + chain A + chain B.
        // Initial 2 at alloc 3..5 (len 2), chain A 5..7 (len 2), chain B 7..11 (len 4).
        storage.release_front_len(2 + 2 + 4); // total 8

        // Ring fully drained — should reset to 0.
        assert_eq!(storage.abs_head, 0);
        assert_eq!(storage.abs_tail, 0);

        // Full capacity available.
        let (_, l_new) = reserve_and_push(&mut storage, 8, 1);
        assert_eq!(l_new, 0..8);
        assert_eq!(storage.slice(l_new).len(), 8);
    }

    #[test]
    fn full_capacity_available_after_drain() {
        // After filling and fully draining the ring, we should be able to
        // reserve the full capacity again regardless of where phys_tail ended up.
        let mut storage = IovecStorage::with_capacity(8);

        // Advance phys_tail to 5.
        let (a0, l0) = reserve_and_push(&mut storage, 5, 1);
        storage.release_front_len(l0.end - a0);
        // Ring empty, but phys_tail = 5.

        // Should be able to fit all 8.
        let (_, l) = reserve_and_push(&mut storage, 8, 1);
        assert_eq!(l.len(), 8);
        assert_eq!(storage.slice(l).len(), 8);
    }

    #[test]
    fn release_chain_with_wrap_gap_then_reuse() {
        // After releasing a chain whose allocation includes a wrap gap,
        // verify the freed space is reusable.
        let mut storage = IovecStorage::with_capacity(4);

        // Fill 3, release 2 so there's room after wrap gap. head=2, tail=3.
        reserve_and_push(&mut storage, 3, 1);
        storage.release_front_len(2);

        // Reserve 2: phys 3, 3+2=5>4 → wrap. abs_tail becomes 4, then 4+2-2=4<=4 → OK.
        // alloc=3..6, live=4..6.
        let (a1, l1) = reserve_and_push(&mut storage, 2, 1);
        assert_eq!(a1, 3);
        assert_eq!(l1, 4..6);

        // Release the remaining 1 from initial + the wrapped chain.
        // Initial remainder: alloc 2..3 (len 1), chain: alloc 3..6 (len 3).
        storage.release_front_len(1 + 3);

        // Ring fully drained — resets to 0. Full capacity available.
        assert_eq!(storage.abs_head, 0);
        let (_, l2) = reserve_and_push(&mut storage, 4, 1);
        assert_eq!(l2, 0..4);
        assert_eq!(storage.slice(l2).len(), 4);
    }
}
