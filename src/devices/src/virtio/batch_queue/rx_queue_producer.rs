// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! RX queue producer for batched virtio receive operations.

use std::ops::Range;

use vm_memory::{GuestMemoryBackend, GuestMemoryMmap};

use super::super::queue::{DescIter, DescriptorChain, Queue};
use super::aliased_ioslice::{AliasedIoSliceMut, AnyIoSlice};
use super::{
    IovecAppender, IovecStorage, ReceivedBytes, WorkItem, WorkItemState, raw_as_io_slices_mut,
};

/// Iterator over the writable slices in one descriptor chain.
///
/// Implements `ExactSizeIterator` so the transform can call `.len()` to know
/// how many iovecs to reserve before pushing.
pub struct WritableChainIter<'a> {
    inner: DescIter<'a>,
    remaining: usize,
}

impl<'a> WritableChainIter<'a> {
    fn new(head: DescriptorChain<'a>) -> Self {
        let remaining = head
            .clone()
            .into_iter()
            .filter(DescriptorChain::is_write_only)
            .count();
        Self {
            inner: head.into_iter(),
            remaining,
        }
    }
}

impl<'a> Iterator for WritableChainIter<'a> {
    type Item = AliasedIoSliceMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let desc = self.inner.next()?;
            if !desc.is_write_only() {
                continue;
            }

            let len = desc.len as usize;
            let slice = desc
                .mem
                .get_slice(desc.addr, len)
                .expect("descriptor validated before transform");
            self.remaining -= 1;
            return Some(unsafe { AliasedIoSliceMut::from_slice(&slice) });
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for WritableChainIter<'_> {}

/// RxQueueProducer owns the RX queue and batches writable descriptor chains.
pub struct RxQueueProducer<T: WorkItemState = ()> {
    queue: Queue,
    mem: GuestMemoryMmap,
    iovecs: IovecStorage,
    work_items: Vec<WorkItem>,
    transformed: Vec<T>,
    head: usize,
}

impl<T: WorkItemState> RxQueueProducer<T> {
    /// Create a new RxQueueProducer with a fixed-size iovec ring buffer.
    ///
    /// `iovec_capacity` is the total number of iovec slots in the ring buffer.
    /// Feeding stops when the ring is full or the queue is drained.
    pub fn new(queue: Queue, mem: GuestMemoryMmap, iovec_capacity: usize) -> Self {
        Self {
            queue,
            mem,
            iovecs: IovecStorage::with_capacity(iovec_capacity),
            work_items: Vec::new(),
            transformed: Vec::new(),
            head: 0,
        }
    }

    /// Feed writable descriptor chains from the queue and transform them.
    ///
    /// The callback must call [`IovecAppender::reserve`] before pushing iovecs.
    /// If `reserve` returns `false` (ring full), return `None` to stop feeding.
    /// On success, return `Some((max_bytes, state))` where `max_bytes` is the
    /// total byte capacity of the original (pre-transform) chain.
    /// Disable guest notifications for the RX queue.
    pub fn disable_notification(&mut self) {
        let mut batch = RxProducerBatch {
            work_items: &mut self.work_items,
            transformed: &mut self.transformed,
            iovecs: &mut self.iovecs,
            queue: &mut self.queue,
            mem: &self.mem,
            head: self.head,
            next_finish_idx: 0,
        };
        batch.disable_notification();
    }

    /// Re-enable guest notifications. Returns `true` if new descriptors
    /// appeared while notifications were disabled (caller should re-feed).
    pub fn enable_notification(&mut self) -> bool {
        let mut batch = RxProducerBatch {
            work_items: &mut self.work_items,
            transformed: &mut self.transformed,
            iovecs: &mut self.iovecs,
            queue: &mut self.queue,
            mem: &self.mem,
            head: self.head,
            next_finish_idx: 0,
        };
        batch.enable_notification()
    }

    pub fn feed_with_transform<F>(&mut self, transform: F) -> usize
    where
        F: for<'a, 'b> FnMut(
            WritableChainIter<'a>,
            &mut IovecAppender<'b, 'a>,
        ) -> Option<(usize, T)>,
    {
        let mut batch = RxProducerBatch {
            work_items: &mut self.work_items,
            transformed: &mut self.transformed,
            iovecs: &mut self.iovecs,
            queue: &mut self.queue,
            mem: &self.mem,
            head: self.head,
            next_finish_idx: 0,
        };
        batch.feed_with_transform(transform)
    }

    /// Number of chains pending.
    pub fn pending_count(&self) -> usize {
        self.work_items.len() - self.head
    }

    /// Number of descriptors available in the avail ring (not yet popped).
    pub fn queue_len(&self) -> u16 {
        self.queue.len(&self.mem)
    }

    /// Negotiated queue size.
    pub fn queue_size(&self) -> u16 {
        self.queue.actual_size()
    }

    /// Check if there are any pending chains.
    pub fn has_pending(&self) -> bool {
        self.head < self.work_items.len()
    }

    /// Number of descriptors available in the virtqueue.
    pub fn queue_avail(&self) -> u16 {
        self.queue.len(&self.mem)
    }

    /// Check whether the guest needs an interrupt after `add_used` calls.
    /// Uses EVENT_IDX when negotiated to coalesce interrupts.
    pub fn needs_notification(&mut self) -> bool {
        self.queue.needs_notification(&self.mem).unwrap_or(true)
    }

    /// Produce frames by calling the callback with a batch.
    ///
    /// Returns the number of chains finished by the callback. The caller is
    /// responsible for signaling the guest when the return value is non-zero.
    pub fn produce<F>(&mut self, f: F) -> usize
    where
        F: for<'a> FnOnce(&mut RxProducerBatch<'a, T>),
    {
        let finished_count;
        {
            let mut batch = RxProducerBatch {
                work_items: &mut self.work_items,
                transformed: &mut self.transformed,
                iovecs: &mut self.iovecs,
                queue: &mut self.queue,
                mem: &self.mem,
                head: self.head,
                next_finish_idx: 0,
            };

            f(&mut batch);
            finished_count = batch.next_finish_idx;
        }

        self.release(finished_count);
        finished_count
    }

    fn release(&mut self, count: usize) {
        if count == 0 {
            return;
        }

        let released: usize = self.work_items[self.head..self.head + count]
            .iter()
            .map(WorkItem::allocation_len)
            .sum();

        self.head += count;
        self.iovecs.release_front_len(released);

        if self.head == self.work_items.len() {
            self.work_items.clear();
            self.transformed.clear();
            self.head = 0;
        }
    }
}

impl RxQueueProducer<()> {
    /// Feed writable descriptor chains without extra transformed state.
    pub fn feed(&mut self) -> usize {
        self.feed_with_transform(|iovecs, out| {
            if !out.reserve(iovecs.len()) {
                return None;
            }
            let total_bytes: usize = iovecs
                .map(|iov| {
                    let n = iov.len();
                    out.push(iov);
                    n
                })
                .sum();
            Some((total_bytes, ()))
        })
    }
}

/// Batch for producing RX chains.
pub struct RxProducerBatch<'a, T: WorkItemState> {
    work_items: &'a mut Vec<WorkItem>,
    transformed: &'a mut Vec<T>,
    iovecs: &'a mut IovecStorage,
    queue: &'a mut Queue,
    mem: &'a GuestMemoryMmap,
    head: usize,
    /// Number of chains finished so far (must be finished sequentially from 0).
    next_finish_idx: usize,
}

impl<T: WorkItemState> RxProducerBatch<'_, T> {
    #[inline]
    fn offset(&self, index: usize) -> usize {
        self.head + index
    }

    #[inline]
    fn offset_range(&self, range: Range<usize>) -> Range<usize> {
        self.head + range.start..self.head + range.end
    }

    /// Disable guest notifications for the RX queue.
    pub fn disable_notification(&mut self) {
        if let Err(e) = self.queue.disable_notification(self.mem) {
            warn!("Failed to disable queue notifications: {e:?}");
        }
    }

    /// Re-enable guest notifications. Returns `true` if new descriptors
    /// appeared while notifications were disabled (caller should re-feed).
    pub fn enable_notification(&mut self) -> bool {
        match self.queue.enable_notification(self.mem) {
            Ok(has_more) => has_more,
            Err(e) => {
                error!("Failed to re-enable queue notifications: {e:?}");
                false
            }
        }
    }

    /// Feed writable descriptor chains from the queue into this batch.
    pub fn feed_with_transform<F>(&mut self, mut transform: F) -> usize
    where
        F: for<'a, 'b> FnMut(
            WritableChainIter<'a>,
            &mut IovecAppender<'b, 'a>,
        ) -> Option<(usize, T)>,
    {
        let mut added = 0;

        'next_chain: loop {
            let Some(head) = self.queue.pop(self.mem) else {
                break 'next_chain;
            };

            let head_index = head.index;

            let mut appender = IovecAppender::new(self.iovecs);
            let Some((max_bytes, state)) = transform(WritableChainIter::new(head), &mut appender)
            else {
                self.queue.undo_pop();
                break 'next_chain;
            };
            let (alloc_start, live, transformed_bytes) = appender.finish();
            let bytes_used = max_bytes - transformed_bytes;
            let allocation = alloc_start..live.end;

            let item = WorkItem::new(head_index, max_bytes, bytes_used, allocation, live);
            let mut state = state;
            state.set_iovecs(item.raw_slice(self.iovecs));
            self.work_items.push(item);
            self.transformed.push(state);

            added += 1;
        }

        added
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.work_items.len() - self.head
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.head >= self.work_items.len()
    }

    #[inline]
    pub fn is_finished(&self, index: usize) -> bool {
        index < self.next_finish_idx
    }

    #[inline]
    pub fn bytes_used(&self, index: usize) -> usize {
        self.work_items[self.offset(index)].bytes_used
    }

    #[inline]
    pub fn max_bytes(&self, index: usize) -> usize {
        self.work_items[self.offset(index)].max_bytes
    }

    pub fn transformed(&self, range: Range<usize>) -> &[T] {
        self.assert_range_not_finished(range.clone());
        &self.transformed[self.offset_range(range)]
    }

    pub fn transformed_mut(&mut self, range: Range<usize>) -> &mut [T] {
        self.assert_range_not_finished(range.clone());
        let r = self.offset_range(range);
        &mut self.transformed[r]
    }

    pub fn transformed_item(&self, index: usize) -> &T {
        &self.transformed[self.offset(index)]
    }

    pub fn transformed_item_mut(&mut self, index: usize) -> &mut T {
        let idx = self.head + index;
        &mut self.transformed[idx]
    }

    pub fn io_slices_mut(&mut self, index: usize) -> &mut [AliasedIoSliceMut<'_>] {
        self.assert_not_finished(index);
        let live = self.work_items[self.offset(index)].live.clone();
        raw_as_io_slices_mut(self.iovecs.slice_mut(live))
    }

    /// Mark a contiguous range of chains as finished and add them to the used ring.
    ///
    /// Chains must be finished in order starting from 0. Out-of-order completion
    /// may be added in the future if needed.
    pub fn finish_many(&mut self, range: Range<usize>) {
        if range.is_empty() {
            return;
        }

        assert!(
            range.start == self.next_finish_idx,
            "chains must be finished sequentially: expected start {}, got {}",
            self.next_finish_idx,
            range.start
        );

        let start = self.offset(range.start);
        let end = self.offset(range.end);
        let items = &self.work_items[start..end];
        if let Err(e) = self.queue.add_used_many(
            self.mem,
            items
                .iter()
                .map(|item| (item.head_index, item.bytes_used as u32)),
        ) {
            error!("RxProducerBatch: failed to add_used_many: {e}");
        }

        self.next_finish_idx = range.end;
    }

    pub fn finish(&mut self, index: usize) {
        self.finish_many(index..index + 1);
    }

    pub fn complete(&mut self, index: usize, bytes: usize) {
        self.assert_not_finished(index);
        let idx = self.head + index;
        let item = &mut self.work_items[idx];
        item.bytes_used += bytes;
        debug_assert!(
            item.bytes_used <= item.max_bytes,
            "complete: bytes_used {} exceeds max_bytes {}",
            item.bytes_used,
            item.max_bytes
        );
        self.finish(index);
    }

    pub fn advance(&mut self, index: usize, bytes: usize) {
        self.assert_not_finished(index);
        let idx = self.offset(index);
        let item = &mut self.work_items[idx];
        item.bytes_used += bytes;
        debug_assert!(
            item.bytes_used <= item.max_bytes,
            "advance: bytes_used {} exceeds max_bytes {}",
            item.bytes_used,
            item.max_bytes
        );
        item.advance(self.iovecs, bytes);
        let iovecs = item.raw_slice(self.iovecs);
        self.transformed[idx].set_iovecs(iovecs);
    }

    pub fn truncate(&mut self, index: usize, max_bytes: usize) {
        self.assert_not_finished(index);
        let idx = self.offset(index);
        let item = &mut self.work_items[idx];
        item.truncate_bytes(self.iovecs, max_bytes);
        let iovecs = item.raw_slice(self.iovecs);
        self.transformed[idx].set_iovecs(iovecs);
    }

    #[allow(clippy::result_unit_err)]
    pub fn write_advance(&mut self, index: usize, data: &[u8]) -> Result<(), ()> {
        let written =
            AliasedIoSliceMut::scatter_write(self.io_slices_mut(index).iter().copied(), data);
        if written != data.len() {
            return Err(());
        }
        self.advance(index, written);
        Ok(())
    }

    #[allow(clippy::result_unit_err)]
    pub fn write_complete(&mut self, index: usize, data: &[u8]) -> Result<(), ()> {
        let written =
            AliasedIoSliceMut::scatter_write(self.io_slices_mut(index).iter().copied(), data);
        if written != data.len() {
            return Err(());
        }
        self.complete(index, written);
        Ok(())
    }

    #[track_caller]
    fn assert_not_finished(&self, index: usize) {
        assert!(
            !self.is_finished(index),
            "chain at index {index} already finished"
        );
    }

    #[track_caller]
    fn assert_range_not_finished(&self, range: Range<usize>) {
        self.assert_not_finished(range.start);
    }
}

impl RxProducerBatch<'_, ()> {
    /// Feed writable descriptor chains without extra transformed state.
    pub fn feed(&mut self) -> usize {
        self.feed_with_transform(|iovecs, out| {
            if !out.reserve(iovecs.len()) {
                return None;
            }
            let total_bytes: usize = iovecs
                .map(|iov| {
                    let n = iov.len();
                    out.push(iov);
                    n
                })
                .sum();
            Some((total_bytes, ()))
        })
    }
}

impl<T: WorkItemState + ReceivedBytes> RxProducerBatch<'_, T> {
    pub fn complete_received(&mut self, index: usize) {
        self.complete_received_many(index..index + 1);
    }

    pub fn complete_received_many(&mut self, range: Range<usize>) {
        for index in range.clone() {
            let idx = self.offset(index);
            let item = &mut self.work_items[idx];
            item.bytes_used += self.transformed[idx].received_bytes();
            debug_assert!(
                item.bytes_used <= item.max_bytes,
                "complete_received_many: bytes_used {} exceeds max_bytes {}",
                item.bytes_used,
                item.max_bytes
            );
        }
        self.finish_many(range);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use crate::virtio::batch_queue::aliased_ioslice::{
        AliasedIoSliceMut, AnyIoSlice, RawAliasedIoSlice,
    };
    use crate::virtio::batch_queue::{ReceivedBytes, WorkItemState};
    use crate::virtio::test_utils::{ExpectedUsed, TestSetup};

    use super::RxQueueProducer;

    type TestRxProducer = RxQueueProducer;

    #[test]
    fn test_initial_state() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        let mut producer: TestRxProducer = RxQueueProducer::new(queue, setup.mem().clone(), 16);

        assert_eq!(producer.pending_count(), 0);
        assert_eq!(producer.feed(), 0);
        assert_eq!(producer.produce(|_batch| {}), 0);
        driver.assert_used(&[]);
    }

    #[test]
    fn test_feed_single_writable_descriptor() {
        let setup = TestSetup::new();
        let (queue, _driver) = setup.create_queue(16);
        _driver.writable(&[1500]);

        let mut producer: TestRxProducer = RxQueueProducer::new(queue, setup.mem().clone(), 16);

        assert_eq!(producer.feed(), 1);
        assert_eq!(producer.pending_count(), 1);
    }

    #[test]
    fn test_feed_chained_writable_descriptors() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.writable(&[512, 1024]);

        let mut producer: TestRxProducer = RxQueueProducer::new(queue, setup.mem().clone(), 16);

        assert_eq!(producer.feed(), 1);
        assert_eq!(producer.pending_count(), 1);

        producer.produce(|batch| {
            let chain = batch.io_slices_mut(0);
            assert_eq!(chain.len(), 2);
            assert_eq!(chain[0].len(), 512);
            assert_eq!(chain[1].len(), 1024);
        });

        driver.assert_used(&[]);
    }

    #[test]
    fn test_feed_respects_iovec_capacity() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500])
            .writable(&[1500]);

        // Iovec capacity of 2: only 2 single-iovec chains fit.
        let mut producer: TestRxProducer = RxQueueProducer::new(queue, setup.mem().clone(), 2);

        assert_eq!(producer.feed(), 2);
        assert_eq!(producer.pending_count(), 2);
    }

    #[test]
    fn test_produce_via_write_bytes() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.writable(&[10, 90]).writable(&[100]).writable(&[100]);

        let mut producer: TestRxProducer = RxQueueProducer::new(queue, setup.mem().clone(), 16);

        producer.feed();

        let completed = producer.produce(|batch| {
            assert_eq!(batch.max_bytes(0), 100);
            batch.write_complete(0, b"Received packet 1").unwrap();
            assert_eq!(batch.bytes_used(0), 17);

            assert_eq!(batch.max_bytes(1), 100);
            batch.write_complete(1, b"Received packet 2").unwrap();
            assert_eq!(batch.bytes_used(1), 17);

            assert_eq!(batch.max_bytes(2), 100);
            assert_eq!(batch.bytes_used(2), 0);
        });

        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 1);
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"Received packet 1")),
            (1, ExpectedUsed::Writable(b"Received packet 2")),
        ]);
    }

    #[test]
    fn test_multiple_produce_cycles() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(32);

        driver
            .writable(&[6, 12, 6])
            .writable(&[6, 12, 6])
            .writable(&[6, 12, 6]);

        let mut producer: TestRxProducer = RxQueueProducer::new(queue, setup.mem().clone(), 32);

        let feed_with_hdr = |p: &mut TestRxProducer| {
            p.feed_with_transform(|iovecs, out| {
                if !out.reserve(iovecs.len()) {
                    return None;
                }
                out.extend(AliasedIoSliceMut::write_prefix(iovecs, b"HD"));
                Some((out.total_bytes() + 2, ()))
            })
        };

        assert_eq!(feed_with_hdr(&mut producer), 3);
        assert_eq!(producer.pending_count(), 3);

        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"aaaaaaaaaaaaaaaaaa").unwrap();

            let written =
                AliasedIoSliceMut::scatter_write(batch.io_slices_mut(1).iter().copied(), b"bbbb");
            assert_eq!(written, 4);
            batch.advance(1, 4);
        });
        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 2);
        driver.assert_used(&[(0, ExpectedUsed::Writable(b"HDaaaaaaaaaaaaaaaaaa"))]);

        driver.writable(&[1, 1, 3, 3, 12, 6]).writable(&[6, 12, 6]);
        assert_eq!(feed_with_hdr(&mut producer), 2);
        assert_eq!(producer.pending_count(), 4);

        let completed = producer.produce(|batch| {
            let written = AliasedIoSliceMut::scatter_write(
                batch.io_slices_mut(0).iter().copied(),
                b"bbbbbbbb",
            );
            assert_eq!(written, 8);
            batch.complete(0, 8);
        });
        assert_eq!(completed, 1);
        assert_eq!(producer.pending_count(), 3);
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"HDaaaaaaaaaaaaaaaaaa")),
            (1, ExpectedUsed::Writable(b"HDbbbbbbbbbbbb")),
        ]);

        let completed = producer.produce(|batch| {
            assert_eq!(batch.len(), 3);
            batch.write_complete(0, b"cccccccccccc").unwrap();
            batch.write_complete(1, b"dddddd").unwrap();
        });
        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 1);
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"HDaaaaaaaaaaaaaaaaaa")),
            (1, ExpectedUsed::Writable(b"HDbbbbbbbbbbbb")),
            (2, ExpectedUsed::Writable(b"HDcccccccccccc")),
            (3, ExpectedUsed::Writable(b"HDdddddd")),
        ]);

        driver.writable(&[6, 12, 6]);
        assert_eq!(feed_with_hdr(&mut producer), 1);
        assert_eq!(producer.pending_count(), 2);

        let completed = producer.produce(|batch| {
            batch.write_complete(0, b"eeee").unwrap();
            batch.write_complete(1, b"ffff").unwrap();
        });
        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 0);
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"HDaaaaaaaaaaaaaaaaaa")),
            (1, ExpectedUsed::Writable(b"HDbbbbbbbbbbbb")),
            (2, ExpectedUsed::Writable(b"HDcccccccccccc")),
            (3, ExpectedUsed::Writable(b"HDdddddd")),
            (4, ExpectedUsed::Writable(b"HDeeee")),
            (5, ExpectedUsed::Writable(b"HDffff")),
        ]);
    }

    #[test]
    #[should_panic(expected = "finished sequentially")]
    fn test_out_of_order_completion_panics() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.writable(&[2, 2]).writable(&[2, 2]);

        let mut producer: TestRxProducer = RxQueueProducer::new(queue, setup.mem().clone(), 16);

        producer.feed();
        producer.produce(|batch| {
            batch.write_complete(1, b"pkt1").unwrap(); // should panic: expected 0
        });
    }

    #[derive(Default)]
    struct CustomState {
        tag: u32,
        received_len: Cell<usize>,
    }

    impl WorkItemState for CustomState {
        fn set_iovecs(&mut self, _iovecs: &[RawAliasedIoSlice]) {}
    }

    impl ReceivedBytes for CustomState {
        fn received_bytes(&self) -> usize {
            self.received_len.get()
        }
    }

    #[test]
    fn test_complete_received_many() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .writable(&[100])
            .writable(&[100])
            .writable(&[100])
            .writable(&[100]);

        let mut producer: RxQueueProducer<CustomState> =
            RxQueueProducer::new(queue, setup.mem().clone(), 16);

        let mut tag = 0u32;
        let added = producer.feed_with_transform(|iovecs, out| {
            if !out.reserve(iovecs.len()) {
                return None;
            }
            tag += 10;
            out.extend(iovecs);
            Some((
                out.total_bytes(),
                CustomState {
                    tag,
                    received_len: Cell::new(0),
                },
            ))
        });
        assert_eq!(added, 4);

        let completed = producer.produce(|batch| {
            assert_eq!(batch.len(), 4);
            assert_eq!(batch.transformed_item(0).tag, 10);
            assert_eq!(batch.transformed_item(1).tag, 20);
            assert_eq!(batch.transformed_item(2).tag, 30);
            assert_eq!(batch.transformed_item(3).tag, 40);

            let written =
                AliasedIoSliceMut::scatter_write(batch.io_slices_mut(0).iter().copied(), b"aaaa");
            batch.transformed_item_mut(0).received_len.set(written);

            let written = AliasedIoSliceMut::scatter_write(
                batch.io_slices_mut(1).iter().copied(),
                b"bbbbbbbb",
            );
            batch.transformed_item_mut(1).received_len.set(written);

            batch.complete_received_many(0..2);
        });
        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 2);
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"aaaa")),
            (1, ExpectedUsed::Writable(b"bbbbbbbb")),
        ]);

        let completed = producer.produce(|batch| {
            assert_eq!(batch.len(), 2);
            assert_eq!(batch.transformed_item(0).tag, 30);
            assert_eq!(batch.transformed_item(1).tag, 40);

            let written =
                AliasedIoSliceMut::scatter_write(batch.io_slices_mut(0).iter().copied(), b"cccccc");
            batch.transformed_item_mut(0).received_len.set(written);

            let written = AliasedIoSliceMut::scatter_write(
                batch.io_slices_mut(1).iter().copied(),
                b"dddddddddddd",
            );
            batch.transformed_item_mut(1).received_len.set(written);

            batch.complete_received_many(0..2);
        });
        assert_eq!(completed, 2);
        assert_eq!(producer.pending_count(), 0);
        driver.assert_used(&[
            (0, ExpectedUsed::Writable(b"aaaa")),
            (1, ExpectedUsed::Writable(b"bbbbbbbb")),
            (2, ExpectedUsed::Writable(b"cccccc")),
            (3, ExpectedUsed::Writable(b"dddddddddddd")),
        ]);
    }

    #[test]
    #[should_panic(expected = "already finished")]
    fn test_double_finish_panics() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.writable(&[100]);

        let mut producer: TestRxProducer = RxQueueProducer::new(queue, setup.mem().clone(), 16);

        producer.feed();
        producer.produce(|batch| {
            batch.complete(0, 10);
            batch.complete(0, 10); // should panic: already finished
        });
    }
}
