// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! TX queue consumer for batched virtio transmit operations.

use std::ops::Range;

use vm_memory::{GuestMemoryBackend, GuestMemoryMmap};

use super::super::queue::{DescIter, DescriptorChain, Queue};
use super::aliased_ioslice::AliasedIoSlice;
use super::{IovecAppender, IovecStorage, WorkItem, WorkItemState, raw_as_io_slices};

/// Iterator over the readable slices in one descriptor chain.
///
/// Implements `ExactSizeIterator` so the transform can call `.len()` to know
/// how many iovecs to reserve before pushing.
pub struct ReadableChainIter<'a> {
    inner: DescIter<'a>,
    remaining: usize,
}

impl<'a> ReadableChainIter<'a> {
    fn new(head: DescriptorChain<'a>) -> Self {
        let remaining = head
            .clone()
            .into_iter()
            .filter(DescriptorChain::is_read_only)
            .count();
        Self {
            inner: head.into_iter(),
            remaining,
        }
    }
}

impl<'a> Iterator for ReadableChainIter<'a> {
    type Item = AliasedIoSlice<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let desc = self.inner.next()?;
            if !desc.is_read_only() {
                continue;
            }

            let len = desc.len as usize;
            let slice = desc
                .mem
                .get_slice(desc.addr, len)
                .expect("descriptor validated before transform");
            self.remaining -= 1;
            return Some(unsafe { AliasedIoSlice::from_slice(&slice) });
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for ReadableChainIter<'_> {}

/// TxQueueConsumer owns the TX queue and batches readable descriptor chains.
pub struct TxQueueConsumer<T: WorkItemState = ()> {
    queue: Queue,
    mem: GuestMemoryMmap,
    iovecs: IovecStorage,
    work_items: Vec<WorkItem>,
    transformed: Vec<T>,
    head: usize,
}

impl<T: WorkItemState> TxQueueConsumer<T> {
    /// Create a new TxQueueConsumer with a fixed-size iovec ring buffer.
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

    /// Feed readable descriptor chains from the queue and transform them.
    ///
    /// The callback receives an iterator over the chain's readable iovecs and
    /// an [`IovecAppender`]. It must call [`IovecAppender::reserve`] before
    /// pushing iovecs. If `reserve` returns `false` (ring full), the callback
    /// should return `None` to stop feeding.
    pub fn disable_notification(&mut self) {
        if let Err(e) = self.queue.disable_notification(&self.mem) {
            warn!("Failed to disable queue notifications: {e:?}");
        }
    }

    pub fn enable_notification(&mut self) -> bool {
        match self.queue.enable_notification(&self.mem) {
            Ok(has_more) => has_more,
            Err(e) => {
                error!("Failed to re-enable queue notifications: {e:?}");
                false
            }
        }
    }

    pub fn feed_with_transform<F>(&mut self, mut transform: F) -> usize
    where
        F: for<'a, 'b> FnMut(ReadableChainIter<'a>, &mut IovecAppender<'b, 'a>) -> Option<T>,
    {
        let mut added = 0;

        'next_chain: loop {
            let Some(head) = self.queue.pop(&self.mem) else {
                break 'next_chain;
            };

            let head_index = head.index;

            let mut appender = IovecAppender::new(&mut self.iovecs);
            let Some(state) = transform(ReadableChainIter::new(head), &mut appender) else {
                self.queue.undo_pop();
                break 'next_chain;
            };
            let (alloc_start, live, max_bytes) = appender.finish();
            let allocation = alloc_start..live.end;

            let item = WorkItem::new(head_index, max_bytes, 0, allocation, live);
            let mut state = state;
            state.set_iovecs(item.raw_slice(&self.iovecs));
            self.work_items.push(item);
            self.transformed.push(state);

            added += 1;
        }

        added
    }

    /// Number of chains pending.
    pub fn pending_count(&self) -> usize {
        self.work_items.len() - self.head
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

    /// Consume pending chains using a callback that performs the actual I/O.
    ///
    /// Returns the number of chains finished by the callback. The caller is
    /// responsible for signaling the guest when the return value is non-zero.
    pub fn consume<F>(&mut self, f: F) -> usize
    where
        F: for<'a> FnOnce(&mut TxConsumerBatch<'a, T>),
    {
        if !self.has_pending() {
            return 0;
        }

        let finished_count;
        {
            let mut batch = TxConsumerBatch {
                work_items: &mut self.work_items[self.head..],
                transformed: &mut self.transformed[self.head..],
                iovecs: &mut self.iovecs,
                queue: &mut self.queue,
                mem: &self.mem,
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

impl TxQueueConsumer<()> {
    /// Feed readable descriptor chains without extra transformed state.
    pub fn feed(&mut self) -> usize {
        self.feed_with_transform(|iovecs, out| {
            if !out.reserve(iovecs.len()) {
                return None;
            }
            out.extend(iovecs);
            Some(())
        })
    }
}

/// Batch for consuming TX chains.
pub struct TxConsumerBatch<'a, T: WorkItemState> {
    work_items: &'a mut [WorkItem],
    transformed: &'a mut [T],
    iovecs: &'a mut IovecStorage,
    queue: &'a mut Queue,
    mem: &'a GuestMemoryMmap,
    /// Number of chains finished so far (must be finished sequentially from 0).
    next_finish_idx: usize,
}

impl<T: WorkItemState> TxConsumerBatch<'_, T> {
    #[inline]
    pub fn len(&self) -> usize {
        self.work_items.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.work_items.is_empty()
    }

    #[inline]
    pub fn is_finished(&self, index: usize) -> bool {
        index < self.next_finish_idx
    }

    #[inline]
    pub fn bytes_used(&self, index: usize) -> usize {
        self.work_items[index].bytes_used
    }

    #[inline]
    pub fn max_bytes(&self, index: usize) -> usize {
        self.work_items[index].max_bytes
    }

    pub fn io_slices(&self, index: usize) -> &[AliasedIoSlice<'_>] {
        self.assert_not_finished(index);
        raw_as_io_slices(self.work_items[index].raw_slice(self.iovecs))
    }

    pub fn transformed(&self, range: Range<usize>) -> &[T] {
        self.assert_range_not_finished(range.clone());
        &self.transformed[range]
    }

    pub fn transformed_mut(&mut self, range: Range<usize>) -> &mut [T] {
        self.assert_range_not_finished(range.clone());
        &mut self.transformed[range]
    }

    pub fn transformed_item(&self, index: usize) -> &T {
        &self.transformed[index]
    }

    pub fn transformed_item_mut(&mut self, index: usize) -> &mut T {
        &mut self.transformed[index]
    }

    pub fn total_bytes(&self) -> usize {
        self.work_items[self.next_finish_idx..]
            .iter()
            .map(|item| item.max_bytes.saturating_sub(item.bytes_used))
            .sum()
    }

    /// Mark chain at `index` as finished and add it to the used ring.
    ///
    /// Chains must be finished in order (0, 1, 2, …). Out-of-order completion
    /// may be added in the future if needed.
    pub fn finish(&mut self, index: usize) {
        assert!(
            index == self.next_finish_idx,
            "chains must be finished sequentially: expected index {}, got {index}",
            self.next_finish_idx
        );
        let item = &self.work_items[index];

        // For TX (device-readable) buffers the `len` field in the used ring is
        // unspecified by the virtio spec and ignored by guest drivers.
        if let Err(e) = self.queue.add_used(self.mem, item.head_index, 0) {
            error!("TxConsumerBatch: failed to add_used: {e}");
        }

        self.next_finish_idx += 1;
    }

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

        let items = &self.work_items[range.clone()];
        if let Err(e) = self
            .queue
            .add_used_many(self.mem, items.iter().map(|item| (item.head_index, 0)))
        {
            error!("TxConsumerBatch: failed to add_used_many: {e}");
        }

        self.next_finish_idx = range.end;
    }

    pub fn advance(&mut self, index: usize, bytes: usize) {
        self.assert_not_finished(index);
        let item = &mut self.work_items[index];
        item.bytes_used += bytes;
        debug_assert!(
            item.bytes_used <= item.max_bytes,
            "advance: bytes_used {} exceeds max_bytes {}",
            item.bytes_used,
            item.max_bytes
        );
        item.advance(self.iovecs, bytes);
        let iovecs = item.raw_slice(self.iovecs);
        self.transformed[index].set_iovecs(iovecs);
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

#[cfg(test)]
mod tests {
    use crate::virtio::batch_queue::aliased_ioslice::{AliasedIoSlice, AnyIoSlice};
    use crate::virtio::test_utils::{ExpectedUsed, TestSetup};

    use super::TxQueueConsumer;

    type TestTxConsumer = TxQueueConsumer;

    fn read_iov(iov: &AliasedIoSlice<'_>) -> Vec<u8> {
        let mut buf = vec![0u8; iov.len()];
        iov.read(&mut buf);
        buf
    }

    #[test]
    fn test_new_consumer_is_empty() {
        let setup = TestSetup::new();
        let (queue, _driver) = setup.create_queue(16);
        let consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        assert_eq!(consumer.pending_count(), 0);
        assert!(!consumer.has_pending());
    }

    #[test]
    fn test_feed_single_descriptor() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"Hello, World!"]);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        let added = consumer.feed();

        assert_eq!(added, 1);
        assert_eq!(consumer.pending_count(), 1);

        let finished = consumer.consume(|batch| {
            assert_eq!(batch.len(), 1);
            assert_eq!(batch.io_slices(0).len(), 1);
            assert_eq!(read_iov(&batch.io_slices(0)[0]), b"Hello, World!");
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        driver.assert_used(&[(0, ExpectedUsed::Readable)]);
    }

    #[test]
    fn test_feed_chained_descriptors() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"First", b"Second"]);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        let added = consumer.feed();

        assert_eq!(added, 1);
        assert_eq!(consumer.pending_count(), 1);

        let finished = consumer.consume(|batch| {
            assert_eq!(batch.io_slices(0).len(), 2);
            assert_eq!(read_iov(&batch.io_slices(0)[0]), b"First");
            assert_eq!(read_iov(&batch.io_slices(0)[1]), b"Second");
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        driver.assert_used(&[(0, ExpectedUsed::Readable)]);
    }

    #[test]
    fn test_feed_multiple_frames() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"Frame1"])
            .readable(&[b"Frame2"])
            .readable(&[b"Frame3"]);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        let added = consumer.feed();

        assert_eq!(added, 3);
        assert_eq!(consumer.pending_count(), 3);

        let finished = consumer.consume(|batch| {
            assert_eq!(batch.len(), 3);
            batch.finish_many(0..3);
        });

        assert_eq!(finished, 3);
        driver.assert_used(&[
            (0, ExpectedUsed::Readable),
            (1, ExpectedUsed::Readable),
            (2, ExpectedUsed::Readable),
        ]);
    }

    #[test]
    fn test_feed_respects_iovec_capacity() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"F0"])
            .readable(&[b"F1"])
            .readable(&[b"F2"])
            .readable(&[b"F3"])
            .readable(&[b"F4"]);

        // Iovec capacity of 2: only 2 single-iovec chains fit.
        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 2);

        assert_eq!(consumer.feed(), 2);
        assert_eq!(consumer.pending_count(), 2);
        assert_eq!(consumer.feed(), 0);
    }

    #[test]
    fn test_feed_transform_callback() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"TestData12345"]);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        let added = consumer.feed_with_transform(|iovecs, out| {
            out.reserve(iovecs.len());
            out.extend(AliasedIoSlice::skip_bytes(iovecs, 4));
            Some(())
        });

        assert_eq!(added, 1);

        consumer.consume(|batch| {
            batch.finish(0);
        });

        driver.assert_used(&[(0, ExpectedUsed::Readable)]);
    }

    #[test]
    fn test_consume_and_finish_all() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"FirstChain"])
            .readable(&[b"SecondChain"]);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        consumer.feed();
        assert_eq!(consumer.pending_count(), 2);

        let finished = consumer.consume(|batch| {
            assert_eq!(batch.total_bytes(), 21);
            batch.finish_many(0..batch.len());
        });

        assert_eq!(finished, 2);
        assert_eq!(consumer.pending_count(), 0);
        driver.assert_used(&[(0, ExpectedUsed::Readable), (1, ExpectedUsed::Readable)]);
    }

    #[test]
    fn test_consume_partial() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"Chain00000"])
            .readable(&[b"Chain11111"])
            .readable(&[b"Chain22222"]);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        consumer.feed();

        let finished = consumer.consume(|batch| {
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        assert_eq!(consumer.pending_count(), 2);
        driver.assert_used(&[(0, ExpectedUsed::Readable)]);
    }

    #[test]
    fn test_release() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"])
            .readable(&[b"test"]);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        consumer.feed();

        let finished = consumer.consume(|batch| {
            batch.finish_many(0..3);
        });

        assert_eq!(finished, 3);
        assert_eq!(consumer.pending_count(), 2);
        driver.assert_used(&[
            (0, ExpectedUsed::Readable),
            (1, ExpectedUsed::Readable),
            (2, ExpectedUsed::Readable),
        ]);
    }

    #[test]
    fn test_empty_queue_returns_zero() {
        let setup = TestSetup::new();
        let (queue, _driver) = setup.create_queue(16);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        assert_eq!(consumer.feed(), 0);
        assert_eq!(consumer.pending_count(), 0);
        assert_eq!(consumer.consume(|_batch| {}), 0);
    }

    #[test]
    fn test_no_finish_preserves_pending() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"TestData"]);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        consumer.feed();

        assert_eq!(consumer.consume(|_batch| {}), 0);
        assert_eq!(consumer.pending_count(), 1);
        driver.assert_used(&[]);
    }

    #[test]
    fn test_remove_header_byte_tracking() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);

        let mut data = vec![0x48u8; 12];
        data.extend(vec![0x50; 100]);
        driver.readable(&[&data]);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        assert_eq!(
            consumer.feed_with_transform(|iovecs, out| {
                out.reserve(iovecs.len());
                out.extend(AliasedIoSlice::skip_bytes(iovecs, 12));
                Some(())
            }),
            1
        );

        let finished = consumer.consume(|batch| {
            let total: usize = batch.io_slices(0).iter().map(|iov| iov.len()).sum();
            assert_eq!(total, 100);
            batch.finish(0);
        });

        assert_eq!(finished, 1);
        assert_eq!(consumer.pending_count(), 0);
        driver.assert_used(&[(0, ExpectedUsed::Readable)]);
    }

    #[test]
    fn test_multi_cycle_partial_writes() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);

        let mut data = vec![0x48u8; 12];
        data.extend(vec![0x50; 100]);
        driver.readable(&[&data]);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        assert_eq!(
            consumer.feed_with_transform(|iovecs, out| {
                out.reserve(iovecs.len());
                out.extend(AliasedIoSlice::skip_bytes(iovecs, 12));
                Some(())
            }),
            1
        );

        consumer.consume(|batch| batch.advance(0, 2));
        consumer.consume(|batch| batch.advance(0, 50));
        consumer.consume(|batch| {
            batch.advance(0, 48);
            batch.finish(0);
        });

        assert_eq!(consumer.pending_count(), 0);
        driver.assert_used(&[(0, ExpectedUsed::Readable)]);
    }

    #[test]
    fn test_stop_resume_across_release() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);

        let data = vec![0x50u8; 30];
        driver.readable(&[&data]).readable(&[&data]);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        consumer.feed();
        assert_eq!(consumer.pending_count(), 2);

        consumer.consume(|batch| {
            batch.finish(0);
            batch.advance(1, 15);
        });
        assert_eq!(consumer.pending_count(), 1);
        driver.assert_used(&[(0, ExpectedUsed::Readable)]);

        driver.readable(&[&data]);

        consumer.feed();
        assert_eq!(consumer.pending_count(), 2);

        consumer.consume(|batch| {
            batch.finish_many(0..2);
        });
        assert_eq!(consumer.pending_count(), 0);

        driver.assert_used(&[
            (0, ExpectedUsed::Readable),
            (1, ExpectedUsed::Readable),
            (2, ExpectedUsed::Readable),
        ]);
    }

    #[test]
    #[should_panic(expected = "finished sequentially")]
    fn test_out_of_order_finish_panics() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"pkt0"]).readable(&[b"pkt1"]);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        consumer.feed();
        consumer.consume(|batch| {
            batch.finish(1); // should panic: expected 0
        });
    }

    #[test]
    #[should_panic(expected = "finished sequentially")]
    fn test_double_finish_panics() {
        let setup = TestSetup::new();
        let (queue, driver) = setup.create_queue(16);
        driver.readable(&[b"data"]);

        let mut consumer: TestTxConsumer = TxQueueConsumer::new(queue, setup.mem().clone(), 16);

        consumer.feed();
        consumer.consume(|batch| {
            batch.finish(0);
            batch.finish(0); // should panic: expected 1
        });
    }
}
