// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared test utilities for TxQueueConsumer and RxQueueProducer tests.

use std::cell::{Cell, RefCell};
use std::mem::size_of;

use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

use crate::virtio::queue::tests::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::virtio::queue::{Descriptor, Queue, VirtqUsedElem};

const MEM_SIZE: u64 = 0x100000;
/// Per-queue data region size (64 KB).
const DATA_REGION_SIZE: u64 = 0x10000;
/// Data regions start after queue structures.
const DATA_BASE: u64 = 0x10000;

/// Test setup that owns guest memory and allocates non-overlapping queues.
pub struct TestSetup {
    mem: GuestMemoryMmap,
    /// Bump allocator for queue structures (low addresses).
    next_struct_addr: Cell<u64>,
    /// Number of queues created (used to partition data regions).
    queue_count: Cell<usize>,
}

impl TestSetup {
    pub fn new() -> Self {
        Self {
            mem: GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MEM_SIZE as usize)]).unwrap(),
            next_struct_addr: Cell::new(0),
            queue_count: Cell::new(0),
        }
    }

    pub fn mem(&self) -> &GuestMemoryMmap {
        &self.mem
    }

    /// Allocate `size` bytes at the next `align`-byte boundary.
    fn alloc(&self, size: u64, align: u64) -> u64 {
        let addr = self.next_struct_addr.get();
        let aligned = (addr + align - 1) & !(align - 1);
        self.next_struct_addr.set(aligned + size);
        assert!(
            self.next_struct_addr.get() <= DATA_BASE,
            "queue structures overflow into data area"
        );
        aligned
    }

    /// Create a queue with the given size and its corresponding driver.
    pub fn create_queue(&self, size: u16) -> (Queue, VirtQueueDriver<'_>) {
        let n = size as u64;
        let ring_overhead = 3 * size_of::<u16>() as u64; // flags + idx + event
        let desc_table = self.alloc(size_of::<Descriptor>() as u64 * n, 16);
        let avail_ring = self.alloc(ring_overhead + size_of::<u16>() as u64 * n, 2);
        let used_ring = self.alloc(ring_overhead + size_of::<VirtqUsedElem>() as u64 * n, 4);

        let mut queue = Queue::new(size);
        queue.size = size;
        queue.ready = true;
        queue.desc_table = GuestAddress(desc_table);
        queue.avail_ring = GuestAddress(avail_ring);
        queue.used_ring = GuestAddress(used_ring);

        let idx = self.queue_count.get();
        self.queue_count.set(idx + 1);
        let data_addr = DATA_BASE + idx as u64 * DATA_REGION_SIZE;
        assert!(
            data_addr + DATA_REGION_SIZE <= MEM_SIZE,
            "out of data regions"
        );

        let driver = VirtQueueDriver::new(&queue, &self.mem, data_addr);
        (queue, driver)
    }
}

/// A segment within a descriptor chain (address + size + optional expected data)
#[derive(Clone)]
pub struct DescSegment {
    /// Guest physical address of this segment
    pub addr: u64,
    /// Length of this segment
    pub len: u32,
    /// For readable segments: copy of expected data (None for writable)
    pub expected_data: Option<Vec<u8>>,
}

/// Information about a built descriptor chain
#[derive(Clone)]
pub struct BuiltChain {
    /// Head descriptor index (used in add_used)
    pub head_index: u16,
    /// Segments in this chain
    pub segments: Vec<DescSegment>,
}

/// Expected state for a chain in the used ring.
#[derive(Debug, Clone)]
pub enum ExpectedUsed<'a> {
    /// Writable chain - verify content matches exactly
    Writable(&'a [u8]),
    /// Readable chain - verify wasn't modified
    Readable,
}

/// Simulates the guest driver side of a VirtIO queue for testing.
///
/// Communicates with the device ONLY through guest memory.
/// Supports incremental descriptor addition during tests.
/// Tracks chain metadata for verification (assert_used_len_exact, etc).
pub struct VirtQueueDriver<'a> {
    mem: &'a GuestMemoryMmap,
    /// Queue size (max descriptors)
    queue_size: u16,
    /// Descriptor table address in guest memory
    desc_table: GuestAddress,
    /// Available ring address in guest memory
    avail_ring: GuestAddress,
    /// Used ring address in guest memory
    used_ring: GuestAddress,
    /// Next descriptor table index to use
    desc_idx: Cell<usize>,
    /// Next available ring index (initialized from memory)
    avail_idx: Cell<u16>,
    /// Next memory address for data allocation
    next_addr: Cell<u64>,
    /// Tracked chains for verification
    chains: RefCell<Vec<BuiltChain>>,
}

impl<'a> VirtQueueDriver<'a> {
    /// Create a new driver by extracting queue addresses from the Queue struct.
    ///
    /// The Queue reference is only used to get addresses - it is NOT stored.
    /// All communication happens through guest memory.
    pub fn new(queue: &Queue, mem: &'a GuestMemoryMmap, data_addr: u64) -> Self {
        // Extract addresses from queue (not stored)
        let desc_table = queue.desc_table;
        let avail_ring = queue.avail_ring;
        let used_ring = queue.used_ring;
        let queue_size = queue.size;

        // Read current avail_idx from memory to support mid-test construction
        let avail_idx_addr = avail_ring.unchecked_add(2);
        let current_avail_idx: u16 = mem.read_obj(avail_idx_addr).unwrap_or(0);

        Self {
            mem,
            queue_size,
            desc_table,
            avail_ring,
            used_ring,
            desc_idx: Cell::new(current_avail_idx as usize), // Start after existing descriptors
            avail_idx: Cell::new(current_avail_idx),
            next_addr: Cell::new(data_addr),
            chains: RefCell::new(Vec::new()),
        }
    }

    // ========================================================================
    // Chain building methods
    // ========================================================================

    /// Add a readable chain. Each slice in `segments` becomes a descriptor.
    ///
    /// Simple case (1 descriptor): `driver.readable(&[b"data"])`
    /// Chained case: `driver.readable(&[b"header", b"payload"])`
    pub fn readable(&self, segments: &[&[u8]]) -> &Self {
        assert!(
            !segments.is_empty(),
            "readable chain must have at least one segment"
        );
        let head_idx = self.desc_idx.get() as u16;
        let mut chain_segments = Vec::new();

        for (i, data) in segments.iter().enumerate() {
            let addr = self.next_addr.get();
            self.next_addr.set(addr + data.len() as u64);
            assert!(self.next_addr.get() <= MEM_SIZE, "out of memory");

            // Write data to guest memory
            self.mem.write(data, GuestAddress(addr)).unwrap();

            let idx = self.desc_idx.get();
            assert!(idx < self.queue_size as usize, "descriptor table full");

            let is_last = i == segments.len() - 1;
            let flags = if is_last { 0 } else { VIRTQ_DESC_F_NEXT };
            let next = if is_last { 0 } else { (idx + 1) as u16 };

            // Write descriptor to guest memory
            self.write_descriptor(idx, addr, data.len() as u32, flags, next);
            self.desc_idx.set(idx + 1);

            chain_segments.push(DescSegment {
                addr,
                len: data.len() as u32,
                expected_data: Some(data.to_vec()),
            });
        }

        // Add to available ring
        self.add_to_avail_ring(head_idx);

        // Track chain
        self.chains.borrow_mut().push(BuiltChain {
            head_index: head_idx,
            segments: chain_segments,
        });

        self
    }

    /// Add a writable chain (for RX). Each length in `sizes` becomes a descriptor.
    ///
    /// Simple case (1 descriptor): `driver.writable(&[1500])`
    /// Chained case: `driver.writable(&[12, 1500])` (e.g., header + payload)
    pub fn writable(&self, sizes: &[u32]) -> &Self {
        assert!(
            !sizes.is_empty(),
            "writable chain must have at least one segment"
        );
        let head_idx = self.desc_idx.get() as u16;
        let mut chain_segments = Vec::new();

        for (i, &len) in sizes.iter().enumerate() {
            let addr = self.next_addr.get();
            self.next_addr.set(addr + len as u64);
            assert!(self.next_addr.get() <= MEM_SIZE, "out of memory");

            let idx = self.desc_idx.get();
            assert!(idx < self.queue_size as usize, "descriptor table full");

            let is_last = i == sizes.len() - 1;
            let flags = VIRTQ_DESC_F_WRITE | if is_last { 0 } else { VIRTQ_DESC_F_NEXT };
            let next = if is_last { 0 } else { (idx + 1) as u16 };

            // Write descriptor to guest memory
            self.write_descriptor(idx, addr, len, flags, next);
            self.desc_idx.set(idx + 1);

            chain_segments.push(DescSegment {
                addr,
                len,
                expected_data: None,
            });
        }

        // Add to available ring
        self.add_to_avail_ring(head_idx);

        // Track chain
        self.chains.borrow_mut().push(BuiltChain {
            head_index: head_idx,
            segments: chain_segments,
        });

        self
    }

    fn write_descriptor(&self, idx: usize, addr: u64, len: u32, flags: u16, next: u16) {
        let desc = Descriptor {
            addr,
            len,
            flags,
            next,
        };
        let desc_addr = self.desc_table.unchecked_add((idx * 16) as u64);
        self.mem.write_obj(desc, desc_addr).unwrap();
    }

    fn add_to_avail_ring(&self, desc_idx: u16) {
        let avail_idx = self.avail_idx.get();

        // Write descriptor index to ring[avail_idx]
        // Available ring layout: flags(2) + idx(2) + ring[size](2*size)
        let ring_entry_addr = self.avail_ring.unchecked_add(4 + (avail_idx as u64) * 2);
        self.mem.write_obj(desc_idx, ring_entry_addr).unwrap();

        // Increment and write avail idx
        let new_avail_idx = avail_idx + 1;
        self.avail_idx.set(new_avail_idx);
        let avail_idx_addr = self.avail_ring.unchecked_add(2);
        self.mem.write_obj(new_avail_idx, avail_idx_addr).unwrap();
    }

    // ========================================================================
    // Query methods
    // ========================================================================

    /// Get the used ring entries as (descriptor_id, len) pairs.
    pub fn used_entries(&self) -> Vec<(u16, u32)> {
        // Used ring layout: flags(2) + idx(2) + ring[size]({id:4, len:4}*size)
        let used_idx_addr = self.used_ring.unchecked_add(2);
        let used_idx: u16 = self.mem.read_obj(used_idx_addr).unwrap();

        let mut entries = Vec::new();
        for i in 0..used_idx {
            // Each used element is 8 bytes: u32 id, u32 len
            let elem_addr = self.used_ring.unchecked_add(4 + (i as u64) * 8);
            let id: u32 = self.mem.read_obj(elem_addr).unwrap();
            let len: u32 = self.mem.read_obj(elem_addr.unchecked_add(4)).unwrap();
            entries.push((id as u16, len));
        }
        entries
    }

    // ========================================================================
    // Verification methods
    // ========================================================================

    /// Assert the used ring matches expected entries.
    ///
    /// Each entry is `(chain_idx, expected)` where `expected` is:
    /// - `Writable(bytes)` - verify writable chain content matches
    /// - `Readable` - verify readable chain wasn't modified
    #[track_caller]
    pub fn assert_used(&self, expected: &[(usize, ExpectedUsed<'_>)]) {
        let used = self.used_entries();
        let chains = self.chains.borrow();

        assert_eq!(
            used.len(),
            expected.len(),
            "used ring count mismatch: expected {}, got {}",
            expected.len(),
            used.len()
        );

        for (i, (chain_idx, expectation)) in expected.iter().enumerate() {
            let chain = &chains[*chain_idx];
            let (actual_id, actual_len) = used[i];

            // Verify descriptor ID
            assert_eq!(
                actual_id, chain.head_index,
                "used[{}] descriptor id mismatch: expected {} (chain {}), got {}",
                i, chain.head_index, chain_idx, actual_id
            );

            match expectation {
                ExpectedUsed::Writable(expected_bytes) => {
                    // Verify length
                    assert_eq!(
                        actual_len,
                        expected_bytes.len() as u32,
                        "used[{}] length mismatch: expected {}, got {}",
                        i,
                        expected_bytes.len(),
                        actual_len
                    );
                    // Verify content
                    let full = self.read_chain(chain);
                    let actual_data = &full[..expected_bytes.len().min(full.len())];
                    assert_eq!(
                        actual_data, *expected_bytes,
                        "used[{}] content mismatch for chain {}: expected {:?}, got {:?}",
                        i, chain_idx, expected_bytes, actual_data
                    );
                }
                ExpectedUsed::Readable => {
                    self.assert_chain_unchanged(&chains, *chain_idx);
                }
            }
        }
    }

    /// Assert a single chain's readable segments weren't modified.
    fn assert_chain_unchanged(&self, chains: &[BuiltChain], chain_idx: usize) {
        let chain = &chains[chain_idx];
        for (seg_idx, seg) in chain.segments.iter().enumerate() {
            if let Some(expected) = &seg.expected_data {
                let mut actual = vec![0u8; seg.len as usize];
                self.mem.read(&mut actual, GuestAddress(seg.addr)).unwrap();
                assert_eq!(
                    &actual, expected,
                    "chain {} segment {} at addr {:x} was modified: expected {:?}, got {:?}",
                    chain_idx, seg_idx, seg.addr, expected, actual
                );
            }
        }
    }

    /// Read data from all segments of a chain into a contiguous Vec.
    fn read_chain(&self, chain: &BuiltChain) -> Vec<u8> {
        let mut data = Vec::new();
        for seg in &chain.segments {
            let mut buf = vec![0u8; seg.len as usize];
            self.mem.read(&mut buf, GuestAddress(seg.addr)).unwrap();
            data.extend(buf);
        }
        data
    }
}
