use super::*;
use std::ffi::CString;
use std::mem::size_of;
use std::sync::Barrier;
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Instant;

use vm_memory::{Bytes, GuestAddress};

use super::super::fuse::{ForgetIn, InHeader, Opcode, OutHeader, ROOT_ID};
use super::super::virtual_entry::{VirtualEntry, VirtualEntryContent};
use crate::legacy::DummyIrqChip;
use crate::virtio::queue::tests::VirtQueue;
use crate::virtio::{MmioTransport, VIRTIO_MMIO_INT_VRING, device_status};
use crate::{Bus, BusDevice};

struct TestDevice<'a> {
    mem: &'a GuestMemoryMmap,
    fs: Arc<Mutex<Fs>>,
    transport: Arc<Mutex<MmioTransport>>,
    bus: Bus,
    queues: Vec<VirtQueue<'a>>,
}

impl<'a> TestDevice<'a> {
    fn new(mem: &'a GuestMemoryMmap, cpus: u32, sync: bool, event_idx: bool) -> Self {
        let mut fs = new_fs(cpus);
        fs.add_virtual_entry(VirtualDirEntry {
            name: CString::new("one-shot").unwrap(),
            entry: VirtualEntry {
                mode: 0o444,
                one_shot: true,
                content: VirtualEntryContent::File { data: b"shared" },
            },
        });
        let fs = Arc::new(Mutex::new(fs));
        let transport = Arc::new(Mutex::new(
            MmioTransport::new(mem.clone(), DummyIrqChip::new().into(), fs.clone()).unwrap(),
        ));
        let mut bus = Bus::new();
        bus.insert(transport.clone(), 0, 0x1000).unwrap();
        let mut device = Self {
            mem,
            fs,
            transport,
            bus,
            queues: Vec::new(),
        };
        device.configure(sync, event_idx);
        device
    }

    fn write_register(&mut self, offset: u64, value: u32) {
        assert!(self.bus.write(0, offset, &value.to_le_bytes()));
    }

    fn configure(&mut self, sync: bool, event_idx: bool) {
        self.queues = (0..self.transport.lock().unwrap().queue_evts().len())
            .map(|index| VirtQueue::new(GuestAddress(index as u64 * 0x1000), self.mem, 16))
            .collect();

        self.write_register(0x70, device_status::ACKNOWLEDGE);
        self.write_register(0x70, device_status::ACKNOWLEDGE | device_status::DRIVER);
        let mut features = 0;
        if sync {
            features |= 1 << uapi::VIRTIO_FS_F_SYNC;
        }
        if event_idx {
            features |= 1 << VIRTIO_RING_F_EVENT_IDX;
        }
        self.write_register(0x20, features);
        self.write_register(0x24, 1);
        self.write_register(0x20, 1 << (VIRTIO_F_VERSION_1 - 32));
        self.write_register(
            0x70,
            device_status::ACKNOWLEDGE | device_status::DRIVER | device_status::FEATURES_OK,
        );

        for index in 0..self.queues.len() {
            if !sync && self.transport.lock().unwrap().queue_is_sync(index) {
                continue;
            }
            let queue = self.queues[index].create_queue();
            self.write_register(0x30, index as u32);
            self.write_register(0x38, u32::from(queue.size));
            for (register, address) in [
                (0x80, queue.desc_table),
                (0x90, queue.avail_ring),
                (0xa0, queue.used_ring),
            ] {
                self.write_register(register, address.0 as u32);
                self.write_register(register + 4, (address.0 >> 32) as u32);
            }
            self.write_register(0x44, 1);
        }
        self.write_register(
            0x70,
            device_status::ACKNOWLEDGE
                | device_status::DRIVER
                | device_status::FEATURES_OK
                | device_status::DRIVER_OK,
        );
        assert!(self.fs.lock().unwrap().is_activated());
    }

    fn publish(&self, index: usize, opcode: Opcode, payload: &[u8], padding: u16) -> (u16, u64) {
        let queue = &self.queues[index];
        let avail = queue.avail.idx.get();
        let unique = ((index as u64) << 32) | (u64::from(avail) + 1);
        let input = GuestAddress(0x10000 + index as u64 * 0x1000);
        let header = InHeader {
            len: (size_of::<InHeader>() + payload.len()) as u32,
            opcode: opcode as u32,
            unique,
            nodeid: ROOT_ID,
            padding,
            ..Default::default()
        };
        self.mem.write_obj(header, input).unwrap();
        self.mem
            .write_slice(
                payload,
                GuestAddress(input.0 + size_of::<InHeader>() as u64),
            )
            .unwrap();
        let flags = if matches!(opcode, Opcode::Forget) {
            0
        } else {
            1
        };
        queue.dtable[0].set(input.0, header.len, flags, 1);
        queue.dtable[1].set(input.0 + 0x400, 512, 2, 0);
        queue.avail.ring[usize::from(avail % queue.size())].set(0);
        queue.avail.event.set(avail);
        let expected = avail.wrapping_add(1);
        self.mem
            .store(expected, queue.avail.idx.location, Ordering::Release)
            .unwrap();
        (expected, unique)
    }

    fn notify(&mut self, index: usize) {
        self.write_register(0x50, index as u32);
    }

    fn used_index(&self, index: usize) -> u16 {
        self.mem
            .load(self.queues[index].used.idx.location, Ordering::Acquire)
            .unwrap()
    }

    fn response(&self, index: usize, expected: u16, unique: u64) -> OutHeader {
        assert_eq!(self.used_index(index), expected);
        let header: OutHeader = self
            .mem
            .read_obj(GuestAddress(0x10400 + index as u64 * 0x1000))
            .unwrap();
        assert_eq!(header.unique, unique);
        let used = self.queues[index].used.ring
            [usize::from(expected.wrapping_sub(1) % self.queues[index].size())]
        .get();
        assert_eq!(used.id, 0);
        assert_eq!(used.len, header.len);
        header
    }

    fn interrupt_status(&mut self) -> u32 {
        let mut data = [0; 4];
        assert!(self.bus.read(0, 0x60, &mut data));
        u32::from_le_bytes(data)
    }

    fn wait_for_worker(&mut self, index: usize, expected: u16) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.used_index(index) != expected
            || self.interrupt_status() & VIRTIO_MMIO_INT_VRING == 0
        {
            assert!(
                Instant::now() < deadline,
                "worker did not complete queue {index}"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for TestDevice<'_> {
    fn drop(&mut self) {
        self.write_register(0x70, 0);
    }
}

fn new_fs(cpus: u32) -> Fs {
    Fs::new(
        "test".into(),
        PermissionSemantics::LinuxComplete,
        None,
        Arc::new(AtomicI32::new(i32::MAX)),
        false,
        Vec::new(),
        cpus,
    )
    .unwrap()
}

struct ObservedTransport {
    transport: Arc<Mutex<MmioTransport>>,
    prepared: Sender<()>,
}

impl BusDevice for ObservedTransport {
    fn prepare_write(
        &mut self,
        vcpuid: u64,
        offset: u64,
        data: &[u8],
    ) -> Option<Arc<dyn BusWriteAction>> {
        let action = self
            .transport
            .lock()
            .unwrap()
            .prepare_write(vcpuid, offset, data);
        if action.is_some() {
            self.prepared.send(()).unwrap();
        }
        action
    }
}

#[test]
fn blocked_sync_queue_does_not_serialize_other_queues() {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
    let mut device = TestDevice::new(&mem, 2, true, true);
    let (first_expected, first_unique) = device.publish(2, Opcode::Lookup, b"missing\0", 0);
    let (second_expected, second_unique) = device.publish(3, Opcode::Lookup, b"missing\0", 0);
    let queue = device.fs.lock().unwrap().sync_queues[0].clone();
    let blocked = queue.queue.lock().unwrap();
    let (prepared, selected) = mpsc::channel();
    let mut bus = Bus::new();
    bus.insert(
        Arc::new(Mutex::new(ObservedTransport {
            transport: device.transport.clone(),
            prepared,
        })),
        0,
        0x1000,
    )
    .unwrap();
    let first_bus = bus.clone();
    let first = thread::spawn(move || first_bus.write(0, 0x50, &2u32.to_le_bytes()));
    let first_selected = selected.recv_timeout(Duration::from_secs(5));
    let (completed, completion) = mpsc::channel();
    let second = thread::spawn(move || {
        let result = bus.write(1, 0x50, &3u32.to_le_bytes());
        completed.send(result).unwrap();
    });
    let second_completed = completion.recv_timeout(Duration::from_secs(5));
    let fs_unlocked = device.fs.try_lock().is_ok();
    let transport_unlocked = device.transport.try_lock().is_ok();
    let first_pending = !first.is_finished();
    let first_used = device.used_index(2);
    drop(blocked);
    assert!(first.join().unwrap());
    second.join().unwrap();
    first_selected.unwrap();
    assert!(second_completed.unwrap());
    assert!(fs_unlocked);
    assert!(transport_unlocked);
    assert!(first_pending);
    assert_eq!(first_used, 0);
    device.response(2, first_expected, first_unique);
    device.response(3, second_expected, second_unique);
    assert_eq!(device.interrupt_status(), 0);
}

#[test]
fn concurrent_kicks_on_one_queue_complete_each_descriptor_once() {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
    let mut device = TestDevice::new(&mem, 1, true, true);
    for _ in 0..8 {
        let (expected, unique) = device.publish(2, Opcode::Lookup, b"missing\0", 0);
        let start = Arc::new(Barrier::new(8));
        let writers: Vec<_> = (0..8)
            .map(|cpu| {
                let bus = device.bus.clone();
                let start = start.clone();
                thread::spawn(move || {
                    start.wait();
                    bus.write(cpu, 0x50, &2u32.to_le_bytes())
                })
            })
            .collect();
        for writer in writers {
            assert!(writer.join().unwrap());
        }
        assert_eq!(device.response(2, expected, unique).error, -libc::ENOENT);
    }
    assert_eq!(device.interrupt_status(), 0);
}

#[test]
fn reset_drains_queue_execution_and_invalidates_selected_handlers() {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
    let mut device = TestDevice::new(&mem, 2, true, true);
    device.publish(2, Opcode::Lookup, b"missing\0", 0);
    let stale = device
        .transport
        .lock()
        .unwrap()
        .prepare_write(0, 0x50, &2u32.to_le_bytes())
        .unwrap();
    let queue = device.fs.lock().unwrap().sync_queues[0].clone();
    let blocked = queue.queue.lock().unwrap();
    let bus = device.bus.clone();
    let reset = thread::spawn(move || bus.write(1, 0x70, &0u32.to_le_bytes()));
    let deadline = Instant::now() + Duration::from_secs(5);
    while queue.runtime.active.load(Ordering::Acquire) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
    let stopped_admission = !queue.runtime.active.load(Ordering::Acquire);
    let reset_pending = !reset.is_finished();
    drop(blocked);
    assert!(reset.join().unwrap());
    assert!(stopped_admission);
    assert!(reset_pending);
    stale.execute();
    assert_eq!(device.used_index(2), 0);

    device.configure(true, true);
    let (expected, unique) = device.publish(2, Opcode::Lookup, b"missing\0", 0);
    stale.execute();
    assert_eq!(device.used_index(2), 0);
    device.notify(2);
    device.response(2, expected, unique);
}

#[test]
fn config_and_queue_layout_match_guest_abi() {
    assert_eq!(size_of::<InHeader>(), 40);
    assert_eq!(offset_of!(InHeader, padding), 38);
    assert_eq!(size_of::<VirtioFsConfig>(), 44);
    assert_eq!(offset_of!(VirtioFsConfig, num_sync_queues), 40);
    for cpus in [0, 1, 4] {
        let mut fs = new_fs(cpus);
        assert_eq!(fs.queue_config().len(), 2 + cpus as usize);
        assert!(!fs.queue_config()[defs::HPQ_INDEX].synchronous);
        assert!(!fs.queue_config()[defs::REQ_INDEX].synchronous);
        assert!(fs.queue_config()[2..].iter().all(|queue| queue.synchronous));
        let mut count = [0; 4];
        fs.read_config(36, &mut count);
        assert_eq!(u32::from_le_bytes(count), 1);
        count.fill(0xff);
        fs.read_config(40, &mut count);
        assert_eq!(count, [0xff; 4]);
        fs.ack_features_by_page(0, 1 << uapi::VIRTIO_FS_F_SYNC);
        assert_eq!(fs.sync_enabled(), cpus != 0);
        if cpus != 0 {
            fs.read_config(40, &mut count);
            assert_eq!(u32::from_le_bytes(count), cpus);
        }
    }
}

#[test]
fn sync_queues_complete_inline_without_interrupts() {
    for event_idx in [false, true] {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let mut device = TestDevice::new(&mem, 4, true, event_idx);
        for index in 2..6 {
            assert!(device.transport.lock().unwrap().queue_is_sync(index));
            for _ in 0..2 {
                let (expected, unique) = device.publish(index, Opcode::Lookup, b"missing\0", 0);
                device.notify(index);
                assert_eq!(
                    device.response(index, expected, unique).error,
                    -libc::ENOENT
                );
                assert_eq!(device.interrupt_status(), 0);
                assert!(
                    device.transport.lock().unwrap().queue_evts()[index]
                        .read()
                        .is_err()
                );
            }
        }
        let mut fs = device.fs.lock().unwrap();
        assert!(fs.sync_queue(0).is_none());
        assert!(fs.sync_queue(1).is_none());
        assert!(fs.sync_queue(6).is_none());
        assert!(fs.sync_queue(u32::MAX).is_none());
        Arc::get_mut(&mut fs.sync_queues[0]).unwrap().ready = false;
        assert!(fs.sync_queue(2).is_none());
    }
}

#[test]
fn legacy_guest_uses_worker_and_ignores_fuse_padding() {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
    let mut device = TestDevice::new(&mem, 4, false, false);
    assert!(device.fs.lock().unwrap().sync_queues.is_empty());
    assert!(device.fs.lock().unwrap().sync_queue(2).is_none());
    assert!(!device.transport.lock().unwrap().queue_is_sync(0));
    assert!(!device.transport.lock().unwrap().queue_is_sync(1));
    let (expected, unique) = device.publish(1, Opcode::Lookup, b"missing\0", 1);
    device.notify(1);
    device.wait_for_worker(1, expected);
    assert_eq!(device.response(1, expected, unique).error, -libc::ENOENT);
    device.write_register(0x64, VIRTIO_MMIO_INT_VRING);
    let forget = ForgetIn { nlookup: 1 };
    let (expected, _) = device.publish(0, Opcode::Forget, forget.as_slice(), 0);
    device.notify(0);
    device.wait_for_worker(0, expected);
    assert_eq!(device.queues[0].used.ring[0].get().len, 0);
}

#[test]
fn synchronous_and_worker_requests_share_filesystem_state() {
    for sync_first in [false, true] {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
        let mut device = TestDevice::new(&mem, 2, true, true);
        let indices = if sync_first { [2, 1] } else { [1, 2] };
        for (position, index) in indices.into_iter().enumerate() {
            let (expected, unique) = device.publish(index, Opcode::Lookup, b"one-shot\0", 0);
            device.notify(index);
            if index == 1 {
                device.wait_for_worker(index, expected);
            }
            let error = device.response(index, expected, unique).error;
            assert_eq!(error, if position == 0 { 0 } else { -libc::ENOENT });
            device.write_register(0x64, VIRTIO_MMIO_INT_VRING);
        }
    }
}

#[test]
fn reset_can_renegotiate_without_sync_queues() {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap();
    let mut device = TestDevice::new(&mem, 2, true, true);
    let (expected, unique) = device.publish(2, Opcode::Lookup, b"missing\0", 0);
    device.notify(2);
    device.response(2, expected, unique);
    device.write_register(0x70, 0);
    {
        let fs = device.fs.lock().unwrap();
        assert!(!fs.is_activated());
        assert_eq!(fs.acked_features(), 0);
        assert!(fs.sync_queues.is_empty());
        assert!(fs.sync_runtime.is_none());
        assert!(fs.worker_thread.is_none());
        assert!(fs.sync_queue(2).is_none());
    }
    device.configure(false, false);
    let (expected, unique) = device.publish(1, Opcode::Lookup, b"missing\0", 0);
    device.notify(1);
    device.wait_for_worker(1, expected);
    assert_eq!(device.response(1, expected, unique).error, -libc::ENOENT);
}

#[test]
fn reset_before_activation_clears_sync_negotiation() {
    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
    let fs = Arc::new(Mutex::new(new_fs(2)));
    let mut transport = MmioTransport::new(mem, DummyIrqChip::new().into(), fs.clone()).unwrap();
    transport.write(0, 0x70, &device_status::ACKNOWLEDGE.to_le_bytes());
    transport.write(
        0,
        0x70,
        &(device_status::ACKNOWLEDGE | device_status::DRIVER).to_le_bytes(),
    );
    transport.write(0, 0x20, &(1u32 << uapi::VIRTIO_FS_F_SYNC).to_le_bytes());
    assert!(fs.lock().unwrap().sync_enabled());
    transport.write(0, 0x70, &0u32.to_le_bytes());
    assert!(!fs.lock().unwrap().sync_enabled());
}
