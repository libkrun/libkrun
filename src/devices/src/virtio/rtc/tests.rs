// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests that drive the device through virtqueues in guest memory, the way a
//! guest driver does.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use polly::event_manager::EventManager;
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use super::device::{AVAIL_FEATURES, Rtc};
use super::protocol::*;
use crate::virtio::device::{InterruptHandler, InterruptType};
use crate::virtio::queue::tests::VirtQueue;
use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::virtio::{DeviceQueue, InterruptTransport, VirtioDevice};

const QUEUE_SIZE: u16 = 16;
const REQUESTQ_START: u64 = 0;
const ALARMQ_START: u64 = 0x2000;
const REQUEST_BUFFERS: u64 = 0x10000;
const ALARM_BUFFERS: u64 = 0x18000;
const RESP_OFFSET: u64 = 0x100;
const FILL: u8 = 0xaa;
const HOUR_NS: u64 = 3_600_000_000_000;

fn guest_memory() -> GuestMemoryMmap {
    GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20000)]).unwrap()
}

fn head(msg_type: u16) -> VirtioRtcReqHead {
    VirtioRtcReqHead {
        msg_type: msg_type.into(),
        ..Default::default()
    }
}

/// Counts the interrupts that the device sent.
#[derive(Default)]
struct Interrupts(AtomicUsize);

impl InterruptHandler for Interrupts {
    fn try_signal(&self, interrupt: InterruptType) -> std::result::Result<(), crate::Error> {
        if let InterruptType::UsedQueue = interrupt {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

/// Makes a request available in the request queue, with a device-writable
/// response buffer of `resp_cap` bytes that is filled with `FILL`.
fn submit_request(
    mem: &GuestMemoryMmap,
    queue: &VirtQueue,
    slot: u64,
    request: &[u8],
    resp_cap: u32,
) {
    let desc = (2 * slot) as u16;
    let req_addr = REQUEST_BUFFERS + slot * 0x200;
    let resp_addr = req_addr + RESP_OFFSET;
    mem.write_slice(request, GuestAddress(req_addr)).unwrap();
    mem.write_slice(&vec![FILL; resp_cap as usize], GuestAddress(resp_addr))
        .unwrap();
    queue.dtable[desc as usize].set(req_addr, request.len() as u32, VIRTQ_DESC_F_NEXT, desc + 1);
    queue.dtable[desc as usize + 1].set(resp_addr, resp_cap, VIRTQ_DESC_F_WRITE, 0);
    push_avail(queue, desc);
}

/// Makes an empty, device-writable buffer available in the alarm queue.
fn post_alarm_buffer(mem: &GuestMemoryMmap, queue: &VirtQueue, buffer: u64, len: u32) {
    let addr = ALARM_BUFFERS + buffer * 0x40;
    mem.write_slice(&[FILL; 0x40], GuestAddress(addr)).unwrap();
    queue.dtable[buffer as usize].set(addr, len, VIRTQ_DESC_F_WRITE, 0);
    push_avail(queue, buffer as u16);
}

fn push_avail(queue: &VirtQueue, head: u16) {
    let idx = queue.avail.idx.get();
    queue.avail.ring[usize::from(idx % QUEUE_SIZE)].set(head);
    queue.avail.idx.set(idx.wrapping_add(1));
}

fn device_queue(queue: &VirtQueue) -> DeviceQueue {
    DeviceQueue::new(
        queue.create_queue(),
        Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
    )
}

/// A response and the number of bytes that the device used for it.
struct Reply {
    bytes: Vec<u8>,
    len: u32,
}

impl Reply {
    fn status(&self) -> u8 {
        self.bytes[0]
    }

    fn parse<T: ByteValued>(&self) -> T {
        T::from_slice(&self.bytes[..size_of::<T>()])
            .copied()
            .unwrap()
    }
}

/// The device with its two queues, activated.
struct Harness<'a> {
    mem: &'a GuestMemoryMmap,
    rtc: Rtc,
    requestq: VirtQueue<'a>,
    alarmq: VirtQueue<'a>,
    interrupts: Arc<Interrupts>,
    requests: u64,
    alarm_buffers: u64,
}

impl<'a> Harness<'a> {
    /// Activates the device with the given negotiated features.
    fn new(mem: &'a GuestMemoryMmap, features: u64) -> Self {
        let requestq = VirtQueue::new(GuestAddress(REQUESTQ_START), mem, QUEUE_SIZE);
        let alarmq = VirtQueue::new(GuestAddress(ALARMQ_START), mem, QUEUE_SIZE);
        let mut queues = vec![device_queue(&requestq), device_queue(&alarmq)];
        let event_idx = features & (1 << 29) != 0;
        for queue in &mut queues {
            queue.queue.set_event_idx(event_idx);
        }

        let interrupts = Arc::new(Interrupts::default());
        let mut rtc = Rtc::new().unwrap();
        rtc.set_acked_features(features);
        rtc.activate(
            mem.clone(),
            InterruptTransport::from_handler(interrupts.clone()),
            queues,
        )
        .unwrap();

        Self {
            mem,
            rtc,
            requestq,
            alarmq,
            interrupts,
            requests: 0,
            alarm_buffers: 0,
        }
    }

    fn interrupts(&self) -> usize {
        self.interrupts.0.load(Ordering::SeqCst)
    }

    /// Sends a request and returns the response.
    fn request<T: ByteValued>(&mut self, request: T, resp_cap: u32) -> Reply {
        self.request_bytes(request.as_slice(), resp_cap)
    }

    fn request_bytes(&mut self, request: &[u8], resp_cap: u32) -> Reply {
        let slot = self.requests % 8;
        let used_before = self.requestq.used.idx.get();
        submit_request(self.mem, &self.requestq, slot, request, resp_cap);
        self.requests += 1;
        self.rtc.queue_event(REQUEST_QUEUE_IDX).write(1).unwrap();
        self.rtc
            .handle_request_event(&utils::epoll::EpollEvent::new(
                utils::epoll::EventSet::IN,
                0,
            ));

        assert_eq!(
            self.requestq.used.idx.get(),
            used_before.wrapping_add(1),
            "the request was not answered"
        );
        let element = self.requestq.used.ring[usize::from(used_before % QUEUE_SIZE)].get();
        assert_eq!(u64::from(element.id), 2 * slot);

        let mut bytes = vec![0; resp_cap as usize];
        let resp_addr = REQUEST_BUFFERS + slot * 0x200 + RESP_OFFSET;
        self.mem
            .read_slice(&mut bytes, GuestAddress(resp_addr))
            .unwrap();
        Reply {
            bytes,
            len: element.len,
        }
    }

    fn alarm_cap_flag(&mut self, clock_id: u16) -> bool {
        let req = VirtioRtcReqClockCap {
            head: head(VIRTIO_RTC_REQ_CLOCK_CAP),
            clock_id: clock_id.into(),
            ..Default::default()
        };
        let reply = self.request(req, 16);
        assert_eq!(reply.status(), VIRTIO_RTC_S_OK);
        reply.parse::<VirtioRtcRespClockCap>().flags & VIRTIO_RTC_FLAG_ALARM_CAP != 0
    }

    fn set_alarm(&mut self, clock_id: u16, alarm_time: u64, enabled: bool) -> u8 {
        let req = VirtioRtcReqSetAlarm {
            head: head(VIRTIO_RTC_REQ_SET_ALARM),
            alarm_time: alarm_time.into(),
            clock_id: clock_id.into(),
            flags: if enabled {
                VIRTIO_RTC_FLAG_ALARM_ENABLED
            } else {
                0
            },
            ..Default::default()
        };
        self.request(req, 8).status()
    }

    fn set_alarm_enabled(&mut self, clock_id: u16, enabled: bool) -> u8 {
        let req = VirtioRtcReqSetAlarmEnabled {
            head: head(VIRTIO_RTC_REQ_SET_ALARM_ENABLED),
            clock_id: clock_id.into(),
            flags: if enabled {
                VIRTIO_RTC_FLAG_ALARM_ENABLED
            } else {
                0
            },
            ..Default::default()
        };
        self.request(req, 8).status()
    }

    /// Returns the alarm time and enabled flag of a clock.
    fn read_alarm(&mut self, clock_id: u16) -> (u64, bool) {
        let req = VirtioRtcReqReadAlarm {
            head: head(VIRTIO_RTC_REQ_READ_ALARM),
            clock_id: clock_id.into(),
            ..Default::default()
        };
        let reply = self.request(req, 24);
        assert_eq!(reply.status(), VIRTIO_RTC_S_OK);
        let resp = reply.parse::<VirtioRtcRespReadAlarm>();
        (
            resp.alarm_time.into(),
            resp.flags & VIRTIO_RTC_FLAG_ALARM_ENABLED != 0,
        )
    }

    fn read_clock(&mut self, clock_id: u16) -> u64 {
        let req = VirtioRtcReqRead {
            head: head(VIRTIO_RTC_REQ_READ),
            clock_id: clock_id.into(),
            ..Default::default()
        };
        let reply = self.request(req, 16);
        assert_eq!(reply.status(), VIRTIO_RTC_S_OK);
        reply.parse::<VirtioRtcRespRead>().clock_reading.into()
    }

    /// Makes an alarm queue buffer of `len` bytes available and notifies the
    /// device.
    fn post_alarm_buffer(&mut self, len: u32) {
        post_alarm_buffer(self.mem, &self.alarmq, self.alarm_buffers, len);
        self.alarm_buffers += 1;
        self.rtc.queue_event(ALARM_QUEUE_IDX).write(1).unwrap();
        self.rtc
            .handle_alarm_queue_event(&utils::epoll::EpollEvent::new(
                utils::epoll::EventSet::IN,
                0,
            ));
    }

    /// The notifications that the device wrote: the clock id of each.
    fn notifications(&self) -> Vec<u16> {
        (0..self.alarmq.used.idx.get())
            .map(|i| {
                let element = self.alarmq.used.ring[usize::from(i % QUEUE_SIZE)].get();
                assert_eq!(element.len as usize, size_of::<VirtioRtcNotifAlarm>());
                let mut bytes = [0u8; size_of::<VirtioRtcNotifAlarm>()];
                let addr = ALARM_BUFFERS + u64::from(element.id) * 0x40;
                self.mem.read_slice(&mut bytes, GuestAddress(addr)).unwrap();
                let notif = VirtioRtcNotifAlarm::from_slice(&bytes).copied().unwrap();
                assert_eq!(u16::from(notif.head.msg_type), VIRTIO_RTC_NOTIF_ALARM);
                notif.clock_id.into()
            })
            .collect()
    }

    /// Waits until the alarm timer fires, and lets the device handle it.
    fn wait_for_timer(&mut self, timeout: Duration) -> bool {
        let fd = std::os::fd::AsRawFd::as_raw_fd(&self.rtc.timer);
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is valid for the duration of the call.
        let ready = unsafe { libc::poll(&mut pfd, 1, timeout.as_millis() as libc::c_int) } > 0;
        if ready {
            self.rtc.handle_timer_event();
        }
        ready
    }
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

const WITH_ALARM: u64 = AVAIL_FEATURES;
const WITHOUT_ALARM: u64 = AVAIL_FEATURES & !(1 << VIRTIO_RTC_F_ALARM);

/// Everything except `EVENT_IDX`, to count the interrupts without the
/// interrupt suppression that `EVENT_IDX` brings.
const ALARM_NO_EVENT_IDX: u64 = (1 << 32) | (1 << VIRTIO_RTC_F_ALARM);

#[test]
fn offered_features_are_pinned() {
    // VERSION_1 (32), EVENT_IDX (29) and the alarm (0). In particular not
    // INDIRECT_DESC (28): libkrun's `Queue` cannot follow indirect tables.
    assert_eq!(AVAIL_FEATURES, (1 << 32) | (1 << 29) | 1);
    assert_eq!(AVAIL_FEATURES & (1 << 28), 0);
    assert_eq!(AVAIL_FEATURES & (1 << 24), 0);
    assert_eq!(Rtc::new().unwrap().avail_features(), AVAIL_FEATURES);
}

#[test]
fn device_identity_and_queues() {
    let rtc = Rtc::new().unwrap();
    assert_eq!(rtc.device_type(), 17);
    assert_eq!(rtc.queue_config().len(), 2);
    assert!(rtc.queue_config().iter().all(|q| q.size == 1024));
    assert_eq!(rtc.config_len(), Some(0));
}

#[test]
fn cfg_reports_three_clocks() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, WITH_ALARM);
    let reply = h.request(
        VirtioRtcReqHead {
            msg_type: VIRTIO_RTC_REQ_CFG.into(),
            ..Default::default()
        },
        16,
    );
    assert_eq!(reply.status(), VIRTIO_RTC_S_OK);
    assert_eq!(reply.len, 16);
    assert_eq!(u16::from(reply.parse::<VirtioRtcRespCfg>().num_clocks), 3);
}

#[test]
fn clock_capabilities() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, WITH_ALARM);
    let expected = [
        (VIRTIO_RTC_CLOCK_UTC_SMEARED, true),
        (VIRTIO_RTC_CLOCK_TAI, false),
        (VIRTIO_RTC_CLOCK_MONOTONIC, false),
    ];
    for (clock_id, (clock_type, alarm)) in expected.into_iter().enumerate() {
        let req = VirtioRtcReqClockCap {
            head: head(VIRTIO_RTC_REQ_CLOCK_CAP),
            clock_id: (clock_id as u16).into(),
            ..Default::default()
        };
        let reply = h.request(req, 16);
        assert_eq!(reply.status(), VIRTIO_RTC_S_OK);
        let cap = reply.parse::<VirtioRtcRespClockCap>();
        assert_eq!(cap.r#type, clock_type);
        assert_eq!(cap.leap_second_smearing, VIRTIO_RTC_SMEAR_UNSPECIFIED);
        assert_eq!(cap.flags & VIRTIO_RTC_FLAG_ALARM_CAP != 0, alarm);
        assert_eq!(cap.reserved, [0; 5]);
    }
}

#[test]
fn alarm_capability_needs_the_negotiated_feature() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, WITHOUT_ALARM);
    assert!(!h.alarm_cap_flag(0));
}

#[test]
fn unknown_clock_is_enodev() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, WITH_ALARM);
    for (msg_type, size) in [
        (VIRTIO_RTC_REQ_CLOCK_CAP, 16),
        (VIRTIO_RTC_REQ_READ, 16),
        (VIRTIO_RTC_REQ_READ_ALARM, 24),
    ] {
        let req = VirtioRtcReqRead {
            head: head(msg_type),
            clock_id: 3.into(),
            ..Default::default()
        };
        assert_eq!(h.request(req, size).status(), VIRTIO_RTC_S_ENODEV);
    }
    assert_eq!(h.set_alarm(3, 0, true), VIRTIO_RTC_S_ENODEV);
    assert_eq!(h.set_alarm_enabled(3, true), VIRTIO_RTC_S_ENODEV);
}

#[test]
fn clocks_are_read_in_nanoseconds() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, WITH_ALARM);

    let before = now_ns();
    let utc = h.read_clock(0);
    assert!(before <= utc && utc <= now_ns());

    assert!(h.read_clock(2) <= h.read_clock(2));
    // TAI is ahead of UTC or equal to it.
    assert!(h.read_clock(1) >= utc);
}

#[test]
fn cross_timestamping_is_not_supported() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, WITH_ALARM);
    for hw_counter in [VIRTIO_RTC_COUNTER_ARM_VCT, VIRTIO_RTC_COUNTER_X86_TSC] {
        let cap = VirtioRtcReqCrossCap {
            head: head(VIRTIO_RTC_REQ_CROSS_CAP),
            clock_id: 0.into(),
            hw_counter,
            ..Default::default()
        };
        let reply = h.request(cap, 16);
        assert_eq!(reply.status(), VIRTIO_RTC_S_OK);
        assert_eq!(reply.parse::<VirtioRtcRespCrossCap>().flags, 0);

        let read = VirtioRtcReqReadCross {
            head: head(VIRTIO_RTC_REQ_READ_CROSS),
            clock_id: 0.into(),
            hw_counter,
            ..Default::default()
        };
        assert_eq!(h.request(read, 24).status(), VIRTIO_RTC_S_EOPNOTSUPP);
    }
}

#[test]
fn unknown_hw_counter_and_message_are_eopnotsupp() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, WITH_ALARM);
    let cap = VirtioRtcReqCrossCap {
        head: head(VIRTIO_RTC_REQ_CROSS_CAP),
        hw_counter: 0x42,
        ..Default::default()
    };
    assert_eq!(h.request(cap, 16).status(), VIRTIO_RTC_S_EOPNOTSUPP);
    assert_eq!(
        h.request(head(0x7777), 16).status(),
        VIRTIO_RTC_S_EOPNOTSUPP
    );
}

#[test]
fn alarm_messages_need_the_feature_and_an_alarm_clock() {
    let mem = guest_memory();
    let mut without = Harness::new(&mem, WITHOUT_ALARM);
    let read = VirtioRtcReqReadAlarm {
        head: head(VIRTIO_RTC_REQ_READ_ALARM),
        ..Default::default()
    };
    assert_eq!(without.request(read, 24).status(), VIRTIO_RTC_S_ENODEV);
    assert_eq!(without.set_alarm(0, 0, true), VIRTIO_RTC_S_ENODEV);
    assert_eq!(without.set_alarm_enabled(0, true), VIRTIO_RTC_S_ENODEV);

    let mem = guest_memory();
    let mut with = Harness::new(&mem, WITH_ALARM);
    for clock_id in [1, 2] {
        assert_eq!(with.set_alarm(clock_id, 0, true), VIRTIO_RTC_S_ENODEV);
        assert_eq!(with.set_alarm_enabled(clock_id, true), VIRTIO_RTC_S_ENODEV);
    }
}

#[test]
fn request_and_response_buffer_sizes() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, WITH_ALARM);
    let cfg = head(VIRTIO_RTC_REQ_CFG);

    // A response buffer that is too small: EINVAL, as far as it fits.
    let reply = h.request(cfg, 4);
    assert_eq!(reply.status(), VIRTIO_RTC_S_EINVAL);
    assert_eq!(reply.len, 4);
    assert_eq!(reply.bytes[1..], [0, 0, 0]);

    // Not even the status fits: nothing is written.
    let reply = h.request_bytes(cfg.as_slice(), 0);
    assert_eq!(reply.len, 0);

    // A request that is too short for its message type.
    let read = VirtioRtcReqRead {
        head: head(VIRTIO_RTC_REQ_READ),
        ..Default::default()
    };
    let reply = h.request_bytes(&read.as_slice()[..12], 16);
    assert_eq!(reply.status(), VIRTIO_RTC_S_EINVAL);
    let reply = h.request_bytes(&cfg.as_slice()[..4], 16);
    assert_eq!(reply.status(), VIRTIO_RTC_S_EINVAL);

    // Additional space in either buffer is ignored.
    let mut long_request = cfg.as_slice().to_vec();
    long_request.extend_from_slice(&[0x55; 24]);
    let reply = h.request_bytes(&long_request, 64);
    assert_eq!(reply.status(), VIRTIO_RTC_S_OK);
    assert_eq!(reply.len, 16);
    assert!(reply.bytes[16..].iter().all(|&b| b == FILL));
}

#[test]
fn every_request_is_answered_and_interrupts_the_guest() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, ALARM_NO_EVENT_IDX);
    assert_eq!(h.interrupts(), 0);
    h.read_clock(0);
    assert_eq!(h.interrupts(), 1);
    h.request(head(0x7777), 16);
    assert_eq!(h.interrupts(), 2);
}

#[test]
fn alarm_in_the_past_is_reported_once_a_buffer_is_available() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, ALARM_NO_EVENT_IDX);
    assert_eq!(h.set_alarm(0, now_ns() - HOUR_NS, true), VIRTIO_RTC_S_OK);
    // The driver has not provided a buffer yet: nothing is lost.
    assert!(h.notifications().is_empty());

    let interrupts = h.interrupts();
    h.post_alarm_buffer(size_of::<VirtioRtcNotifAlarm>() as u32);
    assert_eq!(h.notifications(), vec![0]);
    assert_eq!(h.interrupts(), interrupts + 1);

    // The alarm stays enabled after it expired, and its time is retained.
    let (time, enabled) = h.read_alarm(0);
    assert!(enabled);
    assert!(time < now_ns());

    // The notification is not repeated.
    h.post_alarm_buffer(size_of::<VirtioRtcNotifAlarm>() as u32);
    assert_eq!(h.notifications(), vec![0]);
}

#[test]
fn alarm_in_the_past_with_a_waiting_buffer_is_reported_at_once() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, ALARM_NO_EVENT_IDX);
    h.post_alarm_buffer(size_of::<VirtioRtcNotifAlarm>() as u32);
    assert!(h.notifications().is_empty());
    h.set_alarm(0, 0, true);
    assert_eq!(h.notifications(), vec![0]);
}

#[test]
fn alarm_in_the_future_expires_through_the_timer() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, ALARM_NO_EVENT_IDX);
    h.post_alarm_buffer(size_of::<VirtioRtcNotifAlarm>() as u32);
    let alarm_time = now_ns() + 60_000_000;
    h.set_alarm(0, alarm_time, true);
    assert!(h.notifications().is_empty());
    assert_eq!(h.read_alarm(0), (alarm_time, true));

    assert!(h.wait_for_timer(Duration::from_secs(5)));
    assert_eq!(h.notifications(), vec![0]);
    // The clock does not precede the alarm time after the notification.
    assert!(h.read_clock(0) >= alarm_time);
}

#[test]
fn disabled_alarm_does_not_expire() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, ALARM_NO_EVENT_IDX);
    h.post_alarm_buffer(size_of::<VirtioRtcNotifAlarm>() as u32);

    // Not enabled: even a time in the past is no expiration.
    h.set_alarm(0, 0, false);
    assert_eq!(h.read_alarm(0), (0, false));
    assert!(h.notifications().is_empty());

    // Disabling an alarm in the future cancels the timer.
    h.set_alarm(0, now_ns() + 60_000_000, true);
    assert_eq!(h.set_alarm_enabled(0, false), VIRTIO_RTC_S_OK);
    assert!(!h.wait_for_timer(Duration::from_millis(200)));
    assert!(h.notifications().is_empty());

    // Enabling it again retains the time; one in the past expires.
    h.set_alarm(0, 1, false);
    assert_eq!(h.set_alarm_enabled(0, true), VIRTIO_RTC_S_OK);
    assert_eq!(h.notifications(), vec![0]);
}

#[test]
fn changing_the_alarm_makes_the_earlier_expiration_obsolete() {
    let notif_len = size_of::<VirtioRtcNotifAlarm>() as u32;

    // Setting a time in the future.
    let mem = guest_memory();
    let mut h = Harness::new(&mem, ALARM_NO_EVENT_IDX);
    h.set_alarm(0, 1, true);
    h.set_alarm(0, now_ns() + HOUR_NS, true);
    h.post_alarm_buffer(notif_len);
    assert!(h.notifications().is_empty());

    // Disabling the alarm.
    let mem = guest_memory();
    let mut h = Harness::new(&mem, ALARM_NO_EVENT_IDX);
    h.set_alarm(0, 1, true);
    h.set_alarm_enabled(0, false);
    h.post_alarm_buffer(notif_len);
    assert!(h.notifications().is_empty());
}

#[test]
fn expirations_without_a_buffer_are_reported_once() {
    let notif_len = size_of::<VirtioRtcNotifAlarm>() as u32;
    let mem = guest_memory();
    let mut h = Harness::new(&mem, ALARM_NO_EVENT_IDX);

    // Two expirations before the driver provides a buffer: one report.
    h.set_alarm(0, 1, true);
    h.set_alarm(0, 2, true);
    h.post_alarm_buffer(notif_len);
    assert_eq!(h.notifications(), vec![0]);
    h.post_alarm_buffer(notif_len);
    assert_eq!(h.notifications(), vec![0]);

    // A new expiration, with a buffer waiting, is reported at once.
    h.set_alarm(0, 3, true);
    assert_eq!(h.notifications(), vec![0, 0]);
}

#[test]
fn clock_stepping_back_before_the_alarm_rearms_it() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, ALARM_NO_EVENT_IDX);
    h.set_alarm(0, 1, true);
    h.post_alarm_buffer(size_of::<VirtioRtcNotifAlarm>() as u32);
    assert_eq!(h.notifications(), vec![0]);

    // The test cannot set the realtime clock; moving the alarm time behind
    // the clock is the same comparison as the clock stepping back.
    h.rtc.clocks[0].alarm.as_mut().unwrap().time = now_ns() + HOUR_NS;
    h.rtc.update_alarms();
    assert!(!h.rtc.clocks[0].alarm.unwrap().fired);
    h.rtc.clocks[0].alarm.as_mut().unwrap().time = 1;
    h.rtc.update_alarms();
    h.post_alarm_buffer(size_of::<VirtioRtcNotifAlarm>() as u32);
    assert_eq!(h.notifications(), vec![0, 0]);
}

#[test]
fn unusable_alarm_buffer_is_returned_and_the_next_one_is_used() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, ALARM_NO_EVENT_IDX);
    h.set_alarm(0, 1, true);
    h.post_alarm_buffer(4);
    assert_eq!(h.alarmq.used.idx.get(), 1);
    assert_eq!(h.alarmq.used.ring[0].get().len, 0);
    assert!(h.rtc.clocks[0].alarm.unwrap().pending);

    h.post_alarm_buffer(size_of::<VirtioRtcNotifAlarm>() as u32);
    assert_eq!(h.alarmq.used.idx.get(), 2);
    assert!(!h.rtc.clocks[0].alarm.unwrap().pending);
}

#[test]
fn reset_clears_alarms_and_cancels_the_timer() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, ALARM_NO_EVENT_IDX);
    h.set_alarm(0, now_ns() + 60_000_000, true);
    assert!(h.read_alarm(0).1);

    assert!(h.rtc.reset());
    assert!(!h.rtc.is_activated());
    assert!(h.rtc.queues.is_none());
    assert_eq!(h.rtc.acked_features(), 0);
    assert_eq!(h.rtc.clocks[0].alarm, Some(Default::default()));
    // The timer was armed for the alarm; after the reset it must stay quiet.
    assert!(!h.wait_for_timer(Duration::from_millis(200)));

    // Reset of a device with a pending expiration drops it too.
    let mem = guest_memory();
    let mut h = Harness::new(&mem, ALARM_NO_EVENT_IDX);
    h.set_alarm(0, 1, true);
    assert!(h.rtc.reset());
    assert!(next_pending_clock(&h.rtc).is_none());
}

fn next_pending_clock(rtc: &Rtc) -> Option<usize> {
    rtc.clocks
        .iter()
        .position(|clock| clock.alarm.is_some_and(|alarm| alarm.pending))
}

#[test]
fn event_idx_requests_are_answered_in_a_batch() {
    let mem = guest_memory();
    let mut h = Harness::new(&mem, WITH_ALARM);
    // Several requests are available before the device runs.
    let req = VirtioRtcReqRead {
        head: head(VIRTIO_RTC_REQ_READ),
        clock_id: 2.into(),
        ..Default::default()
    };
    for slot in 0..4 {
        submit_request(&mem, &h.requestq, slot, req.as_slice(), 16);
    }
    h.rtc.queue_event(REQUEST_QUEUE_IDX).write(1).unwrap();
    h.rtc.handle_request_event(&utils::epoll::EpollEvent::new(
        utils::epoll::EventSet::IN,
        0,
    ));
    assert_eq!(h.requestq.used.idx.get(), 4);
    assert!(h.interrupts() >= 1);
    for i in 0..4 {
        assert_eq!(h.requestq.used.ring[i].get().len, 16);
    }
}

#[test]
fn activation_registers_the_queues_and_the_timer_with_the_event_manager() {
    let mem = guest_memory();
    let h = Harness::new(&mem, ALARM_NO_EVENT_IDX);
    let timer_fd = std::os::fd::AsRawFd::as_raw_fd(&h.rtc.timer);
    let requestq_fd = std::os::fd::AsRawFd::as_raw_fd(&**h.rtc.queue_event(REQUEST_QUEUE_IDX));
    let alarmq_fd = std::os::fd::AsRawFd::as_raw_fd(&**h.rtc.queue_event(ALARM_QUEUE_IDX));

    // Move the activated device into the event manager.
    let Harness {
        rtc,
        requestq,
        alarmq,
        interrupts,
        ..
    } = h;
    let rtc = Arc::new(Mutex::new(rtc));
    let mut manager = EventManager::new().unwrap();
    manager.add_subscriber(rtc.clone()).unwrap();

    // The activation event registers the queue events.
    assert_eq!(manager.run_with_timeout(1000).unwrap(), 1);
    assert!(manager.subscriber(requestq_fd).is_ok());
    assert!(manager.subscriber(alarmq_fd).is_ok());
    assert!(manager.subscriber(timer_fd).is_ok());

    // A request that arrives through the event manager is answered.
    let req = VirtioRtcReqHead {
        msg_type: VIRTIO_RTC_REQ_CFG.into(),
        ..Default::default()
    };
    submit_request(&mem, &requestq, 0, req.as_slice(), 16);
    rtc.lock()
        .unwrap()
        .queue_event(REQUEST_QUEUE_IDX)
        .write(1)
        .unwrap();
    assert_eq!(manager.run_with_timeout(1000).unwrap(), 1);
    assert_eq!(requestq.used.idx.get(), 1);
    assert_eq!(interrupts.0.load(Ordering::SeqCst), 1);

    // An alarm that expires wakes the event manager through the timer.
    post_alarm_buffer(&mem, &alarmq, 0, size_of::<VirtioRtcNotifAlarm>() as u32);
    let set = VirtioRtcReqSetAlarm {
        head: head(VIRTIO_RTC_REQ_SET_ALARM),
        alarm_time: (now_ns() + 50_000_000).into(),
        clock_id: 0.into(),
        flags: VIRTIO_RTC_FLAG_ALARM_ENABLED,
        ..Default::default()
    };
    submit_request(&mem, &requestq, 1, set.as_slice(), 8);
    rtc.lock()
        .unwrap()
        .queue_event(REQUEST_QUEUE_IDX)
        .write(1)
        .unwrap();
    assert_eq!(manager.run_with_timeout(1000).unwrap(), 1);
    assert_eq!(alarmq.used.idx.get(), 0);

    let deadline = Instant::now() + Duration::from_secs(5);
    while alarmq.used.idx.get() == 0 && Instant::now() < deadline {
        manager.run_with_timeout(100).unwrap();
    }
    assert_eq!(alarmq.used.idx.get(), 1);
}
