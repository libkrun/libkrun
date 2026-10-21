// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// The request handling is derived from vhost-device-rtc
// (https://github.com/rust-vmm/vhost-device, tag vhost-device-media-v0.1.1),
// which is available under Apache-2.0 or BSD-3-Clause and is used here
// under Apache-2.0:
// Copyright 2026 Panasonic Automotive Systems Co., Ltd.
// Author: Manos Pitsidianakis <manos.pitsidianakis@linaro.org>

use std::io::Write;
use std::mem::size_of;

use utils::eventfd::{EFD_NONBLOCK, EventFd};
use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::clocks::{Alarm, Clock};
use super::protocol::*;
use super::timer::AlarmTimer;
use super::{RtcError, defs};
use crate::virtio::descriptor_utils::{Reader, Writer};
use crate::virtio::{
    ActivateError, ActivateResult, DescriptorChain, DeviceQueue, DeviceState, InterruptTransport,
    QueueConfig, VirtioDevice,
};

/// The features that the device offers.
///
/// `VIRTIO_RING_F_INDIRECT_DESC` is deliberately not offered: libkrun's
/// `Queue` does not implement indirect descriptor tables.
pub(crate) const AVAIL_FEATURES: u64 =
    (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_RING_F_EVENT_IDX) | (1 << VIRTIO_RTC_F_ALARM);

/// How often the alarms are evaluated again if the realtime clock is set
/// while the timer is being armed.
const MAX_ARM_ATTEMPTS: usize = 8;

pub struct Rtc {
    pub(crate) queues: Option<Vec<DeviceQueue>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
    pub(crate) clocks: Vec<Clock>,
    pub(crate) timer: AlarmTimer,
}

/// The reply to a request.
struct Response {
    /// The complete response, including the response header.
    bytes: Vec<u8>,
    /// The request changed an alarm.
    alarms_changed: bool,
}

impl Response {
    fn new<T: ByteValued>(response: T) -> Self {
        Self {
            bytes: response.as_slice().to_vec(),
            alarms_changed: false,
        }
    }

    fn alarms_changed(mut self) -> Self {
        self.alarms_changed = true;
        self
    }
}

/// Reads a request from the start of the device-readable buffer. A buffer
/// that is too small for the request makes the request invalid.
fn read_request<T: ByteValued>(reader: &Reader) -> Result<T, u8> {
    reader.clone().read_obj().map_err(|_| VIRTIO_RTC_S_EINVAL)
}

/// The response has to fit into the device-writable buffer.
fn check_fits<T>(avail: usize) -> Result<(), u8> {
    if avail < size_of::<T>() {
        return Err(VIRTIO_RTC_S_EINVAL);
    }
    Ok(())
}

fn clock_by_id(clocks: &mut [Clock], clock_id: u16) -> Result<&mut Clock, u8> {
    clocks
        .get_mut(usize::from(clock_id))
        .ok_or(VIRTIO_RTC_S_ENODEV)
}

/// The alarm messages are only supported if the alarm feature was
/// negotiated, and only for clocks that have an alarm.
fn alarm_by_clock_id(
    clocks: &mut [Clock],
    have_alarm: bool,
    clock_id: u16,
) -> Result<&mut Alarm, u8> {
    if !have_alarm {
        return Err(VIRTIO_RTC_S_ENODEV);
    }
    clock_by_id(clocks, clock_id)?
        .alarm
        .as_mut()
        .ok_or(VIRTIO_RTC_S_ENODEV)
}

fn known_hw_counter(hw_counter: u8) -> Result<(), u8> {
    match hw_counter {
        VIRTIO_RTC_COUNTER_ARM_VCT | VIRTIO_RTC_COUNTER_X86_TSC => Ok(()),
        _ => Err(VIRTIO_RTC_S_EOPNOTSUPP),
    }
}

/// Executes a request. `Err` carries the status of a failed request.
fn dispatch(
    clocks: &mut [Clock],
    have_alarm: bool,
    reader: &Reader,
    avail: usize,
) -> Result<Response, u8> {
    let head: VirtioRtcReqHead = read_request(reader)?;
    match u16::from(head.msg_type) {
        VIRTIO_RTC_REQ_CFG => {
            check_fits::<VirtioRtcRespCfg>(avail)?;
            Ok(Response::new(VirtioRtcRespCfg {
                num_clocks: (clocks.len() as u16).into(),
                ..Default::default()
            }))
        }
        VIRTIO_RTC_REQ_CLOCK_CAP => {
            let req: VirtioRtcReqClockCap = read_request(reader)?;
            check_fits::<VirtioRtcRespClockCap>(avail)?;
            let clock = clock_by_id(clocks, req.clock_id.into())?;
            let alarm_cap = have_alarm && clock.alarm.is_some();
            Ok(Response::new(VirtioRtcRespClockCap {
                r#type: clock.clock_type,
                leap_second_smearing: clock.leap_second_smearing,
                flags: if alarm_cap {
                    VIRTIO_RTC_FLAG_ALARM_CAP
                } else {
                    0
                },
                ..Default::default()
            }))
        }
        VIRTIO_RTC_REQ_READ => {
            let req: VirtioRtcReqRead = read_request(reader)?;
            check_fits::<VirtioRtcRespRead>(avail)?;
            let clock = clock_by_id(clocks, req.clock_id.into())?;
            let clock_reading = clock.read().map_err(|e| {
                error!("rtc: cannot read clock: {e}");
                VIRTIO_RTC_S_EIO
            })?;
            Ok(Response::new(VirtioRtcRespRead {
                clock_reading: clock_reading.into(),
                ..Default::default()
            }))
        }
        // Cross-timestamping is not supported: no clock reports the
        // capability, and reading a cross-timestamp fails.
        VIRTIO_RTC_REQ_CROSS_CAP => {
            let req: VirtioRtcReqCrossCap = read_request(reader)?;
            check_fits::<VirtioRtcRespCrossCap>(avail)?;
            clock_by_id(clocks, req.clock_id.into())?;
            known_hw_counter(req.hw_counter)?;
            Ok(Response::new(VirtioRtcRespCrossCap::default()))
        }
        VIRTIO_RTC_REQ_READ_CROSS => {
            let req: VirtioRtcReqReadCross = read_request(reader)?;
            check_fits::<VirtioRtcRespReadCross>(avail)?;
            clock_by_id(clocks, req.clock_id.into())?;
            known_hw_counter(req.hw_counter)?;
            Err(VIRTIO_RTC_S_EOPNOTSUPP)
        }
        VIRTIO_RTC_REQ_READ_ALARM => {
            let req: VirtioRtcReqReadAlarm = read_request(reader)?;
            check_fits::<VirtioRtcRespReadAlarm>(avail)?;
            let alarm = alarm_by_clock_id(clocks, have_alarm, req.clock_id.into())?;
            Ok(Response::new(VirtioRtcRespReadAlarm {
                alarm_time: alarm.time.into(),
                flags: if alarm.enabled {
                    VIRTIO_RTC_FLAG_ALARM_ENABLED
                } else {
                    0
                },
                ..Default::default()
            }))
        }
        VIRTIO_RTC_REQ_SET_ALARM => {
            let req: VirtioRtcReqSetAlarm = read_request(reader)?;
            check_fits::<VirtioRtcRespSetAlarm>(avail)?;
            let alarm = alarm_by_clock_id(clocks, have_alarm, req.clock_id.into())?;
            // Setting the alarm time makes a previous expiration obsolete.
            *alarm = Alarm {
                time: req.alarm_time.into(),
                enabled: req.flags & VIRTIO_RTC_FLAG_ALARM_ENABLED != 0,
                ..Alarm::default()
            };
            Ok(Response::new(VirtioRtcRespSetAlarm::default()).alarms_changed())
        }
        VIRTIO_RTC_REQ_SET_ALARM_ENABLED => {
            let req: VirtioRtcReqSetAlarmEnabled = read_request(reader)?;
            check_fits::<VirtioRtcRespSetAlarmEnabled>(avail)?;
            let alarm = alarm_by_clock_id(clocks, have_alarm, req.clock_id.into())?;
            // Enabling or disabling makes a previous expiration obsolete.
            *alarm = Alarm {
                time: alarm.time,
                enabled: req.flags & VIRTIO_RTC_FLAG_ALARM_ENABLED != 0,
                ..Alarm::default()
            };
            Ok(Response::new(VirtioRtcRespSetAlarmEnabled::default()).alarms_changed())
        }
        _ => Err(VIRTIO_RTC_S_EOPNOTSUPP),
    }
}

/// Writes the response header with `status`, as far as it fits. Nothing is
/// written if not even the status field fits.
fn write_status(writer: &mut Writer, status: u8) {
    let head = VirtioRtcRespHead {
        status,
        ..Default::default()
    };
    let len = head.as_slice().len().min(writer.available_bytes());
    if let Err(e) = writer.write_all(&head.as_slice()[..len]) {
        error!("rtc: cannot write the response status: {e}");
    }
}

/// Handles one request. Returns the number of bytes written to the
/// device-writable buffer and whether an alarm changed.
fn handle_request(
    clocks: &mut [Clock],
    have_alarm: bool,
    mem: &GuestMemoryMmap,
    head: DescriptorChain<'_>,
) -> (u32, bool) {
    let (reader, mut writer) = match (Reader::new(mem, head.clone()), Writer::new(mem, head)) {
        (Ok(reader), Ok(writer)) => (reader, writer),
        (Err(e), _) | (_, Err(e)) => {
            error!("rtc: invalid descriptor chain: {e:?}");
            return (0, false);
        }
    };

    let mut alarms_changed = false;
    match dispatch(clocks, have_alarm, &reader, writer.available_bytes()) {
        Ok(response) => {
            alarms_changed = response.alarms_changed;
            if let Err(e) = writer.write_all(&response.bytes) {
                error!("rtc: cannot write the response: {e}");
            }
        }
        Err(status) => write_status(&mut writer, status),
    }
    (writer.bytes_written() as u32, alarms_changed)
}

/// Index of the first clock with an expiration that was not yet reported.
fn next_pending(clocks: &[Clock]) -> Option<usize> {
    clocks
        .iter()
        .position(|clock| clock.alarm.is_some_and(|alarm| alarm.pending))
}

/// Writes an alarm notification for `clock_id` into an alarmq buffer.
fn write_alarm_notification(
    mem: &GuestMemoryMmap,
    head: DescriptorChain<'_>,
    clock_id: usize,
) -> Result<u32, ()> {
    let mut writer = Writer::new(mem, head).map_err(|e| {
        error!("rtc: invalid alarmq descriptor chain: {e:?}");
    })?;
    if writer.available_bytes() < size_of::<VirtioRtcNotifAlarm>() {
        error!("rtc: alarmq buffer is too small for a notification");
        return Err(());
    }
    let notification = VirtioRtcNotifAlarm {
        head: VirtioRtcNotifHead {
            msg_type: VIRTIO_RTC_NOTIF_ALARM.into(),
            ..Default::default()
        },
        clock_id: (clock_id as u16).into(),
        ..Default::default()
    };
    writer.write_obj(notification).map_err(|e| {
        error!("rtc: cannot write the alarm notification: {e}");
    })?;
    Ok(writer.bytes_written() as u32)
}

impl Rtc {
    pub fn new() -> super::Result<Rtc> {
        let mut clocks = vec![Clock::new_utc().map_err(RtcError::Clock)?];
        for clock in [Clock::new_tai(), Clock::new_monotonic()] {
            match clock {
                Ok(clock) => clocks.push(clock),
                Err(e) => warn!("rtc: clock is not available: {e}"),
            }
        }

        Ok(Rtc {
            queues: None,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(EFD_NONBLOCK).map_err(RtcError::EventFd)?,
            device_state: DeviceState::Inactive,
            clocks,
            timer: AlarmTimer::new().map_err(RtcError::Timer)?,
        })
    }

    pub fn id(&self) -> &str {
        defs::RTC_DEV_ID
    }

    pub(crate) fn queue_event(&self, idx: usize) -> &std::sync::Arc<EventFd> {
        &self.queues.as_ref().expect("queues should exist")[idx].event
    }

    pub(crate) fn have_alarm(&self) -> bool {
        self.acked_features & (1 << VIRTIO_RTC_F_ALARM) != 0
    }

    /// Answers the requests in the request queue. Returns whether the guest
    /// has to be signaled.
    pub(crate) fn process_request_queue(&mut self) -> bool {
        let DeviceState::Activated(mem, _) = &self.device_state else {
            return false;
        };
        let mem = mem.clone();
        let have_alarm = self.have_alarm();
        let queue = &mut self
            .queues
            .as_mut()
            .expect("queues should exist when activated")[REQUEST_QUEUE_IDX]
            .queue;

        let mut used = false;
        let mut alarms_changed = false;
        loop {
            if let Err(e) = queue.disable_notification(&mem) {
                error!("rtc: cannot disable request queue notifications: {e:?}");
            }

            let mut processed = false;
            while let Some(head) = queue.pop(&mem) {
                let index = head.index;
                let (len, changed) = handle_request(&mut self.clocks, have_alarm, &mem, head);
                alarms_changed |= changed;
                if let Err(e) = queue.add_used(&mem, index, len) {
                    error!("rtc: failed to add used elements to the queue: {e:?}");
                }
                processed = true;
                used = true;
            }

            // Always re-enable notifications. A queue that cannot be
            // processed, but is not empty, must not make this loop spin.
            let more = queue.enable_notification(&mem).unwrap_or(false);
            if !more || !processed {
                break;
            }
        }
        let mut signal = used && queue.needs_notification(&mem).unwrap_or(true);

        if alarms_changed {
            self.update_alarms();
            signal |= self.deliver_alarms();
        }
        signal
    }

    /// Compares the alarms with their clocks, records expirations, and arms
    /// the timer for the next event.
    ///
    /// The timer is armed for the earliest alarm that did not yet expire. If
    /// all enabled alarms expired, it is armed for a time far in the future
    /// so that setting the clock is still noticed: a clock that steps back
    /// to before an alarm time lets the alarm expire again.
    pub(crate) fn update_alarms(&mut self) {
        for _ in 0..MAX_ARM_ATTEMPTS {
            let mut earliest: Option<u64> = None;
            let mut watch_clock_steps = false;

            for (clock_id, clock) in self.clocks.iter_mut().enumerate() {
                if !clock.alarm.is_some_and(|alarm| alarm.enabled) {
                    continue;
                }
                let now = match clock.read() {
                    Ok(now) => now,
                    Err(e) => {
                        error!("rtc: cannot read clock {clock_id}: {e}");
                        continue;
                    }
                };
                let Some(alarm) = clock.alarm.as_mut() else {
                    continue;
                };

                if alarm.time <= now {
                    if !alarm.fired {
                        alarm.fired = true;
                        alarm.pending = true;
                    }
                    watch_clock_steps = true;
                } else {
                    // The clock is before the alarm time (again): an
                    // earlier expiration is obsolete.
                    alarm.fired = false;
                    alarm.pending = false;
                    earliest = Some(earliest.map_or(alarm.time, |t| t.min(alarm.time)));
                }
            }

            let target = earliest.or(watch_clock_steps.then_some(u64::MAX));
            let Some(target) = target else {
                if let Err(e) = self.timer.disarm() {
                    error!("rtc: cannot disarm the alarm timer: {e}");
                }
                return;
            };
            match self.timer.arm(target) {
                Ok(()) => return,
                // The realtime clock was set while arming: evaluate again.
                Err(e) if e.raw_os_error() == Some(libc::ECANCELED) => continue,
                Err(e) => {
                    error!("rtc: cannot arm the alarm timer: {e}");
                    return;
                }
            }
        }
        warn!("rtc: the realtime clock keeps changing, alarm timer not armed");
    }

    /// Reports expired alarms through the alarm queue, as far as the driver
    /// provided buffers. Returns whether the guest has to be signaled.
    pub(crate) fn deliver_alarms(&mut self) -> bool {
        if !self.have_alarm() {
            return false;
        }
        let DeviceState::Activated(mem, _) = &self.device_state else {
            return false;
        };
        let mem = mem.clone();
        let queue = &mut self
            .queues
            .as_mut()
            .expect("queues should exist when activated")[ALARM_QUEUE_IDX]
            .queue;

        let mut used = false;
        let mut retried = false;
        while let Some(clock_id) = next_pending(&self.clocks) {
            let Some(head) = queue.pop(&mem) else {
                // No buffer. Ask the driver to notify us when it adds one.
                // Retry once in case it added one in the meantime.
                match queue.enable_notification(&mem) {
                    Ok(true) if !retried => {
                        retried = true;
                        continue;
                    }
                    _ => break,
                }
            };
            retried = false;

            let index = head.index;
            let len = match write_alarm_notification(&mem, head, clock_id) {
                Ok(len) => {
                    if let Some(alarm) = self.clocks[clock_id].alarm.as_mut() {
                        alarm.pending = false;
                    }
                    len
                }
                // The buffer is unusable. Give it back and use the next one.
                Err(()) => 0,
            };
            if let Err(e) = queue.add_used(&mem, index, len) {
                error!("rtc: failed to add used elements to the alarm queue: {e:?}");
            }
            used = true;
        }
        used && queue.needs_notification(&mem).unwrap_or(true)
    }
}

impl VirtioDevice for Rtc {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        defs::uapi::VIRTIO_ID_CLOCK
    }

    fn device_name(&self) -> &str {
        "rtc"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn config_len(&self) -> Option<u32> {
        Some(0)
    }

    fn read_config(&self, _offset: u64, _data: &mut [u8]) {
        error!("rtc: invalid request to read config space");
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "rtc: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if queues.len() != NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt");
            return Err(ActivateError::BadActivate);
        }

        self.queues = Some(queues);
        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        if let Some(queues) = self.queues.take() {
            for queue in queues {
                while queue.event.read().is_ok() {}
            }
        }
        while self.activate_evt.read().is_ok() {}

        // The alarm time is 0 and the alarm is disabled after a reset.
        for clock in &mut self.clocks {
            if clock.alarm.is_some() {
                clock.alarm = Some(Alarm::default());
            }
        }
        if let Err(e) = self.timer.disarm() {
            error!("rtc: cannot disarm the alarm timer: {e}");
        }
        // Drop an event that was already pending.
        let _ = self.timer.read();

        self.acked_features = 0;
        self.device_state = DeviceState::Inactive;
        true
    }
}
