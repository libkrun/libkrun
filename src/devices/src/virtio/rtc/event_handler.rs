// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use super::device::Rtc;
use super::protocol::{ALARM_QUEUE_IDX, REQUEST_QUEUE_IDX};
use super::timer::TimerEvent;
use crate::virtio::device::VirtioDevice;

impl Rtc {
    pub(crate) fn handle_request_event(&mut self, event: &EpollEvent) {
        debug!("rtc: request queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("rtc: request queue unexpected event {event_set:?}");
            return;
        }

        if let Err(e) = self.queue_event(REQUEST_QUEUE_IDX).read() {
            error!("Failed to read request queue event: {e:?}");
        } else if self.process_request_queue() {
            self.device_state.signal_used_queue();
        }
    }

    pub(crate) fn handle_alarm_queue_event(&mut self, event: &EpollEvent) {
        debug!("rtc: alarm queue event");

        let event_set = event.event_set();
        if event_set != EventSet::IN {
            warn!("rtc: alarm queue unexpected event {event_set:?}");
            return;
        }

        if let Err(e) = self.queue_event(ALARM_QUEUE_IDX).read() {
            error!("Failed to read alarm queue event: {e:?}");
        } else if self.deliver_alarms() {
            self.device_state.signal_used_queue();
        }
    }

    pub(crate) fn handle_timer_event(&mut self) {
        match self.timer.read() {
            Ok(Some(TimerEvent::Expired | TimerEvent::Canceled)) => {
                debug!("rtc: alarm timer event");
                // Always compare the alarms with the clock: an expiration and
                // a step of the realtime clock are handled the same way.
                if self.is_activated() {
                    self.update_alarms();
                    if self.deliver_alarms() {
                        self.device_state.signal_used_queue();
                    }
                }
            }
            Ok(None) => {}
            Err(e) => error!("Failed to read the alarm timer: {e}"),
        }
    }

    fn handle_activate_event(&self, event_manager: &mut EventManager) {
        debug!("rtc: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume rtc activate event: {e:?}");
        }

        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let self_subscriber = event_manager
            .subscriber(self.activate_evt.as_raw_fd())
            .unwrap();

        for (name, idx) in [("requestq", REQUEST_QUEUE_IDX), ("alarmq", ALARM_QUEUE_IDX)] {
            let fd = self.queue_event(idx).as_raw_fd();
            event_manager
                .register(
                    fd,
                    EpollEvent::new(EventSet::IN, fd as u64),
                    self_subscriber.clone(),
                )
                .unwrap_or_else(|e| {
                    error!("Failed to register rtc {name} with event manager: {e:?}");
                });
        }

        event_manager
            .unregister(self.activate_evt.as_raw_fd())
            .unwrap_or_else(|e| {
                error!("Failed to unregister rtc activate evt: {e:?}");
            })
    }
}

impl Subscriber for Rtc {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let activate_evt = self.activate_evt.as_raw_fd();
        let timer = self.timer.as_raw_fd();

        if source == timer {
            self.handle_timer_event();
        } else if source == activate_evt {
            self.handle_activate_event(event_manager);
        } else if self.is_activated() {
            let requestq = self.queue_event(REQUEST_QUEUE_IDX).as_raw_fd();
            let alarmq = self.queue_event(ALARM_QUEUE_IDX).as_raw_fd();
            if source == requestq {
                self.handle_request_event(event);
            } else if source == alarmq {
                self.handle_alarm_queue_event(event);
            } else {
                warn!("Unexpected rtc event received: {source:?}")
            }
        } else {
            warn!("rtc: The device is not yet activated. Spurious event received: {source:?}");
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![
            EpollEvent::new(EventSet::IN, self.activate_evt.as_raw_fd() as u64),
            EpollEvent::new(EventSet::IN, self.timer.as_raw_fd() as u64),
        ]
    }
}
