// Copyright 2019 The ChromiumOS Authors
// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! 8254 Programmable Interval Timer (PIT) implementation directly ported from crosvm
//! https://github.com/google/crosvm/blob/main/devices/src/pit.rs

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use log::{error, warn};
use utils::eventfd::EventFd;

use crate::bus::BusDevice;

const FREQUENCY_HZ: u64 = 1_193_182;
const NANOS_PER_SEC: u64 = 1_000_000_000;
const MAX_TIMER_FREQ: u32 = 65_536;
const NUM_OF_COUNTERS: usize = 3;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandAccess {
    CommandLatch = 0x00,
    CommandRWLeast = 0x10,
    CommandRWMost = 0x20,
    CommandRWBoth = 0x30,
}

impl CommandAccess {
    fn from_u8(val: u8) -> Option<Self> {
        match val & 0x30 {
            0x00 => Some(CommandAccess::CommandLatch),
            0x10 => Some(CommandAccess::CommandRWLeast),
            0x20 => Some(CommandAccess::CommandRWMost),
            0x30 => Some(CommandAccess::CommandRWBoth),
            _ => None,
        }
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandMode {
    CommandInterrupt = 0x00,
    CommandHWOneShot = 0x02,
    CommandRateGen = 0x04,
    CommandSquareWaveGen = 0x06,
    CommandSWStrobe = 0x08,
    CommandHWStrobe = 0x0a,
}

impl CommandMode {
    fn from_u8(val: u8) -> Option<Self> {
        let mode = val & 0x0e;
        match mode {
            0x00 => Some(CommandMode::CommandInterrupt),
            0x02 => Some(CommandMode::CommandHWOneShot),
            0x04 => Some(CommandMode::CommandRateGen),
            0x06 => Some(CommandMode::CommandSquareWaveGen),
            0x08 => Some(CommandMode::CommandSWStrobe),
            0x0a => Some(CommandMode::CommandHWStrobe),
            _ => None,
        }
    }
}

fn adjust_count(count: u32) -> u32 {
    if count == 0 { MAX_TIMER_FREQ } else { count }
}

struct PitCounter {
    counter_id: usize,
    interrupt_evt: Option<EventFd>,
    reload_value: u16,
    latched_value: u16,
    command: u8,
    status: u8,
    start: Option<Instant>,
    creation_time: Instant,
    wrote_low_byte: bool,
    read_low_byte: bool,
    latched: bool,
    status_latched: bool,
    gate: bool,
    speaker_on: bool,
    count: u32,
    timer_valid: bool,
}

impl PitCounter {
    fn new(counter_id: usize, interrupt_evt: Option<EventFd>) -> Self {
        let now = Instant::now();
        PitCounter {
            counter_id,
            interrupt_evt,
            reload_value: 0,
            latched_value: 0,
            command: 0,
            status: 0,
            start: None,
            creation_time: now,
            wrote_low_byte: false,
            read_low_byte: false,
            latched: false,
            status_latched: false,
            gate: counter_id != 2, // Channels 0 and 1 start gated high; Channel 2 uses speaker gate
            speaker_on: false,
            count: MAX_TIMER_FREQ,
            timer_valid: false,
        }
    }

    fn get_access_mode(&self) -> Option<CommandAccess> {
        CommandAccess::from_u8(self.command)
    }

    fn get_command_mode(&self) -> Option<CommandMode> {
        CommandMode::from_u8(self.command)
    }

    fn get_ticks_passed(&self) -> u64 {
        match self.start {
            None => 0,
            Some(t) => {
                let dur = t.elapsed();
                let dur_ns: u64 = dur.as_secs() * NANOS_PER_SEC + u64::from(dur.subsec_nanos());
                dur_ns * FREQUENCY_HZ / NANOS_PER_SEC
            }
        }
    }

    fn get_read_value(&self) -> u16 {
        match self.start {
            None => 0,
            Some(_) => {
                let count: u64 = adjust_count(self.reload_value.into()).into();
                let ticks_passed = self.get_ticks_passed();
                match self.get_command_mode() {
                    Some(CommandMode::CommandInterrupt)
                    | Some(CommandMode::CommandHWOneShot)
                    | Some(CommandMode::CommandSWStrobe)
                    | Some(CommandMode::CommandHWStrobe) => {
                        if ticks_passed > count {
                            0
                        } else {
                            ((count - ticks_passed) & 0xffff) as u16
                        }
                    }
                    Some(CommandMode::CommandRateGen) => (count - (ticks_passed % count)) as u16,
                    Some(CommandMode::CommandSquareWaveGen) => {
                        (count - ((ticks_passed * 2) % count)) as u16
                    }
                    None => {
                        warn!("Invalid command mode: command = {:#x}", self.command);
                        0
                    }
                }
            }
        }
    }

    fn read_counter(&mut self) -> u8 {
        if self.status_latched {
            self.status_latched = false;
            return self.status;
        }

        let data_value: u16 = if self.latched {
            self.latched_value
        } else {
            self.get_read_value()
        };

        let access_mode = self.get_access_mode();
        match (access_mode, self.read_low_byte) {
            (Some(CommandAccess::CommandRWLeast), _) => {
                self.latched = false;
                (data_value & 0xff) as u8
            }
            (Some(CommandAccess::CommandRWBoth), false) => {
                self.read_low_byte = true;
                (data_value & 0xff) as u8
            }
            (Some(CommandAccess::CommandRWBoth), true)
            | (Some(CommandAccess::CommandRWMost), _) => {
                self.read_low_byte = false;
                self.latched = false;
                (data_value >> 8) as u8
            }
            (_, _) => 0,
        }
    }

    fn write_counter(&mut self, written_datum: u8) {
        let access_mode = self.get_access_mode();
        let datum: u16 = written_datum.into();
        let mut should_start_timer = true;

        self.reload_value = match access_mode {
            Some(CommandAccess::CommandRWLeast) => datum,
            Some(CommandAccess::CommandRWMost) => datum << 8,
            Some(CommandAccess::CommandRWBoth) => {
                if self.wrote_low_byte {
                    self.wrote_low_byte = false;
                    self.reload_value | (datum << 8)
                } else {
                    self.wrote_low_byte = true;
                    should_start_timer = false;
                    datum
                }
            }
            _ => {
                should_start_timer = false;
                self.reload_value
            }
        };

        if should_start_timer {
            let reload: u32 = self.reload_value.into();
            self.load_and_start_timer(reload);
        }
    }

    fn load_and_start_timer(&mut self, initial_count: u32) {
        self.count = adjust_count(initial_count);
        self.start = Some(Instant::now());
        self.timer_valid = true;
    }

    fn latch_counter(&mut self) {
        if self.latched {
            return;
        }
        self.latched_value = self.get_read_value();
        self.latched = true;
        self.read_low_byte = false;
    }

    fn latch_status(&mut self) {
        self.status = self.command & 0x3f;
        if self.start.is_none() {
            self.status |= 0x40; // Null count bit
        }
        if self.get_output() {
            self.status |= 0x80; // Output pin status bit
        }
        self.status_latched = true;
    }

    fn get_output(&self) -> bool {
        let ticks_passed = self.get_ticks_passed();
        let count: u64 = self.count.into();
        match self.get_command_mode() {
            Some(CommandMode::CommandInterrupt) => ticks_passed >= count,
            Some(CommandMode::CommandHWOneShot) => ticks_passed < count,
            Some(CommandMode::CommandRateGen) => {
                ticks_passed != 0 && ticks_passed.is_multiple_of(count)
            }
            Some(CommandMode::CommandSquareWaveGen) => ticks_passed < count.div_ceil(2),
            Some(CommandMode::CommandSWStrobe) | Some(CommandMode::CommandHWStrobe) => {
                ticks_passed == count
            }
            None => false,
        }
    }

    fn store_command(&mut self, datum: u8) {
        self.command = datum;
        self.latched = false;
        if self.timer_valid {
            self.start = None;
            self.timer_valid = false;
        }
        self.wrote_low_byte = false;
        self.read_low_byte = false;
    }

    fn read_speaker(&self) -> u8 {
        let us = self.creation_time.elapsed().subsec_micros();
        let refresh_clock = (us / 15).is_multiple_of(2);
        let mut speaker: u8 = 0;

        if self.gate {
            speaker |= 0x01;
        }
        if self.speaker_on {
            speaker |= 0x02;
        }
        if refresh_clock {
            speaker |= 0x10;
        }
        if self.get_output() {
            speaker |= 0x20;
        }

        speaker
    }

    fn write_speaker(&mut self, datum: u8) {
        let new_gate = (datum & 0x01) != 0;
        if let Some(mode) = self.get_command_mode()
            && !matches!(
                mode,
                CommandMode::CommandInterrupt | CommandMode::CommandSWStrobe
            )
            && new_gate
            && !self.gate
        {
            self.start = Some(Instant::now());
        }
        self.speaker_on = (datum & 0x02) != 0;
        self.gate = new_gate;
    }

    fn next_interrupt_delay(&self) -> Option<Duration> {
        if self.counter_id != 0 || !self.timer_valid {
            return None;
        }

        let count: u64 = self.count.into();
        let ticks_passed = self.get_ticks_passed();

        let remaining_ticks = match self.get_command_mode() {
            Some(CommandMode::CommandInterrupt)
            | Some(CommandMode::CommandHWOneShot)
            | Some(CommandMode::CommandSWStrobe)
            | Some(CommandMode::CommandHWStrobe) => {
                if ticks_passed >= count {
                    return None;
                }
                count - ticks_passed
            }
            Some(CommandMode::CommandRateGen) | Some(CommandMode::CommandSquareWaveGen) => {
                count - (ticks_passed % count)
            }
            None => return None,
        };

        let nanos = (remaining_ticks * NANOS_PER_SEC).div_ceil(FREQUENCY_HZ);
        Some(Duration::from_nanos(nanos))
    }
}

pub struct Pit {
    counters: Vec<Arc<Mutex<PitCounter>>>,
    stop_worker: Arc<AtomicBool>,
    worker_thread: Option<JoinHandle<()>>,
}

impl Pit {
    pub fn new(interrupt_evt: EventFd) -> Self {
        let mut counters = Vec::with_capacity(NUM_OF_COUNTERS);
        let mut evt = Some(interrupt_evt);

        for i in 0..NUM_OF_COUNTERS {
            counters.push(Arc::new(Mutex::new(PitCounter::new(i, evt.take()))));
        }

        let stop_worker = Arc::new(AtomicBool::new(false));
        let worker_stop = stop_worker.clone();
        let counter_0 = counters[0].clone();

        let worker_thread = thread::Builder::new()
            .name("pit_worker".to_string())
            .spawn(move || Self::run_worker(counter_0, worker_stop))
            .ok();

        Pit {
            counters,
            stop_worker,
            worker_thread,
        }
    }

    fn run_worker(counter_0: Arc<Mutex<PitCounter>>, stop: Arc<AtomicBool>) {
        while !stop.load(Ordering::Relaxed) {
            let delay = {
                let counter = counter_0.lock().unwrap();
                counter.next_interrupt_delay()
            };

            match delay {
                Some(dur) if dur > Duration::from_millis(0) => {
                    thread::sleep(dur.min(Duration::from_millis(10)));
                }
                Some(_) => {
                    let mut counter = counter_0.lock().unwrap();
                    if let Some(evt) = &counter.interrupt_evt
                        && let Err(e) = evt.write(1)
                    {
                        error!("PIT IRQ0 trigger failed: {e}");
                    }
                    if matches!(
                        counter.get_command_mode(),
                        Some(CommandMode::CommandInterrupt)
                    ) {
                        counter.timer_valid = false;
                    }
                }
                None => {
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    fn command_write(&mut self, control_word: u8) {
        let command = (control_word & 0xc0) >> 6;
        if command == 3 {
            // ReadBack Command
            let latch_count = (control_word & 0x20) == 0;
            let latch_status = (control_word & 0x10) == 0;

            for i in 0..3 {
                if (control_word & (1 << (i + 1))) != 0 {
                    let mut ch = self.counters[i].lock().unwrap();
                    if latch_count {
                        ch.latch_counter();
                    }
                    if latch_status {
                        ch.latch_status();
                    }
                }
            }
        } else {
            let counter_idx = command as usize;
            let access = (control_word & 0x30) >> 4;
            let mut ch = self.counters[counter_idx].lock().unwrap();

            if access == 0 {
                ch.latch_counter();
            } else {
                ch.store_command(control_word);
            }
        }
    }

    /// Exposed for the hypervisor to wire up Port 0x61 (PC Speaker / NMI Control)
    pub fn read_speaker_port(&self) -> u8 {
        self.counters[2].lock().unwrap().read_speaker()
    }

    /// Exposed for the hypervisor to wire up Port 0x61 (PC Speaker / NMI Control)
    pub fn write_speaker_port(&self, val: u8) {
        self.counters[2].lock().unwrap().write_speaker(val)
    }
}

impl BusDevice for Pit {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }

        // 'offset' is relative to the base address (e.g., 0x40).
        // 0 = Counter 0, 1 = Counter 1, 2 = Counter 2, 3 = Command Word
        match offset {
            0..=2 => {
                data[0] = self.counters[offset as usize]
                    .lock()
                    .unwrap()
                    .read_counter()
            }
            3 => data[0] = 0, // Command port reads are no-ops on 8254
            _ => {}
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            return;
        }

        match offset {
            0..=2 => self.counters[offset as usize]
                .lock()
                .unwrap()
                .write_counter(data[0]),
            3 => self.command_write(data[0]),
            _ => {}
        }
    }
}

impl Drop for Pit {
    fn drop(&mut self) {
        self.stop_worker.store(true, Ordering::Relaxed);
        if let Some(handle) = self.worker_thread.take() {
            let _ = handle.join();
        }
    }
}
