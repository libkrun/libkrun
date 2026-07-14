// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::sync::Arc;

use super::{ActivateResult, InterruptTransport, Queue};
use crate::virtio::AsAny;
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

/// Configuration for a single virtqueue.
/// This is used by devices to declare their queue requirements,
/// and by the transport to construct the actual queues.
#[derive(Clone, Copy, Debug)]
pub struct QueueConfig {
    /// Maximum size of the queue.
    pub size: u16,
}

impl QueueConfig {
    pub const fn new(size: u16) -> Self {
        Self { size }
    }
}

/// A virtqueue combined with its notification eventfd.
/// This is passed to devices during activation.
pub struct DeviceQueue {
    pub queue: Queue,
    pub event: Arc<EventFd>,
}

impl DeviceQueue {
    pub fn new(queue: Queue, event: Arc<EventFd>) -> Self {
        Self { queue, event }
    }
}

/// Enum that indicates if a VirtioDevice is inactive or has been activated
/// and memory attached to it.
pub enum DeviceState {
    Inactive,
    Activated(GuestMemoryMmap, InterruptTransport),
}

impl DeviceState {
    pub fn signal_used_queue(&self) {
        match self {
            Self::Inactive => {
                warn!("DeviceState::signal_used_queue() called, but device is not activated")
            }
            Self::Activated(_, interrupt) => interrupt.signal_used_queue(),
        }
    }
}

impl DeviceState {
    pub fn is_activated(&self) -> bool {
        matches!(self, DeviceState::Activated(..))
    }
}

#[derive(Clone)]
pub struct VirtioShmRegion {
    pub host_addr: u64,
    pub guest_addr: u64,
    pub size: usize,
}

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. The transport constructs queues based on queue_config() and passes them to the device
/// during activation, transferring ownership. After reset, the transport recreates queues
/// from queue_config() for the next negotiation cycle.
pub trait VirtioDevice: AsAny + Send {
    /// Get the available features offered by device.
    fn avail_features(&self) -> u64;

    /// Get acknowledged features of the driver.
    fn acked_features(&self) -> u64;

    /// Set acknowledged features of the driver.
    /// This function must maintain the following invariant:
    /// - self.avail_features() & self.acked_features() = self.get_acked_features()
    fn set_acked_features(&mut self, acked_features: u64);

    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// Device name used for logging information about the device at the transport layer
    fn device_name(&self) -> &str;

    /// Returns the queue configuration for this device.
    /// The transport uses this to construct the queues during initialization and after reset.
    fn queue_config(&self) -> &[QueueConfig];

    /// The set of feature bits shifted by `page * 32`.
    fn avail_features_by_page(&self, page: u32) -> u32 {
        let avail_features = self.avail_features();
        match page {
            // Get the lower 32-bits of the features bitfield.
            0 => avail_features as u32,
            // Get the upper 32-bits of the features bitfield.
            1 => (avail_features >> 32) as u32,
            _ => {
                warn!("Received request for unknown features page.");
                0u32
            }
        }
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features_by_page(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => u64::from(value),
            1 => u64::from(value) << 32,
            _ => {
                warn!("Cannot acknowledge unknown features page: {page}");
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let avail_features = self.avail_features();
        let unrequested_features = v & !avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature: {v:x}");
            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.set_acked_features(self.acked_features() | v);
    }

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, offset: u64, data: &[u8]);

    /// Performs the formal activation for a device, which can be verified also with `is_activated`.
    /// Ownership of the queues is transferred to the device.
    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult;

    /// Checks if the resources of this device are activated.
    fn is_activated(&self) -> bool;

    /// Optionally deactivates this device. The device should drop its queues.
    /// After reset, the transport will recreate queues from queue_config().
    fn reset(&mut self) -> bool {
        false
    }

    /// Get base and size of the SHM region
    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        None
    }

    /// Stop this device's workers and hand its live queues back for snapshot.
    /// The workers own the running queue indices, so the transport cannot read
    /// them until they stop. Must not drain in-flight work — a worker blocked on
    /// a stalled host fd would deadlock; stop at a descriptor boundary. The
    /// default rejects the snapshot.
    fn pause(&mut self) -> std::result::Result<Vec<DeviceQueue>, PauseError> {
        Err(PauseError::Unsupported(self.device_name().to_string()))
    }

    /// Device state beyond the queues (e.g. the console's open ports, which a
    /// restored guest won't re-announce). Captured after [`VirtioDevice::pause`].
    fn save_state(&self) -> Vec<u8> {
        Vec::new()
    }

    /// Load what [`VirtioDevice::save_state`] wrote, before [`VirtioDevice::resume`].
    fn restore_state(&mut self, _state: &[u8]) -> std::result::Result<(), crate::Error> {
        Ok(())
    }

    /// Restart this device with `queues`, in place of [`VirtioDevice::activate`].
    /// The default re-activates; override when resume differs from a fresh
    /// activation (the console restarts only the ports the guest had open).
    fn resume(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        self.activate(mem, interrupt, queues)
    }
}

/// Why a device could not be quiesced for a snapshot.
#[derive(Debug)]
pub enum PauseError {
    /// The device has no quiesce support, so it cannot be snapshotted.
    Unsupported(String),
    /// The device tried to stop its workers and failed.
    Failed(String),
}

impl std::fmt::Display for PauseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PauseError::Unsupported(name) => {
                write!(f, "device {name} does not support snapshot quiesce")
            }
            PauseError::Failed(e) => write!(f, "device quiesce failed: {e}"),
        }
    }
}

pub trait VmmExitObserver: Send {
    /// Callback to finish processing or cleanup the device resources
    fn on_vmm_exit(&mut self) {}
}

impl<F: Fn() + Send> VmmExitObserver for F {
    fn on_vmm_exit(&mut self) {
        self()
    }
}

impl std::fmt::Debug for dyn VirtioDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "VirtioDevice type {}", self.device_type())
    }
}
