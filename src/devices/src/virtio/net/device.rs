// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use crate::Error as DeviceError;
use crate::virtio::net::Result;
use crate::virtio::net::{NUM_QUEUES, QUEUE_CONFIG};
use crate::virtio::queue::Error as QueueError;
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    TYPE_NET, VirtioDevice,
};

use super::backend::{ReadError, WriteError};
use super::worker::NetWorker;

use std::cmp;
use std::io::Write;
use std::os::fd::RawFd;
use std::path::PathBuf;
use virtio_bindings::{virtio_net::VIRTIO_NET_F_MAC, virtio_ring::VIRTIO_RING_F_EVENT_IDX};
use vm_memory::{ByteValued, GuestMemoryMmap};

const VIRTIO_F_VERSION_1: u32 = 32;

// FrontendError removed - no longer used with vectored I/O

#[derive(Debug)]
pub enum RxError {
    Backend(ReadError),
    DeviceError(DeviceError),
    QueueError(QueueError),
}

#[derive(Debug)]
pub enum TxError {
    Backend(WriteError),
    DeviceError(DeviceError),
    QueueError(QueueError),
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioNetConfig {
    mac: [u8; 6],
    status: u16,
    max_virtqueue_pairs: u16,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioNetConfig {}

#[derive(Clone)]
pub enum VirtioNetBackend {
    UnixstreamFd(RawFd),
    UnixstreamPath(PathBuf),
    UnixgramFd(RawFd),
    UnixgramPath(PathBuf, bool),
    #[cfg(target_os = "linux")]
    Tap(String),
}

pub struct Net {
    id: String,
    pub cfg_backend: VirtioNetBackend,

    avail_features: u64,
    acked_features: u64,
    include_vnet_header: bool,

    pub(crate) device_state: DeviceState,

    config: VirtioNetConfig,
}

impl Net {
    /// Create a new virtio network device using the backend
    pub fn new(
        id: String,
        cfg_backend: VirtioNetBackend,
        mac: [u8; 6],
        features: u32,
        include_vnet_header: bool,
    ) -> Result<Self> {
        let avail_features = features as u64
            | (1 << VIRTIO_NET_F_MAC)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | (1 << VIRTIO_F_VERSION_1);

        let config = VirtioNetConfig {
            mac,
            status: 0,
            max_virtqueue_pairs: 0,
        };

        Ok(Net {
            id,
            cfg_backend,

            avail_features,
            acked_features: 0u64,
            include_vnet_header,

            device_state: DeviceState::Inactive,
            config,
        })
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Provides the virtio-net backend of this net device.
    pub fn backend(&self) -> &VirtioNetBackend {
        &self.cfg_backend
    }
}

impl VirtioDevice for Net {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn device_name(&self) -> &str {
        "net"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        log::warn!(
            "Net: guest driver attempted to write device config (offset={:x}, len={:x})",
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
        let [rx_q, tx_q]: [_; NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!("Cannot perform activate. Expected {} queue(s)", NUM_QUEUES);
            ActivateError::BadActivate
        })?;

        match NetWorker::new(
            rx_q,
            tx_q,
            interrupt.clone(),
            mem.clone(),
            self.acked_features,
            self.include_vnet_header,
            self.cfg_backend.clone(),
        ) {
            Ok(worker) => {
                worker.run();
                self.device_state = DeviceState::Activated(mem, interrupt);
                Ok(())
            }
            Err(err) => {
                error!(
                    "Error activating virtio-net ({}) backend: {err:?}",
                    self.id()
                );
                Err(ActivateError::BadActivate)
            }
        }
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}
