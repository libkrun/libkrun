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

#[cfg(windows)]
use super::unixstream::Unixstream;
#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(windows)]
use std::os::windows::io::{AsSocket, BorrowedSocket, OwnedSocket, RawSocket};

use std::cmp;
use std::io::Write;
use std::path::PathBuf;
use virtio_bindings::virtio_net::VIRTIO_NET_F_MAC;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{ByteValued, GuestMemoryError, GuestMemoryMmap};

const VIRTIO_F_VERSION_1: u32 = 32;

#[derive(Debug)]
pub enum FrontendError {
    DescriptorChainTooSmall,
    EmptyQueue,
    GuestMemory(GuestMemoryError),
    QueueError(QueueError),
    ReadOnlyDescriptor,
}

#[derive(Debug)]
pub enum RxError {
    Backend(ReadError),
    DeviceError(DeviceError),
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
    #[cfg(unix)]
    UnixstreamFd(RawFd),
    #[cfg(windows)]
    UnixstreamFd(RawSocket),
    UnixstreamPath(PathBuf),
    #[cfg(unix)]
    UnixgramFd(RawFd),
    #[cfg(unix)]
    UnixgramPath(PathBuf, bool),
    #[cfg(target_os = "linux")]
    Tap(String),
}

pub struct Net {
    id: String,
    pub cfg_backend: VirtioNetBackend,

    avail_features: u64,
    acked_features: u64,

    pub(crate) device_state: DeviceState,

    config: VirtioNetConfig,

    #[cfg(windows)]
    worker_socket: Option<OwnedSocket>,
    #[cfg(windows)]
    worker: Option<NetWorker>,
}

impl Net {
    /// Create a new virtio network device using the backend
    pub fn new(
        id: String,
        cfg_backend: VirtioNetBackend,
        mac: [u8; 6],
        features: u32,
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

            device_state: DeviceState::Inactive,
            config,
            #[cfg(windows)]
            worker_socket: None,
            #[cfg(windows)]
            worker: None,
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

        #[cfg(windows)]
        {
            if self.worker.is_some() {
                error!("virtio-net worker already exists");
                return Err(ActivateError::BadActivate);
            }

            let worker_socket = match &self.cfg_backend {
                VirtioNetBackend::UnixstreamFd(fd) => unsafe { BorrowedSocket::borrow_raw(*fd) },
                VirtioNetBackend::UnixstreamPath(path) => {
                    if self.worker_socket.is_none() {
                        let stream = Unixstream::open(path.clone())
                            .map_err(|_| ActivateError::BadActivate)?;
                        self.worker_socket = Some(stream.fd);
                    }
                    self.worker_socket
                        .as_ref()
                        .expect("worker_socket is initialized")
                        .as_socket()
                }
            };

            let worker = NetWorker::start(
                rx_q,
                tx_q,
                interrupt.clone(),
                mem.clone(),
                self.acked_features,
                worker_socket,
            )?;
            self.worker = Some(worker);
            self.device_state = DeviceState::Activated(mem, interrupt);
            Ok(())
        }

        #[cfg(not(windows))]
        {
            match NetWorker::new(
                rx_q,
                tx_q,
                interrupt.clone(),
                mem.clone(),
                self.acked_features,
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
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn reset(&mut self) -> bool {
        #[cfg(windows)]
        {
            if let Some(worker) = self.worker.take() {
                worker.stop();
            }
            self.acked_features = 0;
            self.device_state = DeviceState::Inactive;
            true
        }
        #[cfg(not(windows))]
        false
    }
}
