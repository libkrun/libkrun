// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use devices::virtio::{TsiFlags, Vsock, VsockError};

type MutexVsock = Arc<Mutex<Vsock>>;

/// Errors associated with `NetworkInterfaceConfig`.
#[derive(Debug)]
pub enum VsockConfigError {
    /// Failed to create the vsock device.
    CreateVsockDevice(VsockError),
}

impl fmt::Display for VsockConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VsockConfigError::*;
        match *self {
            CreateVsockDevice(ref e) => write!(f, "Cannot create vsock device: {e:?}"),
        }
    }
}

type Result<T> = std::result::Result<T, VsockConfigError>;

/// This struct represents the strongly typed equivalent of the json body
/// from vsock related requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VsockDeviceConfig {
    /// ID of the vsock device.
    pub vsock_id: String,
    /// A 32-bit Context Identifier (CID) used to identify the guest.
    pub guest_cid: u32,
    /// An optional map of host to guest port mappings.
    pub host_port_map: Option<HashMap<u16, u16>>,
    /// An optional map of guest port to host UNIX domain sockets for IPC.
    pub unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
    /// TSI feature flags
    pub tsi_flags: TsiFlags,
    /// Optional egress policy: list of allowed CIDR ranges (ip, prefix_len).
    pub egress_cidrs: Option<Vec<(IpAddr, u8)>>,
    /// Optional DNS allow-host list for TSI egress filtering.
    pub egress_hosts: Option<Vec<String>>,
    /// Optional host-trusted DNS resolvers (queries are forwarded only here).
    pub egress_resolvers: Option<Vec<IpAddr>>,
    /// Optional host DNS forwarder every guest UDP DNS query is routed to.
    pub dns_forwarder: Option<std::net::SocketAddr>,
    /// Optional host interceptor for guest stream connects to one port.
    pub stream_intercept: Option<devices::virtio::vsock::StreamIntercept>,
}

struct VsockWrapper {
    vsock: MutexVsock,
}

/// A builder of Vsock from 'VsockDeviceConfig'.
#[derive(Default)]
pub struct VsockBuilder {
    inner: Option<VsockWrapper>,
    tsi_flags: TsiFlags,
}

impl VsockBuilder {
    /// Creates an empty Vsock.
    pub fn new() -> Self {
        Self {
            inner: None,
            tsi_flags: TsiFlags::empty(),
        }
    }

    /// Inserts a Vsock in the store.
    /// If an entry already exists, it will overwrite it.
    pub fn insert(&mut self, cfg: VsockDeviceConfig) -> Result<()> {
        self.tsi_flags = cfg.tsi_flags;
        self.inner = Some(VsockWrapper {
            vsock: Arc::new(Mutex::new(Self::create_vsock(cfg)?)),
        });
        Ok(())
    }

    /// Provides a reference to the Vsock if present.
    pub fn get(&self) -> Option<&MutexVsock> {
        self.inner.as_ref().map(|pair| &pair.vsock)
    }

    pub fn tsi_flags(&self) -> TsiFlags {
        self.tsi_flags
    }

    /// Creates a Vsock device from a VsockDeviceConfig.
    pub fn create_vsock(cfg: VsockDeviceConfig) -> Result<Vsock> {
        Vsock::new(
            u64::from(cfg.guest_cid),
            cfg.host_port_map,
            cfg.unix_ipc_port_map,
            cfg.tsi_flags,
            cfg.egress_cidrs,
            cfg.egress_hosts,
            cfg.egress_resolvers,
            cfg.dns_forwarder,
            cfg.stream_intercept,
        )
        .map_err(VsockConfigError::CreateVsockDevice)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn default_config() -> VsockDeviceConfig {
        let vsock_dev_id = "vsock";
        VsockDeviceConfig {
            vsock_id: vsock_dev_id.to_string(),
            guest_cid: 3,
            host_port_map: None,
            unix_ipc_port_map: None,
            tsi_flags: TsiFlags::empty(),
            egress_cidrs: None,
            egress_hosts: None,
            egress_resolvers: None,
            dns_forwarder: None,
            stream_intercept: None,
        }
    }

    #[test]
    fn test_vsock_insert() {
        let mut store = VsockBuilder::new();
        let mut vsock_config = default_config();

        store.insert(vsock_config.clone()).unwrap();
        let vsock = store.get().unwrap();
        assert_eq!(vsock.lock().unwrap().id(), &vsock_config.vsock_id);

        let new_cid = vsock_config.guest_cid + 1;
        vsock_config.guest_cid = new_cid;
        store.insert(vsock_config).unwrap();
        let vsock = store.get().unwrap();
        assert_eq!(vsock.lock().unwrap().cid(), new_cid as u64);
    }

    #[test]
    fn test_error_messages() {
        use super::VsockConfigError::*;
        use std::io;

        let err = CreateVsockDevice(devices::virtio::VsockError::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{err}{err:?}");
    }
}
