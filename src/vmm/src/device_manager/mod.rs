// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

/// Legacy Device Manager.
pub mod legacy;

/// Device Shared Memory Region Manager.
pub mod shm;

/// Memory Mapped I/O Manager.
#[cfg(target_os = "linux")]
pub mod kvm;
#[cfg(target_os = "linux")]
pub use self::kvm::mmio;
#[cfg(target_os = "macos")]
pub mod hvf;
#[cfg(target_os = "macos")]
pub use self::hvf::mmio;
#[cfg(target_os = "windows")]
pub mod whp;
#[cfg(target_os = "windows")]
pub use self::whp::mmio;

use devices::virtio::{
    MmioTransport,
    persist::{VmDevicesState, restore_device},
};
use std::sync::{Arc, Mutex};

/// Restore existing, quiesced devices in their original registration order.
/// Consume each matching transport once, as fresh-clone activation does: two
/// disks must not both restore their queue indices onto the first disk.
fn restore_devices_in_place(
    transports: &[Arc<Mutex<MmioTransport>>],
    state: &VmDevicesState,
) -> Result<(), String> {
    let mut used = vec![false; transports.len()];
    for (index, snapshot) in state.devices.iter().enumerate() {
        let mut applied = false;
        for (i, transport) in transports.iter().enumerate() {
            if used[i] {
                continue;
            }
            let mut transport = transport.lock().expect("poisoned transport lock");
            if transport.locked_device().device_type() != snapshot.device_type() {
                continue;
            }
            transport
                .rewind_interrupt_status(state.interrupt_status.get(index).copied().unwrap_or(0));
            // A matched device's failure must stop restore. Trying another
            // device of this type could silently restore the wrong disk.
            restore_device(&mut *transport.locked_device(), snapshot)?;
            used[i] = true;
            applied = true;
            break;
        }
        if !applied {
            return Err(format!(
                "no matching transport to restore device type {}",
                snapshot.device_type()
            ));
        }
    }
    Ok(())
}

#[cfg(all(test, not(feature = "tee")))]
mod restore_tests {
    use super::*;
    use devices::{
        legacy::DummyIrqChip,
        virtio::{
            Rng, RngState, VIRTIO_MMIO_INT_CONFIG, VIRTIO_MMIO_INT_VRING, persist::DeviceSnapshot,
        },
    };
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    fn transport() -> Arc<Mutex<MmioTransport>> {
        Arc::new(Mutex::new(
            MmioTransport::new(
                GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
                DummyIrqChip::new().into(),
                Arc::new(Mutex::new(Rng::new().unwrap())),
            )
            .unwrap(),
        ))
    }

    fn snapshot(features: u64) -> DeviceSnapshot {
        DeviceSnapshot::Rng(RngState {
            acked_features: features,
            queue: None,
        })
    }

    #[test]
    fn rewind_restores_each_same_type_device_and_its_pending_interrupt() {
        let transports = [transport(), transport()];
        // A later-timeline config interrupt must not leak into the checkpoint.
        {
            let mut first = transports[0].lock().unwrap();
            first.set_restored_interrupt_status(VIRTIO_MMIO_INT_CONFIG);
            first.replay_restored_interrupt();
            assert_eq!(first.interrupt_evt().read().unwrap(), 1);
        }
        let state = VmDevicesState {
            devices: vec![snapshot(11), snapshot(22)],
            interrupt_status: vec![VIRTIO_MMIO_INT_VRING, VIRTIO_MMIO_INT_CONFIG],
        };
        restore_devices_in_place(&transports, &state).unwrap();
        for (i, transport) in transports.iter().enumerate() {
            let mut transport = transport.lock().unwrap();
            assert_eq!(transport.locked_device().acked_features(), [11, 22][i]);
            transport.replay_restored_interrupt();
            assert_eq!(transport.interrupt_status(), state.interrupt_status[i]);
            assert_eq!(transport.interrupt_evt().read().unwrap(), 1);
        }
    }

    #[test]
    fn rewind_rejects_a_missing_device_instead_of_overwriting_another() {
        let transports = [transport()];
        let state = VmDevicesState {
            devices: vec![snapshot(11), snapshot(22)],
            interrupt_status: vec![],
        };
        assert!(restore_devices_in_place(&transports, &state).is_err());
        assert_eq!(
            transports[0]
                .lock()
                .unwrap()
                .locked_device()
                .acked_features(),
            11
        );
    }
}
