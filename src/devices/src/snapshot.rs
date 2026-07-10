//! Device snapshot seam.
//!
//! Devices live in this crate, so the trait they implement lives here too (the
//! VMM cannot be a dependency — it depends on us). The VMM orchestrates capture
//! by iterating `dyn Snapshottable` and maps the returned bytes/errors into its
//! snapshot format.

use crate::Error;

/// Opaque, independently-versioned per-device state. The device owns the byte
/// layout; the orchestrator only frames it (id + length + version).
pub struct DeviceState {
    pub version: u8,
    pub bytes: Vec<u8>,
}

/// A device that can serialize and restore its runtime state. Implemented by
/// the virtio/legacy devices that must survive a snapshot; iterated as a trait
/// object by the VMM, which is why it stays object-safe.
pub trait Snapshottable: Send {
    /// Stable identifier, used as the device's key in the snapshot.
    fn id(&self) -> &str;
    /// Capture runtime state. Must be called with the device quiescent.
    fn save(&self) -> Result<DeviceState, Error>;
    /// Restore from a previously captured state (used by M2 restore).
    fn restore(&mut self, state: &DeviceState) -> Result<(), Error>;
}
