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

    /// Quiesce the device so [`Snapshottable::save`] sees consistent state.
    /// Stops the worker threads that own the live queue indices; must not drain
    /// (a worker blocked on a stalled host fd would deadlock).
    fn pause(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Capture runtime state. Must be called after [`Snapshottable::pause`].
    fn save(&self) -> Result<DeviceState, Error>;

    /// Load saved state, leaving the device quiesced (workers stopped).
    fn restore(&mut self, state: &DeviceState) -> Result<(), Error>;

    /// Start the workers on the state loaded by [`Snapshottable::restore`].
    /// Separate from `restore`: a worker raises IRQs as soon as it runs, and the
    /// GIC blob (written later, on the vCPU thread) would overwrite them.
    fn resume(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
