//! VM snapshot/restore seam (M0 skeleton).
//!
//! This module defines the *shared* types every backend fills in. The whole
//! point of the seam is that nothing here names a hypervisor: KVM and HVF both
//! produce the same [`VcpuState`], the same opaque device/GIC blobs, and the
//! same on-disk layout. See the M0 design note for the rationale.
//!
//! ponytail: skeleton only. Capture/restore bodies land in M1 (`todo!()` here).

use std::io::Write;
use std::path::Path;

use vm_memory::GuestMemoryMmap;

/// Failure modes for save/restore. Maps to negative errno at the C API edge.
#[derive(Debug)]
pub enum SnapErr {
    /// Underlying I/O on the snapshot files.
    Io(std::io::Error),
    /// `manifest`/`vmstate` version the loader cannot handle. Never half-loads.
    Version { expected: u32, found: u32 },
    /// A device or vCPU rejected the state it was handed.
    State(String),
}

impl From<std::io::Error> for SnapErr {
    fn from(e: std::io::Error) -> Self {
        SnapErr::Io(e)
    }
}

/// Opaque, independently-versioned per-device state. The device owns the byte
/// layout; the orchestrator only length-prefixes and version-checks it.
pub struct DeviceState {
    pub version: u8,
    pub bytes: Vec<u8>,
}

/// Per-vCPU register file — **arch-keyed, hypervisor-neutral**. KVM and HVF map
/// their own ioctls/hypercalls onto the same variant. No backend name appears.
pub enum VcpuState {
    #[cfg(target_arch = "aarch64")]
    Aarch64(Box<Aarch64VcpuState>),
    // x86_64 variant lands with the KVM backend series.
}

/// aarch64 capture set (mirrors the registers a true PC-resume needs).
#[cfg(target_arch = "aarch64")]
pub struct Aarch64VcpuState {
    /// X0..X30, PC, CPSR.
    pub gp: [u64; 33],
    /// (sys_reg id, value) — incl. pointer-auth keys, or `autiasp` faults on resume.
    pub sysregs: Vec<(u32, u64)>,
    /// Q0..Q31 NEON/FP.
    pub simd: [u128; 32],
    /// Per-vCPU GIC CPU-interface (ICC) regs.
    pub icc: Vec<(u32, u64)>,
    /// Virtual timer mask + offset (offset recomputed on restore for CNTVCT continuity).
    pub vtimer: VtimerState,
}

#[cfg(target_arch = "aarch64")]
pub struct VtimerState {
    pub mask: bool,
    pub offset: u64,
}

/// The one polymorphic seam: virtio/legacy devices are iterated as trait
/// objects, so they earn a trait. Everything else (vCPU, memory, GIC) has a
/// single or cfg-split impl and is a plain method / free fn instead.
pub trait Snapshottable {
    fn id(&self) -> &str;
    fn save(&self) -> Result<DeviceState, SnapErr>;
    fn restore(&mut self, state: &DeviceState) -> Result<(), SnapErr>;
}

/// Serialize guest RAM to the snapshot's `memory.img`. Restore is
/// construction-time (a `MAP_PRIVATE` mapping of the image), so only capture is
/// a function here.
pub fn write_mem_image(_mem: &GuestMemoryMmap, _out: &mut dyn Write) -> Result<(), SnapErr> {
    todo!("M1: write guest RAM regions to memory.img")
}

/// Copy-on-write clone of a backing file (disk image). The CoW primitive is a
/// platform detail hidden here — macOS `clonefile`, Linux `FICLONE` with a
/// plain-copy fallback — so callers never see a backend-specific call.
pub fn cow_clone(_src: &Path, _dst: &Path) -> Result<(), SnapErr> {
    todo!("M1: clonefile (macos) / FICLONE+copy fallback (linux)")
}
