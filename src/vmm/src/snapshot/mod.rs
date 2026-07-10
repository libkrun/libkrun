//! VM snapshot format and capture orchestration.
//!
//! The shared types here name no hypervisor: KVM and HVF both fill the same
//! arch-keyed register set, the same opaque GIC/device blobs, and the same
//! on-disk layout (`manifest.json` + `memory.img` + `vmstate`).

use std::fs;
use std::io::Write;
use std::path::Path;

#[cfg(target_arch = "aarch64")]
use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

use vm_memory::{GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

/// What to do with the guest after a snapshot is captured. Mirrors the typed
/// `SnapshotFlags` of the proposed 2.0 Rust API (`RunningVmm::snapshot`); the C
/// shim parses the integer flag into this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotFlags {
    /// Capture, then terminate the process.
    Exit,
    /// Capture, then keep the guest running.
    Resume,
}

impl SnapshotFlags {
    /// Parse the C-ABI integer flag. `None` if unknown.
    pub fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            0 => Some(SnapshotFlags::Exit),
            1 => Some(SnapshotFlags::Resume),
            _ => None,
        }
    }
}

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

// Per-device state and the `Snapshottable` trait live in the devices crate
// (devices can't depend on the VMM). Re-exported here so the snapshot format
// and orchestration can refer to them in one place.
pub use devices::snapshot::{DeviceState, Snapshottable};

/// aarch64 capture set (mirrors the registers a true PC-resume needs).
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Aarch64VcpuState {
    /// X0..X30, PC, CPSR.
    pub gp: [u64; 33],
    /// (sys_reg id, value) — incl. pointer-auth keys, or `autiasp` faults on resume.
    pub sysregs: Vec<(u32, u64)>,
    /// Q0..Q31 NEON/FP.
    pub simd: [u128; 32],
    /// Per-vCPU GIC CPU-interface (ICC) regs.
    pub icc: Vec<(u32, u64)>,
    /// FP control / status.
    pub fpcr: u64,
    pub fpsr: u64,
    /// Virtual timer mask + offset (offset recomputed on restore for CNTVCT continuity).
    pub vtimer: VtimerState,
    /// `mach_absolute_time()` at capture — the vtimer-continuity anchor.
    pub host_counter: u64,
}

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct VtimerState {
    pub mask: bool,
    pub offset: u64,
}

/// Version byte for the per-vCPU `vmstate` section.
#[cfg(target_arch = "aarch64")]
pub const VCPU_SECTION_VERSION: u8 = 1;

#[cfg(target_arch = "aarch64")]
impl Aarch64VcpuState {
    /// Pack into the vCPU section bytes via bincode.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .expect("vcpu state encode is infallible for an in-memory buffer")
    }

    /// Inverse of [`Aarch64VcpuState::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SnapErr> {
        let (state, _) = bincode::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| SnapErr::State(format!("vcpu state: {e}")))?;
        Ok(state)
    }
}

/// Serialize guest RAM to the snapshot's `memory.img`. Restore is
/// construction-time (a `MAP_PRIVATE` mapping of the image), so only capture is
/// a function here.
pub fn write_mem_image(mem: &GuestMemoryMmap, out: &mut dyn Write) -> Result<(), SnapErr> {
    for region in mem.iter() {
        let host = mem
            .get_host_address(region.start_addr())
            .map_err(|e| SnapErr::State(format!("guest memory host address: {e:?}")))?;
        // SAFETY: vCPUs are stopped at capture, so the region is quiescent and
        // the mapping outlives this read. Regions are written in address order.
        let bytes = unsafe { std::slice::from_raw_parts(host, region.len() as usize) };
        out.write_all(bytes)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// snapshot directory: manifest.json + vmstate + memory.img
// ---------------------------------------------------------------------------

/// Snapshot file names within the snapshot directory.
pub const MANIFEST_NAME: &str = "manifest.json";
pub const VMSTATE_NAME: &str = "vmstate";
pub const MEMORY_NAME: &str = "memory.img";

/// Current manifest schema version. Independent of [`VMSTATE_VERSION`].
pub const MANIFEST_VERSION: u32 = 1;

/// The human-readable side of a snapshot: what's needed to rebuild the VM
/// shape before loading `vmstate`/`memory.img`. Device descriptors are added
/// with per-device capture.
#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: u32,
    pub libkrun_version: String,
    pub arch: String,
    pub backend: String,
    pub mem_size_mib: usize,
    pub vcpu_count: u8,
    pub vmstate_version: u32,
}

/// Write a complete snapshot directory: `manifest.json`, the `vmstate` blob,
/// and `memory.img` (the guest RAM dump). Creates `dir` if needed.
pub fn write_snapshot(
    dir: &Path,
    manifest: &Manifest,
    vmstate: &[u8],
    mem: &GuestMemoryMmap,
) -> Result<(), SnapErr> {
    fs::create_dir_all(dir)?;
    let json = serde_json::to_vec_pretty(manifest).map_err(|e| SnapErr::State(e.to_string()))?;
    fs::write(dir.join(MANIFEST_NAME), json)?;
    fs::write(dir.join(VMSTATE_NAME), vmstate)?;
    let mut img = fs::File::create(dir.join(MEMORY_NAME))?;
    write_mem_image(mem, &mut img)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// vmstate binary framing
//
// Magic + version header, then length-prefixed sections. Hand-rolled (not serde)
// because it's a register/queue dump, not config. Each section carries its own
// version byte, so a device's schema can bump without bumping the whole blob.
// ---------------------------------------------------------------------------

/// `vmstate` blob magic. Bumps only on an incompatible framing change.
pub const VMSTATE_MAGIC: &[u8; 4] = b"KRSV";
/// Framing version (the header layout), independent of any section's version.
pub const VMSTATE_VERSION: u32 = 1;

/// Section tags. The byte values are part of the on-disk format — append only.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SectionId {
    Vcpu = 0,
    Gic = 1,
    Device = 2,
}

/// Appends magic + version + length-prefixed sections into an in-memory blob.
pub struct VmstateWriter {
    buf: Vec<u8>,
}

impl Default for VmstateWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl VmstateWriter {
    pub fn new() -> Self {
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(VMSTATE_MAGIC);
        buf.extend_from_slice(&VMSTATE_VERSION.to_le_bytes());
        Self { buf }
    }

    /// One section: `[id:u8][version:u8][len:u32 LE][bytes]`.
    pub fn section(&mut self, id: SectionId, version: u8, bytes: &[u8]) {
        self.buf.push(id as u8);
        self.buf.push(version);
        self.buf
            .extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(bytes);
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// One decoded section, borrowed from the underlying blob.
pub struct Section<'a> {
    pub id: u8,
    pub version: u8,
    pub bytes: &'a [u8],
}

/// Validates the header and iterates sections. Never half-reads: a truncated
/// section yields an error, not a partial value.
pub struct VmstateReader<'a> {
    rest: &'a [u8],
}

impl<'a> VmstateReader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, SnapErr> {
        if data.len() < 8 || &data[0..4] != VMSTATE_MAGIC {
            return Err(SnapErr::State("vmstate: bad magic".into()));
        }
        let found = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if found != VMSTATE_VERSION {
            return Err(SnapErr::Version {
                expected: VMSTATE_VERSION,
                found,
            });
        }
        Ok(Self { rest: &data[8..] })
    }
}

impl<'a> Iterator for VmstateReader<'a> {
    type Item = Result<Section<'a>, SnapErr>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        if self.rest.len() < 6 {
            return Some(Err(SnapErr::State(
                "vmstate: truncated section header".into(),
            )));
        }
        let id = self.rest[0];
        let version = self.rest[1];
        let len = u32::from_le_bytes(self.rest[2..6].try_into().unwrap()) as usize;
        let end = 6 + len;
        if self.rest.len() < end {
            return Some(Err(SnapErr::State(
                "vmstate: truncated section body".into(),
            )));
        }
        let bytes = &self.rest[6..end];
        self.rest = &self.rest[end..];
        Some(Ok(Section { id, version, bytes }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmstate_round_trips() {
        let mut w = VmstateWriter::new();
        w.section(SectionId::Vcpu, 1, &[1, 2, 3]);
        w.section(SectionId::Device, 7, b"blk0-state");
        let blob = w.finish();

        let secs: Vec<_> = VmstateReader::new(&blob)
            .unwrap()
            .map(|s| s.unwrap())
            .collect();
        assert_eq!(secs.len(), 2);
        assert_eq!(secs[0].id, SectionId::Vcpu as u8);
        assert_eq!(secs[0].version, 1);
        assert_eq!(secs[0].bytes, &[1, 2, 3]);
        assert_eq!(secs[1].id, SectionId::Device as u8);
        assert_eq!(secs[1].version, 7);
        assert_eq!(secs[1].bytes, b"blk0-state");
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(matches!(
            VmstateReader::new(b"XXXX\x01\x00\x00\x00"),
            Err(SnapErr::State(_))
        ));
    }

    #[test]
    fn rejects_version_mismatch() {
        let mut blob = Vec::new();
        blob.extend_from_slice(VMSTATE_MAGIC);
        blob.extend_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            VmstateReader::new(&blob),
            Err(SnapErr::Version { found: 99, .. })
        ));
    }

    #[test]
    fn writes_snapshot_directory() {
        use vm_memory::GuestAddress;

        let dir = std::env::temp_dir().join(format!("krun-snap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let manifest = Manifest {
            manifest_version: MANIFEST_VERSION,
            libkrun_version: "1.18.0".into(),
            arch: "aarch64".into(),
            backend: "hvf".into(),
            mem_size_mib: 1,
            vcpu_count: 2,
            vmstate_version: VMSTATE_VERSION,
        };
        let mut w = VmstateWriter::new();
        w.section(SectionId::Vcpu, 1, &[9, 9]);
        let vmstate = w.finish();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        write_snapshot(&dir, &manifest, &vmstate, &mem).unwrap();

        let json = fs::read_to_string(dir.join(MANIFEST_NAME)).unwrap();
        assert!(json.contains("\"arch\": \"aarch64\""));
        assert!(json.contains("\"vcpu_count\": 2"));
        assert_eq!(fs::read(dir.join(VMSTATE_NAME)).unwrap(), vmstate);
        assert_eq!(fs::metadata(dir.join(MEMORY_NAME)).unwrap().len(), 0x1000);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn vcpu_state_round_trips() {
        let state = Aarch64VcpuState {
            gp: core::array::from_fn(|i| i as u64 * 7 + 1),
            sysregs: vec![(0xAAAA, 0x1111), (0xBBBB, 0x2222)],
            simd: core::array::from_fn(|i| (i as u128) << 64 | 0xDEAD),
            icc: vec![(0xC, 0x3)],
            fpcr: 0x55,
            fpsr: 0x66,
            vtimer: VtimerState {
                mask: true,
                offset: 0x1234_5678_9abc,
            },
            host_counter: 0xfeed_face,
        };
        let bytes = state.to_bytes();
        assert_eq!(Aarch64VcpuState::from_bytes(&bytes).unwrap(), state);
        // A truncated blob errors rather than panicking.
        assert!(Aarch64VcpuState::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn manifest_round_trips() {
        let m = Manifest {
            manifest_version: MANIFEST_VERSION,
            libkrun_version: "1.0\"evil".into(),
            arch: "aarch64".into(),
            backend: "hvf".into(),
            mem_size_mib: 1,
            vcpu_count: 1,
            vmstate_version: VMSTATE_VERSION,
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.libkrun_version, "1.0\"evil");
        assert_eq!(back.vcpu_count, 1);
    }

    #[test]
    fn mem_image_writes_regions_in_order() {
        use vm_memory::{Bytes, GuestAddress};

        // Two regions; write a distinct pattern into each, then dump.
        let mem = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 0x1000),
            (GuestAddress(0x1000), 0x1000),
        ])
        .unwrap();
        mem.write_slice(&[0xAA; 0x1000], GuestAddress(0)).unwrap();
        mem.write_slice(&[0xBB; 0x1000], GuestAddress(0x1000))
            .unwrap();

        let mut out = Vec::new();
        write_mem_image(&mem, &mut out).unwrap();

        assert_eq!(out.len(), 0x2000);
        assert!(out[..0x1000].iter().all(|&b| b == 0xAA));
        assert!(out[0x1000..].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn detects_truncated_body() {
        let mut blob = Vec::new();
        blob.extend_from_slice(VMSTATE_MAGIC);
        blob.extend_from_slice(&VMSTATE_VERSION.to_le_bytes());
        blob.extend_from_slice(&[SectionId::Vcpu as u8, 1, 10, 0, 0, 0]); // claims 10 bytes
        blob.extend_from_slice(&[0, 0]); // only 2 present
        let mut r = VmstateReader::new(&blob).unwrap();
        assert!(matches!(r.next(), Some(Err(SnapErr::State(_)))));
    }
}
