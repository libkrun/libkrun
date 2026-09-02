//! VM snapshot format and capture orchestration.
//!
//! The shared types here name no hypervisor: KVM and HVF both fill the same
//! arch-keyed register set, the same opaque GIC/device blobs, and the same
//! on-disk layout (`manifest.json` + `memory.img` + `vmstate`).

use std::fs;
use std::io::{Read, Write};
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

/// Load `memory.img` back into guest RAM (the inverse of [`write_mem_image`]).
/// Regions are filled in the same address order they were dumped.
///
/// ponytail: copies the image into anonymous guest RAM. A `MAP_PRIVATE` mapping
/// of `memory.img` would demand-page instead (lower idle RSS) — the upgrade path
/// if restore RSS matters.
pub fn load_mem_image(mem: &GuestMemoryMmap, src: &mut dyn Read) -> Result<(), SnapErr> {
    for region in mem.iter() {
        let host = mem
            .get_host_address(region.start_addr())
            .map_err(|e| SnapErr::State(format!("guest memory host address: {e:?}")))?;
        // SAFETY: vCPUs are not started yet, so the region is exclusively ours
        // and the mapping outlives this write.
        let bytes = unsafe { std::slice::from_raw_parts_mut(host, region.len() as usize) };
        src.read_exact(bytes)?;
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
/// shape before loading `vmstate`/`memory.img`.
#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: u32,
    pub libkrun_version: String,
    pub arch: String,
    pub backend: String,
    pub mem_size_mib: usize,
    pub vcpu_count: u8,
    pub vmstate_version: u32,
    /// Device kinds in registration order. Restore matches saved device state to
    /// live devices by position, so this is the topology the restore config must
    /// reproduce exactly (device kind is not unique on its own).
    pub devices: Vec<String>,
}

impl Manifest {
    /// Reject a freshly-configured VM that doesn't match the snapshot it is
    /// restoring into. Config-validate restore: the embedder rebuilt the VM
    /// shape (with fresh fds), and this is the single gate before saved state is
    /// hydrated onto it.
    pub fn validate(
        &self,
        arch: &str,
        backend: &str,
        mem_size_mib: usize,
        vcpu_count: u8,
        device_kinds: &[&str],
    ) -> Result<(), SnapErr> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err(SnapErr::Version {
                expected: MANIFEST_VERSION,
                found: self.manifest_version,
            });
        }
        let mismatch = |field: &str, want: &dyn std::fmt::Display, got: &dyn std::fmt::Display| {
            SnapErr::State(format!(
                "snapshot {field} mismatch: snapshot={want}, config={got}"
            ))
        };
        if self.arch != arch {
            return Err(mismatch("arch", &self.arch, &arch));
        }
        if self.backend != backend {
            return Err(mismatch("backend", &self.backend, &backend));
        }
        if self.mem_size_mib != mem_size_mib {
            return Err(mismatch("mem_size_mib", &self.mem_size_mib, &mem_size_mib));
        }
        if self.vcpu_count != vcpu_count {
            return Err(mismatch("vcpu_count", &self.vcpu_count, &vcpu_count));
        }
        if self.devices.len() != device_kinds.len()
            || self.devices.iter().zip(device_kinds).any(|(a, b)| a != b)
        {
            return Err(SnapErr::State(format!(
                "snapshot device topology mismatch: snapshot={:?}, config={:?}",
                self.devices, device_kinds
            )));
        }
        Ok(())
    }
}

/// Read and parse `manifest.json` from a snapshot directory.
pub fn read_manifest(dir: &Path) -> Result<Manifest, SnapErr> {
    let bytes = fs::read(dir.join(MANIFEST_NAME))?;
    serde_json::from_slice(&bytes).map_err(|e| SnapErr::State(format!("manifest: {e}")))
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

/// Everything the `vmstate` blob carries, decoded for restore. The memory image
/// and manifest load separately (the caller owns the guest-RAM lifetime).
#[cfg(target_arch = "aarch64")]
pub struct Vmstate {
    /// One per vCPU, in capture (vCPU index) order.
    pub vcpus: Vec<Aarch64VcpuState>,
    /// Opaque GIC distributor/redistributor blob.
    pub gic: Vec<u8>,
    /// `(device id, state)` pairs; restore binds each onto the live device of
    /// the same id.
    pub devices: Vec<(String, DeviceState)>,
}

/// Decode a `vmstate` blob produced by [`VmstateWriter`] back into its sections.
#[cfg(target_arch = "aarch64")]
pub fn load_vmstate(blob: &[u8]) -> Result<Vmstate, SnapErr> {
    let mut vcpus = Vec::new();
    let mut gic = Vec::new();
    let mut devices = Vec::new();
    for section in VmstateReader::new(blob)? {
        let s = section?;
        match s.id {
            x if x == SectionId::Vcpu as u8 => vcpus.push(Aarch64VcpuState::from_bytes(s.bytes)?),
            x if x == SectionId::Gic as u8 => gic = s.bytes.to_vec(),
            x if x == SectionId::Device as u8 => {
                let (id, bytes) = split_device_section(s.bytes)?;
                devices.push((
                    id,
                    DeviceState {
                        version: s.version,
                        bytes,
                    },
                ));
            }
            other => {
                return Err(SnapErr::State(format!(
                    "vmstate: unknown section id {other}"
                )));
            }
        }
    }
    Ok(Vmstate {
        vcpus,
        gic,
        devices,
    })
}

/// Split a device section's `[id_len u16][id][bytes]` framing (the inverse of
/// the framing [`crate::Vmm::snapshot`] writes).
#[cfg(target_arch = "aarch64")]
fn split_device_section(bytes: &[u8]) -> Result<(String, Vec<u8>), SnapErr> {
    let id_len = bytes
        .get(0..2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()) as usize)
        .ok_or_else(|| SnapErr::State("device section: truncated id length".into()))?;
    let end = 2 + id_len;
    let id = bytes
        .get(2..end)
        .ok_or_else(|| SnapErr::State("device section: truncated id".into()))?;
    let id = String::from_utf8(id.to_vec())
        .map_err(|e| SnapErr::State(format!("device id utf8: {e}")))?;
    Ok((id, bytes[end..].to_vec()))
}

/// A snapshot loaded from disk, ready to hydrate onto a freshly-built VM. The
/// memory image is opened lazily at apply time (it can be large).
#[cfg(target_arch = "aarch64")]
pub struct RestoreInput {
    pub manifest: Manifest,
    pub vmstate: Vmstate,
    pub mem_path: std::path::PathBuf,
}

#[cfg(target_arch = "aarch64")]
impl RestoreInput {
    /// Read `manifest.json` + `vmstate` from a snapshot directory.
    pub fn read(dir: &Path) -> Result<Self, SnapErr> {
        let manifest = read_manifest(dir)?;
        let vmstate = load_vmstate(&fs::read(dir.join(VMSTATE_NAME))?)?;
        Ok(Self {
            manifest,
            vmstate,
            mem_path: dir.join(MEMORY_NAME),
        })
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
            devices: vec![],
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

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn load_vmstate_splits_sections() {
        let vcpu = Aarch64VcpuState {
            gp: core::array::from_fn(|i| i as u64),
            sysregs: vec![(1, 2)],
            simd: [0; 32],
            icc: vec![],
            fpcr: 0,
            fpsr: 0,
            vtimer: VtimerState {
                mask: false,
                offset: 0,
            },
            host_counter: 42,
        };
        let mut w = VmstateWriter::new();
        w.section(SectionId::Vcpu, VCPU_SECTION_VERSION, &vcpu.to_bytes());
        w.section(SectionId::Gic, 1, b"gicblob");
        // Device framing: [id_len u16][id][bytes], section version = dev version.
        let id = b"rtc0";
        let mut payload = (id.len() as u16).to_le_bytes().to_vec();
        payload.extend_from_slice(id);
        payload.extend_from_slice(b"rtcstate");
        w.section(SectionId::Device, 2, &payload);

        let vm = load_vmstate(&w.finish()).unwrap();
        assert_eq!(vm.vcpus.len(), 1);
        assert_eq!(vm.vcpus[0], vcpu);
        assert_eq!(vm.gic, b"gicblob");
        assert_eq!(vm.devices.len(), 1);
        assert_eq!(vm.devices[0].0, "rtc0");
        assert_eq!(vm.devices[0].1.version, 2);
        assert_eq!(vm.devices[0].1.bytes, b"rtcstate");
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn manifest_validate_rejects_mismatch() {
        let m = Manifest {
            manifest_version: MANIFEST_VERSION,
            libkrun_version: "x".into(),
            arch: "aarch64".into(),
            backend: "hvf".into(),
            mem_size_mib: 512,
            vcpu_count: 1,
            vmstate_version: VMSTATE_VERSION,
            devices: vec!["fs".into(), "console".into()],
        };
        let devs = ["fs", "console"];
        assert!(m.validate("aarch64", "hvf", 512, 1, &devs).is_ok());
        assert!(m.validate("aarch64", "hvf", 256, 1, &devs).is_err());
        assert!(m.validate("aarch64", "hvf", 512, 2, &devs).is_err());
        assert!(m.validate("x86_64", "hvf", 512, 1, &devs).is_err());
        // Topology: reordered, missing, extra, and wrong-kind all fail.
        assert!(
            m.validate("aarch64", "hvf", 512, 1, &["console", "fs"])
                .is_err()
        );
        assert!(m.validate("aarch64", "hvf", 512, 1, &["fs"]).is_err());
        assert!(
            m.validate("aarch64", "hvf", 512, 1, &["fs", "console", "block"])
                .is_err()
        );
        assert!(
            m.validate("aarch64", "hvf", 512, 1, &["fs", "block"])
                .is_err()
        );
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
            devices: vec!["fs".into(), "console".into()],
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.libkrun_version, "1.0\"evil");
        assert_eq!(back.vcpu_count, 1);
        assert_eq!(back.devices, ["fs", "console"]);
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
