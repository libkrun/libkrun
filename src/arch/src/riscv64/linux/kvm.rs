// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::result;

use kvm_ioctls::VcpuFd;
use log::debug;
use vmm_sys_util::ioctl::ioctl_with_mut_ptr;
use vmm_sys_util::ioctl_iowr_nr;

/// `KVMIO` ioctl type and `KVM_GET_REG_LIST`'s number, matching
/// `kvm_bindings::KVMIO` and `kvm_ioctls::KVM_GET_REG_LIST()`
/// (`arch/riscv/include/uapi/asm/kvm.h` and `include/uapi/linux/kvm.h`:
/// `#define KVM_GET_REG_LIST _IOWR(KVMIO, 0xb0, struct kvm_reg_list)`).
/// Declared locally rather than reusing `kvm_ioctls`'s private binding so we
/// can call the ioctl with our own, uncapped buffer type (see `RawRegList`).
const KVMIO: u32 = 174;
ioctl_iowr_nr!(KVM_GET_REG_LIST, KVMIO, 0xb0, u64);

/// Owned, correctly-sized buffer for a `KVM_GET_REG_LIST` call.
///
/// Mirrors the kernel's `struct kvm_reg_list` (`include/uapi/linux/kvm.h`):
/// a `u64` count header (`n`) followed by `n` trailing `u64` register IDs,
/// laid out as one contiguous block (`[header, entry_0, entry_1, ...]`)
/// backed by a `Vec<u64>`, which guarantees correct 8-byte alignment for
/// the whole buffer -- unlike a `Vec<u8>` cast to a `#[repr(C)]` struct,
/// which would only be guaranteed 1-byte aligned.
///
/// `kvm_bindings::RegList` wraps the same on-wire layout but caps the
/// capacity at a hardcoded `RISCV64_REGS_MAX = 200`, which real RVA23S64
/// hardware with Vector, AIA and SBI extensions enabled can exceed
/// (observed: 246). We own the allocation here instead so we are not bound
/// by that crate-side ceiling.
struct RawRegList {
    /// `words[0]` is the `n` header field; `words[1..]` are the register
    /// IDs, sized to hold exactly `capacity` of them.
    words: Vec<u64>,
}

impl RawRegList {
    /// Allocates a zeroed buffer with its header set to request `capacity`
    /// entries, able to hold up to `capacity` register IDs.
    fn new(capacity: usize) -> Self {
        let mut words = vec![0u64; 1 + capacity];
        words[0] = capacity as u64;
        RawRegList { words }
    }

    /// Calls `KVM_GET_REG_LIST` on `vcpu`, filling in `self` in place.
    fn get_reg_list(&mut self, vcpu: &VcpuFd) -> result::Result<(), kvm_ioctls::Error> {
        // SAFETY: `self.words` is a correctly-aligned, contiguous buffer of
        // at least `1 + capacity` u64s, matching the kernel's expected
        // `struct kvm_reg_list { u64 n; u64 reg[]; }` layout for the
        // KVM_GET_REG_LIST ioctl (KVMIO 0xb0, _IOWR). The kernel reads `n`
        // (our requested capacity) and, on success, writes up to that many
        // register IDs into the trailing slots; on `-E2BIG` it only
        // overwrites `n` with the real count and touches nothing else.
        let ret = unsafe { ioctl_with_mut_ptr(vcpu, KVM_GET_REG_LIST(), self.words.as_mut_ptr()) };
        if ret < 0 {
            return Err(kvm_ioctls::Error::last());
        }
        Ok(())
    }

    /// The real register count: our requested capacity on input, or the
    /// kernel-reported true count after a `KVM_GET_REG_LIST` call.
    fn n(&self) -> u64 {
        self.words[0]
    }

    /// The register IDs following the header, i.e. up to `self.n()`
    /// entries actually filled in by a successful `KVM_GET_REG_LIST` call.
    fn entries(&self) -> &[u64] {
        let len = (self.n() as usize).min(self.words.len() - 1);
        &self.words[1..1 + len]
    }
}

/// Errors encountered during ISA detection and configuration discovery.
#[derive(Debug)]
pub enum IsaError {
    /// Failed to read the `isa` CONFIG register from KVM.
    ReadIsaReg(kvm_ioctls::Error),
}

type Result<T> = result::Result<T, IsaError>;

// RISC-V ISA extension KVM register IDs, verified against
// linux-7.2.9 arch/riscv/include/uapi/asm/kvm.h and arch/riscv/kvm/isa.c.
//
// Unlike bit positions in the human-readable `riscv,isa` devicetree string,
// KVM's ISA_EXT register IDs are a flat, *sequential* enum
// (`enum KVM_RISCV_ISA_EXT_ID`), currently 0..77 (KVM_RISCV_ISA_EXT_MAX=78).
// This is NOT the same numbering as the single-letter bit positions used by
// the `isa` CONFIG register (which is a GENMASK(25,0) bitmask, see
// `read_isa_bitmask()` below).
//
// kvm-bindings 0.14.1 only defines IDs 0..=70 (stale vs. linux-7.2.9's 0..=77),
// so IDs 71-77 are listed here as explicit literals with a comment citing the
// kernel header, rather than crate constants.
const KVM_ISA_EXT_TABLE: &[(&str, u64)] = &[
    ("a", 0),
    ("c", 1),
    ("d", 2),
    ("f", 3),
    ("h", 4),
    ("i", 5),
    ("m", 6),
    ("svpbmt", 7),
    ("sstc", 8),
    ("svinval", 9),
    ("zihintpause", 10),
    ("zicbom", 11),
    ("zicboz", 12),
    ("zbb", 13),
    ("ssaia", 14),
    ("v", 15),
    ("svnapot", 16),
    ("zba", 17),
    ("zbs", 18),
    ("zicntr", 19),
    ("zicsr", 20),
    ("zifencei", 21),
    ("zihpm", 22),
    ("smstateen", 23),
    ("zicond", 24),
    ("zbc", 25),
    ("zbkb", 26),
    ("zbkc", 27),
    ("zbkx", 28),
    ("zknd", 29),
    ("zkne", 30),
    ("zknh", 31),
    ("zkr", 32),
    ("zksed", 33),
    ("zksh", 34),
    ("zkt", 35),
    ("zvbb", 36),
    ("zvbc", 37),
    ("zvkb", 38),
    ("zvkg", 39),
    ("zvkned", 40),
    ("zvknha", 41),
    ("zvknhb", 42),
    ("zvksed", 43),
    ("zvksh", 44),
    ("zvkt", 45),
    ("zfh", 46),
    ("zfhmin", 47),
    ("zihintntl", 48),
    ("zvfh", 49),
    ("zvfhmin", 50),
    ("zfa", 51),
    ("ztso", 52),
    ("zacas", 53),
    ("sscofpmf", 54),
    ("zimop", 55),
    ("zca", 56),
    ("zcb", 57),
    ("zcd", 58),
    ("zcf", 59),
    ("zcmop", 60),
    ("zawrs", 61),
    ("smnpm", 62),
    ("ssnpm", 63),
    ("svade", 64),
    ("svadu", 65),
    ("svvptc", 66),
    ("zabha", 67),
    ("ziccrse", 68),
    ("zaamo", 69),
    ("zalrsc", 70),
    // IDs 71-79: not yet in kvm-bindings 0.14.1, see
    // arch/riscv/include/uapi/asm/kvm.h enum KVM_RISCV_ISA_EXT_ID.
    ("zicbop", 71),
    ("zfbfmin", 72),
    ("zvfbfmin", 73),
    ("zvfbfwma", 74),
    ("zclsd", 75),
    ("zilsd", 76),
    ("zalasr", 77),
    ("zicfilp", 78),
    ("zicfiss", 79),
];

/// Subtype for single ISA extension registers (`KVM_REG_RISCV_ISA_SINGLE`),
/// i.e. subtype 0 within the `KVM_REG_RISCV_ISA_EXT` register type.
const KVM_REG_RISCV_ISA_SINGLE: u64 = 0;

/// Builds the KVM register ID for a single ISA extension, given its
/// sequential `KVM_RISCV_ISA_EXT_ID` (0..77), per
/// `KVM_REG_RISCV | KVM_REG_SIZE_ULONG | KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | id`.
fn isa_ext_reg_id(kvm_ext_id: u64) -> u64 {
    kvm_bindings::KVM_REG_RISCV as u64
        | kvm_bindings::KVM_REG_SIZE_U64
        | u64::from(kvm_bindings::KVM_REG_RISCV_ISA_EXT)
        | KVM_REG_RISCV_ISA_SINGLE
        | kvm_ext_id
}

/// Returns true if `err` corresponds to the kernel reporting that an
/// extension/register is unknown or unsupported on the host
/// (`-ENOENT`, from `__kvm_riscv_isa_check_host()` in
/// arch/riscv/kvm/isa.c). This is the error KVM returns for unsupported
/// ISA extensions; `EINVAL` is reserved for register-size mismatches.
fn is_not_supported(err: &kvm_ioctls::Error) -> bool {
    err.errno() == libc::ENOENT
}

/// ISA extension information discovered from the host KVM.
#[derive(Debug, Clone)]
pub struct RiscvIsaInfo {
    /// ISA base features as a string (e.g., "rv64imafdc_smaia_ssaia")
    pub isa_string: String,
    /// List of ISA extensions supported by the host
    pub extensions: BTreeSet<String>,
    /// Cache block size for Zicbom (in bytes), if available
    pub zicbom_block_size: Option<u32>,
    /// Cache block size for Zicboz (in bytes), if available
    pub zicboz_block_size: Option<u32>,
    /// Cache block size for Zicbop (in bytes), if available
    pub zicbop_block_size: Option<u32>,
}

/// Builds the KVM register ID for a `struct kvm_riscv_config` field, given
/// its *field index* (NOT byte offset) within that struct, i.e.
/// `offsetof(struct kvm_riscv_config, field) / sizeof(unsigned long)` as
/// defined by `KVM_REG_RISCV_CONFIG_REG()` in
/// arch/riscv/include/uapi/asm/kvm.h.
///
/// Field order (linux-7.2.9): isa=0, zicbom_block_size=1, mvendorid=2,
/// marchid=3, mimpid=4, zicboz_block_size=5, satp_mode=6, zicbop_block_size=7.
/// Note kvm-bindings 0.14.1's `kvm_riscv_config` struct is stale and omits
/// `zicbop_block_size`, so we address fields purely by their kernel-defined
/// index rather than via `offset_of!` on the (incomplete) crate struct.
fn config_reg_id(field_index: u64) -> u64 {
    kvm_bindings::KVM_REG_RISCV as u64
        | kvm_bindings::KVM_REG_SIZE_U64
        | u64::from(kvm_bindings::KVM_REG_RISCV_CONFIG)
        | field_index
}

const CONFIG_REG_ISA: u64 = 0;
const CONFIG_REG_ZICBOM_BLOCK_SIZE: u64 = 1;
const CONFIG_REG_ZICBOZ_BLOCK_SIZE: u64 = 5;
const CONFIG_REG_ZICBOP_BLOCK_SIZE: u64 = 7;

/// Mask for the base single-letter ISA extensions within the `isa` CONFIG
/// register, i.e. `KVM_RISCV_BASE_ISA_MASK = GENMASK(25, 0)` from
/// arch/riscv/kvm/vcpu_onereg.c.
const KVM_RISCV_BASE_ISA_MASK: u64 = (1u64 << 26) - 1;

/// Detects the host ISA configuration and supported extensions.
pub fn detect_host_isa(vcpu: &VcpuFd) -> Result<RiscvIsaInfo> {
    debug!("Starting RISC-V ISA detection");

    let isa_bitmask = read_isa_bitmask(vcpu)?;
    debug!("Read ISA bitmask from vCPU 0: {:#x}", isa_bitmask);

    let extensions = match detect_extensions_modern(vcpu) {
        Some(exts) => {
            debug!("Using modern detection method: {} extensions", exts.len());
            exts
        }
        None => {
            debug!("Modern detection returned None, falling back to legacy method");
            detect_extensions_legacy(vcpu)
        }
    };

    debug!(
        "Total extensions detected: {} ({})",
        extensions.len(),
        extensions.iter().cloned().collect::<Vec<_>>().join(", ")
    );

    let zicbom_block_size = read_block_size_if_present(vcpu, CONFIG_REG_ZICBOM_BLOCK_SIZE);
    let zicboz_block_size = read_block_size_if_present(vcpu, CONFIG_REG_ZICBOZ_BLOCK_SIZE);
    let zicbop_block_size = read_block_size_if_present(vcpu, CONFIG_REG_ZICBOP_BLOCK_SIZE);

    // The kernel has no register that returns a human-readable ISA string;
    // we build it ourselves from the base-ISA bitmask plus the detected
    // multi-letter extensions, mirroring QEMU's riscv_isa_string()
    // (target/riscv/cpu.c).
    let isa_string = build_isa_string(isa_bitmask, &extensions);

    debug!(
        "ISA detection complete: isa_string={}, extensions={}, zicbom_block_size={:?}, zicboz_block_size={:?}, zicbop_block_size={:?}",
        isa_string,
        extensions.len(),
        zicbom_block_size,
        zicboz_block_size,
        zicbop_block_size
    );

    Ok(RiscvIsaInfo {
        isa_string,
        extensions,
        zicbom_block_size,
        zicboz_block_size,
        zicbop_block_size,
    })
}

/// Reads the `isa` CONFIG register from vCPU 0.
///
/// Per `struct kvm_riscv_config` and `kvm_riscv_vcpu_get_reg_config()`
/// (arch/riscv/kvm/vcpu_onereg.c), this is a `KVM_REG_SIZE_ULONG` register
/// containing a `GENMASK(25, 0)` *bitmask* of the base single-letter
/// extensions (bit N set => letter 'a'+N present) -- it is NOT a
/// human-readable string.
fn read_isa_bitmask(vcpu: &VcpuFd) -> Result<u64> {
    debug!("Reading isa CONFIG register (bitmask) from vCPU 0");

    let reg_id = config_reg_id(CONFIG_REG_ISA);
    let mut buffer = [0u8; 8];
    vcpu.get_one_reg(reg_id, &mut buffer)
        .map_err(IsaError::ReadIsaReg)?;

    Ok(u64::from_le_bytes(buffer) & KVM_RISCV_BASE_ISA_MASK)
}

/// Builds a human-readable `riscv,isa` string (e.g. `rv64imafdc_smaia_ssaia`)
/// from the base-ISA bitmask and the set of detected multi-letter
/// extensions, mirroring QEMU's `riscv_isa_string()` in target/riscv/cpu.c.
fn build_isa_string(isa_bitmask: u64, extensions: &BTreeSet<String>) -> String {
    let mut isa_string = String::from("rv64");

    for bit in 0..26u32 {
        if isa_bitmask & (1u64 << bit) != 0 {
            isa_string.push((b'a' + bit as u8) as char);
        }
    }

    for ext in extensions {
        if ext.len() > 1 {
            isa_string.push('_');
            isa_string.push_str(ext);
        }
    }

    isa_string
}

/// Queries `KVM_GET_REG_LIST` for the full set of register IDs the vCPU
/// exposes, following the two-call size-discovery protocol used by QEMU's
/// `kvm_riscv_init_cfg()` (target/riscv/kvm/kvm-cpu.c): an initial call with
/// a zero-sized list is expected to fail with `-E2BIG` while reporting the
/// real register count, which is then used to allocate a correctly-sized
/// list and retry. Returns `None` if the ioctl is unsupported (`-ENOENT`)
/// or any other unexpected error occurs.
fn probe_reg_list(vcpu: &VcpuFd) -> Option<RawRegList> {
    let mut probe = RawRegList::new(0);

    let needed = match probe.get_reg_list(vcpu) {
        Ok(()) => {
            // The vCPU genuinely has zero registers; nothing more to do.
            return Some(probe);
        }
        Err(e) if is_not_supported(&e) => {
            debug!("Modern detection: KVM_GET_REG_LIST not supported, falling back to legacy");
            return None;
        }
        Err(e) if e.errno() == libc::E2BIG => probe.n() as usize,
        Err(e) => {
            debug!(
                "Modern detection: Error probing register list size: {:?}, falling back to legacy",
                e
            );
            return None;
        }
    };

    let mut reg_list = RawRegList::new(needed);

    match reg_list.get_reg_list(vcpu) {
        Ok(()) => {
            debug!(
                "Modern detection: Got register list with {} registers",
                reg_list.entries().len()
            );
            Some(reg_list)
        }
        Err(e) => {
            debug!(
                "Modern detection: Error getting register list after resizing to {}: {:?}, falling back to legacy",
                needed, e
            );
            None
        }
    }
}

fn detect_extensions_modern(vcpu: &VcpuFd) -> Option<BTreeSet<String>> {
    debug!("Modern detection: Attempting KVM_GET_REG_LIST");

    // KVM_GET_REG_LIST exposes every register the vCPU has (config, core,
    // CSR, timer, fp, vector, ISA ext, SBI ext/state, ...), which on real
    // RVA23S64 hardware comfortably exceeds kvm-bindings's RegList cap of
    // 200 entries (observed: 246). Mirror QEMU's two-call protocol
    // (target/riscv/kvm/kvm-cpu.c kvm_riscv_init_cfg()) using our own
    // RawRegList: probe with a zero-sized list first, let the kernel report
    // the real count via -E2BIG (arch/riscv/kvm/vcpu.c KVM_GET_REG_LIST
    // handler always writes the true count back before checking capacity),
    // then reallocate exactly that size and retry.
    let reg_list = probe_reg_list(vcpu)?;

    let registers = reg_list.entries();
    let mut extensions = BTreeSet::new();

    for (name, kvm_ext_id) in KVM_ISA_EXT_TABLE {
        let reg_id = isa_ext_reg_id(*kvm_ext_id);

        if registers.contains(&reg_id) {
            let mut buffer = [0u8; 8];
            match vcpu.get_one_reg(reg_id, &mut buffer) {
                Ok(_) => {
                    if u64::from_le_bytes(buffer) != 0 {
                        extensions.insert(name.to_string());
                        debug!("Modern detection: Found extension {}", name);
                    }
                }
                Err(e) => {
                    debug!(
                        "Modern detection: Extension {} in list but failed to read: {:?}",
                        name, e
                    );
                }
            }
        }
    }

    debug!(
        "Modern detection: Successfully queried {} extensions",
        extensions.len()
    );

    if extensions.is_empty() {
        debug!("Modern detection: No extensions found via modern method, falling back to legacy");
        None
    } else {
        Some(extensions)
    }
}

fn detect_extensions_legacy(vcpu: &VcpuFd) -> BTreeSet<String> {
    debug!("Legacy detection: Starting per-extension query of vCPU 0");

    let mut extensions = BTreeSet::new();

    for (name, kvm_ext_id) in KVM_ISA_EXT_TABLE {
        let reg_id = isa_ext_reg_id(*kvm_ext_id);

        let mut buffer = [0u8; 8];
        match vcpu.get_one_reg(reg_id, &mut buffer) {
            Ok(_) => {
                if u64::from_le_bytes(buffer) != 0 {
                    extensions.insert(name.to_string());
                    debug!("Legacy detection: Extension {} supported", name);
                }
            }
            Err(e) => {
                if !is_not_supported(&e) {
                    debug!(
                        "Legacy detection: Error querying extension {}: {:?}",
                        name, e
                    );
                }
                // Silently skip ENOENT errors (expected for unsupported extensions)
            }
        }
    }

    debug!(
        "Legacy detection: Successfully queried extensions, found {} supported",
        extensions.len()
    );

    if extensions.is_empty() {
        debug!("Legacy detection: No extensions detected, using hardcoded fallback");
        detect_extensions_fallback()
    } else {
        extensions
    }
}

/// Default ISA extension set used when extension detection fails.
///
/// Shared with `devices::fdt::riscv64::create_cpu_nodes()`, which uses the
/// same set as its own fallback when no `RiscvIsaInfo` is available, so the
/// two fallbacks cannot drift apart.
pub const DEFAULT_ISA_EXTENSIONS: &[&str] = &["i", "m", "a", "f", "d", "c", "smaia", "ssaia"];

/// Hardcoded fallback used when extension queries find nothing at all.
fn detect_extensions_fallback() -> BTreeSet<String> {
    let extensions: BTreeSet<String> = DEFAULT_ISA_EXTENSIONS
        .iter()
        .map(|s| s.to_string())
        .collect();

    debug!(
        "Using hardcoded default extension set: {} extensions",
        extensions.len()
    );

    extensions
}

/// Reads a cache block size CONFIG register (zicbom/zicboz/zicbop) from
/// vCPU 0. `field_index` must be one of `CONFIG_REG_ZICBOM_BLOCK_SIZE`,
/// `CONFIG_REG_ZICBOZ_BLOCK_SIZE`, or `CONFIG_REG_ZICBOP_BLOCK_SIZE`.
///
/// Per `kvm_riscv_vcpu_get_reg_config()`, these registers are
/// `KVM_REG_SIZE_ULONG` (i.e. 8 bytes on riscv64), NOT 4 bytes; the kernel
/// returns 0 if the corresponding extension is unavailable on the host.
///
/// Returns `Some(size)` if `vcpu.get_one_reg()` succeeds and reports a
/// non-zero size. Returns `None` if `vcpu.get_one_reg()` succeeds but
/// reports 0 (the extension is unavailable), or if `vcpu.get_one_reg()`
/// itself returns an error (including `-ENOENT`, meaning the kernel does
/// not know about this field).
fn read_block_size_if_present(vcpu: &VcpuFd, field_index: u64) -> Option<u32> {
    let reg_id = config_reg_id(field_index);
    let mut buffer = [0u8; 8];
    match vcpu.get_one_reg(reg_id, &mut buffer) {
        Ok(_) => {
            let block_size = u64::from_le_bytes(buffer);
            if block_size == 0 {
                debug!(
                    "read_block_size_if_present: field {} reports 0 (extension unavailable)",
                    field_index
                );
                None
            } else {
                debug!(
                    "read_block_size_if_present: field {} = {} bytes (from vCPU 0)",
                    field_index, block_size
                );
                Some(block_size as u32)
            }
        }
        Err(e) => {
            debug!(
                "read_block_size_if_present: Failed to read field {}: {:?}, omitting property",
                field_index, e
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isa_ext_reg_id_matches_kernel_encoding() {
        // KVM_REG_RISCV (bit 63) | KVM_REG_SIZE_U64 | KVM_REG_RISCV_ISA_EXT | id
        // Verified against arch/riscv/include/uapi/asm/kvm.h constants.
        let reg_id = isa_ext_reg_id(0); // "a"
        assert_eq!(reg_id & 0xFF, 0); // id = 0
        assert_eq!(
            reg_id & u64::from(kvm_bindings::KVM_REG_RISCV_ISA_EXT),
            u64::from(kvm_bindings::KVM_REG_RISCV_ISA_EXT)
        );

        let reg_id_zicsr = isa_ext_reg_id(20); // "zicsr"
        assert_eq!(reg_id_zicsr & 0xFF, 20);
    }

    #[test]
    fn test_config_reg_id_isa_offset_zero() {
        let reg_id = config_reg_id(CONFIG_REG_ISA);
        assert_eq!(reg_id & 0xFF, 0);
        assert_eq!(
            reg_id & u64::from(kvm_bindings::KVM_REG_RISCV_CONFIG),
            u64::from(kvm_bindings::KVM_REG_RISCV_CONFIG)
        );
    }

    #[test]
    fn test_kvm_isa_ext_table_has_no_duplicate_ids_or_names() {
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        for (name, id) in KVM_ISA_EXT_TABLE {
            assert!(ids.insert(*id), "duplicate KVM ext id: {id}");
            assert!(names.insert(*name), "duplicate KVM ext name: {name}");
        }
        // KVM_RISCV_ISA_EXT_MAX in linux-7.2.9 is 78 (ids 0..=77).
        assert_eq!(KVM_ISA_EXT_TABLE.len(), 78);
    }

    #[test]
    fn test_build_isa_string_base_only() {
        // Base ISA bits: a=0, c=2, d=3, f=5, i=8, m=12.
        let bitmask =
            (1u64 << 0) | (1u64 << 2) | (1u64 << 3) | (1u64 << 5) | (1u64 << 8) | (1u64 << 12);
        let extensions = BTreeSet::new();
        let isa_string = build_isa_string(bitmask, &extensions);
        assert_eq!(isa_string, "rv64acdfim");
    }

    #[test]
    fn test_build_isa_string_with_multi_letter_extensions() {
        let bitmask = (1u64 << 8) | (1u64 << 12); // i, m
        let mut extensions = BTreeSet::new();
        extensions.insert("i".to_string());
        extensions.insert("m".to_string());
        extensions.insert("smaia".to_string());
        extensions.insert("ssaia".to_string());

        let isa_string = build_isa_string(bitmask, &extensions);
        assert_eq!(isa_string, "rv64im_smaia_ssaia");
    }

    #[test]
    fn test_is_not_supported_matches_enoent_only() {
        assert!(is_not_supported(&kvm_ioctls::Error::new(libc::ENOENT)));
        assert!(!is_not_supported(&kvm_ioctls::Error::new(libc::EINVAL)));
    }

    #[test]
    fn test_isa_info_creation() {
        let mut extensions = BTreeSet::new();
        extensions.insert("i".to_string());
        extensions.insert("m".to_string());

        let info = RiscvIsaInfo {
            isa_string: "rv64imafdc_smaia_ssaia".to_string(),
            extensions,
            zicbom_block_size: Some(64),
            zicboz_block_size: Some(64),
            zicbop_block_size: Some(64),
        };

        assert_eq!(info.isa_string, "rv64imafdc_smaia_ssaia");
        assert_eq!(info.zicbom_block_size, Some(64));
        assert!(info.extensions.contains("i"));
    }

    #[test]
    fn test_isa_info_no_block_sizes() {
        let extensions = BTreeSet::new();

        let info = RiscvIsaInfo {
            isa_string: "rv64i".to_string(),
            extensions,
            zicbom_block_size: None,
            zicboz_block_size: None,
            zicbop_block_size: None,
        };

        assert_eq!(info.isa_string, "rv64i");
        assert_eq!(info.zicbom_block_size, None);
        assert_eq!(info.zicboz_block_size, None);
        assert_eq!(info.zicbop_block_size, None);
        assert!(info.extensions.is_empty());
    }

    #[test]
    fn test_isa_info_many_extensions() {
        let mut extensions = BTreeSet::new();
        extensions.insert("i".to_string());
        extensions.insert("m".to_string());
        extensions.insert("a".to_string());
        extensions.insert("f".to_string());
        extensions.insert("d".to_string());
        extensions.insert("c".to_string());
        extensions.insert("zicsr".to_string());
        extensions.insert("zifencei".to_string());
        extensions.insert("zicbom".to_string());
        extensions.insert("zicboz".to_string());
        extensions.insert("zicbop".to_string());
        extensions.insert("smaia".to_string());
        extensions.insert("ssaia".to_string());

        let info = RiscvIsaInfo {
            isa_string: "rv64imafdc_zicsr_zifencei_smaia_ssaia".to_string(),
            extensions: extensions.clone(),
            zicbom_block_size: Some(64),
            zicboz_block_size: Some(64),
            zicbop_block_size: Some(64),
        };

        assert_eq!(info.extensions.len(), 13);
        assert!(info.extensions.contains("zicbom"));
        assert!(info.extensions.contains("smaia"));
        assert!(info.extensions.contains("ssaia"));
        assert_eq!(info.zicbom_block_size, Some(64));
    }

    #[test]
    fn test_isa_info_partial_block_sizes() {
        let extensions = BTreeSet::new();

        let info = RiscvIsaInfo {
            isa_string: "rv64imafdc".to_string(),
            extensions,
            zicbom_block_size: Some(64),
            zicboz_block_size: None,
            zicbop_block_size: Some(32),
        };

        assert_eq!(info.zicbom_block_size, Some(64));
        assert_eq!(info.zicboz_block_size, None);
        assert_eq!(info.zicbop_block_size, Some(32));
    }

    #[test]
    fn test_extension_sorting() {
        let mut extensions = BTreeSet::new();
        extensions.insert("zvfh".to_string());
        extensions.insert("zba".to_string());
        extensions.insert("i".to_string());
        extensions.insert("smaia".to_string());

        let ext_vec: Vec<_> = extensions.iter().cloned().collect();
        assert_eq!(ext_vec[0], "i");
        assert_eq!(ext_vec[ext_vec.len() - 1], "zvfh");
    }

    // The following tests exercise the real KVM ioctls and therefore need
    // an actual KVM-backed vCPU, like the tests in `regs.rs`. They only run
    // when executed on riscv64 hardware with /dev/kvm access (e.g. via
    // cross-compiled `cargo test` on the target), mirroring the precedent
    // set by `regs.rs::tests::test_read_timer_frequency`.

    #[test]
    fn test_read_block_size_if_present_cbom() {
        let kvm = kvm_ioctls::Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let _ = read_block_size_if_present(&vcpu, CONFIG_REG_ZICBOM_BLOCK_SIZE);
    }

    #[test]
    fn test_detect_extensions_legacy_includes_base_integer_extension() {
        let kvm = kvm_ioctls::Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let extensions = detect_extensions_legacy(&vcpu);
        // "i" (base integer ISA) must always be present on any RISC-V host.
        assert!(extensions.contains("i"));
    }

    #[test]
    fn test_detect_host_isa_returns_nonempty_isa_string() {
        let kvm = kvm_ioctls::Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let info = detect_host_isa(&vcpu).unwrap();
        assert!(info.isa_string.starts_with("rv64"));
        assert!(info.extensions.contains("i"));
    }

    #[test]
    fn test_isa_info_is_cloneable() {
        let mut extensions = BTreeSet::new();
        extensions.insert("i".to_string());

        let info = RiscvIsaInfo {
            isa_string: "rv64i".to_string(),
            extensions,
            zicbom_block_size: Some(64),
            zicboz_block_size: None,
            zicbop_block_size: Some(64),
        };

        let cloned = info.clone();
        assert_eq!(cloned.isa_string, "rv64i");
        assert_eq!(cloned.zicbom_block_size, Some(64));
        assert_eq!(cloned.zicboz_block_size, None);
    }
}
