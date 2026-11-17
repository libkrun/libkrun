// SPDX-License-Identifier: Apache-2.0

//! Translate saved arm64 KVM execution back to Hypervisor.framework.
//! RAM and virtio state are unchanged. Register IDs and interrupt state use
//! the Linux KVM UAPI; only guests whose original Mac board was retained can
//! currently return. A native Linux board needs separate device placement.

use std::collections::BTreeMap;

use hvf::HvfVcpuState;

use crate::arm_board::BoardLayout;
use crate::{CheckpointSections, VmCheckpoint, vstate::VmState};

const SYS_BASE: u64 = 0x6030_0000_0013_0000;
const CORE_U64: u64 = 0x6030_0000_0010_0000;
const CORE_U32: u64 = 0x6020_0000_0010_0000;
const CORE_U128: u64 = 0x6040_0000_0010_0000;
// PMCR_EL0 is S3_3_C9_C12_0; S3_1_C0_C0_1 (0xc801) is CLIDR_EL1.
const PMCR_EL0: u64 = SYS_BASE | 0xdce0;
const PAC_ENABLES: u64 = (1 << 31) | (1 << 30) | (1 << 27) | (1 << 13);
const SYS_REGS: &[u16] = &[
    0xc080, 0xc102, 0xc100, 0xc101, 0xc510, 0xc518, 0xc600, 0xc681, 0xde82, 0xc684, 0xde83, 0xc082,
    0xc288, 0xc289, 0xc290, 0xc300, 0xc3a0, 0xd000, 0x8012, 0xc708,
];
const REDIST: &[u32] = &[
    0x10080, 0x10400, 0x10404, 0x10408, 0x1040c, 0x10410, 0x10414, 0x10418, 0x1041c, 0x10c04,
    0x10100, 0x10200, 0x10300,
];
type GicRegisters = Vec<(u32, u64)>;
const ICC: &[u32] = &[
    0xc665, 0xc230, 0xc643, 0xc663, 0xc644, 0xc648, 0xc664, 0xc666, 0xc667,
];

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or("KVM arm64 checkpoint state is truncated")?;
        let data = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(data)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u128(&mut self) -> Result<u128, String> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }
    fn count(&mut self, width: usize) -> Result<usize, String> {
        let count = self.u32()? as usize;
        if count > (self.bytes.len() - self.pos) / width {
            return Err("KVM arm64 checkpoint register list is truncated".into());
        }
        Ok(count)
    }
    fn finish(&self) -> Result<(), String> {
        if self.pos != self.bytes.len() {
            return Err("Unexpected trailing KVM state".into());
        }
        Ok(())
    }
}

struct KvmVm {
    dist: BTreeMap<u32, u32>,
    redist: BTreeMap<u64, u32>,
    icc: BTreeMap<u64, u64>,
    board: BoardLayout,
}
fn insert<K: Ord, V>(map: &mut BTreeMap<K, V>, key: K, value: V) -> Result<(), String> {
    if map.insert(key, value).is_some() {
        return Err("Duplicate KVM state register".into());
    }
    Ok(())
}
impl KvmVm {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let mut dist = BTreeMap::new();
        for _ in 0..r.count(8)? {
            let k = r.u32()?;
            insert(&mut dist, k, r.u32()?)?;
        }
        let mut redist = BTreeMap::new();
        for _ in 0..r.count(12)? {
            let k = r.u64()?;
            insert(&mut redist, k, r.u32()?)?;
        }
        let mut icc = BTreeMap::new();
        for _ in 0..r.count(16)? {
            let k = r.u64()?;
            insert(&mut icc, k, r.u64()?)?;
        }
        // Both GICv2 sections must exist and be empty for a portable Mac board.
        if r.u32()? != 0 || r.u32()? != 0 {
            return Err("A GICv2 checkpoint cannot return to Hypervisor.framework".into());
        }
        let len = r.u32()? as usize;
        let board = BoardLayout::decode(r.take(len)?)?;
        r.finish()?;
        Ok(Self {
            dist,
            redist,
            icc,
            board,
        })
    }
    fn distributor(&self) -> Result<Vec<(u32, u64)>, String> {
        let mut out = Vec::new();
        for (&offset, &value) in &self.dist {
            if (0x6100..0x8000).contains(&offset) {
                if offset % 8 != 0 {
                    continue;
                }
                let high = self
                    .dist
                    .get(&(offset + 4))
                    .ok_or("Missing IROUTER high half")?;
                out.push((offset, u64::from(value) | (u64::from(*high) << 32)));
            } else if offset == 0
                || (0x84..0x100).contains(&offset)
                || (0x104..0x180).contains(&offset)
                || (0x204..0x280).contains(&offset)
                || (0x304..0x380).contains(&offset)
                || (0x420..0x800).contains(&offset)
                || (0xc08..0xd00).contains(&offset)
            {
                out.push((offset, u64::from(value)));
            } else if offset != 0x10 {
                return Err(format!("Unsupported KVM distributor register {offset:#x}"));
            }
        }
        if !self.dist.contains_key(&0) {
            return Err("Missing GIC distributor control".into());
        }
        Ok(out)
    }
    fn per_cpu(&self, index: usize) -> Result<(GicRegisters, GicRegisters), String> {
        let affinity = (index as u64) << 32;
        // SGIs are always edge-triggered (GICR_ICFGR0 is RAO/WI for
        // Int_config[1]). KVM reports 0xaaaaaaaa; HVF's state API reports
        // zero and ignores writes. This is not guest-writable state.
        if self.redist.get(&(affinity | 0x10c00)) != Some(&0xaaaa_aaaa) {
            return Err("Unexpected KVM SGI trigger configuration".into());
        }
        if self.redist.get(&affinity).copied().unwrap_or(0) & 1 != 0 {
            return Err("A checkpoint with enabled GIC LPIs cannot return to this Mac".into());
        }
        if self.redist.get(&(affinity | 0x14)).copied().unwrap_or(0) & 2 != 0 {
            return Err("A sleeping GIC redistributor cannot return to this Mac".into());
        }
        let redist = REDIST
            .iter()
            .map(|&id| {
                self.redist
                    .get(&(affinity | u64::from(id)))
                    .copied()
                    .map(|v| (id, u64::from(v)))
                    .ok_or_else(|| format!("Missing GIC redistributor {id:#x}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (&id, &value) in &self.icc {
            if id >> 32 == index as u64 && !ICC.contains(&(id as u32)) && value != 0 {
                return Err(format!("Unsupported active GIC CPU register {id:#x}"));
            }
        }
        let icc = ICC
            .iter()
            .map(|&id| {
                self.icc
                    .get(&(affinity | u64::from(id)))
                    .copied()
                    .or_else(|| matches!(id, 0xc644 | 0xc648).then_some(0))
                    .map(|v| (id, v))
                    .ok_or_else(|| format!("Missing GIC CPU register {id:#x}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((redist, icc))
    }
}

struct KvmVcpu {
    regs: BTreeMap<u64, u128>,
}
impl KvmVcpu {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        if r.u32()? != 0 {
            return Err("Only runnable KVM vCPUs can return to a Mac".into());
        }
        let mut regs = BTreeMap::new();
        for _ in 0..r.count(24)? {
            let id = r.u64()?;
            insert(&mut regs, id, r.u128()?)?;
        }
        r.finish()?;
        Ok(Self { regs })
    }
    fn get(&self, id: u64) -> Result<u128, String> {
        self.regs
            .get(&id)
            .copied()
            .ok_or_else(|| format!("Missing KVM register {id:#x}"))
    }
    fn get64(&self, id: u64) -> Result<u64, String> {
        u64::try_from(self.get(id)?).map_err(|_| format!("KVM register {id:#x} exceeds its width"))
    }
    fn sys(&self, id: u16) -> Result<u64, String> {
        self.get64(SYS_BASE | u64::from(id))
    }
    fn translate(
        &self,
        index: usize,
        vm: &KvmVm,
        counter: u64,
        offset: u64,
    ) -> Result<HvfVcpuState, String> {
        if self.sys(0xc080)? & PAC_ENABLES != 0 {
            return Err("Pointer authentication in use cannot cross to Apple's algorithm".into());
        }
        if self.sys(0xc082)? & ((3 << 16) | (3 << 24)) != 0 {
            return Err("SVE or SME execution cannot return to this Mac".into());
        }
        if self.regs.get(&PMCR_EL0).copied().unwrap_or(0) & 1 != 0 {
            return Err("Enabled KVM performance counters cannot return to this Mac".into());
        }
        if self.regs.get(&(SYS_BASE | 0xdf11)).copied().unwrap_or(0) & 1 != 0 {
            return Err("An enabled KVM physical timer cannot return to this Mac".into());
        }
        if !matches!(self.get64(CORE_U64 | 66)? & 0xf, 0 | 4 | 5) {
            return Err("Only EL0/EL1 execution can return to this Mac".into());
        }
        let mpidr = self.sys(0xc005)?;
        if mpidr & 0x0000_00ff_00ff_ffff != index as u64 {
            return Err("KVM vCPU affinity does not match the saved Mac board".into());
        }
        // Debug address/control registers are not part of the HVF restore ABI.
        // Refuse enabled hardware break/watchpoints rather than silently lose them.
        for i in 0..16u16 {
            for id in [0x8005 + i * 8, 0x8007 + i * 8] {
                if self
                    .regs
                    .get(&(SYS_BASE | u64::from(id)))
                    .copied()
                    .unwrap_or(0)
                    & 1
                    != 0
                {
                    return Err("Enabled KVM hardware breakpoints cannot return to this Mac".into());
                }
            }
        }
        let mut gp = [0; 31];
        for (i, v) in gp.iter_mut().enumerate() {
            *v = self.get64(CORE_U64 | (i as u64 * 2))?;
        }
        let mut simd = [0; 32];
        for (i, v) in simd.iter_mut().enumerate() {
            *v = self.get(CORE_U128 | (84 + i as u64 * 4))?;
        }
        let mut sys = vec![
            (0xc208, self.get64(CORE_U64 | 62)?), // SP_EL0
            (0xe208, self.get64(CORE_U64 | 68)?), // SP_EL1
            (0xc201, self.get64(CORE_U64 | 70)?), // ELR_EL1
            (0xc200, self.get64(CORE_U64 | 72)?), // SPSR_EL1
        ];
        for &reg in SYS_REGS {
            sys.push((reg, self.sys(reg)?));
        }
        let ctl = self.sys(0xdf19)?;
        // KVM's UAPI deliberately swaps the CNT and CVAL encodings. An
        // immediate timer interrupt lets the portable kernel observe the
        // destination's counter frequency before returning to userspace.
        sys.push((
            0xdf1a,
            if ctl & 1 != 0 {
                counter
            } else {
                self.sys(0xdf02)?
            },
        ));
        sys.push((0xdf19, ctl));
        let (gic_redist, gic_icc) = vm.per_cpu(index)?;
        Ok(HvfVcpuState {
            gp,
            pc: self.get64(CORE_U64 | 64)?,
            cpsr: self.get64(CORE_U64 | 66)?,
            fpsr: self.get64(CORE_U32 | 212)?,
            fpcr: self.get64(CORE_U32 | 213)?,
            simd,
            sys,
            gic_redist,
            gic_icc,
            vtimer_offset: offset,
            guest_counter: counter,
        })
    }
}

pub(crate) fn import(sections: CheckpointSections<'_>) -> Result<VmCheckpoint, String> {
    let vm = KvmVm::parse(sections.vm)?;
    let count = sections.vcpus.len();
    if count == 0 || count > 16 || vm.board.cpu_slots < count as u32 || vm.board.cpu_slots > 16 {
        return Err("The saved Mac board must have 1 to 16 CPU slots".into());
    }
    if sections.ioapic.is_some() || sections.cpu_growth.is_some() {
        return Err("Unsupported KVM interrupt or CPU-growth state".into());
    }
    let cpus = sections
        .vcpus
        .iter()
        .map(|b| KvmVcpu::parse(b))
        .collect::<Result<Vec<_>, _>>()?;
    let counter = cpus
        .iter()
        .map(|c| c.sys(0xdf1a))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .unwrap();
    // All vCPUs share the same epoch; taking this once avoids per-CPU skew.
    let offset = unsafe { hvf::mach_absolute_time() }.wrapping_sub(counter);
    let vcpu_states = cpus
        .iter()
        .enumerate()
        .map(|(i, c)| c.translate(i, &vm, counter, offset))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VmCheckpoint {
        vm_state: VmState {
            gic_distributor: vm.distributor()?,
            board: Some(vm.board),
        },
        vcpu_states,
        devices: sections.devices,
        ioapic: None,
        cpu_growth: None,
        memory_growth: sections.memory_growth,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (KvmVcpu, KvmVm) {
        let mut regs = BTreeMap::new();
        for i in 0..31 {
            regs.insert(CORE_U64 | (i * 2), u128::from(i + 100));
        }
        for i in 0..32 {
            regs.insert(CORE_U128 | (84 + i * 4), (u128::from(i + 1) << 64) | 0xff);
        }
        for n in [62, 64, 66, 68, 70, 72] {
            regs.insert(CORE_U64 | n, u128::from(0x1000 + n));
        }
        regs.insert(CORE_U64 | 66, 0x3c5);
        regs.insert(CORE_U32 | 212, 0x10);
        regs.insert(CORE_U32 | 213, 0x20);
        for &reg in SYS_REGS {
            regs.insert(SYS_BASE | u64::from(reg), 0);
        }
        regs.insert(SYS_BASE | 0xc005, 0x8000_0000);
        regs.insert(SYS_BASE | 0xdf19, 1);
        regs.insert(SYS_BASE | 0xdf1a, 5000);
        regs.insert(SYS_BASE | 0xdf02, 9000);
        let vm = KvmVm {
            dist: [(0, 0x52), (0x6100, 0x12345678), (0x6104, 0x87654321)].into(),
            redist: REDIST
                .iter()
                .map(|&id| (u64::from(id), id))
                .chain([(0x10c00, 0xaaaa_aaaa)])
                .collect(),
            icc: ICC
                .iter()
                .map(|&id| (u64::from(id), u64::from(id)))
                .collect(),
            board: BoardLayout {
                gic_dist_base: 0x09df_0000,
                gic_dist_size: 0x10000,
                gic_redist_base: 0x09e0_0000,
                gic_redist_size: 0x20_0000,
                cpu_slots: 16,
                legacy: vec![],
                first_virtio_addr: 0x0a00_3000,
                first_virtio_intid: 34,
            },
        };
        (KvmVcpu { regs }, vm)
    }

    #[test]
    fn restores_core_simd_timer_and_interrupt_state() {
        let (cpu, vm) = fixture();
        let state = cpu.translate(0, &vm, 6000, 123).unwrap();
        assert_eq!(state.gp[30], 130);
        assert_eq!(state.pc, 0x1040);
        assert_eq!(state.simd[31], (32u128 << 64) | 0xff);
        assert_eq!((state.fpsr, state.fpcr), (0x10, 0x20));
        assert!(state.sys.contains(&(0xc208, 0x103e)));
        assert!(state.sys.contains(&(0xe208, 0x1044)));
        assert!(state.sys.contains(&(0xdf1a, 6000)));
        assert_eq!((state.guest_counter, state.vtimer_offset), (6000, 123));
        assert_eq!(state.gic_icc.first(), Some(&(0xc665, 0xc665)));
        assert_eq!(state.gic_icc.last(), Some(&(0xc667, 0xc667)));
        assert_eq!(state.gic_redist.last(), Some(&(0x10300, 0x10300)));
        assert_eq!(
            vm.distributor().unwrap(),
            vec![(0, 0x52), (0x6100, 0x8765432112345678)]
        );
    }

    #[test]
    fn disabled_timer_keeps_compare_and_missing_high_half_is_rejected() {
        let (mut cpu, mut vm) = fixture();
        cpu.regs.insert(SYS_BASE | 0xdf19, 0);
        assert!(
            cpu.translate(0, &vm, 6000, 123)
                .unwrap()
                .sys
                .contains(&(0xdf1a, 9000))
        );
        vm.dist.remove(&0x6104);
        assert!(vm.distributor().unwrap_err().contains("high half"));
    }

    #[test]
    fn cache_identification_is_not_performance_counter_control() {
        let (mut cpu, vm) = fixture();
        // CLIDR_EL1 from a nested M4 KVM capture (S3_1_C0_C0_1).
        cpu.regs.insert(SYS_BASE | 0xc801, 0x0200_0021);
        // PMCR_EL0 is S3_3_C9_C12_0. An absent or disabled PMU is safe;
        // cache identification must not be mistaken for its global enable.
        cpu.translate(0, &vm, 6000, 123).unwrap();
        cpu.regs.insert(SYS_BASE | 0xdce0, 0x4101_3000);
        cpu.translate(0, &vm, 6000, 123).unwrap();
        cpu.regs.insert(SYS_BASE | 0xdce0, 0x4101_3001);
        assert!(
            cpu.translate(0, &vm, 6000, 123)
                .unwrap_err()
                .contains("performance counters")
        );
    }

    #[test]
    fn active_unsupported_state_is_not_discarded() {
        for (reg, value, message) in [
            (0xc080, 1 << 31, "Pointer authentication"),
            (0xc082, 1 << 16, "SVE"),
            (0x8005, 1, "breakpoints"),
            (0xc005, 1, "affinity"),
        ] {
            let (mut cpu, vm) = fixture();
            cpu.regs.insert(SYS_BASE | reg, value);
            assert!(
                cpu.translate(0, &vm, 6000, 123)
                    .unwrap_err()
                    .contains(message)
            );
        }
        let (cpu, mut vm) = fixture();
        vm.redist.insert(0, 1);
        assert!(
            cpu.translate(0, &vm, 6000, 123)
                .unwrap_err()
                .contains("LPIs")
        );
    }

    #[test]
    fn malformed_register_tables_are_rejected() {
        let mut blob = vec![0; 4];
        blob.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(KvmVcpu::parse(&blob).is_err());
        let mut blob = vec![0; 4];
        blob.extend_from_slice(&2u32.to_le_bytes());
        for _ in 0..2 {
            blob.extend_from_slice(&CORE_U64.to_le_bytes());
            blob.extend_from_slice(&0u128.to_le_bytes());
        }
        assert!(KvmVcpu::parse(&blob).err().unwrap().contains("Duplicate"));
        let mut r = Reader::new(&[0; 3]);
        assert!(r.u32().is_err());
    }

    #[test]
    #[ignore = "requires a captured arm64 cloud checkpoint state via SMOL_KVM_RETURN_STATE"]
    fn captured_cloud_state_translates() {
        let raw = std::fs::read(std::env::var_os("SMOL_KVM_RETURN_STATE").unwrap()).unwrap();
        let mut tagged = crate::KVM_ARM_CHECKPOINT_TAG.to_vec();
        tagged.extend_from_slice(&raw);
        let state = VmCheckpoint::deserialize(&tagged).unwrap();
        assert_eq!(state.vcpu_states.len(), 1);
        assert_eq!(state.vm_state.board.as_ref().unwrap().cpu_slots, 16);
        assert!(state.vcpu_states[0].guest_counter > 0);
        assert!(!state.vcpu_states[0].gic_redist.is_empty());
    }

    #[test]
    #[ignore = "requires Hypervisor entitlements, an isolated test process, and SMOL_KVM_RETURN_STATE"]
    fn captured_cloud_state_is_accepted_by_hvf() {
        let raw = std::fs::read(std::env::var_os("SMOL_KVM_RETURN_STATE").unwrap()).unwrap();
        let mut tagged = crate::KVM_ARM_CHECKPOINT_TAG.to_vec();
        tagged.extend_from_slice(&raw);
        let state = VmCheckpoint::deserialize(&tagged).unwrap();
        assert_eq!(state.vcpu_states.len(), 1);
        let _vm = hvf::HvfVm::new(false).unwrap();
        let _gic = devices::legacy::HvfGicV3::new(u64::from(
            state.vm_state.board.as_ref().unwrap().cpu_slots,
        ))
        .unwrap();
        let cpu = hvf::HvfVcpu::new(0, false).unwrap();
        hvf::gic_restore_distributor(&state.vm_state.gic_distributor).unwrap();
        hvf::vcpu_restore_state(cpu.id(), &state.vcpu_states[0]).unwrap();
        let readback = hvf::vcpu_save_state(cpu.id()).unwrap();
        let expected = &state.vcpu_states[0];
        assert_eq!(readback.gp, expected.gp);
        assert_eq!(readback.pc, expected.pc);
        assert_eq!(readback.cpsr, expected.cpsr);
        assert_eq!(readback.simd, expected.simd);
        for &(id, value) in &expected.gic_redist {
            let actual = readback
                .gic_redist
                .iter()
                .find(|(r, _)| *r == id)
                .unwrap()
                .1;
            assert_eq!(actual, value, "redistributor register {id:#x}");
        }
        for &(id, value) in &expected.gic_icc {
            let actual = readback.gic_icc.iter().find(|(r, _)| *r == id).unwrap().1;
            if id == 0xc664 {
                assert_eq!(actual & 3, value & 3);
            } else {
                assert_eq!(actual, value, "ICC register {id:#x}");
            }
        }
        assert!(readback.guest_counter >= expected.guest_counter);
        unsafe {
            assert_eq!(
                hvf::bindings::hv_vcpu_destroy(cpu.id()),
                hvf::bindings::HV_SUCCESS
            );
            assert_eq!(hvf::bindings::hv_vm_destroy(), hvf::bindings::HV_SUCCESS);
        }
    }
}
