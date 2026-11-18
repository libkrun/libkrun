use super::*;

struct Cleanup(u64);
impl Drop for Cleanup {
    fn drop(&mut self) {
        unsafe {
            hv_vcpu_destroy(self.0);
            hv_vm_destroy();
        }
    }
}

fn cpu_with_gic() -> (HvfVcpu<'static>, Cleanup) {
    let _vm = HvfVm::new(false).unwrap();
    // Register snapshots include the hardware GIC CPU interface. Construct it
    // just as the VMM does, without booting a guest or touching any user VM.
    unsafe {
        let config: libloading::Symbol<unsafe extern "C" fn() -> hv_gic_config_t> =
            HVF.get(b"hv_gic_config_create").unwrap();
        let dist: libloading::Symbol<unsafe extern "C" fn(hv_gic_config_t, u64) -> hv_return_t> =
            HVF.get(b"hv_gic_config_set_distributor_base").unwrap();
        let redist: libloading::Symbol<unsafe extern "C" fn(hv_gic_config_t, u64) -> hv_return_t> =
            HVF.get(b"hv_gic_config_set_redistributor_base").unwrap();
        let create: libloading::Symbol<unsafe extern "C" fn(hv_gic_config_t) -> hv_return_t> =
            HVF.get(b"hv_gic_create").unwrap();
        let cfg = config();
        assert_eq!(dist(cfg, 0x0800_0000), HV_SUCCESS);
        assert_eq!(redist(cfg, 0x080a_0000), HV_SUCCESS);
        assert_eq!(create(cfg), HV_SUCCESS);
    }
    let cpu = HvfVcpu::new(0, false).unwrap();
    let cleanup = Cleanup(cpu.id());
    cpu.set_initial_state(0x8000_0000, 0).unwrap();
    (cpu, cleanup)
}

fn defer_read(cpu: &mut HvfVcpu, value: u64) {
    cpu.pending_mmio_read = Some(MmioRead {
        addr: 0x0900_0000,
        len: 8,
        srt: 0,
    });
    cpu.mmio_buf = value.to_le_bytes();
    cpu.pending_advance_pc = true;
}

#[test]
#[ignore = "requires Apple Silicon Hypervisor.framework; run explicitly with --ignored --test-threads=1"]
fn checkpoint_captures_the_completed_device_read() {
    let (mut cpu, _cleanup) = cpu_with_gic();
    cpu.write_reg(hv_reg_t_HV_REG_X0, 7).unwrap();
    defer_read(&mut cpu, 0x1234_5678_abcd_ef01);
    let checkpoint = cpu.save_state().unwrap();
    assert_eq!(checkpoint.gp[0], 0x1234_5678_abcd_ef01);
    assert_eq!(checkpoint.pc, 0x8000_0004);
    cpu.complete_pending_exit().unwrap();
    assert_eq!(cpu.read_reg(hv_reg_t_HV_REG_PC).unwrap(), checkpoint.pc);
}

#[test]
#[ignore = "requires Apple Silicon Hypervisor.framework; run explicitly with --ignored --test-threads=1"]
fn rewind_discards_newer_device_reads_and_timer_masks() {
    let (mut cpu, _cleanup) = cpu_with_gic();
    cpu.write_reg(hv_reg_t_HV_REG_X0, 7).unwrap();
    let checkpoint = cpu.save_state().unwrap();

    // The VM has run further and paused after a different MMIO instruction.
    defer_read(&mut cpu, 0xdead_beef);
    cpu.vtimer_masked = true;
    vcpu_set_vtimer_mask(cpu.id(), true).unwrap();
    cpu.restore_state(&checkpoint).unwrap();
    cpu.complete_pending_exit().unwrap();
    assert_eq!(cpu.read_reg(hv_reg_t_HV_REG_X0).unwrap(), checkpoint.gp[0]);
    assert_eq!(cpu.read_reg(hv_reg_t_HV_REG_PC).unwrap(), checkpoint.pc);
    let mut masked = true;
    assert_eq!(
        unsafe { hv_vcpu_get_vtimer_mask(cpu.id(), &mut masked) },
        HV_SUCCESS
    );
    assert!(
        !masked,
        "a later timer exit must not suppress the restored timer"
    );
    assert!(!cpu.vtimer_masked);
}

#[test]
#[ignore = "requires Apple Silicon Hypervisor.framework; run explicitly with --ignored --test-threads=1"]
fn rewind_replaces_distributor_interrupt_bits() {
    let (_cpu, _cleanup) = cpu_with_gic();
    // IRQs 40 and 41 occupy different bits in the same SPI register bank.
    // Rewind must remove later enable/pending/active bits, not union them
    // with the checkpoint as guest write-one-to-set semantics would do.
    for reg in [0x104, 0x204, 0x304] {
        assert_eq!(unsafe { (GIC_REGS.set_dist)(reg, 1 << 9) }, HV_SUCCESS);
    }
    let checkpoint = gic_save_distributor().unwrap();
    for reg in [0x104, 0x204, 0x304] {
        assert_eq!(unsafe { (GIC_REGS.set_dist)(reg, 1 << 8) }, HV_SUCCESS);
    }
    gic_restore_distributor(&checkpoint).unwrap();
    for reg in [0x104, 0x204, 0x304] {
        let mut actual = 0;
        assert_eq!(unsafe { (GIC_REGS.get_dist)(reg, &mut actual) }, HV_SUCCESS);
        let expected = checkpoint
            .iter()
            .find(|(r, _)| *r == u32::from(reg))
            .unwrap()
            .1;
        assert_eq!(actual, expected, "distributor register {reg:#x}");
    }
}

#[test]
#[ignore = "requires Apple Silicon Hypervisor.framework; run explicitly with --ignored --test-threads=1"]
fn rewind_replaces_private_interrupt_bits() {
    let (mut cpu, _cleanup) = cpu_with_gic();
    for reg in [0x10100, 0x10200, 0x10300] {
        assert_eq!(
            unsafe { (GIC_REGS.set_redist)(cpu.id(), reg, 1 << 27) },
            HV_SUCCESS
        );
    }
    let checkpoint = cpu.save_state().unwrap();
    for reg in [0x10100, 0x10200, 0x10300] {
        assert_eq!(
            unsafe { (GIC_REGS.set_redist)(cpu.id(), reg, 1 << 28) },
            HV_SUCCESS
        );
    }
    cpu.restore_state(&checkpoint).unwrap();
    for reg in [0x10100, 0x10200, 0x10300] {
        let mut actual = 0;
        assert_eq!(
            unsafe { (GIC_REGS.get_redist)(cpu.id(), reg, &mut actual) },
            HV_SUCCESS
        );
        let expected = checkpoint
            .gic_redist
            .iter()
            .find(|(r, _)| *r == reg)
            .unwrap()
            .1;
        assert_eq!(actual, expected, "redistributor register {reg:#x}");
    }
}

#[test]
#[ignore = "requires Apple Silicon Hypervisor.framework; run explicitly with --ignored --test-threads=1"]
fn restored_interrupt_wakes_a_guest_waiting_for_interrupt() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;
    let (mut cpu, _cleanup) = cpu_with_gic();
    // A masked guest IRQ still wakes WFI. HVC immediately afterwards returns
    // control to the test without requiring a guest exception-vector table.
    let size = host_page_size() as usize;
    let memory = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    assert_ne!(memory, libc::MAP_FAILED);
    unsafe {
        std::ptr::copy_nonoverlapping([0xd503207fu32, 0xd4000002].as_ptr(), memory.cast(), 2);
        assert_eq!(
            hv_vm_map(
                memory,
                0x8000_0000,
                size,
                u64::from(HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC)
            ),
            HV_SUCCESS
        );
    }
    for (reg, val) in [
        (0x84, 1 << 10),
        (0x104, 1 << 10),
        (0x428, 0xc0c0c0c0),
        (0xc08, 2 << 20),
        (0x6150, 0),
        (0, 3),
    ] {
        assert_eq!(unsafe { (GIC_REGS.set_dist)(reg, val) }, HV_SUCCESS);
    }
    for (reg, val) in [(50789, 7), (49712, 0xf0), (50791, 1)] {
        assert_eq!(
            unsafe { (GIC_REGS.set_icc)(cpu.id(), reg, val) },
            HV_SUCCESS
        );
    }
    let checkpoint = cpu.save_state().unwrap();
    let mut distributor = gic_save_distributor().unwrap();
    for scenario in [
        "no interrupt",
        "fresh edge",
        "edge after restore",
        "restored pending edge",
    ] {
        if scenario == "restored pending edge" {
            distributor = gic_save_distributor().unwrap();
        }
        if scenario != "no interrupt" {
            gic_restore_distributor(&distributor).unwrap();
            cpu.restore_state(&checkpoint).unwrap();
        }
        let finished = Arc::new(AtomicBool::new(false));
        let cancel = finished.clone();
        let mut id = cpu.id();
        let timer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            if matches!(scenario, "fresh edge" | "edge after restore") {
                let set_spi: libloading::Symbol<unsafe extern "C" fn(u32, bool) -> hv_return_t> =
                    unsafe { HVF.get(b"hv_gic_set_spi").unwrap() };
                assert_eq!(unsafe { set_spi(42, true) }, HV_SUCCESS);
            }
            std::thread::sleep(Duration::from_millis(100));
            if !cancel.load(Ordering::Acquire) {
                unsafe {
                    hv_vcpus_exit(&mut id, 1);
                }
            }
        });
        assert_eq!(unsafe { hv_vcpu_run(cpu.id()) }, HV_SUCCESS);
        finished.store(true, Ordering::Release);
        timer.join().unwrap();
        if scenario == "no interrupt" {
            assert_eq!(
                cpu.vcpu_exit.reason, HV_EXIT_REASON_CANCELED,
                "WFI must actually wait without an interrupt"
            );
            continue;
        }
        assert_eq!(cpu.vcpu_exit.reason, HV_EXIT_REASON_EXCEPTION, "{scenario}");
        assert_eq!(
            cpu.vcpu_exit.exception.syndrome >> 26,
            EC_AA64_HVC,
            "{scenario}"
        );
    }
    unsafe {
        hv_vm_unmap(0x8000_0000, size);
        libc::munmap(memory, size);
    }
}
