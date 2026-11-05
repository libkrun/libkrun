use std::env;
use std::process::Command;
use std::thread;

use arch::{IRQ_BASE, IRQ_MAX, MMIO_MEM_START};
use crossbeam_channel::unbounded;
use hvf::HvfVcpu;
use utils::eventfd::EFD_NONBLOCK;
use utils::pollable_channel::pollable_channel;
use vm_memory::GuestAddress;

use super::device_manager::irq::IrqAllocator;
use super::vstate::VcpuEvent;
use super::*;

fn check_terminal_responses(test_name: &str, control: VmCtl) {
    const CASE_ENV: &str = "LIBKRUN_TEST_VM_CONTROL_EXIT_CASE";
    let cases = [
        (Some(32), VcpuResponse::Reset, i32::MAX, 32),
        (None, VcpuResponse::Reset, i32::MAX, 0),
        (Some(32), VcpuResponse::Reset, 17, 17),
        (Some(32), VcpuResponse::Exited(1), i32::MAX, 1),
        (Some(32), VcpuResponse::Exited(1), 17, 17),
    ];

    let Ok(case) = env::var(CASE_ENV) else {
        for (index, (_, _, _, expected)) in cases.iter().enumerate() {
            let output = Command::new(env::current_exe().unwrap())
                .args(["--exact", test_name, "--nocapture"])
                .env(CASE_ENV, index.to_string())
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(*expected),
                "case {index}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        return;
    };
    let (reset_exit_code, response, init_exit_code, _) =
        cases.into_iter().nth(case.parse().unwrap()).unwrap();

    let mut arch_memory_info = ArchMemoryInfo::default();
    let vm = Vm::new(&mut arch_memory_info, false).unwrap();
    let (event_sender, event_receiver) = unbounded();
    let (response_sender, response_receiver) = unbounded();
    let (id_sender, id_receiver) = unbounded();
    let resume = matches!(control, VmCtl::Resume);
    let vcpu_thread = thread::spawn(move || {
        let vcpu = HvfVcpu::new(0, false).unwrap();
        id_sender.send(vcpu.id()).unwrap();
        match (resume, event_receiver.recv().unwrap()) {
            (false, VcpuEvent::Pause) | (true, VcpuEvent::Resume(_)) => {}
            (_, event) => panic!("unexpected control event: {event:?}"),
        }
        response_sender.send(response).unwrap();
        let _ = event_receiver.recv();
    });
    let handle = VcpuHandle::new(
        event_sender,
        response_receiver,
        id_receiver.recv().unwrap(),
        vcpu_thread,
    );
    let (vm_ctl_tx, vm_ctl_rx) = pollable_channel().unwrap();
    let mut mmio_base = MMIO_MEM_START;
    let mut vmm = Vmm {
        guest_memory: GuestMemoryMmap::from_ranges(&[(GuestAddress(0x8000_0000), 0x1000)]).unwrap(),
        arch_memory_info,
        kernel_cmdline: KernelCmdline::new(0x1000),
        vcpus_handles: vec![handle],
        exit_evt: EventFd::new(EFD_NONBLOCK).unwrap(),
        reset_exit_code,
        vm,
        exit_observers: Vec::new(),
        exit_code: Arc::new(AtomicI32::new(init_exit_code)),
        mmio_device_manager: MMIODeviceManager::new(
            &mut mmio_base,
            IrqAllocator::new(IRQ_BASE, IRQ_MAX),
        ),
        vm_ctl_tx,
        vm_ctl_rx,
        paused: resume,
        paused_at: unsafe { hvf::mach_absolute_time() },
        ram_in_blocks: false,
    };

    match control {
        VmCtl::Pause => vmm.pause().unwrap(),
        VmCtl::Resume => vmm.resume().unwrap(),
    }
    panic!("VM control returned after a terminal vCPU response");
}

#[test]
fn test_pause_handles_terminal_responses() {
    check_terminal_responses(
        "vmm::tests::test_pause_handles_terminal_responses",
        VmCtl::Pause,
    );
}

#[test]
fn test_resume_handles_terminal_responses() {
    check_terminal_responses(
        "vmm::tests::test_resume_handles_terminal_responses",
        VmCtl::Resume,
    );
}
