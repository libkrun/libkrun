// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows Hypervisor Platform (WHP) vCPU/VM integration.
//!
//! This is the Windows counterpart to `linux/vstate.rs` (KVM) and
//! `macos/vstate.rs` (HVF). It exposes the same `Vm` / `Vcpu` / `VcpuHandle`
//! surface the rest of the VMM drives, implemented on top of the `krun-whp`
//! wrappers (`WhpVm`, `WhpVcpu`, `VcpuExitReason`, ...).
//!
//! Scope: WHP targets x86_64, so the register-configuration and exit-handling
//! shape follows the Linux x86_64 path (PIO -> `io_bus`, MMIO -> `mmio_bus`,
//! CPUID/MSR completion), while the threading + channel plumbing mirrors the
//! single-hypervisor macOS backend.
//!
//! Verification status: this module is wired against the `whp` crate API but the
//! guest-visible behaviour (initial register/segment state for the Linux boot
//! protocol, MMIO instruction emulation, interrupt injection timing) has NOT been
//! validated on a real Windows host with the Windows Hypervisor Platform enabled.
//! Such sites are marked `TODO(whp-host)`.

// Snapshot/restore state and some helpers are present for cross-platform parity
// but not yet wired on Windows; allow until the snapshot path is ported.
#![allow(dead_code)]

use std::fmt::{Display, Formatter};
use std::result;
use std::sync::Arc;
use std::thread;

use crossbeam_channel::{Receiver, Sender, unbounded};
use whp::{VcpuExitReason, WhpEmulator, WhpVcpu, WhpVm};

use crate::vmm_config::machine_config::CpuFeaturesTemplate;
use utils::eventfd::EventFd;
use vm_memory::{Address, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

/// Errors associated with the WHP-backed VMM state.
#[derive(Debug)]
pub enum Error {
    /// Failed to create or configure the WHP partition.
    VmSetup(whp::Error),
    /// Failed to map a guest memory region into the partition.
    SetUserMemoryRegion(whp::Error),
    /// Failed to create a WHP virtual processor.
    VcpuSetup(whp::Error),
    /// Failed to read/write vCPU registers via WHP.
    VcpuRegisters(whp::Error),
    /// Failed to program the boot register/segment state.
    ConfigureRegisters(arch::x86_64::regs::Error),
    /// Failed to program the boot MSRs.
    ConfigureMsrs(arch::x86_64::msr::Error),
    /// Error while running the vCPU (`WHvRunVirtualProcessor`).
    VcpuRun(whp::Error),
    /// Failed to spawn the vCPU thread.
    VcpuSpawn(std::io::Error),
    /// Could not initialize the vCPU's thread-local pointer.
    VcpuTlsInit,
    /// The vCPU was not associated with the current thread's TLS.
    VcpuTlsNotPresent,
    /// Failed to deliver an event to the vCPU thread.
    VcpuEvent,
    /// The WHP partition reported an unrecoverable exit.
    VcpuUnhandledExit(VcpuExitReason),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use Error::*;
        match self {
            VmSetup(e) => write!(f, "Cannot create the WHP partition: {e}"),
            SetUserMemoryRegion(e) => write!(f, "Cannot map guest memory into WHP: {e}"),
            VcpuSetup(e) => write!(f, "Cannot create a WHP virtual processor: {e}"),
            VcpuRegisters(e) => write!(f, "Cannot access vCPU registers: {e}"),
            ConfigureRegisters(e) => write!(f, "Cannot program boot register state: {e:?}"),
            ConfigureMsrs(e) => write!(f, "Cannot program boot MSRs: {e:?}"),
            VcpuRun(e) => write!(f, "Failure during vCPU run: {e}"),
            VcpuSpawn(e) => write!(f, "Cannot spawn the vCPU thread: {e}"),
            VcpuTlsInit => write!(f, "Cannot initialize the vCPU TLS"),
            VcpuTlsNotPresent => write!(f, "The vCPU is not present in TLS"),
            VcpuEvent => write!(f, "Cannot deliver an event to the vCPU thread"),
            VcpuUnhandledExit(r) => write!(f, "Unhandled WHP vCPU exit: {r:?}"),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

/// A WHP partition wrapper, analogous to the KVM/HVF `Vm`.
pub struct Vm {
    whp_vm: Arc<WhpVm>,
}

impl Vm {
    /// Creates a new WHP partition sized for `vcpu_count` virtual processors.
    pub fn new(vcpu_count: u32) -> Result<Self> {
        let whp_vm = WhpVm::new(vcpu_count).map_err(Error::VmSetup)?;
        Ok(Vm {
            whp_vm: Arc::new(whp_vm),
        })
    }

    pub fn whp_vm(&self) -> &Arc<WhpVm> {
        &self.whp_vm
    }

    pub fn adjust_clock_after_pause(&self, _paused_ns: u64) -> Result<()> {
        // WHP exposes no host-visible guest clock control analogous to
        // KVM_KVMCLOCK_CTRL; guest timekeeping rides the reference TSC.
        Ok(())
    }

    /// Capture VM-level checkpoint state. WHP exposes no host-serializable
    /// in-partition device state (no in-kernel IRQ chip/PIT analogue), so there
    /// is nothing to capture — mirrors the empty macOS `VmState`.
    pub fn save_state(&self) -> Result<VmState> {
        Ok(VmState)
    }

    /// Restore VM-level checkpoint state. No-op for the same reason as
    /// [`Self::save_state`].
    pub fn restore_state(&self, _state: &VmState) -> Result<()> {
        Ok(())
    }

    /// Maps every guest-memory region into the WHP partition's guest physical
    /// address space.
    pub fn memory_init(&mut self, guest_mem: &GuestMemoryMmap) -> Result<()> {
        for region in guest_mem.iter() {
            // Safe to unwrap: the region start address is a valid guest address.
            let host_addr = guest_mem.get_host_address(region.start_addr()).unwrap();
            debug!(
                "WHP map: host_addr={:x?} guest_addr={:x?} len={:x?}",
                host_addr,
                region.start_addr().raw_value(),
                region.len()
            );
            // SAFETY: `host_addr` points into the live guest-memory mmap which
            // outlives the partition, and the region length is page-aligned.
            unsafe {
                self.whp_vm
                    .map_memory(
                        host_addr as *mut std::ffi::c_void,
                        region.start_addr().raw_value(),
                        region.len(),
                    )
                    .map_err(Error::SetUserMemoryRegion)?;
            }
        }
        Ok(())
    }
}

/// Encapsulates configuration parameters for the guest vCPUs.
#[derive(Debug, Eq, PartialEq)]
pub struct VcpuConfig {
    /// Number of guest VCPUs.
    pub vcpu_count: u8,
    /// Enable hyperthreading in the CPUID configuration.
    pub ht_enabled: bool,
    /// CPUID template to use.
    pub cpu_template: Option<CpuFeaturesTemplate>,
}

/// A WHP virtual-processor wrapper, analogous to the KVM/HVF `Vcpu`.
pub struct Vcpu {
    id: u8,
    whp_vcpu: WhpVcpu,
    /// Instruction emulator used to service MMIO exits (WHP does not decode the
    /// faulting instruction for us).
    emulator: WhpEmulator,
    /// Guest physical entry point the vCPU should begin executing at.
    boot_entry_addr: u64,
    /// PIO bus (x86 `in`/`out`), e.g. the serial console and legacy devices.
    io_bus: devices::Bus,
    /// MMIO bus (virtio-over-MMIO and friends).
    mmio_bus: Option<devices::Bus>,
    /// When set, the vCPU thread holds in its paused event loop before running
    /// any guest code, so a restore-into-a-clone can load register state onto it
    /// (and resume it) before the guest executes. Used by the fork clone path.
    start_paused: bool,
    #[allow(dead_code)]
    exit_evt: EventFd,

    // Receiving end of the events channel owned by the vCPU side.
    event_receiver: Receiver<VcpuEvent>,
    // Transmitting end of the events channel, handed to the `VcpuHandle`.
    event_sender: Option<Sender<VcpuEvent>>,
    // Receiving end of the responses channel, handed to the `VcpuHandle`.
    response_receiver: Option<Receiver<VcpuResponse>>,
    // Transmitting end of the responses channel owned by the vCPU side.
    response_sender: Sender<VcpuResponse>,
}

impl Vcpu {
    /// Constructs a new WHP-backed vCPU `id` for partition `vm`.
    pub fn new_x86_64(id: u8, vm: &Vm, exit_evt: EventFd) -> Result<Self> {
        let whp_vcpu = WhpVcpu::new(vm.whp_vm.clone(), u32::from(id)).map_err(Error::VcpuSetup)?;
        let emulator = WhpEmulator::with_mmio_callbacks().map_err(Error::VcpuSetup)?;
        let (event_sender, event_receiver) = unbounded();
        let (response_sender, response_receiver) = unbounded();
        Ok(Vcpu {
            id,
            whp_vcpu,
            emulator,
            boot_entry_addr: 0,
            io_bus: devices::Bus::new(),
            mmio_bus: None,
            start_paused: false,
            exit_evt,
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
        })
    }

    pub fn cpu_index(&self) -> u8 {
        self.id
    }

    /// Mark this vCPU to start in its paused event loop (see the `start_paused`
    /// field). Call before [`Self::start_threaded`]. Used by the fork clone path
    /// so register state can be restored before the guest runs.
    pub fn set_start_paused(&mut self, v: bool) {
        self.start_paused = v;
    }

    /// On KVM this installs a signal handler used to kick the vCPU out of
    /// `KVM_RUN`. WHP uses `WhpVm::cancel_vcpu` instead (see
    /// `VcpuHandle::send_event`), so this is a no-op kept for interface parity.
    pub fn register_kick_signal_handler() {}

    pub fn set_mmio_bus(&mut self, mmio_bus: devices::Bus) {
        self.mmio_bus = Some(mmio_bus);
    }

    pub fn set_io_bus(&mut self, io_bus: devices::Bus) {
        self.io_bus = io_bus;
    }

    /// Configures the initial vCPU register/segment state for the Linux boot
    /// protocol and records the kernel entry point.
    ///
    /// Programs MSRs, then control/segment registers (CR0/CR3/CR4, EFER, GDT,
    /// CS/DS/SS, page tables), then the general registers + RIP, via the WHP arch
    /// backend (`arch::x86_64::windows`), mirroring the KVM/HVF `configure_x86_64`
    /// ordering. TODO(whp-host): validate the programmed state actually boots a
    /// guest on real WHP hardware.
    pub fn configure_x86_64(&mut self, guest_mem: &GuestMemoryMmap, entry_addr: u64) -> Result<()> {
        self.boot_entry_addr = entry_addr;
        arch::x86_64::windows::msr::setup_msrs(&self.whp_vcpu).map_err(Error::ConfigureMsrs)?;
        arch::x86_64::windows::regs::setup_sregs(guest_mem, &self.whp_vcpu)
            .map_err(Error::ConfigureRegisters)?;
        arch::x86_64::windows::regs::setup_regs(&self.whp_vcpu, entry_addr)
            .map_err(Error::ConfigureRegisters)?;
        Ok(())
    }

    /// Moves the vCPU onto its own thread and returns a handle to drive it.
    pub fn start_threaded(mut self) -> Result<VcpuHandle> {
        let event_sender = self.event_sender.take().unwrap();
        let response_receiver = self.response_receiver.take().unwrap();
        // Captured before the vCPU moves onto its thread, so the handle can cancel
        // the running virtual processor to deliver events promptly.
        let whp_vm = self.whp_vcpu.vm().clone();
        let vp_index = self.whp_vcpu.index();
        let vcpu_thread = thread::Builder::new()
            .name(format!("fc_vcpu {}", self.cpu_index()))
            .spawn(move || {
                self.run();
            })
            .map_err(Error::VcpuSpawn)?;

        Ok(VcpuHandle::new(
            event_sender,
            response_receiver,
            vcpu_thread,
            whp_vm,
            vp_index,
        ))
    }

    /// Handles a single WHP exit, dispatching device accesses to the buses.
    ///
    /// Returns `Ok(true)` to keep running, `Ok(false)` to stop the vCPU.
    fn handle_exit(&mut self, reason: VcpuExitReason) -> Result<bool> {
        match reason {
            VcpuExitReason::IoPortAccess => {
                // Mirror KVM's IoIn/IoOut: move `size` bytes between RAX and the
                // PIO bus according to the access direction.
                let info = self.whp_vcpu.io_port_exit_info();
                let port = u64::from(info.port);
                let size = (info.size as usize).clamp(1, 8);
                let mut bytes = info.rax.to_le_bytes();
                if info.is_write {
                    self.io_bus.write(0, port, &bytes[..size]);
                    self.whp_vcpu.advance_rip().map_err(Error::VcpuRegisters)?;
                } else {
                    self.io_bus.read(0, port, &mut bytes[..size]);
                    let rax = u64::from_le_bytes(bytes);
                    self.whp_vcpu
                        .complete_io_in(rax)
                        .map_err(Error::VcpuRegisters)?;
                }
                Ok(true)
            }
            VcpuExitReason::MemoryAccess => {
                // WHP does not decode the faulting instruction, so run it through
                // the WHP instruction emulator, routing the device-side access to
                // the MMIO bus. The emulator advances RIP / updates registers via
                // its register callbacks (so no explicit `advance_rip` here).
                if let Some(mmio_bus) = self.mmio_bus.clone() {
                    let mut handler = |gpa: u64, data: &mut [u8], is_write: bool| {
                        if is_write {
                            mmio_bus.write(0, gpa, data);
                        } else {
                            mmio_bus.read(0, gpa, data);
                        }
                    };
                    // SAFETY: called immediately after a MemoryAccess exit, with an
                    // emulator built via `with_mmio_callbacks`.
                    unsafe { self.emulator.emulate_mmio(&self.whp_vcpu, &mut handler) }
                        .map_err(Error::VcpuRegisters)?;
                } else {
                    self.whp_vcpu.advance_rip().map_err(Error::VcpuRegisters)?;
                }
                Ok(true)
            }
            VcpuExitReason::CpuidAccess => {
                // Pass the hypervisor's default CPUID result straight through.
                // TODO(whp-host): apply libkrun's CPUID masking/templating here,
                // the WHP analogue of `krun-cpuid`.
                let info = self.whp_vcpu.cpuid_exit_info();
                self.whp_vcpu
                    .complete_cpuid(
                        info.default_eax,
                        info.default_ebx,
                        info.default_ecx,
                        info.default_edx,
                    )
                    .map_err(Error::VcpuRegisters)?;
                Ok(true)
            }
            VcpuExitReason::MsrAccess => {
                // Unhandled MSRs (e.g. Hyper-V synthetic MSRs in the 0x4000_00xx
                // range, since WHP presents a Hyper-V interface). Reads return 0;
                // writes are ignored. Both MUST advance RIP past the RD/WRMSR, or
                // the instruction re-executes forever.
                let info = self.whp_vcpu.msr_exit_info();
                if info.is_write {
                    self.whp_vcpu.advance_rip().map_err(Error::VcpuRegisters)?;
                } else {
                    self.whp_vcpu
                        .complete_msr_read(0, 0)
                        .map_err(Error::VcpuRegisters)?;
                }
                Ok(true)
            }
            VcpuExitReason::Halt => {
                // The guest executed HLT. Older WHP (e.g. Windows 10 1909)
                // surfaces idle HLTs as exits rather than handling them inside
                // WHvRunVirtualProcessor; treating every HLT as terminal kills
                // the vCPU the first time the guest idles, long before userspace.
                // If interrupts are enabled this is an idle wait — re-enter the
                // run loop so WHP blocks until a wake interrupt (timer or a
                // device IRQ injected from a watcher thread) resumes the vCPU.
                // Only a HLT with interrupts masked is a real, unrecoverable
                // shutdown halt that should stop the vCPU.
                match self.whp_vcpu.interrupts_enabled() {
                    Ok(true) => Ok(true),
                    Ok(false) => {
                        info!(
                            "WHP vCPU {} halted with interrupts masked; stopping",
                            self.id
                        );
                        Ok(false)
                    }
                    Err(e) => {
                        error!(
                            "WHP vCPU {} HLT: cannot read RFLAGS: {e}; stopping",
                            self.id
                        );
                        Ok(false)
                    }
                }
            }
            VcpuExitReason::Canceled => {
                // Woken to service a pending event (pause/resume/exit).
                Ok(true)
            }
            VcpuExitReason::UnrecoverableException
            | VcpuExitReason::InvalidVpRegisterValue
            | VcpuExitReason::UnsupportedFeature => {
                error!(
                    "WHP vCPU {} fatal exit {:?}: {}",
                    self.id,
                    reason,
                    self.whp_vcpu.debug_state()
                );
                Err(Error::VcpuUnhandledExit(reason))
            }
            other => {
                error!("WHP vCPU {} unhandled exit: {other:?}", self.id);
                Err(Error::VcpuUnhandledExit(other))
            }
        }
    }

    /// Drains any pending control events. Returns `false` when the vCPU should
    /// terminate.
    fn service_events(&self) -> bool {
        while let Ok(event) = self.event_receiver.try_recv() {
            match event {
                VcpuEvent::Pause => {
                    let _ = self.response_sender.send(VcpuResponse::Paused);
                    if !self.run_paused_loop() {
                        return false;
                    }
                }
                VcpuEvent::Resume { .. } => {
                    let _ = self.response_sender.send(VcpuResponse::Resumed);
                }
                // Save/restore are only valid while paused; the orchestrator
                // always pauses first, so receiving one here is a protocol error.
                VcpuEvent::SaveState | VcpuEvent::RestoreState(_) => {
                    error!("ignoring vcpu SaveState/RestoreState received while running");
                }
            }
        }
        true
    }

    /// Block in the paused event loop: service Pause/SaveState/RestoreState and
    /// return `true` on Resume (caller proceeds to run the guest) or `false` on
    /// error / channel close (caller exits). The vCPU is quiescent here, which is
    /// the safe boundary to capture/restore its WHP register + LAPIC + XSAVE
    /// state for checkpoint/fork.
    fn run_paused_loop(&self) -> bool {
        loop {
            match self.event_receiver.recv() {
                Ok(VcpuEvent::Resume { .. }) => {
                    let _ = self.response_sender.send(VcpuResponse::Resumed);
                    return true;
                }
                Ok(VcpuEvent::Pause) => {
                    let _ = self.response_sender.send(VcpuResponse::Paused);
                }
                Ok(VcpuEvent::SaveState) => match self.whp_vcpu.save_state() {
                    Ok(state) => {
                        let _ = self
                            .response_sender
                            .send(VcpuResponse::SavedState(Box::new(VcpuState(state))));
                    }
                    Err(e) => {
                        error!("failed to capture WHP vcpu state: {e}");
                        return false;
                    }
                },
                Ok(VcpuEvent::RestoreState(state)) => {
                    if let Err(e) = self.whp_vcpu.restore_state(&state.0) {
                        let message = e.to_string();
                        error!("failed to restore WHP vcpu state: {message}");
                        let _ = self
                            .response_sender
                            .send(VcpuResponse::RestoreFailed(message));
                        return false;
                    }
                    let _ = self.response_sender.send(VcpuResponse::RestoredState);
                }
                Err(_) => return false,
            }
        }
    }

    /// Main loop of the vCPU thread: run the WHP vCPU and handle its exits.
    pub fn run(&mut self) {
        // Fork clone restore: hold in the paused loop until the orchestrator has
        // restored register state and sent Resume, so the guest never executes
        // with cold (boot) registers.
        if self.start_paused && !self.run_paused_loop() {
            // run_paused_loop returns false on a restore error or a channel close
            // (VM teardown). Report a non-zero code so a failed clone restore is
            // not mistaken for a clean exit (the orchestrator also observes the
            // missing RestoredState ack).
            let _ = self.response_sender.send(VcpuResponse::Exited(1));
            return;
        }
        loop {
            if !self.service_events() {
                break;
            }
            match self.whp_vcpu.run() {
                Ok(reason) => match self.handle_exit(reason) {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(e) => {
                        error!("WHP vCPU {} run error: {e}", self.id);
                        break;
                    }
                },
                Err(e) => {
                    error!("WHP vCPU {} WHvRunVirtualProcessor failed: {e}", self.id);
                    break;
                }
            }
        }
        let _ = self.response_sender.send(VcpuResponse::Exited(0));
    }
}

/// Per-vCPU architectural state for checkpoint/restore, wrapping the WHP
/// register + LAPIC + XSAVE capture from the `whp` crate.
#[derive(Clone, Debug, Default)]
pub struct VcpuState(whp::WhpVcpuState);

impl VcpuState {
    pub fn serialize(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn deserialize(bytes: &[u8]) -> result::Result<VcpuState, String> {
        Ok(VcpuState(whp::WhpVcpuState::from_bytes(bytes)?))
    }
}

/// VM-level checkpoint state. WHP has no host-serializable in-partition device
/// state to capture here (no in-kernel IRQ chip/PIT analogue exposed), mirroring
/// the empty macOS `VmState`.
#[derive(Clone, Debug, Default)]
pub struct VmState;

impl VmState {
    pub fn serialize(&self) -> Vec<u8> {
        Vec::new()
    }

    pub fn deserialize(_bytes: &[u8]) -> result::Result<VmState, String> {
        Ok(VmState)
    }
}

#[derive(Debug)]
/// Events the vCPU thread can receive.
pub enum VcpuEvent {
    /// Pause the vCPU.
    Pause,
    /// Resume the vCPU.
    Resume { paused_ns: u64 },
    /// Capture the vCPU's architectural state (only valid while paused).
    SaveState,
    /// Restore previously-captured vCPU state (only valid while paused).
    RestoreState(Box<VcpuState>),
}

#[derive(Debug)]
/// Responses the vCPU thread reports back.
pub enum VcpuResponse {
    /// vCPU is paused.
    Paused,
    /// vCPU is resumed.
    Resumed,
    /// vCPU stopped with the given exit code.
    Exited(u8),
    /// Captured vCPU state, in reply to [`VcpuEvent::SaveState`].
    SavedState(Box<VcpuState>),
    /// Acknowledges a [`VcpuEvent::RestoreState`].
    RestoredState,
    /// The vCPU rejected checkpoint state and cannot safely resume.
    RestoreFailed(String),
}

/// Wrapper over the vCPU thread that hides the channel interactions, and (on
/// WHP) cancels the running virtual processor to deliver events promptly.
pub struct VcpuHandle {
    event_sender: Sender<VcpuEvent>,
    response_receiver: Receiver<VcpuResponse>,
    whp_vm: Arc<WhpVm>,
    vp_index: u32,
    #[allow(dead_code)]
    vcpu_thread: Option<thread::JoinHandle<()>>,
}

impl VcpuHandle {
    pub fn new(
        event_sender: Sender<VcpuEvent>,
        response_receiver: Receiver<VcpuResponse>,
        vcpu_thread: thread::JoinHandle<()>,
        whp_vm: Arc<WhpVm>,
        vp_index: u32,
    ) -> Self {
        Self {
            event_sender,
            response_receiver,
            whp_vm,
            vp_index,
            vcpu_thread: Some(vcpu_thread),
        }
    }

    pub fn send_event(&self, event: VcpuEvent) -> Result<()> {
        self.event_sender
            .send(event)
            .map_err(|_| Error::VcpuEvent)?;
        // Cancel the running virtual processor so it exits `WHvRunVirtualProcessor`
        // promptly and services the event (the WHP analogue of KVM's immediate
        // exit / HVF's vcpu_request_exit).
        self.whp_vm.cancel_vcpu(self.vp_index);
        Ok(())
    }

    pub fn response_receiver(&self) -> &Receiver<VcpuResponse> {
        &self.response_receiver
    }
}
