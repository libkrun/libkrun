// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::result;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::super::{FC_EXIT_CODE_GENERIC_ERROR, FC_EXIT_CODE_OK};
use crate::vmm_config::machine_config::CpuFeaturesTemplate;

use arch::ArchMemoryInfo;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, unbounded};
use devices::legacy::VcpuList;
use hvf::{HvfVcpu, HvfVm, VcpuExit, Vcpus};
use utils::eventfd::EventFd;
use vm_memory::{
    Address, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion,
};

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug)]
pub enum Error {
    /// Invalid guest memory configuration.
    GuestMemoryMmap(GuestMemoryError),
    /// The number of configured slots is bigger than the maximum reported by KVM.
    NotEnoughMemorySlots,
    /// Error configuring the general purpose aarch64 registers.
    REGSConfiguration(arch::aarch64::regs::Error),
    /// Cannot set the memory regions.
    SetUserMemoryRegion(hvf::Error),
    /// Failed to signal Vcpu.
    SignalVcpu(utils::errno::Error),
    /// Failed to request an HVF vCPU exit.
    VcpuRequestExit(hvf::Error),
    /// Cannot send event to vCPU.
    VcpuEvent,
    /// Error doing Vcpu Init on Arm.
    VcpuArmInit,
    /// Error getting the Vcpu preferred target on Arm.
    VcpuArmPreferredTarget,
    /// vCPU count is not initialized.
    VcpuCountNotInitialized,
    /// Cannot run the VCPUs.
    VcpuRun,
    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(io::Error),
    /// Cannot cleanly initialize vcpu TLS.
    VcpuTlsInit,
    /// Vcpu not present in TLS.
    VcpuTlsNotPresent,
    /// Unexpected KVM_RUN exit reason
    VcpuUnhandledKvmExit,
    /// Cannot configure the microvm.
    VmSetup(hvf::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            GuestMemoryMmap(e) => write!(f, "Guest memory error: {e:?}"),
            VcpuCountNotInitialized => write!(f, "vCPU count is not initialized"),
            VmSetup(e) => write!(f, "Cannot configure the microvm: {e:?}"),
            VcpuRun => write!(f, "Cannot run the VCPUs"),
            NotEnoughMemorySlots => write!(
                f,
                "The number of configured slots is bigger than the maximum reported by KVM"
            ),
            SetUserMemoryRegion(e) => write!(f, "Cannot set the memory regions: {e:?}"),
            SignalVcpu(e) => write!(f, "Failed to signal Vcpu: {e}"),
            VcpuRequestExit(e) => write!(f, "Failed to request vCPU exit: {e:?}"),
            VcpuEvent => write!(f, "Cannot send event to vCPU"),
            REGSConfiguration(e) => write!(
                f,
                "Error configuring the general purpose aarch64 registers: {e:?}"
            ),
            VcpuSpawn(e) => write!(f, "Cannot spawn a new vCPU thread: {e}"),
            VcpuTlsInit => write!(f, "Cannot clean init vcpu TLS"),
            VcpuTlsNotPresent => write!(f, "Vcpu not present in TLS"),
            VcpuUnhandledKvmExit => write!(f, "Unexpected KVM_RUN exit reason"),
            VcpuArmPreferredTarget => write!(f, "Error getting the Vcpu preferred target on Arm"),
            VcpuArmInit => write!(f, "Error doing Vcpu Init on Arm"),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

/// A wrapper around creating and using a VM.
pub struct Vm {
    hvf_vm: HvfVm,
}

impl Vm {
    /// Constructs a new `Vm` using the given `Kvm` instance.
    pub fn new(nested_enabled: bool) -> Result<Self> {
        let hvf_vm = HvfVm::new(nested_enabled).map_err(Error::VmSetup)?;

        Ok(Vm { hvf_vm })
    }

    pub fn hvf_vm(&self) -> &HvfVm {
        &self.hvf_vm
    }

    pub fn adjust_clock_after_pause(&self, _paused_ns: u64) -> Result<()> {
        Ok(())
    }

    /// Capture VM-level state for a checkpoint. HVF has no in-kernel interrupt
    /// controller / PIT / clock to serialize (unlike KVM's PIC/IOAPIC/PIT/clock)
    /// — guest-timer continuity is handled by the vtimer-offset adjustment on
    /// resume — so the macOS `VmState` is empty. Present for cross-platform
    /// symmetry with the KVM `Vm::save_state`.
    #[cfg(target_arch = "aarch64")]
    pub fn save_state(&self) -> Result<VmState> {
        // Capture the in-kernel HVF GIC distributor state (SPI group/priority/
        // config/routing + set-enables). A restored clone is a fresh hv_vm_create
        // whose vGIC is in reset state, so without this its device IRQs (e.g.
        // vsock) are masked and never wake the guest from WFI. Best-effort: if
        // there is no in-kernel GIC (emulated fallback), leave it empty — the
        // in-place pause/resume checkpoint path does not need it.
        let gic_distributor = match hvf::gic_save_distributor() {
            Ok(regs) => {
                debug!("captured {} GIC distributor registers", regs.len());
                regs
            }
            Err(e) => {
                // Not fatal for in-place pause/resume (no in-kernel GIC to
                // transfer), but a fork clone will not receive device IRQs
                // without it — surface it rather than failing silently.
                warn!(
                    "GIC distributor capture failed ({e:?}); a fork clone may not wake on device IRQs"
                );
                Vec::new()
            }
        };
        Ok(VmState { gic_distributor })
    }

    /// Restore VM-level state: replay the GIC distributor registers onto the
    /// clone's fresh vGIC (GICD_CTLR enabled last). No-op if empty.
    #[cfg(target_arch = "aarch64")]
    pub fn restore_state(&self, state: &VmState) -> Result<()> {
        if !state.gic_distributor.is_empty()
            && let Err(e) = hvf::gic_restore_distributor(&state.gic_distributor)
        {
            error!("failed to restore GIC distributor state: {e:?}");
        }
        Ok(())
    }

    /// Initializes the guest memory.
    pub fn memory_init(&mut self, guest_mem: &GuestMemoryMmap) -> Result<()> {
        for region in guest_mem.iter() {
            // It's safe to unwrap because the guest address is valid.
            let host_addr = guest_mem.get_host_address(region.start_addr()).unwrap();
            debug!(
                "Guest memory host_addr={:x?} guest_addr={:x?} len={:x?}",
                host_addr,
                region.start_addr().raw_value(),
                region.len()
            );
            self.hvf_vm
                .map_memory(
                    host_addr as u64,
                    region.start_addr().raw_value(),
                    region.len(),
                )
                .map_err(Error::SetUserMemoryRegion)?;
        }

        Ok(())
    }

    pub fn add_mapping(
        &self,
        reply_sender: Sender<bool>,
        host_addr: u64,
        guest_addr: u64,
        len: u64,
    ) {
        debug!("add_mapping: host_addr={host_addr:x}, guest_addr={guest_addr:x}, len={len}");
        if let Err(e) = self.hvf_vm.unmap_memory(guest_addr, len) {
            error!("Error removing memory map: {e:?}");
        }

        if let Err(e) = self.hvf_vm.map_memory(host_addr, guest_addr, len) {
            error!("Error adding memory map: {e:?}");
            reply_sender.send(false).unwrap();
        } else {
            reply_sender.send(true).unwrap();
        }
    }

    pub fn remove_mapping(&self, reply_sender: Sender<bool>, guest_addr: u64, len: u64) {
        debug!("remove_mapping: guest_addr={guest_addr:x}, len={len}");
        if let Err(e) = self.hvf_vm.unmap_memory(guest_addr, len) {
            error!("Error removing memory map: {e:?}");
            reply_sender.send(false).unwrap();
        } else {
            reply_sender.send(true).unwrap();
        }
    }
}

/// Encapsulates configuration parameters for the guest vCPUS.
#[derive(Debug, Eq, PartialEq)]
pub struct VcpuConfig {
    /// Number of guest VCPUs.
    pub vcpu_count: u8,
    /// Enable hyperthreading in the CPUID configuration.
    pub ht_enabled: bool,
    /// CPUID template to use.
    pub cpu_template: Option<CpuFeaturesTemplate>,
}

// Using this for easier explicit type-casting to help IDEs interpret the code.
type VcpuCell = Cell<Option<*const Vcpu>>;

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    id: u8,
    boot_entry_addr: u64,
    boot_receiver: Option<Receiver<u64>>,
    boot_senders: Option<HashMap<u64, Sender<u64>>>,
    fdt_addr: u64,
    mmio_bus: Option<devices::Bus>,
    #[cfg_attr(all(test, target_arch = "aarch64"), allow(unused))]
    exit_evt: EventFd,

    #[cfg(target_arch = "aarch64")]
    mpidr: u64,

    #[allow(unused)]
    event_receiver: Receiver<VcpuEvent>,
    // The transmitting end of the events channel which will be given to the handler.
    event_sender: Option<Sender<VcpuEvent>>,
    // The receiving end of the responses channel which will be given to the handler.
    response_receiver: Option<Receiver<VcpuResponse>>,
    // The transmitting end of the responses channel owned by the vcpu side.
    response_sender: Sender<VcpuResponse>,

    vcpu_list: Arc<VcpuList>,
    nested_enabled: bool,
    /// When set, the vCPU thread does NOT run guest code after thread setup; it
    /// sits in the paused event loop until a `Resume` arrives. Used by the
    /// restore-into-a-fresh-clone path so the orchestrator can load the saved
    /// register state before the guest executes (the KVM analogue is starting
    /// the vCPU in its paused state machine).
    start_paused: bool,
}

impl Vcpu {
    thread_local!(static TLS_VCPU_PTR: VcpuCell = const { Cell::new(None) });

    /// Associates `self` with the current thread.
    ///
    /// It is a prerequisite to successfully run `init_thread_local_data()` before using
    /// `run_on_thread_local()` on the current thread.
    /// This function will return an error if there already is a `Vcpu` present in the TLS.
    fn init_thread_local_data(&mut self) -> Result<()> {
        Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| {
            if cell.get().is_some() {
                return Err(Error::VcpuTlsInit);
            }
            cell.set(Some(self as *const Vcpu));
            Ok(())
        })
    }

    /// Deassociates `self` from the current thread.
    ///
    /// Should be called if the current `self` had called `init_thread_local_data()` and
    /// now needs to move to a different thread.
    ///
    /// Fails if `self` was not previously associated with the current thread.
    fn reset_thread_local_data(&mut self) -> Result<()> {
        // Best-effort to clean up TLS. If the `Vcpu` was moved to another thread
        // _before_ running this, then there is nothing we can do.
        Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| {
            if let Some(vcpu_ptr) = cell.get()
                && std::ptr::eq(vcpu_ptr, self)
            {
                Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| cell.take());
                return Ok(());
            }
            Err(Error::VcpuTlsNotPresent)
        })
    }

    /// Registers a signal handler which makes use of TLS and kvm immediate exit to
    /// kick the vcpu running on the current thread, if there is one.
    pub fn register_kick_signal_handler() {
        /*
        extern "C" fn handle_signal(_: c_int, _: *mut siginfo_t, _: *mut c_void) {
            // This is safe because it's temporarily aliasing the `Vcpu` object, but we are
            // only reading `vcpu.fd` which does not change for the lifetime of the `Vcpu`.
            unsafe {
                let _ = Vcpu::run_on_thread_local(|_vcpu| {
                    vcpu.fd.set_kvm_immediate_exit(1);
                    fence(Ordering::Release);
                });
            }
        }
        */

        //register_signal_handler(sigrtmin() + VCPU_RTSIG_OFFSET, handle_signal)
        //    .expect("Failed to register vcpu signal handler");
    }

    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm_fd` - The kvm `VmFd` for the virtual machine this vcpu will get attached to.
    /// * `exit_evt` - An `EventFd` that will be written into when this vcpu exits.
    pub fn new_aarch64(
        id: u8,
        boot_entry_addr: GuestAddress,
        boot_receiver: Option<Receiver<u64>>,
        exit_evt: EventFd,
        vcpu_list: Arc<VcpuList>,
        nested_enabled: bool,
    ) -> Result<Self> {
        let (event_sender, event_receiver) = unbounded();
        let (response_sender, response_receiver) = unbounded();

        Ok(Vcpu {
            id,
            boot_entry_addr: boot_entry_addr.raw_value(),
            boot_receiver,
            boot_senders: None,
            fdt_addr: 0,
            mmio_bus: None,
            exit_evt,
            mpidr: id as u64,
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
            vcpu_list,
            nested_enabled,
            start_paused: false,
        })
    }

    /// Mark this vCPU to start paused (see [`Vcpu::start_paused`]). Call before
    /// [`Vcpu::start_threaded`] on the restore-into-a-clone path.
    pub fn set_start_paused(&mut self, v: bool) {
        self.start_paused = v;
    }

    /// Returns the cpu index as seen by the guest OS.
    pub fn cpu_index(&self) -> u8 {
        self.id
    }

    /// Gets the MPIDR register value.
    pub fn get_mpidr(&self) -> u64 {
        self.mpidr
    }

    /// Sets a MMIO bus for this vcpu.
    pub fn set_mmio_bus(&mut self, mmio_bus: devices::Bus) {
        self.mmio_bus = Some(mmio_bus);
    }

    pub fn set_boot_senders(&mut self, boot_senders: HashMap<u64, Sender<u64>>) {
        self.boot_senders = Some(boot_senders);
    }

    /// Configures an aarch64 specific vcpu.
    ///
    /// # Arguments
    ///
    /// * `guest_mem` - The guest memory used by this microvm.
    pub fn configure_aarch64(&mut self, mem_info: &ArchMemoryInfo) -> Result<()> {
        self.fdt_addr = mem_info.fdt_addr;

        Ok(())
    }

    /// Moves the vcpu to its own thread and constructs a VcpuHandle.
    /// The handle can be used to control the remote vcpu.
    pub fn start_threaded(mut self) -> Result<VcpuHandle> {
        let event_sender = self.event_sender.take().unwrap();
        let response_receiver = self.response_receiver.take().unwrap();
        let (init_tls_sender, init_tls_receiver) = unbounded();
        let vcpu_list = self.vcpu_list.clone();

        let vcpu_thread = thread::Builder::new()
            .name(format!("fc_vcpu {}", self.cpu_index()))
            .spawn(move || {
                self.init_thread_local_data()
                    .expect("Cannot cleanly initialize vcpu TLS.");

                self.run(init_tls_sender);
            })
            .map_err(Error::VcpuSpawn)?;

        let hvf_vcpuid = init_tls_receiver
            .recv()
            .expect("Error waiting for TLS initialization.");

        Ok(VcpuHandle::new(
            event_sender,
            response_receiver,
            hvf_vcpuid,
            vcpu_list,
            vcpu_thread,
        ))
    }

    /// Returns error or enum specifying whether emulation was handled or interrupted.
    fn run_emulation(&mut self, hvf_vcpu: &mut HvfVcpu) -> Result<VcpuEmulation> {
        let vcpuid = hvf_vcpu.id();

        match hvf_vcpu.run(self.vcpu_list.clone()) {
            Ok(exit) => match exit {
                VcpuExit::Breakpoint => {
                    debug!("vCPU {vcpuid} breakpoint");
                    Ok(VcpuEmulation::Interrupted)
                }
                VcpuExit::Canceled => {
                    debug!("vCPU {vcpuid} canceled");
                    Ok(VcpuEmulation::Interrupted)
                }
                VcpuExit::CpuOn(mpidr, entry, context_id) => {
                    debug!("CpuOn: mpidr=0x{mpidr:x} entry=0x{entry:x} context_id={context_id}");
                    if let Some(boot_senders) = &self.boot_senders {
                        if let Some(sender) = boot_senders.get(&mpidr) {
                            sender.send(entry).unwrap()
                        }
                    } else {
                        error!("CpuOn request coming from an unexpected vCPU={}", self.id);
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::HypervisorCall => {
                    debug!("vCPU {vcpuid} HVC");
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::MmioRead(addr, data) => {
                    if let Some(ref mmio_bus) = self.mmio_bus {
                        debug!("vCPU {vcpuid} MMIO read 0x{addr:x}");
                        mmio_bus.read(vcpuid, addr, data);
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if let Some(ref mmio_bus) = self.mmio_bus {
                        mmio_bus.write(vcpuid, addr, data);
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::PsciHandled => {
                    debug!("vCPU {vcpuid} PSCI");
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::SecureMonitorCall => {
                    debug!("vCPU {vcpuid} SMC");
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::Shutdown => {
                    info!("vCPU {vcpuid} received shutdown signal");
                    Ok(VcpuEmulation::Stopped)
                }
                VcpuExit::SystemRegister => {
                    debug!("vCPU {vcpuid} accessed a system register");
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::VtimerActivated => {
                    debug!("vCPU {vcpuid} VtimerActivated");
                    self.vcpu_list.set_vtimer_irq(vcpuid);
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::WaitForEvent => {
                    debug!("vCPU {vcpuid} WaitForEvent");
                    Ok(VcpuEmulation::WaitForEvent)
                }
                VcpuExit::WaitForEventExpired => {
                    debug!("vCPU {vcpuid} WaitForEventExpired");
                    Ok(VcpuEmulation::WaitForEventExpired)
                }
                VcpuExit::WaitForEventTimeout(duration) => {
                    debug!("vCPU {vcpuid} WaitForEventTimeout timeout={duration:?}");
                    Ok(VcpuEmulation::WaitForEventTimeout(duration))
                }
            },
            Err(e) => panic!("Error running HVF vCPU: {e:?}"),
        }
    }

    /// Main loop of the vCPU thread.
    pub fn run(&mut self, init_tls_sender: Sender<u64>) {
        let mut hvf_vcpu =
            HvfVcpu::new(self.mpidr, self.nested_enabled).expect("Can't create HVF vCPU");
        let hvf_vcpuid = hvf_vcpu.id();

        let (wfe_sender, wfe_receiver) = unbounded();
        self.vcpu_list.register(hvf_vcpuid, wfe_sender);

        init_tls_sender
            .send(hvf_vcpuid)
            .expect("Cannot notify vcpu TLS initialization.");

        // Restore-into-a-clone: the secondary-vCPU PSCI `CpuOn` handshake already
        // happened in the golden, and each vCPU's PC comes from the restored
        // register state — so do NOT block on `boot_receiver` (no `CpuOn` will be
        // sent here, and the orchestrator drives restore over the event channel).
        // set_initial_state's entry_addr is overwritten by the restore anyway.
        let entry_addr = match &self.boot_receiver {
            Some(boot_receiver) if !self.start_paused => boot_receiver.recv().unwrap(),
            _ => self.boot_entry_addr,
        };

        hvf_vcpu
            .set_initial_state(entry_addr, self.fdt_addr)
            .unwrap_or_else(|_| panic!("Can't set HVF vCPU {hvf_vcpuid} initial state"));

        // Restore-into-a-clone: hold here in the paused event loop (handling the
        // orchestrator's RestoreState) until a Resume arrives, so the saved
        // register state is loaded BEFORE the guest executes. set_initial_state
        // above still ran to program the VMM-managed EL2/HCR state (which is not
        // part of the snapshot); the restore overwrites PC/CPSR/EL1/GP/SIMD.
        if self.start_paused && !self.run_paused_loop(hvf_vcpuid) {
            self.exit(FC_EXIT_CODE_GENERIC_ERROR);
            return;
        }

        loop {
            if !self.handle_pending_event(false, hvf_vcpuid) {
                self.exit(FC_EXIT_CODE_GENERIC_ERROR);
                break;
            }

            match self.run_emulation(&mut hvf_vcpu) {
                // Emulation ran successfully, continue.
                Ok(VcpuEmulation::Handled) => (),
                // Emulation was interrupted by a breakpoint.
                Ok(VcpuEmulation::Interrupted) => {
                    if !self.handle_pending_event(false, hvf_vcpuid) {
                        self.exit(FC_EXIT_CODE_GENERIC_ERROR);
                        break;
                    }
                }
                // Wait for an external event.
                Ok(VcpuEmulation::WaitForEvent) => {
                    self.wait_for_event(hvf_vcpuid, &wfe_receiver, None)
                }
                Ok(VcpuEmulation::WaitForEventExpired) => (),
                Ok(VcpuEmulation::WaitForEventTimeout(timeout)) => {
                    self.wait_for_event(hvf_vcpuid, &wfe_receiver, Some(timeout))
                }
                // The guest was rebooted or halted.
                Ok(VcpuEmulation::Stopped) => {
                    self.exit(FC_EXIT_CODE_OK);
                    break;
                }
                // Emulation errors lead to vCPU exit.
                Err(_) => {
                    self.exit(FC_EXIT_CODE_GENERIC_ERROR);
                    break;
                }
            }
        }
    }

    fn wait_for_event(
        &mut self,
        hvf_vcpuid: u64,
        receiver: &Receiver<u32>,
        timeout: Option<Duration>,
    ) {
        if self.vcpu_list.should_wait(hvf_vcpuid) {
            if let Some(timeout) = timeout {
                match receiver.recv_timeout(timeout) {
                    Ok(_) => {}
                    Err(e) => match e {
                        RecvTimeoutError::Timeout => {}
                        RecvTimeoutError::Disconnected => panic!("WFE channel closed unexpectedly"),
                    },
                }
            } else {
                receiver.recv().unwrap();
            }
        }
    }

    /// Block in the paused event loop: handle Pause/SaveState/RestoreState and
    /// return `true` on Resume (caller proceeds to run the guest) or `false` on
    /// error / channel close (caller exits). Shared by the `Pause` event handler
    /// and the restore-into-a-clone paused start (see [`Vcpu::start_paused`]).
    fn run_paused_loop(&mut self, hvf_vcpuid: u64) -> bool {
        loop {
            match self.event_receiver.recv() {
                Ok(VcpuEvent::Resume { paused_ns }) => {
                    if hvf::vcpu_adjust_vtimer_offset(hvf_vcpuid, paused_ns).is_err() {
                        return false;
                    }
                    self.response_sender
                        .send(VcpuResponse::Resumed)
                        .expect("failed to send resume status");
                    return true;
                }
                Ok(VcpuEvent::Pause) => {
                    self.response_sender
                        .send(VcpuResponse::Paused)
                        .expect("failed to send pause status");
                }
                // Checkpoint: capture register state while paused (the safe
                // boundary). Stays paused afterwards.
                #[cfg(target_arch = "aarch64")]
                Ok(VcpuEvent::SaveState) => match hvf::vcpu_save_state(hvf_vcpuid) {
                    Ok(state) => self
                        .response_sender
                        .send(VcpuResponse::SavedState(Box::new(state)))
                        .expect("failed to send saved vcpu state"),
                    Err(e) => {
                        error!("failed to capture HVF vcpu state: {e:?}");
                        return false;
                    }
                },
                // Restore: load captured register state onto the paused vCPU.
                #[cfg(target_arch = "aarch64")]
                Ok(VcpuEvent::RestoreState(state)) => {
                    if let Err(e) = hvf::vcpu_restore_state(hvf_vcpuid, &state) {
                        let message = format!("{e:?}");
                        error!("failed to restore HVF vcpu state: {message}");
                        let _ = self
                            .response_sender
                            .send(VcpuResponse::RestoreFailed(message));
                        return false;
                    }
                    self.response_sender
                        .send(VcpuResponse::RestoredState)
                        .expect("failed to send restored vcpu ack");
                }
                Err(_) => return false,
            }
        }
    }

    fn handle_pending_event(&mut self, block: bool, hvf_vcpuid: u64) -> bool {
        let event = if block {
            match self.event_receiver.recv() {
                Ok(event) => Some(event),
                Err(_) => return false,
            }
        } else {
            match self.event_receiver.try_recv() {
                Ok(event) => Some(event),
                Err(crossbeam_channel::TryRecvError::Empty) => None,
                Err(crossbeam_channel::TryRecvError::Disconnected) => return false,
            }
        };

        match event {
            Some(VcpuEvent::Pause) => {
                self.response_sender
                    .send(VcpuResponse::Paused)
                    .expect("failed to send pause status");
                self.run_paused_loop(hvf_vcpuid)
            }
            Some(VcpuEvent::Resume { paused_ns }) => {
                if hvf::vcpu_adjust_vtimer_offset(hvf_vcpuid, paused_ns).is_err() {
                    return false;
                }
                self.response_sender
                    .send(VcpuResponse::Resumed)
                    .expect("failed to send resume status");
                true
            }
            // Save/restore are only valid while paused; the orchestrator always
            // pauses first, so receiving one here is a protocol error — ignore it.
            #[cfg(target_arch = "aarch64")]
            Some(VcpuEvent::SaveState) | Some(VcpuEvent::RestoreState(_)) => {
                error!("ignoring vcpu SaveState/RestoreState received while running");
                true
            }
            None => true,
        }
    }

    fn exit(&mut self, exit_code: u8) {
        self.response_sender
            .send(VcpuResponse::Exited(exit_code))
            .expect("failed to send Exited status");

        if let Err(e) = self.exit_evt.write(1) {
            error!("Failed signaling vcpu exit event: {e}");
        }
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        let _ = self.reset_thread_local_data();
    }
}

/// Captured HVF vCPU register state (the macOS analogue of KVM's `VcpuState`),
/// used by the cross-platform checkpoint/restore orchestration in `vmm::lib`.
#[cfg(target_arch = "aarch64")]
pub type VcpuState = hvf::HvfVcpuState;

/// VM-level state for a checkpoint. Empty on HVF (no in-kernel PIC/PIT/clock to
/// serialize); see [`Vm::save_state`].
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Debug, Default)]
pub struct VmState {
    /// In-kernel HVF GIC distributor registers as (reg-offset, value) pairs
    /// (see [`Vm::save_state`]). Empty when there is no in-kernel GIC.
    pub gic_distributor: Vec<(u32, u64)>,
}

#[cfg(target_arch = "aarch64")]
impl VmState {
    /// Serialize the VM-level state (the HVF GIC distributor registers) to a
    /// byte blob (mirrors the KVM `VmState::serialize` signature so the
    /// cross-platform [`crate::VmCheckpoint`] can call it uniformly).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.gic_distributor.len() * 12);
        out.extend_from_slice(&(self.gic_distributor.len() as u32).to_le_bytes());
        for &(reg, val) in &self.gic_distributor {
            out.extend_from_slice(&reg.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        out
    }

    /// Reconstruct from a blob produced by [`Self::serialize`].
    pub fn deserialize(bytes: &[u8]) -> std::result::Result<VmState, String> {
        if bytes.is_empty() {
            return Ok(VmState::default());
        }
        let err = || "macOS VmState blob truncated".to_string();
        let mut pos = 0usize;
        let take = |b: &[u8], pos: &mut usize, n: usize| -> std::result::Result<Vec<u8>, String> {
            if *pos + n > b.len() {
                return Err("macOS VmState blob truncated".to_string());
            }
            let s = b[*pos..*pos + n].to_vec();
            *pos += n;
            Ok(s)
        };
        let n =
            u32::from_le_bytes(take(bytes, &mut pos, 4)?.try_into().map_err(|_| err())?) as usize;
        let mut gic_distributor = Vec::with_capacity(n);
        for _ in 0..n {
            let reg = u32::from_le_bytes(take(bytes, &mut pos, 4)?.try_into().map_err(|_| err())?);
            let val = u64::from_le_bytes(take(bytes, &mut pos, 8)?.try_into().map_err(|_| err())?);
            gic_distributor.push((reg, val));
        }
        Ok(VmState { gic_distributor })
    }
}

#[derive(Debug)]
/// List of events that the Vcpu can receive.
pub enum VcpuEvent {
    /// Pause the Vcpu.
    Pause,
    /// Event that should resume the Vcpu.
    Resume { paused_ns: u64 },
    /// Capture the full vCPU register state (the vCPU must be paused).
    #[cfg(target_arch = "aarch64")]
    SaveState,
    /// Restore previously-captured vCPU register state (vCPU paused).
    #[cfg(target_arch = "aarch64")]
    RestoreState(Box<VcpuState>),
}

#[derive(Debug)]
/// List of responses that the Vcpu reports.
pub enum VcpuResponse {
    /// Vcpu is paused.
    Paused,
    /// Vcpu is resumed.
    Resumed,
    /// Vcpu is stopped.
    Exited(u8),
    /// Captured vCPU register state, in reply to [`VcpuEvent::SaveState`].
    #[cfg(target_arch = "aarch64")]
    SavedState(Box<VcpuState>),
    /// Acknowledges a [`VcpuEvent::RestoreState`].
    #[cfg(target_arch = "aarch64")]
    RestoredState,
    /// The vCPU rejected checkpoint state and cannot safely resume.
    #[cfg(target_arch = "aarch64")]
    RestoreFailed(String),
}

/// Wrapper over Vcpu that hides the underlying interactions with the Vcpu thread.
pub struct VcpuHandle {
    event_sender: Sender<VcpuEvent>,
    response_receiver: Receiver<VcpuResponse>,
    hvf_vcpuid: u64,
    vcpu_list: Arc<VcpuList>,
    // Held to own the vCPU thread's JoinHandle for the lifetime of the handle
    // (so the thread isn't detached); not read back.
    #[allow(dead_code)]
    vcpu_thread: Option<thread::JoinHandle<()>>,
}

impl VcpuHandle {
    pub fn new(
        event_sender: Sender<VcpuEvent>,
        response_receiver: Receiver<VcpuResponse>,
        hvf_vcpuid: u64,
        vcpu_list: Arc<VcpuList>,
        vcpu_thread: thread::JoinHandle<()>,
    ) -> Self {
        Self {
            event_sender,
            response_receiver,
            hvf_vcpuid,
            vcpu_list,
            vcpu_thread: Some(vcpu_thread),
        }
    }

    pub fn send_event(&self, event: VcpuEvent) -> Result<()> {
        self.event_sender
            .send(event)
            .map_err(|_| Error::VcpuEvent)?;

        hvf::vcpu_request_exit(self.hvf_vcpuid).map_err(Error::VcpuRequestExit)?;
        self.vcpu_list.wake(self.hvf_vcpuid);
        Ok(())
    }

    pub fn response_receiver(&self) -> &Receiver<VcpuResponse> {
        &self.response_receiver
    }
}

enum VcpuEmulation {
    Handled,
    Interrupted,
    Stopped,
    WaitForEvent,
    WaitForEventExpired,
    WaitForEventTimeout(Duration),
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use crossbeam_channel::RecvTimeoutError;
    use std::sync::Arc;
    #[cfg(target_arch = "x86_64")]
    use std::time::Duration;

    use super::*;
    use arch::aarch64::layout::DRAM_MEM_START_EFI;
    use devices::legacy::VcpuList;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    // Auxiliary function being used throughout the tests.
    // Does NOT create a real HVF VM — Vcpu::new_aarch64 and most vcpu methods
    // work without one, keeping tests free from the one-VM-per-process limit.
    fn setup_vcpu(mem_size: usize) -> (Vcpu, GuestMemoryMmap) {
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), mem_size)]).unwrap();
        let exit_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap();
        let vcpu_list = Arc::new(VcpuList::new(1));
        let vcpu = Vcpu::new_aarch64(1, GuestAddress(0), None, exit_evt, vcpu_list, false).unwrap();
        (vcpu, gm)
    }

    #[test]
    fn test_set_mmio_bus() {
        let (mut vcpu, _) = setup_vcpu(0x1000);
        assert!(vcpu.mmio_bus.is_none());
        vcpu.set_mmio_bus(devices::Bus::new());
        assert!(vcpu.mmio_bus.is_some());
    }

    #[test]
    fn test_vm_memory_init() {
        let mut vm = Vm::new(false).expect("Cannot create new vm");

        // Use a realistic guest physical address; hv_vm_map rejects GPA 0.
        let gm = GuestMemoryMmap::from_ranges(&[(
            GuestAddress(DRAM_MEM_START_EFI),
            0x20_0000, // 2 MB
        )])
        .unwrap();
        vm.memory_init(&gm).expect("memory_init failed");
    }

    #[test]
    fn test_configure_vcpu() {
        // configure_aarch64 only sets fdt_addr — no HVF VM needed.
        let mem_info = arch::ArchMemoryInfo::default();

        // Try it for when vcpu id is 0.
        let vcpu_list = Arc::new(VcpuList::new(1));
        let mut vcpu = Vcpu::new_aarch64(
            0,
            GuestAddress(0),
            None,
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            vcpu_list,
            false,
        )
        .unwrap();
        assert!(vcpu.configure_aarch64(&mem_info).is_ok());

        // Try it for when vcpu id is NOT 0.
        let vcpu_list = Arc::new(VcpuList::new(2));
        let mut vcpu = Vcpu::new_aarch64(
            1,
            GuestAddress(0),
            None,
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            vcpu_list,
            false,
        )
        .unwrap();
        assert!(vcpu.configure_aarch64(&mem_info).is_ok());
    }

    #[test]
    fn test_vcpu_tls() {
        let (mut vcpu, _) = setup_vcpu(0x1000);

        // Reset should fail before TLS is initialized.
        assert!(vcpu.reset_thread_local_data().is_err());

        // Initialize vcpu TLS.
        vcpu.init_thread_local_data().unwrap();

        // Reset vcpu TLS.
        assert!(vcpu.reset_thread_local_data().is_ok());

        // Second reset should return error.
        assert!(vcpu.reset_thread_local_data().is_err());
    }

    #[test]
    fn test_invalid_tls() {
        let (mut vcpu, _) = setup_vcpu(0x1000);
        // Initialize vcpu TLS.
        vcpu.init_thread_local_data().unwrap();
        // Trying to initialize non-empty TLS should error.
        vcpu.init_thread_local_data().unwrap_err();
    }

    #[cfg(target_arch = "x86_64")]
    // Sends an event to a vcpu and expects a particular response.
    fn queue_event_expect_response(handle: &VcpuHandle, event: VcpuEvent, response: VcpuResponse) {
        handle
            .send_event(event)
            .expect("failed to send event to vcpu");
        assert_eq!(
            handle
                .response_receiver()
                .recv_timeout(Duration::from_millis(100))
                .expect("did not receive event response from vcpu"),
            response
        );
    }

    #[cfg(target_arch = "x86_64")]
    // Sends an event to a vcpu and expects no response.
    fn queue_event_expect_timeout(handle: &VcpuHandle, event: VcpuEvent) {
        handle
            .send_event(event)
            .expect("failed to send event to vcpu");
        assert_eq!(
            handle
                .response_receiver()
                .recv_timeout(Duration::from_millis(100)),
            Err(RecvTimeoutError::Timeout)
        );
    }
}
