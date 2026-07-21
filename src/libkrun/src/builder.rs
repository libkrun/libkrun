use crossbeam_channel::Sender;
use std::fs::File;
use std::io::{self, IsTerminal};
#[cfg(unix)]
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle};
#[cfg(windows)]
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};
#[cfg(windows)]
use utils::windows::SendHandle;
#[cfg(windows)]
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

use vmm::builder::StartMicrovmError;
#[cfg(all(feature = "vhost-user", target_os = "linux"))]
use vmm::device_manager;
#[cfg(any(not(any(feature = "tee", feature = "aws-nitro")), feature = "gpu"))]
use vmm::device_manager::shm::ShmManager;
use vmm::{Error, Vmm};

use vmm::resources::{DefaultVirtioConsoleConfig, PortConfig, TsiFlags, VirtioConsoleConfigMode, VmResources};

#[cfg(feature = "net")]
use vmm::vmm_config::net::NetBuilder;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use vmm::vmm_config::fs::FsDeviceConfig;
#[cfg(feature = "blk")]
use vmm::vmm_config::block::BlockBuilder;
#[cfg(all(feature = "vhost-user", target_os = "linux"))]
use vmm::resources::VhostUserDeviceConfig;

use vmm::vmm_config::kernel_cmdline::DEFAULT_KERNEL_CMDLINE;

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use devices::virtio::passthrough::PermissionSemantics;
use devices::virtio::{PortDescription, Vsock, port_io};
use devices::legacy::{IrqChip, IrqChipDevice};
#[cfg(target_arch = "x86_64")]
use devices::legacy::{Cmos, IoApic, IrqChipT, KvmIoapic};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use devices::legacy::{KvmGicV2, KvmGicV3};
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use devices::legacy::{GicV3, HvfGicV3};
#[cfg(all(target_arch = "riscv64", target_os = "linux"))]
use devices::legacy::KvmAia;
#[cfg(target_os = "macos")]
use devices::legacy::VcpuList;
#[cfg(target_arch = "x86_64")]
use vmm::device_manager::legacy::PortIODeviceManager;

#[cfg(feature = "tee")]
use kbs_types::Tee;

#[cfg(target_os = "linux")]
use vmm::signal_handler::register_sigint_handler;
#[cfg(target_os = "linux")]
use vmm::signal_handler::register_sigwinch_handler;

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use devices::virtio::{VirtioShmRegion, fs::ExportTable};
#[cfg(feature = "gpu")]
use devices::display::DisplayInfo;
#[cfg(feature = "gpu")]
use devices::display::NoopDisplayBackend;
#[cfg(feature = "gpu")]
use krun_display::DisplayBackend;
#[cfg(feature = "gpu")]
use krun_display::IntoDisplayBackend;

#[cfg(feature = "amd-sev")]
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
#[cfg(unix)]
use libc::{STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};
#[cfg(unix)]
use nix::unistd::isatty;
use polly::event_manager::EventManager;
use utils::eventfd::EventFd;
use utils::worker_message::WorkerMessage;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use vm_memory::Address;
#[cfg(feature = "tee")]
use vm_memory::GuestAddress;
#[cfg(not(feature = "aws-nitro"))]
use vm_memory::GuestMemory;

use kernel::cmdline::Cmdline;

#[cfg(all(target_os = "linux", feature = "tee"))]
use vmm::vstate::MeasuredRegion;
#[cfg(feature = "tee")]
use vmm::vstate::KvmContext;
#[cfg(feature = "amd-sev")]
use vmm::vstate::Error as VstateError;

/// Builds and starts a microVM based on the current Firecracker VmResources configuration.
///
/// This is the default build recipe, one could build other microVM flavors by using the
/// independent functions in this module instead of calling this recipe.
///
/// An `Arc` reference of the built `Vmm` is also plugged in the `EventManager`, while another
/// is returned.
pub(crate) fn build_microvm(
    vm_resources: &VmResources,
    event_manager: &mut EventManager,
    _shutdown_efd: Option<EventFd>,
    _sender: Sender<WorkerMessage>,
) -> std::result::Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    let payload = vmm::builder::choose_payload(
        vm_resources.kernel_bundle.as_ref(),
        #[cfg(feature = "tee")]
        vm_resources.qboot_bundle.as_ref(),
        #[cfg(feature = "tee")]
        vm_resources.initrd_bundle.as_ref(),
        vm_resources.external_kernel(),
        vm_resources.firmware_config.as_ref(),
    )?;

    #[cfg(not(feature = "tee"))]
    let fs_shm_sizes: Vec<Option<usize>> = vm_resources.fs.iter().map(|f| f.shm_size).collect();
    #[cfg(feature = "tee")]
    let fs_shm_sizes: Vec<Option<usize>> = Vec::new();

    let (guest_memory, arch_memory_info, mut _shm_manager, payload_config) =
        vmm::builder::create_guest_memory(
            vm_resources
                .vm_config()
                .mem_size_mib
                .ok_or(StartMicrovmError::MissingMemSizeConfig)?,
            vm_resources.kernel_bundle.as_ref(),
            #[cfg(feature = "tee")]
            vm_resources.qboot_bundle.as_ref(),
            #[cfg(feature = "tee")]
            vm_resources.initrd_bundle.as_ref(),
            vm_resources.firmware_config.as_ref(),
            &fs_shm_sizes,
            vm_resources
                .gpu_virgl_flags
                .map(|_| vm_resources.gpu_shm_size.unwrap_or(1 << 33)),
            {
                #[cfg(all(feature = "vhost-user", target_os = "linux"))]
                {
                    !vm_resources.vhost_user_devices.is_empty()
                }
                #[cfg(not(all(feature = "vhost-user", target_os = "linux")))]
                {
                    false
                }
            },
            &payload,
        )?;

    let vcpu_config = vm_resources.vcpu_config();

    // Clone the command-line so that a failed boot doesn't pollute the original.
    #[allow(unused_mut)]
    let mut kernel_cmdline = Cmdline::new(arch::CMDLINE_MAX_SIZE);
    if let Some(cmdline) = payload_config.kernel_cmdline {
        kernel_cmdline.insert_str(cmdline.as_str()).unwrap();
    } else if let Some(cmdline) = &vm_resources.kernel_cmdline.prolog {
        kernel_cmdline.insert_str(cmdline).unwrap();
    } else {
        kernel_cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).unwrap();
    }

    if let Some(cmdline) = &vm_resources.kernel_cmdline.krun_env {
        kernel_cmdline.insert_str(cmdline.as_str()).unwrap();
    }

    if let Some(kernel_console) = &vm_resources.kernel_console {
        let cmdline = kernel_cmdline.as_str();
        let console_start_idx = cmdline.find("console=").unwrap();
        let console_end_idx = cmdline
            .get(console_start_idx..)
            .and_then(|s| s.find(" ").map(|i| i + console_start_idx));

        let cmdline = cmdline.replace(
            &cmdline[console_start_idx..console_end_idx.unwrap()],
            format!("console={kernel_console}").as_str(),
        );
        kernel_cmdline = Cmdline::new(arch::CMDLINE_MAX_SIZE);
        kernel_cmdline.insert_str(cmdline).unwrap();
    }

    #[cfg(not(feature = "tee"))]
    #[allow(unused_mut)]
    let mut vm = vmm::builder::setup_vm(&guest_memory, vm_resources.nested_enabled)?;

    #[cfg(feature = "tee")]
    let (_kvm, vm) = {
        let kvm = KvmContext::new()
            .map_err(Error::KvmContext)
            .map_err(StartMicrovmError::Internal)?;
        let vm = vmm::builder::setup_vm(
            &kvm,
            &guest_memory,
            vm_resources,
            #[cfg(feature = "tdx")]
            _sender.clone(),
        )?;
        (kvm, vm)
    };

    #[cfg(feature = "tee")]
    let tee = vm_resources.tee_config().tee;

    #[cfg(feature = "amd-sev")]
    let snp_launcher = match tee {
        Tee::Snp => Some(
            vm.snp_secure_virt_prepare(&guest_memory)
                .map_err(StartMicrovmError::SecureVirtPrepare)?,
        ),
        _ => None,
    };

    #[cfg(feature = "tdx")]
    let mut tdx_launcher = match tee {
        Tee::Tdx => vm
            .tdx_secure_virt_prepare()
            .map_err(StartMicrovmError::SecureVirtPrepare)?,
        _ => panic!(),
    };

    #[cfg(all(feature = "tee", not(feature = "tdx")))]
    let measured_regions = {
        println!("Injecting and measuring memory regions. This may take a while.");

        let qboot_size = if let Some(qboot_bundle) = &vm_resources.qboot_bundle {
            qboot_bundle.size
        } else {
            return Err(StartMicrovmError::MissingKernelConfig);
        };
        let (kernel_guest_addr, kernel_size) =
            if let Some(kernel_bundle) = &vm_resources.kernel_bundle {
                (kernel_bundle.guest_addr, kernel_bundle.size)
            } else {
                return Err(StartMicrovmError::MissingKernelConfig);
            };
        let (initrd_addr, initrd_size) = if let Some(initrd_config) = &payload_config.initrd_config
        {
            (initrd_config.address, initrd_config.size)
        } else {
            return Err(StartMicrovmError::MissingKernelConfig);
        };

        vec![
            MeasuredRegion {
                guest_addr: arch::FIRMWARE_START,
                host_addr: guest_memory
                    .get_host_address(GuestAddress(arch::FIRMWARE_START))
                    .unwrap() as u64,
                size: qboot_size,
            },
            MeasuredRegion {
                guest_addr: kernel_guest_addr,
                host_addr: guest_memory
                    .get_host_address(GuestAddress(kernel_guest_addr))
                    .unwrap() as u64,
                size: kernel_size,
            },
            MeasuredRegion {
                guest_addr: initrd_addr.0,
                host_addr: guest_memory.get_host_address(initrd_addr).unwrap() as u64,
                size: initrd_size,
            },
            MeasuredRegion {
                guest_addr: arch::x86_64::layout::ZERO_PAGE_START,
                host_addr: guest_memory
                    .get_host_address(GuestAddress(arch::x86_64::layout::ZERO_PAGE_START))
                    .unwrap() as u64,
                size: 4096,
            },
        ]
    };

    #[cfg(feature = "tdx")]
    let measured_regions = {
        println!("Injecting and measuring memory regions. This may take a while.");
        let qboot_size = if let Some(qboot_bundle) = &vm_resources.qboot_bundle {
            qboot_bundle.size
        } else {
            return Err(StartMicrovmError::MissingKernelConfig);
        };
        let m = vec![
            MeasuredRegion {
                guest_addr: 0,
                host_addr: guest_memory.get_host_address(GuestAddress(0)).unwrap() as u64,
                size: 0x8000_0000,
            },
            MeasuredRegion {
                guest_addr: arch::FIRMWARE_START,
                host_addr: guest_memory
                    .get_host_address(GuestAddress(arch::FIRMWARE_START))
                    .unwrap() as u64,
                size: qboot_size,
            },
        ];

        m
    };

    let mut serial_devices = Vec::new();

    // We can't call to `setup_terminal_raw_mode` until `Vmm` is created,
    // so let's keep track of FDs connected to legacy serial devices here
    // and set raw mode on them later.
    let mut serial_ttys = Vec::new();

    #[cfg(unix)]
    for s in &vm_resources.serial_consoles {
        let input: Option<Box<dyn devices::legacy::ReadableFd + Send>> = if s.input_fd >= 0 {
            let file = unsafe { File::from_raw_fd(s.input_fd) };
            if file.is_terminal() {
                serial_ttys.push(unsafe { BorrowedFd::borrow_raw(file.as_raw_fd()) });
            }
            Some(Box::new(file))
        } else {
            None
        };

        let output: Option<Box<dyn io::Write + Send>> = if s.output_fd >= 0 {
            Some(Box::new(unsafe { File::from_raw_fd(s.output_fd) }))
        } else {
            None
        };

        serial_devices.push(vmm::builder::setup_serial_device(event_manager, input, output)?);
    }

    #[cfg(windows)]
    for s in &vm_resources.serial_consoles {
        let input: Option<Box<dyn devices::legacy::ReadableFd + Send>> =
            if is_valid_handle(s.input_handle.as_raw_handle()) {
                if unsafe {
                    BorrowedHandle::borrow_raw(s.input_handle.as_raw_handle()).is_terminal()
                } {
                    serial_ttys.push(s.input_handle);
                }
                Some(Box::new(unsafe {
                    File::from_raw_handle(s.input_handle.as_raw_handle())
                }))
            } else {
                None
            };

        let output: Option<Box<dyn io::Write + Send>> =
            if is_valid_handle(s.output_handle.as_raw_handle()) {
                Some(Box::new(unsafe {
                    File::from_raw_handle(s.output_handle.as_raw_handle())
                }))
            } else {
                None
            };

        serial_devices.push(vmm::builder::setup_serial_device(event_manager, input, output)?);
    }

    let exit_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK)
        .map_err(Error::EventFd)
        .map_err(StartMicrovmError::Internal)?;

    #[cfg(target_arch = "x86_64")]
    // Safe to unwrap 'serial_device' as it's always 'Some' on x86_64.
    // x86_64 uses the i8042 reset event as the Vmm exit event.
    let mut pio_device_manager = PortIODeviceManager::new(
        Arc::new(Mutex::new(Cmos::new(
            arch_memory_info.ram_below_gap,
            arch_memory_info.ram_above_gap,
        ))),
        serial_devices,
        exit_evt
            .try_clone()
            .map_err(Error::EventFd)
            .map_err(StartMicrovmError::Internal)?,
    )
    .map_err(Error::CreateLegacyDevice)
    .map_err(StartMicrovmError::Internal)?;

    // Instantiate the MMIO device manager.
    // 'mmio_base' address has to be an address which is protected by the kernel
    // and is architectural specific.
    #[allow(unused_mut)]
    let mut mmio_device_manager = vmm::device_manager::mmio::MMIODeviceManager::new(
        &mut (arch::MMIO_MEM_START.clone()),
        (arch::IRQ_BASE, arch::IRQ_MAX),
    );

    #[cfg(target_os = "macos")]
    let vcpu_list = {
        let cpu_count = vm_resources.vm_config().vcpu_count.unwrap();
        Arc::new(VcpuList::new(cpu_count as u64))
    };

    let vcpus;
    let intc: IrqChip;
    // For x86_64 we need to create the interrupt controller before calling `KVM_CREATE_VCPUS`
    // while on aarch64 we need to do it the other way around.
    #[cfg(target_arch = "x86_64")]
    {
        let ioapic: Box<dyn IrqChipT> = if vm_resources.split_irqchip {
            Box::new(
                IoApic::new(vm.fd(), _sender.clone())
                    .map_err(StartMicrovmError::CreateKvmIrqChip)?,
            )
        } else {
            Box::new(KvmIoapic::new(vm.fd()).map_err(StartMicrovmError::CreateKvmIrqChip)?)
        };
        intc = Arc::new(Mutex::new(IrqChipDevice::new(ioapic)));

        vmm::builder::attach_legacy_devices(
            &vm,
            vm_resources.split_irqchip,
            &mut pio_device_manager,
            &mut mmio_device_manager,
            Some(intc.clone()),
        )?;

        let kernel_boot = vm_resources.firmware_config.is_none() && !cfg!(feature = "tee");

        vcpus = vmm::builder::create_vcpus_x86_64(
            &vm,
            &vcpu_config,
            &guest_memory,
            payload_config.entry_addr,
            &pio_device_manager.io_bus,
            &exit_evt,
            kernel_boot,
            payload_config.pvh,
            #[cfg(feature = "tee")]
            _sender,
        )
        .map_err(StartMicrovmError::Internal)?;
    }

    #[cfg(feature = "tdx")]
    {
        for vcpu in &vcpus {
            vcpu.tdx_secure_virt_prepare(&mut tdx_launcher);
        }
        vm.tdx_secure_virt_init_vcpus(&mut tdx_launcher).unwrap();
    }

    // On aarch64, the vCPUs need to be created (i.e call KVM_CREATE_VCPU) and configured before
    // setting up the IRQ chip because the `KVM_CREATE_VCPU` ioctl will return error if the IRQCHIP
    // was already initialized.
    // Search for `kvm_arch_vcpu_create` in arch/arm/kvm/arm.c.
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        vcpus = vmm::builder::create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &arch_memory_info,
            payload_config.entry_addr,
            &exit_evt,
        )
        .map_err(StartMicrovmError::Internal)?;

        intc = {
            // The SoC in some popular boards (namely, the RPi family) doesn't support an
            // architected vGIC, which is required for requesting KVM the instantiation of a
            // GICv3. To relieve the users from having to configure the gic version manually,
            // try first to instantiate a GICv3, and fall back to a GICv2 if it fails.
            let vcpu_count = vm_resources.vm_config().vcpu_count.unwrap() as u64;
            let gic = match KvmGicV3::new(vm.fd(), vcpu_count) {
                Ok(gicv3) => IrqChipDevice::new(Box::new(gicv3)),
                Err(_) => {
                    warn!("KVM GICv3 creation failed, falling back to KVM GICv2");
                    IrqChipDevice::new(Box::new(KvmGicV2::new(vm.fd(), vcpu_count)))
                }
            };
            Arc::new(Mutex::new(gic))
        };

        vmm::builder::attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            intc.clone(),
            serial_devices,
        )?;
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        intc = {
            // If the system supports the in-kernel GIC, use it. Otherwise, fall back to the
            // userspace implementation.
            let gic = match HvfGicV3::new(vm_resources.vm_config().vcpu_count.unwrap() as u64) {
                Ok(hvfgic) => IrqChipDevice::new(Box::new(hvfgic)),
                Err(_) => IrqChipDevice::new(Box::new(GicV3::new(vcpu_list.clone()))),
            };
            Arc::new(Mutex::new(gic))
        };

        vcpus = vmm::builder::create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &arch_memory_info,
            payload_config.entry_addr,
            &exit_evt,
            vcpu_list.clone(),
            vm_resources.nested_enabled,
        )
        .map_err(StartMicrovmError::Internal)?;

        vmm::builder::attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            intc.clone(),
            serial_devices,
            event_manager,
            _shutdown_efd,
        )?;
    }

    #[cfg(all(target_arch = "riscv64", target_os = "linux"))]
    {
        vcpus = vmm::builder::create_vcpus_riscv64(
            &vm,
            &vcpu_config,
            &guest_memory,
            payload_config.entry_addr,
            &exit_evt,
        )
        .map_err(StartMicrovmError::Internal)?;

        intc = Arc::new(Mutex::new(IrqChipDevice::new(Box::new(
            KvmAia::new(vm.fd(), vm_resources.vm_config().vcpu_count.unwrap() as u32).unwrap(),
        ))));

        vmm::builder::attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            intc.clone(),
            serial_devices,
        )?;
    }

    // We use this atomic to record the exit code set by init/init.c in the VM.
    let exit_code = Arc::new(AtomicI32::new(i32::MAX));

    #[cfg(target_os = "macos")]
    let (vm_ctl_tx, vm_ctl_rx) = utils::pollable_channel::pollable_channel();

    let mut vmm = Vmm {
        guest_memory,
        arch_memory_info,
        kernel_cmdline,
        vcpus_handles: Vec::new(),
        exit_evt,
        exit_observers: Vec::new(),
        exit_code: exit_code.clone(),
        vm,
        mmio_device_manager,
        #[cfg(target_arch = "x86_64")]
        pio_device_manager,
        #[cfg(target_os = "macos")]
        vm_ctl_tx,
        #[cfg(target_os = "macos")]
        vm_ctl_rx,
        #[cfg(target_os = "macos")]
        paused: false,
        #[cfg(target_os = "macos")]
        paused_at: 0,
    };

    // Set raw mode for FDs that are connected to legacy serial devices.
    for serial_tty in serial_ttys {
        vmm::builder::setup_terminal_raw_mode(&mut vmm, Some(serial_tty), false);
    }

    #[cfg(not(feature = "tee"))]
    attach_balloon_device(&mut vmm, event_manager, intc.clone())?;
    #[cfg(not(feature = "tee"))]
    {
        #[cfg(all(feature = "vhost-user", target_os = "linux"))]
        {
            const VIRTIO_ID_RNG: u32 = 4;
            for device_config in &vm_resources.vhost_user_devices {
                attach_vhost_user_device(&mut vmm, event_manager, intc.clone(), device_config)?;
            }

            let has_vhost_user_rng = vm_resources
                .vhost_user_devices
                .iter()
                .any(|dev| dev.device_type == VIRTIO_ID_RNG);

            if !has_vhost_user_rng {
                attach_rng_device(&mut vmm, event_manager, intc.clone())?;
            }
        }

        #[cfg(not(all(feature = "vhost-user", target_os = "linux")))]
        {
            attach_rng_device(&mut vmm, event_manager, intc.clone())?;
        }
    }
    for (console_id, console_cfg) in vm_resources.virtio_consoles.iter().enumerate() {
        attach_console_devices(
            &mut vmm,
            event_manager,
            intc.clone(),
            vm_resources,
            Some(console_cfg),
            console_id as u32,
        )?;
    }

    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    let export_table: Option<ExportTable> = if cfg!(feature = "gpu") {
        Some(Default::default())
    } else {
        None
    };

    #[cfg(feature = "gpu")]
    if let Some(virgl_flags) = vm_resources.gpu_virgl_flags {
        let display_backend = vm_resources
            .display_backend
            .unwrap_or_else(|| NoopDisplayBackend::into_display_backend(None));

        attach_gpu_device(
            &mut vmm,
            &mut _shm_manager,
            #[cfg(not(feature = "tee"))]
            export_table.clone(),
            intc.clone(),
            virgl_flags,
            Box::from(&vm_resources.displays[..]),
            display_backend,
            #[cfg(target_os = "macos")]
            _sender.clone(),
        )?;
    }

    #[cfg(feature = "input")]
    if !vm_resources.input_backends.is_empty() {
        attach_input_devices(&mut vmm, &vm_resources.input_backends, intc.clone())?;
    }

    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    attach_fs_devices(
        &mut vmm,
        &vm_resources.fs,
        &mut _shm_manager,
        #[cfg(not(feature = "tee"))]
        export_table,
        intc.clone(),
        exit_code,
        #[cfg(target_os = "macos")]
        _sender,
    )?;
    #[cfg(feature = "blk")]
    attach_block_devices(&mut vmm, &vm_resources.block, intc.clone())?;

    if let Some(vsock) = vm_resources.vsock.get() {
        attach_unixsock_vsock_device(&mut vmm, vsock, event_manager, intc.clone())?;
        let tsi_flags = vm_resources.vsock.tsi_flags();
        if tsi_flags.contains(TsiFlags::HIJACK_INET) {
            vmm.kernel_cmdline.insert_str("tsi_hijack")?;
        }
        if tsi_flags.contains(TsiFlags::HIJACK_UNIX) {
            vmm.kernel_cmdline.insert_str("tsi_hijack_unix")?;
        }
    }

    #[cfg(feature = "net")]
    attach_net_devices(&mut vmm, &vm_resources.net, intc.clone())?;
    #[cfg(feature = "net")]
    if vm_resources.dhcp_client {
        vmm.kernel_cmdline.insert_str("KRUN_DHCP=1")?;
    }

    if let Some(s) = &vm_resources.kernel_cmdline.epilog {
        vmm.kernel_cmdline.insert_str(s).unwrap();
    };

    // Write the kernel command line to guest memory. This is x86_64 specific, since on
    // aarch64 the command line will be specified through the FDT.
    #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
    vmm::builder::load_cmdline(&vmm)?;

    vmm.configure_system(
        vcpus.as_slice(),
        &intc,
        &payload_config.initrd_config,
        &vm_resources.smbios_oem_strings,
        payload_config.pvh,
    )
    .map_err(StartMicrovmError::Internal)?;

    #[cfg(feature = "tee")]
    {
        match tee {
            #[cfg(feature = "amd-sev")]
            Tee::Snp => {
                let cpuid = _kvm
                    .fd()
                    .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
                    .map_err(VstateError::KvmCpuId)
                    .map_err(StartMicrovmError::SecureVirtAttest)?;
                vmm.kvm_vm()
                    .snp_secure_virt_measure(
                        cpuid,
                        vmm.guest_memory(),
                        measured_regions,
                        snp_launcher.unwrap(),
                    )
                    .map_err(StartMicrovmError::SecureVirtAttest)?;
            }
            #[cfg(feature = "tdx")]
            Tee::Tdx => {
                vmm.kvm_vm()
                    .tdx_secure_virt_prepare_memory(&mut tdx_launcher, &measured_regions)
                    .unwrap();
                vmm.kvm_vm()
                    .tdx_secure_virt_finalize_vm(tdx_launcher)
                    .map_err(StartMicrovmError::SecureVirtPrepare)?;
            }
            _ => return Err(StartMicrovmError::InvalidTee),
        }

        println!("Starting TEE/microVM.");
    }

    vmm.start_vcpus(vcpus)
        .map_err(StartMicrovmError::Internal)?;

    // Clippy thinks we don't need Arc<Mutex<...
    // but we don't want to change the event_manager interface
    #[allow(clippy::arc_with_non_send_sync)]
    let vmm = Arc::new(Mutex::new(vmm));
    event_manager
        .add_subscriber(vmm.clone())
        .map_err(StartMicrovmError::RegisterEvent)?;

    Ok(vmm)
}

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
fn attach_fs_devices(
    vmm: &mut Vmm,
    fs_devs: &[FsDeviceConfig],
    shm_manager: &mut ShmManager,
    #[cfg(not(feature = "tee"))] export_table: Option<ExportTable>,
    intc: IrqChip,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")] map_sender: Sender<WorkerMessage>,
) -> std::result::Result<(), StartMicrovmError> {
    use StartMicrovmError::*;

    for (i, config) in fs_devs.iter().enumerate() {
        let fs = Arc::new(Mutex::new(
            devices::virtio::Fs::new(
                config.fs_id.clone(),
                PermissionSemantics::LinuxComplete,
                config.shared_dir.clone(),
                exit_code.clone(),
                config.read_only,
                config.virtual_entries.clone(),
            )
            .unwrap(),
        ));

        let id = format!("{}{}", String::from(fs.lock().unwrap().id()), i);

        if let Some(shm_region) = shm_manager.fs_region(i) {
            fs.lock().unwrap().set_shm_region(VirtioShmRegion {
                host_addr: vmm
                    .guest_memory
                    .get_host_address(shm_region.guest_addr)
                    .map_err(StartMicrovmError::ShmHostAddr)? as u64,
                guest_addr: shm_region.guest_addr.raw_value(),
                size: shm_region.size,
            });
        }

        #[cfg(not(feature = "tee"))]
        if let Some(export_table) = export_table.as_ref() {
            fs.lock().unwrap().set_export_table(export_table.clone());
        }

        #[cfg(target_os = "macos")]
        fs.lock().unwrap().set_map_sender(map_sender.clone());

        // The device mutex mustn't be locked here otherwise it will deadlock.
        vmm::builder::attach_mmio_device(vmm, id, intc.clone(), fs).map_err(RegisterFsDevice)?;
    }

    Ok(())
}

#[cfg(unix)]
fn autoconfigure_console_ports(
    vmm: &mut Vmm,
    _vm_resources: &VmResources,
    cfg: Option<&DefaultVirtioConsoleConfig>,
) -> std::result::Result<Vec<PortDescription>, StartMicrovmError> {
    let (input_fd, output_fd, err_fd) = match cfg {
        Some(c) => (c.input_fd, c.output_fd, c.err_fd),
        None => (STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO),
    };
    {
        let input_is_terminal =
            input_fd >= 0 && isatty(unsafe { BorrowedFd::borrow_raw(input_fd) }).unwrap_or(false);
        let output_is_terminal =
            output_fd >= 0 && isatty(unsafe { BorrowedFd::borrow_raw(output_fd) }).unwrap_or(false);
        let error_is_terminal =
            err_fd >= 0 && isatty(unsafe { BorrowedFd::borrow_raw(err_fd) }).unwrap_or(false);

        let term_fd = if input_is_terminal {
            Some(unsafe { BorrowedFd::borrow_raw(input_fd) })
        } else if output_is_terminal {
            Some(unsafe { BorrowedFd::borrow_raw(output_fd) })
        } else if error_is_terminal {
            Some(unsafe { BorrowedFd::borrow_raw(err_fd) })
        } else {
            None
        };

        let forwarding_sigint;
        let console_input = if input_is_terminal && input_fd >= 0 {
            forwarding_sigint = false;
            Some(port_io::input_to_raw_fd_dup(input_fd).unwrap())
        } else {
            #[cfg(target_os = "linux")]
            {
                forwarding_sigint = true;
                let sigint_input = port_io::PortInputSigInt::new();
                let sigint_input_fd = sigint_input.sigint_evt().as_raw_fd();
                register_sigint_handler(sigint_input_fd)
                    .map_err(StartMicrovmError::RegisterFsSigwinch)?;
                Some(Box::new(sigint_input) as _)
            }
            #[cfg(not(target_os = "linux"))]
            {
                forwarding_sigint = false;
                Some(port_io::input_empty().unwrap())
            }
        };

        let console_output = if output_is_terminal && output_fd >= 0 {
            Some(port_io::output_to_raw_fd_dup(output_fd).unwrap())
        } else {
            Some(port_io::output_to_log_as_err())
        };

        let terminal_properties = term_fd
            .map(|fd| port_io::term_fd(fd.as_raw_fd()).unwrap())
            .unwrap_or_else(|| port_io::term_fixed_size(0, 0));

        vmm::builder::setup_terminal_raw_mode(vmm, term_fd, forwarding_sigint);

        let mut ports = vec![PortDescription::console(
            console_input,
            console_output,
            terminal_properties,
        )];

        if input_fd >= 0 && !input_is_terminal {
            ports.push(PortDescription::input_pipe(
                "krun-stdin",
                port_io::input_to_raw_fd_dup(input_fd).unwrap(),
            ));
        }

        if output_fd >= 0 && !output_is_terminal {
            ports.push(PortDescription::output_pipe(
                "krun-stdout",
                port_io::output_to_raw_fd_dup(output_fd).unwrap(),
            ));
        };

        if err_fd >= 0 && !error_is_terminal {
            ports.push(PortDescription::output_pipe(
                "krun-stderr",
                port_io::output_to_raw_fd_dup(err_fd).unwrap(),
            ));
        }

        Ok(ports)
    }
}

#[cfg(windows)]
fn is_valid_handle(h: *mut core::ffi::c_void) -> bool {
    !h.is_null() && h != INVALID_HANDLE_VALUE
}

#[cfg(target_os = "windows")]
fn autoconfigure_console_ports(
    vmm: &mut Vmm,
    vm_resources: &VmResources,
    cfg: Option<&DefaultVirtioConsoleConfig>,
    creating_implicit_console: bool,
) -> std::result::Result<Vec<PortDescription>, StartMicrovmError> {
    use StartMicrovmError::*;

    let mut console_output_path: Option<PathBuf> = None;
    if let Some(path) = vm_resources.console_output.clone() {
        if !vm_resources.disable_implicit_console && creating_implicit_console {
            console_output_path = Some(path)
        }
    }

    if let Some(console_output_path) = console_output_path {
        let file = File::create(console_output_path).map_err(OpenConsoleFile)?;
        // Manually emulate our Legacy behavior: In the case of output_path we have always used the
        // stdin to determine the console size
        let stdin_h = unsafe { BorrowedHandle::borrow_raw(GetStdHandle(STD_INPUT_HANDLE)) };
        let term_h = if stdin_h.is_terminal() {
            port_io::term_handle(stdin_h.as_raw_handle()).unwrap()
        } else {
            port_io::term_fixed_size(0, 0)
        };
        Ok(vec![PortDescription::console(
            Some(port_io::input_empty().unwrap()),
            Some(port_io::output_file(file).unwrap()),
            term_h,
        )])
    } else {
        let (input_h, output_h, err_h) = match cfg {
            Some(c) => (
                c.input_handle.as_raw_handle(),
                c.output_handle.as_raw_handle(),
                c.err_handle.as_raw_handle(),
            ),
            None => unsafe {
                (
                    GetStdHandle(STD_INPUT_HANDLE),
                    GetStdHandle(STD_OUTPUT_HANDLE),
                    GetStdHandle(STD_ERROR_HANDLE),
                )
            },
        };
        let input_is_terminal = (unsafe { BorrowedHandle::borrow_raw(input_h) }).is_terminal();
        let output_is_terminal = (unsafe { BorrowedHandle::borrow_raw(output_h) }).is_terminal();
        let error_is_terminal = (unsafe { BorrowedHandle::borrow_raw(err_h) }).is_terminal();

        let term_h = if input_is_terminal {
            Some(SendHandle::new(input_h))
        } else if output_is_terminal {
            Some(SendHandle::new(output_h))
        } else if error_is_terminal {
            Some(SendHandle::new(err_h))
        } else {
            None
        };

        let forwarding_sigint = false;
        let console_input = if input_is_terminal {
            Some(port_io::input_to_handle_dup(input_h).unwrap())
        } else {
            Some(port_io::input_empty().unwrap())
        };

        let console_output = if output_is_terminal {
            Some(port_io::output_to_handle_dup(output_h).unwrap())
        } else {
            Some(port_io::output_to_log_as_err())
        };

        let terminal_properties = term_h
            .map(|h| port_io::term_handle(h.as_raw_handle()).unwrap())
            .unwrap_or_else(|| port_io::term_fixed_size(0, 0));

        vmm::builder::setup_terminal_raw_mode(vmm, term_h, forwarding_sigint);

        let mut ports = vec![PortDescription::console(
            console_input,
            console_output,
            terminal_properties,
        )];

        if is_valid_handle(input_h) && !input_is_terminal {
            ports.push(PortDescription::input_pipe(
                "krun-stdin",
                port_io::input_to_handle_dup(input_h).unwrap(),
            ));
        }

        if is_valid_handle(output_h) && !output_is_terminal {
            ports.push(PortDescription::output_pipe(
                "krun-stdout",
                port_io::output_to_handle_dup(output_h).unwrap(),
            ));
        };

        if is_valid_handle(err_h) && !error_is_terminal {
            ports.push(PortDescription::output_pipe(
                "krun-stderr",
                port_io::output_to_handle_dup(err_h).unwrap(),
            ));
        }

        Ok(ports)
    }
}

#[cfg(unix)]
fn create_explicit_ports(
    vmm: &mut Vmm,
    port_configs: &[PortConfig],
) -> std::result::Result<Vec<PortDescription>, StartMicrovmError> {
    let mut ports = Vec::with_capacity(port_configs.len());

    for port_cfg in port_configs {
        let port_desc = match port_cfg {
            PortConfig::Tty { name, tty_fd } => {
                assert!(*tty_fd > 0, "PortConfig::Tty must have a valid tty_fd");
                let term_fd = unsafe { BorrowedFd::borrow_raw(*tty_fd) };
                vmm::builder::setup_terminal_raw_mode(vmm, Some(term_fd), false);

                PortDescription {
                    name: name.clone().into(),
                    input: Some(port_io::input_to_raw_fd_dup(*tty_fd).unwrap()),
                    output: Some(port_io::output_to_raw_fd_dup(*tty_fd).unwrap()),
                    terminal: Some(port_io::term_fd(*tty_fd).unwrap()),
                }
            }
            PortConfig::InOut {
                name,
                input_fd,
                output_fd,
            } => PortDescription {
                name: name.clone().into(),
                input: if *input_fd < 0 {
                    None
                } else {
                    Some(port_io::input_to_raw_fd_dup(*input_fd).unwrap())
                },
                output: if *output_fd < 0 {
                    None
                } else {
                    Some(port_io::output_to_raw_fd_dup(*output_fd).unwrap())
                },
                terminal: None,
            },
        };

        ports.push(port_desc);
    }

    Ok(ports)
}

#[cfg(target_os = "windows")]
fn create_explicit_ports(
    vmm: &mut Vmm,
    port_configs: &[PortConfig],
) -> std::result::Result<Vec<PortDescription>, StartMicrovmError> {
    let mut ports = Vec::with_capacity(port_configs.len());

    for port_cfg in port_configs {
        let port_desc = match port_cfg {
            PortConfig::Tty { name, tty_handle } => {
                assert!(
                    is_valid_handle(tty_handle.as_raw_handle()),
                    "PortConfig::Tty must have a valid tty_handle"
                );
                let term_h = SendHandle::new(tty_handle.as_raw_handle());
                vmm::builder::setup_terminal_raw_mode(vmm, Some(term_h), false);

                PortDescription {
                    name: name.clone().into(),
                    input: Some(port_io::input_to_handle_dup(tty_handle.as_raw_handle()).unwrap()),
                    output: Some(
                        port_io::output_to_handle_dup(tty_handle.as_raw_handle()).unwrap(),
                    ),
                    terminal: Some(port_io::term_handle(tty_handle.as_raw_handle()).unwrap()),
                }
            }
            PortConfig::InOut {
                name,
                input_handle,
                output_handle,
            } => PortDescription {
                name: name.clone().into(),
                input: if !is_valid_handle(input_handle.as_raw_handle()) {
                    None
                } else {
                    Some(port_io::input_to_handle_dup(input_handle.as_raw_handle()).unwrap())
                },
                output: if !is_valid_handle(output_handle.as_raw_handle()) {
                    None
                } else {
                    Some(port_io::output_to_handle_dup(output_handle.as_raw_handle()).unwrap())
                },
                terminal: None,
            },
        };

        ports.push(port_desc);
    }

    Ok(ports)
}

fn attach_console_devices(
    vmm: &mut Vmm,
    event_manager: &mut EventManager,
    intc: IrqChip,
    vm_resources: &VmResources,
    cfg: Option<&VirtioConsoleConfigMode>,
    id_number: u32,
) -> std::result::Result<(), StartMicrovmError> {
    use StartMicrovmError::*;

    let ports = match cfg {
        None => autoconfigure_console_ports(vmm, vm_resources, None)?,
        Some(VirtioConsoleConfigMode::Autoconfigure(autocfg)) => {
            autoconfigure_console_ports(vmm, vm_resources, Some(autocfg))?
        }
        Some(VirtioConsoleConfigMode::Explicit(ports)) => create_explicit_ports(vmm, ports)?,
    };

    let console = Arc::new(Mutex::new(devices::virtio::Console::new(ports).unwrap()));

    vmm.exit_observers.push(console.clone());

    event_manager
        .add_subscriber(console.clone())
        .map_err(RegisterEvent)?;

    #[cfg(target_os = "linux")]
    register_sigwinch_handler(console.lock().unwrap().get_sigwinch_fd())
        .map_err(RegisterFsSigwinch)?;

    // The device mutex mustn't be locked here otherwise it will deadlock.
    vmm::builder::attach_mmio_device(vmm, format!("hvc{id_number}"), intc, console)
        .map_err(RegisterConsoleDevice)?;

    Ok(())
}

#[cfg(feature = "net")]
fn attach_net_devices(
    vmm: &mut Vmm,
    net_devices: &NetBuilder,
    intc: IrqChip,
) -> Result<(), StartMicrovmError> {
    for net_device in net_devices.list.iter() {
        let id = net_device.lock().unwrap().id().to_string();

        vmm::builder::attach_mmio_device(vmm, id, intc.clone(), net_device.clone())
            .map_err(StartMicrovmError::RegisterNetDevice)?;
    }
    Ok(())
}

fn attach_unixsock_vsock_device(
    vmm: &mut Vmm,
    unix_vsock: &Arc<Mutex<Vsock>>,
    event_manager: &mut EventManager,
    intc: IrqChip,
) -> std::result::Result<(), StartMicrovmError> {
    use StartMicrovmError::*;

    event_manager
        .add_subscriber(unix_vsock.clone())
        .map_err(RegisterEvent)?;

    let id = String::from(unix_vsock.lock().unwrap().id());

    // The device mutex mustn't be locked here otherwise it will deadlock.
    vmm::builder::attach_mmio_device(vmm, id, intc, unix_vsock.clone())
        .map_err(RegisterVsockDevice)?;

    Ok(())
}

#[cfg(not(feature = "tee"))]
fn attach_balloon_device(
    vmm: &mut Vmm,
    event_manager: &mut EventManager,
    intc: IrqChip,
) -> std::result::Result<(), StartMicrovmError> {
    use StartMicrovmError::*;

    let balloon = Arc::new(Mutex::new(devices::virtio::Balloon::new().unwrap()));

    event_manager
        .add_subscriber(balloon.clone())
        .map_err(RegisterEvent)?;

    let id = String::from(balloon.lock().unwrap().id());

    // The device mutex mustn't be locked here otherwise it will deadlock.
    vmm::builder::attach_mmio_device(vmm, id, intc.clone(), balloon)
        .map_err(RegisterBalloonDevice)?;

    Ok(())
}

#[cfg(feature = "blk")]
fn attach_block_devices(
    vmm: &mut Vmm,
    block_devs: &BlockBuilder,
    intc: IrqChip,
) -> std::result::Result<(), StartMicrovmError> {
    use StartMicrovmError::*;

    for block in block_devs.list.iter() {
        let id = String::from(block.lock().unwrap().id());

        // The device mutex mustn't be locked here otherwise it will deadlock.
        vmm::builder::attach_mmio_device(vmm, id, intc.clone(), block.clone())
            .map_err(RegisterBlockDevice)?;
    }

    Ok(())
}

#[cfg(not(feature = "tee"))]
fn attach_rng_device(
    vmm: &mut Vmm,
    event_manager: &mut EventManager,
    intc: IrqChip,
) -> std::result::Result<(), StartMicrovmError> {
    use StartMicrovmError::*;

    let rng = Arc::new(Mutex::new(devices::virtio::Rng::new().unwrap()));

    event_manager
        .add_subscriber(rng.clone())
        .map_err(RegisterEvent)?;

    let id = String::from(rng.lock().unwrap().id());

    // The device mutex mustn't be locked here otherwise it will deadlock.
    vmm::builder::attach_mmio_device(vmm, id, intc.clone(), rng).map_err(RegisterRngDevice)?;

    Ok(())
}

#[cfg(not(feature = "tee"))]
#[cfg(all(feature = "vhost-user", target_os = "linux"))]
fn attach_vhost_user_device(
    vmm: &mut Vmm,
    event_manager: &mut EventManager,
    intc: IrqChip,
    device_config: &VhostUserDeviceConfig,
) -> std::result::Result<(), StartMicrovmError> {
    use StartMicrovmError::*;

    let device_name = device_config
        .name
        .clone()
        .unwrap_or_else(|| format!("vhost-user-{}", device_config.device_type));

    let device = Arc::new(Mutex::new(
        devices::virtio::VhostUserDevice::new(
            &device_config.socket_path,
            device_config.device_type,
            device_name.clone(),
            device_config.num_queues,
            &device_config.queue_sizes,
            None,
        )
        .map_err(|e| RegisterVhostUserDevice(device_manager::mmio::Error::VhostUserDevice(e)))?,
    ));

    event_manager
        .add_subscriber(device.clone())
        .map_err(RegisterEvent)?;

    vmm::builder::attach_mmio_device(vmm, device_name, intc.clone(), device)
        .map_err(RegisterVhostUserDevice)?;

    Ok(())
}

#[cfg(feature = "gpu")]
#[allow(clippy::too_many_arguments)]
fn attach_gpu_device(
    vmm: &mut Vmm,
    shm_manager: &mut ShmManager,
    #[cfg(not(feature = "tee"))] mut export_table: Option<ExportTable>,
    intc: IrqChip,
    virgl_flags: u32,
    displays: Box<[DisplayInfo]>,
    display_backend: DisplayBackend<'static>,
    #[cfg(target_os = "macos")] map_sender: Sender<WorkerMessage>,
) -> std::result::Result<(), StartMicrovmError> {
    use StartMicrovmError::*;

    let gpu = Arc::new(Mutex::new(
        devices::virtio::Gpu::new(
            virgl_flags,
            displays,
            display_backend,
            #[cfg(target_os = "macos")]
            map_sender,
        )
        .unwrap(),
    ));

    let id = String::from(gpu.lock().unwrap().id());

    if let Some(shm_region) = shm_manager.gpu_region() {
        gpu.lock().unwrap().set_shm_region(VirtioShmRegion {
            host_addr: vmm
                .guest_memory
                .get_host_address(shm_region.guest_addr)
                .map_err(StartMicrovmError::ShmHostAddr)? as u64,
            guest_addr: shm_region.guest_addr.raw_value(),
            size: shm_region.size,
        });
    }

    #[cfg(not(feature = "tee"))]
    if let Some(export_table) = export_table.take() {
        gpu.lock().unwrap().set_export_table(export_table);
    }

    // The device mutex mustn't be locked here otherwise it will deadlock.
    vmm::builder::attach_mmio_device(vmm, id, intc, gpu).map_err(RegisterGpuDevice)?;

    Ok(())
}

#[cfg(feature = "input")]
fn attach_input_devices(
    vmm: &mut Vmm,
    input_backends: &[(
        krun_input::InputConfigBackend<'static>,
        krun_input::InputEventProviderBackend<'static>,
    )],
    intc: IrqChip,
) -> std::result::Result<(), StartMicrovmError> {
    use StartMicrovmError::*;

    for (index, (config_backend, events_backend)) in input_backends.iter().enumerate() {
        let input_device = Arc::new(Mutex::new(
            devices::virtio::input::Input::new(*config_backend, *events_backend).unwrap(),
        ));

        let id = format!("input{}", index);
        vmm::builder::attach_mmio_device(vmm, id, intc.clone(), input_device)
            .map_err(RegisterInputDevice)?;
    }

    Ok(())
}
