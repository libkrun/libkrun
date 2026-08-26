// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enables pre-boot setup, instantiation and booting of a Firecracker VMM.

use crossbeam_channel::Sender;
#[cfg(target_os = "macos")]
use crossbeam_channel::unbounded;
use kernel::cmdline::Cmdline;
#[cfg(target_os = "macos")]
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{self, IsTerminal, Read};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::fd::{BorrowedFd, FromRawFd};
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

use super::{Error, Vmm};

#[cfg(target_arch = "x86_64")]
use crate::device_manager::legacy::PortIODeviceManager;
use crate::device_manager::mmio::MMIODeviceManager;
use crate::resources::TsiFlags;
use crate::resources::{
    DefaultVirtioConsoleConfig, PortConfig, VirtioConsoleConfigMode, VmResources,
};
use crate::vmm_config::external_kernel::{ExternalKernel, KernelFormat};
#[cfg(feature = "net")]
use crate::vmm_config::net::NetBuilder;
#[cfg(target_arch = "x86_64")]
use devices::legacy::Cmos;
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use devices::legacy::IoApic;
#[cfg(target_arch = "x86_64")]
use devices::legacy::IrqChipT;
#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
use devices::legacy::KvmAia;
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use devices::legacy::KvmIoapic;
use devices::legacy::Serial;
#[cfg(target_os = "macos")]
use devices::legacy::VcpuList;
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
use devices::legacy::WhpIoapic;
#[cfg(target_os = "macos")]
use devices::legacy::{GicV3, HvfGicV3};
use devices::legacy::{IrqChip, IrqChipDevice};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
use devices::legacy::{KvmGicV2, KvmGicV3};
use devices::virtio::Vsock;
use devices::virtio::{MmioTransport, PortDescription, VirtioDevice, port_io};

#[cfg(feature = "tee")]
use kbs_types::Tee;

use crate::device_manager;
#[cfg(all(feature = "vhost-user", target_os = "linux"))]
use crate::resources::VhostUserDeviceConfig;
#[cfg(target_os = "linux")]
use crate::signal_handler::register_sigint_handler;
#[cfg(target_os = "linux")]
use crate::signal_handler::register_sigwinch_handler;
use crate::terminal::{term_restore_mode, term_set_raw_mode};
#[cfg(feature = "blk")]
use crate::vmm_config::block::BlockBuilder;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use crate::vmm_config::fs::FsDeviceConfig;
use crate::vmm_config::kernel_cmdline::DEFAULT_KERNEL_CMDLINE;
#[cfg(target_os = "linux")]
use crate::vstate::KvmContext;
#[cfg(all(target_os = "linux", feature = "tee"))]
use crate::vstate::MeasuredRegion;
use crate::vstate::{Error as VstateError, Vcpu, VcpuConfig, Vm};
use arch::{ArchMemoryInfo, InitrdConfig};
use device_manager::shm::ShmManager;
#[cfg(feature = "gpu")]
use devices::virtio::display::DisplayInfo;
#[cfg(feature = "gpu")]
use devices::virtio::display::NoopDisplayBackend;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use devices::virtio::{VirtioShmRegion, fs::ExportTable};
use flate2::read::GzDecoder;
#[cfg(feature = "gpu")]
use krun_display::DisplayBackend;
#[cfg(feature = "gpu")]
use krun_display::IntoDisplayBackend;
#[cfg(feature = "amd-sev")]
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
#[cfg(unix)]
use libc::{STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};
#[cfg(target_arch = "x86_64")]
use linux_loader::loader::{self, KernelLoader};
#[cfg(unix)]
use nix::unistd::isatty;
use polly::event_manager::{Error as EventManagerError, EventManager};
use utils::eventfd::EventFd;
use utils::worker_message::WorkerMessage;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use vm_memory::Address;
use vm_memory::Bytes;
#[cfg(all(feature = "vhost-user", target_os = "linux"))]
use vm_memory::FileOffset;
#[cfg(not(feature = "aws-nitro"))]
use vm_memory::GuestMemory;
#[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
use vm_memory::GuestRegionMmap;
#[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
use vm_memory::mmap::MmapRegion;
use vm_memory::{FileOffset, GuestAddress, GuestMemoryMmap};

/// Errors associated with starting the instance.
#[derive(Debug)]
pub enum StartMicrovmError {
    /// Unable to attach block device to Vmm.
    AttachBlockDevice(io::Error),
    #[cfg(target_os = "macos")]
    /// Failed to create HVF in-kernel IrqChip.
    CreateHvfIrqChip(hvf::Error),
    #[cfg(target_os = "linux")]
    /// Failed to create KVM in-kernel IrqChip.
    CreateKvmIrqChip(kvm_ioctls::Error),
    /// Failed to create a `RateLimiter` object.
    CreateRateLimiter(io::Error),
    /// Cannot open the file containing the kernel code.
    ElfOpenKernel(io::Error),
    /// Cannot load the kernel into the VM.
    ElfLoadKernel(linux_loader::loader::Error),
    /// The firmware can't be loaded into the provided memory address.
    FirmwareInvalidAddress(vm_memory::GuestMemoryError),
    /// Cannot read firmware contents from file.
    FirmwareRead(io::Error),
    /// Memory regions are overlapping or mmap fails.
    GuestMemoryMmap(String),
    /// The BZIP2 decoder couldn't decompress the kernel.
    ImageBz2Decoder(io::Error),
    /// Cannot find compressed kernel in file.
    ImageBz2Invalid,
    /// Cannot load the kernel from the uncompressed ELF data.
    ImageBz2LoadKernel(linux_loader::loader::Error),
    /// Cannot open the file containing the kernel code.
    ImageBz2OpenKernel(io::Error),
    /// The GZIP decoder couldn't decompress the kernel.
    ImageGzDecoder(io::Error),
    /// Cannot find compressed kernel in file.
    ImageGzInvalid,
    /// Cannot load the kernel from the uncompressed ELF data.
    ImageGzLoadKernel(linux_loader::loader::Error),
    /// Cannot open the file containing the kernel code.
    ImageGzOpenKernel(io::Error),
    /// The ZSTD decoder couldn't decompress the kernel.
    ImageZstdDecoder(io::Error),
    /// Cannot find compressed kernel in file.
    ImageZstdInvalid,
    /// Cannot load the kernel from the uncompressed ELF data.
    ImageZstdLoadKernel(linux_loader::loader::Error),
    /// Cannot open the file containing the kernel code.
    ImageZstdOpenKernel(io::Error),
    /// Cannot load initrd due to an invalid memory configuration.
    InitrdLoad,
    /// Cannot load initrd due to an invalid image.
    InitrdRead(io::Error),
    /// Internal error encountered while starting a microVM.
    Internal(Error),
    /// Cannot inject the kernel into the guest memory due to a problem with the bundle.
    InvalidKernelBundle(vm_memory::mmap::MmapRegionError),
    /// The kernel command line is invalid.
    KernelCmdline(String),
    /// The kernel doesn't fit into the microVM memory.
    KernelDoesNotFit(u64, usize),
    /// The supplied kernel format is not supported.
    KernelFormatUnsupported,
    /// Cannot load command line string.
    LoadCommandline(kernel::cmdline::Error),
    /// The start command was issued more than once.
    MicroVMAlreadyRunning,
    /// Cannot start the VM because the kernel was not configured.
    MissingKernelConfig,
    /// Cannot start the VM because the size of the guest memory  was not specified.
    MissingMemSizeConfig,
    /// The net device configuration is missing the tap device.
    NetDeviceNotConfigured,
    /// Cannot open the block device backing file.
    OpenBlockDevice(io::Error),
    /// Cannot open console output file.
    OpenConsoleFile(io::Error),
    /// The GZIP decoder couldn't decompress the kernel.
    PeGzDecoder(io::Error),
    /// Cannot open the file containing the kernel code.
    PeGzOpenKernel(io::Error),
    /// Cannot find compressed kernel in file.
    PeGzInvalid,
    /// Cannot open the file containing the kernel code.
    RawOpenKernel(io::Error),
    /// Cannot initialize a MMIO Balloon device or add a device to the MMIO Bus.
    RegisterBalloonDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Block Device or add a device to the MMIO Bus.
    RegisterBlockDevice(device_manager::mmio::Error),
    /// Cannot register an EventHandler.
    RegisterEvent(EventManagerError),
    /// Cannot initialize a MMIO Fs Device or add ad device to the MMIO Bus.
    RegisterFsDevice(device_manager::mmio::Error),
    // Cannot initialize a MMIO Fs Device or add ad device to the MMIO Bus.
    RegisterConsoleDevice(device_manager::mmio::Error),
    /// Cannot register SIGWINCH event file descriptor.
    #[cfg(target_os = "linux")]
    RegisterFsSigwinch(kvm_ioctls::Error),
    /// Cannot initialize a MMIO Gpu device or add a device to the MMIO Bus.
    RegisterGpuDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Input device or add a device to the MMIO Bus.
    RegisterInputDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Network Device or add a device to the MMIO Bus.
    RegisterNetDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Rng device or add a device to the MMIO Bus.
    RegisterRngDevice(device_manager::mmio::Error),
    /// Cannot initialize a vhost-user device or add a device to the MMIO Bus.
    RegisterVhostUserDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Vsock Device or add a device to the MMIO Bus.
    RegisterVsockDevice(device_manager::mmio::Error),
    /// Cannot attest the VM in the Secure Virtualization context.
    SecureVirtAttest(VstateError),
    /// Cannot initialize the Secure Virtualization backend.
    SecureVirtPrepare(VstateError),
    /// Error configuring an SHM region.
    ShmConfig(device_manager::shm::Error),
    /// Error creating an SHM region.
    ShmCreate(device_manager::shm::Error),
    /// Error obtaining the host address of an SHM region.
    ShmHostAddr(vm_memory::GuestMemoryError),
    /// The TEE specified is not supported.
    InvalidTee,
}

/// It's convenient to automatically convert `kernel::cmdline::Error`s
/// to `StartMicrovmError`s.
impl std::convert::From<kernel::cmdline::Error> for StartMicrovmError {
    fn from(e: kernel::cmdline::Error) -> StartMicrovmError {
        StartMicrovmError::KernelCmdline(e.to_string())
    }
}

impl Display for StartMicrovmError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::StartMicrovmError::*;
        match *self {
            AttachBlockDevice(ref err) => {
                write!(f, "Unable to attach block device to Vmm. Error: {err}")
            }
            #[cfg(target_os = "macos")]
            CreateHvfIrqChip(ref err) => {
                write!(f, "Cannot create HVF in-kernel IrqChip: {err}")
            }
            #[cfg(target_os = "linux")]
            CreateKvmIrqChip(ref err) => {
                write!(f, "Cannot create KVM in-kernel IrqChip: {err}")
            }
            CreateRateLimiter(ref err) => write!(f, "Cannot create RateLimiter: {err}"),
            ElfOpenKernel(ref err) => {
                write!(f, "Cannot open the file containing the kernel code: {err}")
            }
            ElfLoadKernel(ref err) => {
                write!(f, "Cannot load the kernel into the VM: {err}")
            }
            FirmwareInvalidAddress(ref err) => {
                write!(
                    f,
                    "The firmware can't be loaded into the guest memory: {err}"
                )
            }
            FirmwareRead(ref err) => {
                write!(f, "Cannot read firmware contents from file: {err}")
            }
            GuestMemoryMmap(ref err) => {
                // Remove imbricated quotes from error message.
                let mut err_msg = format!("{err:?}");
                err_msg = err_msg.replace('\"', "");
                write!(f, "Invalid Memory Configuration: {err_msg}")
            }
            ImageBz2Decoder(ref err) => {
                write!(f, "The BZIP2 decoder couldn't decompress the kernel. {err}")
            }
            ImageBz2Invalid => {
                write!(f, "Cannot find compressed kernel in file.")
            }
            ImageBz2LoadKernel(ref err) => {
                write!(
                    f,
                    "Cannot load the kernel from the uncompressed ELF data. {err}"
                )
            }
            ImageBz2OpenKernel(ref err) => {
                write!(f, "Cannot open the file containing the kernel code. {err}")
            }
            ImageGzDecoder(ref err) => {
                write!(f, "The GZIP decoder couldn't decompress the kernel. {err}")
            }
            ImageGzInvalid => {
                write!(f, "Cannot find compressed kernel in file.")
            }
            ImageGzLoadKernel(ref err) => {
                write!(
                    f,
                    "Cannot load the kernel from the uncompressed ELF data. {err}"
                )
            }
            ImageGzOpenKernel(ref err) => {
                write!(f, "Cannot open the file containing the kernel code. {err}")
            }
            ImageZstdDecoder(ref err) => {
                write!(f, "The ZSTD decoder couldn't decompress the kernel. {err}")
            }
            ImageZstdInvalid => {
                write!(f, "Cannot find compressed kernel in file.")
            }
            ImageZstdLoadKernel(ref err) => {
                write!(
                    f,
                    "Cannot load the kernel from the uncompressed ELF data. {err}"
                )
            }
            ImageZstdOpenKernel(ref err) => {
                write!(f, "Cannot open the file containing the kernel code. {err}")
            }
            InitrdLoad => write!(
                f,
                "Cannot load initrd due to an invalid memory configuration."
            ),
            InitrdRead(ref err) => write!(f, "Cannot load initrd due to an invalid image: {err}"),
            Internal(ref err) => write!(f, "Internal error while starting microVM: {err:?}"),
            InvalidKernelBundle(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot inject the kernel into the guest memory due to a problem with the \
                     bundle. {err_msg}"
                )
            }
            KernelCmdline(ref err) => write!(f, "Invalid kernel command line: {err}"),
            KernelDoesNotFit(load_addr, size) => write!(
                f,
                "The kernel doesn't fit in the microVM memory (load_addr={load_addr}, size={size})"
            ),
            KernelFormatUnsupported => {
                write!(f, "The supplied kernel format is not supported.")
            }
            LoadCommandline(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(f, "Cannot load command line string. {err_msg}")
            }
            MicroVMAlreadyRunning => write!(f, "Microvm already running."),
            MissingKernelConfig => write!(f, "Cannot start microvm without kernel configuration."),
            MissingMemSizeConfig => {
                write!(f, "Cannot start microvm without guest mem_size config.")
            }
            NetDeviceNotConfigured => {
                write!(f, "The net device configuration is missing the tap device.")
            }
            OpenBlockDevice(ref err) => {
                let mut err_msg = format!("{err:?}");
                err_msg = err_msg.replace('\"', "");

                write!(f, "Cannot open the block device backing file. {err_msg}")
            }
            OpenConsoleFile(ref err) => {
                let mut err_msg = format!("{err:?}");
                err_msg = err_msg.replace('\"', "");

                write!(f, "Cannot open the console output file. {err_msg}")
            }
            PeGzDecoder(ref err) => {
                write!(f, "The GZIP decoder couldn't decompress the kernel. {err}")
            }
            PeGzOpenKernel(ref err) => {
                write!(f, "Cannot open the file containing the kernel code. {err}")
            }
            PeGzInvalid => {
                write!(f, "Cannot find compressed kernel in file.")
            }
            RawOpenKernel(ref err) => {
                write!(f, "Cannot open the file containing the kernel code: {err}")
            }
            RegisterBalloonDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a MMIO Balloon Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterBlockDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a MMIO Block Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterEvent(ref err) => write!(f, "Cannot register EventHandler. {err:?}"),
            RegisterFsDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot initialize a MMIO Fs Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterConsoleDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot initialize a MMIO Console Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            #[cfg(target_os = "linux")]
            RegisterFsSigwinch(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot register SIGWINCH file descriptor for Fs Device. {err_msg}"
                )
            }
            RegisterGpuDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a MMIO Gpu Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterInputDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a MMIO Input Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterNetDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot initialize a MMIO Network Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterRngDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a MMIO Rng Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterVhostUserDevice(ref err) => {
                let mut err_msg = err.to_string();
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a vhost-user device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            RegisterVsockDevice(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot initialize a MMIO Vsock Device or add a device to the MMIO Bus. {err_msg}"
                )
            }
            SecureVirtAttest(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot attest the VM in the Secure Virtualization context. {err_msg}"
                )
            }
            SecureVirtPrepare(ref err) => {
                let mut err_msg = format!("{err}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Cannot initialize the Secure Virtualization backend. {err_msg}"
                )
            }
            ShmHostAddr(ref err) => {
                let mut err_msg = format!("{err:?}");
                err_msg = err_msg.replace('\"', "");

                write!(
                    f,
                    "Error obtaining the host address of an SHM region. {err_msg}"
                )
            }
            ShmConfig(ref err) => {
                let mut err_msg = format!("{err:?}");
                err_msg = err_msg.replace('\"', "");

                write!(f, "Error while configuring an SHM region. {err_msg}")
            }
            ShmCreate(ref err) => {
                let mut err_msg = format!("{err:?}");
                err_msg = err_msg.replace('\"', "");

                write!(f, "Error while creating an SHM region. {err_msg}")
            }
            InvalidTee => {
                write!(f, "TEE selected is not currently supported")
            }
        }
    }
}

pub enum Payload {
    #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
    KernelMmap,
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    KernelCopy,
    ExternalKernel(ExternalKernel),
    #[cfg(test)]
    Empty,
    Firmware,
    #[cfg(feature = "tee")]
    Tee,
}

fn choose_payload(vm_resources: &VmResources) -> Result<Payload, StartMicrovmError> {
    if let Some(_kernel_bundle) = &vm_resources.kernel_bundle {
        #[cfg(feature = "tee")]
        if vm_resources.qboot_bundle.is_none() || vm_resources.initrd_bundle.is_none() {
            return Err(StartMicrovmError::MissingKernelConfig);
        }

        #[cfg(feature = "tee")]
        return Ok(Payload::Tee);

        #[cfg(all(
            any(target_os = "linux", target_os = "windows"),
            target_arch = "x86_64",
            not(feature = "tee")
        ))]
        return Ok(Payload::KernelMmap);

        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        return Ok(Payload::KernelCopy);
    } else if let Some(external_kernel) = vm_resources.external_kernel() {
        Ok(Payload::ExternalKernel(external_kernel.clone()))
    } else if vm_resources.firmware_config.is_some() {
        Ok(Payload::Firmware)
    } else {
        Err(StartMicrovmError::MissingKernelConfig)
    }
}

/// Builds and starts a microVM based on the current Firecracker VmResources configuration.
///
/// This is the default build recipe, one could build other microVM flavors by using the
/// independent functions in this module instead of calling this recipe.
///
/// An `Arc` reference of the built `Vmm` is also plugged in the `EventManager`, while another
/// is returned.
/// Restore context for building a VM from a checkpoint (cross-process fork /
/// hibernate-restore) instead of cold-booting. Platform-neutral: `checkpoint`
/// is the serialized [`VmCheckpoint`] blob (so this type needs no per-arch cfg),
/// deserialized only on platforms that support restore.
pub struct RestoreCtx {
    /// Guest RAM for the clone — a CoW clone of the golden VM's memory (Linux
    /// `memfd` `MAP_PRIVATE`) / `vm_remap` (macOS), already holding the image.
    pub guest_memory: GuestMemoryMmap,
    /// One entry per guest-memory region. `true` identifies RAM that was
    /// file-backed by the source and must be materialized when this clone is
    /// promoted; `false` preserves device SHM/GPU regions as anonymous.
    pub fork_backed_regions: Vec<bool>,
    /// Serialized `VmCheckpoint` (VM + vCPU + device state).
    pub checkpoint: Vec<u8>,
}

pub fn build_microvm(
    vm_resources: &super::resources::VmResources,
    event_manager: &mut EventManager,
    _shutdown_efd: Option<EventFd>,
    _sender: Sender<WorkerMessage>,
    restore: Option<RestoreCtx>,
) -> std::result::Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    let t_vmm = std::time::Instant::now();
    let vmm_timing_on = std::env::var("LIBKRUN_TIMING").is_ok();
    macro_rules! vmm_timing {
        ($label:expr) => {
            if vmm_timing_on {
                eprintln!("[vmm] {:28} {}ms", $label, t_vmm.elapsed().as_millis());
            }
        };
    }

    let payload = choose_payload(vm_resources)?;
    vmm_timing!("payload selected");

    let (guest_memory, arch_memory_info, mut _shm_manager, payload_config) = create_guest_memory(
        vm_resources
            .vm_config()
            .mem_size_mib
            .ok_or(StartMicrovmError::MissingMemSizeConfig)?,
        vm_resources,
        &payload,
        restore
            .as_ref()
            .map(|r| (r.guest_memory.clone(), r.fork_backed_regions.clone())),
    )?;
    vmm_timing!("memory created");

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

    #[cfg(all(not(feature = "tee"), not(target_os = "windows")))]
    #[allow(unused_mut)]
    let mut vm = setup_vm(&guest_memory, vm_resources.nested_enabled)?;
    // WHP needs the virtual-processor count at partition-creation time.
    #[cfg(all(not(feature = "tee"), target_os = "windows"))]
    #[allow(unused_mut)]
    let mut vm = setup_vm(&guest_memory, vm_resources.vm_config().vcpu_count.unwrap())?;
    #[cfg(not(feature = "tee"))]
    vmm_timing!("vm created (HVF+mmap)");

    #[cfg(feature = "tee")]
    let (_kvm, vm) = {
        let kvm = KvmContext::new()
            .map_err(Error::KvmContext)
            .map_err(StartMicrovmError::Internal)?;
        let vm = setup_vm(
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

        serial_devices.push(setup_serial_device(event_manager, input, output)?);
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

        serial_devices.push(setup_serial_device(event_manager, input, output)?);
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
    let mut mmio_device_manager = MMIODeviceManager::new(
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
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
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

        attach_legacy_devices(
            &vm,
            vm_resources.split_irqchip,
            &mut pio_device_manager,
            &mut mmio_device_manager,
            Some(intc.clone()),
        )?;

        // When restoring (fork/hibernate) the guest is past boot: skip boot vCPU
        // setup, which writes boot page tables/GDT into guest memory via
        // `setup_sregs` and would corrupt the cloned running-state RAM. The vCPU
        // registers are loaded from the checkpoint by `restore_vcpu_states`.
        let kernel_boot =
            restore.is_none() && vm_resources.firmware_config.is_none() && !cfg!(feature = "tee");

        vcpus = create_vcpus_x86_64(
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

    // x86_64 on WHP: the interrupt controller is the WHP IOAPIC, and vCPUs are
    // backed by WHP virtual processors (no KVM ioctls / cpuid/msr fixups here —
    // WHP handles CPUID/MSR via run-loop exits).
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    {
        let ioapic: Box<dyn IrqChipT> = Box::new(WhpIoapic::new(vm.whp_vm().clone()));
        intc = Arc::new(Mutex::new(IrqChipDevice::new(ioapic)));

        attach_legacy_devices(
            &vm,
            vm_resources.split_irqchip,
            &mut pio_device_manager,
            &mut mmio_device_manager,
            Some(intc.clone()),
        )?;

        vcpus = create_vcpus_x86_64_whp(
            &vm,
            &vcpu_config,
            &guest_memory,
            payload_config.entry_addr,
            &pio_device_manager.io_bus,
            &exit_evt,
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
        vcpus = create_vcpus_aarch64(
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
                Ok(gicv3) => {
                    // Register the vGICv3 with the VM so checkpoint/restore
                    // (fork) can transfer its state; per-CPU registers are
                    // addressed by each vCPU's MPIDR.
                    vm.register_vgic(
                        gicv3.device_fd(),
                        vcpus.iter().map(|v| v.get_mpidr()).collect(),
                    );
                    IrqChipDevice::new(Box::new(gicv3))
                }
                Err(_) => {
                    warn!("KVM GICv3 creation failed, falling back to KVM GICv2");
                    let gicv2 = KvmGicV2::new(vm.fd(), vcpu_count);
                    // Register the vGICv2 with the VM so checkpoint/restore
                    // (fork) can transfer its state; per-CPU registers are
                    // addressed by vCPU index (v2's cpuid attr field).
                    vm.register_vgic_v2(gicv2.device_fd(), vcpu_count);
                    IrqChipDevice::new(Box::new(gicv2))
                }
            };
            Arc::new(Mutex::new(gic))
        };

        attach_legacy_devices(
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

        vcpus = create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &arch_memory_info,
            payload_config.entry_addr,
            &exit_evt,
            vcpu_list.clone(),
            vm_resources.nested_enabled,
        )
        .map_err(StartMicrovmError::Internal)?;

        attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            intc.clone(),
            serial_devices,
            event_manager,
            _shutdown_efd,
        )?;
    }
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    vmm_timing!("vcpus + irq created");

    #[cfg(all(target_arch = "riscv64", target_os = "linux"))]
    {
        vcpus = create_vcpus_riscv64(
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

        attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            intc.clone(),
            serial_devices,
        )?;
    }

    // We use this atomic to record the exit code set by init/init.c in the VM.
    let exit_code = Arc::new(AtomicI32::new(i32::MAX));

    let mut vmm = Vmm {
        guest_memory,
        arch_memory_info,
        kernel_cmdline,
        vcpus_handles: Vec::new(),
        run_state: super::VmmRunState::Paused,
        paused_at: None,
        devices_quiesced: false,
        exit_evt,
        exit_observers: Vec::new(),
        exit_code: exit_code.clone(),
        vm,
        mmio_device_manager,
        #[cfg(not(feature = "tee"))]
        balloon: None,
        #[cfg(target_arch = "x86_64")]
        pio_device_manager,
        #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
        intc: intc.clone(),
    };

    // Set raw mode for FDs that are connected to legacy serial devices.
    for serial_tty in serial_ttys {
        setup_terminal_raw_mode(&mut vmm, Some(serial_tty), false);
    }

    vmm_timing!("before device attach");
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

    // WHP's emulated LAPIC timer delivers no interrupts to the guest, so steer
    // the guest onto its i8253 (PIT) clockevent — which we emulate (see the
    // `Pit` device) — instead of the dead LAPIC timer. Without this the guest
    // calibrates and selects the LAPIC timer and then never ticks.
    #[cfg(target_os = "windows")]
    vmm.kernel_cmdline.insert_str("nolapic_timer")?;

    #[cfg(feature = "net")]
    attach_net_devices(&mut vmm, &vm_resources.net, intc.clone())?;
    #[cfg(feature = "net")]
    if vm_resources.dhcp_client {
        vmm.kernel_cmdline.insert_str("KRUN_DHCP=1")?;
    }

    if let Some(s) = &vm_resources.kernel_cmdline.epilog {
        vmm.kernel_cmdline.insert_str(s).unwrap();
    };
    vmm_timing!("devices attached");

    // Boot-time system configuration (cmdline, zero-page/FDT, boot regs) is
    // SKIPPED when restoring — the clone's guest RAM + restored vCPU/device
    // state already encode a running guest past boot.
    if restore.is_none() {
        // Write the kernel command line to guest memory. This is x86_64 specific, since on
        // aarch64 the command line will be specified through the FDT.
        #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
        load_cmdline(&vmm)?;

        vmm.configure_system(
            vcpus.as_slice(),
            &intc,
            &payload_config.initrd_config,
            &vm_resources.smbios_oem_strings,
            payload_config.pvh,
        )
        .map_err(StartMicrovmError::Internal)?;
        vmm_timing!("system configured (FDT)");
    }

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

    match restore {
        None => {
            vmm.start_vcpus(vcpus)
                .map_err(StartMicrovmError::Internal)?;
            vmm_timing!("vcpus running");
        }
        Some(_ctx) => {
            // Restore-into-a-fresh-clone: start vCPUs paused, apply the
            // checkpoint (VM + device re-activation + vCPU registers), then
            // resume so the clone runs from the checkpoint instruction.
            #[cfg(fork_supported)]
            {
                let checkpoint = super::VmCheckpoint::deserialize(&_ctx.checkpoint)
                    .map_err(StartMicrovmError::GuestMemoryMmap)?;
                vmm.start_vcpus_paused(vcpus)
                    .map_err(StartMicrovmError::Internal)?;
                vmm.apply_restore(checkpoint)
                    .map_err(StartMicrovmError::Internal)?;
                // Device re-activation signals each device's activate eventfd; the
                // event manager must process those (registering the RX/TX queue
                // handlers) BEFORE the guest resumes. Otherwise the clone resumes
                // into a window where guest queue kicks (e.g. vsock TX) are not
                // serviced and the agent channel never completes its handshake.
                for _ in 0..8 {
                    let _ = event_manager.run_with_timeout(0);
                }
                vmm.resume().map_err(StartMicrovmError::Internal)?;
                vmm_timing!("vcpus restored + running");
            }
            #[cfg(not(fork_supported))]
            {
                let _ = vcpus;
                return Err(StartMicrovmError::GuestMemoryMmap(
                    "restore-from-snapshot is not supported on this platform".to_string(),
                ));
            }
        }
    }

    // Clippy thinks we don't need Arc<Mutex<...
    // but we don't want to change the event_manager interface
    #[allow(clippy::arc_with_non_send_sync)]
    let vmm = Arc::new(Mutex::new(vmm));
    event_manager
        .add_subscriber(vmm.clone())
        .map_err(StartMicrovmError::RegisterEvent)?;
    vmm_timing!("build_microvm complete");

    Ok(vmm)
}

fn load_external_kernel(
    guest_mem: &GuestMemoryMmap,
    arch_mem_info: &ArchMemoryInfo,
    external_kernel: &ExternalKernel,
) -> std::result::Result<
    (GuestAddress, Option<InitrdConfig>, Option<String>, bool),
    StartMicrovmError,
> {
    #[allow(unused_mut)]
    let mut pvh = false;
    let entry_addr = match external_kernel.format {
        // Raw images are treated as bundled kernels on x86_64
        #[cfg(target_arch = "x86_64")]
        KernelFormat::Raw => unreachable!(),
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        KernelFormat::Raw => {
            let data: Vec<u8> = std::fs::read(external_kernel.path.clone())
                .map_err(StartMicrovmError::RawOpenKernel)?;
            guest_mem.write(&data, GuestAddress(0x8000_0000)).unwrap();
            GuestAddress(0x8000_0000)
        }
        #[cfg(target_arch = "x86_64")]
        // TODO(whp-host): linux-loader's ELF load needs `File: ReadVolatile`, which
        // vm-memory only implements on Unix. Port external ELF kernel loading to
        // Windows (e.g. read into a buffer and load from a `ReadVolatile` slice).
        #[cfg(target_os = "windows")]
        KernelFormat::Elf => {
            return Err(StartMicrovmError::ElfOpenKernel(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "external ELF kernel loading is not yet supported on Windows (WHP)",
            )));
        }
        #[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
        KernelFormat::Elf => {
            let mut file = File::options()
                .read(true)
                .write(false)
                .open(external_kernel.path.clone())
                .map_err(StartMicrovmError::ElfOpenKernel)?;
            let load_result = loader::Elf::load(guest_mem, None, &mut file, None)
                .map_err(StartMicrovmError::ElfLoadKernel)?;
            match load_result.pvh_boot_cap {
                loader::PvhBootCapability::PvhEntryPresent(guest_address) => {
                    pvh = true;
                    guest_address
                }
                _ => load_result.kernel_load,
            }
        }
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        KernelFormat::PeGz => {
            let data: Vec<u8> = std::fs::read(external_kernel.path.clone())
                .map_err(StartMicrovmError::PeGzOpenKernel)?;
            if let Some(magic) = data
                .windows(3)
                .position(|window| window == [0x1f, 0x8b, 0x8])
            {
                debug!("Found GZIP header on PE file at: 0x{magic:x}");
                let (_, compressed) = data.split_at(magic);
                let mut gz = GzDecoder::new(compressed);
                let mut kernel_data: Vec<u8> = Vec::new();
                gz.read_to_end(&mut kernel_data)
                    .map_err(StartMicrovmError::PeGzDecoder)?;
                guest_mem
                    .write(&kernel_data, GuestAddress(0x8000_0000))
                    .unwrap();
                GuestAddress(0x8000_0000)
            } else {
                return Err(StartMicrovmError::PeGzInvalid);
            }
        }
        #[cfg(target_arch = "x86_64")]
        KernelFormat::ImageBz2 => {
            let data: Vec<u8> = std::fs::read(external_kernel.path.clone())
                .map_err(StartMicrovmError::ImageBz2OpenKernel)?;
            if let Some(magic) = data.windows(3).position(|window| window == *b"BZh") {
                debug!("Found BZIP2 header on Image file at: 0x{magic:x}");
                let (_, compressed) = data.split_at(magic);
                let mut kernel_data: Vec<u8> = Vec::new();
                let mut bz2 = bzip2::read::BzDecoder::new(compressed);
                bz2.read_to_end(&mut kernel_data)
                    .map_err(StartMicrovmError::ImageBz2Decoder)?;
                let load_result = loader::Elf::load(
                    guest_mem,
                    None,
                    &mut std::io::Cursor::new(kernel_data),
                    None,
                )
                .map_err(StartMicrovmError::ImageBz2LoadKernel)?;
                load_result.kernel_load
            } else {
                return Err(StartMicrovmError::ImageBz2Invalid);
            }
        }
        #[cfg(target_arch = "x86_64")]
        KernelFormat::ImageGz => {
            let data: Vec<u8> = std::fs::read(external_kernel.path.clone())
                .map_err(StartMicrovmError::ImageGzOpenKernel)?;
            if let Some(magic) = data
                .windows(3)
                .position(|window| window == [0x1f, 0x8b, 0x8])
            {
                debug!("Found GZIP header on Image file at: 0x{magic:x}");
                let (_, compressed) = data.split_at(magic);
                let mut gz = GzDecoder::new(compressed);
                let mut kernel_data: Vec<u8> = Vec::new();
                gz.read_to_end(&mut kernel_data)
                    .map_err(StartMicrovmError::ImageGzDecoder)?;
                let load_result = loader::Elf::load(
                    guest_mem,
                    None,
                    &mut std::io::Cursor::new(kernel_data),
                    None,
                )
                .map_err(StartMicrovmError::ImageGzLoadKernel)?;
                load_result.kernel_load
            } else {
                return Err(StartMicrovmError::ImageGzInvalid);
            }
        }
        #[cfg(target_arch = "x86_64")]
        KernelFormat::ImageZstd => {
            let data: Vec<u8> = std::fs::read(external_kernel.path.clone())
                .map_err(StartMicrovmError::ImageZstdOpenKernel)?;
            if let Some(magic) = data
                .windows(4)
                .position(|window| window == [0x28, 0xb5, 0x2f, 0xfd])
            {
                debug!("Found ZSTD header on Image file at: 0x{magic:x}");
                let (_, zstd_data) = data.split_at(magic);
                let mut kernel_data: Vec<u8> = Vec::new();
                let _ = zstd::stream::copy_decode(zstd_data, &mut kernel_data);
                let load_result = loader::Elf::load(
                    guest_mem,
                    None,
                    &mut std::io::Cursor::new(kernel_data),
                    None,
                )
                .map_err(StartMicrovmError::ImageZstdLoadKernel)?;
                load_result.kernel_load
            } else {
                return Err(StartMicrovmError::ImageZstdInvalid);
            }
        }
        _ => return Err(StartMicrovmError::KernelFormatUnsupported),
    };

    debug!("load_external_kernel: 0x{:x}", entry_addr.0);

    let initrd_config = if let Some(initramfs_path) = &external_kernel.initramfs_path {
        let data = std::fs::read(initramfs_path).map_err(StartMicrovmError::InitrdRead)?;
        guest_mem
            .write(&data, GuestAddress(arch_mem_info.initrd_addr))
            .unwrap();
        Some(InitrdConfig {
            address: GuestAddress(arch_mem_info.initrd_addr),
            size: data.len(),
        })
    } else {
        None
    };

    Ok((
        entry_addr,
        initrd_config,
        external_kernel.cmdline.clone(),
        pvh,
    ))
}

struct LoadedPayload {
    guest_mem: GuestMemoryMmap,
    entry_addr: GuestAddress,
    initrd_config: Option<InitrdConfig>,
    kernel_cmdline: Option<String>,
    pvh: bool,
}

fn load_payload(
    _vm_resources: &VmResources,
    guest_mem: GuestMemoryMmap,
    _arch_mem_info: &ArchMemoryInfo,
    payload: &Payload,
) -> std::result::Result<LoadedPayload, StartMicrovmError> {
    match payload {
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        Payload::KernelCopy => {
            let (kernel_entry_addr, kernel_host_addr, kernel_guest_addr, kernel_size) =
                if let Some(kernel_bundle) = &_vm_resources.kernel_bundle {
                    (
                        kernel_bundle.entry_addr,
                        kernel_bundle.host_addr,
                        kernel_bundle.guest_addr,
                        kernel_bundle.size,
                    )
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };

            let kernel_data =
                unsafe { std::slice::from_raw_parts(kernel_host_addr as *mut u8, kernel_size) };
            if kernel_guest_addr + kernel_size as u64 > _arch_mem_info.ram_last_addr {
                return Err(StartMicrovmError::KernelDoesNotFit(
                    kernel_guest_addr,
                    kernel_size,
                ));
            }
            guest_mem
                .write(kernel_data, GuestAddress(kernel_guest_addr))
                .unwrap();
            Ok(LoadedPayload {
                guest_mem,
                entry_addr: GuestAddress(kernel_entry_addr),
                initrd_config: None,
                kernel_cmdline: None,
                pvh: false,
            })
        }
        #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
        Payload::KernelMmap => {
            let (kernel_entry_addr, kernel_host_addr, kernel_guest_addr, kernel_size) =
                if let Some(kernel_bundle) = &_vm_resources.kernel_bundle {
                    (
                        kernel_bundle.entry_addr,
                        kernel_bundle.host_addr,
                        kernel_bundle.guest_addr,
                        kernel_bundle.size,
                    )
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };

            #[cfg(all(feature = "vhost-user", target_os = "linux"))]
            let use_vhost_user = !_vm_resources.vhost_user_devices.is_empty();
            #[cfg(not(all(feature = "vhost-user", target_os = "linux")))]
            let use_vhost_user = false;

            let kernel_region = if use_vhost_user {
                #[cfg(all(feature = "vhost-user", target_os = "linux"))]
                {
                    debug!(
                        "Creating file-backed kernel region for vhost-user (size=0x{:x})",
                        kernel_size
                    );
                    // SAFETY: memfd_create is called with a valid null-terminated C string and valid flags.
                    // File descriptor ownership is transferred to File::from_raw_fd below.
                    let memfd = unsafe {
                        let fd = libc::memfd_create(c"kernel".as_ptr(), libc::MFD_CLOEXEC);
                        if fd < 0 {
                            error!(
                                "Failed to create memfd for kernel: {:?}",
                                io::Error::last_os_error()
                            );
                            return Err(StartMicrovmError::GuestMemoryMmap(format!(
                                "memfd_create failed: {:?}",
                                io::Error::last_os_error()
                            )));
                        }
                        if libc::ftruncate(fd, kernel_size as i64) < 0 {
                            error!(
                                "Failed to ftruncate kernel memfd: {:?}",
                                io::Error::last_os_error()
                            );
                            libc::close(fd);
                            return Err(StartMicrovmError::GuestMemoryMmap(format!(
                                "ftruncate failed: {:?}",
                                io::Error::last_os_error()
                            )));
                        }
                        debug!("Created kernel memfd with fd={}", fd);
                        File::from_raw_fd(fd)
                    };

                    let file_offset = FileOffset::new(memfd, 0);
                    let region = MmapRegion::from_file(file_offset, kernel_size)
                        .map_err(StartMicrovmError::InvalidKernelBundle)?;

                    // SAFETY: kernel_host_addr points to valid kernel data of size kernel_size,
                    // provided by the kernel bundle loader.
                    let kernel_data = unsafe {
                        std::slice::from_raw_parts(kernel_host_addr as *const u8, kernel_size)
                    };
                    // SAFETY: Both source (kernel_data) and destination (region) are valid for
                    // kernel_size bytes. Regions don't overlap as dest is newly allocated memfd-backed
                    // memory and source is from kernel bundle.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            kernel_data.as_ptr(),
                            region.as_ptr(),
                            kernel_size,
                        );
                    }
                    debug!("Copied kernel data to file-backed region");

                    region
                }
                #[cfg(not(all(feature = "vhost-user", target_os = "linux")))]
                unreachable!()
            } else if memfd_backed_ram_enabled() {
                // Forkable: back the kernel region with a memfd (copying the
                // kernel image in) so its runtime-mutated pages (.data/.bss) are
                // CoW-shareable to clones — a `build_raw` view of libkrunfw's
                // buffer is anonymous and would be zeroed on a clone.
                let memfd = create_guest_ram_memfd(kernel_size).map_err(|e| {
                    StartMicrovmError::GuestMemoryMmap(format!("kernel memfd: {e}"))
                })?;
                let region = MmapRegion::from_file(FileOffset::new(memfd, 0), kernel_size)
                    .map_err(StartMicrovmError::InvalidKernelBundle)?;
                // Safety: copy `kernel_size` bytes from libkrunfw's kernel buffer
                // into the freshly-mapped memfd region (both are `kernel_size`).
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        kernel_host_addr as *const u8,
                        region.as_ptr(),
                        kernel_size,
                    );
                }
                region
            } else {
                // SAFETY: kernel_host_addr points to valid kernel data of size kernel_size.
                // The memory region is managed by the kernel bundle and remains valid.
                #[cfg(not(target_os = "windows"))]
                let region = unsafe {
                    MmapRegion::build_raw(kernel_host_addr as *mut u8, kernel_size, 0, 0)
                        .map_err(StartMicrovmError::InvalidKernelBundle)?
                };
                // vm-memory has no `build_raw` (raw-pointer view) on Windows; allocate a
                // fresh anonymous region and copy the kernel image in.
                // TODO(whp-host): a zero-copy view of libkrunfw's buffer would avoid the copy.
                #[cfg(target_os = "windows")]
                let region = {
                    let region = MmapRegion::new(kernel_size)
                        .map_err(StartMicrovmError::InvalidKernelBundle)?;
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            kernel_host_addr as *const u8,
                            region.as_ptr(),
                            kernel_size,
                        );
                    }
                    region
                };
                region
            };

            Ok(LoadedPayload {
                guest_mem: guest_mem
                    .insert_region(Arc::new(
                        GuestRegionMmap::new(kernel_region, GuestAddress(kernel_guest_addr))
                            .ok_or_else(|| {
                                StartMicrovmError::GuestMemoryMmap(
                                    "Failed to create GuestRegionMmap".to_string(),
                                )
                            })?,
                    ))
                    .map_err(|e| StartMicrovmError::GuestMemoryMmap(format!("{e:?}")))?,
                entry_addr: GuestAddress(kernel_entry_addr),
                initrd_config: None,
                kernel_cmdline: None,
                pvh: false,
            })
        }
        Payload::ExternalKernel(external_kernel) => {
            let (entry_addr, initrd_config, cmdline, pvh) =
                load_external_kernel(&guest_mem, _arch_mem_info, external_kernel)?;
            Ok(LoadedPayload {
                guest_mem,
                entry_addr,
                initrd_config,
                kernel_cmdline: cmdline,
                pvh,
            })
        }
        #[cfg(test)]
        Payload::Empty => Ok(LoadedPayload {
            guest_mem,
            entry_addr: GuestAddress(0),
            initrd_config: None,
            kernel_cmdline: None,
            pvh: false,
        }),
        #[cfg(feature = "tee")]
        Payload::Tee => {
            let (kernel_host_addr, kernel_guest_addr, kernel_size) =
                if let Some(kernel_bundle) = &_vm_resources.kernel_bundle {
                    (
                        kernel_bundle.host_addr,
                        kernel_bundle.guest_addr,
                        kernel_bundle.size,
                    )
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };
            let kernel_data =
                unsafe { std::slice::from_raw_parts(kernel_host_addr as *mut u8, kernel_size) };
            guest_mem
                .write(kernel_data, GuestAddress(kernel_guest_addr))
                .unwrap();

            let (qboot_host_addr, qboot_size) =
                if let Some(qboot_bundle) = &_vm_resources.qboot_bundle {
                    (qboot_bundle.host_addr, qboot_bundle.size)
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };
            let qboot_data =
                unsafe { std::slice::from_raw_parts(qboot_host_addr as *mut u8, qboot_size) };
            guest_mem
                .write(qboot_data, GuestAddress(arch::FIRMWARE_START))
                .unwrap();

            let (initrd_host_addr, initrd_size) =
                if let Some(initrd_bundle) = &_vm_resources.initrd_bundle {
                    (initrd_bundle.host_addr, initrd_bundle.size)
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };
            let initrd_data =
                unsafe { std::slice::from_raw_parts(initrd_host_addr as *mut u8, initrd_size) };
            guest_mem
                .write(initrd_data, GuestAddress(_arch_mem_info.initrd_addr))
                .unwrap();

            let initrd_config = InitrdConfig {
                address: GuestAddress(_arch_mem_info.initrd_addr),
                size: initrd_data.len(),
            };

            Ok(LoadedPayload {
                guest_mem,
                entry_addr: GuestAddress(arch::RESET_VECTOR),
                initrd_config: Some(initrd_config),
                kernel_cmdline: None,
                pvh: false,
            })
        }
        Payload::Firmware => Ok(LoadedPayload {
            guest_mem,
            entry_addr: GuestAddress(arch::RESET_VECTOR),
            initrd_config: None,
            kernel_cmdline: None,
            pvh: false,
        }),
    }
}

pub struct PayloadConfig {
    entry_addr: GuestAddress,
    initrd_config: Option<InitrdConfig>,
    kernel_cmdline: Option<String>,
    pvh: bool,
}

/// Whether guest RAM should be `memfd`-backed (CoW-fork-cloneable) instead of
/// anonymous. Opt-in via `SMOLVM_FORKABLE=1`; Linux-only (`memfd_create`).
/// True when guest RAM should be backed by a real, CoW-cloneable file object
/// (for fast VM fork): a `memfd` on Linux, a regular temp file on macOS (which
/// has no `memfd`, but a file mmap'd `MAP_PRIVATE` gives the same cross-process
/// CoW — validated against HVF). Gated on the per-VM `SMOLVM_FORKABLE` opt-in.
fn memfd_backed_ram_enabled() -> bool {
    (cfg!(target_os = "linux") || cfg!(target_os = "macos") || cfg!(target_os = "windows"))
        && std::env::var_os("SMOLVM_FORKABLE").is_some_and(|v| v == "1")
}

/// Create an anonymous, RAM-backed `memfd` of `size` bytes to back a guest-RAM
/// region. Being a real file object, it can later be CoW-cloned with
/// `mmap(MAP_PRIVATE)` for fast, dense VM fork.
#[cfg(target_os = "linux")]
pub(crate) fn create_guest_ram_memfd(size: usize) -> std::result::Result<File, String> {
    use std::os::fd::FromRawFd;
    let name = std::ffi::CString::new("smolvm-guest-ram").expect("static name");
    // Safety: passing a valid C string and flags; the returned fd is owned.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(format!("memfd_create: {}", std::io::Error::last_os_error()));
    }
    // Safety: `fd` is a fresh, owned file descriptor from memfd_create.
    let file = unsafe { File::from_raw_fd(fd) };
    file.set_len(size as u64)
        .map_err(|e| format!("sizing guest-RAM memfd to {size}: {e}"))?;
    Ok(file)
}

/// Directory backing the macOS guest-RAM temp files (`$TMPDIR`, else `/tmp`).
#[cfg(target_os = "macos")]
fn guest_ram_dir() -> String {
    std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string())
}

/// Reap guest-RAM backing files left by forkable goldens whose process is gone.
///
/// macOS has no `memfd` and no `DELETE_ON_CLOSE`, and a forkable golden is
/// typically killed externally (no clean-shutdown hook), so its RAM file can't
/// be unlinked on exit. The file name embeds the creating pid; before each
/// forkable launch we remove any file whose pid is no longer alive
/// (`kill(pid, 0)` → `ESRCH`), which bounds disk use instead of leaking the
/// multi-hundred-MB RAM images across launches. A file owned by a LIVE process
/// is left untouched — a running golden is still serving clones by that path.
#[cfg(target_os = "macos")]
fn reap_orphaned_guest_ram() {
    reap_orphaned_guest_ram_in(&guest_ram_dir());
}

#[cfg(target_os = "macos")]
fn reap_orphaned_guest_ram_in(dir: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid_str) = name
            .to_str()
            .and_then(|n| n.strip_prefix("smolvm-guest-ram-"))
            .and_then(|rest| rest.split('-').next())
        else {
            continue;
        };
        // Legacy (pre-pid) names carry no parseable pid; leave them for manual
        // cleanup since liveness can't be determined from the name alone.
        let Ok(pid) = pid_str.parse::<libc::pid_t>() else {
            continue;
        };
        // Safety: signal 0 only probes for the process's existence, sends nothing.
        let dead = unsafe { libc::kill(pid, 0) } != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        if dead {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// macOS has no `memfd`; back the guest-RAM region with a regular temp file
/// instead. mmap'd `MAP_SHARED` it serves the golden's RAM, and a clone re-opens
/// the same path and maps it `MAP_PRIVATE` for copy-on-write (validated: HVF
/// honors the host CoW on guest writes). The path is recovered at fork time via
/// `fcntl(F_GETPATH)`, so the file is NOT unlinked while the golden lives.
/// Cleanup is by liveness instead: the name embeds the creating pid and dead-pid
/// files are reaped on the next forkable launch (see `reap_orphaned_guest_ram`).
#[cfg(target_os = "macos")]
pub(crate) fn create_guest_ram_memfd(size: usize) -> std::result::Result<File, String> {
    use std::os::fd::FromRawFd;
    use std::sync::Once;
    // Reap leftovers from dead goldens once per process, before creating ours.
    static REAP: Once = Once::new();
    REAP.call_once(reap_orphaned_guest_ram);
    let dir = guest_ram_dir();
    let pid = std::process::id();
    let mut template = format!(
        "{}/smolvm-guest-ram-{pid}-XXXXXX",
        dir.trim_end_matches('/')
    )
    .into_bytes();
    template.push(0);
    // Safety: `template` is a NUL-terminated, writable buffer; mkstemp fills in
    // the XXXXXX and returns an owned fd to the freshly-created file.
    let fd = unsafe { libc::mkstemp(template.as_mut_ptr() as *mut libc::c_char) };
    if fd < 0 {
        return Err(format!(
            "mkstemp guest-RAM file: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Safety: `fd` is a fresh, owned fd from mkstemp.
    let file = unsafe { File::from_raw_fd(fd) };
    file.set_len(size as u64)
        .map_err(|e| format!("sizing guest-RAM file to {size}: {e}"))?;
    Ok(file)
}

/// Windows has no `memfd`; back the guest-RAM region with a regular temp file
/// (the macOS model). vm-memory maps it `FILE_MAP_ALL_ACCESS` to serve the
/// golden's RAM, and a clone re-opens the same path to read its image. The path
/// is recovered at fork time via `GetFinalPathNameByHandleW`.
///
/// The file is opened `FILE_FLAG_DELETE_ON_CLOSE` with share read/write/delete,
/// so the OS reclaims it once every handle is closed — i.e. when the frozen
/// golden process dies (it is typically killed externally, so there is no clean
/// shutdown hook to unlink it) and any clone that eager-copied it has finished.
/// Without this the multi-hundred-MB RAM files leak into `%TEMP%` and fill the
/// disk across forks.
#[cfg(target_os = "windows")]
pub(crate) fn create_guest_ram_memfd(size: usize) -> std::result::Result<File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    const FILE_SHARE_READ_WRITE_DELETE: u32 = 0x1 | 0x2 | 0x4;
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    // Unique per (process, call) without needing a RNG: pid + monotonic counter.
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("smolvm-guest-ram-{pid}-{n}.bin"));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ_WRITE_DELETE)
        .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
        .open(&path)
        .map_err(|e| format!("create guest-RAM file {}: {e}", path.display()))?;
    file.set_len(size as u64)
        .map_err(|e| format!("sizing guest-RAM file to {size}: {e}"))?;
    Ok(file)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn create_guest_ram_memfd(_size: usize) -> std::result::Result<File, String> {
    Err("forkable guest RAM is Linux/macOS/Windows-only".to_string())
}

/// Build the `(GuestAddress, size, Option<FileOffset>)` list for
/// `from_ranges_with_files`: the first `ram_region_count` regions get their own
/// guest-RAM `memfd`; the trailing SHM/GPU regions stay anonymous (`None`).
fn build_memfd_backed_ranges(
    regions: &[(GuestAddress, usize)],
    ram_region_count: usize,
) -> std::result::Result<Vec<(GuestAddress, usize, Option<FileOffset>)>, String> {
    let mut out = Vec::with_capacity(regions.len());
    for (i, &(addr, size)) in regions.iter().enumerate() {
        let file = if i < ram_region_count {
            Some(FileOffset::new(create_guest_ram_memfd(size)?, 0))
        } else {
            None
        };
        out.push((addr, size, file));
    }
    Ok(out)
}

pub fn create_guest_memory(
    mem_size: usize,
    vm_resources: &VmResources,
    payload: &Payload,
    // Restore mode: when `Some`, use this guest memory (a CoW clone of a golden
    // VM's RAM that already contains the running image) instead of allocating
    // fresh, and SKIP loading the kernel/firmware/initrd. The same memory layout
    // (config) must have produced it.
    restore_mem: Option<(GuestMemoryMmap, Vec<bool>)>,
) -> std::result::Result<
    (GuestMemoryMmap, ArchMemoryInfo, ShmManager, PayloadConfig),
    StartMicrovmError,
> {
    let mem_size = mem_size << 20;

    let (firmware_data, firmware_size) = if let Some(firmware) = &vm_resources.firmware_config {
        let data = std::fs::read(firmware.path.clone()).map_err(StartMicrovmError::FirmwareRead)?;
        let len = data.len();
        (Some(data), Some(len))
    } else {
        (None, None)
    };

    #[cfg(target_arch = "x86_64")]
    let (arch_mem_info, mut arch_mem_regions) = match payload {
        #[cfg(not(feature = "tee"))]
        Payload::KernelMmap => {
            let (kernel_guest_addr, kernel_size) =
                if let Some(kernel_bundle) = &vm_resources.kernel_bundle {
                    (kernel_bundle.guest_addr, kernel_bundle.size)
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };
            arch::arch_memory_regions(mem_size, Some(kernel_guest_addr), kernel_size, 0, None)
        }
        Payload::ExternalKernel(external_kernel) => arch::arch_memory_regions(
            mem_size,
            None,
            0,
            external_kernel.initramfs_size,
            firmware_size,
        ),
        #[cfg(feature = "tee")]
        Payload::Tee => {
            let (kernel_guest_addr, kernel_size) =
                if let Some(kernel_bundle) = &vm_resources.kernel_bundle {
                    (kernel_bundle.guest_addr, kernel_bundle.size)
                } else {
                    return Err(StartMicrovmError::MissingKernelConfig);
                };
            arch::arch_memory_regions(mem_size, Some(kernel_guest_addr), kernel_size, 0, None)
        }
        #[cfg(test)]
        Payload::Empty => arch::arch_memory_regions(mem_size, None, 0, 0, None),
        Payload::Firmware => arch::arch_memory_regions(mem_size, None, 0, 0, firmware_size),
    };
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    let (arch_mem_info, mut arch_mem_regions) = match payload {
        Payload::ExternalKernel(external_kernel) => {
            arch::arch_memory_regions(mem_size, external_kernel.initramfs_size, None)
        }
        _ => arch::arch_memory_regions(mem_size, 0, firmware_size),
    };

    let mut shm_manager = ShmManager::new(&arch_mem_info);

    #[cfg(not(feature = "tee"))]
    for (index, fs) in vm_resources.fs.iter().enumerate() {
        if let Some(shm_size) = fs.shm_size {
            shm_manager
                .create_fs_region(index, shm_size)
                .map_err(StartMicrovmError::ShmCreate)?;
        }
    }
    if vm_resources.gpu_virgl_flags.is_some() {
        let size = vm_resources.gpu_shm_size.unwrap_or(1 << 33);
        shm_manager
            .create_gpu_region(size)
            .map_err(StartMicrovmError::ShmCreate)?;
    }

    // For vhost-user devices, we need file-backed memory so the backend can mmap it
    #[cfg(all(feature = "vhost-user", target_os = "linux"))]
    let use_vhost_user = !vm_resources.vhost_user_devices.is_empty();
    #[cfg(not(all(feature = "vhost-user", target_os = "linux")))]
    let use_vhost_user = false;

    // Number of guest-RAM regions before the SHM/GPU regions are appended —
    // only the RAM regions are CoW-fork-backed; SHM/GPU stay anonymous.
    let ram_region_count = arch_mem_regions.len();
    // Add SHM regions before creating guest memory
    arch_mem_regions.extend(shm_manager.regions());

    // Restore: the provided CoW-clone memory already holds the running image —
    // skip allocation + payload load entirely.
    if let Some((guest_mem, fork_backed_regions)) = restore_mem {
        // A clone normally keeps its inherited raw MAP_PRIVATE mappings and is
        // therefore a cheap leaf. When explicitly launched forkable, give it
        // fresh file-backed memory containing its current state. This one-time
        // materialization makes the restored machine a stable source for its
        // own descendants without mutating the ancestor's backing files.
        let guest_mem = if memfd_backed_ram_enabled() {
            super::snapshot::materialize_guest_memory(&guest_mem, &fork_backed_regions).map_err(
                |error| {
                    StartMicrovmError::GuestMemoryMmap(format!(
                        "materialize restored fork source: {error}"
                    ))
                },
            )?
        } else {
            guest_mem
        };
        let payload_config = PayloadConfig {
            entry_addr: GuestAddress(0),
            initrd_config: None,
            kernel_cmdline: None,
            pvh: false,
        };
        return Ok((guest_mem, arch_mem_info, shm_manager, payload_config));
    }

    let guest_mem = if use_vhost_user {
        #[cfg(all(feature = "vhost-user", target_os = "linux"))]
        {
            debug!(
                "Creating file-backed memory for vhost-user (regions: {})",
                arch_mem_regions.len()
            );
            // Create file-backed memory regions using memfd
            let regions_with_files: Vec<_> = arch_mem_regions
                .iter()
                .map(|(addr, size)| {
                    debug!(
                        "Creating memfd for region: addr=0x{:x}, size=0x{:x}",
                        addr.0, size
                    );
                    // SAFETY: memfd_create is called with a valid null-terminated C string and valid flags.
                    // File descriptor ownership is transferred to File::from_raw_fd below.
                    let memfd = unsafe {
                        let fd = libc::memfd_create(c"guest_mem".as_ptr(), libc::MFD_CLOEXEC);
                        if fd < 0 {
                            error!("Failed to create memfd: {:?}", io::Error::last_os_error());
                            return Err(io::Error::last_os_error());
                        }
                        if libc::ftruncate(fd, *size as i64) < 0 {
                            error!(
                                "Failed to ftruncate memfd: {:?}",
                                io::Error::last_os_error()
                            );
                            libc::close(fd);
                            return Err(io::Error::last_os_error());
                        }
                        debug!("Created memfd with fd={}", fd);
                        File::from_raw_fd(fd)
                    };

                    let file_offset = FileOffset::new(memfd, 0);
                    Ok((*addr, *size, Some(file_offset)))
                })
                .collect::<Result<Vec<_>, io::Error>>()
                .map_err(|e| {
                    StartMicrovmError::GuestMemoryMmap(format!("memfd creation failed: {e:?}"))
                })?;

            debug!(
                "Created {} file-backed memory regions",
                regions_with_files.len()
            );
            GuestMemoryMmap::from_ranges_with_files(&regions_with_files)
                .map_err(|e| StartMicrovmError::GuestMemoryMmap(format!("{e:?}")))?
        }
        #[cfg(not(all(feature = "vhost-user", target_os = "linux")))]
        unreachable!()
    } else if memfd_backed_ram_enabled() {
        // Back ALL guest regions (RAM *and* device-SHM such as the virtiofs-DAX
        // rootfs window) with memfds so a fork clone can CoW-share every region.
        // Backing only the RAM regions left SHM windows anonymous → zeroed on the
        // clone → the guest's file-backed code vanished → triple fault.
        let _ = ram_region_count;
        let ranges = build_memfd_backed_ranges(&arch_mem_regions, arch_mem_regions.len())
            .map_err(|e| StartMicrovmError::GuestMemoryMmap(format!("memfd backing: {e}")))?;
        GuestMemoryMmap::from_ranges_with_files(ranges)
            .map_err(|e| StartMicrovmError::GuestMemoryMmap(format!("{e:?}")))?
    } else {
        GuestMemoryMmap::from_ranges(&arch_mem_regions)
            .map_err(|e| StartMicrovmError::GuestMemoryMmap(format!("{e:?}")))?
    };

    let LoadedPayload {
        guest_mem,
        entry_addr,
        initrd_config,
        kernel_cmdline: cmdline,
        pvh,
    } = load_payload(vm_resources, guest_mem, &arch_mem_info, payload)?;

    // Only write firmware if data exists AND this isn't an ExternalKernel payload
    // (ExternalKernel does direct kernel boot and doesn't use EFI firmware)
    if !matches!(payload, Payload::ExternalKernel(_))
        && let Some(firmware_data) = firmware_data.as_ref()
    {
        guest_mem
            .write(firmware_data, GuestAddress(arch_mem_info.firmware_addr))
            .map_err(StartMicrovmError::FirmwareInvalidAddress)?;
    }

    let payload_config = PayloadConfig {
        entry_addr,
        initrd_config,
        kernel_cmdline: cmdline.clone(),
        pvh,
    };

    Ok((guest_mem, arch_mem_info, shm_manager, payload_config))
}

#[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
fn load_cmdline(vmm: &Vmm) -> std::result::Result<(), StartMicrovmError> {
    kernel::loader::load_cmdline(
        vmm.guest_memory(),
        GuestAddress(arch::x86_64::layout::CMDLINE_START),
        &vmm.kernel_cmdline
            .as_cstring()
            .map_err(StartMicrovmError::LoadCommandline)?,
    )
    .map_err(StartMicrovmError::LoadCommandline)
}

#[cfg(all(target_os = "linux", not(feature = "tee")))]
pub(crate) fn setup_vm(
    guest_memory: &GuestMemoryMmap,
    _nested_enabled: bool,
) -> std::result::Result<Vm, StartMicrovmError> {
    let kvm = KvmContext::new()
        .map_err(Error::KvmContext)
        .map_err(StartMicrovmError::Internal)?;
    let mut vm = Vm::new(kvm.fd())
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    vm.memory_init(guest_memory, kvm.max_memslots())
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    Ok(vm)
}

#[cfg(all(feature = "tee", target_arch = "x86_64"))]
fn validate_tee_config(tee: Tee) -> std::result::Result<(), StartMicrovmError> {
    match tee {
        #[cfg(feature = "amd-sev")]
        Tee::Snp => Ok(()),
        #[cfg(feature = "tdx")]
        Tee::Tdx => Ok(()),
        _ => Err(StartMicrovmError::InvalidTee),
    }
}

#[cfg(all(feature = "tee", not(target_arch = "x86_64")))]
fn validate_tee_config(_tee: Tee) -> std::result::Result<(), StartMicrovmError> {
    Err(StartMicrovmError::InvalidTee)
}

#[cfg(all(target_os = "linux", feature = "tee"))]
pub(crate) fn setup_vm(
    kvm: &KvmContext,
    guest_memory: &GuestMemoryMmap,
    resources: &super::resources::VmResources,
    #[cfg(feature = "tdx")] _sender: Sender<WorkerMessage>,
) -> std::result::Result<Vm, StartMicrovmError> {
    validate_tee_config(resources.tee_config().tee)?;

    let mut vm = Vm::new(
        kvm.fd(),
        resources.tee_config(),
        #[cfg(feature = "tdx")]
        _sender,
    )
    .map_err(Error::Vm)
    .map_err(StartMicrovmError::Internal)?;
    vm.memory_init(guest_memory, kvm.max_memslots())
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    Ok(vm)
}
#[cfg(target_os = "macos")]
pub(crate) fn setup_vm(
    guest_memory: &GuestMemoryMmap,
    nested_enabled: bool,
) -> std::result::Result<Vm, StartMicrovmError> {
    let mut vm = Vm::new(nested_enabled)
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    vm.memory_init(guest_memory)
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    Ok(vm)
}

#[cfg(target_os = "windows")]
pub(crate) fn setup_vm(
    guest_memory: &GuestMemoryMmap,
    vcpu_count: u8,
) -> std::result::Result<Vm, StartMicrovmError> {
    // WHP creates the partition (with the processor count fixed) up front, then
    // maps guest memory into it.
    let mut vm = Vm::new(u32::from(vcpu_count))
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    vm.memory_init(guest_memory)
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    Ok(vm)
}

/// Sets up the serial device.
pub fn setup_serial_device(
    event_manager: &mut EventManager,
    input: Option<Box<dyn devices::legacy::ReadableFd + Send>>,
    out: Option<Box<dyn io::Write + Send>>,
) -> std::result::Result<Arc<Mutex<Serial>>, StartMicrovmError> {
    let interrupt_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK)
        .map_err(Error::EventFd)
        .map_err(StartMicrovmError::Internal)?;
    let has_input = input.is_some();
    let serial = Arc::new(Mutex::new(Serial::new(interrupt_evt, out, input)));
    if has_input && let Err(e) = event_manager.add_subscriber(serial.clone()) {
        // TODO: We just log this message, and immediately return Ok, instead of returning the
        // actual error because this operation always fails with EPERM when adding a fd which
        // has been redirected to /dev/null via dup2 (this may happen inside the jailer).
        // Find a better solution to this (and think about the state of the serial device
        // while we're at it).
        warn!("Could not add serial input event to epoll: {e:?}");
    }
    Ok(serial)
}

#[cfg(target_arch = "x86_64")]
fn attach_legacy_devices(
    vm: &Vm,
    split_irqchip: bool,
    pio_device_manager: &mut PortIODeviceManager,
    mmio_device_manager: &mut MMIODeviceManager,
    intc: Option<Arc<Mutex<IrqChipDevice>>>,
) -> std::result::Result<(), StartMicrovmError> {
    pio_device_manager
        .register_devices()
        .map_err(Error::LegacyIOBus)
        .map_err(StartMicrovmError::Internal)?;

    // WHP has no PIT, and its emulated LAPIC timer delivers no interrupts to the
    // guest, so without this the guest has no working clockevent and timers /
    // `nanosleep` hang. Emulate the i8254 channel-0 timer (IRQ 0): it asserts
    // IRQ 0 through the IOAPIC at the cadence the guest programs via ports
    // 0x40/0x43, giving the guest's i8253 clockevent a tick. Paired with
    // `nolapic_timer` on the kernel cmdline so the guest picks the PIT over the
    // dead LAPIC timer.
    #[cfg(target_os = "windows")]
    if let Some(intc) = intc.clone() {
        let pit = devices::legacy::Pit::new(intc)
            .map_err(|e| Error::LegacyIOBus(device_manager::legacy::Error::EventFd(e)))
            .map_err(StartMicrovmError::Internal)?;
        pio_device_manager
            .io_bus
            .insert(Arc::new(Mutex::new(pit)), 0x40, 0x4)
            .map_err(|e| Error::LegacyIOBus(device_manager::legacy::Error::BusError(e)))
            .map_err(StartMicrovmError::Internal)?;
    }

    // On WHP the IOAPIC is always a software device reached over MMIO: WHP
    // emulates the LAPIC but not the IOAPIC, so the guest must be able to
    // program the redirection table through our bus. Without this the guest's
    // writes to 0xFEC00000 are dropped, every virtio pin stays masked at reset,
    // and device-completion interrupts (e.g. the FUSE_INIT reply) are never
    // delivered — the guest hangs mounting its rootfs before reaching init.
    // On KVM/HVF the in-kernel/userspace split-irqchip option governs this.
    let register_ioapic = split_irqchip || cfg!(target_os = "windows");
    if register_ioapic {
        mmio_device_manager
            .register_mmio_ioapic(intc)
            .map_err(Error::RegisterMMIODevice)
            .map_err(StartMicrovmError::Internal)?;
    }

    // KVM wires legacy-device IRQs through irqfds. WHP has no irqfd; the WHP
    // IOAPIC injects these via `request_interrupt` from the run loop instead, so
    // the registration is a no-op on Windows.
    // TODO(whp-host): wire the legacy COM/keyboard interrupt lines into the WHP
    // IOAPIC and validate on a real WHP host.
    #[cfg(target_os = "linux")]
    macro_rules! register_irqfd_evt {
        ($evt: ident, $index: expr_2021) => {{
            vm.fd()
                .register_irqfd(&pio_device_manager.$evt, $index)
                .map_err(|e| {
                    Error::LegacyIOBus(device_manager::legacy::Error::EventFd(
                        io::Error::from_raw_os_error(e.errno()),
                    ))
                })
                .map_err(StartMicrovmError::Internal)?;
        }};
    }
    #[cfg(not(target_os = "linux"))]
    macro_rules! register_irqfd_evt {
        ($evt: ident, $index: expr_2021) => {{
            let _ = (&vm, &pio_device_manager.$evt, $index);
        }};
    }

    register_irqfd_evt!(com_evt_1, 4);
    register_irqfd_evt!(com_evt_2, 3);
    register_irqfd_evt!(com_evt_3, 4);
    register_irqfd_evt!(com_evt_4, 3);
    register_irqfd_evt!(kbd_evt, 1);
    Ok(())
}

#[cfg(all(
    any(target_arch = "aarch64", target_arch = "riscv64"),
    target_os = "linux"
))]
fn attach_legacy_devices(
    vm: &Vm,
    mmio_device_manager: &mut MMIODeviceManager,
    kernel_cmdline: &mut kernel::cmdline::Cmdline,
    intc: IrqChip,
    serial: Vec<Arc<Mutex<Serial>>>,
) -> std::result::Result<(), StartMicrovmError> {
    for s in serial {
        mmio_device_manager
            .register_mmio_serial(vm.fd(), kernel_cmdline, intc.clone(), s)
            .map_err(Error::RegisterMMIODevice)
            .map_err(StartMicrovmError::Internal)?;
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    mmio_device_manager
        .register_mmio_rtc(vm.fd())
        .map_err(Error::RegisterMMIODevice)
        .map_err(StartMicrovmError::Internal)?;

    Ok(())
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
fn attach_legacy_devices(
    vm: &Vm,
    mmio_device_manager: &mut MMIODeviceManager,
    kernel_cmdline: &mut kernel::cmdline::Cmdline,
    intc: IrqChip,
    serial: Vec<Arc<Mutex<Serial>>>,
    event_manager: &mut EventManager,
    shutdown_efd: Option<EventFd>,
) -> Result<(), StartMicrovmError> {
    for s in serial {
        mmio_device_manager
            .register_mmio_serial(vm, kernel_cmdline, intc.clone(), s)
            .map_err(Error::RegisterMMIODevice)
            .map_err(StartMicrovmError::Internal)?;
    }

    mmio_device_manager
        .register_mmio_rtc(vm, intc.clone())
        .map_err(Error::RegisterMMIODevice)
        .map_err(StartMicrovmError::Internal)?;

    mmio_device_manager
        .register_mmio_gic(vm, intc.clone())
        .map_err(Error::RegisterMMIODevice)
        .map_err(StartMicrovmError::Internal)?;

    if let Some(shutdown_efd) = shutdown_efd {
        mmio_device_manager
            .register_mmio_gpio(vm, intc.clone(), event_manager, shutdown_efd)
            .map_err(Error::RegisterMMIODevice)
            .map_err(StartMicrovmError::Internal)?;
    }

    Ok(())
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn create_vcpus_x86_64(
    vm: &Vm,
    vcpu_config: &VcpuConfig,
    guest_mem: &GuestMemoryMmap,
    entry_addr: GuestAddress,
    io_bus: &devices::Bus,
    exit_evt: &EventFd,
    kernel_boot: bool,
    pvh: bool,
    #[cfg(feature = "tee")] pm_sender: Sender<WorkerMessage>,
) -> super::Result<Vec<Vcpu>> {
    let mut vcpus = Vec::with_capacity(vcpu_config.vcpu_count as usize);
    for cpu_index in 0..vcpu_config.vcpu_count {
        let mut vcpu = Vcpu::new_x86_64(
            cpu_index,
            vm.fd(),
            vm.supported_cpuid().clone(),
            vm.supported_msrs().clone(),
            io_bus.clone(),
            exit_evt.try_clone().map_err(Error::EventFd)?,
            #[cfg(feature = "tee")]
            pm_sender.clone(),
        )
        .map_err(Error::Vcpu)?;

        vcpu.configure_x86_64(guest_mem, entry_addr, vcpu_config, kernel_boot, pvh)
            .map_err(Error::Vcpu)?;

        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
fn create_vcpus_x86_64_whp(
    vm: &Vm,
    vcpu_config: &VcpuConfig,
    guest_mem: &GuestMemoryMmap,
    entry_addr: GuestAddress,
    io_bus: &devices::Bus,
    exit_evt: &EventFd,
) -> super::Result<Vec<Vcpu>> {
    let mut vcpus = Vec::with_capacity(vcpu_config.vcpu_count as usize);
    for cpu_index in 0..vcpu_config.vcpu_count {
        let mut vcpu =
            Vcpu::new_x86_64(cpu_index, vm, exit_evt.try_clone().map_err(Error::EventFd)?)
                .map_err(Error::Vcpu)?;
        vcpu.set_io_bus(io_bus.clone());
        vcpu.configure_x86_64(guest_mem, entry_addr.raw_value())
            .map_err(Error::Vcpu)?;
        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn create_vcpus_aarch64(
    vm: &Vm,
    vcpu_config: &VcpuConfig,
    mem_info: &ArchMemoryInfo,
    entry_addr: GuestAddress,
    exit_evt: &EventFd,
) -> super::Result<Vec<Vcpu>> {
    let mut vcpus = Vec::with_capacity(vcpu_config.vcpu_count as usize);
    for cpu_index in 0..vcpu_config.vcpu_count {
        let mut vcpu = Vcpu::new_aarch64(
            cpu_index,
            vm.fd(),
            exit_evt.try_clone().map_err(Error::EventFd)?,
        )
        .map_err(Error::Vcpu)?;

        vcpu.configure_aarch64(vm.fd(), mem_info, entry_addr)
            .map_err(Error::Vcpu)?;

        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
fn create_vcpus_aarch64(
    _vm: &Vm,
    vcpu_config: &VcpuConfig,
    mem_info: &ArchMemoryInfo,
    entry_addr: GuestAddress,
    exit_evt: &EventFd,
    vcpu_list: Arc<VcpuList>,
    nested_enabled: bool,
) -> super::Result<Vec<Vcpu>> {
    let mut vcpus = Vec::with_capacity(vcpu_config.vcpu_count as usize);
    let mut boot_senders: HashMap<u64, Sender<u64>> = HashMap::new();

    for cpu_index in 0..vcpu_config.vcpu_count {
        let (boot_sender, boot_receiver) = if cpu_index != 0 {
            let (boot_sender, boot_receiver) = unbounded();
            (Some(boot_sender), Some(boot_receiver))
        } else {
            (None, None)
        };

        let mut vcpu = Vcpu::new_aarch64(
            cpu_index,
            entry_addr,
            boot_receiver,
            exit_evt.try_clone().map_err(Error::EventFd)?,
            vcpu_list.clone(),
            nested_enabled,
        )
        .map_err(Error::Vcpu)?;

        vcpu.configure_aarch64(mem_info).map_err(Error::Vcpu)?;

        if let Some(boot_sender) = boot_sender {
            boot_senders.insert(vcpu.get_mpidr(), boot_sender);
        }

        vcpus.push(vcpu);
    }

    vcpus[0].set_boot_senders(boot_senders);

    Ok(vcpus)
}

#[cfg(all(target_arch = "riscv64", target_os = "linux"))]
fn create_vcpus_riscv64(
    vm: &Vm,
    vcpu_config: &VcpuConfig,
    guest_mem: &GuestMemoryMmap,
    entry_addr: GuestAddress,
    exit_evt: &EventFd,
) -> super::Result<Vec<Vcpu>> {
    let mut vcpus = Vec::with_capacity(vcpu_config.vcpu_count as usize);
    for cpu_index in 0..vcpu_config.vcpu_count {
        let mut vcpu = Vcpu::new_riscv64(
            cpu_index,
            vm.fd(),
            exit_evt.try_clone().map_err(Error::EventFd)?,
        )
        .map_err(Error::Vcpu)?;

        vcpu.configure_riscv64(vm.fd(), guest_mem, entry_addr)
            .map_err(Error::Vcpu)?;

        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

/// Attaches an virtio mmio device to the device manager.
fn attach_mmio_device(
    vmm: &mut Vmm,
    id: String,
    intc: IrqChip,
    device: Arc<Mutex<dyn VirtioDevice>>,
) -> std::result::Result<(), device_manager::mmio::Error> {
    // On WHP a host thread bridges the device's interrupt eventfd to the IOAPIC
    // (no kernel-side irqfd); keep a handle to the IRQ chip for that watcher.
    #[cfg(target_os = "windows")]
    let irq_intc = intc.clone();
    let mmio_device = MmioTransport::new(vmm.guest_memory().clone(), intc, device)?;

    let type_id = mmio_device.locked_device().device_type();
    let _cmdline = &mut vmm.kernel_cmdline;

    #[cfg(target_os = "linux")]
    let (_mmio_base, _irq) =
        vmm.mmio_device_manager
            .register_mmio_device(vmm.vm.fd(), mmio_device, type_id, id)?;
    #[cfg(target_os = "macos")]
    let (_mmio_base, _irq) =
        vmm.mmio_device_manager
            .register_mmio_device(mmio_device, type_id, id)?;
    #[cfg(target_os = "windows")]
    let (_mmio_base, _irq) = {
        // Clone the device's interrupt eventfd before the transport is moved into
        // the manager, then spawn a watcher that raises the IOAPIC line whenever
        // the device signals an IRQ (the WHP analogue of KVM's irqfd).
        let irq_evt = mmio_device
            .interrupt_evt()
            .try_clone()
            .map_err(device_manager::mmio::Error::EventFd)?;
        let (mmio_base, irq) =
            vmm.mmio_device_manager
                .register_mmio_device(mmio_device, type_id, id)?;
        std::thread::Builder::new()
            .name(format!("whp-irq-{irq}"))
            .spawn(move || {
                loop {
                    if irq_evt.wait_timeout(u32::MAX) {
                        let _ = irq_intc.lock().unwrap().set_irq(Some(irq), None);
                    }
                }
            })
            .map_err(device_manager::mmio::Error::EventFd)?;
        (mmio_base, irq)
    };

    #[cfg(target_arch = "x86_64")]
    vmm.mmio_device_manager
        .add_device_to_cmdline(_cmdline, _mmio_base, _irq)?;

    Ok(())
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
    use self::StartMicrovmError::*;

    for (i, config) in fs_devs.iter().enumerate() {
        let fs = Arc::new(Mutex::new(
            devices::virtio::Fs::new(
                config.fs_id.clone(),
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
        attach_mmio_device(vmm, id, intc.clone(), fs).map_err(RegisterFsDevice)?;
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

        setup_terminal_raw_mode(vmm, term_fd, forwarding_sigint);

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
) -> std::result::Result<Vec<PortDescription>, StartMicrovmError> {
    use self::StartMicrovmError::*;

    let mut console_output_path: Option<PathBuf> = None;
    if let Some(path) = vm_resources.console_output.clone() {
        if !vm_resources.disable_implicit_console {
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

        setup_terminal_raw_mode(vmm, term_h, forwarding_sigint);

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
fn setup_terminal_raw_mode(
    vmm: &mut Vmm,
    term_fd: Option<BorrowedFd<'_>>,
    handle_signals_by_terminal: bool,
) {
    if let Some(term_fd) = term_fd {
        match term_set_raw_mode(term_fd, handle_signals_by_terminal) {
            Ok(old_mode) => {
                let raw_fd = term_fd.as_raw_fd();
                vmm.exit_observers.push(Arc::new(Mutex::new(move || {
                    if let Err(e) =
                        term_restore_mode(unsafe { BorrowedFd::borrow_raw(raw_fd) }, &old_mode)
                    {
                        log::error!("Failed to restore terminal mode: {e}")
                    }
                })));
            }
            Err(e) => {
                log::error!("Failed to set terminal to raw mode: {e}")
            }
        };
    }
}

#[cfg(target_os = "windows")]
fn setup_terminal_raw_mode(
    vmm: &mut Vmm,
    term_handle: Option<SendHandle>,
    handle_signals_by_terminal: bool,
) {
    if let Some(term_handle) = term_handle {
        match term_set_raw_mode(term_handle, handle_signals_by_terminal) {
            Ok(old_mode) => {
                vmm.exit_observers.push(Arc::new(Mutex::new(move || {
                    if let Err(e) = term_restore_mode(term_handle, &old_mode) {
                        log::error!("Failed to restore terminal mode: {e}")
                    }
                })));
            }
            Err(e) => {
                log::error!("Failed to set terminal to raw mode: {e}")
            }
        };
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
                setup_terminal_raw_mode(vmm, Some(term_fd), false);

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
                setup_terminal_raw_mode(vmm, Some(term_h), false);

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
    use self::StartMicrovmError::*;

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
    attach_mmio_device(vmm, format!("hvc{id_number}"), intc, console)
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

        attach_mmio_device(vmm, id, intc.clone(), net_device.clone())
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
    use self::StartMicrovmError::*;

    event_manager
        .add_subscriber(unix_vsock.clone())
        .map_err(RegisterEvent)?;

    let id = String::from(unix_vsock.lock().unwrap().id());

    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_mmio_device(vmm, id, intc, unix_vsock.clone()).map_err(RegisterVsockDevice)?;

    Ok(())
}

#[cfg(not(feature = "tee"))]
fn attach_balloon_device(
    vmm: &mut Vmm,
    event_manager: &mut EventManager,
    intc: IrqChip,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    let balloon = Arc::new(Mutex::new(devices::virtio::Balloon::new().unwrap()));

    event_manager
        .add_subscriber(balloon.clone())
        .map_err(RegisterEvent)?;

    let id = String::from(balloon.lock().unwrap().id());

    vmm.set_balloon(balloon.clone());

    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_mmio_device(vmm, id, intc.clone(), balloon).map_err(RegisterBalloonDevice)?;

    Ok(())
}

#[cfg(feature = "blk")]
fn attach_block_devices(
    vmm: &mut Vmm,
    block_devs: &BlockBuilder,
    intc: IrqChip,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    for block in block_devs.list.iter() {
        let id = String::from(block.lock().unwrap().id());

        // The device mutex mustn't be locked here otherwise it will deadlock.
        attach_mmio_device(vmm, id, intc.clone(), block.clone()).map_err(RegisterBlockDevice)?;
    }

    Ok(())
}

#[cfg(not(feature = "tee"))]
fn attach_rng_device(
    vmm: &mut Vmm,
    event_manager: &mut EventManager,
    intc: IrqChip,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    let rng = Arc::new(Mutex::new(devices::virtio::Rng::new().unwrap()));

    event_manager
        .add_subscriber(rng.clone())
        .map_err(RegisterEvent)?;

    let id = String::from(rng.lock().unwrap().id());

    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_mmio_device(vmm, id, intc.clone(), rng).map_err(RegisterRngDevice)?;

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
    use self::StartMicrovmError::*;

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
        )
        .map_err(|e| RegisterVhostUserDevice(device_manager::mmio::Error::VhostUserDevice(e)))?,
    ));

    event_manager
        .add_subscriber(device.clone())
        .map_err(RegisterEvent)?;

    attach_mmio_device(vmm, device_name, intc.clone(), device).map_err(RegisterVhostUserDevice)?;

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
    use self::StartMicrovmError::*;

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
    attach_mmio_device(vmm, id, intc, gpu).map_err(RegisterGpuDevice)?;

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
    use self::StartMicrovmError::*;

    for (index, (config_backend, events_backend)) in input_backends.iter().enumerate() {
        let input_device = Arc::new(Mutex::new(
            devices::virtio::input::Input::new(*config_backend, *events_backend).unwrap(),
        ));

        let id = format!("input{}", index);
        attach_mmio_device(vmm, id, intc.clone(), input_device).map_err(RegisterInputDevice)?;
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::vmm_config::kernel_bundle::KernelBundle;

    #[cfg(target_os = "macos")]
    #[test]
    fn reaps_dead_pid_guest_ram_keeps_live_and_legacy() {
        use std::fs;
        let dir = std::env::temp_dir().join(format!("grr-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        // A pid we know is dead: spawn a child and reap it.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead_pid = child.id();
        child.wait().unwrap();

        let live = dir.join(format!("smolvm-guest-ram-{}-AAAAAA", std::process::id()));
        let dead = dir.join(format!("smolvm-guest-ram-{dead_pid}-BBBBBB"));
        let legacy = dir.join("smolvm-guest-ram-CCCCCC"); // pre-pid name, no pid
        let other = dir.join("unrelated.bin");
        for f in [&live, &dead, &legacy, &other] {
            fs::write(f, b"x").unwrap();
        }

        reap_orphaned_guest_ram_in(dir.to_str().unwrap());

        assert!(live.exists(), "a live golden's RAM file must be kept");
        assert!(!dead.exists(), "a dead pid's RAM file must be reaped");
        assert!(
            legacy.exists(),
            "legacy (no-pid) files are left for manual cleanup"
        );
        assert!(other.exists(), "unrelated files are untouched");

        let _ = fs::remove_dir_all(&dir);
    }

    #[allow(unused)]
    fn default_guest_memory(
        mem_size_mib: usize,
    ) -> std::result::Result<
        (GuestMemoryMmap, ArchMemoryInfo, ShmManager, PayloadConfig),
        StartMicrovmError,
    > {
        let mut vm_resources = VmResources::default();
        vm_resources.kernel_bundle = Some(KernelBundle {
            host_addr: 0x1000,
            guest_addr: 0x1000,
            entry_addr: 0x1000,
            size: 0x1000,
        });

        create_guest_memory(mem_size_mib, &vm_resources, &Payload::Empty, None)
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_create_vcpus_x86_64() {
        let vcpu_count = 2;

        let vcpu_config = VcpuConfig {
            vcpu_count,
            ht_enabled: false,
            cpu_template: None,
            nested_enabled: false,
        };

        let (guest_memory, _arch_memory_info, _shm_manager, _payload_config) =
            default_guest_memory(128).unwrap();
        let vm = setup_vm(&guest_memory, false).unwrap();
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();

        // Dummy entry_addr, vcpus will not boot.
        let entry_addr = GuestAddress(0);
        let bus = devices::Bus::new();
        let vcpu_vec = create_vcpus_x86_64(
            &vm,
            &vcpu_config,
            &guest_memory,
            entry_addr,
            &bus,
            &EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            true,
            false,
        )
        .unwrap();
        assert_eq!(vcpu_vec.len(), vcpu_count as usize);
    }

    #[test]
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    fn test_create_vcpus_aarch64() {
        let (guest_memory, arch_memory_info, _shm_manager, _payload_config) =
            default_guest_memory(128).unwrap();
        let vm = setup_vm(&guest_memory, false).unwrap();
        let vcpu_count = 2;

        let vcpu_config = VcpuConfig {
            vcpu_count,
            ht_enabled: false,
            cpu_template: None,
            nested_enabled: false,
        };

        // Dummy entry_addr, vcpus will not boot.
        let entry_addr = GuestAddress(0);
        let vcpu_vec = create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &arch_memory_info,
            entry_addr,
            &EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();
        assert_eq!(vcpu_vec.len(), vcpu_count as usize);
    }

    #[test]
    fn test_error_messages() {
        use crate::builder::StartMicrovmError::*;
        let err = AttachBlockDevice(io::Error::from_raw_os_error(0));
        let _ = format!("{err}{err:?}");

        let err = CreateRateLimiter(io::Error::from_raw_os_error(0));
        let _ = format!("{err}{err:?}");

        let err = Internal(Error::Serial(io::Error::from_raw_os_error(0)));
        let _ = format!("{err}{err:?}");

        let err = InvalidKernelBundle(vm_memory::mmap::MmapRegionError::InvalidPointer);
        let _ = format!("{err}{err:?}");

        let err = KernelCmdline(String::from("dummy --cmdline"));
        let _ = format!("{err}{err:?}");

        let err = LoadCommandline(kernel::cmdline::Error::TooLarge);
        let _ = format!("{err}{err:?}");

        let err = MicroVMAlreadyRunning;
        let _ = format!("{err}{err:?}");

        let err = MissingKernelConfig;
        let _ = format!("{err}{err:?}");

        let err = MissingMemSizeConfig;
        let _ = format!("{err}{err:?}");

        let err = NetDeviceNotConfigured;
        let _ = format!("{err}{err:?}");

        let err = OpenBlockDevice(io::Error::from_raw_os_error(0));
        let _ = format!("{err}{err:?}");

        let err = RegisterBlockDevice(device_manager::mmio::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{err}{err:?}");

        let err = RegisterEvent(EventManagerError::EpollCreate(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{err}{err:?}");

        let err = RegisterNetDevice(device_manager::mmio::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{err}{err:?}");

        let err = RegisterVsockDevice(device_manager::mmio::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{err}{err:?}");
    }

    #[test]
    fn test_kernel_cmdline_err_to_startuvm_err() {
        let err = StartMicrovmError::from(kernel::cmdline::Error::HasSpace);
        let _ = format!("{err}{err:?}");
    }
}
