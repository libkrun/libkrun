use std::marker::PhantomData;
#[cfg(unix)]
use std::os::fd::{IntoRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

use crossbeam_channel::unbounded;
use polly::event_manager::EventManager;
#[cfg(target_os = "macos")]
use utils::eventfd::EventFd;
use vmm::Vmm as InnerVmm;
#[cfg(unix)]
use vmm::resources::SerialConsoleConfig;
use vmm::resources::VmResources;
use vmm::vmm_config::machine_config::VmConfig;

use super::device_builders::{DeviceManager, MmioDeviceManager};
use super::error::Error;
use super::payload::Payload;

#[derive(Default)]
pub struct VmmBuilder<'a> {
    vcpus: Option<u8>,
    ram_mib: Option<u32>,
    payload: Option<Payload>,
    device_manager: Option<Box<dyn DeviceManager<'a> + 'a>>,
    #[cfg(unix)]
    serial_consoles: Vec<SerialConsoleConfig>,
    kernel_console: Option<String>,
    nested_virt: bool,
    split_irqchip: bool,
    smbios_oem_strings: Vec<String>,
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl<'a> VmmBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn vcpus(mut self, count: u8) -> Result<Self, Error> {
        if count == 0 {
            return Err(Error::OutOfRange());
        }
        self.vcpus = Some(count);
        Ok(self)
    }

    pub fn ram_mib(mut self, mib: u32) -> Result<Self, Error> {
        if mib == 0 {
            return Err(Error::OutOfRange());
        }
        self.ram_mib = Some(mib);
        Ok(self)
    }

    pub fn payload(mut self, payload: Payload) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn devices(mut self, devices: MmioDeviceManager<'a>) -> Self {
        self.device_manager = Some(Box::new(devices));
        self
    }

    pub fn set_kernel_console(mut self, console: &str) -> Self {
        self.kernel_console = Some(console.to_string());
        self
    }

    /// Add a legacy serial console device with the given input and output file descriptors.
    ///
    /// Can be called multiple times to add multiple serial consoles (ttyS0, ttyS1, …).
    /// This is required for FreeBSD guests which use the legacy serial console instead
    /// of the virtio console.
    #[cfg(unix)]
    pub fn add_serial_console(
        mut self,
        input_fd: Option<OwnedFd>,
        output_fd: Option<OwnedFd>,
    ) -> Self {
        self.serial_consoles.push(SerialConsoleConfig {
            input_fd: input_fd.map_or(-1, |fd| fd.into_raw_fd()),
            output_fd: output_fd.map_or(-1, |fd| fd.into_raw_fd()),
        });
        self
    }

    pub fn nested_virt(mut self, enabled: bool) -> Self {
        self.nested_virt = enabled;
        self
    }

    pub fn split_irqchip(mut self, enabled: bool) -> Result<Self, Error> {
        if enabled && !cfg!(target_arch = "x86_64") {
            return Err(Error::InvalidParam());
        }
        self.split_irqchip = enabled;
        Ok(self)
    }

    pub fn add_smbios_oem_string(mut self, s: &str) -> Self {
        self.smbios_oem_strings.push(s.to_string());
        self
    }

    pub fn build(self) -> Result<Vmm<'a>, Error> {
        build_vm(self).inspect_err(|e| log::error!("{e}"))
    }
}

enum VmmInner {
    Vmm {
        #[allow(dead_code)]
        vmm: Arc<Mutex<InnerVmm>>,
        event_manager: EventManager,
        #[allow(dead_code)]
        _worker_sender: crossbeam_channel::Sender<utils::worker_message::WorkerMessage>,
        #[cfg(target_os = "macos")]
        shutdown_efd: Arc<EventFd>,
    },
    #[cfg(feature = "aws-nitro")]
    Nitro(aws_nitro::enclave::NitroEnclave),
}

pub struct Vmm<'a> {
    inner: VmmInner,
    _lifetime: PhantomData<&'a ()>,
}

/// Handle to the inner VMM, usable from another thread while the
/// event loop runs on the main thread via [`Vmm::run`].
///
/// Obtain via [`Vmm::handle`] before calling `run()`.
// FIXME: make Vmm::run() non-blocking (requires making EventManager Send)
// so that run() returns a RunningVmm with wait(). Then this handle
// can be obtained from RunningVmm instead of requiring a pre-run call.
#[derive(Clone)]
pub struct VmmHandle {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    vmm: Arc<Mutex<InnerVmm>>,
    #[cfg(target_os = "macos")]
    shutdown_efd: Arc<EventFd>,
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl VmmHandle {
    pub fn pause(&self) -> Result<(), Error> {
        #[cfg(target_os = "macos")]
        {
            self.vmm
                .lock()
                .unwrap()
                .pause()
                .map_err(|e| Error::Internal(format!("pause: {e}")))
        }
        #[cfg(not(target_os = "macos"))]
        Err(Error::FeatureDisabled())
    }

    pub fn resume(&self) -> Result<(), Error> {
        #[cfg(target_os = "macos")]
        {
            self.vmm
                .lock()
                .unwrap()
                .resume()
                .map_err(|e| Error::Internal(format!("resume: {e}")))
        }
        #[cfg(not(target_os = "macos"))]
        Err(Error::FeatureDisabled())
    }

    /// Signal the guest to perform an orderly ACPI shutdown.
    ///
    /// On macOS this writes to the GPIO device's eventfd, which triggers
    /// a restart-key press in the guest. On other platforms this is not
    /// supported.
    pub fn shutdown(&self) -> Result<(), Error> {
        #[cfg(target_os = "macos")]
        {
            self.shutdown_efd
                .write(1)
                .map_err(|e| Error::Internal(format!("shutdown: {e}")))
        }
        #[cfg(not(target_os = "macos"))]
        Err(Error::FeatureDisabled())
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl<'a> Vmm<'a> {
    /// Obtain a thread-safe handle to the inner VMM.
    ///
    /// Must be called before [`run`](Self::run) which consumes `self`.
    /// The handle can be moved to another thread for pause/resume.
    pub fn handle(&self) -> Result<VmmHandle, Error> {
        match &self.inner {
            VmmInner::Vmm {
                vmm,
                #[cfg(target_os = "macos")]
                shutdown_efd,
                ..
            } => Ok(VmmHandle {
                vmm: vmm.clone(),
                #[cfg(target_os = "macos")]
                shutdown_efd: shutdown_efd.clone(),
            }),
            #[cfg(feature = "aws-nitro")]
            VmmInner::Nitro(_) => Err(Error::FeatureDisabled()),
        }
    }

    pub fn run(self) {
        match self.inner {
            VmmInner::Vmm {
                mut event_manager, ..
            } => loop {
                if let Err(e) = event_manager.run() {
                    log::error!("fatal event loop error: {e:?}");
                    return;
                }
            },
            #[cfg(feature = "aws-nitro")]
            VmmInner::Nitro(enclave) => {
                let exit_code = enclave.run().unwrap_or_else(|e| {
                    log::error!("Error running nitro enclave: {e}");
                    -libc::EINVAL
                });
                unsafe { libc::_exit(exit_code) }
            }
        }
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
pub fn check_nested_virt() -> bool {
    #[cfg(target_os = "macos")]
    {
        hvf::check_nested_virt().unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let paths = [
            "/sys/module/kvm_intel/parameters/nested",
            "/sys/module/kvm_amd/parameters/nested",
        ];
        paths.iter().any(|path| {
            fs::read_to_string(path).is_ok_and(|contents| {
                let val = contents.trim();
                val == "1" || val.eq_ignore_ascii_case("Y")
            })
        })
    }
}

fn build_vm(builder_cfg: VmmBuilder<'_>) -> Result<Vmm<'_>, Error> {
    use super::payload::PayloadKind;

    let vcpus_count = builder_cfg
        .vcpus
        .ok_or_else(|| Error::MissingConfig("vcpus not set".into()))?;
    let ram_mib = builder_cfg
        .ram_mib
        .ok_or_else(|| Error::MissingConfig("ram_mib not set".into()))?;
    let payload = builder_cfg
        .payload
        .ok_or_else(|| Error::MissingConfig("payload not set".into()))?;

    #[cfg(feature = "aws-nitro")]
    if let PayloadKind::Nitro(nitro_config) = payload.kind {
        let enclave = nitro_config
            .into_enclave(vcpus_count, ram_mib as usize)
            .map_err(|e| Error::MissingConfig(e.to_string()))?;
        return Ok(Vmm {
            inner: VmmInner::Nitro(enclave),
            _lifetime: PhantomData,
        });
    }

    let device_manager = builder_cfg
        .device_manager
        .ok_or_else(|| Error::MissingConfig("no device manager set (call .devices())".into()))?;

    let mut vm_resources = VmResources::default();
    vm_resources
        .set_vm_config(&VmConfig {
            vcpu_count: Some(vcpus_count),
            mem_size_mib: Some(ram_mib as usize),
            ht_enabled: Some(false),
            cpu_template: None,
        })
        .map_err(|e| {
            log::error!("vm config: {e:?}");
            Error::InvalidParam()
        })?;

    match payload.kind {
        PayloadKind::Kernel { bundle } => {
            vm_resources.kernel_bundle = Some(bundle);
        }
        PayloadKind::External { kernel } => {
            vm_resources.external_kernel = Some(kernel);
        }
        PayloadKind::Firmware { path } => {
            vm_resources.set_firmware_config(vmm::vmm_config::firmware::FirmwareConfig { path });
        }
        #[cfg(feature = "tee")]
        PayloadKind::Tee {
            bundle,
            qboot_bundle,
            initrd_bundle,
            tee_config_path,
        } => {
            vm_resources.kernel_bundle = Some(bundle);
            vm_resources.set_qboot_bundle(qboot_bundle).map_err(|e| {
                log::error!("qboot bundle: {e}");
                Error::InvalidParam()
            })?;
            vm_resources.set_initrd_bundle(initrd_bundle).map_err(|e| {
                log::error!("initrd bundle: {e}");
                Error::InvalidParam()
            })?;
            vm_resources.set_tee_config(tee_config_path).map_err(|e| {
                log::error!("tee config: {e:?}");
                Error::InvalidParam()
            })?;
        }
        #[cfg(feature = "aws-nitro")]
        PayloadKind::Nitro(_) => unreachable!("handled above"),
    }

    vm_resources.kernel_cmdline.prolog = Some(payload.cmdline);

    vm_resources.nested_enabled = builder_cfg.nested_virt;
    vm_resources.split_irqchip = builder_cfg.split_irqchip;
    if !builder_cfg.smbios_oem_strings.is_empty() {
        vm_resources.smbios_oem_strings = Some(builder_cfg.smbios_oem_strings);
    }

    if let Some(console) = builder_cfg.kernel_console {
        vm_resources.kernel_console = Some(console);
    }

    #[cfg(unix)]
    {
        vm_resources.serial_consoles = builder_cfg.serial_consoles;
    }

    let mut event_manager = EventManager::new().map_err(|e| Error::Internal(format!("{e:?}")))?;

    let (sender, _receiver) = unbounded();

    #[cfg(target_os = "macos")]
    let shutdown_efd =
        Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(|_| Error::ResourceAlloc())?);

    let inner = crate::builder::build_microvm(
        &vm_resources,
        &mut event_manager,
        #[cfg(target_os = "macos")]
        Some(EventFd::try_clone(&shutdown_efd).expect("dup shutdown_efd")),
        #[cfg(not(target_os = "macos"))]
        None,
        sender.clone(),
        device_manager,
    )
    .map_err(|e| Error::BootError(format!("{e:?}")))?;

    Ok(Vmm {
        inner: VmmInner::Vmm {
            vmm: inner,
            event_manager,
            _worker_sender: sender,
            #[cfg(target_os = "macos")]
            shutdown_efd,
        },
        _lifetime: PhantomData,
    })
}
