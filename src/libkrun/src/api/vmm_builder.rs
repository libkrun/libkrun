use std::marker::PhantomData;
#[cfg(unix)]
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};

use crossbeam_channel::unbounded;
use polly::event_manager::EventManager;
use vmm::Vmm as InnerVmm;
use vmm::resources::VmResources;
use vmm::vmm_config::machine_config::VmConfig;

use super::devices::{DeviceManager, MmioDeviceManager};
use super::error::{DetailedError, Error};
use super::payload::Payload;

pub struct VmmBuilder<'a> {
    vcpus: Option<u8>,
    ram_mib: Option<u32>,
    kernel: Option<Payload>,
    device_manager: Option<Box<dyn DeviceManager<'a> + 'a>>,
    #[cfg(unix)]
    serial_input_fd: Option<RawFd>,
    kernel_console: Option<String>,
    #[cfg(feature = "tee")]
    tee_config_path: Option<std::path::PathBuf>,
}

impl Default for VmmBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[ffier::export]
impl<'a> VmmBuilder<'a> {
    pub fn new() -> Self {
        VmmBuilder {
            vcpus: None,
            ram_mib: None,
            kernel: None,
            device_manager: None,
            #[cfg(unix)]
            serial_input_fd: None,
            kernel_console: None,
            #[cfg(feature = "tee")]
            tee_config_path: None,
        }
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
        self.kernel = Some(payload);
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

    /// Set the fd used as input for the legacy serial console (e.g. a pipe read end).
    ///
    /// When set, a serial console device is created with this fd as input and the
    /// corresponding output duplicated to stdout. This is required for FreeBSD guests
    /// which use the legacy serial console instead of the virtio console.
    #[cfg(unix)]
    pub fn serial_input_fd(mut self, fd: i32) -> Self {
        self.serial_input_fd = Some(fd);
        self
    }

    pub fn build(self) -> Result<Vmm<'a>, Error> {
        build_vm(self).map_err(|e| {
            log::error!("{e}");
            e.code
        })
    }
}

impl<'a> VmmBuilder<'a> {
    /// Load TEE configuration from a JSON file.
    ///
    /// The file is parsed to obtain the TEE type (SNP/TDX), vCPU count,
    /// and RAM size — overriding values set by [`vcpus`](Self::vcpus) and
    /// [`ram_mib`](Self::ram_mib) if already set.
    #[cfg(feature = "tee")]
    pub fn set_tee_config_file(mut self, path: &str) -> Self {
        self.tee_config_path = Some(std::path::PathBuf::from(path));
        self
    }
}

pub struct Vmm<'a> {
    #[allow(dead_code)]
    inner: Arc<Mutex<InnerVmm>>,
    event_manager: EventManager,
    #[allow(dead_code)]
    _worker_sender: crossbeam_channel::Sender<utils::worker_message::WorkerMessage>,
    _lifetime: PhantomData<&'a ()>,
}

#[ffier::export]
impl<'a> Vmm<'a> {
    pub fn run(&mut self) {
        loop {
            if let Err(e) = self.event_manager.run() {
                log::error!("fatal event loop error: {e:?}");
                return;
            }
        }
    }
}

fn build_vm(builder_cfg: VmmBuilder<'_>) -> Result<Vmm<'_>, DetailedError> {
    let vcpus_count = builder_cfg
        .vcpus
        .ok_or_else(|| DetailedError::new(Error::MissingConfig(), "vcpus not set"))?;
    let ram_mib = builder_cfg
        .ram_mib
        .ok_or_else(|| DetailedError::new(Error::MissingConfig(), "ram_mib not set"))?;
    let device_manager = builder_cfg.device_manager.ok_or_else(|| {
        DetailedError::new(
            Error::MissingConfig(),
            "no device manager set (call .devices())",
        )
    })?;
    let loaded_kernel = builder_cfg
        .kernel
        .ok_or_else(|| DetailedError::new(Error::MissingConfig(), "kernel not set"))?;

    let mut vm_resources = VmResources::default();
    vm_resources
        .set_vm_config(&VmConfig {
            vcpu_count: Some(vcpus_count),
            mem_size_mib: Some(ram_mib as usize),
            ht_enabled: Some(false),
            cpu_template: None,
        })
        .map_err(|e| DetailedError::new(Error::InvalidParam(), format!("{e:?}")))?;

    vm_resources.kernel_bundle = loaded_kernel.bundle;
    if let vmm::builder::Payload::ExternalKernel(ref ek) = loaded_kernel.payload {
        vm_resources.external_kernel = Some(ek.clone());
    }

    #[cfg(feature = "tee")]
    if let Some(qboot) = loaded_kernel.qboot_bundle {
        vm_resources
            .set_qboot_bundle(qboot)
            .map_err(|e| DetailedError::new(Error::InvalidParam(), format!("{e}")))?;
    }

    #[cfg(feature = "tee")]
    if let Some(initrd) = loaded_kernel.initrd_bundle {
        vm_resources
            .set_initrd_bundle(initrd)
            .map_err(|e| DetailedError::new(Error::InvalidParam(), format!("{e}")))?;
    }

    vm_resources.kernel_cmdline.prolog = Some(loaded_kernel.cmdline);

    if let Some(console) = builder_cfg.kernel_console {
        vm_resources.kernel_console = Some(console);
    }

    #[cfg(feature = "tee")]
    if let Some(tee_path) = builder_cfg.tee_config_path {
        vm_resources
            .set_tee_config(tee_path)
            .map_err(|e| DetailedError::new(Error::InvalidParam(), format!("{e:?}")))?;
    }

    #[cfg(unix)]
    if let Some(serial_fd) = builder_cfg.serial_input_fd {
        use vmm::resources::SerialConsoleConfig;
        vm_resources.serial_consoles.push(SerialConsoleConfig {
            input_fd: serial_fd,
            output_fd: unsafe { libc::dup(serial_fd) },
        });
    }

    let mut event_manager = EventManager::new()
        .map_err(|e| DetailedError::new(Error::Internal(), format!("{e:?}")))?;

    let (sender, _receiver) = unbounded();

    let inner = crate::builder::build_microvm(
        &vm_resources,
        &mut event_manager,
        None,
        sender.clone(),
        device_manager,
    )
    .map_err(|e| DetailedError::new(Error::BootError(), format!("{e:?}")))?;

    Ok(Vmm {
        inner,
        event_manager,
        _worker_sender: sender,
        _lifetime: PhantomData,
    })
}
