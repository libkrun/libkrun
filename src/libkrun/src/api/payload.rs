use std::path::PathBuf;

use super::error::Error;

#[allow(dead_code)]
pub(crate) enum PayloadKind {
    Vmm {
        bundle: Option<vmm::vmm_config::kernel_bundle::KernelBundle>,
        payload: vmm::builder::Payload,
        #[cfg(feature = "tee")]
        qboot_bundle: Option<vmm::vmm_config::kernel_bundle::QbootBundle>,
        #[cfg(feature = "tee")]
        initrd_bundle: Option<vmm::vmm_config::kernel_bundle::InitrdBundle>,
    },
    #[cfg(feature = "aws-nitro")]
    Nitro(crate::builder::NitroConfig),
}

#[allow(dead_code)]
pub struct Payload {
    pub(crate) kind: PayloadKind,
    pub(crate) cmdline: String,
}

#[ffier::export]
impl Payload {
    pub fn load_krunfw() -> Result<Self, Error> {
        let lib = KRUNFW.as_ref().ok_or_else(|| {
            log::error!("could not load {KRUNFW_NAME}");
            Error::FileNotFound()
        })?;
        let get_kernel: libloading::Symbol<
            unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *mut libc::c_char,
        > = unsafe {
            lib.get(b"krunfw_get_kernel").map_err(|e| {
                log::error!("krunfw symbol: {e}");
                Error::Internal()
            })?
        };

        let mut guest_addr: u64 = 0;
        let mut entry_addr: u64 = 0;
        let mut size: usize = 0;
        let host_addr = unsafe { get_kernel(&mut guest_addr, &mut entry_addr, &mut size) };
        if host_addr.is_null() {
            log::error!("krunfw_get_kernel returned null");
            return Err(Error::BootError());
        }
        let bundle = vmm::vmm_config::kernel_bundle::KernelBundle {
            host_addr: host_addr as u64,
            guest_addr,
            entry_addr,
            size,
        };

        #[cfg(feature = "tee")]
        let (qboot_bundle, initrd_bundle) = load_tee_bundles(lib)?;

        let payload_type = vmm::builder::choose_payload(
            Some(&bundle),
            #[cfg(feature = "tee")]
            qboot_bundle.as_ref(),
            #[cfg(feature = "tee")]
            initrd_bundle.as_ref(),
            None,
            None,
        )
        .map_err(|e| {
            log::error!("choose_payload: {e:?}");
            Error::BootError()
        })?;

        let cmdline = vmm::vmm_config::kernel_cmdline::DEFAULT_KERNEL_CMDLINE.replace(" quiet", "");

        Ok(Payload {
            kind: PayloadKind::Vmm {
                bundle: Some(bundle),
                payload: payload_type,
                #[cfg(feature = "tee")]
                qboot_bundle,
                #[cfg(feature = "tee")]
                initrd_bundle,
            },
            cmdline,
        })
    }

    pub fn load_external(path: &str, format: KernelFormat, cmdline: &str) -> Result<Self, Error> {
        use vmm::vmm_config::external_kernel::{ExternalKernel, KernelFormat as VmmKernelFormat};

        let vmm_format = match format {
            KernelFormat::Elf => VmmKernelFormat::Elf,
            KernelFormat::Raw => VmmKernelFormat::Raw,
        };

        let external_kernel = ExternalKernel {
            path: PathBuf::from(path),
            format: vmm_format,
            initramfs_path: None,
            initramfs_size: 0,
            cmdline: Some(cmdline.to_string()),
        };

        let payload_type = vmm::builder::choose_payload(
            None,
            #[cfg(feature = "tee")]
            None,
            #[cfg(feature = "tee")]
            None,
            Some(&external_kernel),
            None,
        )
        .map_err(|e| {
            log::error!("choose_payload: {e:?}");
            Error::BootError()
        })?;

        Ok(Payload {
            kind: PayloadKind::Vmm {
                bundle: None,
                payload: payload_type,
                #[cfg(feature = "tee")]
                qboot_bundle: None,
                #[cfg(feature = "tee")]
                initrd_bundle: None,
            },
            cmdline: cmdline.to_string(),
        })
    }

    pub fn cmdline(&self) -> &str {
        &self.cmdline
    }

    pub fn append_cmdline(&mut self, extra: &str) {
        if !extra.is_empty() {
            self.cmdline.push(' ');
            self.cmdline.push_str(extra);
        }
    }
}

#[cfg(feature = "aws-nitro")]
#[ffier::export]
impl Payload {
    pub fn nitro_enclave(config: crate::builder::NitroConfig) -> Result<Self, Error> {
        Ok(Payload {
            kind: PayloadKind::Nitro(config),
            cmdline: String::new(),
        })
    }
}

/// Load qboot and initrd bundles from the TEE-specific krunfw library.
#[cfg(feature = "tee")]
fn load_tee_bundles(
    lib: &libloading::Library,
) -> Result<
    (
        Option<vmm::vmm_config::kernel_bundle::QbootBundle>,
        Option<vmm::vmm_config::kernel_bundle::InitrdBundle>,
    ),
    Error,
> {
    use vmm::vmm_config::kernel_bundle::{InitrdBundle, QbootBundle};

    let get_qboot: libloading::Symbol<
        unsafe extern "C" fn(*mut usize) -> *mut libc::c_char,
    > = unsafe {
        lib.get(b"krunfw_get_qboot").map_err(|e| {
            log::error!("krunfw symbol krunfw_get_qboot: {e}");
            Error::Internal()
        })?
    };

    let get_initrd: libloading::Symbol<
        unsafe extern "C" fn(*mut usize) -> *mut libc::c_char,
    > = unsafe {
        lib.get(b"krunfw_get_initrd").map_err(|e| {
            log::error!("krunfw symbol krunfw_get_initrd: {e}");
            Error::Internal()
        })?
    };

    let mut qboot_size: usize = 0;
    let qboot_host_addr = unsafe { get_qboot(&mut qboot_size) };
    if qboot_host_addr.is_null() {
        log::error!("krunfw_get_qboot returned null");
        return Err(Error::BootError());
    }
    let qboot_bundle = QbootBundle {
        host_addr: qboot_host_addr as u64,
        size: qboot_size,
    };

    let mut initrd_size: usize = 0;
    let initrd_host_addr = unsafe { get_initrd(&mut initrd_size) };
    if initrd_host_addr.is_null() {
        log::error!("krunfw_get_initrd returned null");
        return Err(Error::BootError());
    }
    let initrd_bundle = InitrdBundle {
        host_addr: initrd_host_addr as u64,
        size: initrd_size,
    };

    Ok((Some(qboot_bundle), Some(initrd_bundle)))
}

#[ffier::export]
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum KernelFormat {
    Elf,
    Raw,
}

#[cfg(all(target_os = "linux", not(feature = "tee")))]
const KRUNFW_NAME: &str = "libkrunfw.so.5";
#[cfg(all(target_os = "linux", feature = "amd-sev"))]
const KRUNFW_NAME: &str = "libkrunfw-sev.so.5";
#[cfg(all(target_os = "linux", feature = "tdx"))]
const KRUNFW_NAME: &str = "libkrunfw-tdx.so.5";
#[cfg(target_os = "macos")]
const KRUNFW_NAME: &str = "libkrunfw.5.dylib";

static KRUNFW: std::sync::LazyLock<Option<libloading::Library>> =
    std::sync::LazyLock::new(|| unsafe { libloading::Library::new(KRUNFW_NAME).ok() });
