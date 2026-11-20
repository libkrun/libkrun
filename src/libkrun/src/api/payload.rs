use std::path::PathBuf;

use super::error::VmmError;
pub use crate::vmm::vmm_config::external_kernel::KernelFormat;

#[cfg(feature = "aws-nitro")]
use crate::NitroConfig;

pub(crate) enum PayloadKind {
    Kernel {
        bundle: crate::vmm::vmm_config::kernel_bundle::KernelBundle,
    },
    External {
        kernel: crate::vmm::vmm_config::external_kernel::ExternalKernel,
    },
    Firmware {
        path: PathBuf,
    },
    #[cfg(feature = "tee")]
    Tee {
        bundle: crate::vmm::vmm_config::kernel_bundle::KernelBundle,
        qboot_bundle: Option<crate::vmm::vmm_config::kernel_bundle::QbootBundle>,
        initrd_bundle: crate::vmm::vmm_config::kernel_bundle::InitrdBundle,
        tee_config_path: PathBuf,
        #[cfg(feature = "tdx")]
        firmware_path: Option<PathBuf>,
    },
    #[cfg(feature = "aws-nitro")]
    Nitro(NitroConfig),
}

pub struct Payload {
    pub(crate) kind: PayloadKind,
    pub(crate) cmdline: String,
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl Payload {
    pub fn load_krunfw() -> Result<Self, VmmError> {
        let lib = krunfw_library()?;

        let bundle = load_kernel_bundle(lib)?;
        Ok(Payload {
            kind: PayloadKind::Kernel { bundle },
            cmdline: crate::vmm::vmm_config::kernel_cmdline::DEFAULT_KERNEL_CMDLINE.to_string(),
        })
    }

    pub fn load_krunfw_tee(
        tee_config_path: &str,
        firmware_path: Option<&str>,
    ) -> Result<Self, VmmError> {
        #[cfg(feature = "tee")]
        {
            let lib = krunfw_library()?;

            let bundle = load_kernel_bundle(lib)?;
            #[cfg(feature = "tdx")]
            let use_td_shim = firmware_path.is_some_and(|s| !s.is_empty());
            #[cfg(feature = "tdx")]
            let (qboot_bundle, initrd_bundle) = if use_td_shim {
                (None, load_initrd_bundle(lib)?)
            } else {
                let (qboot, initrd) = load_tee_bundles(lib)?;
                (Some(qboot), initrd)
            };
            #[cfg(not(feature = "tdx"))]
            let (qboot_bundle, initrd_bundle) = {
                let _ = firmware_path;
                let (qboot, initrd) = load_tee_bundles(lib)?;
                (Some(qboot), initrd)
            };

            Ok(Payload {
                kind: PayloadKind::Tee {
                    bundle,
                    qboot_bundle,
                    initrd_bundle,
                    tee_config_path: PathBuf::from(tee_config_path),
                    #[cfg(feature = "tdx")]
                    firmware_path: firmware_path.filter(|s| !s.is_empty()).map(PathBuf::from),
                },
                cmdline: crate::vmm::vmm_config::kernel_cmdline::DEFAULT_KERNEL_CMDLINE.to_string(),
            })
        }
        #[cfg(not(feature = "tee"))]
        {
            let _ = tee_config_path;
            let _ = firmware_path;
            Err(VmmError::FeatureDisabled())
        }
    }

    pub fn load_external(
        kernel_path: &str,
        format: KernelFormat,
        initrd_path: Option<&str>,
        cmdline: &str,
    ) -> Result<Self, VmmError> {
        use crate::vmm::vmm_config::external_kernel::ExternalKernel;

        let (initramfs_path, initramfs_size) = if let Some(initrd) = initrd_path {
            let path = PathBuf::from(initrd);
            let size = std::fs::metadata(&path)
                .map_err(|e| {
                    log::error!("can't read initramfs metadata {path:?}: {e:?}");
                    VmmError::FileNotFound()
                })?
                .len();
            (Some(path), size)
        } else {
            (None, 0)
        };

        let external_kernel = ExternalKernel {
            path: PathBuf::from(kernel_path),
            format,
            initramfs_path,
            initramfs_size,
            cmdline: Some(cmdline.to_string()),
        };

        Ok(Payload {
            kind: PayloadKind::External {
                kernel: external_kernel,
            },
            cmdline: cmdline.to_string(),
        })
    }

    pub fn load_firmware(path: &str, cmdline: &str) -> Result<Self, VmmError> {
        Ok(Payload {
            kind: PayloadKind::Firmware {
                path: PathBuf::from(path),
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
            if let PayloadKind::External { ref mut kernel } = self.kind {
                kernel.cmdline = Some(self.cmdline.clone());
            }
        }
    }

    #[cfg(feature = "aws-nitro")]
    pub fn nitro_enclave(config: NitroConfig) -> Result<Self, VmmError> {
        Ok(Payload {
            kind: PayloadKind::Nitro(config),
            cmdline: String::new(),
        })
    }
}

fn load_kernel_bundle(
    lib: &libloading::Library,
) -> Result<crate::vmm::vmm_config::kernel_bundle::KernelBundle, VmmError> {
    let get_version: libloading::Symbol<unsafe extern "C" fn() -> libc::c_int> = unsafe {
        lib.get(b"krunfw_get_version").map_err(|e| {
            VmmError::BootError(format!(
                "cannot verify libkrunfw ABI {KRUNFW_ABI} (TSIv4): krunfw_get_version: {e}"
            ))
        })?
    };
    let version = unsafe { get_version() };
    if version != KRUNFW_ABI {
        return Err(VmmError::BootError(format!(
            "libkrunfw ABI mismatch: expected {KRUNFW_ABI} (TSIv4), found {version}"
        )));
    }

    let get_kernel: libloading::Symbol<
        unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *mut libc::c_char,
    > = unsafe {
        lib.get(b"krunfw_get_kernel")
            .map_err(|e| VmmError::Internal(format!("krunfw symbol: {e}")))?
    };

    let mut guest_addr: u64 = 0;
    let mut entry_addr: u64 = 0;
    let mut size: usize = 0;
    let host_addr = unsafe { get_kernel(&mut guest_addr, &mut entry_addr, &mut size) };
    if host_addr.is_null() {
        return Err(VmmError::BootError(
            "krunfw_get_kernel returned null".into(),
        ));
    }

    Ok(crate::vmm::vmm_config::kernel_bundle::KernelBundle {
        host_addr: host_addr as u64,
        guest_addr,
        entry_addr,
        size,
    })
}

#[cfg(feature = "tee")]
fn load_tee_bundles(
    lib: &libloading::Library,
) -> Result<
    (
        crate::vmm::vmm_config::kernel_bundle::QbootBundle,
        crate::vmm::vmm_config::kernel_bundle::InitrdBundle,
    ),
    VmmError,
> {
    use crate::vmm::vmm_config::kernel_bundle::{InitrdBundle, QbootBundle};

    let get_qboot: libloading::Symbol<unsafe extern "C" fn(*mut usize) -> *mut libc::c_char> = unsafe {
        lib.get(b"krunfw_get_qboot")
            .map_err(|e| VmmError::Internal(format!("krunfw symbol krunfw_get_qboot: {e}")))?
    };

    let get_initrd: libloading::Symbol<unsafe extern "C" fn(*mut usize) -> *mut libc::c_char> = unsafe {
        lib.get(b"krunfw_get_initrd")
            .map_err(|e| VmmError::Internal(format!("krunfw symbol krunfw_get_initrd: {e}")))?
    };

    let mut qboot_size: usize = 0;
    let qboot_host_addr = unsafe { get_qboot(&mut qboot_size) };
    if qboot_host_addr.is_null() {
        return Err(VmmError::BootError("krunfw_get_qboot returned null".into()));
    }
    let qboot_bundle = QbootBundle {
        host_addr: qboot_host_addr as u64,
        size: qboot_size,
    };

    let mut initrd_size: usize = 0;
    let initrd_host_addr = unsafe { get_initrd(&mut initrd_size) };
    if initrd_host_addr.is_null() {
        return Err(VmmError::BootError(
            "krunfw_get_initrd returned null".into(),
        ));
    }
    let initrd_bundle = InitrdBundle {
        host_addr: initrd_host_addr as u64,
        size: initrd_size,
    };

    Ok((qboot_bundle, initrd_bundle))
}

#[cfg(all(feature = "tee", feature = "tdx"))]
fn load_initrd_bundle(
    lib: &libloading::Library,
) -> Result<crate::vmm::vmm_config::kernel_bundle::InitrdBundle, VmmError> {
    use crate::vmm::vmm_config::kernel_bundle::InitrdBundle;

    let get_initrd: libloading::Symbol<unsafe extern "C" fn(*mut usize) -> *mut libc::c_char> = unsafe {
        lib.get(b"krunfw_get_initrd")
            .map_err(|e| VmmError::Internal(format!("krunfw symbol krunfw_get_initrd: {e}")))?
    };

    let mut initrd_size: usize = 0;
    let initrd_host_addr = unsafe { get_initrd(&mut initrd_size) };
    if initrd_host_addr.is_null() {
        return Err(VmmError::BootError(
            "krunfw_get_initrd returned null".into(),
        ));
    }
    let initrd_bundle = InitrdBundle {
        host_addr: initrd_host_addr as u64,
        size: initrd_size,
    };

    Ok(initrd_bundle)
}

#[cfg(all(target_os = "linux", not(feature = "tee")))]
const KRUNFW_NAME: &str = "libkrunfw.so.6";
#[cfg(all(target_os = "linux", feature = "amd-sev"))]
const KRUNFW_NAME: &str = "libkrunfw-sev.so.6";
#[cfg(all(target_os = "linux", feature = "tdx"))]
const KRUNFW_NAME: &str = "libkrunfw-tdx.so.6";
#[cfg(target_os = "macos")]
const KRUNFW_NAME: &str = "libkrunfw.6.dylib";
#[cfg(target_os = "windows")]
const KRUNFW_NAME: &str = "libkrunfw.dll";

const KRUNFW_ABI: libc::c_int = 6;

static KRUNFW: std::sync::LazyLock<Result<libloading::Library, libloading::Error>> =
    std::sync::LazyLock::new(|| unsafe { libloading::Library::new(KRUNFW_NAME) });

fn krunfw_library() -> Result<&'static libloading::Library, VmmError> {
    KRUNFW.as_ref().map_err(|e| {
        VmmError::BootError(format!(
            "could not load {KRUNFW_NAME} (requires libkrunfw ABI {KRUNFW_ABI}, TSIv4): {e}"
        ))
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use vmm_sys_util::tempfile::TempFile;

    const KERNEL: &str = r#"
#include <stddef.h>
#include <stdint.h>
char *krunfw_get_kernel(uint64_t *load, uint64_t *entry, size_t *size)
{
    static char data[] = { 1, 2, 3, 4 };
    *load = 0x100000;
    *entry = 0x100100;
    *size = sizeof(data);
    return data;
}
"#;

    fn fixture(source: &str) -> (libloading::Library, TempFile) {
        let file = TempFile::new().unwrap();
        let link_flag = if cfg!(target_os = "macos") {
            "-dynamiclib"
        } else {
            "-shared"
        };
        let mut compiler = Command::new("cc")
            .args([link_flag, "-fPIC", "-x", "c", "-o"])
            .arg(file.as_path())
            .arg("-")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        compiler
            .stdin
            .take()
            .unwrap()
            .write_all(source.as_bytes())
            .unwrap();
        let output = compiler.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let library = unsafe { libloading::Library::new(file.as_path()).unwrap() };
        (library, file)
    }

    #[test]
    fn accepts_abi_6() {
        let (library, _file) = fixture(&format!(
            "int krunfw_get_version(void) {{ return 6; }}\n{KERNEL}"
        ));
        let bundle = load_kernel_bundle(&library).unwrap();
        assert_eq!(bundle.guest_addr, 0x100000);
        assert_eq!(bundle.entry_addr, 0x100100);
        assert_eq!(bundle.size, 4);
        assert_eq!(unsafe { *(bundle.host_addr as *const u8) }, 1);
    }

    #[test]
    fn rejects_incompatible_abi_before_kernel_lookup() {
        for version in [-1, 0, 5, 7] {
            let (library, _file) = fixture(&format!(
                "int krunfw_get_version(void) {{ return {version}; }}"
            ));
            let error = load_kernel_bundle(&library).unwrap_err();
            assert!(matches!(error, VmmError::BootError(_)));
            let message = error.to_string();
            assert!(message.contains("expected 6"), "{message}");
            assert!(message.contains(&format!("found {version}")), "{message}");
        }
    }

    #[test]
    fn rejects_missing_abi_export() {
        let (library, _file) = fixture(KERNEL);
        let error = load_kernel_bundle(&library).unwrap_err();
        assert!(matches!(error, VmmError::BootError(_)));
        let message = error.to_string();
        assert!(message.contains("krunfw_get_version"), "{message}");
        assert!(message.contains("ABI 6"), "{message}");
    }

    #[test]
    fn abi_6_still_requires_kernel_export() {
        let (library, _file) = fixture("int krunfw_get_version(void) { return 6; }");
        assert!(matches!(
            load_kernel_bundle(&library),
            Err(VmmError::Internal(_))
        ));
    }

    #[test]
    fn abi_6_still_rejects_null_kernel() {
        let (library, _file) = fixture(
            r#"
#include <stddef.h>
#include <stdint.h>
int krunfw_get_version(void) { return 6; }
char *krunfw_get_kernel(uint64_t *load, uint64_t *entry, size_t *size) { return NULL; }
"#,
        );
        let error = load_kernel_bundle(&library).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("krunfw_get_kernel returned null")
        );
    }
}
