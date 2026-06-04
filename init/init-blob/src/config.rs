// SPDX-License-Identifier: Apache-2.0
//
//! Init configuration builder and applicator.
//!
//! A [`Builder`] can be constructed from scratch or from an OCI runtime-spec
//! config.json via [`Builder::from_oci_json`]. The internal serialization
//! format is an implementation detail — callers should not rely on it.
//!
//! ```ignore
//! let config = Config::builder()
//!     .args(&["/usr/bin/bash", "--login"])
//!     .env(&["HOME=/root"])
//!     .workdir("/home/user")
//!     .build();
//! unsafe { config.apply(std::ptr::null_mut(), ctx_id, "/dev/root").unwrap() };
//! // config must remain alive until the VM exits.
//! ```

use std::borrow::Cow;
use std::ffi::{CString, c_char, c_void};
use std::mem::ManuallyDrop;

use libloading::os::unix::Library;

use crate::init_schema::{ConfigSchema, Mount};
use crate::oci_schema::OciSchema;
#[cfg(feature = "ffi")]
use crate::{FfiBorrow, FfiType};

/// Error type for init configuration operations.
#[derive(Clone, Debug, thiserror::Error)]
#[cfg_attr(feature = "ffi", derive(ffier::FfiError))]
#[non_exhaustive]
pub enum ConfigError {
    /// The JSON string could not be parsed.
    #[error("invalid config JSON: {0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 1))]
    InvalidJson(Box<str>),
}

/// Error returned by [`Config::apply`].
#[derive(Clone, Debug, thiserror::Error)]
#[cfg_attr(feature = "ffi", derive(ffier::FfiError))]
#[non_exhaustive]
pub enum ApplyError {
    /// A required libkrun symbol could not be found via dlsym.
    #[error("{0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 1))]
    SymbolNotFound(Box<str>),

    /// `krun_fs_add_overlay_file` failed.
    #[error("overlay file: {}", std::io::Error::from_raw_os_error(*.0))]
    #[cfg_attr(feature = "ffi", ffier(code = 2))]
    OverlayFile(i32),

    /// `krun_append_kernel_cmdline` failed.
    #[error("kernel cmdline: {}", std::io::Error::from_raw_os_error(*.0))]
    #[cfg_attr(feature = "ffi", ffier(code = 3))]
    KernelCmdline(i32),
}

/// Guest-side path of the init binary (e.g. for `init=` kernel arg).
pub const INIT_PATH: &str = "/init.krun";

/// Kernel cmdline argument to boot with the embedded init.
pub const KERNEL_INIT_ARG: &str = "init=/init.krun";

/// A file that the init process expects to find on the guest root filesystem.
pub(crate) struct GuestFile {
    pub path: &'static str,
    pub data: Cow<'static, [u8]>,
    pub mode: u32,
    pub one_shot: bool,
}

/// Built init configuration. Immutable after construction.
///
/// Holds the init binary and serialized config JSON as guest files.
/// [`apply`](Self::apply) passes pointers to this data into libkrun — the
/// caller **must keep this value alive for the entire lifetime of the VM**.
/// Dropping it while the VM is running causes dangling pointers.
pub struct Config {
    files: Vec<GuestFile>,
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl Config {
    /// Start building a new init configuration.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Apply this init configuration to a libkrun VM context.
    ///
    /// Adds the init binary and associated configuration file(s) as
    /// overlay files on the specified virtiofs device, and appends
    /// the appropriate kernel command line argument to specify the
    /// init binary.
    ///
    /// `lib_handle` is the result of `dlopen("libkrun.so")`. Pass NULL to
    /// search the global symbol namespace (requires libkrun was linked or
    /// opened with `RTLD_GLOBAL`).
    ///
    /// # Safety
    ///
    /// - If `lib_handle` is non-null it must be a valid handle returned by
    ///   `dlopen` (or equivalent) that remains open for the duration of
    ///   this call.
    /// - The caller must keep this `Config` alive for the entire lifetime
    ///   of the VM. `apply` passes data pointers to libkrun that remain
    ///   borrowed until the VM exits.
    pub unsafe fn apply(
        &self,
        lib_handle: *mut c_void,
        ctx_id: u32,
        fs_tag: &str,
    ) -> Result<(), ApplyError> {
        type AddOverlayFileFn = unsafe extern "C" fn(
            u32,
            *const c_char,
            *const c_char,
            *const u8,
            usize,
            u32,
            bool,
        ) -> i32;
        type AppendKernelCmdlineFn = unsafe extern "C" fn(u32, *const c_char) -> i32;

        fn load_sym<T: Copy>(lib_handle: *mut c_void, name: &[u8]) -> Result<T, ApplyError> {
            if lib_handle.is_null() {
                let lib = Library::this();
                unsafe { lib.get(name) }.map(|s| *s)
            } else {
                let lib = ManuallyDrop::new(unsafe { Library::from_raw(lib_handle) });
                unsafe { lib.get(name) }.map(|s| *s)
            }
            .map_err(|e| ApplyError::SymbolNotFound(e.to_string().into()))
        }

        let add_overlay_file: AddOverlayFileFn =
            load_sym(lib_handle, b"krun_fs_add_overlay_file\0")?;
        let append_kernel_cmdline: AppendKernelCmdlineFn =
            load_sym(lib_handle, b"krun_append_kernel_cmdline\0")?;

        let c_fs_tag = CString::new(fs_tag).expect("fs_tag must not contain NUL bytes");

        for file in &self.files {
            let c_path = CString::new(file.path).expect("path must not contain NUL bytes");
            let ret = unsafe {
                add_overlay_file(
                    ctx_id,
                    c_fs_tag.as_ptr(),
                    c_path.as_ptr(),
                    file.data.as_ptr(),
                    file.data.len(),
                    file.mode,
                    file.one_shot,
                )
            };
            if ret != 0 {
                return Err(ApplyError::OverlayFile(-ret));
            }
        }

        let c_init_arg = CString::new(KERNEL_INIT_ARG).unwrap();
        let ret = unsafe { append_kernel_cmdline(ctx_id, c_init_arg.as_ptr()) };
        if ret != 0 {
            return Err(ApplyError::KernelCmdline(-ret));
        }

        Ok(())
    }
}

/// Builder for [`Config`].
#[derive(Clone, Debug, Default)]
pub struct Builder {
    inner: ConfigSchema,
    rlimits: Vec<String>,
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl Builder {
    /// Parse an OCI runtime-spec config.json string into a builder.
    ///
    /// Unknown fields are silently ignored. The caller can further
    /// modify the builder (e.g. add rlimits, mounts) before calling
    /// [`build()`](Self::build).
    pub fn from_oci_json(json: &str) -> Result<Self, ConfigError> {
        let oci: OciSchema = serde_json::from_str(json)
            .map_err(|e| ConfigError::InvalidJson(e.to_string().into()))?;
        Ok(Self {
            inner: oci.into(),
            rlimits: Vec::new(),
        })
    }

    /// Append a single argument to argv.
    pub fn arg(mut self, arg: &str) -> Self {
        self.inner.process.args.push(arg.to_string());
        self
    }

    /// Append multiple arguments to argv.
    pub fn args(mut self, argv: &[&str]) -> Self {
        self.inner
            .process
            .args
            .extend(argv.iter().map(|s| s.to_string()));
        self
    }

    /// Append a single environment variable (`"KEY=value"`).
    pub fn env_var(mut self, var: &str) -> Self {
        self.inner.process.env.push(var.to_string());
        self
    }

    /// Append multiple environment variables.
    pub fn env(mut self, vars: &[&str]) -> Self {
        self.inner
            .process
            .env
            .extend(vars.iter().map(|s| s.to_string()));
        self
    }

    /// Set the guest working directory.
    pub fn workdir(mut self, dir: &str) -> Self {
        self.inner.process.cwd = Some(dir.to_string());
        self
    }

    /// Add a mount specification.
    pub fn mount(mut self, destination: &str, fs_type: &str, source: &str) -> Self {
        self.inner.mounts.push(Mount {
            destination: destination.to_string(),
            fs_type: fs_type.to_string(),
            source: source.to_string(),
        });
        self
    }

    /// Append a single resource limit (`"id=cur:max"`, e.g. `"7=0:0"`).
    pub fn rlimit(mut self, limit: &str) -> Self {
        self.rlimits.push(limit.to_string());
        self
    }

    /// Append multiple resource limits.
    pub fn rlimits(mut self, limits: &[&str]) -> Self {
        self.rlimits.extend(limits.iter().map(|s| s.to_string()));
        self
    }

    /// Consume the builder, serialize the config, and return the
    /// finished [`Config`].
    pub fn build(mut self) -> Config {
        // FIXME: do not mixup user env vars with libkrun internal config.
        // Inject rlimits as KRUN_RLIMITS env var.
        if !self.rlimits.is_empty() {
            let value = self.rlimits.join(",");
            self.inner
                .process
                .env
                .retain(|e| !e.starts_with("KRUN_RLIMITS="));
            self.inner.process.env.push(format!("KRUN_RLIMITS={value}"));
        }

        let config_json =
            serde_json::to_vec(&self.inner).expect("ConfigSchema serialization cannot fail");
        Config {
            files: vec![
                GuestFile {
                    path: INIT_PATH,
                    data: Cow::Borrowed(super::INIT_BINARY),
                    mode: 0o755,
                    one_shot: true,
                },
                GuestFile {
                    path: "/.krun_config.json",
                    data: Cow::Owned(config_json),
                    mode: 0o644,
                    one_shot: true,
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_config_json(cfg: &Config) -> serde_json::Value {
        let config_file = &cfg.files[1];
        serde_json::from_slice(&config_file.data).unwrap()
    }

    #[test]
    fn builder_produces_valid_config() {
        let cfg = Config::builder()
            .args(&["/usr/bin/bash", "--login"])
            .env(&["HOME=/root", "TERM=xterm-256color"])
            .workdir("/home/user")
            .mount("/tmp", "tmpfs", "tmpfs")
            .rlimits(&["7=0:0"])
            .build();

        let json = parse_config_json(&cfg);
        assert_eq!(
            json["process"]["args"],
            serde_json::json!(["/usr/bin/bash", "--login"])
        );
        assert_eq!(json["process"]["cwd"], "/home/user");
        assert_eq!(json["mounts"][0]["type"], "tmpfs");

        // rlimits injected as env var
        let env = json["process"]["env"].as_array().unwrap();
        assert!(env.iter().any(|v| v.as_str() == Some("KRUN_RLIMITS=7=0:0")));
    }

    #[test]
    fn from_oci_json() {
        let json = r#"{"process":{"args":["/bin/sh"],"cwd":"/"}}"#;
        let cfg = Builder::from_oci_json(json).unwrap().build();
        let parsed = parse_config_json(&cfg);
        assert_eq!(parsed["process"]["args"], serde_json::json!(["/bin/sh"]));
    }

    #[test]
    fn files_contain_init_and_config() {
        let cfg = Config::builder().args(&["/bin/sh"]).build();
        assert_eq!(cfg.files.len(), 2);
        assert_eq!(cfg.files[0].path, INIT_PATH);
        assert!(!cfg.files[0].data.is_empty());
        assert_eq!(cfg.files[1].path, "/.krun_config.json");
    }
}
