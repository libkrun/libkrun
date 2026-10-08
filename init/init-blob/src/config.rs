// SPDX-License-Identifier: Apache-2.0
//
//! Init configuration builder and applicator.
//!
//! A [`Builder`] can be constructed from scratch or from an OCI runtime-spec
//! config.json via [`Builder::from_oci_json`]. The internal serialization
//! format is an implementation detail — callers should not rely on it.

use std::borrow::Cow;

use crate::init_schema::{ConfigSchema, ControlServerConfig, Mount};
use crate::oci_schema::OciSchema;
#[cfg(feature = "ffi")]
use crate::{FfiBorrow, FfiType};
use krun_init_common::control::DEFAULT_VSOCK_PORT;

#[cfg(feature = "direct")]
pub type VmmError = krun::VmmError;

#[cfg(all(feature = "ffi-client", not(feature = "direct")))]
pub type VmmError = krun_via_cdylib_weak::VmmError;

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
#[cfg(any(feature = "direct", feature = "ffi-client"))]
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "ffi", derive(ffier::FfiError))]
#[non_exhaustive]
pub enum ApplyError {
    /// A required libkrun symbol could not be loaded.
    #[error("{0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 1))]
    SymbolNotFound(Box<str>),
    /// An error occurred while adding an overlay file.
    #[error("overlay error: {0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 2, opaque))]
    OverlayError(VmmError),
    /// A control socket was configured but `apply` was used instead of `apply_with_vsock`.
    #[error("the control socket needs a vsock device, use apply_with_vsock")]
    #[cfg_attr(feature = "ffi", ffier(code = 3))]
    ControlSocketWithoutVsock(),
}

/// Guest-side path of the init binary (e.g. for `init=` kernel arg).
pub const INIT_PATH: &str = "/init.krun";

/// Kernel cmdline argument to boot with the embedded init.
pub const KERNEL_INIT_ARG: &str = "init=/init.krun";

/// A file that the init process expects to find on the guest root filesystem.
#[cfg_attr(not(any(feature = "direct", feature = "ffi-client")), allow(dead_code))]
pub(crate) struct GuestFile {
    pub path: &'static str,
    pub data: Cow<'static, [u8]>,
    pub mode: u32,
    pub one_shot: bool,
}

/// Host endpoint of the guest control server.
#[cfg_attr(not(any(feature = "direct", feature = "ffi-client")), allow(dead_code))]
pub(crate) struct ControlEndpoint {
    pub socket_path: String,
    pub vsock_port: u32,
}

/// Built init configuration. Immutable after construction.
///
/// Holds the init binary and serialized config JSON as guest files.
/// The caller **must keep this value alive for the entire lifetime of the VM**.
pub struct Config {
    #[cfg_attr(not(any(feature = "direct", feature = "ffi-client")), allow(dead_code))]
    files: Vec<GuestFile>,
    #[cfg_attr(not(any(feature = "direct", feature = "ffi-client")), allow(dead_code))]
    control: Option<ControlEndpoint>,
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl Config {
    /// Start building a new init configuration.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Apply this init configuration to a VM's filesystem overlay and payload.
    ///
    /// Adds the init binary and associated configuration file(s) as overlay
    /// files, and appends the init kernel command line argument to the payload.
    /// Fails when a control socket is configured: that needs a vsock device,
    /// use [`apply_with_vsock`](Self::apply_with_vsock).
    ///
    /// The caller must keep this `Config` (or `KrunInitConfig`) alive for the
    /// entire lifetime of the VM; `apply` borrows data pointers that remain
    /// referenced until the VM exits.
    ///
    /// Symbols are loaded from the global namespace (`RTLD_DEFAULT`).
    #[cfg(feature = "ffi-client")]
    pub fn apply<'a>(
        &'a self,
        #[cfg_attr(feature = "ffi", ffier(foreign = krun_via_cdylib_weak, c_name = "KrunFsOverlay"))]
        overlay: &mut krun_via_cdylib_weak::FsOverlay<'a>,
        #[cfg_attr(feature = "ffi", ffier(foreign = krun_via_cdylib_weak, c_name = "KrunPayload"))]
        payload: &mut krun_via_cdylib_weak::Payload,
    ) -> Result<(), ApplyError> {
        self.apply_in(core::ptr::null_mut(), overlay, payload)
    }

    /// Like [`apply`](Self::apply), and also map the control server's vsock
    /// port to the configured control socket on `vsock`.
    #[cfg(feature = "ffi-client")]
    pub fn apply_with_vsock<'a>(
        &'a self,
        #[cfg_attr(feature = "ffi", ffier(foreign = krun_via_cdylib_weak, c_name = "KrunFsOverlay"))]
        overlay: &mut krun_via_cdylib_weak::FsOverlay<'a>,
        #[cfg_attr(feature = "ffi", ffier(foreign = krun_via_cdylib_weak, c_name = "KrunPayload"))]
        payload: &mut krun_via_cdylib_weak::Payload,
        #[cfg_attr(feature = "ffi", ffier(foreign = krun_via_cdylib_weak, c_name = "KrunVsockDevice"))]
        vsock: &mut krun_via_cdylib_weak::VsockDevice,
    ) -> Result<(), ApplyError> {
        self.apply_with_vsock_in(core::ptr::null_mut(), overlay, payload, vsock)
    }

    /// Like [`apply`](Self::apply), but loads symbols from a specific library
    /// handle (e.g. from `dlopen`). Pass null for `RTLD_DEFAULT`.
    ///
    /// - If `lib_handle` is non-null it must be a valid handle returned by
    ///   `dlopen` (or equivalent) that remains open for the duration of
    ///   this call.
    /// - The caller must keep this `Config` (or `KrunInitConfig`) alive for the
    ///   entire lifetime of the VM.
    #[cfg(feature = "ffi-client")]
    pub fn apply_in<'a>(
        &'a self,
        lib_handle: *mut core::ffi::c_void,
        #[cfg_attr(feature = "ffi", ffier(foreign = krun_via_cdylib_weak, c_name = "KrunFsOverlay"))]
        overlay: &mut krun_via_cdylib_weak::FsOverlay<'a>,
        #[cfg_attr(feature = "ffi", ffier(foreign = krun_via_cdylib_weak, c_name = "KrunPayload"))]
        payload: &mut krun_via_cdylib_weak::Payload,
    ) -> Result<(), ApplyError> {
        if self.control.is_some() {
            return Err(ApplyError::ControlSocketWithoutVsock());
        }
        self.apply_files_in(lib_handle, overlay, payload)
    }

    /// Like [`apply_with_vsock`](Self::apply_with_vsock), loading symbols
    /// from `lib_handle` as [`apply_in`](Self::apply_in) does.
    #[cfg(feature = "ffi-client")]
    pub fn apply_with_vsock_in<'a>(
        &'a self,
        lib_handle: *mut core::ffi::c_void,
        #[cfg_attr(feature = "ffi", ffier(foreign = krun_via_cdylib_weak, c_name = "KrunFsOverlay"))]
        overlay: &mut krun_via_cdylib_weak::FsOverlay<'a>,
        #[cfg_attr(feature = "ffi", ffier(foreign = krun_via_cdylib_weak, c_name = "KrunPayload"))]
        payload: &mut krun_via_cdylib_weak::Payload,
        #[cfg_attr(feature = "ffi", ffier(foreign = krun_via_cdylib_weak, c_name = "KrunVsockDevice"))]
        vsock: &mut krun_via_cdylib_weak::VsockDevice,
    ) -> Result<(), ApplyError> {
        if let Some(control) = &self.control {
            krun_via_cdylib_weak::require(
                core::ptr::NonNull::new(lib_handle),
                &[krun_via_cdylib_weak::Symbol::KrunVsockDeviceAddUnixPort],
            )
            .map_err(|e| ApplyError::SymbolNotFound(e.to_string().into()))?;
            vsock.add_unix_port(control.vsock_port, &control.socket_path, true);
        }
        self.apply_files_in(lib_handle, overlay, payload)
    }
}

#[cfg(feature = "ffi-client")]
impl Config {
    fn apply_files_in<'a>(
        &'a self,
        lib_handle: *mut core::ffi::c_void,
        overlay: &mut krun_via_cdylib_weak::FsOverlay<'a>,
        payload: &mut krun_via_cdylib_weak::Payload,
    ) -> Result<(), ApplyError> {
        krun_via_cdylib_weak::require(
            core::ptr::NonNull::new(lib_handle),
            &[
                krun_via_cdylib_weak::Symbol::KrunFsOverlayAddFile,
                krun_via_cdylib_weak::Symbol::KrunPayloadAppendCmdline,
            ],
        )
        .map_err(|e| ApplyError::SymbolNotFound(e.to_string().into()))?;

        for file in &self.files {
            overlay
                .add_file(file.path, &file.data, file.mode, file.one_shot)
                .map_err(ApplyError::OverlayError)?;
        }
        payload.append_cmdline(KERNEL_INIT_ARG);
        Ok(())
    }
}

#[cfg(feature = "direct")]
impl Config {
    /// Apply this init configuration using statically-linked libkrun types.
    ///
    /// The caller must keep this `Config` alive for the entire lifetime of the VM.
    pub fn apply<'a>(
        &'a self,
        overlay: &mut krun::FsOverlay<'a>,
        payload: &mut krun::Payload,
    ) -> Result<(), ApplyError> {
        if self.control.is_some() {
            return Err(ApplyError::ControlSocketWithoutVsock());
        }
        self.apply_files(overlay, payload)
    }

    /// Like [`apply`](Self::apply), and also map the control server's vsock
    /// port to the configured control socket on `vsock`.
    pub fn apply_with_vsock<'a>(
        &'a self,
        overlay: &mut krun::FsOverlay<'a>,
        payload: &mut krun::Payload,
        vsock: &mut krun::VsockDevice,
    ) -> Result<(), ApplyError> {
        if let Some(control) = &self.control {
            vsock.add_unix_port(control.vsock_port, &control.socket_path, true);
        }
        self.apply_files(overlay, payload)
    }

    fn apply_files<'a>(
        &'a self,
        overlay: &mut krun::FsOverlay<'a>,
        payload: &mut krun::Payload,
    ) -> Result<(), ApplyError> {
        for file in &self.files {
            overlay
                .add_file(file.path, &file.data, file.mode, file.one_shot)
                .map_err(ApplyError::OverlayError)?;
        }
        payload.append_cmdline(KERNEL_INIT_ARG);
        Ok(())
    }
}

/// Builder for [`Config`].
#[derive(Clone, Debug)]
pub struct Builder {
    inner: ConfigSchema,
    rlimits: Vec<String>,
    control_socket: Option<String>,
    control_vsock_port: u32,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            inner: ConfigSchema::default(),
            rlimits: Vec::new(),
            control_socket: None,
            control_vsock_port: DEFAULT_VSOCK_PORT,
        }
    }
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
            ..Self::default()
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

    /// Enable DHCP client in the guest.
    pub fn dhcp(mut self, enable: bool) -> Self {
        self.inner
            .process
            .env
            .retain(|e| !e.starts_with("KRUN_DHCP="));
        if enable {
            self.inner.process.env.push("KRUN_DHCP=1".to_string());
        }
        self
    }

    /// Run a control server in the guest and expose it to the host as the
    /// Unix socket `path`.
    ///
    /// The server lets the host start additional processes in the running
    /// VM ([`Controller::exec_pipes`](crate::Controller::exec_pipes),
    /// [`exec_tty`](crate::Controller::exec_tty)) and deliver signals to
    /// the workload ([`signal_entrypoint`](crate::Controller::signal_entrypoint)).
    /// [`Config::apply`] maps the server's vsock port to `path` on the vsock
    /// device it is given. Not available when the workload runs as PID 1.
    pub fn control_socket(mut self, path: &str) -> Self {
        self.control_socket = Some(path.to_string());
        self
    }

    /// Override the guest vsock port of the control server.
    pub fn control_vsock_port(mut self, port: u32) -> Self {
        self.control_vsock_port = port;
        self
    }

    /// Set the root disk to remount on boot.
    pub fn set_root_disk_remount(
        mut self,
        device: &str,
        fstype: Option<&str>,
        options: Option<&str>,
    ) -> Self {
        self.inner
            .process
            .env
            .retain(|e| !e.starts_with("KRUN_BLOCK_ROOT_"));
        self.inner
            .process
            .env
            .push(format!("KRUN_BLOCK_ROOT_DEVICE={device}"));
        if let Some(fs) = fstype {
            self.inner
                .process
                .env
                .push(format!("KRUN_BLOCK_ROOT_FSTYPE={fs}"));
        }
        if let Some(opts) = options {
            self.inner
                .process
                .env
                .push(format!("KRUN_BLOCK_ROOT_OPTIONS={opts}"));
        }
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

        let control = self.control_socket.map(|socket_path| ControlEndpoint {
            socket_path,
            vsock_port: self.control_vsock_port,
        });
        if control.is_some() {
            self.inner.control_server = Some(ControlServerConfig {
                vsock_port: self.control_vsock_port,
            });
        }

        let config_json =
            serde_json::to_vec(&self.inner).expect("ConfigSchema serialization cannot fail");
        Config {
            control,
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

        // NOTE: rlimits are currently injected as env var - see FIXME in build()
        assert_eq!(
            json["process"]["env"],
            serde_json::json!(["HOME=/root", "TERM=xterm-256color", "KRUN_RLIMITS=7=0:0"])
        );
    }

    #[test]
    fn control_server_is_configured_only_with_a_socket() {
        let cfg = Config::builder().args(&["/bin/sh"]).build();
        assert!(parse_config_json(&cfg).get("control_server").is_none());
        assert!(cfg.control.is_none());

        let cfg = Config::builder()
            .args(&["/bin/sh"])
            .control_socket("/run/krun-init.sock")
            .build();
        assert_eq!(
            parse_config_json(&cfg)["control_server"],
            serde_json::json!({"vsock_port": DEFAULT_VSOCK_PORT})
        );
        let control = cfg.control.as_ref().unwrap();
        assert_eq!(control.socket_path, "/run/krun-init.sock");

        let cfg = Config::builder()
            .control_socket("/run/krun-init.sock")
            .control_vsock_port(1024)
            .build();
        assert_eq!(
            parse_config_json(&cfg)["control_server"]["vsock_port"],
            1024
        );
        assert_eq!(cfg.control.as_ref().unwrap().vsock_port, 1024);
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
