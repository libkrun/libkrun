// SPDX-License-Identifier: Apache-2.0
//
//! Init configuration builder and applicator.
//!
//! A [`Builder`] can be constructed from scratch or from an OCI runtime-spec
//! config.json via [`Builder::from_oci_json`]. The internal serialization
//! format is an implementation detail — callers should not rely on it.

use std::borrow::Cow;

#[cfg(unix)]
use crate::init_schema::ControlServerConfig;
use crate::init_schema::{ConfigSchema, Mount};
use crate::oci_schema::OciSchema;
#[cfg(feature = "ffi")]
use crate::{FfiBorrow, FfiType};
#[cfg(unix)]
use krun_init_common::control::DEFAULT_VSOCK_PORT;

#[cfg(feature = "krun")]
pub type VmmError = krun::VmmError;

#[cfg(feature = "ffi")]
pub type VmmError = libkrun_via_libc::VmmError;

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
#[cfg(any(feature = "krun", feature = "ffi"))]
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
    #[cfg(unix)]
    #[error("the control socket needs a vsock device, use apply_with_vsock")]
    #[cfg_attr(feature = "ffi", ffier(code = 3))]
    ControlSocketWithoutVsock(),
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

/// Host endpoint of the guest control server.
#[cfg(unix)]
pub(crate) struct ControlEndpoint {
    pub socket_path: String,
    pub vsock_port: u32,
}

/// Built init configuration. Immutable after construction.
///
/// Holds the init binary and serialized config JSON as guest files.
/// The caller **must keep this value alive for the entire lifetime of the VM**.
pub struct Config {
    files: Vec<GuestFile>,
    #[cfg(unix)]
    control: Option<ControlEndpoint>,
}

#[cfg(feature = "ffi")]
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
    /// On Unix, a configured control socket needs a vsock device; use
    /// `apply_with_vsock` in that case.
    ///
    /// The caller must keep this `Config` (or `KrunInitConfig`) alive for the
    /// entire lifetime of the VM; `apply` borrows data pointers that remain
    /// referenced until the VM exits.
    pub fn apply<'a>(
        &'a self,
        #[ffier(foreign = ::libkrun_via_libc, c_name = "KrunFsOverlay")]
        overlay: &mut libkrun_via_libc::FsOverlay<'a>,
        #[ffier(foreign = ::libkrun_via_libc, c_name = "KrunPayload")]
        payload: &mut libkrun_via_libc::Payload,
    ) -> Result<(), ApplyError> {
        #[cfg(unix)]
        if self.control.is_some() {
            return Err(ApplyError::ControlSocketWithoutVsock());
        }
        self.apply_files(overlay, payload)
    }

    /// Like [`apply`](Self::apply), and also map the control server's vsock
    /// port to the configured control socket on `vsock`.
    #[cfg(unix)]
    pub fn apply_with_vsock<'a>(
        &'a self,
        #[ffier(foreign = ::libkrun_via_libc, c_name = "KrunFsOverlay")]
        overlay: &mut libkrun_via_libc::FsOverlay<'a>,
        #[ffier(foreign = ::libkrun_via_libc, c_name = "KrunPayload")]
        payload: &mut libkrun_via_libc::Payload,
        #[ffier(foreign = ::libkrun_via_libc, c_name = "KrunVsockDevice")]
        vsock: &mut libkrun_via_libc::VsockDevice,
    ) -> Result<(), ApplyError> {
        if let Some(control) = &self.control {
            libkrun_via_libc::ffi::require(&[
                libkrun_via_libc::ffi::Symbol::KrunVsockDeviceAddUnixPort,
            ])
            .map_err(|e| ApplyError::SymbolNotFound(e.to_string().into()))?;
            vsock.add_unix_port(control.vsock_port, &control.socket_path, true);
        }
        self.apply_files(overlay, payload)
    }
}

#[cfg(feature = "ffi")]
impl Config {
    fn apply_files<'a>(
        &'a self,
        overlay: &mut libkrun_via_libc::FsOverlay<'a>,
        payload: &mut libkrun_via_libc::Payload,
    ) -> Result<(), ApplyError> {
        libkrun_via_libc::ffi::require(&[
            libkrun_via_libc::ffi::Symbol::KrunFsOverlayAddFile,
            libkrun_via_libc::ffi::Symbol::KrunPayloadAppendCmdline,
        ])
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

#[cfg(all(not(feature = "ffi"), feature = "krun"))]
impl Config {
    /// Start building a new init configuration.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Apply this init configuration using statically-linked libkrun types.
    ///
    /// The caller must keep this `Config` alive for the entire lifetime of the VM.
    pub fn apply<'a>(
        &'a self,
        overlay: &mut krun::FsOverlay<'a>,
        payload: &mut krun::Payload,
    ) -> Result<(), ApplyError> {
        #[cfg(unix)]
        if self.control.is_some() {
            return Err(ApplyError::ControlSocketWithoutVsock());
        }
        self.apply_files(overlay, payload)
    }

    /// Like [`apply`](Self::apply), and also map the control server's vsock
    /// port to the configured control socket on `vsock`.
    #[cfg(unix)]
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
#[cfg_attr(not(unix), derive(Default))]
pub struct Builder {
    inner: ConfigSchema,
    rlimits: Vec<String>,
    #[cfg(unix)]
    control_socket: Option<String>,
    #[cfg(unix)]
    control_vsock_port: u32,
}

#[cfg(unix)]
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
        self.inner.dhcp = enable.then_some(true);
        self
    }

    /// Keep the guest's DHCP lease renewed, retrying lost requests, instead of
    /// configuring the interface once. Intended for guests on a physical
    /// network; requires the DHCP client to be enabled.
    pub fn dhcp_renew(mut self, enable: bool) -> Self {
        self.inner.dhcp_renew = enable.then_some(true);
        self
    }

    /// Run a control server in the guest and expose it to the host as the
    /// Unix socket `path`.
    ///
    /// The server lets the host start additional processes in the running
    /// VM ([`Controller::exec_pipes`](crate::Controller::exec_pipes),
    /// [`exec_tty`](crate::Controller::exec_tty)) and deliver signals to
    /// the workload ([`signal_entrypoint`](crate::Controller::signal_entrypoint)).
    /// [`Config::apply_with_vsock`] maps the server's vsock port to `path` on
    /// the vsock device it is given. Not available when the workload runs as PID 1.
    #[cfg(unix)]
    pub fn control_socket(mut self, path: &str) -> Self {
        self.control_socket = Some(path.to_string());
        self
    }

    /// Override the guest vsock port of the control server.
    #[cfg(unix)]
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

        #[cfg(unix)]
        let control = self.control_socket.map(|socket_path| ControlEndpoint {
            socket_path,
            vsock_port: self.control_vsock_port,
        });
        #[cfg(unix)]
        if control.is_some() {
            self.inner.control_server = Some(ControlServerConfig {
                vsock_port: self.control_vsock_port,
            });
        }

        let config_json =
            serde_json::to_vec(&self.inner).expect("ConfigSchema serialization cannot fail");
        Config {
            #[cfg(unix)]
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
    #[cfg(unix)]
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

    #[test]
    fn dhcp_flags_are_serialized() {
        let json = parse_config_json(&Config::builder().dhcp(true).dhcp_renew(true).build());
        assert_eq!(json["dhcp"], serde_json::json!(true));
        assert_eq!(json["dhcp_renew"], serde_json::json!(true));

        // Disabled flags are omitted entirely.
        let json = parse_config_json(&Config::builder().dhcp(false).build());
        assert!(json.get("dhcp").is_none());
        assert!(json.get("dhcp_renew").is_none());
    }
}
