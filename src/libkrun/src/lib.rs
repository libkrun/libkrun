#![recursion_limit = "256"]

pub mod api;
pub use api::*;

#[cfg(feature = "ffi")]
ffier::generate_bridge!(
    local = __ffier_krun_metadata,
    schema_output = "../../target/ffier-krun.json"
);

#[allow(dead_code)]
mod builder;

#[cfg(feature = "aws-nitro")]
use std::path::PathBuf;
#[cfg(feature = "aws-nitro")]
#[derive(Default)]
pub struct NitroConfig {
    workdir: Option<String>,
    exec_path: Option<String>,
    env: Option<String>,
    args: Option<String>,
    rlimits: Option<String>,
    console_output: Option<PathBuf>,
    rootfs: Option<String>,
    net_unixfd: Option<std::os::fd::RawFd>,
    debug: bool,
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "feature = \"aws-nitro\""))]
#[cfg_attr(not(feature = "ffi"), cfg(feature = "aws-nitro"))]
impl NitroConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rootfs(mut self, path: &str) -> Self {
        self.rootfs = Some(path.to_string());
        self
    }

    pub fn exec_path(mut self, path: &str) -> Self {
        self.exec_path = Some(path.to_string());
        self
    }

    pub fn args(mut self, args: &str) -> Self {
        self.args = Some(args.to_string());
        self
    }

    pub fn env(mut self, env: &str) -> Self {
        self.env = Some(env.to_string());
        self
    }

    pub fn workdir(mut self, path: &str) -> Self {
        self.workdir = Some(path.to_string());
        self
    }

    pub fn rlimits(mut self, rlimits: &str) -> Self {
        self.rlimits = Some(rlimits.to_string());
        self
    }

    pub fn console_output(mut self, path: &str) -> Self {
        self.console_output = Some(PathBuf::from(path));
        self
    }

    pub fn net_fd(mut self, fd: i32) -> Self {
        self.net_unixfd = if fd >= 0 { Some(fd) } else { None };
        self
    }

    pub fn debug(mut self, enable: bool) -> Self {
        self.debug = enable;
        self
    }
}

#[cfg(feature = "aws-nitro")]
impl NitroConfig {
    pub(crate) fn into_enclave(
        self,
        vcpus: u8,
        mem_size_mib: usize,
    ) -> Result<aws_nitro::enclave::NitroEnclave, String> {
        let rootfs = self.rootfs.ok_or("rootfs not specified")?;
        let exec_path = self.exec_path.ok_or("exec path not specified")?;
        let exec_env = self.env.ok_or("execution env not specified")?;
        let exec_args = self.args.ok_or("execution args not specified")?;
        let output_path = self
            .console_output
            .ok_or("console output path not specified")?;
        Ok(aws_nitro::enclave::NitroEnclave {
            mem_size_mib,
            vcpus,
            rootfs,
            exec_path,
            exec_args,
            exec_env,
            net_unixfd: self.net_unixfd,
            output_path,
            debug: self.debug,
        })
    }
}
