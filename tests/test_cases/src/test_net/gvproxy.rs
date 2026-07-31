//! Gvproxy backend for virtio-net tests.

use super::NetBackend;
use crate::test_net::get_krun_add_net_unixgram;
use crate::{ShouldRun, TestSetup, krun_call, krun_call_u32};
use anyhow::Context;
use krun_sys::{
    COMPAT_NET_FEATURES, KRUN_FEATURE_NET, NET_FLAG_DHCP_CLIENT, NET_FLAG_VFKIT, krun_has_feature,
};
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Read gvproxy binary path from `KRUN_TEST_GVPROXY_PATH` (set by `tests/run.sh`).
/// Returns `None` if the variable is unset or the referenced file doesn't exist.
pub(crate) fn gvproxy_path() -> Option<PathBuf> {
    let path = std::env::var_os("KRUN_TEST_GVPROXY_PATH")?;
    let p = PathBuf::from(path);
    p.exists().then_some(p)
}

pub(crate) struct Gvproxy<'a> {
    vfkit_sock: &'a str,
    log_path: &'a Path,
    net_sock: Option<&'a str>,
    ssh_port: Option<i32>,
}

impl<'a> Gvproxy<'a> {
    pub fn new(vfkit_sock: &'a str, log_path: &'a Path) -> Self {
        Self {
            vfkit_sock,
            log_path,
            net_sock: None,
            ssh_port: None,
        }
    }

    /// Add `--listen unix://<path>` so callers can hit the HTTP API
    /// (e.g. [`setup_gvproxy_port_forward`]).
    pub fn net_sock(&mut self, net_sock: &'a str) -> &mut Self {
        self.net_sock = Some(net_sock);
        self
    }

    /// Add `--ssh-port <n>`. Pass `-1` to disable the default :22 forwarder.
    pub fn ssh_port(&mut self, ssh_port: i32) -> &mut Self {
        self.ssh_port = Some(ssh_port);
        self
    }

    pub fn start(&mut self) -> io::Result<Child> {
        let gvproxy = gvproxy_path().expect("gvproxy not found");
        let log_file = std::fs::File::create(self.log_path)?;

        let mut cmd = Command::new(gvproxy);
        cmd.arg("--listen-vfkit")
            .arg(format!("unixgram:{}", self.vfkit_sock));
        if let Some(net_sock) = self.net_sock {
            cmd.arg("--listen").arg(format!("unix://{}", net_sock));
        }
        if let Some(port) = self.ssh_port {
            cmd.arg("--ssh-port").arg(port.to_string());
        }
        cmd.arg("-debug");

        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log_file)
            .spawn()
    }
}

pub(crate) fn wait_for_socket(path: &Path, timeout_ms: u64) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed().as_millis() < timeout_ms as u128 {
        if path.exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

/// Set up a gvproxy port-forwarding rule via its HTTP API.
///
/// Sends `POST /services/forwarder/expose` with
/// `{"local":":<port>","remote":"<remote_ip>:<port>"}` to the net unix socket.
/// Retries until gvproxy is accepting connections (up to ~10 s).
pub(crate) fn setup_gvproxy_port_forward(
    net_sock_path: &str,
    port: u16,
    remote_ip: Ipv4Addr,
) -> anyhow::Result<()> {
    let mut stream = None;
    for _ in 0..100 {
        match UnixStream::connect(net_sock_path) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    let mut stream = stream
        .ok_or_else(|| anyhow::anyhow!("gvproxy HTTP socket not ready: {}", net_sock_path))?;

    let body = format!(r#"{{"local":":{port}","remote":"{remote_ip}:{port}"}}"#);
    let request = format!(
        "POST /services/forwarder/expose HTTP/1.0\r\nHost: unix\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );

    stream
        .write_all(request.as_bytes())
        .context("write port-forward request")?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .context("read port-forward response")?;

    if !response.contains("200") {
        anyhow::bail!("gvproxy port-forward expose failed: {}", response);
    }

    Ok(())
}

fn gvproxy_should_run() -> ShouldRun {
    if unsafe { krun_call_u32!(krun_has_feature(KRUN_FEATURE_NET.into())) }.ok() != Some(1) {
        return ShouldRun::No("libkrun compiled without NET");
    }
    match gvproxy_path() {
        Some(_) => ShouldRun::Yes,
        None => ShouldRun::No("gvproxy not installed"),
    }
}

fn setup_backend_with_socket(
    ctx: u32,
    test_setup: &TestSetup,
    socket_name: &str,
    log_name: &str,
) -> anyhow::Result<()> {
    let tmp_dir = test_setup
        .tmp_dir
        .canonicalize()
        .unwrap_or_else(|_| test_setup.tmp_dir.clone());
    let socket_path = tmp_dir.join(socket_name);
    let gvproxy_log = tmp_dir.join(log_name);

    let socket_path_str = socket_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("gvproxy socket path is not valid UTF-8"))?;
    let gvproxy_child = Gvproxy::new(socket_path_str, &gvproxy_log).start()?;
    test_setup.register_cleanup_pid(gvproxy_child.id());

    anyhow::ensure!(
        wait_for_socket(&socket_path, 5000),
        "gvproxy failed to create socket"
    );

    let mut mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
    let c_socket_path = CString::new(socket_path_str)?;

    unsafe {
        krun_call!(get_krun_add_net_unixgram()(
            ctx,
            c_socket_path.as_ptr(),
            -1,
            mac.as_mut_ptr(),
            COMPAT_NET_FEATURES,
            NET_FLAG_VFKIT | NET_FLAG_DHCP_CLIENT,
        ))?;
    }
    Ok(())
}

pub(crate) struct GvproxyBackend;

impl NetBackend for GvproxyBackend {
    fn should_run(&self) -> ShouldRun {
        gvproxy_should_run()
    }

    fn setup_backend(&self, ctx: u32, test_setup: &TestSetup) -> anyhow::Result<()> {
        setup_backend_with_socket(ctx, test_setup, "gvproxy.sock", "gvproxy.log")
    }
}

/// Gvproxy variant with a socket path >= 96 bytes, triggering the
/// ENAMETOOLONG bug when the local socket was derived from the peer path.
pub(crate) struct GvproxyLongPath;

impl NetBackend for GvproxyLongPath {
    fn should_run(&self) -> ShouldRun {
        gvproxy_should_run()
    }

    fn setup_backend(&self, ctx: u32, test_setup: &TestSetup) -> anyhow::Result<()> {
        let tmp_dir = test_setup
            .tmp_dir
            .canonicalize()
            .unwrap_or_else(|_| test_setup.tmp_dir.clone());
        let base_len = tmp_dir.to_str().map(|s| s.len()).unwrap_or(0);
        const TARGET_PATH_LEN: usize = 96;
        let prefix = "gvp-";
        let suffix = ".sock";
        let name_needed = TARGET_PATH_LEN.saturating_sub(base_len + 1);
        let pad_len = name_needed
            .saturating_sub(prefix.len() + suffix.len())
            .max(1);
        let socket_name = format!("{}{}{}", prefix, "x".repeat(pad_len), suffix);

        setup_backend_with_socket(ctx, test_setup, &socket_name, "gvproxy-long-path.log")
    }
}
