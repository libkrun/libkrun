use crate::{ShouldRun, TestSetup};
use anyhow::{Context, bail};
use nix::libc;
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(feature = "dynamic-linking")]
fn require_symbols() -> Result<(), libloading::Error> {
    krun::require(
        None,
        &[
            krun::Symbol::KrunNetDeviceNewVhostUserPath,
            krun::Symbol::KrunNetDeviceNewVhostUserFd,
        ],
    )
}

pub(crate) fn should_run() -> ShouldRun {
    if !cfg!(target_os = "linux") {
        return ShouldRun::No("vhost-user net requires Linux");
    }
    #[cfg(feature = "dynamic-linking")]
    if require_symbols().is_err() {
        return ShouldRun::No("vhost-user net is unavailable in this libkrun build");
    }
    if matches!(
        krun::NetDevice::new_vhost_user_path("net0", "", &[2; 6]),
        Err(krun::VmmError::FeatureDisabled(..))
    ) {
        return ShouldRun::No("vhost-user net is disabled in this libkrun build");
    }
    match Command::new("passt").arg("--help").output() {
        Ok(output)
            if (String::from_utf8_lossy(&output.stderr).contains("--vhost-user")
                || String::from_utf8_lossy(&output.stdout).contains("--vhost-user")) =>
        {
            ShouldRun::Yes
        }
        _ => ShouldRun::No("passt with vhost-user support not installed"),
    }
}

fn command() -> Command {
    let mut command = Command::new("passt");
    command
        .args([
            "-f",
            "--vhost-user",
            "-4",
            "--address",
            "169.254.2.15",
            "--netmask",
            "255.255.0.0",
            "--gateway",
            "169.254.2.2",
            "--map-host-loopback",
            "169.254.2.2",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    command
}

pub(crate) fn setup_fd(test_setup: &TestSetup) -> anyhow::Result<krun::NetDevice> {
    #[cfg(feature = "dynamic-linking")]
    require_symbols().context("load vhost-user net symbols")?;

    let (frontend, backend) = UnixStream::pair()?;
    let backend_fd = backend.as_raw_fd();
    let mut command = command();
    command.args(["--fd", &backend_fd.to_string()]);
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(backend_fd, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().context("start passt --vhost-user")?;
    test_setup.register_cleanup_pid(child.id());
    drop(backend);
    let mac = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
    krun::NetDevice::new_vhost_user_fd("net0", frontend.as_fd(), &mac)
        .map_err(|e| anyhow::anyhow!("NetDevice: {e:?}"))
}

pub(crate) fn setup_path(test_setup: &TestSetup) -> anyhow::Result<krun::NetDevice> {
    #[cfg(feature = "dynamic-linking")]
    require_symbols().context("load vhost-user net symbols")?;

    let path = test_setup.tmp_dir.join("passt.socket");
    let mut child = command()
        .arg("--one-off")
        .arg("--socket")
        .arg(&path)
        .spawn()
        .context("start passt --vhost-user")?;
    test_setup.register_cleanup_pid(child.id());
    let deadline = Instant::now() + Duration::from_secs(5);
    let path = path.to_str().context("socket path is not UTF-8")?;
    let mac = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
    loop {
        match krun::NetDevice::new_vhost_user_path("net0", path, &mac) {
            Ok(device) => return Ok(device),
            Err(error) => {
                if let Some(status) = child.try_wait()? {
                    bail!("passt exited before listening: {status}: {error:?}");
                }
                if Instant::now() >= deadline {
                    bail!("timed out waiting for passt socket: {error:?}");
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
}
