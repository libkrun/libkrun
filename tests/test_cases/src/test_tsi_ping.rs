use macros::{guest, host};

#[derive(Clone, Copy)]
pub enum IpVersion {
    V4,
    V6,
}

pub struct TestTsiPing {
    version: IpVersion,
}

impl TestTsiPing {
    pub fn v4() -> Self {
        Self {
            version: IpVersion::V4,
        }
    }

    pub fn v6() -> Self {
        Self {
            version: IpVersion::V6,
        }
    }
}

#[host]
mod host {
    use super::*;
    use crate::common::setup_fs_and_enter_with_env;
    use crate::{Test, TestOutcome, TestSetup};
    use crate::{krun_call, krun_call_u32};
    use krun_sys::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::unix::io::AsRawFd;
    use std::process::Command;

    const CONTAINERFILE: &str = "\
FROM fedora:latest
RUN dnf install -y iputils && dnf clean all
";

    /// 1-second timeout for host-side `ping -W`: macOS wants milliseconds, Linux wants seconds.
    const PING_W_TIMEOUT: &str = if cfg!(target_os = "macos") {
        "1000"
    } else {
        "1"
    };

    fn find_pingable_ipv4() -> Option<Ipv4Addr> {
        // Use `ip` on Linux, `ifconfig` on macOS to find non-loopback IPv4 addresses.
        let text = if cfg!(target_os = "linux") {
            let output = Command::new("ip")
                .args(["-4", "-o", "addr", "show", "scope", "global"])
                .output()
                .ok()?;
            String::from_utf8(output.stdout).ok()?
        } else {
            let output = Command::new("ifconfig").output().ok()?;
            String::from_utf8(output.stdout).ok()?
        };

        for line in text.lines() {
            let mut tokens = line.split_whitespace();
            while let Some(token) = tokens.next() {
                if token == "inet" {
                    if let Some(addr_token) = tokens.next() {
                        let addr_str = addr_token.split('/').next().unwrap_or(addr_token);
                        if let Ok(addr) = addr_str.parse::<Ipv4Addr>()
                            && !addr.is_loopback()
                            && !addr.is_unspecified()
                        {
                            let status = Command::new("ping")
                                .args(["-c", "1", "-W", PING_W_TIMEOUT, addr_str])
                                .output()
                                .ok()?
                                .status;
                            if status.success() {
                                return Some(addr);
                            }
                        }
                    }
                    break;
                }
            }
        }
        None
    }

    fn find_pingable_ipv6() -> Option<Ipv6Addr> {
        // Use `ip` on Linux, `ifconfig` on macOS to find global IPv6 addresses.
        let text = if cfg!(target_os = "linux") {
            let output = Command::new("ip")
                .args(["-6", "-o", "addr", "show", "scope", "global"])
                .output()
                .ok()?;
            String::from_utf8(output.stdout).ok()?
        } else {
            let output = Command::new("ifconfig").output().ok()?;
            String::from_utf8(output.stdout).ok()?
        };

        for line in text.lines() {
            let mut tokens = line.split_whitespace();
            while let Some(token) = tokens.next() {
                if token == "inet6" {
                    if let Some(addr_token) = tokens.next() {
                        // Strip prefix length (e.g. /64, /128) and scope id (e.g. %en0)
                        let addr_str = addr_token.split('/').next().unwrap_or(addr_token);
                        let addr_str = addr_str.split('%').next().unwrap_or(addr_str);
                        if let Ok(addr) = addr_str.parse::<Ipv6Addr>()
                            && !addr.is_loopback()
                            && !addr.is_unspecified()
                            && !addr.is_unicast_link_local()
                        {
                            // macOS uses `ping6`, Linux uses `ping -6`.
                            // macOS ping6 has no -W flag.
                            let status = if cfg!(target_os = "macos") {
                                Command::new("ping6").args(["-c", "1", addr_str]).output()
                            } else {
                                Command::new("ping")
                                    .args(["-6", "-c", "1", "-W", PING_W_TIMEOUT, addr_str])
                                    .output()
                            }
                            .ok()?
                            .status;
                            if status.success() {
                                return Some(addr);
                            }
                        }
                    }
                    break;
                }
            }
        }
        None
    }

    impl Test for TestTsiPing {
        fn rootfs_image(&self) -> Option<&'static str> {
            Some(CONTAINERFILE)
        }

        fn timeout_secs(&self) -> u64 {
            10
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let (env_name, target_str) = match self.version {
                IpVersion::V4 => {
                    let addr = if let Ok(target) = std::env::var("PING_TARGET") {
                        target
                    } else if let Some(a) = find_pingable_ipv4() {
                        a.to_string()
                    } else {
                        println!("SKIP:no pingable IPv4 address found on host");
                        return Ok(());
                    };
                    ("PING_TARGET", addr)
                }
                IpVersion::V6 => {
                    let addr = if let Ok(target) = std::env::var("PING6_TARGET") {
                        target
                    } else if let Some(a) = find_pingable_ipv6() {
                        a.to_string()
                    } else {
                        println!("SKIP:no pingable IPv6 address found on host");
                        return Ok(());
                    };
                    ("PING6_TARGET", addr)
                }
            };

            let env_val = format!("{env_name}={target_str}");
            unsafe {
                krun_call!(krun_init_log(
                    KRUN_LOG_TARGET_DEFAULT,
                    KRUN_LOG_LEVEL_TRACE,
                    KRUN_LOG_STYLE_AUTO,
                    0
                ))?;
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_add_vsock(ctx, KRUN_TSI_HIJACK_INET))?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                krun_call!(krun_add_virtio_console_default(
                    ctx,
                    std::io::stdin().as_raw_fd(),
                    std::io::stdout().as_raw_fd(),
                    std::io::stderr().as_raw_fd(),
                ))?;
                setup_fs_and_enter_with_env(ctx, test_setup, &[env_val.as_str()])?;
            }
            Ok(())
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            let output = String::from_utf8(stdout).unwrap_or_default();
            if let Some(reason) = output.strip_prefix("SKIP:") {
                let reason = Box::leak(reason.trim().to_string().into_boxed_str());
                TestOutcome::Skip(reason)
            } else if output == "OK\n" {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(format!("expected {:?}, got {:?}", "OK\n", output))
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use std::process::Command;

    impl Test for TestTsiPing {
        fn in_guest(self: Box<Self>) {
            let (env_var, v6_flag) = match self.version {
                IpVersion::V4 => ("PING_TARGET", None),
                IpVersion::V6 => ("PING6_TARGET", Some("-6")),
            };
            let target = std::env::var(env_var).unwrap_or_else(|_| panic!("{env_var} not set"));

            let mut args = Vec::new();
            if let Some(flag) = v6_flag {
                args.push(flag);
            }
            // Uses -w (deadline): ping exits with code 1 if fewer than 3
            // replies arrive within 5 seconds, ensuring all pings succeed.
            args.extend(["-c", "3", "-w", "5", &target]);

            let output = Command::new("/usr/bin/ping")
                .args(&args)
                .output()
                .expect("Failed to run ping");

            if output.status.success() {
                println!("OK");
            } else {
                let stderr = String::from_utf8(output.stderr).unwrap();
                let stdout = String::from_utf8(output.stdout).unwrap();
                panic!(
                    "ping {target} failed (exit={}):\nstdout: {stdout}\nstderr: {stderr}",
                    output.status,
                );
            }
        }
    }
}
