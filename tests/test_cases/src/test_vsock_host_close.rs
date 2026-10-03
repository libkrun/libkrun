use macros::{guest, host};
use std::io::{Read, Write};
use std::iter;
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub struct TestVsockHostClose;

const VSOCK_PORT: u32 = 1234;
const SMALL_PAYLOAD: usize = 16 * 1024;
const LARGE_PAYLOAD: usize = 4 * 1024 * 1024;
const LARGE_ROUNDS: usize = 32;

fn payload_sizes() -> impl Iterator<Item = usize> {
    iter::once(SMALL_PAYLOAD).chain(iter::repeat_n(LARGE_PAYLOAD, LARGE_ROUNDS))
}

fn stream_set_timeouts(stream: &UnixStream) {
    let timeout = Some(Duration::from_secs(5));
    stream.set_read_timeout(timeout).unwrap();
    stream.set_write_timeout(timeout).unwrap();
}

#[host]
mod host {
    use super::*;

    use anyhow::{bail, ensure};
    use nix::sys::prctl::set_pdeathsig;
    use nix::sys::signal::{Signal, kill};
    use nix::sys::socket::{setsockopt, sockopt::SndBuf};
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    use nix::unistd::{ForkResult, Pid, fork, getpid, getppid};
    use std::io::ErrorKind;
    use std::os::unix::net::UnixListener;
    use std::thread;

    use crate::common::{build_init_config, init_krun, setup_standard_devices};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        krun::require(
            None,
            &[
                krun::Symbol::KrunVsockDeviceNew,
                krun::Symbol::KrunVsockDeviceDestroy,
                krun::Symbol::KrunVsockDeviceAddUnixPort,
            ],
        )
    }

    struct VmProcess(Option<Pid>);

    impl VmProcess {
        fn accept(&mut self, listener: &UnixListener) -> anyhow::Result<UnixStream> {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => return Ok(stream),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
                let status = waitpid(self.0.unwrap(), Some(WaitPidFlag::WNOHANG))?;
                if status != WaitStatus::StillAlive {
                    self.0 = None;
                    bail!("VM exited before completing all transfers: {status:?}");
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for VmProcess {
        fn drop(&mut self) {
            if let Some(pid) = self.0 {
                let _ = kill(pid, Signal::SIGKILL);
                let _ = waitpid(pid, None);
            }
        }
    }

    fn server(listener: UnixListener, pid: Pid) -> anyhow::Result<()> {
        let mut vm = VmProcess(Some(pid));
        listener.set_nonblocking(true)?;
        let payload: Vec<u8> = (0..LARGE_PAYLOAD).map(|i| (i % 251) as u8).collect();
        for size in payload_sizes() {
            let mut stream = vm.accept(&listener)?;
            stream_set_timeouts(&stream);
            let mut ready = [0];
            stream.read_exact(&mut ready)?;
            ensure!(ready == [1], "guest readiness byte missing");

            if size == SMALL_PAYLOAD {
                setsockopt(&stream, SndBuf, &(2 * SMALL_PAYLOAD))?;
                // Stop the muxer as well as the vCPUs so IN and HUP are
                // necessarily pending together when the VM resumes.
                kill(pid, Signal::SIGSTOP)?;
                ensure!(
                    waitpid(pid, Some(WaitPidFlag::WUNTRACED))?
                        == WaitStatus::Stopped(pid, Signal::SIGSTOP),
                    "VM did not stop"
                );
                stream.write_all(&payload[..size])?;
                drop(stream);
                kill(pid, Signal::SIGCONT)?;
            } else {
                stream.write_all(&payload[..size])?;
                drop(stream);
            }
        }
        let status = waitpid(pid, None)?;
        vm.0 = None;
        ensure!(
            status == WaitStatus::Exited(pid, 0),
            "VM exited: {status:?}"
        );
        println!("HOST OK");
        Ok(())
    }

    impl Test for TestVsockHostClose {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            ShouldRun::Yes
        }

        fn timeout_secs(&self) -> u64 {
            30
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _test_setup: TestSetup) -> TestOutcome {
            if stdout == b"OK\nHOST OK\n" {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(format!(
                    "host and guest did not both complete: {}",
                    String::from_utf8_lossy(&stdout)
                ))
            }
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let sock_path = test_setup.tmp_dir.join("test.sock");
            let listener = UnixListener::bind(&sock_path)?;
            let parent = getpid();
            // Fork before libkrun starts any threads; the parent must keep
            // running while the entire VM process is stopped.
            match unsafe { fork()? } {
                ForkResult::Parent { child } => return server(listener, child),
                ForkResult::Child => {
                    set_pdeathsig(Signal::SIGKILL)?;
                    ensure!(getppid() == parent, "test supervisor exited");
                    drop(listener);
                }
            }

            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();

            let init_config = build_init_config(&test_setup.test_case, &[]);
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let stderr = std::io::stderr();
            let (mut devices, payload) =
                setup_standard_devices(&test_setup, &init_config, &stdin, &stdout, &stderr)?;
            let mut vsock = krun::VsockDevice::new(3, krun::TsiFlags::empty())
                .map_err(|e| anyhow::anyhow!("VsockDevice: {e:?}"))?;
            vsock.add_unix_port(VSOCK_PORT, sock_path.to_str().unwrap(), false);
            devices.add(vsock);

            let vmm = krun::VmmBuilder::new()
                .vcpus(1)
                .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
                .ram_mib(256)
                .map_err(|e| anyhow::anyhow!("ram_mib: {e:?}"))?
                .payload(payload)
                .devices(devices)
                .build()
                .map_err(|e| anyhow::anyhow!("build: {e:?}"))?;

            vmm.run();
            unreachable!()
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;

    use nix::libc::VMADDR_CID_HOST;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, VsockAddr, connect, socket};
    use std::os::fd::AsRawFd;
    use std::thread;

    impl Test for TestVsockHostClose {
        fn in_guest(self: Box<Self>) {
            for size in payload_sizes() {
                let sock = socket(
                    AddressFamily::Vsock,
                    SockType::Stream,
                    SockFlag::empty(),
                    None,
                )
                .unwrap();
                connect(
                    sock.as_raw_fd(),
                    &VsockAddr::new(VMADDR_CID_HOST, VSOCK_PORT),
                )
                .unwrap();
                let mut stream = UnixStream::from(sock);
                stream_set_timeouts(&stream);
                stream.write_all(&[1]).unwrap();
                if size == LARGE_PAYLOAD {
                    // Exhaust receive credit before reading to exercise
                    // resumption as well as draining across RX buffers.
                    thread::sleep(Duration::from_millis(20));
                }

                let mut payload = vec![0; size];
                stream.read_exact(&mut payload).unwrap();
                assert!(
                    payload
                        .iter()
                        .enumerate()
                        .all(|(i, &b)| b == (i % 251) as u8)
                );
                assert_eq!(stream.read(&mut [0]).unwrap(), 0);
            }
            println!("OK");
        }
    }
}
