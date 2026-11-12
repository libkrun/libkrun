use macros::{guest, host};

pub struct TestTsiControlProtocol {
    pub faults: bool,
}

#[host]
mod host {
    use super::*;
    use crate::common::{build_init_config, setup_standard_devices};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};
    #[cfg(feature = "dynamic-linking")]
    use krun::{DeviceManager, ffi::Symbol};
    use std::{env, io};

    impl Test for TestTsiControlProtocol {
        fn should_run(&self) -> ShouldRun {
            if self.faults && env::var_os("KRUN_TEST_TSI_FAULTS").is_none() {
                ShouldRun::No("requires tsi-fault-injection build and KRUN_TEST_TSI_FAULTS=1")
            } else {
                ShouldRun::Yes
            }
        }

        fn timeout_secs(&self) -> u64 {
            150
        }

        fn start_vm(self: Box<Self>, setup: TestSetup) -> anyhow::Result<()> {
            #[cfg(feature = "dynamic-linking")]
            anyhow::ensure!(
                [Symbol::KrunVsockDeviceNew, Symbol::KrunVsockDeviceDestroy]
                    .into_iter()
                    .all(|symbol| symbol.is_available()),
                "required TSI symbols unavailable"
            );
            let platform = if cfg!(target_os = "macos") {
                "TSI_HOST_MACOS=1"
            } else {
                "TSI_HOST_MACOS=0"
            };
            let config = build_init_config(&setup.test_case, &[platform]);
            let (stdin, stdout, stderr) = (io::stdin(), io::stdout(), io::stderr());
            let (mut devices, payload) =
                setup_standard_devices(&setup, &config, &stdin, &stdout, &stderr)?;
            let mut flags = krun::TsiFlags::HIJACK_INET;
            if cfg!(target_os = "linux") {
                flags |= krun::TsiFlags::HIJACK_UNIX;
            }
            if env::var_os("KRUN_TEST_TSI_TCP_PUBLICATION_STRICT").is_some() {
                flags |= krun::TsiFlags::FAIL_ON_TCP_PUBLICATION_ERROR;
            }
            devices
                .add(krun::VsockDevice::new(3, flags).map_err(|e| anyhow::anyhow!("vsock: {e}"))?);
            let vmm = krun::VmmBuilder::new()
                .vcpus(2)
                .map_err(|e| anyhow::anyhow!("vcpus: {e}"))?
                .ram_mib(256)
                .map_err(|e| anyhow::anyhow!("memory: {e}"))?
                .payload(payload)
                .devices(devices)
                .build()
                .map_err(|e| anyhow::anyhow!("VM: {e}"))?;
            vmm.run();
            unreachable!()
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _setup: TestSetup) -> TestOutcome {
            let output = String::from_utf8_lossy(&stdout);
            if output.lines().last() == Some("TSI_CONTROL_PROTOCOL_OK") {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(format!("control protocol failed: {output}"))
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use nix::libc;
    use nix::sys::socket::{
        AddressFamily, MsgFlags, SockFlag, SockType, SockaddrIn, VsockAddr, bind, recvfrom, sendto,
        setsockopt, socket, sockopt,
    };
    use nix::sys::time::{TimeVal, TimeValLike};
    use std::array;
    use std::env;
    use std::fs;
    use std::io;
    use std::mem::zeroed;
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::ptr;
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    const PROXY: u32 = 620;
    const DIAGNOSTIC: u32 = 0x5453_4946;

    struct Control {
        socket: OwnedFd,
        id: u64,
    }

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn word(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    }

    impl Control {
        fn new() -> Self {
            let socket = socket(
                AddressFamily::Vsock,
                SockType::Datagram,
                SockFlag::SOCK_CLOEXEC,
                None,
            )
            .unwrap();
            setsockopt(&socket, sockopt::ReceiveTimeout, &TimeVal::seconds(3)).unwrap();
            Self {
                socket,
                id: 0x7473_6900_0000_0000,
            }
        }

        fn send(&self, operation: u32, packet: &[u8]) {
            assert_eq!(
                sendto(
                    self.socket.as_raw_fd(),
                    packet,
                    &VsockAddr::new(2, operation),
                    MsgFlags::empty()
                )
                .unwrap(),
                packet.len()
            );
        }

        fn receive(&self, operation: u32) -> Vec<u8> {
            let mut data = [0; 512];
            let (count, source) =
                recvfrom::<VsockAddr>(self.socket.as_raw_fd(), &mut data).unwrap();
            let source = source.unwrap();
            assert_eq!(source.cid(), 2);
            assert_eq!(source.port(), operation);
            data[..count].to_vec()
        }

        fn packet(&mut self, operation: u32, body: &[u8], flags: u32) -> Vec<u8> {
            self.id += 1;
            let mut packet = words(&[4, operation]);
            packet.extend_from_slice(&self.id.to_le_bytes());
            packet.extend(words(&[body.len() as u32, flags]));
            packet.extend_from_slice(body);
            packet
        }

        fn exchange_packet(&self, operation: u32, packet: &[u8]) -> Vec<u8> {
            self.send(operation, packet);
            let reply = self.receive(operation);
            assert!(reply.len() >= 28);
            assert_eq!(word(&reply), 4);
            assert_eq!(word(&reply[4..]), operation);
            assert_eq!(&reply[8..16], &packet[8..16]);
            assert_eq!(word(&reply[20..]), 1);
            assert_eq!(word(&reply[16..]) as usize, reply.len() - 24);
            reply[24..].to_vec()
        }

        fn exchange(&mut self, operation: u32, body: &[u8]) -> Vec<u8> {
            let packet = self.packet(operation, body, 0);
            self.exchange_packet(operation, &packet)
        }

        fn release(&mut self, data_port: u32) {
            let packet = self.packet(1031, &words(&[data_port, PROXY]), 2);
            self.send(1031, &packet);
        }

        fn diagnostic(&self, operation: u32, fault: u32) -> [u32; 5] {
            self.send(DIAGNOSTIC, &words(&[1, operation, fault, 0]));
            let data = self.receive(DIAGNOSTIC);
            assert_eq!(data.len(), 20, "diagnostic endpoint must be active");
            let values: [u32; 5] = array::from_fn(|index| word(&data[index * 4..]));
            assert_eq!(&values[..2], &[1, 0]);
            values
        }
    }

    fn create_body(port: u32, family: u16, kind: u16, protocol: u32) -> Vec<u8> {
        let mut body = port.to_le_bytes().to_vec();
        body.extend_from_slice(&family.to_le_bytes());
        body.extend_from_slice(&kind.to_le_bytes());
        body.extend_from_slice(&protocol.to_le_bytes());
        body
    }

    fn wire_contract() {
        let mut control = Control::new();
        if env::var("TSI_HOST_MACOS").unwrap() == "1" {
            for kind in [1, 2] {
                assert_eq!(
                    word(&control.exchange(1024, &create_body(0xf000_0001, 1, kind, 0))) as i32,
                    -libc::EPERM
                );
            }
        }
        for (family, kind, protocol, expected) in [
            (99, 2, 0, -97),
            (2, 3, 0, -94),
            (2, 2, 132, -93),
            (2, 1, 17, -93),
            (10, 2, 1, -93),
            (2, 2, 58, -93),
        ] {
            let reply = control.exchange(1024, &create_body(0xf000_0001, family, kind, protocol));
            assert_eq!(word(&reply) as i32, expected);
        }
        let body = create_body(0xf000_0001, 2, 2, 17);
        for mutation in 0..6 {
            let mut packet = control.packet(1024, &body, 0);
            match mutation {
                0 => packet[..4].copy_from_slice(&3u32.to_le_bytes()),
                1 => packet[4..8].copy_from_slice(&1036u32.to_le_bytes()),
                2 => packet[16..20].copy_from_slice(&13u32.to_le_bytes()),
                3 => packet[20..24].copy_from_slice(&1u32.to_le_bytes()),
                4 => {
                    packet.pop();
                }
                5 => packet.push(0),
                _ => unreachable!(),
            }
            let reply = control.exchange_packet(1024, &packet);
            assert_eq!(word(&reply) as i32, if mutation == 0 { -93 } else { -71 });
        }
        for index in 0..32 {
            let port = 0xf000_0010 + index;
            let family = if index % 2 == 0 { 2u16 } else { 10 };
            let body = create_body(port, family, 2, 17);
            assert_eq!(word(&control.exchange(1024, &body)), 0);
            assert_eq!(word(&control.exchange(1024, &body)) as i32, -98);
            if index == 0 {
                let data = socket(
                    AddressFamily::Vsock,
                    SockType::Datagram,
                    SockFlag::SOCK_CLOEXEC,
                    None,
                )
                .unwrap();
                bind(
                    data.as_raw_fd(),
                    &VsockAddr::new(libc::VMADDR_CID_ANY, port),
                )
                .unwrap();
                let mut frame = vec![0u8; 169];
                frame[..12].copy_from_slice(&words(&[4, 28, 1]));
                frame[16..18].copy_from_slice(&10u16.to_le_bytes());
                frame[18..20].copy_from_slice(&9u16.to_be_bytes());
                frame[39] = 1;
                sendto(
                    data.as_raw_fd(),
                    &frame,
                    &VsockAddr::new(2, 1032),
                    MsgFlags::empty(),
                )
                .unwrap();
                assert_eq!(
                    control.exchange(1035, &words(&[port, PROXY, 1, 4])),
                    words(&[0, 97])
                );
                assert_eq!(
                    control.exchange(1035, &words(&[port, PROXY, 1, 4])),
                    words(&[0, 0])
                );
                frame[12..16].copy_from_slice(&8u32.to_le_bytes());
                sendto(
                    data.as_raw_fd(),
                    &frame,
                    &VsockAddr::new(2, 1032),
                    MsgFlags::empty(),
                )
                .unwrap();
                assert_eq!(
                    control.exchange(1035, &words(&[port, PROXY, 1, 4])),
                    words(&[0, 0])
                );
            }
            assert_eq!(
                word(&control.exchange(1034, &words(&[port, PROXY, 1, 2, 1]))),
                0
            );
            let reply = control.exchange(1035, &words(&[port, PROXY, 1, 2]));
            assert_eq!(&reply, &words(&[0, 1]));
            assert_eq!(
                word(&control.exchange(1035, &words(&[port, PROXY, 1, 0xffff]))) as i32,
                -92
            );
            let len = if family == 2 { 16 } else { 28 };
            let mut bind = words(&[port, len]);
            let mut address = [0u8; 128];
            address[..2].copy_from_slice(&family.to_le_bytes());
            bind.extend_from_slice(&address);
            assert_eq!(word(&control.exchange(1036, &bind)), 0);
            let reply = control.exchange(1026, &words(&[port, PROXY, 0]));
            assert_eq!(word(&reply), 0);
            assert_eq!(word(&reply[4..]), len);
            assert_eq!(&reply[8..10], &family.to_le_bytes());
            assert_ne!(&reply[10..12], &[0, 0]);
            assert!(reply[8 + len as usize..].iter().all(|b| *b == 0));
            control.release(port);
            let reply = control.exchange(1026, &words(&[port, PROXY, 0]));
            assert_eq!(word(&reply) as i32, -22);
            assert!(reply[4..].iter().all(|b| *b == 0));
        }
        println!(
            "PASS control envelope/version/length/flags, protocol errors, IDs/sources, duplicate create, bind/name/options and 32 releases"
        );
    }

    fn active_udp() -> UdpSocket {
        let fd = unsafe { libc::socket(46, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        assert!(
            fd >= 0,
            "explicit TSI socket: {}",
            io::Error::last_os_error()
        );
        let socket = unsafe { UdpSocket::from_raw_fd(fd) };
        socket.connect("127.0.0.1:9").unwrap();
        assert_eq!(socket.peer_addr().unwrap().to_string(), "127.0.0.1:9");
        socket
    }

    extern "C" fn signal_handler(_: libc::c_int) {}

    fn read_metadata(socket: &UdpSocket, operation: u32) -> io::Result<()> {
        if operation == 1026 {
            let peer = socket.peer_addr()?;
            assert_eq!(peer.to_string(), "127.0.0.1:9");
        } else {
            assert!(socket.take_error()?.is_none());
        }
        Ok(())
    }

    fn fault_contract(operation: u32) {
        let control = Control::new();
        let baseline = control.diagnostic(0, 0)[4];
        let socket = Arc::new(active_udp());
        let mut faults: Vec<_> = (1..=14).collect();
        if operation == 1026 {
            faults.extend([18, 19]);
        }
        for fault in faults {
            control.diagnostic(operation, fault);
            let reply = read_metadata(&socket, operation);
            if matches!(fault, 11..=14) {
                reply.unwrap();
            } else {
                let error = reply.unwrap_err().raw_os_error().unwrap();
                assert!(
                    error == libc::EPROTO
                        || (fault == 1 && error == libc::EPROTONOSUPPORT)
                        || (fault == 18 && error == libc::EINVAL)
                        || (fault == 19 && matches!(error, libc::EINVAL | libc::EAFNOSUPPORT)),
                    "fault={fault} errno={error}"
                );
            }
            read_metadata(&socket, operation).unwrap();
            let counters = control.diagnostic(0, 0);
            assert_eq!(counters[3], 1, "fault={fault} must be injected");
        }
        for fault in [15, 20, 21, 22] {
            control.diagnostic(operation, fault);
            let started = Instant::now();
            assert_eq!(
                read_metadata(&socket, operation)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::ETIMEDOUT)
            );
            assert!((Duration::from_secs(4)..Duration::from_secs(8)).contains(&started.elapsed()));
            read_metadata(&socket, operation).unwrap();
        }
        for _ in 0..64 {
            let old = active_udp();
            control.diagnostic(operation, 16);
            let (tx, rx) = mpsc::channel();
            let thread = thread::spawn(move || {
                let result = read_metadata(&old, operation);
                tx.send((old, result)).unwrap();
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            while control.diagnostic(0, 0)[3] == 0 {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(1));
            }
            control.diagnostic(0, 24);
            let (old, result) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(matches!(
                result.unwrap_err().raw_os_error(),
                Some(libc::EPROTO | libc::EPROTONOSUPPORT)
            ));
            thread.join().unwrap();
            drop(old);
            let replacement = active_udp();
            read_metadata(&replacement, operation).unwrap();
            assert_eq!(control.diagnostic(0, 0)[3], 3);
            drop(replacement);
            assert_eq!(control.diagnostic(0, 0)[4], baseline + 1);
        }
        let old_action = unsafe {
            let mut action: libc::sigaction = zeroed();
            let mut previous: libc::sigaction = zeroed();
            action.sa_sigaction = signal_handler as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGUSR1, &action, &mut previous), 0);
            previous
        };
        control.diagnostic(operation, 16);
        let (ready_tx, ready_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let worker = socket.clone();
        let thread = thread::spawn(move || {
            ready_tx
                .send(unsafe { libc::pthread_self() } as usize)
                .unwrap();
            result_tx.send(read_metadata(&worker, operation)).unwrap();
        });
        let id = ready_rx.recv().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while control.diagnostic(0, 0)[3] == 0 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            unsafe { libc::pthread_kill(id as libc::pthread_t, libc::SIGUSR1) },
            0
        );
        thread::sleep(Duration::from_millis(100));
        assert!(matches!(
            result_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        control.diagnostic(0, 23);
        result_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        thread.join().unwrap();
        unsafe {
            assert_eq!(
                libc::sigaction(libc::SIGUSR1, &old_action, ptr::null_mut()),
                0
            )
        };
        control.diagnostic(operation, 16);
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let _socket = active_udp();
            let _result = read_metadata(&_socket, operation);
            unsafe { libc::_exit(77) };
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while control.diagnostic(0, 0)[3] == 0 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(unsafe { libc::kill(child, libc::SIGKILL) }, 0);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
        control.diagnostic(operation, 14);
        assert_eq!(control.diagnostic(0, 0)[4], baseline + 1);
        drop(socket);
        assert_eq!(control.diagnostic(0, 0)[4], baseline);
        control.diagnostic(1024, 1);
        let fd = unsafe { libc::socket(46, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);
        let poisoned = unsafe { UdpSocket::from_raw_fd(fd) };
        assert!(poisoned.connect("127.0.0.1:9").is_err());
        assert_eq!(
            poisoned.connect("127.0.0.1:9").unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        drop(poisoned);
        assert_eq!(control.diagnostic(0, 0)[4], baseline);
        let poisoned = active_udp();
        control.diagnostic(1034, 1);
        assert!(poisoned.set_broadcast(true).is_err());
        assert_eq!(
            poisoned.set_broadcast(false).unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        drop(poisoned);
        assert_eq!(control.diagnostic(0, 0)[4], baseline);
        let fd = unsafe { libc::socket(46, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);
        let poisoned = unsafe { OwnedFd::from_raw_fd(fd) };
        bind(
            poisoned.as_raw_fd(),
            &SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        control.diagnostic(1029, 17);
        assert_eq!(unsafe { libc::listen(poisoned.as_raw_fd(), 8) }, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EPROTO)
        );
        assert_eq!(unsafe { libc::listen(poisoned.as_raw_fd(), 8) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EIO));
        drop(poisoned);
        let deadline = Instant::now() + Duration::from_secs(10);
        while control.diagnostic(0, 0)[4] != baseline {
            assert!(
                Instant::now() < deadline,
                "failed listener proxy not released"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(active_udp().peer_addr().is_ok());
        println!(
            "PASS operation {operation}: malformed/wrong-source/wrong-ID/duplicate replies, bounded recovery, 64 stale replacements, ordinary/fatal signals, uncertain create/setopt/listen and cleanup"
        );
    }

    impl Test for TestTsiControlProtocol {
        fn in_guest(self: Box<Self>) {
            fs::write("/sys/module/kernel/parameters/tsi_hijack", "N").unwrap();
            fs::write("/sys/module/kernel/parameters/tsi_hijack_unix", "N").unwrap();
            if self.faults {
                for operation in [1026, 1035] {
                    fault_contract(operation);
                }
            } else {
                wire_contract();
            }
            println!("TSI_CONTROL_PROTOCOL_OK");
        }
    }
}
