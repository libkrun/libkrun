use macros::{guest, host};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct TestTsiSocketContract {
    pub ipv6: bool,
    pub hijack: bool,
}

impl TestTsiSocketContract {
    fn loopback(&self) -> IpAddr {
        if self.ipv6 {
            Ipv6Addr::LOCALHOST.into()
        } else {
            Ipv4Addr::LOCALHOST.into()
        }
    }
}

const INCOMING_UDP: u16 = 45001;
const INCOMING_TCP: u16 = 45002;
const MAPPED_PUBLICATION: u16 = 45003;

#[host]
mod host {
    use super::*;
    use crate::common::{build_init_config, setup_standard_devices};
    use crate::{Test, TestOutcome, TestSetup};
    use anyhow::ensure;
    #[cfg(feature = "dynamic-linking")]
    use krun::{DeviceManager, ffi::Symbol};
    use nix::sys::socket::{
        AddressFamily, SockFlag, SockType, SockaddrStorage, bind, getsockname, socket,
    };
    use std::env;
    use std::fs;
    use std::io::{self, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::path::Path;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn bound_tcp_socket(ip: IpAddr) -> anyhow::Result<(OwnedFd, u16)> {
        let family = if ip.is_ipv6() {
            AddressFamily::Inet6
        } else {
            AddressFamily::Inet
        };
        let fd = socket(family, SockType::Stream, SockFlag::empty(), None)?;
        bind(
            fd.as_raw_fd(),
            &SockaddrStorage::from(SocketAddr::new(ip, 0)),
        )?;
        let address: SockaddrStorage = getsockname(fd.as_raw_fd())?;
        let port = if ip.is_ipv6() {
            address.as_sockaddr_in6().unwrap().port()
        } else {
            address.as_sockaddr_in().unwrap().port()
        };
        Ok((fd, port))
    }

    fn publish_result(directory: &Path, name: &str, result: anyhow::Result<()>) {
        let message = match result {
            Ok(()) => "OK".into(),
            Err(error) => format!("FAIL: {error:#}"),
        };
        let path = directory.join(name);
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, message).unwrap();
        fs::rename(temporary, path).unwrap();
    }

    fn publication_fixture(directory: &Path, listener: TcpListener, guest_port: u16) {
        let directory = directory.to_path_buf();
        thread::spawn(move || {
            let result = (|| -> anyhow::Result<()> {
                let address = listener.local_addr()?;
                let deadline = Instant::now() + Duration::from_secs(40);
                while !directory
                    .join(format!("publication-{guest_port}-release"))
                    .exists()
                {
                    ensure!(Instant::now() < deadline, "publication release timed out");
                    thread::sleep(Duration::from_millis(10));
                }
                drop(listener);
                ensure!(
                    TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err(),
                    "listener published before retry"
                );
                fs::write(
                    directory.join(format!("publication-{guest_port}-released")),
                    "OK",
                )?;
                while !directory
                    .join(format!("publication-{guest_port}-ready"))
                    .exists()
                {
                    ensure!(Instant::now() < deadline, "publication retry timed out");
                    thread::sleep(Duration::from_millis(10));
                }
                let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3))?;
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                let mut reply = [0; 5];
                stream.read_exact(&mut reply)?;
                ensure!(&reply == b"retry", "publication retry payload");
                Ok(())
            })();
            publish_result(
                &directory,
                &format!("publication-{guest_port}-result"),
                result,
            );
        });
    }

    impl Test for TestTsiSocketContract {
        fn timeout_secs(&self) -> u64 {
            60
        }

        fn start_vm(self: Box<Self>, setup: TestSetup) -> anyhow::Result<()> {
            #[cfg(feature = "dynamic-linking")]
            anyhow::ensure!(
                [
                    Symbol::KrunVsockDeviceNew,
                    Symbol::KrunVsockDeviceDestroy,
                    Symbol::KrunVsockDeviceAddPortForward,
                ]
                .into_iter()
                .all(|symbol| symbol.is_available()),
                "required TSI symbols unavailable"
            );
            eprintln!("socket contract: ipv6={} hijack={}", self.ipv6, self.hijack);
            let ip = self.loopback();
            let udp = Arc::new(UdpSocket::bind((ip, 0))?);
            let other = Arc::new(UdpSocket::bind((ip, 0))?);
            let tcp = TcpListener::bind((ip, 0))?;
            let conflict = TcpListener::bind((ip, 0))?;
            let conflict_port = conflict.local_addr()?.port();
            let mapped_conflict = TcpListener::bind((ip, 0))?;
            let mapped_conflict_port = mapped_conflict.local_addr()?.port();
            let (refused, refused_port) = bound_tcp_socket(ip)?;
            #[cfg(target_os = "macos")]
            let (pending, pending_port) = bound_tcp_socket(ip)?;
            let incoming_udp = UdpSocket::bind((ip, 0))?;
            let incoming_tcp = TcpListener::bind((ip, 0))?;
            let values = [
                format!("TSI_UDP={}", udp.local_addr()?.port()),
                format!("TSI_OTHER={}", other.local_addr()?.port()),
                format!("TSI_TCP={}", tcp.local_addr()?.port()),
                format!("TSI_CONFLICT={conflict_port}"),
                format!("TSI_REFUSED={refused_port}"),
                #[cfg(target_os = "macos")]
                format!("TSI_PENDING={pending_port}"),
                format!(
                    "TSI_STRICT={}",
                    u8::from(env::var_os("KRUN_TEST_TSI_TCP_PUBLICATION_STRICT").is_some())
                ),
            ];
            let udp_port = incoming_udp.local_addr()?.port();
            let tcp_port = incoming_tcp.local_addr()?.port();
            drop((incoming_udp, incoming_tcp));
            for (socket, foreign) in [(udp.clone(), other.clone()), (other, udp)] {
                thread::spawn(move || {
                    let mut data = [0; 65536];
                    loop {
                        let (count, peer) = socket.recv_from(&mut data).unwrap();
                        if &data[..count] == b"filter" {
                            foreign.send_to(b"wrong peer", peer).unwrap();
                        }
                        socket.send_to(&data[..count], peer).unwrap();
                    }
                });
            }
            thread::spawn(move || {
                for stream in tcp.incoming() {
                    let mut stream = stream.unwrap();
                    thread::spawn(move || {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let mut data = Vec::new();
                        stream.read_to_end(&mut data).unwrap();
                        stream.write_all(&data).unwrap();
                    });
                }
            });
            let directory = setup.tmp_dir.join("rootfs");
            publication_fixture(&directory, conflict, conflict_port);
            publication_fixture(&directory, mapped_conflict, MAPPED_PUBLICATION);
            thread::spawn(move || {
                let result = (|| -> anyhow::Result<()> {
                    let deadline = Instant::now() + Duration::from_secs(40);
                    while !directory.join("incoming-ready").exists() {
                        ensure!(Instant::now() < deadline, "incoming sockets not ready");
                        thread::sleep(Duration::from_millis(10));
                    }
                    let socket = UdpSocket::bind((ip, 0))?;
                    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
                    socket.send_to(b"incoming UDP", (ip, udp_port))?;
                    let mut data = [0; 32];
                    let (count, peer) = socket.recv_from(&mut data)?;
                    ensure!(&data[..count] == b"incoming UDP", "UDP reply");
                    ensure!(peer.port() == udp_port, "mapped UDP reply source");
                    let mut stream = TcpStream::connect((ip, tcp_port))?;
                    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                    stream.write_all(b"incoming TCP")?;
                    stream.read_exact(&mut data[..12])?;
                    ensure!(&data[..12] == b"incoming TCP", "TCP reply");
                    Ok(())
                })();
                publish_result(&directory, "incoming-result", result);
            });
            let environment: Vec<_> = values.iter().map(String::as_str).collect();
            let config = build_init_config(&setup.test_case, &environment);
            let (stdin, stdout, stderr) = (io::stdin(), io::stdout(), io::stderr());
            let (mut devices, payload) =
                setup_standard_devices(&setup, &config, &stdin, &stdout, &stderr)?;
            let mut flags = krun::TsiFlags::HIJACK_INET;
            if env::var_os("KRUN_TEST_TSI_TCP_PUBLICATION_STRICT").is_some() {
                flags |= krun::TsiFlags::FAIL_ON_TCP_PUBLICATION_ERROR;
            }
            let mut vsock =
                krun::VsockDevice::new(3, flags).map_err(|e| anyhow::anyhow!("vsock: {e}"))?;
            for (guest, host) in [
                (INCOMING_UDP, udp_port),
                (INCOMING_TCP, tcp_port),
                (MAPPED_PUBLICATION, mapped_conflict_port),
            ] {
                vsock
                    .add_port_forward(&format!("{guest}:{host}"))
                    .map_err(|e| anyhow::anyhow!("mapping: {e}"))?;
            }
            devices.add(vsock);
            let vmm = krun::VmmBuilder::new()
                .vcpus(2)
                .map_err(|e| anyhow::anyhow!("vcpus: {e}"))?
                .ram_mib(256)
                .map_err(|e| anyhow::anyhow!("memory: {e}"))?
                .payload(payload)
                .devices(devices)
                .build()
                .map_err(|e| anyhow::anyhow!("VM: {e}"))?;
            // Darwin leaves connects to bound, non-listening TCP sockets pending.
            drop(refused);
            #[cfg(target_os = "macos")]
            let _keep_pending = pending;
            vmm.run();
            unreachable!()
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _setup: TestSetup) -> TestOutcome {
            let output = String::from_utf8_lossy(&stdout);
            if output.lines().last() == Some("TSI_SOCKET_CONTRACT_OK") {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(format!("socket contract failed: {output}"))
            }
        }
    }
}

#[guest]
mod guest {
    use super::*;
    use crate::Test;
    use nix::libc;
    use std::env;
    use std::fs;
    use std::io::{self, Read, Write};
    use std::mem::{size_of, zeroed};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::Path;
    use std::ptr;
    use std::thread;
    use std::time::{Duration, Instant};

    fn port(name: &str) -> u16 {
        env::var(name).unwrap().parse().unwrap()
    }

    fn option(fd: i32, level: i32, name: i32, value: Option<i32>) -> i32 {
        let mut data = value.unwrap_or(0);
        let mut size = size_of::<i32>() as libc::socklen_t;
        let result = unsafe {
            if value.is_some() {
                libc::setsockopt(fd, level, name, (&data as *const i32).cast(), size)
            } else {
                libc::getsockopt(fd, level, name, (&mut data as *mut i32).cast(), &mut size)
            }
        };
        assert_eq!(
            result,
            0,
            "option level={level} name={name}: {}",
            io::Error::last_os_error()
        );
        data
    }

    impl TestTsiSocketContract {
        fn socket(&self, kind: i32) -> OwnedFd {
            let family = match (self.ipv6, self.hijack) {
                (false, true) => libc::AF_INET,
                (true, true) => libc::AF_INET6,
                (false, false) => 46,
                (true, false) => 47,
            };
            let fd = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, 0) };
            assert!(
                fd >= 0,
                "socket({family}, {kind}): {}",
                io::Error::last_os_error()
            );
            unsafe { OwnedFd::from_raw_fd(fd) }
        }

        fn udp(&self) -> UdpSocket {
            let socket = UdpSocket::from(self.socket(libc::SOCK_DGRAM));
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
        }

        fn udp_contract(&self) {
            let address = SocketAddr::new(self.loopback(), port("TSI_UDP"));
            let other = SocketAddr::new(self.loopback(), port("TSI_OTHER"));
            let socket = self.udp();
            let fd = socket.as_raw_fd();
            option(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, Some(1));
            option(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, Some(65536));
            for count in [0, 1, 3072, 8192] {
                let payload: Vec<_> = (0..count).map(|i| (i % 251) as u8).collect();
                assert_eq!(socket.send_to(&payload, address).unwrap(), count);
                let mut data = vec![0; count + 1];
                let (received, peer) = socket.peek_from(&mut data).unwrap();
                assert_eq!(received, count);
                assert_eq!(peer, address);
                assert_eq!(&data[..count], payload);
                assert_eq!(socket.recv_from(&mut data).unwrap(), (count, address));
            }
            socket.send_to(&[0x5a; 32], address).unwrap();
            let mut complete = [0u8; 32];
            let mut iov = libc::iovec {
                iov_base: complete.as_mut_ptr().cast(),
                iov_len: complete.len(),
            };
            let mut message: libc::msghdr = unsafe { zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            assert_eq!(unsafe { libc::recvmsg(fd, &mut message, 0) }, 32);
            assert_eq!(message.msg_flags & libc::MSG_TRUNC, 0);
            socket.send_to(&[0x5a; 32], address).unwrap();
            let mut truncated = [0u8; 8];
            let mut iov = libc::iovec {
                iov_base: truncated.as_mut_ptr().cast(),
                iov_len: truncated.len(),
            };
            let mut message: libc::msghdr = unsafe { zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            assert_eq!(
                unsafe { libc::recvmsg(fd, &mut message, libc::MSG_TRUNC) },
                32
            );
            assert_ne!(message.msg_flags & libc::MSG_TRUNC, 0);
            assert_eq!(truncated, [0x5a; 8]);
            assert_eq!(option(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, None), 1);
            assert!(option(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, None) > 0);
            assert_eq!(
                option(fd, libc::SOL_SOCKET, libc::SO_TYPE, None),
                libc::SOCK_DGRAM
            );
            assert!(socket.local_addr().unwrap().port() != 0);
            socket.connect(address).unwrap();
            assert_eq!(socket.peer_addr().unwrap(), address);
            socket.send(b"filter").unwrap();
            let mut data = [0; 32];
            assert_eq!(socket.recv(&mut data).unwrap(), 6);
            assert_eq!(&data[..6], b"filter");
            socket.send_to(b"connected sendto", address).unwrap();
            assert_eq!(socket.recv(&mut data).unwrap(), 16);
            let unspecified = libc::sockaddr {
                sa_family: libc::AF_UNSPEC as _,
                sa_data: [0; 14],
            };
            assert_eq!(
                unsafe { libc::connect(fd, &unspecified, size_of::<libc::sockaddr>() as _) },
                0
            );
            assert_eq!(
                socket.peer_addr().unwrap_err().raw_os_error(),
                Some(libc::ENOTCONN)
            );
            socket.send_to(b"disconnected", other).unwrap();
            let (count, peer) = socket.recv_from(&mut data).unwrap();
            assert_eq!(peer, other);
            assert_eq!(&data[..count], b"disconnected");
            socket.connect(other).unwrap();
            socket.send(b"reconnected").unwrap();
            assert_eq!(socket.recv(&mut data).unwrap(), 11);
            assert_eq!(
                socket.send(&vec![0; 65369]).unwrap_err().raw_os_error(),
                Some(libc::EMSGSIZE)
            );
            drop(socket);
            for _ in 0..32 {
                let socket = self.udp();
                socket.send_to(b"replacement", address).unwrap();
                assert_eq!(socket.recv(&mut data).unwrap(), 11);
            }
            println!(
                "PASS UDP empty/large/peek, names/options, connected peer filtering, disconnect/reconnect, limits and 32 replacements"
            );
        }

        fn tcp_contract(&self) {
            let started = Instant::now();
            let pending = env::var("TSI_PENDING").ok().map(|port| {
                let mut socket =
                    TcpStream::from(self.socket(libc::SOCK_STREAM | libc::SOCK_NONBLOCK));
                let address = SocketAddr::new(self.loopback(), port.parse().unwrap());
                assert_eq!(connect(socket.as_raw_fd(), address), -1);
                assert_eq!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINPROGRESS)
                );
                assert_eq!(connect(socket.as_raw_fd(), address), -1);
                assert_eq!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::EALREADY)
                );
                assert!(socket.take_error().unwrap().is_none());
                assert_eq!(
                    socket.peer_addr().unwrap_err().raw_os_error(),
                    Some(libc::ENOTCONN)
                );
                assert_eq!(
                    socket.write(b"pending").unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                assert_eq!(
                    socket.set_nodelay(true).unwrap_err().raw_os_error(),
                    Some(libc::EAGAIN)
                );
                socket
            });
            let address = SocketAddr::new(self.loopback(), port("TSI_TCP"));
            let socket = self.socket(libc::SOCK_STREAM | libc::SOCK_NONBLOCK);
            let fd = socket.as_raw_fd();
            option(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, Some(1));
            let result = connect(fd, address);
            assert!(
                result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EINPROGRESS)
            );
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut poll, 1, 5000) }, 1);
            assert_eq!(option(fd, libc::SOL_SOCKET, libc::SO_ERROR, None), 0);
            assert_eq!(option(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, None), 1);
            let mut stream = TcpStream::from(socket);
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert_eq!(stream.peer_addr().unwrap(), address);
            assert_eq!(stream.local_addr().unwrap().ip(), self.loopback());
            let payload = vec![0xa7; 256 * 1024];
            stream.write_all(&payload).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).unwrap();
            assert_eq!(reply, payload);
            assert_eq!(stream.local_addr().unwrap().ip(), self.loopback());
            if let Some(pending) = pending {
                let udp = self.udp();
                udp.send_to(b"progress", (self.loopback(), port("TSI_UDP")))
                    .unwrap();
                let mut reply = [0u8; 8];
                assert_eq!(udp.recv(&mut reply).unwrap(), 8);
                assert_eq!(&reply, b"progress");
                assert_eq!(
                    pending.peer_addr().unwrap_err().raw_os_error(),
                    Some(libc::ENOTCONN)
                );
                assert!(
                    started.elapsed() < Duration::from_secs(2),
                    "other sockets stalled behind pending connect"
                );
                let closing = Instant::now();
                drop(pending);
                assert!(
                    closing.elapsed() < Duration::from_secs(1),
                    "closing pending connect blocked"
                );
                println!(
                    "PASS pending TCP connect permits independent TCP/UDP progress and prompt close"
                );
            }
            let socket = self.socket(libc::SOCK_STREAM | libc::SOCK_NONBLOCK);
            let fd = socket.as_raw_fd();
            assert_eq!(
                connect(fd, SocketAddr::new(self.loopback(), port("TSI_REFUSED"))),
                -1
            );
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EINPROGRESS)
            );
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut poll, 1, 5000) }, 1);
            assert_eq!(
                option(fd, libc::SOL_SOCKET, libc::SO_ERROR, None),
                libc::ECONNREFUSED
            );
            assert_eq!(option(fd, libc::SOL_SOCKET, libc::SO_ERROR, None), 0);
            println!(
                "PASS TCP nonblocking connect/refusal, option replay, names after shutdown, bulk transfer and half-close"
            );
        }

        fn incoming(&self) {
            let udp = self.udp();
            let fd = udp.as_raw_fd();
            let (level, name) = if self.ipv6 {
                (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
            } else {
                (libc::IPPROTO_IP, libc::IP_PKTINFO)
            };
            option(fd, level, name, Some(1));
            bind(fd, SocketAddr::new(self.loopback(), INCOMING_UDP));
            let name = udp.local_addr().unwrap();
            assert_eq!(name.port(), INCOMING_UDP);
            let tcp = self.socket(libc::SOCK_STREAM);
            bind(
                tcp.as_raw_fd(),
                SocketAddr::new(self.loopback(), INCOMING_TCP),
            );
            assert_eq!(unsafe { libc::listen(tcp.as_raw_fd(), 8) }, 0);
            let tcp = TcpListener::from(tcp);
            fs::write("/incoming-ready", b"ready").unwrap();
            let mut data = [0; 32];
            let mut peer: libc::sockaddr_storage = unsafe { zeroed() };
            let mut control = [0usize; 32];
            let mut iov = libc::iovec {
                iov_base: data.as_mut_ptr().cast(),
                iov_len: data.len(),
            };
            let mut message: libc::msghdr = unsafe { zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_name = (&mut peer as *mut libc::sockaddr_storage).cast();
            message.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
            message.msg_control = control.as_mut_ptr().cast();
            // musl and glibc use different widths for msg_controllen.
            #[allow(clippy::unnecessary_cast)]
            let control_length = size_of_val(&control) as _;
            message.msg_controllen = control_length;
            let count = unsafe { libc::recvmsg(fd, &mut message, 0) };
            assert!(
                count >= 0,
                "incoming recvmsg: {}",
                io::Error::last_os_error()
            );
            let count = count as usize;
            assert_eq!(&data[..count], b"incoming UDP");
            let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
            let mut packet_info = false;
            while !header.is_null() {
                let native = unsafe { &*header };
                if self.ipv6
                    && native.cmsg_level == libc::IPPROTO_IPV6
                    && native.cmsg_type == libc::IPV6_PKTINFO
                {
                    let info = unsafe {
                        ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::in6_pktinfo>())
                    };
                    assert_eq!(
                        IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)),
                        self.loopback()
                    );
                    assert!(info.ipi6_ifindex > 0);
                    packet_info = true;
                } else if !self.ipv6
                    && native.cmsg_level == libc::IPPROTO_IP
                    && native.cmsg_type == libc::IP_PKTINFO
                {
                    let info = unsafe {
                        ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::in_pktinfo>())
                    };
                    assert_eq!(
                        IpAddr::V4(Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes())),
                        self.loopback()
                    );
                    assert!(info.ipi_ifindex > 0);
                    packet_info = true;
                }
                header = unsafe { libc::CMSG_NXTHDR(&message, header) };
            }
            assert!(
                packet_info,
                "incoming destination/interface metadata missing"
            );
            assert_eq!(
                unsafe { libc::connect(fd, message.msg_name.cast(), message.msg_namelen) },
                0
            );
            let unspecified = libc::sockaddr {
                sa_family: libc::AF_UNSPEC as _,
                sa_data: [0; 14],
            };
            assert_eq!(
                unsafe { libc::connect(fd, &unspecified, size_of::<libc::sockaddr>() as _) },
                0
            );
            assert_eq!(udp.local_addr().unwrap(), name);
            assert_eq!(
                unsafe {
                    libc::sendto(
                        fd,
                        data.as_ptr().cast(),
                        count,
                        0,
                        message.msg_name.cast(),
                        message.msg_namelen,
                    )
                },
                count as isize
            );
            assert_eq!(udp.local_addr().unwrap(), name);
            let (mut stream, peer) = tcp.accept().unwrap();
            assert_eq!(peer.ip(), self.loopback());
            assert_eq!(stream.local_addr().unwrap().ip(), self.loopback());
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream.read_exact(&mut data[..12]).unwrap();
            stream.write_all(&data[..12]).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !Path::new("/incoming-result").exists() {
                assert!(Instant::now() < deadline, "incoming fixture timed out");
                thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(fs::read_to_string("/incoming-result").unwrap(), "OK");
            println!("PASS incoming TCP and UDP before send, port mappings and logical bind names");
            for guest_port in [port("TSI_CONFLICT"), MAPPED_PUBLICATION] {
                self.publication(guest_port);
            }
        }

        fn publication(&self, guest_port: u16) {
            let mut conflict = self.socket(libc::SOCK_STREAM);
            option(
                conflict.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                Some(1),
            );
            bind(
                conflict.as_raw_fd(),
                SocketAddr::new(self.loopback(), guest_port),
            );
            let result = unsafe { libc::listen(conflict.as_raw_fd(), 8) };
            if env::var("TSI_STRICT").unwrap() == "1" {
                assert_eq!(result, -1);
                assert_eq!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::EADDRINUSE)
                );
                assert_eq!(
                    option(
                        conflict.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_ACCEPTCONN,
                        None
                    ),
                    0
                );
            } else {
                assert_eq!(result, 0);
                assert_eq!(
                    option(
                        conflict.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_ACCEPTCONN,
                        None
                    ),
                    1
                );
                let duplicate = unsafe { libc::dup(conflict.as_raw_fd()) };
                assert!(duplicate >= 0);
                let listener = TcpListener::from(unsafe { OwnedFd::from_raw_fd(duplicate) });
                let mut client = TcpStream::connect((self.loopback(), guest_port)).unwrap();
                client.write_all(b"local").unwrap();
                let (mut accepted, _) = listener.accept().unwrap();
                let mut payload = [0; 5];
                accepted.read_exact(&mut payload).unwrap();
                assert_eq!(&payload, b"local");
                client.shutdown(Shutdown::Write).unwrap();
                assert_eq!(accepted.read(&mut payload).unwrap(), 0);
            }
            fs::write(format!("/publication-{guest_port}-release"), "ready").unwrap();
            wait_for(&format!("/publication-{guest_port}-released"));
            if env::var("TSI_STRICT").unwrap() != "1" {
                drop(conflict);
                conflict = self.socket(libc::SOCK_STREAM);
                option(
                    conflict.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    Some(1),
                );
                bind(
                    conflict.as_raw_fd(),
                    SocketAddr::new(self.loopback(), guest_port),
                );
            }
            assert_eq!(unsafe { libc::listen(conflict.as_raw_fd(), 8) }, 0);
            let listener = TcpListener::from(conflict);
            fs::write(format!("/publication-{guest_port}-ready"), "ready").unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"retry").unwrap();
            let result = format!("/publication-{guest_port}-result");
            wait_for(&result);
            assert_eq!(fs::read_to_string(&result).unwrap(), "OK");
            println!("PASS TCP publication conflict/retry on guest port {guest_port}");
        }
    }

    fn wait_for(path: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !Path::new(path).exists() {
            assert!(Instant::now() < deadline, "waiting for {path}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn raw_address(address: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
        let size = match address {
            SocketAddr::V4(address) => {
                let native = unsafe {
                    &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>()
                };
                native.sin_family = libc::AF_INET as _;
                native.sin_port = address.port().to_be();
                native.sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
                size_of::<libc::sockaddr_in>()
            }
            SocketAddr::V6(address) => {
                let native = unsafe {
                    &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
                };
                native.sin6_family = libc::AF_INET6 as _;
                native.sin6_port = address.port().to_be();
                native.sin6_addr.s6_addr = address.ip().octets();
                size_of::<libc::sockaddr_in6>()
            }
        };
        (storage, size as _)
    }

    fn connect(fd: i32, address: SocketAddr) -> i32 {
        let (native, size) = raw_address(address);
        unsafe { libc::connect(fd, (&native as *const libc::sockaddr_storage).cast(), size) }
    }

    fn bind(fd: i32, address: SocketAddr) {
        let (native, size) = raw_address(address);
        assert_eq!(
            unsafe { libc::bind(fd, (&native as *const libc::sockaddr_storage).cast(), size) },
            0,
            "bind {address}: {}",
            io::Error::last_os_error()
        );
    }

    impl Test for TestTsiSocketContract {
        fn in_guest(self: Box<Self>) {
            fs::write(
                "/sys/module/kernel/parameters/tsi_hijack",
                if self.hijack { "Y" } else { "N" },
            )
            .unwrap();
            assert!(!Path::new("/sys/class/net/eth0").exists());
            self.udp_contract();
            self.tcp_contract();
            self.incoming();
            println!("TSI_SOCKET_CONTRACT_OK");
        }
    }
}
