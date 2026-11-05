use macros::{guest, host};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

const BODY: &str = "tsi application networking works\n";
const GUEST_PORT: u16 = 8080;
const DNS_LARGE_ANSWERS: u16 = 192;

#[derive(Clone, Copy)]
pub enum Application {
    CurlHttp,
    CurlHttps,
    CurlParallelDelayed,
    CurlParallelTimeout,
    WgetHttp,
    DigUdp,
    DigTcp,
    DigUdpLarge,
    DigUdpFallback,
    Dnsmasq,
    DnsmasqWildcard,
    PythonHttp,
    OpenSslDtls,
    Ping,
}

#[derive(Clone, Copy)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    fn loopback(self) -> IpAddr {
        match self {
            Self::Ipv4 => Ipv4Addr::LOCALHOST.into(),
            Self::Ipv6 => Ipv6Addr::LOCALHOST.into(),
        }
    }

    fn host(self) -> &'static str {
        match self {
            Self::Ipv4 => "127.0.0.1",
            Self::Ipv6 => "::1",
        }
    }

    fn ping_target(self) -> &'static str {
        match self {
            Self::Ipv4 => "192.0.2.1",
            Self::Ipv6 => "fd00:7473:7069::1",
        }
    }

    fn authority(self) -> &'static str {
        match self {
            Self::Ipv4 => "127.0.0.1",
            Self::Ipv6 => "[::1]",
        }
    }
}

pub struct TestTsiApplication {
    application: Application,
    family: AddressFamily,
}

impl TestTsiApplication {
    pub fn new(application: Application, family: AddressFamily) -> Self {
        Self {
            application,
            family,
        }
    }
}

fn dns_client(family: AddressFamily, port: u16, tcp: bool) -> Command {
    dns_client_addr(family.loopback(), port, tcp)
}

fn dns_client_addr(address: IpAddr, port: u16, tcp: bool) -> Command {
    let mut command = Command::new("dig");
    command.args([
        &format!("@{address}"),
        "-p",
        &port.to_string(),
        "+time=2",
        "+tries=1",
        "+short",
        "+ignore",
        "tsi-app.test",
        "A",
    ]);
    command.args([
        "-b",
        if address.is_ipv6() {
            "::1"
        } else {
            "127.0.0.1"
        },
    ]);
    command.arg(if tcp { "+tcp" } else { "+notcp" });
    command
}

#[host]
mod host {
    use super::*;
    use crate::common::{build_init_config, setup_standard_devices};
    use crate::{ShouldRun, Test, TestOutcome, TestSetup};
    use anyhow::{Context, ensure};
    #[cfg(feature = "dynamic-linking")]
    use krun::DeviceManager;
    use std::env;
    use std::fs;
    use std::io::{self, ErrorKind, Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::path::Path;
    use std::process::Stdio;
    use std::thread;
    use std::time::{Duration, Instant};

    const DNS_HOST_CLIENTS: usize = 16;

    const CONTAINERFILE: &str = "FROM fedora:43\nRUN dnf install -y curl wget python3 bind-utils openssl dnsmasq iputils && dnf clean all\n";

    #[cfg(feature = "dynamic-linking")]
    fn symbols_available() -> bool {
        use krun::ffi::Symbol;
        [
            Symbol::KrunVsockDeviceNew,
            Symbol::KrunVsockDeviceDestroy,
            Symbol::KrunVsockDeviceAddPortForward,
        ]
        .into_iter()
        .all(|symbol| symbol.is_available())
    }

    fn http_response(stream: &mut TcpStream) -> anyhow::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
            stream.read_exact(&mut byte)?;
            request.push(byte[0]);
        }
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
            BODY.len()
        )?;
        Ok(())
    }

    fn http_fixture(family: AddressFamily) -> anyhow::Result<u16> {
        let listener = TcpListener::bind((family.loopback(), 0))?;
        let port = listener.local_addr()?.port();
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                if let Err(error) = http_response(&mut stream) {
                    eprintln!("HTTP fixture: {error}");
                }
            }
        });
        Ok(port)
    }

    fn dns_answer(query: &[u8], answers: u16, truncated: bool) -> anyhow::Result<Vec<u8>> {
        ensure!(
            query.len() >= 12 && query[4..6] == [0, 1],
            "invalid DNS query"
        );
        let mut end = 12;
        loop {
            let len = *query.get(end).context("truncated DNS name")? as usize;
            ensure!(len <= 63, "unexpected DNS label");
            end += len + 1;
            if len == 0 {
                break;
            }
        }
        end += 4;
        ensure!(end <= query.len(), "truncated DNS question");
        let mut answer = query[..end].to_vec();
        answer[2..12].copy_from_slice(&[0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]);
        if truncated {
            answer[2] |= 0x02;
        } else {
            answer[6..8].copy_from_slice(&answers.to_be_bytes());
            for index in 0..answers {
                let last = if answers == 1 { 42 } else { (index + 1) as u8 };
                answer.extend_from_slice(&[
                    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, last,
                ]);
            }
        }
        Ok(answer)
    }

    fn dns_sockets(family: AddressFamily) -> anyhow::Result<(TcpListener, UdpSocket)> {
        loop {
            let listener = TcpListener::bind((family.loopback(), 0))?;
            match UdpSocket::bind(listener.local_addr()?) {
                Ok(socket) => return Ok((listener, socket)),
                Err(error) if error.kind() == ErrorKind::AddrInUse => (),
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn dns_fixture(
        application: Application,
        family: AddressFamily,
        root: &Path,
    ) -> anyhow::Result<u16> {
        let (listener, socket) = dns_sockets(family)?;
        let port = listener.local_addr()?.port();
        let fallback = matches!(application, Application::DigUdpFallback);
        let answers = if matches!(application, Application::DigUdpLarge) {
            DNS_LARGE_ANSWERS
        } else {
            1
        };
        if matches!(application, Application::DigTcp) || fallback {
            let root = root.to_path_buf();
            thread::spawn(move || {
                for mut stream in listener.incoming().flatten() {
                    let mut exchange = || -> anyhow::Result<()> {
                        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                        let mut len = [0; 2];
                        stream.read_exact(&mut len)?;
                        let mut query = vec![0; u16::from_be_bytes(len) as usize];
                        stream.read_exact(&mut query)?;
                        let answer = dns_answer(&query, answers, false)?;
                        fs::write(root.join("dns-tcp-result"), "OK")?;
                        stream.write_all(&(answer.len() as u16).to_be_bytes())?;
                        stream.write_all(&answer)?;
                        Ok(())
                    };
                    if let Err(error) = exchange() {
                        eprintln!("DNS TCP fixture: {error}");
                    }
                }
            });
        }
        if !matches!(application, Application::DigTcp) {
            let root = root.to_path_buf();
            thread::spawn(move || {
                let exchange = || -> anyhow::Result<()> {
                    let mut query = [0; 4096];
                    loop {
                        let (len, peer) = socket.recv_from(&mut query)?;
                        let answer = dns_answer(&query[..len], answers, fallback)?;
                        fs::write(root.join("dns-udp-result"), answer.len().to_string())?;
                        socket.send_to(&answer, peer)?;
                    }
                };
                if let Err(error) = exchange() {
                    eprintln!("DNS UDP fixture: {error}");
                }
            });
        }
        Ok(port)
    }

    fn dns_server_fixture(
        setup: &TestSetup,
        root: &Path,
        family: AddressFamily,
        wildcard: bool,
    ) -> anyhow::Result<u16> {
        let (tcp, udp) = dns_sockets(family)?;
        let port = tcp.local_addr()?.port();
        drop((tcp, udp));
        let setup = TestSetup {
            test_case: setup.test_case.clone(),
            tmp_dir: setup.tmp_dir.clone(),
        };
        let root = root.to_path_buf();
        thread::spawn(move || {
            let result = (|| -> anyhow::Result<()> {
                let deadline = Instant::now() + Duration::from_secs(20);
                while !root.join("dns-ready").exists() {
                    ensure!(Instant::now() < deadline, "DNS server did not start");
                    thread::sleep(Duration::from_millis(20));
                }
                let mut clients = Vec::new();
                for index in 0..DNS_HOST_CLIENTS {
                    let address = if wildcard && index % 2 != 0 {
                        match family {
                            AddressFamily::Ipv4 => env::var("KRUN_TEST_TSI_IPV4_ALTERNATE")
                                .map(|address| address.parse().expect("alternate IPv4 address"))
                                .unwrap_or_else(|_| {
                                    if cfg!(target_os = "linux") {
                                        Ipv4Addr::new(127, 0, 0, 2).into()
                                    } else {
                                        family.loopback()
                                    }
                                }),
                            AddressFamily::Ipv6 => env::var("KRUN_TEST_TSI_IPV6_ALTERNATE")
                                .map(|address| address.parse().expect("alternate IPv6 address"))
                                .unwrap_or(family.loopback()),
                        }
                    } else {
                        family.loopback()
                    };
                    let client = dns_client_addr(address, port, false)
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()?;
                    setup.register_cleanup_pid(client.id());
                    clients.push(client);
                }
                for client in clients {
                    let result = client.wait_with_output()?;
                    ensure!(
                        result.status.success(),
                        "host UDP dig failed: stdout={} stderr={}",
                        String::from_utf8_lossy(&result.stdout),
                        String::from_utf8_lossy(&result.stderr)
                    );
                    ensure!(
                        result.stdout == b"192.0.2.42\n",
                        "wrong host UDP DNS answer: {}",
                        String::from_utf8_lossy(&result.stdout)
                    );
                }
                let client = dns_client(family, port, true)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;
                setup.register_cleanup_pid(client.id());
                let result = client.wait_with_output()?;
                ensure!(
                    result.status.success(),
                    "host TCP dig failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                ensure!(
                    result.stdout == b"192.0.2.42\n",
                    "wrong host TCP DNS answer"
                );
                eprintln!(
                    "incoming DNS: {DNS_HOST_CLIENTS} host UDP clients and one host TCP client passed"
                );
                Ok(())
            })();
            let verdict = match result {
                Ok(()) => "OK".to_string(),
                Err(error) => format!("FAIL: {error:#}"),
            };
            let _ = fs::write(root.join("dns-host-result"), verdict);
        });
        Ok(port)
    }

    fn certificate(setup: &TestSetup, root: &Path, family: AddressFamily) -> anyhow::Result<()> {
        let cert = root.join("tsi-app-ca.pem");
        let key = setup.tmp_dir.join("server.key");
        let output = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=tsi-app.test",
                "-addext",
                &format!("subjectAltName=IP:{}", family.host()),
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .output()
            .context("generate test certificate")?;
        ensure!(
            output.status.success(),
            "openssl req: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::copy(&key, root.join("tsi-app-key.pem"))?;
        Ok(())
    }

    fn tls_fixture(setup: &TestSetup, root: &Path, family: AddressFamily) -> anyhow::Result<u16> {
        certificate(setup, root, family)?;
        let cert = root.join("tsi-app-ca.pem");
        let key = root.join("tsi-app-key.pem");
        let reserve = TcpListener::bind((family.loopback(), 0))?;
        let port = reserve.local_addr()?.port();
        drop(reserve);
        let mut server = Command::new("openssl")
            .args([
                "s_server",
                "-quiet",
                "-WWW",
                "-accept",
                &format!("{}:{port}", family.authority()),
                "-cert",
            ])
            .arg(&cert)
            .arg("-key")
            .arg(&key)
            .current_dir(root.join("srv"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .context("start TLS fixture")?;
        setup.register_cleanup_pid(server.id());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if TcpStream::connect((family.loopback(), port)).is_ok() {
                break;
            }
            ensure!(server.try_wait()?.is_none(), "TLS fixture exited");
            ensure!(
                Instant::now() < deadline,
                "TLS fixture did not become ready"
            );
            thread::sleep(Duration::from_millis(20));
        }
        Ok(port)
    }

    fn dtls_fixture(setup: &TestSetup, root: &Path, family: AddressFamily) -> anyhow::Result<u16> {
        certificate(setup, root, family)?;
        for name in ["dtls-ready", "dtls-result"] {
            let path = root.join(name);
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        let reserve = UdpSocket::bind((family.loopback(), 0))?;
        let port = reserve.local_addr()?.port();
        drop(reserve);
        let setup = TestSetup {
            test_case: setup.test_case.clone(),
            tmp_dir: setup.tmp_dir.clone(),
        };
        let root = root.to_path_buf();
        thread::spawn(move || {
            let result = (|| -> anyhow::Result<()> {
                let deadline = Instant::now() + Duration::from_secs(20);
                while !root.join("dtls-ready").exists() {
                    ensure!(Instant::now() < deadline, "DTLS server did not start");
                    thread::sleep(Duration::from_millis(20));
                }
                let mut client = Command::new("openssl")
                    .args([
                        "s_client",
                        "-dtls1_2",
                        "-quiet",
                        "-verify_return_error",
                        "-verify_ip",
                        family.host(),
                        "-connect",
                        &format!("{}:{port}", family.authority()),
                        "-CAfile",
                    ])
                    .arg(root.join("tsi-app-ca.pem"))
                    .stdin(Stdio::piped())
                    .stdout(fs::File::create(root.join("dtls-host.body"))?)
                    .stderr(fs::File::create(root.join("dtls-host.stderr"))?)
                    .spawn()?;
                setup.register_cleanup_pid(client.id());
                client.stdin.as_mut().unwrap().write_all(BODY.as_bytes())?;
                while fs::read(root.join("dtls-host.body")).ok().as_deref() != Some(BODY.as_bytes())
                {
                    ensure!(client.try_wait()?.is_none(), "DTLS client exited");
                    ensure!(Instant::now() < deadline, "host DTLS response timed out");
                    thread::sleep(Duration::from_millis(20));
                }
                client.kill()?;
                client.wait()?;
                Ok(())
            })();
            let verdict = match result {
                Ok(()) => "OK".to_string(),
                Err(error) => format!("FAIL: {error:#}"),
            };
            let _ = fs::write(root.join("dtls-result"), verdict);
        });
        Ok(port)
    }

    fn parallel_fixture(
        root: &Path,
        timeout: bool,
        family: AddressFamily,
    ) -> anyhow::Result<(u16, u16)> {
        use nix::sys::socket::{Backlog, listen};

        for name in [
            "parallel-start",
            "parallel-result",
            "fast.body",
            "slow.body",
        ] {
            match fs::remove_file(root.join(name)) {
                Ok(()) => (),
                Err(error) if error.kind() == ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        let listener = TcpListener::bind((family.loopback(), 0))?;
        listen(&listener, Backlog::new(0)?)?;
        let slow_port = listener.local_addr()?.port();
        let filler = TcpStream::connect((family.loopback(), slow_port))?;
        let fast_port = http_fixture(family)?;
        let root = root.to_path_buf();
        thread::spawn(move || {
            let result = (|| -> anyhow::Result<()> {
                let startup = Instant::now() + Duration::from_secs(10);
                while !root.join("parallel-start").exists() {
                    ensure!(Instant::now() < startup, "curl did not start");
                    thread::sleep(Duration::from_millis(20));
                }
                let started = Instant::now();
                let mut progressed = false;
                while started.elapsed() < Duration::from_secs(4) {
                    if fs::read(root.join("fast.body")).is_ok_and(|body| body == BODY.as_bytes()) {
                        progressed = true;
                        break;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                let verdict = if progressed {
                    "OK"
                } else {
                    "FAIL: fast transfer stalled behind connect"
                };
                let temporary = root.join("parallel-result.tmp");
                fs::write(&temporary, verdict)?;
                fs::rename(temporary, root.join("parallel-result"))?;
                let hold = if timeout {
                    Duration::from_secs(4)
                } else {
                    Duration::from_millis(750)
                };
                thread::sleep(hold.saturating_sub(started.elapsed()));
                let (accepted, _) = listener.accept()?;
                drop(accepted);
                drop(filler);
                let (mut slow, _) = listener.accept()?;
                http_response(&mut slow)
            })();
            if let Err(error) = result {
                eprintln!("parallel fixture: {error:#}");
            }
        });
        Ok((slow_port, fast_port))
    }

    fn incoming_fixture(port: u16, root: &Path, family: AddressFamily) {
        let result_path = root.join("incoming-result");
        thread::spawn(move || {
            let result = (|| -> anyhow::Result<()> {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    if let Ok(mut stream) = TcpStream::connect((family.loopback(), port)) {
                        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                        stream
                            .write_all(b"GET /tsi-app.txt HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
                        let mut response = String::new();
                        stream.read_to_string(&mut response)?;
                        ensure!(
                            response.ends_with(BODY),
                            "wrong guest HTTP response: {response}"
                        );
                        return Ok(());
                    }
                    ensure!(Instant::now() < deadline, "guest HTTP server not published");
                    thread::sleep(Duration::from_millis(50));
                }
            })();
            let message = result
                .map(|_| "OK".to_string())
                .unwrap_or_else(|e| format!("FAIL: {e:#}"));
            let temporary = result_path.with_extension("tmp");
            fs::write(&temporary, message).unwrap();
            fs::rename(temporary, result_path).unwrap();
        });
    }

    fn ping_fixture(family: AddressFamily) -> anyhow::Result<u16> {
        ensure!(
            env::var_os("KRUN_TEST_PRIVATE_NETNS").is_some(),
            "ping fixture requires a private network namespace; use the test runner"
        );
        fs::write("/proc/sys/net/ipv4/ping_group_range", "0 0")?;
        let mut command = Command::new("ip");
        let address = match family {
            AddressFamily::Ipv4 => format!("{}/32", family.ping_target()),
            AddressFamily::Ipv6 => {
                command.arg("-6");
                format!("{}/128", family.ping_target())
            }
        };
        command.args(["address", "replace", &address, "dev", "lo"]);
        if matches!(family, AddressFamily::Ipv6) {
            command.arg("nodad");
        }
        ensure!(command.status()?.success(), "set up host-only ping target");
        Ok(0)
    }

    impl Test for TestTsiApplication {
        fn should_run(&self) -> ShouldRun {
            if !cfg!(target_os = "linux") && matches!(self.application, Application::Ping) {
                return ShouldRun::No("ICMP datagram proxy requires a Linux host");
            }
            if cfg!(target_os = "macos")
                && matches!(
                    self.application,
                    Application::CurlParallelDelayed | Application::CurlParallelTimeout
                )
            {
                return ShouldRun::No(
                    "delayed-connect fixture requires Linux accept queue behavior",
                );
            }
            #[cfg(feature = "dynamic-linking")]
            if !symbols_available() {
                return ShouldRun::No("required libkrun symbols unavailable");
            }
            ShouldRun::Yes
        }

        fn rootfs_image(&self) -> Option<&'static str> {
            if env::var_os("KRUN_TEST_TSI_APPS_ROOTFS").is_some() {
                None
            } else {
                Some(CONTAINERFILE)
            }
        }

        fn timeout_secs(&self) -> u64 {
            40
        }

        fn start_vm(self: Box<Self>, setup: TestSetup) -> anyhow::Result<()> {
            let root = setup.tmp_dir.join("rootfs");
            if let Some(source) = env::var_os("KRUN_TEST_TSI_APPS_ROOTFS") {
                let source = Path::new(&source)
                    .canonicalize()
                    .context("application rootfs")?;
                let status = Command::new("cp")
                    .arg("-a")
                    .arg(source.join("."))
                    .arg(&root)
                    .status()?;
                ensure!(status.success(), "copy application rootfs");
            }
            fs::create_dir_all(root.join("srv"))?;
            fs::write(root.join("srv/tsi-app.txt"), BODY)?;
            let family = self.family;
            let mut slow_env = None;
            let port = match self.application {
                Application::CurlHttp | Application::WgetHttp => http_fixture(family)?,
                Application::CurlHttps => tls_fixture(&setup, &root, family)?,
                Application::CurlParallelDelayed | Application::CurlParallelTimeout => {
                    let (slow, fast) = parallel_fixture(
                        &root,
                        matches!(self.application, Application::CurlParallelTimeout),
                        family,
                    )?;
                    slow_env = Some(format!("TSI_APP_SLOW_PORT={slow}"));
                    fast
                }
                Application::Ping => ping_fixture(family)?,
                Application::OpenSslDtls => dtls_fixture(&setup, &root, family)?,
                Application::DigUdp
                | Application::DigTcp
                | Application::DigUdpLarge
                | Application::DigUdpFallback => dns_fixture(self.application, family, &root)?,
                Application::Dnsmasq | Application::DnsmasqWildcard => dns_server_fixture(
                    &setup,
                    &root,
                    family,
                    matches!(self.application, Application::DnsmasqWildcard),
                )?,
                Application::PythonHttp => {
                    match fs::remove_file(root.join("incoming-result")) {
                        Ok(()) => (),
                        Err(error) if error.kind() == ErrorKind::NotFound => (),
                        Err(error) => return Err(error.into()),
                    }
                    let reserve = TcpListener::bind((family.loopback(), 0))?;
                    let port = reserve.local_addr()?.port();
                    drop(reserve);
                    incoming_fixture(port, &root, family);
                    port
                }
            };
            let port_env = format!("TSI_APP_PORT={port}");
            let mut guest_env = vec![
                port_env.as_str(),
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG=C",
            ];
            if let Some(slow) = &slow_env {
                guest_env.push(slow);
            }
            let config = build_init_config(&setup.test_case, &guest_env);
            let (stdin, stdout, stderr) = (io::stdin(), io::stdout(), io::stderr());
            let (mut devices, payload) =
                setup_standard_devices(&setup, &config, &stdin, &stdout, &stderr)?;
            let mut flags = krun::TsiFlags::HIJACK_INET;
            if env::var_os("KRUN_TEST_TSI_TCP_PUBLICATION_STRICT").is_some() {
                flags |= krun::TsiFlags::FAIL_ON_TCP_PUBLICATION_ERROR;
            }
            let mut vsock = krun::VsockDevice::new(3, flags)
                .map_err(|e| anyhow::anyhow!("VsockDevice: {e}"))?;
            if matches!(
                self.application,
                Application::PythonHttp
                    | Application::OpenSslDtls
                    | Application::Dnsmasq
                    | Application::DnsmasqWildcard
            ) {
                vsock
                    .add_port_forward(&format!("{GUEST_PORT}:{port}"))
                    .map_err(|e| anyhow::anyhow!("port forward: {e}"))?;
            }
            devices.add(vsock);
            let vmm = krun::VmmBuilder::new()
                .vcpus(2)
                .map_err(|e| anyhow::anyhow!("vcpus: {e}"))?
                .ram_mib(512)
                .map_err(|e| anyhow::anyhow!("RAM: {e}"))?
                .payload(payload)
                .devices(devices)
                .build()
                .map_err(|e| anyhow::anyhow!("VM: {e}"))?;
            vmm.run();
            unreachable!()
        }

        fn check(self: Box<Self>, stdout: Vec<u8>, _setup: TestSetup) -> TestOutcome {
            let output = String::from_utf8_lossy(&stdout);
            if output.lines().last() == Some("TSI_APPLICATION_OK") {
                TestOutcome::Pass
            } else {
                TestOutcome::Fail(format!(
                    "application did not complete successfully; stdout: {output}"
                ))
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
    use std::io::{self, Write};
    use std::net::TcpStream;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, Output, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    struct Server(Child);
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn output(command: &mut Command) -> Output {
        eprintln!("application command: {command:?}");
        let output = command.output().expect("run installed application");
        eprintln!(
            "status: {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "application failed: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        output
    }

    fn ping(family: AddressFamily) {
        fs::write("/proc/sys/net/ipv4/ping_group_range", "0 2147483647").unwrap();
        for target in [family.ping_target(), family.host()] {
            for options in [&[][..], &["-C"][..], &["-e", "4242"][..]] {
                let mut command = Command::new("ping");
                command.arg(match family {
                    AddressFamily::Ipv4 => "-4",
                    AddressFamily::Ipv6 => "-6",
                });
                command.args(["-n", "-c", "3", "-i", "0.1", "-W", "1", "-w", "3"]);
                command.args(options).arg(target).uid(65534).gid(65534);
                // Prevent file capabilities from hiding a raw-socket fallback.
                unsafe {
                    command.pre_exec(|| {
                        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                            return Err(io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let result = output(&mut command);
                let stdout = String::from_utf8(result.stdout).unwrap();
                eprintln!("{stdout}");
                assert!(stdout.contains("3 packets transmitted, 3 received, 0% packet loss"));
                let replies: Vec<_> = stdout
                    .lines()
                    .filter(|line| line.contains("icmp_seq="))
                    .collect();
                assert_eq!(replies.len(), 3);
                for reply in replies {
                    let ttl: u8 = reply
                        .split_whitespace()
                        .find_map(|word| word.strip_prefix("ttl="))
                        .unwrap()
                        .parse()
                        .unwrap();
                    assert!(ttl > 0, "missing reply TTL/hop-limit: {reply}");
                }
            }
        }
    }

    fn dtls_server(family: AddressFamily) -> Server {
        let child = Command::new("openssl")
            .args([
                "s_server",
                "-dtls1_2",
                "-quiet",
                "-accept",
                &format!("{}:{GUEST_PORT}", family.authority()),
                "-cert",
                "/tsi-app-ca.pem",
                "-key",
                "/tsi-app-key.pem",
            ])
            .stdin(Stdio::piped())
            .stdout(fs::File::create("/dtls-guest.body").unwrap())
            .stderr(fs::File::create("/dtls-guest.stderr").unwrap())
            .spawn()
            .unwrap();
        let mut server = Server(child);
        wait_udp_binding(&mut server, family, false);
        server
    }

    fn wait_udp_binding(server: &mut Server, family: AddressFamily, wildcard: bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let (table, address) = match family {
                AddressFamily::Ipv4 => (
                    "/proc/net/udp",
                    if wildcard { "00000000" } else { "0100007F" },
                ),
                AddressFamily::Ipv6 => (
                    "/proc/net/udp6",
                    if wildcard {
                        "00000000000000000000000000000000"
                    } else {
                        "00000000000000000000000001000000"
                    },
                ),
            };
            let table = fs::read_to_string(table).unwrap();
            if table.contains(&format!("{address}:{GUEST_PORT:04X}")) {
                break;
            }
            assert!(server.0.try_wait().unwrap().is_none(), "UDP server exited");
            assert!(Instant::now() < deadline, "UDP server did not bind");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_body(path: &str, body: &[u8]) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while fs::read(path).ok().as_deref() != Some(body) {
            assert!(
                Instant::now() < deadline,
                "expected contents missing: {path}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn curl(url: &str, tls: bool) {
        let mut command = Command::new("curl");
        command.args([
            "--noproxy",
            "*",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "3",
            "--max-time",
            "5",
        ]);
        if tls {
            command.args(["--cacert", "/tsi-app-ca.pem"]);
        }
        let result = output(command.arg(url));
        assert_eq!(result.stdout, BODY.as_bytes());
    }

    impl Test for TestTsiApplication {
        fn in_guest(self: Box<Self>) {
            assert_eq!(
                fs::read_to_string("/sys/module/kernel/parameters/tsi_hijack")
                    .unwrap()
                    .trim(),
                "Y"
            );
            assert!(!Path::new("/sys/class/net/eth0").exists());
            let family = self.family;
            let authority = family.authority();
            let port: u16 = env::var("TSI_APP_PORT").unwrap().parse().unwrap();
            let (application, version) = match self.application {
                Application::CurlHttp
                | Application::CurlHttps
                | Application::CurlParallelDelayed
                | Application::CurlParallelTimeout => ("curl", "--version"),
                Application::WgetHttp => ("wget", "--version"),
                Application::DigUdp
                | Application::DigTcp
                | Application::DigUdpLarge
                | Application::DigUdpFallback => ("dig", "-v"),
                Application::Dnsmasq | Application::DnsmasqWildcard => ("dnsmasq", "--version"),
                Application::PythonHttp => ("python3", "--version"),
                Application::OpenSslDtls => ("openssl", "version"),
                Application::Ping => ("ping", "-V"),
            };
            let version = output(Command::new(application).arg(version));
            eprintln!(
                "application version: {}{}",
                String::from_utf8_lossy(&version.stdout),
                String::from_utf8_lossy(&version.stderr)
            );
            match self.application {
                Application::Ping => ping(family),
                Application::CurlHttp => {
                    curl(&format!("http://{authority}:{port}/tsi-app.txt"), false)
                }
                Application::CurlHttps => {
                    curl(&format!("https://{authority}:{port}/tsi-app.txt"), true)
                }
                Application::CurlParallelDelayed | Application::CurlParallelTimeout => {
                    let timeout = matches!(self.application, Application::CurlParallelTimeout);
                    let slow = env::var("TSI_APP_SLOW_PORT").unwrap();
                    let connect_timeout = if timeout { "1" } else { "8" };
                    let max_time = if timeout { "2" } else { "10" };
                    let mut command = Command::new("curl");
                    command.args([
                        "--parallel",
                        "--parallel-immediate",
                        "--parallel-max",
                        "2",
                        "--fail-early",
                    ]);
                    for (index, (name, port)) in [("slow", slow), ("fast", port.to_string())]
                        .into_iter()
                        .enumerate()
                    {
                        if index != 0 {
                            command.arg("--next");
                        }
                        command.args([
                            "--noproxy",
                            "*",
                            "--fail",
                            "--silent",
                            "--show-error",
                            "--connect-timeout",
                            connect_timeout,
                            "--max-time",
                            max_time,
                            "--output",
                            &format!("/{name}.body"),
                            &format!("http://{authority}:{port}/tsi-app.txt"),
                        ]);
                    }
                    fs::write("/parallel-start", "start").unwrap();
                    let started = Instant::now();
                    let result = command.output().expect("run stock curl parallel transfers");
                    let elapsed = started.elapsed();
                    eprintln!(
                        "parallel curl: status={} elapsed={elapsed:?} stderr={}",
                        result.status,
                        String::from_utf8_lossy(&result.stderr)
                    );
                    if timeout {
                        assert_eq!(
                            result.status.code(),
                            Some(28),
                            "curl should report its connect timeout"
                        );
                        assert!(
                            elapsed < Duration::from_millis(2500),
                            "curl timeout blocked the event loop: {elapsed:?}"
                        );
                    } else {
                        assert!(result.status.success());
                        assert_eq!(fs::read("/slow.body").unwrap(), BODY.as_bytes());
                    }
                    assert_eq!(fs::read("/fast.body").unwrap(), BODY.as_bytes());
                    assert_eq!(fs::read_to_string("/parallel-result").unwrap(), "OK");
                }
                Application::OpenSslDtls => {
                    let mut server = dtls_server(family);
                    fs::write("/dtls-ready", "ready").unwrap();
                    wait_body("/dtls-guest.body", BODY.as_bytes());
                    server
                        .0
                        .stdin
                        .as_mut()
                        .unwrap()
                        .write_all(BODY.as_bytes())
                        .unwrap();
                    wait_body("/dtls-host.body", BODY.as_bytes());
                    wait_body("/dtls-result", b"OK");
                    drop(server);
                    let mut server = dtls_server(family);
                    let mut client = Server(
                        Command::new("openssl")
                            .args([
                                "s_client",
                                "-dtls1_2",
                                "-quiet",
                                "-verify_return_error",
                                "-verify_ip",
                                family.host(),
                                "-connect",
                                &format!("{}:{GUEST_PORT}", family.authority()),
                                "-CAfile",
                                "/tsi-app-ca.pem",
                            ])
                            .stdin(Stdio::piped())
                            .stdout(fs::File::create("/dtls-local.body").unwrap())
                            .stderr(Stdio::inherit())
                            .spawn()
                            .unwrap(),
                    );
                    client
                        .0
                        .stdin
                        .as_mut()
                        .unwrap()
                        .write_all(b"guest-local DTLS\n")
                        .unwrap();
                    wait_body("/dtls-guest.body", b"guest-local DTLS\n");
                    server
                        .0
                        .stdin
                        .as_mut()
                        .unwrap()
                        .write_all(BODY.as_bytes())
                        .unwrap();
                    wait_body("/dtls-local.body", BODY.as_bytes());
                }
                Application::WgetHttp => {
                    let result = output(Command::new("wget").args([
                        "--no-proxy",
                        "--quiet",
                        "--timeout=5",
                        "--tries=1",
                        "-O",
                        "-",
                        &format!("http://{authority}:{port}/tsi-app.txt"),
                    ]));
                    assert_eq!(result.stdout, BODY.as_bytes());
                }
                Application::DigUdp
                | Application::DigTcp
                | Application::DigUdpLarge
                | Application::DigUdpFallback => {
                    let mut command = Command::new("dig");
                    command.args([
                        &format!("@{}", family.host()),
                        "-p",
                        &port.to_string(),
                        "+time=2",
                        "+tries=1",
                        "+short",
                    ]);
                    if matches!(self.application, Application::DigTcp) {
                        command.arg("+tcp");
                    }
                    let large = matches!(self.application, Application::DigUdpLarge);
                    if large {
                        command.args(["+bufsize=4096", "+ignore"]);
                    }
                    let result = output(command.args(["tsi-app.test", "A"]));
                    let response = String::from_utf8(result.stdout).unwrap();
                    let lines: Vec<_> = response
                        .lines()
                        .filter(|line| !line.starts_with(';') && !line.is_empty())
                        .collect();
                    let expected: Vec<_> = if large {
                        (1..=DNS_LARGE_ANSWERS)
                            .map(|last| format!("192.0.2.{last}"))
                            .collect()
                    } else {
                        vec!["192.0.2.42".to_string()]
                    };
                    assert_eq!(lines, expected);
                    let tcp = Path::new("/dns-tcp-result").exists();
                    let udp = Path::new("/dns-udp-result").exists();
                    assert_eq!(
                        tcp,
                        matches!(
                            self.application,
                            Application::DigTcp | Application::DigUdpFallback
                        )
                    );
                    assert_eq!(udp, !matches!(self.application, Application::DigTcp));
                    if large {
                        let len: usize = fs::read_to_string("/dns-udp-result")
                            .unwrap()
                            .parse()
                            .unwrap();
                        assert!(len > 3000, "large DNS reply only {len} bytes");
                        eprintln!(
                            "DNS UDP reply: {len} bytes, {DNS_LARGE_ANSWERS} answers, no TCP retry"
                        );
                    }
                }
                Application::Dnsmasq | Application::DnsmasqWildcard => {
                    let wildcard = matches!(self.application, Application::DnsmasqWildcard);
                    let mut command = Command::new("dnsmasq");
                    command.args([
                        "--keep-in-foreground",
                        "--conf-file=/dev/null",
                        "--no-resolv",
                        "--no-hosts",
                        &format!("--port={GUEST_PORT}"),
                        "--user=root",
                        "--group=root",
                        "--address=/tsi-app.test/192.0.2.42",
                        "--log-facility=-",
                        "--log-queries",
                    ]);
                    if wildcard {
                        command.arg("--interface=lo");
                    } else {
                        command.args([
                            "--bind-interfaces",
                            &format!("--listen-address={}", family.host()),
                        ]);
                    }
                    let child = command
                        .stdout(Stdio::null())
                        .spawn()
                        .expect("start stock DNS server");
                    let mut server = Server(child);
                    wait_udp_binding(&mut server, family, wildcard);
                    fs::write("/dns-ready", "ready").unwrap();
                    for tcp in [false, true] {
                        let result = output(&mut dns_client(family, GUEST_PORT, tcp));
                        assert_eq!(result.stdout, b"192.0.2.42\n");
                    }
                    wait_body("/dns-host-result", b"OK");
                }
                Application::PythonHttp => {
                    let mut server = Server(
                        Command::new("python3")
                            .args([
                                "-u",
                                "-m",
                                "http.server",
                                &GUEST_PORT.to_string(),
                                "--bind",
                                family.host(),
                                "--directory",
                                "/srv",
                            ])
                            .stdout(Stdio::null())
                            .spawn()
                            .expect("start Python HTTP server"),
                    );
                    let deadline = Instant::now() + Duration::from_secs(15);
                    loop {
                        if TcpStream::connect((family.loopback(), GUEST_PORT)).is_ok() {
                            break;
                        }
                        assert!(
                            server.0.try_wait().unwrap().is_none(),
                            "Python HTTP server exited"
                        );
                        assert!(
                            Instant::now() < deadline,
                            "Python HTTP server startup timed out"
                        );
                        thread::sleep(Duration::from_millis(20));
                    }
                    curl(
                        &format!("http://{authority}:{GUEST_PORT}/tsi-app.txt"),
                        false,
                    );
                    loop {
                        if let Ok(result) = fs::read_to_string("/incoming-result") {
                            assert_eq!(result, "OK");
                            break;
                        }
                        assert!(
                            Instant::now() < deadline,
                            "host did not reach Python HTTP server"
                        );
                        thread::sleep(Duration::from_millis(20));
                    }
                }
            }
            println!("TSI_APPLICATION_OK");
        }
    }
}
