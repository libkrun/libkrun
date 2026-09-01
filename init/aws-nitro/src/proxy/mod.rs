use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use nix::errno::Errno;
use nix::libc as nix_c;
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{self, Signal};
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType};
use nix::sys::stat::{self, Mode, SFlag};
use nix::unistd::{self, ForkResult};
use vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};

const VSOCK_PORT_OFFSET_NET: u32 = 2;
const VSOCK_PORT_OFFSET_OUTPUT: u32 = 3;
const VSOCK_PORT_OFFSET_SIGNAL_HANDLER: u32 = 5;

const TUN_DEV_MAJOR: u64 = 10;
const TUN_DEV_MINOR: u64 = 200;

const ETH_HEADER_LEN: i32 = 14;

/// Redirect std{err, out} output to a vsock connected to the host.
/// This allows the host to read application output.
fn init_output_proxy(vsock_port: u32) -> anyhow::Result<()> {
    let addr = VsockAddr::new(VMADDR_CID_HOST, vsock_port);
    let stream = VsockStream::connect(&addr).context("unable to connect to host vsock")?;
    // STDERR and STDOUT now point to the vsock, so we can let the original vsock fd be dropped
    // when it goes out of scope and close the streams when we're ready.
    unistd::dup2_stderr(&stream).context("unable to redirect stderr to vsock")?;
    unistd::dup2_stdout(&stream).context("unable to redirect stdout to vsock")
}

/// Initialize the enclave TAP device to route all network traffic to the
/// host.
fn init_tun() -> anyhow::Result<()> {
    match unistd::mkdir("/dev/net", Mode::from_bits_truncate(0o755)) {
        Ok(_) | Err(Errno::EEXIST) => {}
        Err(e) => bail!("failure to create /dev/net: {}", e),
    }

    match Path::new("/dev/net/tun").try_exists() {
        Ok(false) => {
            let dev = stat::makedev(TUN_DEV_MAJOR, TUN_DEV_MINOR);
            // Allow all users to read/write to /dev/net/tun. Allowing
            // the device to be accessible by non-root users is safe
            // as CAP_NET_ADMIN is required for connecting to network
            // devices not owned by the user in question.
            stat::mknod(
                "/dev/net/tun",
                SFlag::S_IFCHR,
                Mode::from_bits_truncate(0o666),
                dev,
            )
            .context("unable to create /dev/net/tun device node")?;
        }
        Ok(true) => {
            let path = "/dev/net/tun";
            let mut permissions = fs::metadata(path)
                .context("unable to get /dev/net/tun metadata")?
                .permissions();
            permissions.set_mode(0o666);
            fs::set_permissions(path, permissions)
                .context("unable to set file permissions for /dev/net/tun")?;
        }
        Err(e) => bail!("unable to verify status of /dev/net/tun: {}", e),
    }
    Ok(())
}

fn ifr_with_name_and_addr(name: &str, ipaddr: Ipv4Addr) -> nix_c::ifreq {
    let mut ifr = ifr_with_name(name);

    let mut addr = unsafe { mem::zeroed::<nix_c::sockaddr_in>() };
    addr.sin_family = nix_c::AF_INET as u16;
    addr.sin_addr = nix_c::in_addr {
        s_addr: u32::from_ne_bytes(ipaddr.octets()),
    };
    ifr.ifr_ifru.ifru_addr = unsafe { mem::transmute::<nix_c::sockaddr_in, nix_c::sockaddr>(addr) };
    ifr
}

fn setup_default_tap_gateway(ifr: &mut nix_c::ifreq) -> nix_c::rtentry {
    let mut route = unsafe { mem::zeroed::<nix_c::rtentry>() };

    // Set the gateway IP.
    let mut gateway_sa = unsafe { mem::zeroed::<nix_c::sockaddr_in>() };
    gateway_sa.sin_family = nix_c::AF_INET as u16;
    let ipaddr = Ipv4Addr::new(172, 31, 10, 83);
    gateway_sa.sin_addr.s_addr = u32::from(ipaddr).to_be();
    route.rt_gateway = unsafe { mem::transmute::<nix_c::sockaddr_in, nix_c::sockaddr>(gateway_sa) };

    // Set the destination to 0.0.0.0 (default route).
    let mut dest_sa = unsafe { mem::zeroed::<nix_c::sockaddr_in>() };
    dest_sa.sin_family = nix_c::AF_INET as u16;
    dest_sa.sin_addr.s_addr = nix_c::INADDR_ANY;
    route.rt_dst = unsafe { mem::transmute::<nix_c::sockaddr_in, nix_c::sockaddr>(dest_sa) };

    // Set the genmask to 0.0.0.0
    let mut genmask_sa = unsafe { mem::zeroed::<nix_c::sockaddr_in>() };
    genmask_sa.sin_family = nix_c::AF_INET as u16;
    genmask_sa.sin_addr.s_addr = nix_c::INADDR_ANY;
    route.rt_genmask = unsafe { mem::transmute::<nix_c::sockaddr_in, nix_c::sockaddr>(genmask_sa) };

    // Set the flags to UP and GATEWAY for default gateway.
    route.rt_flags = nix_c::RTF_UP | nix_c::RTF_GATEWAY;

    // Set the interface.
    route.rt_dev = ifr.ifr_name.as_mut_ptr();

    route
}

/// Assign IP data to route enclave network to the TAP device.
fn assign_tap_ipaddr(name: &str) -> anyhow::Result<()> {
    let sock_fd = socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )?;

    // Set the IP address
    let ipaddr = Ipv4Addr::new(172, 31, 10, 83);
    let mut ifr = ifr_with_name_and_addr(name, ipaddr);
    nix::ioctl_write_ptr_bad!(siocsifaddr, nix_c::SIOCSIFADDR, nix_c::ifreq);
    unsafe { siocsifaddr(sock_fd.as_raw_fd(), &ifr).context("unable to set TAP IP address")? };

    // Set the netmask.
    let ipaddr = Ipv4Addr::new(255, 255, 255, 0);
    ifr = ifr_with_name_and_addr(name, ipaddr);
    nix::ioctl_write_ptr_bad!(siocsifnetmask, nix_c::SIOCSIFNETMASK, nix_c::ifreq);
    unsafe {
        siocsifnetmask(sock_fd.as_raw_fd(), &ifr).context("unable to set TAP netmask")?;
    }

    // Set the MAC address.
    ifr = ifr_with_name(name);
    ifr.ifr_ifru.ifru_hwaddr.sa_family = nix_c::ARPHRD_ETHER;
    let mac: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
    unsafe {
        ifr.ifr_ifru.ifru_hwaddr.sa_data[..mac.len()]
            .copy_from_slice(&mac.map(|i| i as nix_c::c_char))
    };

    nix::ioctl_write_ptr_bad!(siocsifhwaddr, nix_c::SIOCSIFHWADDR, nix_c::ifreq);
    unsafe { siocsifhwaddr(sock_fd.as_raw_fd(), &ifr).context("unable to set TAP MAC address")? };

    // Set the flags to UP and RUNNING.
    ifr = ifr_with_name(name);
    nix::ioctl_read_bad!(siocgifflags, nix_c::SIOCGIFFLAGS, nix_c::ifreq);
    nix::ioctl_write_ptr_bad!(siocsifflags, nix_c::SIOCSIFFLAGS, nix_c::ifreq);
    unsafe {
        siocgifflags(sock_fd.as_raw_fd(), &mut ifr).context("unable to get TAP flags")?;
        ifr.ifr_ifru.ifru_flags |= (nix_c::IFF_UP | nix_c::IFF_RUNNING) as i16;
        siocsifflags(sock_fd.as_raw_fd(), &ifr).context("unable to get TAP flags")?;
    }

    // Set the default gateway to the TAP device.
    let route = setup_default_tap_gateway(&mut ifr);
    nix::ioctl_write_ptr_bad!(siocaddrt, nix_c::SIOCADDRT, nix_c::rtentry);
    unsafe {
        siocaddrt(sock_fd.as_raw_fd(), &route)
            .context("unable to set default gateway for TAP device")?;
    }
    Ok(())
}

fn ifr_with_name(name: &str) -> nix_c::ifreq {
    let mut ifreq = unsafe { mem::zeroed::<nix_c::ifreq>() };
    let name_bytes: Vec<nix_c::c_char> = name
        .as_bytes()
        .iter()
        .map(|c| *c as nix_c::c_char)
        .collect();
    ifreq.ifr_name[..name_bytes.len()].copy_from_slice(&name_bytes);
    ifreq
}

/// Allocate a TAP device for enclave network traffic.
fn alloc_tap(name: &mut String) -> anyhow::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .context("unable to open /dev/net/tun")?;

    let mut ifreq = ifr_with_name(name.as_str());
    ifreq.ifr_ifru.ifru_flags = (nix_c::IFF_TAP | nix_c::IFF_NO_PI) as i16;

    // TUNSETIFF = _IOW('T', 202, int)
    nix::ioctl_write_ptr_bad!(tunsetiff, 0x400454ca, nix_c::ifreq);
    unsafe { tunsetiff(f.as_raw_fd(), &ifreq).context("unable to call tunsetiff ioctl")? };

    let len = ifreq
        .ifr_name
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(ifreq.ifr_name.len());
    name.clear();
    name.push_str(&String::from_utf8_lossy(
        #[allow(clippy::unnecessary_cast)]
        &ifreq.ifr_name[..len]
            .iter()
            .map(|&c| c as u8)
            .collect::<Vec<u8>>(),
    ));

    assign_tap_ipaddr(name).context("unable to assign IP data to TAP device")?;
    Ok(f)
}

/// Forward ethernet packets to/from the host vsock providing network access
/// and the guest TAP device routing application network traffic.
fn forward_network_traffic(
    writep: &OwnedFd,
    shutdown_read: &OwnedFd,
    tap_name: &str,
    stream: &mut VsockStream,
    tun_fd: &mut File,
) -> anyhow::Result<()> {
    // Fetch the TAP device's Maximum Transfer Unit (MTU) and allocate a
    // buffer in that size to transfer ethernet frames to/from the host.
    let sock_fd = socket::socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .context("unable to create INET socket to get TAP MTU")?;
    let mut ifr = ifr_with_name(tap_name);

    nix::ioctl_read_bad!(siocgifmtu, nix_c::SIOCGIFMTU, nix_c::ifreq);
    unsafe {
        siocgifmtu(sock_fd.as_raw_fd(), &mut ifr).context("unable to call siocgifmtu ioctl")?
    };

    drop(sock_fd);

    let eth_frame_size = unsafe { ifr.ifr_ifru.ifru_mtu + ETH_HEADER_LEN };
    let mut buf: Vec<u8> = vec![0; eth_frame_size as usize];

    // Forward the max ethernet frame size to the host for it to allocate a
    // corresponding buffer.
    //
    // To avoid issues where the host endianness and the enclave endianness
    // is different, convert to big endian to pass the max ethernet frame
    // size to the host.
    let eth_frame_size_be = (eth_frame_size as u32).to_be_bytes();
    stream
        .write_all(&eth_frame_size_be)
        .context("unable to forward eth frame size to host")?;

    let stream_borrowed_fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
    let tun_borrowed_fd = unsafe { BorrowedFd::borrow_raw(tun_fd.as_raw_fd()) };
    let shutdown_borrowed_fd = unsafe { BorrowedFd::borrow_raw(shutdown_read.as_raw_fd()) };

    let mut pfds = [
        PollFd::new(stream_borrowed_fd, PollFlags::POLLIN),
        PollFd::new(tun_borrowed_fd, PollFlags::POLLIN),
        PollFd::new(shutdown_borrowed_fd, PollFlags::POLLIN),
    ];

    //Signal to the parent process that initialization is complete.
    unistd::write(writep, &[1])
        .context("unable to signal parent process network proxy is ready")?;

    loop {
        let nready = nix::poll::poll(&mut pfds, PollTimeout::NONE)?;
        if nready == 0 {
            continue;
        }

        let mut event_found = false;
        // Event on vsock. Read the frame and write it to the TAP device.
        if let Some(vsock_event) = pfds[0].revents()
            && vsock_event.contains(PollFlags::POLLIN)
        {
            let mut size = [0u8; 4];
            stream
                .read_exact(&mut size)
                .context("unable to read ethernet frame size")?;
            let len = u32::from_be_bytes(size);
            if len > eth_frame_size as u32 {
                bail!(
                    "ethernet frame size {} exceeds MTU + header size {}",
                    len,
                    eth_frame_size
                );
            }

            // Resize the buffer to the size of the ethernet frame.
            stream
                .read_exact(&mut buf[..len as usize])
                .context("unable to resize buffer to size of ethernet frame")?;

            // TAP devices are expected to write an entire frame at once
            // and not do partial writes. Only retry if the syscall is
            // interrupted.
            tun_fd
                .write_all(&buf[..len as usize])
                .context("unable to write eth frame")?;
            event_found = true;
        }

        // Event on the TAP device. Read the frame and write it to the vsock.
        if let Some(tap_event) = pfds[1].revents()
            && tap_event.contains(PollFlags::POLLIN)
        {
            // TAP devices are expected to read an entire frame at once
            // and not do partial reads. Only retry if the syscall is
            // interrupted.
            let nread = loop {
                match tun_fd.read(&mut buf) {
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Ok(0) | Err(_) => {
                        bail!("failed to read the ethernet frame from the TAP device")
                    }
                    Ok(r) => break r,
                }
            };

            let size = (nread as u32).to_be_bytes();
            stream
                .write_all(&size)
                .context("unable to write eth frame size")?;
            stream
                .write_all(&buf[..nread])
                .context("unable to write eth frame")?;
            event_found = true;
        }

        if event_found {
            continue;
        }

        // No events on network proxy sockets, check shutdown FD and shut
        // down if event found.
        if let Some(shutdown_event) = pfds[2].revents()
            && shutdown_event == PollFlags::POLLIN
        {
            break;
        }
    }

    Ok(())
}

/// Initialize a TAP device to route network to/from.
fn init_network_proxy(
    readp: &OwnedFd,
    writep: &OwnedFd,
    shutdown_write: &OwnedFd,
    shutdown_read: &OwnedFd,
    vsock_port: u32,
) -> anyhow::Result<()> {
    init_tun()?;

    let mut tap_name = String::from("tap0");
    let mut tun_fd = alloc_tap(&mut tap_name)?;

    match unsafe { unistd::fork().context("unable to fork process for network proxy")? } {
        ForkResult::Parent { .. } => {
            let mut buf = [0u8; 1];
            if let Err(e) = unistd::read(readp, &mut buf) {
                bail!(
                    "error waiting for network proxy to report ready state: {}",
                    e
                );
            }
            // We can continue onward with execution and not wait for the
            // child to finish
        }
        ForkResult::Child => {
            // Close the child's copy of the write end so the child sees EOF
            // when the parent drops shutdown_write. Uses raw close because we
            // only have a borrow; process::exit() below prevents double-close.
            // To make this explicit, take shutdown_write by value (OwnedFd)
            // and use drop() instead — but that prevents passing it to other
            // proxies from the caller.
            unistd::close(shutdown_write.as_raw_fd())
                .context("unable to close shutdown_write pipe")?;

            let addr = VsockAddr::new(VMADDR_CID_HOST, vsock_port);
            let mut stream = VsockStream::connect(&addr).context("unable to connect to host")?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;

            match forward_network_traffic(
                writep,
                shutdown_read,
                &tap_name,
                &mut stream,
                &mut tun_fd,
            ) {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    println!("failure to forward network traffic: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

/// Initialize a sign handling proxy to forward signals from the host to the parent process.
fn init_signal_handler_proxy(
    readp: &OwnedFd,
    writep: &OwnedFd,
    shutdown_write: &OwnedFd,
    shutdown_read: &OwnedFd,
    vsock_port: u32,
) -> anyhow::Result<()> {
    match unsafe { unistd::fork()? } {
        ForkResult::Parent { .. } => {
            let mut buf = [0u8; 1];
            if let Err(e) = unistd::read(readp, &mut buf) {
                bail!(
                    "error waiting for signal handler proxy to report ready state: {}",
                    e
                );
            }
            // We can continue onward with execution and not wait for the
            // child to finish
        }
        ForkResult::Child => {
            unistd::close(shutdown_write.as_raw_fd())
                .context("unable to close shutdown write pipe")?;

            let addr = VsockAddr::new(VMADDR_CID_HOST, vsock_port);
            let mut stream = VsockStream::connect(&addr).context("unable to connect to host")?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;

            let stream_borrowed_fd = unsafe { BorrowedFd::borrow_raw(stream.as_raw_fd()) };
            let shutdown_read_borrowed_fd =
                unsafe { BorrowedFd::borrow_raw(shutdown_read.as_raw_fd()) };

            let mut pfds = [
                PollFd::new(stream_borrowed_fd, PollFlags::POLLIN),
                PollFd::new(shutdown_read_borrowed_fd, PollFlags::POLLIN),
            ];

            // Signal to the parent process that initialization is complete.
            unistd::write(writep, &[1]).context("unable to write signal handler readiness")?;

            loop {
                let nready =
                    nix::poll::poll(&mut pfds, PollTimeout::NONE).context("unable to poll fds")?;
                if nready == 0 {
                    continue;
                }

                // Event on vsock. Read the signal and forward it to the parent process.
                if let Some(vsock_event) = pfds[0].revents()
                    && vsock_event == PollFlags::POLLIN
                {
                    let mut sig = [0u8; 4];
                    match stream.read_exact(&mut sig) {
                        Ok(()) => {
                            let sig_int = i32::from_ne_bytes(sig);
                            let sig = Signal::try_from(sig_int).unwrap_or(Signal::SIGTERM);
                            signal::kill(unistd::getppid(), sig)
                                .context(format!("unable to send {} to parent process", sig))?;
                        }
                        Err(_) => signal::kill(unistd::getppid(), Signal::SIGTERM)
                            .context("unable to send SIGTERM to parent process")?,
                    }
                }

                // Event on shutdown FD. Close the vsock and exit.
                if let Some(shutdown_event) = pfds[1].revents()
                    && shutdown_event == PollFlags::POLLIN
                {
                    break;
                }
            }
            std::process::exit(0);
        }
    }
    Ok(())
}

pub fn init(
    cid: u32,
    args: &super::args_reader::EnclaveArgs,
    shutdown_read: &OwnedFd,
    shutdown_write: &OwnedFd,
) -> anyhow::Result<()> {
    let (readp, writep) = nix::unistd::pipe().context("unable to create readiness pipe")?;

    // If not running in debug mode, initialize the application output proxy.
    // Otherwise, the enclave uses the console (which is already connected)
    // for output.
    if args.app_output {
        init_output_proxy(cid + VSOCK_PORT_OFFSET_OUTPUT)?;
    }

    // Initialize the network proxy if configured.
    if args.network_proxy {
        init_network_proxy(
            &readp,
            &writep,
            shutdown_write,
            shutdown_read,
            cid + VSOCK_PORT_OFFSET_NET,
        )?;
    }

    // The signal proxy is always initialized to allow the host to send signals to the enclave.
    init_signal_handler_proxy(
        &readp,
        &writep,
        shutdown_write,
        shutdown_read,
        cid + VSOCK_PORT_OFFSET_SIGNAL_HANDLER,
    )?;

    Ok(())
}
