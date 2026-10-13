use macros::{guest, host};

pub struct TestMultiportConsole;

#[host]
mod host {
    use super::*;
    #[cfg(feature = "dynamic-linking")]
    use krun::DeviceManager;

    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::thread;

    use crate::common::{build_init_config, setup_rootfs};
    use crate::{Test, TestSetup};

    fn spawn_ping_pong_responder(stream: UnixStream) {
        thread::spawn(move || {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok() && !line.is_empty() {
                let response = line.replace("PING", "PONG");
                writer.write_all(response.as_bytes()).unwrap();
                writer.flush().unwrap();
                line.clear();
            }
        });
    }

    fn add_ping_pong_port<'a>(
        builder: &mut krun::ConsoleBuilder<'a>,
        guest: &'a UnixStream,
        host: UnixStream,
        name: &str,
    ) -> anyhow::Result<()> {
        builder
            .add_inout_port(name, Some(guest.as_fd()), Some(guest.as_fd()), None)
            .map_err(|e| anyhow::anyhow!("add_inout_port: {e:?}"))?;
        spawn_ping_pong_responder(host);
        Ok(())
    }

    /// Registers a port whose host side never reads anything. Returns the
    /// host end so the caller can keep it alive (and the socket's kernel
    /// buffer un-drained) for the life of the VM, simulating a
    /// backpressured/non-responsive host sink (e.g. a full pipe).
    fn add_mute_port<'a>(
        builder: &mut krun::ConsoleBuilder<'a>,
        guest: &'a UnixStream,
        name: &str,
    ) -> anyhow::Result<()> {
        builder
            .add_inout_port(name, Some(guest.as_fd()), Some(guest.as_fd()), None)
            .map_err(|e| anyhow::anyhow!("add_inout_port: {e:?}"))?;
        Ok(())
    }

    impl Test for TestMultiportConsole {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            let root_dir = setup_rootfs(&test_setup)?;
            let init_config = build_init_config(&test_setup.test_case, &[]);

            let mut rootfs = krun::FsDevice::new("/dev/root", root_dir.to_str().unwrap())
                .map_err(|e| anyhow::anyhow!("FsDevice::new: {e:?}"))?;
            let mut payload =
                krun::Payload::load_krunfw().map_err(|e| anyhow::anyhow!("load_krunfw: {e:?}"))?;
            let mut overlay = krun::FsOverlay::new();
            init_config
                .apply(&mut overlay, &mut payload)
                .map_err(|e| anyhow::anyhow!("Config::apply: {e}"))?;
            rootfs.set_overlay(overlay);

            // Default console with stdout only (for "OK" output)
            let stdout = std::io::stdout();
            let mut default_console = krun::ConsoleDevice::builder();
            default_console
                .add_default_console(None, Some(stdout.as_fd()), None)
                .map_err(|e| anyhow::anyhow!("add_default_console: {e:?}"))?;
            let default_console = default_console
                .build()
                .map_err(|e| anyhow::anyhow!("build default console: {e:?}"))?;

            // Second console with test ports
            let (guest_alpha, host_alpha) = UnixStream::pair()?;
            let (guest_beta, host_beta) = UnixStream::pair()?;
            let (guest_gamma, host_gamma) = UnixStream::pair()?;
            // Mute port: the host end is kept open but is never read from or
            // dropped, so its kernel socket buffer fills up and stays full,
            // simulating a backpressured/non-responsive host sink (e.g. a
            // full pipe). Used to verify that closing a port under these
            // conditions pauses it instead of blocking the VMM event loop.
            let (guest_mute, host_mute) = UnixStream::pair()?;
            let mut test_console = krun::ConsoleDevice::builder();
            add_ping_pong_port(
                &mut test_console,
                &guest_alpha,
                host_alpha,
                "test-port-alpha",
            )?;
            add_ping_pong_port(&mut test_console, &guest_beta, host_beta, "test-port-beta")?;
            add_ping_pong_port(
                &mut test_console,
                &guest_gamma,
                host_gamma,
                "test-port-gamma",
            )?;
            add_mute_port(&mut test_console, &guest_mute, "test-port-mute")?;
            let test_console = test_console
                .build()
                .map_err(|e| anyhow::anyhow!("build test console: {e:?}"))?;
            // Keep the host end of the mute port alive for the lifetime of
            // the VM: dropping it would close the socket and let the guest
            // side drain/err out instead of staying backpressured.
            std::mem::forget(host_mute);

            let mut devices = krun::MmioDeviceManager::new();
            devices.add(rootfs);
            devices.add(default_console);
            devices.add(test_console);

            let vmm = krun::VmmBuilder::new()
                .vcpus(1)
                .map_err(|e| anyhow::anyhow!("vcpus: {e:?}"))?
                .ram_mib(1024)
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
    use std::fs;
    use std::io::{BufRead, BufReader, ErrorKind, Write};
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::{Duration, Instant};

    fn ping_pong(device_path: &str, message: &str) -> String {
        let mut port = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)
            .unwrap();

        port.write_all(message.as_bytes()).unwrap();
        port.flush().unwrap();

        let mut reader = BufReader::new(port);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();
        response
    }

    fn test_port(port_map: &std::collections::HashMap<String, String>, name: &str, message: &str) {
        let device_path = format!("/dev/{}", port_map.get(name).unwrap());
        let expected = message.replace("PING", "PONG").to_string();

        // First open: exercises the normal open path.
        let response = ping_pong(&device_path, message);
        assert_eq!(response, expected, "{}: wrong response (1st open)", name);

        // `ping_pong` already dropped (closed) the port's file handle above,
        // which makes the guest driver send VIRTIO_CONSOLE_PORT_OPEN(id, 0)
        // to the host. Reopening the very same port here sends
        // VIRTIO_CONSOLE_PORT_OPEN(id, 1) again, exercising the host-side
        // close/reopen (queue reclaim) path on libkrun's virtio-console
        // device. See `Console::process_control_tx` / `Port::shutdown`.
        let response = ping_pong(&device_path, message);
        assert_eq!(response, expected, "{}: wrong response (reopened)", name);
    }

    /// Regression test for a guest-initiated port close hanging the VMM
    /// event loop when the host-side sink is backpressured/non-responsive
    /// (see Port::pause() in the virtio-console device). Writes to the
    /// mute port until the write would block (its host side never reads),
    /// closes the port while still backpressured, then verifies a sibling
    /// port stays responsive within a bounded time -- proving the VMM
    /// event loop kept running instead of blocking in the close handler.
    fn test_close_under_backpressure(port_map: &std::collections::HashMap<String, String>) {
        let mute_path = format!("/dev/{}", port_map.get("test-port-mute").unwrap());

        {
            let mut port = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(nix::libc::O_NONBLOCK)
                .open(&mute_path)
                .unwrap();

            // Keep writing until the virtqueue itself is full (the guest
            // kernel driver returns EAGAIN once there's no more space for
            // another buffer), which forces the host-side TX worker to be
            // actively blocked in `wait_until_writable()` on the never-read
            // host socket when we close the port below.
            let chunk = [b'x'; 4096];
            loop {
                match port.write(&chunk) {
                    Ok(_) => continue,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => panic!("unexpected error saturating mute port: {e}"),
                }
            }
            // Port (and its fd) is dropped here, sending
            // VIRTIO_CONSOLE_PORT_OPEN(id, 0) to the host while the TX
            // worker is still backpressured.
        }

        // The close above must not have hung the VMM event loop: a
        // ping-pong on a sibling port must still complete promptly.
        let alpha_path = format!("/dev/{}", port_map.get("test-port-alpha").unwrap());
        let start = Instant::now();
        let response = ping_pong(&alpha_path, "PING-AFTER-MUTE-CLOSE\n");
        let elapsed = start.elapsed();
        assert_eq!(response, "PONG-AFTER-MUTE-CLOSE\n");
        assert!(
            elapsed < Duration::from_secs(5),
            "ping-pong on sibling port took {elapsed:?} after closing a backpressured port; \
             the VMM event loop may have blocked in Port::pause()/shutdown()"
        );
    }

    impl Test for TestMultiportConsole {
        fn in_guest(self: Box<Self>) {
            let ports_dir = "/sys/class/virtio-ports";

            let mut port_map = std::collections::HashMap::new();

            for entry in fs::read_dir(ports_dir).unwrap() {
                let entry = entry.unwrap();
                let port_name_path = entry.path().join("name");

                if port_name_path.exists() {
                    let port_name = fs::read_to_string(&port_name_path)
                        .unwrap()
                        .trim()
                        .to_string();

                    if !port_name.is_empty() {
                        let device_name = entry.file_name().to_string_lossy().to_string();
                        port_map.insert(port_name, device_name);
                    }
                }
            }

            assert!(
                port_map.contains_key("krun-stdout"),
                "krun-stdout not found"
            );
            assert!(
                port_map.contains_key("test-port-alpha"),
                "test-port-alpha not found"
            );
            assert!(
                port_map.contains_key("test-port-beta"),
                "test-port-beta not found"
            );
            assert!(
                port_map.contains_key("test-port-gamma"),
                "test-port-gamma not found"
            );
            assert!(
                port_map.contains_key("test-port-mute"),
                "test-port-mute not found"
            );

            // We shouldn't have any more than configured here
            assert_eq!(port_map.len(), 5);

            test_port(&port_map, "test-port-alpha", "PING-ALPHA\n");
            test_port(&port_map, "test-port-beta", "PING-BETA\n");
            test_port(&port_map, "test-port-gamma", "PING-GAMMA\n");
            test_close_under_backpressure(&port_map);

            println!("OK");
        }
    }
}
