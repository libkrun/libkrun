use macros::{guest, host};

pub struct TestMultiportConsole;

#[host]
mod host {
    use super::*;

    use std::io::{BufRead, BufReader, Write};
    use std::mem;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::thread;

    use crate::common::{build_init_config, init_krun, setup_rootfs};
    use crate::{ShouldRun, Test, TestSetup};

    #[cfg(feature = "dynamic-linking")]
    fn require_symbols() -> Result<(), libloading::Error> {
        crate::common::require_vm_symbols()?;
        krun::require(None, &[krun::Symbol::KrunConsoleBuilderAddInoutPort])
    }

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

    fn add_ping_pong_port(
        builder: &mut krun::ConsoleBuilder<'_>,
        name: &str,
    ) -> anyhow::Result<()> {
        let (guest, host) = UnixStream::pair()?;
        let input = guest.as_fd().try_clone_to_owned().expect("dup guest fd");
        let output = guest.as_fd().try_clone_to_owned().expect("dup guest fd");
        builder
            .add_inout_port(name, Some(input), Some(output))
            .map_err(|e| anyhow::anyhow!("add_inout_port: {e:?}"))?;
        mem::forget(guest);
        spawn_ping_pong_responder(host);
        Ok(())
    }

    impl Test for TestMultiportConsole {
        fn should_run(&self) -> ShouldRun {
            #[cfg(feature = "dynamic-linking")]
            if require_symbols().is_err() {
                return ShouldRun::No("feature not enabled in this libkrun build");
            }
            ShouldRun::Yes
        }

        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            init_krun()?;
            #[cfg(feature = "dynamic-linking")]
            require_symbols().unwrap();

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
            let mut default_console = krun::ConsoleDevice::builder();
            default_console
                .add_default_console(
                    None,
                    Some(
                        std::io::stdout()
                            .as_fd()
                            .try_clone_to_owned()
                            .expect("dup stdout"),
                    ),
                    None,
                )
                .map_err(|e| anyhow::anyhow!("add_default_console: {e:?}"))?;
            let default_console = default_console
                .build()
                .map_err(|e| anyhow::anyhow!("build default console: {e:?}"))?;

            // Second console with test ports
            let mut test_console = krun::ConsoleDevice::builder();
            add_ping_pong_port(&mut test_console, "test-port-alpha")?;
            add_ping_pong_port(&mut test_console, "test-port-beta")?;
            add_ping_pong_port(&mut test_console, "test-port-gamma")?;
            let test_console = test_console
                .build()
                .map_err(|e| anyhow::anyhow!("build test console: {e:?}"))?;

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
    use std::io::{BufRead, BufReader, Write};

    fn test_port(port_map: &std::collections::HashMap<String, String>, name: &str, message: &str) {
        let device_path = format!("/dev/{}", port_map.get(name).unwrap());
        let mut port = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&device_path)
            .unwrap();

        port.write_all(message.as_bytes()).unwrap();
        port.flush().unwrap();

        let mut reader = BufReader::new(port);
        let mut response = String::new();
        reader.read_line(&mut response).unwrap();

        let expected = message.replace("PING", "PONG").to_string();
        assert_eq!(response, expected, "{}: wrong response", name);
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

            // We shouldn't have any more than configured here
            assert_eq!(port_map.len(), 4);

            test_port(&port_map, "test-port-alpha", "PING-ALPHA\n");
            test_port(&port_map, "test-port-beta", "PING-BETA\n");
            test_port(&port_map, "test-port-gamma", "PING-GAMMA\n");

            println!("OK");
        }
    }
}
