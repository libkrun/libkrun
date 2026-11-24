use macros::{guest, host};

pub struct TestConsoleTermSize;

const COLS: u16 = 132;
const ROWS: u16 = 43;

#[host]
mod host {
    use super::*;
    #[cfg(feature = "dynamic-linking")]
    use krun::DeviceManager;

    use std::io::{self, BufRead, BufReader, Write};
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

    impl Test for TestConsoleTermSize {
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

            let stdout = io::stdout();
            let mut default_console = krun::ConsoleDevice::builder();
            default_console
                .add_default_console(None, Some(stdout.as_fd()), None)
                .map_err(|e| anyhow::anyhow!("add_default_console: {e:?}"))?;
            let default_console = default_console
                .build()
                .map_err(|e| anyhow::anyhow!("build default console: {e:?}"))?;

            let (guest_console, host_console) = UnixStream::pair()?;
            let (guest_data, host_data) = UnixStream::pair()?;
            let term_size = krun::TermSize {
                cols: COLS,
                rows: ROWS,
            };
            let mut test_console = krun::ConsoleDevice::builder();
            test_console
                .add_inout_port(
                    "sized-console",
                    Some(guest_console.as_fd()),
                    Some(guest_console.as_fd()),
                    Some(&term_size),
                )
                .map_err(|e| anyhow::anyhow!("add_inout_port sized-console: {e:?}"))?;
            test_console
                .add_inout_port(
                    "data-port",
                    Some(guest_data.as_fd()),
                    Some(guest_data.as_fd()),
                    None,
                )
                .map_err(|e| anyhow::anyhow!("add_inout_port data-port: {e:?}"))?;
            let test_console = test_console
                .build()
                .map_err(|e| anyhow::anyhow!("build test console: {e:?}"))?;
            spawn_ping_pong_responder(host_console);
            spawn_ping_pong_responder(host_data);

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
    use nix::libc;
    use nix::sys::termios::{self, SetArg};
    use std::collections::HashMap;
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, BufRead, BufReader, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::thread;
    use std::time::{Duration, Instant};

    nix::ioctl_read_bad!(tiocgwinsz, libc::TIOCGWINSZ, libc::winsize);

    fn open_rw(path: &str) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(path)
    }

    fn port_devices_by_name() -> HashMap<String, String> {
        fs::read_dir("/sys/class/virtio-ports")
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter_map(|entry| {
                let name = fs::read_to_string(entry.path().join("name")).ok()?;
                let device = entry.file_name().to_string_lossy().into_owned();
                Some((name.trim().to_string(), device))
            })
            .filter(|(name, _)| !name.is_empty())
            .collect()
    }

    fn win_size(tty: &File) -> (u16, u16) {
        let mut ws = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: `ws` is a valid winsize for TIOCGWINSZ to fill in.
        unsafe { tiocgwinsz(tty.as_raw_fd(), &mut ws) }.unwrap();
        (ws.ws_col, ws.ws_row)
    }

    // The guest applies the size from deferred work scheduled when the hvc is
    // first opened, so it may not be visible yet right after open().
    fn wait_for_sized_console(consoles: &[(String, File)]) -> usize {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(index) = consoles
                .iter()
                .position(|(_, tty)| win_size(tty) == (COLS, ROWS))
            {
                return index;
            }
            let sizes: Vec<_> = consoles
                .iter()
                .map(|(path, tty)| (path, win_size(tty)))
                .collect();
            assert!(
                Instant::now() < deadline,
                "no console reports {COLS}x{ROWS}: {sizes:?}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn ping_pong(port: File, message: &str) {
        let mut writer = port.try_clone().unwrap();
        writer.write_all(message.as_bytes()).unwrap();
        writer.flush().unwrap();

        let mut response = String::new();
        BufReader::new(port).read_line(&mut response).unwrap();
        assert_eq!(response, message.replace("PING", "PONG"));
    }

    impl Test for TestConsoleTermSize {
        fn in_guest(self: Box<Self>) {
            let ports = port_devices_by_name();
            assert!(ports.contains_key("sized-console"), "ports: {ports:?}");
            assert!(ports.contains_key("data-port"), "ports: {ports:?}");

            // The default console and the sized port are the only consoles, in no fixed hvc order.
            let mut consoles: Vec<(String, File)> = (0..8)
                .filter_map(|i| {
                    let path = format!("/dev/hvc{i}");
                    open_rw(&path).ok().map(|tty| (path, tty))
                })
                .collect();
            let paths: Vec<&String> = consoles.iter().map(|(path, _)| path).collect();
            assert_eq!(consoles.len(), 2, "consoles: {paths:?}");

            let sized_index = wait_for_sized_console(&consoles);
            let (_, sized) = consoles.swap_remove(sized_index);

            // Raw mode keeps the tty from echoing the host's reply back to it.
            let mut attrs = termios::tcgetattr(&sized).unwrap();
            termios::cfmakeraw(&mut attrs);
            termios::tcsetattr(&sized, SetArg::TCSANOW, &attrs).unwrap();
            ping_pong(sized, "PING-CONSOLE\n");

            let data = open_rw(&format!("/dev/{}", ports["data-port"])).unwrap();
            ping_pong(data, "PING-DATA\n");

            println!("OK");
        }
    }
}
