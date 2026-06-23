mod config;
#[cfg(target_os = "linux")]
mod dhcp;
mod env;
mod exec;
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod fs;
#[cfg(feature = "timesync")]
mod timesync;

/// Ensure init has open stdin/stdout/stderr.
///
/// The kernel hands init closed fds 0/1/2 when the console (hvc0) is not yet
/// registered as it execs init, and Rust std's sanitize_standard_fds() aborts on
/// that before main() runs. Open them first (the console, else /dev/null);
/// setup_redirects() rewires them to the krun ports later.
#[cfg(target_os = "linux")]
extern "C" fn ensure_stdio() {
    use nix::fcntl::{self, OFlag};
    use nix::mount::{self, MsFlags};
    use nix::sys::stat::Mode;
    use nix::unistd;
    use std::os::fd::AsRawFd;

    if unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_GETFD) } >= 0 {
        return;
    }
    let _ = std::fs::create_dir_all("/dev");
    let _ = mount::mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::empty(),
        None::<&str>,
    );

    let Ok(fd) = fcntl::open(c"/dev/console", OFlag::O_RDWR, Mode::empty())
        .or_else(|_| fcntl::open(c"/dev/null", OFlag::O_RDWR, Mode::empty()))
    else {
        return;
    };
    let _ = unistd::dup2_stdin(&fd);
    let _ = unistd::dup2_stdout(&fd);
    let _ = unistd::dup2_stderr(&fd);
    if fd.as_raw_fd() <= libc::STDERR_FILENO {
        // fd is a stdio slot that dup2 just wrote to — don't close it.
        std::mem::forget(fd);
    }
}
#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array")]
static ENSURE_STDIO_CTOR: extern "C" fn() = ensure_stdio;

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "freebsd")]
    freebsd::open_console();

    #[cfg(target_os = "freebsd")]
    freebsd::populate_env_from_kenv();

    #[cfg(any(feature = "amd-sev", feature = "tdx"))]
    fs::mount_tee_block_device()?;

    #[cfg(target_os = "linux")]
    {
        fs::mount_filesystems()?;
        fs::mount_block_root_device()?;
        fs::mount_shared_root()?;
    }

    let _ = nix::unistd::setsid();
    unsafe { libc::ioctl(0, libc::TIOCSCTTY as _, 1i32) };

    #[cfg(target_os = "freebsd")]
    unsafe {
        libc::setlogin(c"root".as_ptr())
    };

    env::setup_network(
        #[cfg(target_os = "linux")]
        "eth0",
    );

    #[cfg(target_os = "linux")]
    if env::tsi_enabled() {
        env::enable_dummy_interface();
    }

    #[cfg(target_os = "freebsd")]
    let iso_mounted = std::env::var("KRUN_CONFIG").is_err() && freebsd::mount_config_iso();

    #[cfg(target_os = "linux")]
    let cfg = config::load(fs::is_mount_point);
    #[cfg(not(target_os = "linux"))]
    let cfg = config::load();

    #[cfg(target_os = "freebsd")]
    if iso_mounted {
        freebsd::unmount_config_iso();
    }

    #[cfg(target_os = "linux")]
    if let Some(ref path) = cfg.tmpfs {
        fs::mount_tmpfs(path)?;
    }

    env::apply_env();
    env::apply_hostname();
    env::apply_rlimits();

    if let Some(workdir) = std::env::var("KRUN_WORKDIR").ok().or(cfg.workdir)
        && let Err(e) = nix::unistd::chdir(workdir.as_str())
    {
        eprintln!("chdir to {workdir} failed: {e}");
        std::process::exit(125);
    }

    // The kernel places everything after `--` in the cmdline as this
    // process's argv[1..].  The C init built exec_argv by replacing argv[0]
    // with KRUN_INIT (or /bin/sh) and keeping argv[1..] in every branch.
    let proc_args: Vec<String> = std::env::args().collect();

    let argv: Vec<String> = if let Ok(init) = std::env::var("KRUN_INIT") {
        // KRUN_INIT holds the binary; kernel cmdline args are the arguments.
        let mut v = vec![init];
        v.extend_from_slice(proc_args.get(1..).unwrap_or_default());
        v
    } else if let Some(v) = cfg.argv {
        v
    } else if proc_args.len() > 1 {
        // No KRUN_INIT and no config: treat proc_args[1..] as the command.
        //
        // Intentional divergence from the C init: the C init substituted
        // argv[0] with "/bin/sh" and forwarded the remaining args as shell
        // arguments ("/bin/sh arg1 arg2 ...").  That made sense when krun
        // callers relied on the shell to interpret cmdline tokens, but it
        // means proc_args[1] is treated as a script path rather than a binary.
        //
        // The Rust init treats proc_args[1] as the executable directly.  The
        // typical krun caller that omits both KRUN_INIT and a config file
        // intends the cmdline argument to be the command, not a shell script,
        // so this behaviour is more useful and less surprising.
        proc_args.into_iter().skip(1).collect()
    } else {
        vec!["/bin/sh".to_string()]
    };

    #[cfg(feature = "timesync")]
    timesync::run();

    exec::run_workload(&argv);
}
