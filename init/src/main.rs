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

fn main() -> anyhow::Result<()> {
    println!("check1");
    #[cfg(target_os = "freebsd")]
    freebsd::open_console();

    #[cfg(target_os = "freebsd")]
    freebsd::populate_env_from_kenv();

    #[cfg(any(feature = "amd-sev", feature = "tdx"))]
    fs::mount_tee_block_device()?;

    println!("check2");
    #[cfg(target_os = "linux")]
    {
        fs::mount_filesystems()?;
        fs::mount_block_root_device()?;
        fs::mount_shared_root()?;
    }

    println!("check3");
    let _ = nix::unistd::setsid();
    unsafe { libc::ioctl(0, libc::TIOCSCTTY as _, 1i32) };

    println!("check4");
    #[cfg(target_os = "freebsd")]
    unsafe {
        libc::setlogin(c"root".as_ptr())
    };

    println!("check5");
    env::setup_network(
        #[cfg(target_os = "linux")]
        "eth0",
    );

    println!("check6");
    #[cfg(target_os = "linux")]
    if env::tsi_enabled() {
        env::enable_dummy_interface();
    }

    println!("check7");
    #[cfg(target_os = "freebsd")]
    let iso_mounted = std::env::var("KRUN_CONFIG").is_err() && freebsd::mount_config_iso();

    println!("check8");
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
    println!("check9");

    env::apply_env();
    env::apply_hostname();
    env::apply_rlimits();

    println!("check10");
    if let Some(workdir) = std::env::var("KRUN_WORKDIR").ok().or(cfg.workdir)
        && let Err(e) = nix::unistd::chdir(workdir.as_str())
    {
        eprintln!("chdir to {workdir} failed: {e}");
        std::process::exit(125);
    }

    println!("check11");
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
    println!("check12");

    #[cfg(feature = "timesync")]
    timesync::run();

    println!("check13");
    exec::run_workload(&argv);
}
