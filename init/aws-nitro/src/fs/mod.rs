use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::os::{fd::AsFd, unix::fs as unix_fs};

use anyhow::Context;
use nix::errno::Errno;
use nix::mount::{self, MsFlags};
use nix::sys::stat::Mode;
use nix::unistd;

/// Initialize /dev/console and redirect std{err, in, out} to it for early debug output.
pub fn console_init() -> anyhow::Result<()> {
    let path = "/dev/console";

    match mount::mount(
        Some("dev"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    ) {
        Ok(_) => Ok(()),
        Err(Errno::EBUSY) => Ok(()),
        Err(e) => Err(e),
    }?;

    // Redirect stdin, stdout, and stderr to /dev/console.
    let console_r = OpenOptions::new()
        .read(true)
        .open(path)
        .context("unable to open /dev/console as read-only")?;

    unistd::dup2_stdin(console_r.as_fd()).context("unable to redirect stdin")?;

    let console_w = OpenOptions::new()
        .write(true)
        .open(path)
        .context("unable to open /dev/console as write-only")?;
    let console_w = console_w.as_fd();

    unistd::dup2_stdout(console_w).context("unable to redirect stdout")?;
    unistd::dup2_stderr(console_w).context("unable to redirect stderr")
}

/// Mount the extracted rootfs and switch the root directory to it.
pub fn mount_rootfs() -> anyhow::Result<()> {
    mount::mount(
        Some("/rootfs"),
        "/rootfs",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("unable to mount /rootfs with mount()")?;
    unistd::chdir("/rootfs").context("unable to change current dir to /rootfs")?;

    mount::mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>)
        .context("unable to move . to / with mount()")?;
    unistd::chroot(".").context("unable to change root to . ")?;
    unistd::chdir("/").context("unable to change dir to /")?;

    Ok(())
}

fn init_dev_filesystem() -> anyhow::Result<()> {
    let sys_dirs = ["/dev", "/proc", "/run", "/sys", "/tmp"];
    let dev_dirs = ["/dev/shm", "/dev/pts"];

    // Create the system directories not provided by the enclave rootfs.
    for dir in sys_dirs {
        unistd::mkdir(dir, Mode::from_bits_truncate(0o755))
            .context(format!("unable to mkdir {}", dir))?;
    }

    // Mount /dev for device files.
    mount::mount(
        Some("/dev"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("unable to mount /dev")?;

    // Create the initial device files.
    for dir in dev_dirs {
        unistd::mkdir(dir, Mode::from_bits_truncate(0o755))
            .context(format!("unable to mkdir {}", dir))?;
    }

    mount::mount(
        Some("shm"),
        "/dev/shm",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("unable to mount /dev/shm")?;

    mount::mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("unable to mount /dev/pts")?;

    Ok(())
}

fn init_proc_filesystem() -> anyhow::Result<()> {
    // Initialize the /proc filesystem for special files representing the current state of the
    // kernel.
    mount::mount(
        Some("/proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("unable to mount /proc")?;

    unix_fs::symlink("/proc/self/fd", "/dev/fd")
        .context("unable to symlink /dev/fd -> /proc/self/fd")?;
    unix_fs::symlink("/proc/self/fd/0", "/dev/stdin")
        .context("unable to symlink /dev/stdin -> /proc/self/fd/0")?;
    unix_fs::symlink("/proc/self/fd/1", "/dev/stdout")
        .context("unable to symlink /dev/stdout -> /proc/self/fd/1")?;
    unix_fs::symlink("/proc/self/fd/2", "/dev/stderr")
        .context("unable to symlink /dev/stderr -> /proc/self/fd/2")?;

    Ok(())
}

/// Initialize the rest of the root filesystem with ephemeral enclave file systems.
pub fn init_filesystem() -> anyhow::Result<()> {
    init_dev_filesystem().context("unable to initialize /dev")?;
    init_proc_filesystem().context("unable to initialize /proc")?;

    // Mount the /run directory to store volatile runtime data about the system since boot.
    mount::mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0755"),
    )
    .context("unable to mount /run")?;

    // Mount the /tmp directory for temporary files (cleraed on reboot).
    mount::mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("unable to mount /tmp")?;

    // Mount the sysfs, accessed to set or obtain information about the kernel's view of the
    // system.
    mount::mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("unable to mount /sys")?;

    // Initialize the cgroup root.
    mount::mount(
        Some("cgroup_root"),
        "/sys/fs/cgroup",
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=0755"),
    )
    .context("unable to mount /sys/fs/cgroup")?;

    Ok(())
}

/// Initialize the cgroups.
pub fn init_cgroups() -> anyhow::Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .open("/proc/cgroups")
        .context("unable to open /proc/cgroups")?;

    let buf_reader = BufReader::new(f);
    let mut lines = buf_reader.lines();

    // Skip the first line.
    lines.next();

    for line in lines {
        let line = line.context("unable to read line of /proc/cgroups")?;
        let sysfs_path = "/sys/fs/cgroup/";

        // Cgroup lines have the following format: subsys_name | hierarchy | num_cgroups | enabled
        let mut line = line.split_whitespace();
        let subsys_name = match line.next() {
            Some(l) => l,
            None => continue,
        };

        // Skip hierarchy and num_cgroups
        let mut line = line.skip(2);

        let enabled = match line.next() {
            Some(l) => l.parse().unwrap_or(0),
            None => continue,
        };

        let path = format!("{}{}", sysfs_path, subsys_name);

        if enabled > 0 {
            unistd::mkdir(path.as_str(), Mode::from_bits_truncate(0o755))
                .context(format!("unable to mkdir {}", path))?;
            mount::mount(
                Some(subsys_name),
                path.as_str(),
                Some("cgroup"),
                MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
                Some(subsys_name),
            )
            .context(format!("unable to mount {}", path))?;
        }
    }

    Ok(())
}
