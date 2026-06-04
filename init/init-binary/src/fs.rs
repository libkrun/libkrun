use std::env;
use std::fs::{self, File, Permissions};
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::{self as unix_fs, PermissionsExt};

use anyhow::{Context, bail};
use nix::errno::Errno;
use nix::mount::{self, MsFlags};
use nix::unistd;

/// Mount, treating EBUSY (already mounted) as success.
fn mount_or_busy(
    src: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: MsFlags,
) -> anyhow::Result<()> {
    match mount::mount(src, target, fstype, flags, None::<&str>) {
        Ok(()) => Ok(()),
        Err(Errno::EBUSY) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("mount {target}")),
    }
}

pub fn mount_filesystems() -> anyhow::Result<()> {
    let base_flags = MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_RELATIME;
    fs::create_dir_all("/dev").context("create /dev")?;
    fs::create_dir_all("/proc").context("create /proc")?;
    fs::create_dir_all("/sys").context("create /sys")?;

    mount_or_busy(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_RELATIME,
    )?;

    // Best-effort: allow nested virtualization by unprivileged processes.
    match fs::set_permissions("/dev/kvm", Permissions::from_mode(0o666)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => eprintln!("chmod(/dev/kvm): {e}"),
        _ => {}
    }

    mount_or_busy(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NODEV | base_flags,
    )?;

    mount_or_busy(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NODEV | base_flags,
    )?;

    mount_or_busy(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        MsFlags::MS_NODEV | base_flags,
    )?;

    fs::create_dir_all("/dev/pts").context("create /dev/pts")?;
    fs::create_dir_all("/dev/shm").context("create /dev/shm")?;

    mount_or_busy(Some("devpts"), "/dev/pts", Some("devpts"), base_flags)?;
    mount_or_busy(Some("tmpfs"), "/dev/shm", Some("tmpfs"), base_flags)?;

    // Best-effort; may already exist.
    let _ = unix_fs::symlink("/proc/self/fd", "/dev/fd");

    Ok(())
}

/// Returns true if path is listed as a mount point in /proc/mounts.
///
/// Uses /proc/mounts instead of stat() because Podman arranges tmpfs
/// auto-mounts that would be triggered by a stat call.
pub fn is_mount_point(path: &str) -> bool {
    let Ok(f) = File::open("/proc/mounts") else {
        return false;
    };
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        let mut parts = line.split_whitespace();
        let _ = parts.next(); // device
        if parts.next() == Some(path) {
            return true;
        }
    }
    false
}

pub fn mount_tmpfs(path: &str) -> anyhow::Result<()> {
    mount::mount(
        Some("tmpfs"),
        path,
        Some("tmpfs"),
        MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_RELATIME,
        None::<&str>,
    )
    .with_context(|| format!("mount tmpfs at {path}"))
}

/// Mount /dev/vda as ext4, then pivot root into it.
#[cfg(any(feature = "amd-sev", feature = "tdx"))]
pub fn mount_tee_block_device() -> anyhow::Result<()> {
    fs::create_dir_all("/tmp/vda").context("create /tmp/vda")?;

    mount_or_busy(
        Some("/dev/vda"),
        "/tmp/vda",
        Some("ext4"),
        MsFlags::MS_RELATIME,
    )?;
    unistd::chdir("/tmp/vda").context("chdir /tmp/vda")?;

    mount_or_busy(Some("."), "/", None::<&str>, MsFlags::MS_MOVE)?;
    unistd::chroot(".").context("chroot .")
}

/// Mount source onto target, trying each non-virtual filesystem listed in
/// /proc/filesystems when fstype is None.
pub fn try_mount(
    source: &str,
    target: &str,
    fstype: Option<&str>,
    flags: MsFlags,
    data: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(fs) = fstype {
        return mount::mount(Some(source), target, Some(fs), flags, data)
            .with_context(|| format!("mount {source} -> {target} as {fs}"));
    }

    let f = File::open("/proc/filesystems").context("open /proc/filesystems")?;
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        if line.starts_with("nodev") {
            continue;
        }
        let fs = line.trim();
        if mount::mount(Some(source), target, Some(fs), flags, data).is_ok() {
            return Ok(());
        }
    }
    bail!("no supported filesystem found for {source}")
}

/// Handle KRUN_BLOCK_ROOT_DEVICE: mount the block device at /newroot,
/// ask the virtiofs device to remove the temporary root, then pivot.
pub fn mount_block_root_device() -> anyhow::Result<()> {
    let Some(krun_root) = env::var_os("KRUN_BLOCK_ROOT_DEVICE") else {
        return Ok(());
    };
    let krun_root = krun_root.to_string_lossy().into_owned();

    fs::create_dir_all("/newroot").context("create /newroot")?;

    let fstype = env::var("KRUN_BLOCK_ROOT_FSTYPE").ok();
    let options = env::var("KRUN_BLOCK_ROOT_OPTIONS").ok();

    try_mount(
        &krun_root,
        "/newroot",
        fstype.as_deref(),
        MsFlags::empty(),
        options.as_deref(),
    )?;

    unistd::chdir("/newroot").context("chdir /newroot")?;

    mount::mount(Some("."), "/", None::<&str>, MsFlags::MS_MOVE, None::<&str>)
        .context("pivot root MS_MOVE")?;

    unistd::chroot(".").context("chroot after block root pivot")?;

    // Re-mount standard filesystems now that we're in the new root.
    mount_filesystems()?;

    Ok(())
}

pub fn mount_shared_root() -> anyhow::Result<()> {
    mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_SHARED,
        None::<&str>,
    )
    .context("set MS_SHARED on root mount")
}
