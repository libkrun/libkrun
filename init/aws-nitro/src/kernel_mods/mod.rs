use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};

use anyhow::{Context, bail};
use nix::libc as nix_c;
use nix::unistd;

const KRUN_LINUX_MODS_DIR_NAME: &str = "/krun_linux_mods";

/// Load a kernel module.
fn load_module(path: &str) -> anyhow::Result<()> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix_c::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => bail!("unable to open kernel module {}", path),
    };

    let ret = unsafe { nix_c::syscall(nix_c::SYS_finit_module, file.as_raw_fd(), c"".as_ptr(), 0) };

    if ret < 0 {
        let os_err = io::Error::last_os_error();
        if os_err.kind() != io::ErrorKind::AlreadyExists {
            bail!("failure to init kernel module {}: {}", path, os_err);
        }
    }

    unistd::unlink(path).context("unable to unlink kernel module path")?;

    Ok(())
}

/// Load the configured kernel modules.
pub fn load_modules() -> anyhow::Result<()> {
    let entries = match fs::read_dir(KRUN_LINUX_MODS_DIR_NAME) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => bail!(
            "unable to open kernel module configuration directory {}",
            KRUN_LINUX_MODS_DIR_NAME
        ),
    };
    for entry in entries {
        let entry = entry?;
        // The full path of the module file.
        let path = format!(
            "{}/{}",
            KRUN_LINUX_MODS_DIR_NAME,
            entry
                .file_name()
                .to_str()
                .context("unable to convert kernel module name to a string")?
        );

        load_module(&path)?;
    }

    Ok(())
}
