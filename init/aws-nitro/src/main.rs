mod archive;
mod args_reader;
mod fs;
mod kernel_mods;
mod nsm;
mod proxy;

use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::time::Duration;

use anyhow::{Context, bail};
use nix::libc as nix_c;
use nix::sys::signal;
use nix::sys::wait::{self, WaitStatus};
use nix::unistd::{self, ForkResult};
use signal_hook::consts::SIGTERM;
use signal_hook::iterator::Signals;
use vsock::{VMADDR_CID_HOST, VsockAddr, VsockStream};

const VSOCK_PORT_OFFSET_ARGS_READER: u32 = 1;
const VSOCK_PORT_OFFSET_APP_RET_CODE: u32 = 4;

/// Launch the application specified with argv and envp.
fn launch(argv: Vec<String>, envp: Vec<String>) -> anyhow::Result<()> {
    // Create a new session and set the process group ID.
    let _ = unistd::setsid().context("unable to set sid")?;

    let argv_cstr: Vec<CString> = argv
        .iter()
        .map(|s| CString::new(s.trim_end_matches('\0')).unwrap())
        .collect();

    let envp_cstr: Vec<CString> = envp
        .iter()
        .map(|s| CString::new(s.trim_end_matches('\0')).unwrap())
        .collect();

    // Add the envp to the environment variables.
    let env0 = CString::new(envp[0].as_str()).context("unable to create CStr from envp[0]")?;
    let ret = unsafe { nix_c::putenv(env0.into_raw()) };
    if ret < 0 {
        bail!("unable to initialize default path environment");
    }

    unistd::execvpe(&argv_cstr[0], &argv_cstr, &envp_cstr).context("unable to call execvpe")?;

    Ok(())
}

/// Dereference and close the application output vsock.
fn close_app_output() -> anyhow::Result<()> {
    unistd::close(nix_c::STDOUT_FILENO).context("unable to close STDOUT fd")?;
    unistd::close(nix_c::STDERR_FILENO).context("unable to close STDERR fd")?;
    Ok(())
}

/// CLose and exit each device proxy.
fn exit_proxies(output_enabled: bool, shutdown_write: &OwnedFd) -> anyhow::Result<()> {
    // The shutdown value is irrelevant, it acts as a signal to all device proxy
    // threads that the enclave is exiting. Upon receiving this signal, each
    // device proxy will close their respective vsock and exit.
    unistd::write(shutdown_write, &[1]).context("unable to write to shutdown pipe")?;

    // If not in debug mode, close the application output vsock.
    if output_enabled {
        close_app_output()?;
    }

    Ok(())
}

/// Forward the application return code to the host.
fn write_app_ret(code: i32, cid: u32) -> anyhow::Result<()> {
    let vsock_port = cid + VSOCK_PORT_OFFSET_APP_RET_CODE;
    let addr = VsockAddr::new(VMADDR_CID_HOST, vsock_port);
    let mut stream = VsockStream::connect(&addr).context("unable to connect to host")?;

    // The host needs to join all device proxy threads before reading the return code. Allow some
    // time for the host to connect to the return code vsock.
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    // Write the return code.
    stream
        .write_all(&code.to_ne_bytes())
        .context("unable to write return code to host")?;

    // Read a return code (value is irrelevant) from the host. This is to ensure that the host was
    // able to read the return code from the vsock before the enclave exits.
    let mut read_code_buf = [0u8; 4];
    stream
        .read_exact(&mut read_code_buf)
        .context("unable to read return code confirmation from host")?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    // Some linux modules, like virtio-mmio, may be required for console output. Load these modules
    // immediately to ensure they are available to the initrd.
    kernel_mods::load_modules().context("unable to load linux kernel modules")?;

    // Initialize early debug output with /dev/console.
    fs::console_init().context("unable to initialize /dev/console")?;

    // Fetch the enclave VM's CID in order to calculate vsock port offsets for host communication.
    let cid = vsock::get_local_cid().context("unable to get enclave VM's CID")?;
    if cid == 0 {
        return Ok(());
    }

    // Read the enclave arguments from the host.
    let args = args_reader::read(cid + VSOCK_PORT_OFFSET_ARGS_READER)?;

    // Create a handle to the NSM.
    let nsm_fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
    if nsm_fd < 0 {
        bail!("unable to open NSM guest module");
    }

    // Measure the rootfs and execution environment in the NSM PCRs.
    nsm::pcr_extend_exec_path(nsm_fd, &args.exec_path, &args.exec_argv, &args.exec_envp)?;

    // Extract the rootfs from memory and write it to the enclave filesystem.
    archive::extract(nsm_fd, &args.rootfs_archive)?;

    // Lock NSM PCRs 16 and 17 and close NSM handle.
    nsm::lock_and_exit(nsm_fd)?;

    // Mount the root filesystem
    fs::mount_rootfs()?;

    // Initialize the rest of the filesystem.
    fs::init_filesystem()?;

    // Initialize the cgroups.
    fs::init_cgroups()?;

    let (shutdown_readp, shutdown_writep) = unistd::pipe()?;

    // Initialize each configured device proxy.
    proxy::init(cid, &args, &shutdown_readp, &shutdown_writep)?;

    match unsafe { unistd::fork()? } {
        ForkResult::Parent { child } => {
            // Initialize the shutdown handler for signals to be forwarded to the application
            // process.
            let mut signals = Signals::new([SIGTERM])?;
            std::thread::spawn(move || {
                for signal in signals.forever() {
                    if signal == SIGTERM {
                        // Send the signal to the application process.
                        let _ = signal::kill(child, signal::SIGTERM);
                    }
                }
            });

            // Wait for the application process to exit.
            let code = match wait::waitpid(child, None)? {
                // If the process was ended by a signal, the return code may
                // represent a value that under normal circumstances would
                // indicate an error. Therefore, if the application ended from
                // a signal, zero-out the return code (indicating that the
                // application process exited gracefully).
                WaitStatus::Exited(_, code) => code,
                _ => 0,
            };
            // Close and exit each device proxy.
            exit_proxies(args.app_output, &shutdown_writep)?;
            // Write the return code to the host.
            write_app_ret(code, cid)?;
        }
        ForkResult::Child => {
            // Drop the shutdown pipe's so that we don't leak them into the exec'd application.
            drop(shutdown_writep);
            drop(shutdown_readp);

            // Execute the enclave application.
            launch(args.exec_argv, args.exec_envp)?;
        }
    }

    Ok(())
}
