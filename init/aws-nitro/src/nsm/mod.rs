use anyhow::bail;
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver as nitro_driver;

const NSM_PCR_CHUNK_SIZE: usize = 0x800; // 2KiB
const NSM_PCR_ROOTFS: u16 = 16;
const NSM_PCR_EXEC_DATA: u16 = 17;

/// Measure the enclave execution environment {path, argv, envp} in NSM PCR 17.
///
/// NSM PCR 17 contains the measurement of the execution environment (path,
/// argv, envp).
pub fn pcr_extend_exec_path(
    nsm_fd: i32,
    path: &str,
    argv: &[String],
    envp: &[String],
) -> anyhow::Result<()> {
    // Measure the execution path.
    measure_exec_string(nsm_fd, path)?;

    // Measure each execution argument.
    for arg in argv {
        measure_exec_string(nsm_fd, arg)?;
    }

    // Measure each environment variable.
    for env in envp {
        measure_exec_string(nsm_fd, env)?;
    }

    Ok(())
}

fn measure_exec_string(fd: i32, data: &str) -> anyhow::Result<()> {
    let req = Request::ExtendPCR {
        index: NSM_PCR_EXEC_DATA,
        data: data.as_bytes().to_vec(),
    };
    let resp = nitro_driver::nsm_process_request(fd, req);
    match resp {
        Response::ExtendPCR { .. } => Ok(()),
        Response::Error(e) => bail!("failure to extend PCR {}: {:?}", NSM_PCR_EXEC_DATA, e),
        r => bail!("unexpected NSM response: {:?}", r),
    }
}

/// Extend the rootfs NSM PCR with a data block from the TAR archive
pub fn pcr_extend_rootfs(nsm_fd: i32, rootfs: &[u8]) -> anyhow::Result<()> {
    // Measure the root filesystem with NSM PCR 16. NSM PCR extension requests have a data size
    // cap of 4KiB (usually smaller than the rootfs size). Therefore, measure the rootfs in
    // 2KiB chunks.
    for chunk in rootfs.chunks(NSM_PCR_CHUNK_SIZE) {
        let req = Request::ExtendPCR {
            index: NSM_PCR_ROOTFS,
            data: chunk.to_vec(),
        };
        let resp = nitro_driver::nsm_process_request(nsm_fd, req);
        match resp {
            Response::ExtendPCR { .. } => continue,
            Response::Error(e) => bail!("failure to extend PCR {}: {:?}", NSM_PCR_ROOTFS, e),
            r => bail!("unexpected NSM response: {:?}", r),
        }
    }
    Ok(())
}

/// Lock PCRs measured by init process and close the NSM handle.
pub fn lock_and_exit(nsm_fd: i32) -> anyhow::Result<()> {
    // Lock PCRs 16 and 17 so they cannot be extended further. This is to ensure there can be
    // no further data measured other than the rootfs and execution environment.
    for index in [NSM_PCR_ROOTFS, NSM_PCR_EXEC_DATA] {
        let req = Request::LockPCR { index };
        let resp = nitro_driver::nsm_process_request(nsm_fd, req);
        match resp {
            Response::LockPCR => continue,
            Response::Error(e) => bail!("failure to lock PCR {}: {:?}", index, e),
            r => bail!("unexpected NSM response: {:?}", r),
        }
    }

    // Close the NSM device handle.
    nitro_driver::nsm_exit(nsm_fd);
    Ok(())
}
