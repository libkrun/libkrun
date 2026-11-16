#[macro_use]
extern crate log;

use crossbeam_channel::unbounded;
#[cfg(feature = "blk")]
use devices::virtio::CacheType;
#[cfg(feature = "blk")]
use devices::virtio::block::{ImageType, SyncMode};
#[cfg(feature = "gpu")]
use devices::virtio::gpu::display::DisplayInfo;
#[cfg(feature = "net")]
use devices::virtio::net::device::VirtioNetBackend;
use env_logger::{Env, Target};
#[cfg(feature = "gpu")]
use krun_display::DisplayBackend;

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use devices::virtio::fs::virtual_entry::{VirtualDirEntry, VirtualEntry, VirtualEntryContent};
use libc::{c_char, c_int, size_t};
use once_cell::sync::Lazy;
use polly::event_manager::EventManager;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::convert::TryInto;
use std::env;
use std::ffi::CString;
use std::ffi::{CStr, c_void};
use std::fs::File;
use std::io::IsTerminal;
#[cfg(snapshot_supported)]
use std::io::Write;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::fd::{BorrowedFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::net::UnixListener;
#[cfg(windows)]
use std::os::windows::io::BorrowedHandle;
use std::path::PathBuf;
use std::slice;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, Ordering};
// Arc is used by the (Unix-only) control-socket / vsock paths and by the
// snapshot checkpoint/restore handlers (the latter now also on Windows/WHP).
#[cfg(any(not(target_os = "windows"), snapshot_supported))]
use std::sync::Arc;
use utils::eventfd::EventFd;
#[cfg(target_os = "windows")]
use utils::windows::SendHandle;
use vmm::resources::{
    DefaultVirtioConsoleConfig, PortConfig, SerialConsoleConfig, VirtioConsoleConfigMode,
    VmResources,
};
use vmm::resources::{TsiFlags, VsockConfig};
#[cfg(feature = "blk")]
use vmm::vmm_config::block::{BlockDeviceConfig, BlockRootConfig};
#[cfg(not(feature = "tee"))]
use vmm::vmm_config::external_kernel::{ExternalKernel, KernelFormat};
#[cfg(not(feature = "tee"))]
use vmm::vmm_config::firmware::FirmwareConfig;
#[cfg(not(feature = "tee"))]
use vmm::vmm_config::fs::FsDeviceConfig;
use vmm::vmm_config::kernel_bundle::KernelBundle;
#[cfg(feature = "tee")]
use vmm::vmm_config::kernel_bundle::{InitrdBundle, QbootBundle};
use vmm::vmm_config::kernel_cmdline::{DEFAULT_KERNEL_CMDLINE, KernelCmdlineConfig};
use vmm::vmm_config::machine_config::VmConfig;
#[cfg(feature = "net")]
use vmm::vmm_config::net::NetworkInterfaceConfig;
use vmm::vmm_config::vsock::VsockDeviceConfig;

#[cfg(feature = "aws-nitro")]
use aws_nitro::enclave::NitroEnclave;

#[cfg(feature = "gpu")]
use devices::virtio::display::{DisplayInfoEdid, MAX_DISPLAYS, PhysicalSize};
#[cfg(feature = "input")]
use krun_input::{InputConfigBackend, InputEventProviderBackend};

// Value returned on success. We use libc's errors otherwise.
const KRUN_SUCCESS: i32 = 0;
// Maximum number of arguments/environment variables we allow
const MAX_ARGS: usize = 4096;

thread_local! {
    // `krun_start_enter` and its error consumer run on the same thread. A
    // thread-local buffer avoids cross-talk when several VMs start in parallel.
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_last_error(message: impl Into<String>) {
    let message = message.into();
    let value = CString::new(message)
        .unwrap_or_else(|_| CString::new("libkrun error contained an interior NUL byte").unwrap());
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(value));
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

/// Returns a thread-local description of the most recent libkrun failure.
/// The pointer remains valid until the next libkrun call that updates it on
/// this thread and must not be freed by the caller.
#[unsafe(no_mangle)]
pub extern "C" fn krun_get_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(std::ptr::null(), |message| message.as_ptr())
    })
}
/// Maximum number of virtqueues allowed by virtio spec (16-bit queue index: 0-65535)
#[cfg(feature = "vhost-user")]
const VIRTIO_MAX_QUEUES: usize = 65536;

// krunfw library name for each context
#[cfg(all(target_os = "linux", not(feature = "tee")))]
const KRUNFW_NAME: &str = "libkrunfw.so.5";
#[cfg(all(target_os = "linux", feature = "amd-sev"))]
const KRUNFW_NAME: &str = "libkrunfw-sev.so.5";
#[cfg(all(target_os = "linux", feature = "tdx"))]
const KRUNFW_NAME: &str = "libkrunfw-tdx.so.5";
#[cfg(target_os = "macos")]
const KRUNFW_NAME: &str = "libkrunfw.5.dylib";
#[cfg(target_os = "windows")]
const KRUNFW_NAME: &str = "libkrunfw.dll";

#[cfg(feature = "aws-nitro")]
static KRUN_NITRO_DEBUG: Mutex<bool> = Mutex::new(false);

// Path to the init binary to be executed inside the VM.
const INIT_PATH: &str = "/init.krun";

#[cfg(all(
    feature = "init-blob",
    not(any(feature = "tee", feature = "aws-nitro"))
))]
const DEFAULT_INIT_PAYLOAD: &[u8] = init_blob::INIT_BINARY;

#[cfg(all(
    feature = "init-blob",
    not(any(feature = "tee", feature = "aws-nitro"))
))]
fn init_virtual_entry() -> VirtualDirEntry {
    VirtualDirEntry {
        name: CString::new("init.krun").unwrap(),
        entry: VirtualEntry {
            mode: 0o755,
            one_shot: true,
            content: VirtualEntryContent::File {
                data: DEFAULT_INIT_PAYLOAD,
            },
        },
    }
}

static KRUNFW: LazyLock<Option<libloading::Library>> =
    LazyLock::new(|| unsafe { libloading::Library::new(KRUNFW_NAME).ok() });

pub struct KrunfwBindings {
    get_kernel: libloading::Symbol<
        'static,
        unsafe extern "C" fn(*mut u64, *mut u64, *mut size_t) -> *mut c_char,
    >,
    #[cfg(feature = "tee")]
    get_initrd: libloading::Symbol<'static, unsafe extern "C" fn(*mut size_t) -> *mut c_char>,
    #[cfg(feature = "tee")]
    get_qboot: libloading::Symbol<'static, unsafe extern "C" fn(*mut size_t) -> *mut c_char>,
}

impl KrunfwBindings {
    fn load_bindings() -> Result<KrunfwBindings, libloading::Error> {
        let krunfw = match KRUNFW.as_ref() {
            Some(krunfw) => krunfw,
            None => return Err(libloading::Error::DlOpenUnknown),
        };
        Ok(unsafe {
            KrunfwBindings {
                get_kernel: krunfw.get(b"krunfw_get_kernel")?,
                #[cfg(feature = "tee")]
                get_initrd: krunfw.get(b"krunfw_get_initrd")?,
                #[cfg(feature = "tee")]
                get_qboot: krunfw.get(b"krunfw_get_qboot")?,
            }
        })
    }

    pub fn new() -> Option<Self> {
        Self::load_bindings().ok()
    }
}

#[derive(Default)]
struct ContextConfig {
    krunfw: Option<KrunfwBindings>,
    vmr: VmResources,
    workdir: Option<String>,
    exec_path: Option<String>,
    env: Option<String>,
    args: Option<String>,
    rlimits: Option<String>,
    net_index: u8,
    tsi_port_map: Option<HashMap<u16, u16>>,
    egress_cidrs: Option<Vec<(std::net::IpAddr, u8)>>,
    control_socket_path: Option<PathBuf>,
    vsock_config: VsockConfig,
    #[cfg(feature = "blk")]
    block_cfgs: Vec<BlockDeviceConfig>,
    #[cfg(feature = "blk")]
    block_root: Option<BlockRootConfig>,
    #[cfg(feature = "tee")]
    tee_config_file: Option<PathBuf>,
    unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
    egress_hosts: Option<Vec<String>>,
    egress_resolvers: Option<Vec<std::net::IpAddr>>,
    dns_forwarder: Option<std::net::SocketAddr>,
    stream_intercept: Option<devices::virtio::vsock::StreamIntercept>,
    shutdown_efd: Option<EventFd>,
    gpu_virgl_flags: Option<u32>,
    gpu_shm_size: Option<usize>,
    /// Console output path, only used by the aws-nitro TryFrom path.
    #[cfg(feature = "aws-nitro")]
    nitro_console_output: Option<PathBuf>,
    vmm_uid: Option<u32>,
    vmm_gid: Option<u32>,
    #[cfg(all(
        feature = "init-blob",
        not(any(feature = "tee", feature = "aws-nitro"))
    ))]
    disable_implicit_init: bool,
    /// When set, boot this VM as a fork clone from the snapshot dir (checkpoint
    /// + manifest written by a golden VM's FORK command) instead of cold boot.
    snapshot_dir: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    snapshot_memory: Option<std::fs::File>,
    #[cfg(target_os = "linux")]
    snapshot_memory_immutable: bool,
}

impl ContextConfig {
    fn set_workdir(&mut self, workdir: String) {
        self.workdir = Some(workdir);
    }

    fn get_workdir(&self) -> String {
        match &self.workdir {
            Some(workdir) => format!("KRUN_WORKDIR={workdir}"),
            None => "".to_string(),
        }
    }

    fn set_exec_path(&mut self, exec_path: String) {
        self.exec_path = Some(exec_path);
    }

    fn get_exec_path(&self) -> String {
        match &self.exec_path {
            Some(exec_path) => format!("KRUN_INIT={exec_path}"),
            None => "".to_string(),
        }
    }

    #[cfg(all(feature = "blk", not(feature = "tee")))]
    fn set_block_root(&mut self, device: String, fstype: Option<String>, options: Option<String>) {
        self.block_root = Some(BlockRootConfig {
            device,
            fstype,
            options,
        });
    }

    fn get_block_root(&self) -> String {
        #[cfg(feature = "blk")]
        match &self.block_root {
            Some(block_root) => {
                let mut res = format!("KRUN_BLOCK_ROOT_DEVICE={}", block_root.device);
                if let Some(fstype) = &block_root.fstype {
                    res += &format!(" KRUN_BLOCK_ROOT_FSTYPE={fstype}");
                }
                if let Some(options) = &block_root.options {
                    res += &format!(" KRUN_BLOCK_ROOT_OPTIONS={options}");
                }
                res
            }
            None => "".to_string(),
        }
        #[cfg(not(feature = "blk"))]
        "".to_string()
    }

    fn set_env(&mut self, env: String) {
        self.env = Some(env);
    }

    fn get_env(&self) -> String {
        match &self.env {
            Some(env) => env.clone(),
            None => "".to_string(),
        }
    }

    fn set_args(&mut self, args: String) {
        self.args = Some(args);
    }

    fn get_args(&self) -> String {
        match &self.args {
            Some(args) => args.clone(),
            None => "".to_string(),
        }
    }

    fn set_rlimits(&mut self, rlimits: String) {
        self.rlimits = Some(rlimits);
    }

    fn get_rlimits(&self) -> String {
        match &self.rlimits {
            Some(rlimits) => format!("KRUN_RLIMITS={rlimits}"),
            None => "".to_string(),
        }
    }

    #[cfg(feature = "blk")]
    fn add_block_cfg(&mut self, block_cfg: BlockDeviceConfig) {
        self.block_cfgs.push(block_cfg);
    }

    #[cfg(feature = "blk")]
    fn get_block_cfg(&self) -> Vec<BlockDeviceConfig> {
        self.block_cfgs.clone()
    }

    fn set_port_map(&mut self, new_port_map: HashMap<u16, u16>) -> Result<(), ()> {
        if self.net_index != 0 {
            return Err(());
        }

        self.tsi_port_map.replace(new_port_map);
        Ok(())
    }

    #[cfg(feature = "tee")]
    fn set_tee_config_file(&mut self, filepath: PathBuf) {
        self.tee_config_file = Some(filepath);
    }

    #[cfg(feature = "tee")]
    fn get_tee_config_file(&self) -> Option<PathBuf> {
        self.tee_config_file.clone()
    }

    fn add_vsock_port(&mut self, port: u32, filepath: PathBuf, listen: bool) {
        if let Some(map) = &mut self.unix_ipc_port_map {
            map.insert(port, (filepath, listen));
        } else {
            let mut map: HashMap<u32, (PathBuf, bool)> = HashMap::new();
            map.insert(port, (filepath, listen));
            self.unix_ipc_port_map = Some(map);
        }
    }

    fn set_gpu_virgl_flags(&mut self, virgl_flags: u32) {
        self.gpu_virgl_flags = Some(virgl_flags);
    }

    fn set_gpu_shm_size(&mut self, shm_size: usize) {
        self.gpu_shm_size = Some(shm_size);
    }

    fn set_vmm_uid(&mut self, vmm_uid: u32) {
        self.vmm_uid = Some(vmm_uid);
    }

    fn set_vmm_gid(&mut self, vmm_gid: u32) {
        self.vmm_gid = Some(vmm_gid);
    }
}

#[cfg(feature = "aws-nitro")]
impl TryFrom<ContextConfig> for NitroEnclave {
    type Error = i32;

    fn try_from(ctx: ContextConfig) -> Result<Self, Self::Error> {
        let vm_config = ctx.vmr.vm_config();

        let Some(mem_size_mib) = vm_config.mem_size_mib else {
            error!("memory size not configured");
            return Err(-libc::EINVAL);
        };

        let Some(vcpus) = vm_config.vcpu_count else {
            error!("vCPU count not configured");
            return Err(-libc::EINVAL);
        };

        let rootfs = if let Some(path) = &ctx.vmr.fs.first() {
            path.shared_dir.clone()
        } else {
            error!("rootfs path required");
            return Err(-libc::EINVAL);
        };

        let Some(exec_path) = ctx.exec_path else {
            error!("exec path not specified");
            return Err(-libc::EINVAL);
        };

        let Some(exec_env) = ctx.env else {
            error!("execution env not specified");
            return Err(-libc::EINVAL);
        };

        let Some(exec_args) = ctx.args else {
            error!("execution args not specified");
            return Err(-libc::EINVAL);
        };

        let net_unixfd = {
            let mut list = ctx.vmr.net.list;
            let len = list.len();
            match len {
                0 => None,
                1 => {
                    let device = list.pop_front().unwrap();
                    let device = device.lock().unwrap();

                    let fd = match device.cfg_backend {
                        VirtioNetBackend::UnixstreamFd(fd) => std::os::fd::RawFd::from(fd),
                        _ => return Err(libc::EINVAL),
                    };

                    Some(fd)
                }
                _ => {
                    error!(
                        "more than one network interface configured (max 1 allowed, found {len})"
                    );
                    return Err(-libc::EINVAL);
                }
            }
        };

        let Some(output_path) = ctx.nitro_console_output else {
            error!("console output path not specified");
            return Err(-libc::EINVAL);
        };

        let debug = KRUN_NITRO_DEBUG.lock().unwrap();

        Ok(Self {
            mem_size_mib,
            vcpus,
            rootfs,
            exec_path,
            exec_args,
            exec_env,
            net_unixfd,
            output_path,
            debug: *debug,
        })
    }
}

// TODO: Use this everywhere instead of the manual match
#[allow(dead_code)]
fn with_cfg(ctx_id: u32, f: impl FnOnce(&mut ContextConfig) -> i32) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => f(ctx_cfg.get_mut()),
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

static CTX_MAP: Lazy<Mutex<HashMap<u32, ContextConfig>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static CTX_IDS: AtomicI32 = AtomicI32::new(0);

/// One guest RAM region as `(gpa_start, host_va, len)`.
type GuestRamRegion = (u64, u64, u64);

/// Guest RAM regions per running context, published by `krun_start_enter` once
/// the VM's memory exists. Read by `krun_get_guest_ram` so an in-process
/// embedder can access guest memory for zero-copy transfers.
static GUEST_RAM: Lazy<Mutex<HashMap<u32, Vec<GuestRamRegion>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// An in-process VM checkpoint kept resident in the libkrun process: the
/// captured VM/vCPU/device state plus the guest-memory image. Used by the
/// control-socket CHECKPOINT/RESTORE commands to rewind a running VM without
/// serializing to disk (the same in-memory model the fork fast-path uses).
#[cfg(snapshot_supported)]
struct StashedCheckpoint {
    checkpoint: vmm::VmCheckpoint,
    // Eager byte image + region layout. NOTE: the in-process rewind (RESTORE
    // into the same, *resuming* VM) requires an eager copy of guest RAM taken at
    // checkpoint time — a CoW (`MAP_PRIVATE`) clone is NOT valid here, because
    // the resuming parent keeps writing the shared memfd and the clone would
    // observe those later writes on un-CoW'd pages (plan §4). CoW memory is for
    // *fork* (parent frozen), via `Vmm::checkpoint_cow`.
    mem_descs: Vec<vmm::snapshot::MemoryRegionDesc>,
    memory: Vec<u8>,
}

#[cfg(snapshot_supported)]
static CHECKPOINTS: Lazy<Mutex<HashMap<String, StashedCheckpoint>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// A durable checkpoint whose CPU/device boundary and immutable RAM generation
/// have been captured, but whose process-independent memory image is still
/// being serialized after the source resumes.
#[cfg(all(snapshot_supported, deferred_stream_supported))]
struct PreparedSave {
    checkpoint: vmm::VmCheckpoint,
    memory: vmm::snapshot::DeferredMemorySave,
}

#[cfg(all(snapshot_supported, deferred_stream_supported))]
mod prepared_saves;

#[cfg(all(snapshot_supported, deferred_stream_supported))]
static PREPARED_SAVES: prepared_saves::PreparedSaves<PreparedSave> =
    prepared_saves::PreparedSaves::new();

fn log_level_to_filter_str(level: u32) -> &'static str {
    match level {
        0 => "off",
        1 => "error",
        2 => "warn",
        3 => "info",
        4 => "debug",
        _ => "trace",
    }
}

#[cfg(snapshot_supported)]
fn checkpoint_failure_reply(
    error: &str,
    was_running: bool,
    resume: impl FnOnce() -> std::result::Result<(), String>,
) -> String {
    if was_running && let Err(resume_error) = resume() {
        return format!(
            "ERR EIO checkpoint failed: {error}; source resume failed: {resume_error}\n"
        );
    }
    format!("ERR EIO checkpoint failed: {error}\n")
}

/// One free page hinting round for the `HINT_FREE` control command.
#[cfg(not(feature = "tee"))]
fn hint_free_pages(balloon: &Arc<Mutex<devices::virtio::Balloon>>, timeout_ms: u64) -> String {
    let start = std::time::Instant::now();
    if let Err(e) = balloon.lock().unwrap().start_free_page_hint() {
        return format!("ERR ENOTSUP {e}\n");
    }
    let deadline = start + std::time::Duration::from_millis(timeout_ms);
    let progress = loop {
        let progress = balloon.lock().unwrap().free_page_hint_progress();
        if progress.finished || std::time::Instant::now() >= deadline {
            break progress;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    };
    balloon.lock().unwrap().finish_free_page_hint();
    format!(
        "OK hinted {} bytes in {} ms{}\n",
        progress.bytes,
        start.elapsed().as_millis(),
        if progress.finished {
            ""
        } else {
            " (timed out)"
        }
    )
}

#[cfg(snapshot_supported)]
fn handle_checkpoint(vmm: &Arc<Mutex<vmm::Vmm>>, id: &str) -> String {
    if id.is_empty() {
        return "ERR EINVAL checkpoint id required\n".to_string();
    }
    // Pauses the vCPUs + drains device workers at a clean boundary, then captures
    // state + an eager guest-RAM image (correct for rewind — see StashedCheckpoint).
    // The VM remains paused (workers re-armed) on success.
    let mut memory = Vec::new();
    // End the capture lock before attempting rollback; a match on the lock
    // expression would otherwise retain that guard through its error arm.
    let (captured, was_running) = {
        let mut machine = vmm.lock().unwrap();
        let was_running = machine.run_state() == "running";
        (machine.checkpoint(&mut memory), was_running)
    };
    let (checkpoint, mem_descs) = match captured {
        Ok(v) => v,
        Err(error) => {
            return checkpoint_failure_reply(&error.to_string(), was_running, || {
                vmm.lock()
                    .unwrap()
                    .resume()
                    .map_err(|error| error.to_string())
            });
        }
    };
    let bytes = memory.len();
    CHECKPOINTS.lock().unwrap().insert(
        id.to_string(),
        StashedCheckpoint {
            checkpoint,
            mem_descs,
            memory,
        },
    );
    format!("OK checkpointed {id} ({bytes} bytes, paused)\n")
}

#[cfg(snapshot_supported)]
fn handle_restore(vmm: &Arc<Mutex<vmm::Vmm>>, id: &str) -> String {
    if id.is_empty() {
        return "ERR EINVAL checkpoint id required\n".to_string();
    }
    let stash = match CHECKPOINTS.lock().unwrap().remove(id) {
        Some(s) => s,
        None => return format!("ERR ENOENT no checkpoint '{id}'\n"),
    };
    // Requires the VM to be paused; loads guest RAM + VM/device/vCPU state and
    // re-arms device workers. The VM stays paused — the caller sends RESUME.
    let StashedCheckpoint {
        checkpoint,
        mem_descs,
        memory,
    } = stash;
    match vmm
        .lock()
        .unwrap()
        .restore(checkpoint, &mem_descs, &mut memory.as_slice())
    {
        Ok(()) => format!("OK restored {id} (paused)\n"),
        Err(e) => format!("ERR EIO restore failed: {e}\n"),
    }
}

/// Magic for a self-contained durable snapshot manifest ("SMOLPORT").
#[cfg(snapshot_supported)]
const PORTABLE_MANIFEST_MAGIC: u64 = 0x534d4f4c504f5254;
/// Durable snapshot manifest version.
#[cfg(snapshot_supported)]
const PORTABLE_MANIFEST_VERSION: u32 = 1;

/// Serialize the layout of the eager guest-memory image. The VM/vCPU/device
/// checkpoint is stored separately in `checkpoint.bin`; `memory.bin` contains
/// region bytes in this descriptor order.
#[cfg(snapshot_supported)]
fn encode_portable_manifest(descs: &[vmm::snapshot::MemoryRegionDesc]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + descs.len() * 16);
    buf.extend_from_slice(&PORTABLE_MANIFEST_MAGIC.to_le_bytes());
    buf.extend_from_slice(&PORTABLE_MANIFEST_VERSION.to_le_bytes());
    buf.extend_from_slice(&(descs.len() as u32).to_le_bytes());
    for desc in descs {
        buf.extend_from_slice(&desc.gpa.to_le_bytes());
        buf.extend_from_slice(&desc.len.to_le_bytes());
    }
    buf
}

#[cfg(snapshot_supported)]
fn decode_portable_manifest(bytes: &[u8]) -> std::io::Result<Vec<vmm::snapshot::MemoryRegionDesc>> {
    let invalid =
        |message: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string());
    let mut offset = 0_usize;
    let take = |offset: &mut usize, len: usize| -> std::io::Result<&[u8]> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| invalid("portable manifest offset overflow"))?;
        let value = bytes
            .get(*offset..end)
            .ok_or_else(|| invalid("portable manifest truncated"))?;
        *offset = end;
        Ok(value)
    };
    let magic = u64::from_le_bytes(take(&mut offset, 8)?.try_into().unwrap());
    if magic != PORTABLE_MANIFEST_MAGIC {
        return Err(invalid("bad portable manifest magic"));
    }
    let version = u32::from_le_bytes(take(&mut offset, 4)?.try_into().unwrap());
    if version != PORTABLE_MANIFEST_VERSION {
        return Err(invalid("unsupported portable manifest version"));
    }
    let region_count = u32::from_le_bytes(take(&mut offset, 4)?.try_into().unwrap()) as usize;
    if region_count == 0 || region_count > 4096 {
        return Err(invalid("invalid portable manifest region count"));
    }
    let mut descs = Vec::with_capacity(region_count);
    let mut previous_end = 0_u64;
    let mut total_len = 0_u64;
    for _ in 0..region_count {
        let gpa = u64::from_le_bytes(take(&mut offset, 8)?.try_into().unwrap());
        let len = u64::from_le_bytes(take(&mut offset, 8)?.try_into().unwrap());
        if len == 0 {
            return Err(invalid("zero-length portable memory region"));
        }
        let end = gpa
            .checked_add(len)
            .ok_or_else(|| invalid("portable memory region address overflow"))?;
        if !descs.is_empty() && gpa < previous_end {
            return Err(invalid("overlapping or unsorted portable memory regions"));
        }
        total_len = total_len
            .checked_add(len)
            .ok_or_else(|| invalid("portable memory image length overflow"))?;
        previous_end = end;
        descs.push(vmm::snapshot::MemoryRegionDesc { gpa, len });
    }
    if offset != bytes.len() {
        return Err(invalid("portable manifest has trailing bytes"));
    }
    Ok(descs)
}

#[cfg(snapshot_supported)]
fn publish_portable_save(
    dir: &std::path::Path,
    memory: Option<File>,
    checkpoint: vmm::VmCheckpoint,
    descs: &[vmm::snapshot::MemoryRegionDesc],
    durable: bool,
) -> std::result::Result<(u64, usize), String> {
    let memory_partial = dir.join("memory.bin.partial");
    let checkpoint_partial = dir.join("checkpoint.bin.partial");
    let manifest_partial = dir.join("manifest.bin.partial");
    if let Some(memory) = memory.as_ref().filter(|_| durable) {
        memory
            .sync_all()
            .map_err(|error| format!("sync memory image: {error}"))?;
    }

    let checkpoint_bytes = checkpoint.serialize();
    let checkpoint_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&checkpoint_partial)
        .map_err(|error| format!("create checkpoint state: {error}"))?;
    (&checkpoint_file)
        .write_all(&checkpoint_bytes)
        .map_err(|error| format!("write checkpoint state: {error}"))?;
    if durable {
        checkpoint_file
            .sync_all()
            .map_err(|error| format!("sync checkpoint state: {error}"))?;
    }

    let manifest_bytes = encode_portable_manifest(descs);
    let manifest_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_partial)
        .map_err(|error| format!("create snapshot manifest: {error}"))?;
    (&manifest_file)
        .write_all(&manifest_bytes)
        .map_err(|error| format!("write snapshot manifest: {error}"))?;
    if durable {
        manifest_file
            .sync_all()
            .map_err(|error| format!("sync snapshot manifest: {error}"))?;
    }

    if memory.is_some() {
        std::fs::rename(&memory_partial, dir.join("memory.bin"))
            .map_err(|error| format!("publish memory image: {error}"))?;
    }
    std::fs::rename(&checkpoint_partial, dir.join("checkpoint.bin"))
        .map_err(|error| format!("publish checkpoint state: {error}"))?;
    // Publish the manifest last: its presence is the completeness marker.
    std::fs::rename(&manifest_partial, dir.join("manifest.bin"))
        .map_err(|error| format!("publish snapshot manifest: {error}"))?;

    Ok((vmm::snapshot::memory_image_len(descs), descs.len()))
}

/// Persist a self-contained VM checkpoint to a newly-created directory. The
/// manifest is renamed into place last, so a reader never accepts a partial
/// checkpoint. The VM remains paused on success to let the caller capture its
/// disks at the same consistency boundary; failures resume it automatically.
///
/// A durable save syncs every file before replying. Without `durable` the
/// files are complete for this host's readers but not yet on disk: the VM is
/// still paused while the reply is pending, so the sync would stall the guest
/// on the host disk's flush rate. Only a caller that resumes the VM and copies
/// the files elsewhere before discarding them should skip it.
#[cfg(snapshot_supported)]
fn handle_save(vmm: &Arc<Mutex<vmm::Vmm>>, dir: &str, durable: bool) -> String {
    if dir.is_empty() {
        return "ERR EINVAL snapshot dir required\n".to_string();
    }
    let dir = std::path::Path::new(dir);
    if let Err(error) = std::fs::create_dir(dir) {
        return format!("ERR EIO create {}: {error}\n", dir.display());
    }

    let memory_partial = dir.join("memory.bin.partial");
    let result = (|| -> std::result::Result<(u64, usize), String> {
        let mut memory = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&memory_partial)
            .map_err(|error| format!("create memory image: {error}"))?;
        #[cfg(unix)]
        let (checkpoint, descs) = vmm
            .lock()
            .unwrap()
            .checkpoint_frozen_sparse(&mut memory)
            .map_err(|error| format!("capture VM: {error}"))?;
        #[cfg(not(unix))]
        let (checkpoint, descs) = vmm
            .lock()
            .unwrap()
            .checkpoint_frozen(&mut memory)
            .map_err(|error| format!("capture VM: {error}"))?;
        publish_portable_save(dir, Some(memory), checkpoint, &descs, durable)
    })();

    match result {
        Ok((bytes, regions)) => {
            format!("OK saved ({bytes} bytes, {regions} regions, paused)\n")
        }
        Err(error) => {
            let resume_error = vmm.lock().unwrap().resume().err();
            let _ = std::fs::remove_dir_all(dir);
            match resume_error {
                Some(resume_error) => {
                    format!("ERR EIO {error}; resume after failed save: {resume_error}\n")
                }
                None => format!("ERR EIO {error}\n"),
            }
        }
    }
}

/// `SAVE` for a VM frozen as a fork base: the same self-contained checkpoint,
/// taken without resuming the VM afterwards or on failure, since its clones
/// map its RAM.
#[cfg(all(snapshot_supported, fork_supported, unix))]
fn handle_save_frozen(vmm: &Arc<Mutex<vmm::Vmm>>, dir: &str) -> String {
    if dir.is_empty() {
        return "ERR EINVAL snapshot dir required\n".to_string();
    }
    let dir = std::path::Path::new(dir);
    if let Err(error) = std::fs::create_dir(dir) {
        return format!("ERR EIO create {}: {error}\n", dir.display());
    }
    let memory_partial = dir.join("memory.bin.partial");
    let result = (|| -> std::result::Result<(u64, usize), String> {
        let mut memory = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&memory_partial)
            .map_err(|error| format!("create memory image: {error}"))?;
        let (checkpoint, descs) = vmm
            .lock()
            .unwrap()
            .checkpoint_fork_base_sparse(&mut memory)
            .map_err(|error| format!("capture VM: {error}"))?;
        publish_portable_save(dir, Some(memory), checkpoint, &descs, true)
    })();
    match result {
        Ok((bytes, regions)) => format!("OK saved ({bytes} bytes, {regions} regions, frozen)\n"),
        Err(error) => {
            let _ = std::fs::remove_dir_all(dir);
            format!("ERR EIO {error}\n")
        }
    }
}

/// Capture a durable CPU/device/RAM boundary without serializing RAM while the
/// source is paused. The caller stages disk state, resumes the VM, and then
/// sends `FINISH_SAVE` to write the retained generation.
#[cfg(all(snapshot_supported, deferred_stream_supported))]
fn handle_prepare_save(vmm: &Arc<Mutex<vmm::Vmm>>, dir: &str, held: bool) -> String {
    if dir.is_empty() {
        return "ERR EINVAL snapshot dir required\n".to_string();
    }
    let Some(preparation) = PREPARED_SAVES.reserve(dir) else {
        return "ERR EBUSY another durable save is still pending\n".to_string();
    };
    let dir_path = std::path::PathBuf::from(dir);
    if let Err(error) = std::fs::create_dir(&dir_path) {
        return format!("ERR EIO create {}: {error}\n", dir_path.display());
    }

    let capture = {
        let mut vmm = vmm.lock().unwrap();
        if held {
            vmm.checkpoint_frozen_held_sparse(&dir_path)
        } else {
            vmm.checkpoint_frozen_deferred_sparse(&dir_path)
        }
    };
    let (checkpoint, memory) = match capture {
        Ok(capture) => capture,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&dir_path);
            let message = error.to_string();
            if message.contains("deferred durable save requires") {
                return format!("ERR ENOTSUP {message}\n");
            }
            return format!("ERR EIO capture VM: {message}\n");
        }
    };
    preparation.publish(PreparedSave { checkpoint, memory });
    "OK prepared (paused)\n".to_string()
}

/// Until the paused-state reply is delivered, the caller cannot own cleanup.
/// A failed prepare does not transfer that ownership in the first place.
#[cfg(all(snapshot_supported, deferred_stream_supported))]
fn write_prepared_save_reply(
    stream: &mut impl Write,
    response: &str,
    recover: impl FnOnce(),
) -> std::io::Result<()> {
    let result = stream.write_all(response.as_bytes());
    if result.is_err() && response == "OK prepared (paused)\n" {
        recover();
    }
    result
}

#[cfg(all(snapshot_supported, deferred_stream_supported))]
fn handle_finish_save(dir: &str) -> String {
    let dir_path = std::path::Path::new(dir);
    let Some(result) = PREPARED_SAVES.finish(
        dir,
        |prepared| -> std::result::Result<(u64, usize), String> {
            let memory_partial = dir_path.join("memory.bin.partial");
            let mut memory = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&memory_partial)
                .map_err(|error| format!("create memory image: {error}"))?;
            let descs = prepared
                .memory
                .finish(&mut memory)
                .map_err(|error| format!("serialize retained RAM generation: {error}"))?;
            publish_portable_save(dir_path, Some(memory), prepared.checkpoint, &descs, true)
        },
    ) else {
        return "ERR ENOENT no prepared durable save\n".to_string();
    };
    match result {
        Ok((bytes, regions)) => format!("OK saved ({bytes} bytes, {regions} regions)\n"),
        Err(error) => {
            let _ = std::fs::remove_dir_all(dir_path);
            format!("ERR EIO {error}\n")
        }
    }
}

#[cfg(all(snapshot_supported, deferred_stream_supported))]
fn handle_finish_save_stream<W: Write>(dir: &str, stream: &mut W) -> String {
    let Some(result) = PREPARED_SAVES.finish(dir, |prepared| {
        prepared
            .memory
            .finish_stream(stream)
            .map_err(|error| format!("stream retained RAM: {error}"))
            .and_then(|descs| {
                publish_portable_save(
                    std::path::Path::new(dir),
                    None,
                    prepared.checkpoint,
                    &descs,
                    true,
                )
            })
    }) else {
        return "ERR ENOENT no prepared durable save\n".to_string();
    };
    match result {
        Ok((bytes, regions)) => format!("OK saved ({bytes} bytes, {regions} regions)\n"),
        Err(error) => format!("ERR EIO {error}\n"),
    }
}

/// Metadata is a captured-state handoff, not a durable completion marker.
/// The final reply follows successful RAM output and metadata persistence.
#[cfg(all(
    snapshot_supported,
    any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
fn handle_finish_save_sparse<W: Write + AsRawFd>(dir: &str, stream: &mut W) -> String {
    let Some(result) = PREPARED_SAVES.finish(dir, |prepared| {
        let state = prepared.checkpoint.serialize();
        #[cfg(target_os = "linux")]
        let socket = stream.as_raw_fd();
        let write_header = |descs: &[vmm::snapshot::MemoryRegionDesc], output: &mut W| {
            let layout = encode_portable_manifest(descs);
            write_checkpoint_stream_header(output, &state, &layout)
        };
        #[cfg(target_os = "linux")]
        let saved = prepared.memory.finish_sparse_stream_with_header_to_socket(
            stream,
            socket,
            write_header,
        );
        #[cfg(target_os = "macos")]
        let saved = prepared
            .memory
            .finish_sparse_stream_with_header(stream, write_header);
        saved
            .map_err(|error| format!("stream sparse retained RAM: {error}"))
            .and_then(|descs| {
                publish_portable_save(
                    std::path::Path::new(dir),
                    None,
                    prepared.checkpoint,
                    &descs,
                    true,
                )
            })
    }) else {
        return "ERR ENOENT no prepared durable save\n".to_string();
    };
    match result {
        Ok((bytes, regions)) => format!("OK saved ({bytes} bytes, {regions} regions)\n"),
        Err(error) => format!("ERR EIO {error}\n"),
    }
}

#[cfg(all(
    snapshot_supported,
    any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )
))]
fn write_checkpoint_stream_header(
    output: &mut impl Write,
    state: &[u8],
    layout: &[u8],
) -> std::io::Result<()> {
    const MAX_STATE: usize = 16 * 1024 * 1024;
    const MAX_LAYOUT: usize = 1024 * 1024;
    if state.is_empty() || layout.is_empty() || state.len() > MAX_STATE || layout.len() > MAX_LAYOUT
    {
        return Err(std::io::Error::other(
            "checkpoint stream metadata exceeds bounds",
        ));
    }
    output.write_all(b"SMOLCKS1")?;
    output.write_all(&(state.len() as u32).to_le_bytes())?;
    output.write_all(&(layout.len() as u32).to_le_bytes())?;
    output.write_all(state)?;
    output.write_all(layout)
}

#[cfg(all(snapshot_supported, deferred_stream_supported))]
fn handle_cancel_save(dir: &str) -> String {
    if PREPARED_SAVES.cancel(dir) {
        let _ = std::fs::remove_dir_all(dir);
        "OK canceled\n".to_string()
    } else {
        "ERR ENOENT save is finishing or does not exist\n".to_string()
    }
}

#[cfg(all(snapshot_supported, deferred_stream_supported))]
/// The live virtio-fs device named by the first word of `arg`, and the rest.
#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    not(any(feature = "tee", feature = "aws-nitro"))
))]
fn live_device(
    arg: &str,
) -> Result<
    (
        std::sync::Arc<devices::virtio::fs::live_fs::LiveShares>,
        &str,
    ),
    String,
> {
    let mut parts = arg.splitn(2, char::is_whitespace);
    let tag = parts.next().unwrap_or("");
    let rest = parts.next().map(str::trim_start).unwrap_or("");
    match devices::virtio::fs::live_fs::live_shares(tag) {
        Some(shares) => Ok((shares, rest)),
        None if tag.is_empty() => Err("ERR EINVAL live device tag required\n".to_string()),
        None => Err(format!("ERR ENOENT no live virtio-fs device {tag}\n")),
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    not(any(feature = "tee", feature = "aws-nitro"))
))]
fn handle_share_add(arg: &str) -> String {
    let (shares, rest) = match live_device(arg) {
        Ok(device) => device,
        Err(reply) => return reply,
    };
    let mut parts = rest.splitn(2, char::is_whitespace);
    let name = parts.next().unwrap_or("");
    let path = parts.next().map(str::trim_start).unwrap_or("");
    if name.is_empty() || path.is_empty() {
        return "ERR EINVAL usage: SHARE_ADD <tag> <name> <host dir>\n".to_string();
    }
    if path.chars().any(char::is_control) {
        return "ERR EINVAL share path contains a control character\n".to_string();
    }
    match shares.attach(name, std::path::Path::new(path)) {
        Ok(_) => format!("OK attached {name}\n"),
        Err(error) => format!("ERR EINVAL {error}\n"),
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    not(any(feature = "tee", feature = "aws-nitro"))
))]
fn handle_share_remove(arg: &str) -> String {
    let (shares, name) = match live_device(arg) {
        Ok(device) => device,
        Err(reply) => return reply,
    };
    let name = name.trim();
    if name.is_empty() {
        return "ERR EINVAL usage: SHARE_REMOVE <tag> <name>\n".to_string();
    }
    match shares.detach(name) {
        Ok(()) => format!("OK detached {name}\n"),
        Err(error) => format!("ERR ENOENT {error}\n"),
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    not(any(feature = "tee", feature = "aws-nitro"))
))]
fn handle_share_list(arg: &str) -> String {
    let (shares, _) = match live_device(arg) {
        Ok(device) => device,
        Err(reply) => return reply,
    };
    let listed: Vec<String> = shares
        .list()
        .into_iter()
        .map(|(name, path)| format!("{name}={}", path.display()))
        .collect();
    format!("OK {}\n", listed.join("\t"))
}

#[cfg(all(snapshot_supported, deferred_stream_supported))]
fn handle_save_status(dir: &str) -> String {
    if dir.is_empty() {
        return "ERR EINVAL snapshot dir required\n".to_string();
    }
    // This reports retained RAM ownership, never artifact durability.
    let state = match PREPARED_SAVES.status(dir) {
        Some(prepared_saves::Status::Preparing) => "preparing",
        Some(prepared_saves::Status::Ready) => "ready",
        Some(prepared_saves::Status::Finishing) => "finishing",
        None => "memory_released",
    };
    format!("OK {state}\n")
}

/// Magic for the fork manifest ("SMOLFORK").
#[cfg(fork_supported)]
const FORK_MANIFEST_MAGIC: u64 = 0x534d4f4c464f524b;

/// Magic for a guardian-backed fork manifest ("SMOLGRDN").
#[cfg(all(fork_supported, target_os = "linux"))]
const GUARDIAN_MANIFEST_MAGIC: u64 = 0x534d4f4c4752444e;
#[cfg(all(fork_supported, target_os = "linux"))]
const GUARDIAN_MANIFEST_VERSION: u32 = 1;
#[cfg(all(
    fork_supported,
    fork_continue_supported,
    target_os = "linux",
    any(feature = "blk", test)
))]
const GUARDIAN_SOCKET_NAME: &str = "g";

#[cfg(fork_supported)]
fn atomic_write_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "output path has no file name",
        )
    })?;
    let partial = path.with_file_name(format!("{}.partial", file_name.to_string_lossy()));
    let mut published = false;
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::hard_link(&partial, path)?;
        published = true;
        let _ = std::fs::remove_file(&partial);
        // Windows does not allow File::open on a directory. The data file was
        // flushed before its hard link became visible; NTFS journals the link.
        #[cfg(not(target_os = "windows"))]
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        if published {
            let _ = std::fs::remove_file(path);
        }
        let _ = std::fs::remove_file(&partial);
    }
    result
}

/// Serialize the fork manifest: owner pid + guest-RAM region descriptors
/// (gpa/len/memfd-fd/offset + backing-file path) so a clone can reach the
/// backing RAM — via `/proc/<pid>/fd` on Linux, or the file path on macOS.
#[cfg(fork_supported)]
fn write_fork_manifest(
    path: &std::path::Path,
    owner_pid: i32,
    descs: &[vmm::snapshot::MemfdRegionDesc],
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&FORK_MANIFEST_MAGIC.to_le_bytes());
    buf.extend_from_slice(&owner_pid.to_le_bytes());
    buf.extend_from_slice(&(descs.len() as u32).to_le_bytes());
    for d in descs {
        buf.extend_from_slice(&d.gpa.to_le_bytes());
        buf.extend_from_slice(&d.len.to_le_bytes());
        buf.extend_from_slice(&d.fd.to_le_bytes());
        buf.extend_from_slice(&d.offset.to_le_bytes());
        let pb = d.path.as_bytes();
        buf.extend_from_slice(&(pb.len() as u32).to_le_bytes());
        buf.extend_from_slice(pb);
    }
    atomic_write_file(path, &buf)
}

/// Parse a manifest written by [`write_fork_manifest`].
#[cfg(fork_supported)]
fn read_fork_manifest(
    path: &std::path::Path,
) -> std::io::Result<(i32, Vec<vmm::snapshot::MemfdRegionDesc>)> {
    let b = std::fs::read(path)?;
    let err = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
    let mut p = 0usize;
    let take = |b: &[u8], p: &mut usize, n: usize| -> std::io::Result<Vec<u8>> {
        if *p + n > b.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "fork manifest truncated",
            ));
        }
        let s = b[*p..*p + n].to_vec();
        *p += n;
        Ok(s)
    };
    let magic = u64::from_le_bytes(take(&b, &mut p, 8)?.try_into().unwrap());
    if magic != FORK_MANIFEST_MAGIC {
        return Err(err("bad fork manifest magic"));
    }
    let owner_pid = i32::from_le_bytes(take(&b, &mut p, 4)?.try_into().unwrap());
    let n = u32::from_le_bytes(take(&b, &mut p, 4)?.try_into().unwrap()) as usize;
    let mut descs = Vec::with_capacity(n);
    for _ in 0..n {
        let gpa = u64::from_le_bytes(take(&b, &mut p, 8)?.try_into().unwrap());
        let len = u64::from_le_bytes(take(&b, &mut p, 8)?.try_into().unwrap());
        let fd = i32::from_le_bytes(take(&b, &mut p, 4)?.try_into().unwrap());
        let offset = u64::from_le_bytes(take(&b, &mut p, 8)?.try_into().unwrap());
        let plen = u32::from_le_bytes(take(&b, &mut p, 4)?.try_into().unwrap()) as usize;
        let path = String::from_utf8(take(&b, &mut p, plen)?)
            .map_err(|_| err("fork manifest: non-UTF8 region path"))?;
        descs.push(vmm::snapshot::MemfdRegionDesc {
            gpa,
            len,
            fd,
            offset,
            path,
        });
    }
    Ok((owner_pid, descs))
}

#[cfg(all(
    fork_supported,
    target_os = "linux",
    any(test, all(fork_continue_supported, feature = "blk"))
))]
fn write_guardian_manifest(
    path: &std::path::Path,
    desc: &vmm::generation_guardian::GuardianGenerationDesc,
) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let socket = desc.socket_path.as_os_str().as_bytes();
    let socket_len = u32::try_from(socket.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "guardian socket path is too long",
        )
    })?;
    let region_count = u32::try_from(desc.regions.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "too many RAM regions")
    })?;
    let mut bytes = Vec::with_capacity(72 + socket.len() + desc.regions.len() * 16);
    bytes.extend_from_slice(&GUARDIAN_MANIFEST_MAGIC.to_le_bytes());
    bytes.extend_from_slice(&GUARDIAN_MANIFEST_VERSION.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&desc.guardian_pid.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&desc.guardian_start_time.to_le_bytes());
    bytes.extend_from_slice(&socket_len.to_le_bytes());
    bytes.extend_from_slice(&region_count.to_le_bytes());
    bytes.extend_from_slice(&desc.token);
    bytes.extend_from_slice(socket);
    for region in &desc.regions {
        bytes.extend_from_slice(&region.gpa.to_le_bytes());
        bytes.extend_from_slice(&region.len.to_le_bytes());
    }
    atomic_write_file(path, &bytes)
}

#[cfg(all(fork_supported, target_os = "linux"))]
fn read_guardian_manifest(
    path: &std::path::Path,
) -> std::io::Result<vmm::generation_guardian::GuardianGenerationDesc> {
    use std::os::unix::ffi::OsStringExt;

    let bytes = std::fs::read(path)?;
    let invalid =
        |message: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string());
    let mut offset = 0_usize;
    let take = |offset: &mut usize, length: usize| -> std::io::Result<&[u8]> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| invalid("guardian manifest offset overflow"))?;
        let value = bytes
            .get(*offset..end)
            .ok_or_else(|| invalid("guardian manifest is truncated"))?;
        *offset = end;
        Ok(value)
    };
    let magic = u64::from_le_bytes(take(&mut offset, 8)?.try_into().unwrap());
    if magic != GUARDIAN_MANIFEST_MAGIC {
        return Err(invalid("bad guardian manifest magic"));
    }
    let version = u32::from_le_bytes(take(&mut offset, 4)?.try_into().unwrap());
    if version != GUARDIAN_MANIFEST_VERSION {
        return Err(invalid("unsupported guardian manifest version"));
    }
    let flags = u32::from_le_bytes(take(&mut offset, 4)?.try_into().unwrap());
    if flags != 0 {
        return Err(invalid("guardian manifest has unsupported flags"));
    }
    let guardian_pid = i32::from_le_bytes(take(&mut offset, 4)?.try_into().unwrap());
    let reserved = u32::from_le_bytes(take(&mut offset, 4)?.try_into().unwrap());
    if guardian_pid <= 0 || reserved != 0 {
        return Err(invalid("guardian manifest has invalid process metadata"));
    }
    let guardian_start_time = u64::from_le_bytes(take(&mut offset, 8)?.try_into().unwrap());
    if guardian_start_time == 0 {
        return Err(invalid("guardian manifest has zero process start time"));
    }
    let socket_len = u32::from_le_bytes(take(&mut offset, 4)?.try_into().unwrap()) as usize;
    let region_count = u32::from_le_bytes(take(&mut offset, 4)?.try_into().unwrap()) as usize;
    // The manifest stores the original filesystem path, not the short alias
    // used to fit sockaddr_un when connecting to a deep socket directory.
    if socket_len == 0
        || socket_len >= libc::PATH_MAX as usize
        || region_count == 0
        || region_count > 256
    {
        return Err(invalid("guardian manifest has invalid dimensions"));
    }
    let mut token = [0_u8; 32];
    token.copy_from_slice(take(&mut offset, 32)?);
    if token.iter().all(|byte| *byte == 0) {
        return Err(invalid("guardian manifest has an empty token"));
    }
    let socket_path = std::path::PathBuf::from(std::ffi::OsString::from_vec(
        take(&mut offset, socket_len)?.to_vec(),
    ));
    if !socket_path.is_absolute() {
        return Err(invalid("guardian socket path must be absolute"));
    }
    let mut regions = Vec::with_capacity(region_count);
    let mut previous_end = 0_u64;
    for index in 0..region_count {
        let gpa = u64::from_le_bytes(take(&mut offset, 8)?.try_into().unwrap());
        let len = u64::from_le_bytes(take(&mut offset, 8)?.try_into().unwrap());
        let end = gpa
            .checked_add(len)
            .ok_or_else(|| invalid("guardian RAM region address overflow"))?;
        if len == 0 || len % 4096 != 0 || (index > 0 && gpa < previous_end) {
            return Err(invalid("guardian RAM regions are invalid or overlapping"));
        }
        regions.push(vmm::demand_paging::DemandPageRegion { gpa, len });
        previous_end = end;
    }
    if offset != bytes.len() {
        return Err(invalid("guardian manifest has trailing bytes"));
    }
    Ok(vmm::generation_guardian::GuardianGenerationDesc {
        guardian_pid,
        guardian_start_time,
        socket_path,
        token,
        regions,
    })
}

#[cfg(fork_supported)]
fn rollback_failed_fork(
    vmm: &Arc<Mutex<vmm::Vmm>>,
    dir: &std::path::Path,
    checkpoint: vmm::VmCheckpoint,
    failure: String,
) -> String {
    let recovery_checkpoint = checkpoint.serialize();
    if let Err(error) = vmm.lock().unwrap().rollback_fork_checkpoint(checkpoint) {
        let recovery = match std::fs::write(dir.join("checkpoint.bin"), recovery_checkpoint) {
            Ok(()) => format!("checkpoint preserved at {}", dir.display()),
            Err(write_error) => format!(
                "checkpoint preservation at {} failed: {write_error}",
                dir.display()
            ),
        };
        return format!("ERR EIO {failure}; rollback failed: {error}; {recovery}\n");
    }

    let mut cleanup_errors = Vec::new();
    for name in ["checkpoint.bin", "manifest.bin"] {
        if let Err(error) = std::fs::remove_file(dir.join(name))
            && error.kind() != std::io::ErrorKind::NotFound
        {
            cleanup_errors.push(format!("remove {name}: {error}"));
        }
    }

    if cleanup_errors.is_empty() {
        format!("ERR EIO {failure}\n")
    } else {
        format!(
            "ERR EIO {failure}; rollback succeeded but cleanup failed: {}\n",
            cleanup_errors.join(", ")
        )
    }
}

#[cfg(fork_supported)]
fn handle_fork(vmm: &Arc<Mutex<vmm::Vmm>>, dir: &str) -> String {
    if dir.is_empty() {
        return "ERR EINVAL fork snapshot dir required\n".to_string();
    }
    let dir = std::path::Path::new(dir);
    if let Err(e) = std::fs::create_dir_all(dir) {
        return format!("ERR EIO create {}: {e}\n", dir.display());
    }
    // Clones will map this VMM's live RAM files, so no balloon release may
    // punch them from here on, even when this fork fails.
    #[cfg(not(feature = "tee"))]
    devices::virtio::balloon::mark_guest_ram_shared();
    // Capture + freeze (the VM stays paused as the CoW base).
    let (checkpoint, memory) = match vmm.lock().unwrap().checkpoint_for_fork() {
        Ok(v) => v,
        Err(vmm::Error::ForkRequiresMemfd) => {
            return "ERR EINVAL no memfd-backed RAM (start the golden VM with SMOLVM_FORKABLE=1)\n"
                .to_string();
        }
        Err(e) => return format!("ERR EIO fork checkpoint failed: {e}\n"),
    };
    if let Err(e) = std::fs::write(dir.join("checkpoint.bin"), checkpoint.serialize()) {
        return rollback_failed_fork(vmm, dir, checkpoint, format!("write checkpoint: {e}"));
    }
    let pid = std::process::id() as i32;
    let (regions, written) = match memory {
        vmm::ForkMemory::Mapped(descs) => (
            descs.len(),
            write_fork_manifest(&dir.join("manifest.bin"), pid, &descs),
        ),
        #[cfg(target_os = "linux")]
        vmm::ForkMemory::Layered(generation) => (
            generation.memory_regions().len(),
            publish_layered_manifest(vmm, &generation, dir),
        ),
    };
    if let Err(e) = written {
        return rollback_failed_fork(vmm, dir, checkpoint, format!("write manifest: {e}"));
    }
    format!("OK forked (frozen base, pid {pid}, {} regions)\n", regions)
}

#[cfg(all(fork_supported, fork_continue_supported, feature = "blk"))]
fn read_fork_block_pivots(dir: &std::path::Path) -> std::io::Result<Vec<(String, String)>> {
    let contents = std::fs::read_to_string(dir.join("block-pivots.tsv"))?;
    let mut pivots = Vec::new();
    for (line_number, line) in contents.lines().enumerate() {
        let (id, path) = line.split_once('\t').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("block pivot line {} needs id<TAB>path", line_number + 1),
            )
        })?;
        if id.is_empty() || path.is_empty() || path.contains('\0') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid block pivot line {}", line_number + 1),
            ));
        }
        let path = std::path::Path::new(path).canonicalize()?;
        pivots.push((id.to_string(), path.to_string_lossy().into_owned()));
    }
    if pivots.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "at least one block pivot is required",
        ));
    }
    Ok(pivots)
}

/// Create an immutable RAM + disk generation while the same source VMM
/// continues on private writable layers.
#[cfg(all(fork_supported, fork_continue_supported, feature = "blk"))]
fn handle_fork_continue(vmm: &Arc<Mutex<vmm::Vmm>>, dir: &str) -> String {
    handle_fork_continue_inner(vmm, dir, false)
}

/// Guardian-backed variant. The first generation can still use the source's
/// immutable memfd directly; later generations retain the exact private source
/// view in a kernel-COW guardian and can be demand-paged by clones.
#[cfg(all(
    fork_supported,
    target_os = "linux",
    target_arch = "x86_64",
    feature = "blk"
))]
fn handle_fork_continue_paged(vmm: &Arc<Mutex<vmm::Vmm>>, dir: &str) -> String {
    handle_fork_continue_inner(vmm, dir, true)
}

#[cfg(all(fork_supported, fork_continue_supported, feature = "blk"))]
fn handle_fork_continue_inner(vmm: &Arc<Mutex<vmm::Vmm>>, dir: &str, demand_paged: bool) -> String {
    #[cfg(target_os = "macos")]
    let _ = demand_paged;
    if dir.is_empty() {
        return "ERR EINVAL fork snapshot dir required\n".to_string();
    }
    let dir = std::path::Path::new(dir);
    if let Err(error) = std::fs::create_dir_all(dir) {
        return format!("ERR EIO create {}: {error}\n", dir.display());
    }
    let block_pivots = match read_fork_block_pivots(dir) {
        Ok(pivots) => pivots,
        Err(error) => return format!("ERR EINVAL read block pivots: {error}\n"),
    };
    #[cfg(target_os = "linux")]
    // The snapshot directory already carries an unpredictable generation id;
    // keep the socket basename minimal so a cache path that can host agent.sock
    // does not fail only on its second live branch at sockaddr_un's much lower
    // path ceiling.
    let guardian_socket = demand_paged.then(|| dir.join(GUARDIAN_SOCKET_NAME));
    #[cfg(target_os = "macos")]
    let guardian_socket: Option<std::path::PathBuf> = None;
    let commit_marker = dir.join("source-continues-v1");
    let (checkpoint, generation) = match vmm.lock().unwrap().checkpoint_for_fork_continue(
        &block_pivots,
        guardian_socket.as_deref(),
        &commit_marker,
    ) {
        Ok(value) => value,
        Err(vmm::Error::ForkRequiresMemfd) => {
            return "ERR EINVAL no memfd-backed RAM (start the VM with SMOLVM_FORKABLE=1)\n"
                .to_string();
        }
        Err(error) => return format!("ERR EIO fork-continue checkpoint failed: {error}\n"),
    };
    if let Err(error) = atomic_write_file(&dir.join("checkpoint.bin"), &checkpoint.serialize()) {
        return format!("ERR EIO write checkpoint: {error}; source already resumed\n");
    }
    match generation {
        #[cfg(target_os = "linux")]
        vmm::ForkContinueRamGeneration::Layered(generation) => {
            if let Err(error) = publish_layered_manifest(vmm, &generation, dir) {
                let _ = std::fs::remove_file(dir.join("checkpoint.bin"));
                return format!(
                    "ERR EIO write layered manifest: {error}; source already resumed\n"
                );
            }
            format!(
                "OK forked generation (running source, layered RAM, {} regions, {} disks)\n",
                generation.memory_regions().len(),
                block_pivots.len()
            )
        }
        vmm::ForkContinueRamGeneration::Mapped(descs) => {
            let pid = std::process::id() as i32;
            if let Err(error) = write_fork_manifest(&dir.join("manifest.bin"), pid, &descs) {
                let _ = std::fs::remove_file(dir.join("checkpoint.bin"));
                return format!("ERR EIO write manifest: {error}; source already resumed\n");
            }
            format!(
                "OK forked generation (running source, memfd pid {pid}, {} regions, {} disks)\n",
                descs.len(),
                block_pivots.len()
            )
        }
        #[cfg(target_os = "linux")]
        vmm::ForkContinueRamGeneration::Guardian(guardian) => {
            let desc = guardian.description();
            if let Err(error) = write_guardian_manifest(&dir.join("manifest.bin"), desc) {
                let _ = std::fs::remove_file(dir.join("checkpoint.bin"));
                return format!(
                    "ERR EIO write guardian manifest: {error}; source already resumed\n"
                );
            }
            let region_count = desc.regions.len();
            let guardian_pid = desc.guardian_pid;
            guardian.disarm();
            format!(
                "OK forked generation (running source, guardian pid {guardian_pid}, {region_count} regions, {} disks)\n",
                block_pivots.len()
            )
        }
    }
}

#[cfg(all(fork_supported, target_os = "linux"))]
fn publish_layered_manifest(
    vmm: &Arc<Mutex<vmm::Vmm>>,
    generation: &vmm::layered_restore::Generation,
    dir: &std::path::Path,
) -> std::io::Result<()> {
    let (bytes, service) = generation.publish_manifest(&dir.join("f"))?;
    let manifest = dir.join("manifest.bin");
    atomic_write_file(&manifest, &bytes)?;
    if let Err(error) = vmm.lock().unwrap().retain_layered_export(service) {
        let _ = std::fs::remove_file(manifest);
        return Err(error);
    }
    Ok(())
}

#[cfg(fork_supported)]
fn handle_rollback_fork(vmm: &Arc<Mutex<vmm::Vmm>>, dir: &str) -> String {
    if dir.is_empty() {
        return "ERR EINVAL fork snapshot dir required\n".to_string();
    }
    let checkpoint_path = std::path::Path::new(dir).join("checkpoint.bin");
    let bytes = match std::fs::read(&checkpoint_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return format!(
                "ERR EIO read rollback checkpoint {}: {error}\n",
                checkpoint_path.display()
            );
        }
    };
    let checkpoint = match vmm::VmCheckpoint::deserialize(&bytes) {
        Ok(checkpoint) => checkpoint,
        Err(error) => return format!("ERR EINVAL decode rollback checkpoint: {error}\n"),
    };
    match vmm.lock().unwrap().rollback_fork_checkpoint(checkpoint) {
        Ok(()) => "OK running\n".to_string(),
        Err(error) => format!("ERR EIO rollback fork: {error}\n"),
    }
}

/// Build a [`vmm::builder::RestoreCtx`] from a fork snapshot directory: parse the
/// manifest, CoW-map the golden VM's guest RAM (Linux: via `/proc/<pid>/fd`;
/// macOS: by the backing-file path recorded in the manifest), and load the
/// serialized checkpoint.
#[cfg(all(fork_supported, any(test, not(target_os = "linux"))))]
fn build_restore_ctx(
    dir: &std::path::Path,
) -> std::result::Result<vmm::builder::RestoreCtx, String> {
    build_restore_ctx_with_memory(dir, None, false)
}

#[cfg(fork_supported)]
fn build_restore_ctx_with_memory(
    dir: &std::path::Path,
    readonly_memory: Option<&std::fs::File>,
    immutable: bool,
) -> std::result::Result<vmm::builder::RestoreCtx, String> {
    let layered_requested = cfg!(target_os = "linux")
        && immutable
        && std::env::var_os("SMOLVM_FORKABLE").is_some_and(|value| value == "1");
    build_restore_ctx_with_memory_mode(dir, readonly_memory, layered_requested)
}

#[cfg(fork_supported)]
fn build_restore_ctx_with_memory_mode(
    dir: &std::path::Path,
    readonly_memory: Option<&std::fs::File>,
    _layered_requested: bool,
) -> std::result::Result<vmm::builder::RestoreCtx, String> {
    let manifest_path = dir.join("manifest.bin");
    let manifest = std::fs::read(&manifest_path).map_err(|e| format!("manifest: {e}"))?;
    let magic_bytes = manifest
        .get(..8)
        .ok_or_else(|| "manifest: truncated".to_string())?;
    let magic = u64::from_le_bytes(magic_bytes.try_into().unwrap());
    if readonly_memory.is_some() && magic != PORTABLE_MANIFEST_MAGIC {
        return Err("read-only memory input requires a portable snapshot".into());
    }
    #[cfg(target_os = "linux")]
    if magic_bytes == vmm::layered_restore::MANIFEST_MAGIC {
        let generation = vmm::layered_restore::Generation::decode_manifest(&manifest)
            .map_err(|error| format!("layered RAM manifest: {error}"))?;
        let guest_memory = generation
            .restore()
            .map_err(|error| format!("map layered RAM: {error}"))?;
        let count = generation.memory_regions().len();
        let checkpoint = std::fs::read(dir.join("checkpoint.bin"))
            .map_err(|error| format!("checkpoint: {error}"))?;
        return Ok(vmm::builder::RestoreCtx {
            demand_pager: None,
            layered_ram: Some(generation),
            guest_memory,
            fork_backed_regions: vec![true; count],
            checkpoint,
            portable_clock: false,
            #[cfg(target_os = "linux")]
            cow_backing: Vec::new(),
        });
    }
    if magic == PORTABLE_MANIFEST_MAGIC {
        let descs = decode_portable_manifest(&manifest).map_err(|e| format!("manifest: {e}"))?;
        let checkpoint =
            std::fs::read(dir.join("checkpoint.bin")).map_err(|e| format!("checkpoint: {e}"))?;
        let memory_path = dir.join("memory.bin");
        let memory_file = if let Some(_file) = readonly_memory {
            #[cfg(target_os = "linux")]
            if std::env::var_os("SMOLVM_FORKABLE").is_none_or(|value| value != "1") {
                return Err("read-only restore memory requires Linux forkable promotion".into());
            }
            #[cfg(not(target_os = "linux"))]
            return Err("read-only restore memory is unsupported on this platform".into());
            #[cfg(target_os = "linux")]
            _file
                .try_clone()
                .map_err(|e| format!("duplicate memory input: {e}"))?
        } else {
            // Layered restore keeps this descriptor as the immutable branch
            // base. Never retain a writable capability for later handoff;
            // legacy restore paths still require their writable mapping.
            std::fs::OpenOptions::new()
                .read(true)
                .write(!_layered_requested)
                .open(&memory_path)
                .map_err(|e| format!("memory: {e}"))?
        };
        let actual_memory_len = memory_file
            .metadata()
            .map_err(|e| format!("memory metadata: {e}"))?
            .len();
        let expected_memory_len = vmm::snapshot::memory_image_len(&descs);
        if actual_memory_len != expected_memory_len {
            return Err(format!(
                "memory: image length {actual_memory_len} does not match manifest {expected_memory_len}"
            ));
        }
        #[cfg(target_os = "linux")]
        let layered_ram = if _layered_requested {
            Some(
                vmm::layered_restore::Generation::from_immutable_file(&descs, &memory_file)
                    .map_err(|error| format!("retain layered restore input: {error}"))?,
            )
        } else {
            None
        };
        #[cfg(target_os = "linux")]
        let guest_memory = if let Some(generation) = &layered_ram {
            generation
                .restore()
                .map_err(|error| format!("map layered restore input: {error}"))?
        } else if std::env::var_os("SMOLVM_FORKABLE").is_some_and(|value| value == "1") {
            vmm::snapshot::map_guest_memory_file_forkable(&descs, &memory_file)
                .map_err(|e| format!("promote portable guest memory: {e}"))?
        } else {
            vmm::snapshot::map_guest_memory_file(&descs, &memory_file)
                .map_err(|e| format!("map guest memory: {e}"))?
        };
        #[cfg(all(unix, not(target_os = "linux")))]
        let guest_memory = vmm::snapshot::map_guest_memory_file(&descs, &memory_file)
            .map_err(|e| format!("map guest memory: {e}"))?;
        // Windows cannot unlink a live file mapping when smolvm consumes the
        // one-shot checkpoint after restore, so retain the eager owned-memory
        // fallback there.
        #[cfg(windows)]
        let guest_memory = {
            let mut memory_reader = std::io::BufReader::new(memory_file);
            vmm::snapshot::load_guest_memory(&descs, &mut memory_reader)
                .map_err(|e| format!("load guest memory: {e}"))?
        };
        return Ok(vmm::builder::RestoreCtx {
            #[cfg(target_os = "linux")]
            demand_pager: None,
            #[cfg(target_os = "linux")]
            layered_ram,
            guest_memory,
            fork_backed_regions: vec![true; descs.len()],
            checkpoint,
            portable_clock: true,
            #[cfg(target_os = "linux")]
            cow_backing: Vec::new(),
        });
    }
    #[cfg(target_os = "linux")]
    if magic == GUARDIAN_MANIFEST_MAGIC {
        let desc = read_guardian_manifest(&manifest_path)
            .map_err(|error| format!("guardian manifest: {error}"))?;
        let checkpoint =
            std::fs::read(dir.join("checkpoint.bin")).map_err(|e| format!("checkpoint: {e}"))?;
        let source = vmm::generation_guardian::GuardianPageSource::connect(&desc)
            .map_err(|error| format!("connect RAM guardian: {error}"))?;
        let demand = vmm::demand_paging::create_demand_paged_memory(
            &desc.regions,
            Box::new(source),
            vmm::demand_paging::UserfaultfdMode::KernelFaults,
        )
        .map_err(|error| format!("create demand-paged guest RAM: {error}"))?;
        return Ok(vmm::builder::RestoreCtx {
            demand_pager: Some(demand.pager),
            layered_ram: None,
            guest_memory: demand.memory,
            // A leaf can keep these anonymous demand-paged mappings. An
            // explicitly forkable child must materialize them into fresh
            // memfds during boot: userfaultfd missing-page ownership is not
            // inherited by a later raw fork, so directly guardian-forking an
            // incompletely faulted descendant could silently turn untouched
            // parent pages into zero pages.
            fork_backed_regions: vec![true; desc.regions.len()],
            checkpoint,
            portable_clock: false,
            #[cfg(target_os = "linux")]
            cow_backing: Vec::new(),
        });
    }
    if magic != FORK_MANIFEST_MAGIC {
        return Err("manifest: unrecognized snapshot format".to_string());
    }
    let (_owner_pid, descs) =
        read_fork_manifest(&manifest_path).map_err(|e| format!("manifest: {e}"))?;
    let checkpoint =
        std::fs::read(dir.join("checkpoint.bin")).map_err(|e| format!("checkpoint: {e}"))?;
    #[cfg(target_os = "linux")]
    let (guest_memory, cow_backing) =
        vmm::snapshot::open_cow_memory_from_pid_with_backing(_owner_pid, &descs)
            .map_err(|e| format!("cow-map guest memory: {e}"))?;
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let guest_memory = vmm::snapshot::open_cow_memory_from_paths(&descs)
        .map_err(|e| format!("cow-map guest memory: {e}"))?;
    Ok(vmm::builder::RestoreCtx {
        #[cfg(target_os = "linux")]
        demand_pager: None,
        #[cfg(target_os = "linux")]
        layered_ram: None,
        guest_memory,
        fork_backed_regions: descs
            .iter()
            .map(|desc| desc.fd >= 0 || !desc.path.is_empty())
            .collect(),
        checkpoint,
        portable_clock: false,
        #[cfg(target_os = "linux")]
        cow_backing,
    })
}

const MAX_CONTROL_COMMAND_BYTES: usize = 4096;

fn read_control_command<R: std::io::Read>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut command = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte)? {
            0 => return Ok(command),
            _ if byte[0] == b'\n' => return Ok(command),
            _ if command.len() == MAX_CONTROL_COMMAND_BYTES => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "control command exceeds 4096 bytes",
                ));
            }
            _ => command.push(byte[0]),
        }
    }
}

#[cfg(feature = "blk")]
fn parse_disk_growth(arg: &str) -> Result<(&str, u64), &'static str> {
    let mut fields = arg.split_whitespace();
    let id = fields
        .next()
        .ok_or("expected disk id and capacity in bytes")?;
    let bytes = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|bytes| *bytes > 0 && bytes.is_multiple_of(512))
        .ok_or("capacity must be a nonzero sector-aligned byte count")?;
    if fields.next().is_some() {
        return Err("expected exactly disk id and capacity in bytes");
    }
    Ok((id, bytes))
}

#[cfg(unix)]
type ControlStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
type ControlStream = std::net::TcpStream;

fn handle_control_stream(mut stream: ControlStream, vmm: &Arc<Mutex<vmm::Vmm>>) {
    let response = match read_control_command(&mut stream) {
        Ok(buf) if buf.is_empty() => "ERR EINVAL empty command\n".to_string(),
        Ok(buf) => {
            let cmd = String::from_utf8_lossy(&buf);
            let cmd = cmd.trim();
            // Split into a verb (case-insensitive) and an optional argument
            // (e.g. a checkpoint id), preserving the argument's case.
            let mut parts = cmd.splitn(2, char::is_whitespace);
            let verb = parts.next().unwrap_or("").to_ascii_uppercase();
            // `_arg` (underscore): only the CHECKPOINT/RESTORE/FORK arms use it,
            // and those are cfg-gated out on aarch64-linux, where it'd otherwise
            // be an unused-variable error under -D warnings.
            let _arg = parts.next().map(str::trim).unwrap_or("");
            match verb.as_str() {
                #[cfg(all(
                    any(target_os = "linux", target_os = "macos"),
                    any(target_arch = "x86_64", target_arch = "aarch64"),
                    not(feature = "tee")
                ))]
                "PROTOTYPE_GROW_MEMORY" => match _arg.parse::<u64>() {
                    Ok(mib) => match vmm.lock().unwrap().prototype_grow_memory(mib) {
                        Ok(()) => "OK RAM registered; guest onlining pending\n".into(),
                        Err(error) => format!("ERR EIO {error}\n"),
                    },
                    Err(_) => "ERR EINVAL expected additional MiB\n".into(),
                },
                #[cfg(all(
                    any(target_os = "linux", target_os = "macos"),
                    any(target_arch = "x86_64", target_arch = "aarch64"),
                    not(feature = "tee")
                ))]
                "PROTOTYPE_MEMORY_STATUS" => match vmm.lock().unwrap().prototype_memory_status() {
                    Ok((mapped, plugged)) => format!("OK mapped {mapped} plugged {plugged}\n"),
                    Err(error) => format!("ERR EIO {error}\n"),
                },
                #[cfg(all(
                    any(target_os = "linux", target_os = "macos"),
                    any(target_arch = "x86_64", target_arch = "aarch64"),
                    not(feature = "tee")
                ))]
                "PROTOTYPE_MEMORY_INFO" => match vmm.lock().unwrap().prototype_memory_info() {
                    Ok(info) => info,
                    Err(error) => format!("ERR EIO {error}\n"),
                },
                #[cfg(all(
                    any(
                        all(target_os = "linux", target_arch = "x86_64"),
                        all(target_os = "macos", target_arch = "aarch64")
                    ),
                    not(feature = "tee")
                ))]
                "PROTOTYPE_CPU_STATUS" => match vmm.lock().unwrap().prototype_cpu_status() {
                    Ok((created, capacity)) => {
                        format!("OK created {created} capacity {capacity}\n")
                    }
                    Err(error) => format!("ERR EIO {error}\n"),
                },
                #[cfg(all(target_os = "linux", target_arch = "x86_64", not(feature = "tee")))]
                "CPU_SHRINK_CAPABILITIES" => "OK preserved-offline-cpu-slots-v1\n".into(),
                #[cfg(all(
                    any(
                        all(target_os = "linux", target_arch = "x86_64"),
                        all(target_os = "macos", target_arch = "aarch64")
                    ),
                    not(feature = "tee")
                ))]
                "PROTOTYPE_GROW_CPUS" => match _arg.parse::<u8>() {
                    Ok(count) => match vmm.lock().unwrap().prototype_grow_cpus(count) {
                        Ok(()) => format!("OK created {count} vCPUs; guest online required\n"),
                        Err(error) => format!("ERR EIO {error}\n"),
                    },
                    Err(_) => "ERR EINVAL expected CPU count\n".into(),
                },
                #[cfg(feature = "blk")]
                "GROW_DISK_CAPABILITIES" => "OK grow-disk-v1\n".to_string(),
                // The privileged embedder must enforce exclusive disk ownership
                // and serialize machine lifecycle operations before requesting growth.
                #[cfg(feature = "blk")]
                "GROW_DISK" => match parse_disk_growth(_arg) {
                    Ok((id, bytes)) => match vmm.lock().unwrap().grow_block_device(id, bytes) {
                        Ok(()) => format!("OK disk {id} capacity {bytes}\n"),
                        Err(error) => format!("ERR EIO {error}\n"),
                    },
                    Err(error) => format!("ERR EINVAL {error}\n"),
                },
                #[cfg(all(snapshot_supported, deferred_stream_supported))]
                "SAVE_CAPABILITIES" => "OK deferred-stream-v1\n".to_string(),
                #[cfg(all(
                    snapshot_supported,
                    any(
                        all(target_os = "linux", target_arch = "x86_64"),
                        all(target_os = "macos", target_arch = "aarch64")
                    )
                ))]
                "SAVE_SPARSE_CAPABILITIES" => "OK sparse-stream-v1 ownership-v1\n".to_string(),
                // PREPARE_SAVE_HELD reads RAM in place, without rebasing it, for a
                // guest with device windows (virtio-fs DAX mappings stay intact).
                #[cfg(all(snapshot_supported, deferred_stream_supported, target_os = "linux"))]
                "SAVE_HELD_CAPABILITIES" => "OK held-windows-in-place-v1\n".to_string(),
                "PAUSE" => match vmm.lock().unwrap().pause() {
                    Ok(()) => "OK paused\n".to_string(),
                    Err(e) => format!("ERR EIO {e}\n"),
                },
                "RESUME" => match vmm.lock().unwrap().resume() {
                    Ok(()) => "OK running\n".to_string(),
                    Err(e) => format!("ERR EIO {e}\n"),
                },
                "STATUS" => {
                    let vmm = vmm.lock().unwrap();
                    #[cfg(target_os = "linux")]
                    {
                        match vmm.demand_pager_failure() {
                            Some(error) => format!("ERR EIO RAM pager failed: {error}\n"),
                            None => format!("OK {}\n", vmm.run_state()),
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    format!("OK {}\n", vmm.run_state())
                }
                // BALLOON <mib>: ask the guest to inflate its balloon to <mib>
                // MiB (0 deflates fully); the freed pages are reclaimed by the
                // host as the guest surrenders them. BALLOON with no argument
                // reports "target actual" in MiB (actual is guest-reported and
                // lags while in/deflation is in progress).
                #[cfg(not(feature = "tee"))]
                "BALLOON" => {
                    let mut vmm = vmm.lock().unwrap();
                    if _arg.is_empty() {
                        match vmm.balloon_pages() {
                            Ok((t, a)) => format!("OK target={} actual={}\n", t / 256, a / 256),
                            Err(e) => format!("ERR ENODEV {e}\n"),
                        }
                    } else {
                        match _arg.parse::<u32>() {
                            Ok(mib) => match vmm.balloon_set_target_mib(mib) {
                                Ok(_) => format!("OK balloon target {mib} MiB\n"),
                                Err(e) => format!("ERR ENODEV {e}\n"),
                            },
                            Err(_) => "ERR EINVAL balloon target must be MiB\n".to_string(),
                        }
                    }
                }
                // HINT_FREE [timeout_ms]: have the guest hand its free memory
                // to the balloon so the host discards it, then let the guest
                // reuse it. A checkpoint taken right after skips that memory
                // instead of saving whatever it last held. Waits up to
                // timeout_ms (default 2000) for the guest to finish.
                #[cfg(not(feature = "tee"))]
                "HINT_FREE" => {
                    let timeout = if _arg.is_empty() {
                        Ok(2000)
                    } else {
                        _arg.parse::<u64>()
                    };
                    match (timeout, vmm.lock().unwrap().balloon()) {
                        (Err(_), _) => "ERR EINVAL timeout must be milliseconds\n".to_string(),
                        (_, None) => "ERR ENODEV no balloon device\n".to_string(),
                        (Ok(ms), Some(balloon)) => hint_free_pages(&balloon, ms),
                    }
                }
                // CHECKPOINT <id>: capture VM/vCPU/device state + guest memory
                // into an in-process stash keyed by <id>. The VM is left paused;
                // send RESUME to keep the original running, or RESTORE <id>
                // later to rewind it to this point.
                #[cfg(snapshot_supported)]
                "CHECKPOINT" => handle_checkpoint(vmm, _arg),
                // RESTORE <id>: rewind the (paused) VM to a stashed checkpoint.
                // The VM stays paused; send RESUME afterwards. Consumes the
                // stash (one-shot) since the captured state is moved into KVM.
                #[cfg(snapshot_supported)]
                "RESTORE" => handle_restore(vmm, _arg),
                // SAVE <dir>: write a self-contained, process-independent VM
                // checkpoint and leave the VM paused so the caller can capture
                // disk state from the same boundary.
                #[cfg(snapshot_supported)]
                "SAVE" => handle_save(vmm, _arg, true),
                // SAVE_UNSYNCED <dir>: SAVE without syncing its files, for a
                // caller that resumes the VM and packs them into a durable
                // artifact of its own. The source resumes after the RAM copy
                // instead of after the host disk flushes it.
                #[cfg(snapshot_supported)]
                "SAVE_UNSYNCED" => handle_save(vmm, _arg, false),
                // SAVE_FROZEN <dir>: SAVE for a VM frozen as a fork base. It
                // stays frozen whatever happens, since its clones map its RAM.
                #[cfg(all(snapshot_supported, fork_supported, unix))]
                "SAVE_FROZEN" => handle_save_frozen(vmm, _arg),
                // SHARE_ADD <tag> <name> <host dir>: attach a host directory to
                // the live virtio-fs device <tag> under <name>, while it runs.
                #[cfg(all(
                    any(target_os = "linux", target_os = "macos"),
                    not(any(feature = "tee", feature = "aws-nitro"))
                ))]
                "SHARE_ADD" => handle_share_add(_arg),
                // SHARE_REMOVE <tag> <name>: detach it, revoking the guest's
                // access to everything under it, open files included.
                #[cfg(all(
                    any(target_os = "linux", target_os = "macos"),
                    not(any(feature = "tee", feature = "aws-nitro"))
                ))]
                "SHARE_REMOVE" => handle_share_remove(_arg),
                // SHARE_LIST <tag>: the attached shares, as name=host dir
                // separated by tabs.
                #[cfg(all(
                    any(target_os = "linux", target_os = "macos"),
                    not(any(feature = "tee", feature = "aws-nitro"))
                ))]
                "SHARE_LIST" => handle_share_list(_arg),
                // PREPARE_SAVE captures an immutable COW RAM generation and
                // leaves the VM paused only for caller-side disk staging.
                // After RESUME, FINISH_SAVE persists that retained generation;
                // CANCEL_SAVE releases it after a caller-side failure.
                #[cfg(all(snapshot_supported, deferred_stream_supported))]
                // PREPARE_SAVE_LAYERED is PREPARE_SAVE only for RAM that is a
                // layered generation, whose capture leaves device windows in
                // place; anything else declines without pausing, and the
                // caller falls back to SAVE.
                "PREPARE_SAVE_LAYERED" if !vmm.lock().unwrap().has_layered_ram() => {
                    "ERR ENOTSUP guest RAM is not a layered generation\n".to_string()
                }
                #[cfg(all(snapshot_supported, deferred_stream_supported))]
                // PREPARE_SAVE_HELD is PREPARE_SAVE for a caller that keeps
                // the VM paused until FINISH_SAVE* and then stops it, so RAM
                // that cannot be retained as a generation is read in place.
                "PREPARE_SAVE" | "PREPARE_SAVE_HELD" | "PREPARE_SAVE_LAYERED" => {
                    let response = handle_prepare_save(vmm, _arg, verb == "PREPARE_SAVE_HELD");
                    if let Err(error) = write_prepared_save_reply(&mut stream, &response, || {
                        // The control listener is serial: no later command can
                        // consume this preparation before reply delivery ends.
                        if let Err(error) = vmm.lock().unwrap().resume() {
                            error!("resume after disconnected checkpoint preparation: {error}");
                        }
                        let cancelled = handle_cancel_save(_arg);
                        if !cancelled.starts_with("OK ") {
                            error!("cancel disconnected checkpoint preparation: {cancelled}");
                        }
                    }) {
                        warn!("deliver checkpoint preparation reply: {error}");
                    }
                    return;
                }
                #[cfg(all(snapshot_supported, deferred_stream_supported))]
                "FINISH_SAVE" | "FINISH_SAVE_STREAM" | "FINISH_SAVE_SPARSE" => {
                    // RAM persistence can take seconds for large resident
                    // guests. Keep the control listener available so a resumed
                    // source can fork, checkpoint again, or answer health
                    // probes while this caller waits for durable completion.
                    let dir = _arg.to_string();
                    let send_memory = verb == "FINISH_SAVE_STREAM";
                    let sparse_memory = verb == "FINISH_SAVE_SPARSE";
                    let stream = Arc::new(Mutex::new(Some(stream)));
                    let worker_stream = Arc::clone(&stream);
                    let worker = std::thread::Builder::new()
                        .name("krun durable save".into())
                        .spawn(move || {
                            if let Some(mut stream) = worker_stream.lock().unwrap().take() {
                                let response = if sparse_memory {
                                    #[cfg(any(
                                        all(target_os = "linux", target_arch = "x86_64"),
                                        all(target_os = "macos", target_arch = "aarch64")
                                    ))]
                                    {
                                        handle_finish_save_sparse(&dir, &mut stream)
                                    }
                                    #[cfg(not(any(
                                        all(target_os = "linux", target_arch = "x86_64"),
                                        all(target_os = "macos", target_arch = "aarch64")
                                    )))]
                                    {
                                        "ERR ENOTSUP sparse save is unavailable\n".to_string()
                                    }
                                } else if send_memory {
                                    handle_finish_save_stream(&dir, &mut stream)
                                } else {
                                    handle_finish_save(&dir)
                                };
                                let _ = stream.write_all(response.as_bytes());
                            }
                        });
                    if let Err(error) = worker
                        && let Some(mut stream) = stream.lock().unwrap().take()
                    {
                        let response = format!("ERR EAGAIN start durable save: {error}\n");
                        let _ = stream.write_all(response.as_bytes());
                    }
                    return;
                }
                #[cfg(all(snapshot_supported, deferred_stream_supported))]
                "CANCEL_SAVE" => handle_cancel_save(_arg),
                #[cfg(all(snapshot_supported, deferred_stream_supported))]
                "SAVE_STATUS" => handle_save_status(_arg),
                // FORK <dir>: capture a fork checkpoint to <dir> (checkpoint.bin +
                // manifest.bin) and leave this VM FROZEN as the CoW base. A clone
                // process then boots from <dir> via krun_set_snapshot, mapping this
                // VM's guest-RAM memfd MAP_PRIVATE. Requires memfd-backed RAM
                // (SMOLVM_FORKABLE=1).
                #[cfg(fork_supported)]
                "FORK" => handle_fork(vmm, _arg),
                #[cfg(all(fork_supported, fork_continue_supported, feature = "blk"))]
                "FORK_CONTINUE" => handle_fork_continue(vmm, _arg),
                #[cfg(all(
                    fork_supported,
                    target_os = "linux",
                    target_arch = "x86_64",
                    feature = "blk"
                ))]
                "FORK_CONTINUE_PAGED" => handle_fork_continue_paged(vmm, _arg),
                #[cfg(fork_supported)]
                "ROLLBACK_FORK" => handle_rollback_fork(vmm, _arg),
                _ => "ERR EINVAL unknown command\n".to_string(),
            }
        }
        Err(e) => format!("ERR EIO {e}\n"),
    };

    let _ = stream.write_all(response.as_bytes());
}

#[cfg(test)]
mod control_command_tests {
    use super::*;

    #[cfg(feature = "blk")]
    #[test]
    fn disk_growth_command_requires_an_exact_aligned_capacity() {
        assert_eq!(
            parse_disk_growth("storage 2147483648"),
            Ok(("storage", 2147483648))
        );
        for invalid in [
            "",
            "storage",
            "storage 0",
            "storage -512",
            "storage 513",
            "storage 18446744073709551616",
            "storage 512 extra",
        ] {
            assert!(parse_disk_growth(invalid).is_err(), "{invalid}");
        }
    }

    #[cfg(all(snapshot_supported, fork_continue_supported))]
    #[test]
    fn disconnected_prepared_reply_recovers_source_once() {
        use std::os::unix::net::UnixStream;

        let (mut server, client) = UnixStream::pair().unwrap();
        // A read shutdown alone still accepts peer writes on macOS.
        drop(client);
        let mut recoveries = 0;
        let result = write_prepared_save_reply(&mut server, "OK prepared (paused)\n", || {
            recoveries += 1;
        });
        assert!(result.is_err());
        assert_eq!(recoveries, 1);
    }

    #[cfg(all(snapshot_supported, fork_continue_supported))]
    #[test]
    fn prepared_reply_preserves_success_and_failed_prepare_ownership() {
        use std::os::unix::net::UnixStream;

        let mut output = Vec::new();
        write_prepared_save_reply(&mut output, "OK prepared (paused)\n", || {
            panic!("delivered preparation belongs to the caller");
        })
        .unwrap();
        assert_eq!(output, b"OK prepared (paused)\n");

        let (mut server, client) = UnixStream::pair().unwrap();
        drop(client);
        assert!(
            write_prepared_save_reply(&mut server, "ERR EBUSY another save is pending\n", || {
                panic!("failed preparation must not cancel another save");
            })
            .is_err()
        );
    }

    #[cfg(snapshot_supported)]
    #[test]
    fn failed_checkpoint_preserves_paused_sources() {
        let reply = checkpoint_failure_reply("storage unavailable", false, || {
            panic!("an already-paused machine must not resume")
        });
        assert_eq!(reply, "ERR EIO checkpoint failed: storage unavailable\n");
    }

    #[cfg(snapshot_supported)]
    #[test]
    fn failed_checkpoint_resumes_running_sources_once() {
        let attempts = std::cell::Cell::new(0);
        let reply = checkpoint_failure_reply("storage unavailable", true, || {
            attempts.set(attempts.get() + 1);
            Ok(())
        });
        assert_eq!(attempts.get(), 1);
        assert_eq!(reply, "ERR EIO checkpoint failed: storage unavailable\n");
    }

    #[cfg(snapshot_supported)]
    #[test]
    fn failed_checkpoint_reports_both_capture_and_resume_errors() {
        let reply = checkpoint_failure_reply("storage unavailable", true, || {
            Err("vCPU unavailable".into())
        });
        assert_eq!(
            reply,
            "ERR EIO checkpoint failed: storage unavailable; source resume failed: vCPU unavailable\n"
        );
    }

    #[cfg(all(snapshot_supported, target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn sparse_checkpoint_header_is_bounded_and_explicitly_framed() {
        let mut output = Vec::new();
        write_checkpoint_stream_header(&mut output, b"cpu", b"layout").unwrap();
        assert_eq!(&output[..8], b"SMOLCKS1");
        assert_eq!(u32::from_le_bytes(output[8..12].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(output[12..16].try_into().unwrap()), 6);
        assert_eq!(&output[16..], b"cpulayout");
        for (state, layout) in [(b"".as_slice(), b"layout".as_slice()), (b"cpu", b"")] {
            let mut output = Vec::new();
            assert!(write_checkpoint_stream_header(&mut output, state, layout).is_err());
            assert!(output.is_empty());
        }
        let mut output = Vec::new();
        assert!(
            write_checkpoint_stream_header(&mut output, b"cpu", &vec![0; 1024 * 1024 + 1]).is_err()
        );
        assert!(output.is_empty());
    }

    #[cfg(all(target_os = "linux", fork_supported))]
    #[test]
    fn direct_file_restore_can_publish_a_layered_branch() {
        use vm_memory::{Bytes, GuestAddress};
        let dir = std::env::temp_dir().join(format!(
            "krun-direct-layered-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let descs = [vmm::snapshot::MemoryRegionDesc { gpa: 0, len: 4096 }];
        std::fs::write(dir.join("manifest.bin"), encode_portable_manifest(&descs)).unwrap();
        std::fs::write(dir.join("checkpoint.bin"), b"opaque device state").unwrap();
        std::fs::write(dir.join("memory.bin"), [0x6a; 4096]).unwrap();
        let result = (|| {
            let restored = build_restore_ctx_with_memory_mode(&dir, None, true)
                .map_err(std::io::Error::other)?;
            let generation = restored.layered_ram.as_ref().unwrap();
            let (manifest, service) = generation.publish_manifest(&dir.join("handoff.sock"))?;
            let imported = vmm::layered_restore::Generation::decode_manifest(&manifest)?;
            drop(service);
            drop(restored);
            let child = imported.restore()?;
            assert_eq!(child.read_obj::<u8>(GuestAddress(0)).unwrap(), 0x6a);
            Ok::<(), std::io::Error>(())
        })();
        std::fs::remove_dir_all(&dir).unwrap();
        result.unwrap();
    }

    #[test]
    fn last_error_is_thread_local_and_copied_as_c_string() {
        clear_last_error();
        assert!(krun_get_last_error().is_null());
        set_last_error("checkpoint restore failed");
        let message = unsafe { CStr::from_ptr(krun_get_last_error()) };
        assert_eq!(message.to_bytes(), b"checkpoint restore failed");
        clear_last_error();
        assert!(krun_get_last_error().is_null());
    }

    #[test]
    fn control_commands_are_complete_and_bounded() {
        let command = format!("ROLLBACK_FORK /{}\nignored", "x".repeat(512));
        let parsed = read_control_command(&mut command.as_bytes()).unwrap();
        assert_eq!(parsed, command.as_bytes()[..command.find('\n').unwrap()]);

        let oversized = vec![b'x'; MAX_CONTROL_COMMAND_BYTES + 1];
        let error = read_control_command(&mut oversized.as_slice()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(snapshot_supported)]
    #[test]
    fn portable_manifest_roundtrips_and_rejects_corruption() {
        let descs = vec![
            vmm::snapshot::MemoryRegionDesc {
                gpa: 0x1000,
                len: 0x2000,
            },
            vmm::snapshot::MemoryRegionDesc {
                gpa: 0x1_0000_0000,
                len: 0x4000,
            },
        ];
        let encoded = encode_portable_manifest(&descs);
        assert_eq!(decode_portable_manifest(&encoded).unwrap(), descs);

        assert!(decode_portable_manifest(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_portable_manifest(&trailing).is_err());
        let mut wrong_version = encoded;
        wrong_version[8..12].copy_from_slice(&2_u32.to_le_bytes());
        assert!(decode_portable_manifest(&wrong_version).is_err());

        let mut overlapping = encode_portable_manifest(&descs);
        overlapping[32..40].copy_from_slice(&0x2000_u64.to_le_bytes());
        assert!(decode_portable_manifest(&overlapping).is_err());

        let mut overflowing = encode_portable_manifest(&descs[..1]);
        overflowing[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_portable_manifest(&overflowing).is_err());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn guardian_manifest_builds_an_exact_demand_paged_restore() {
        use vm_memory::{Bytes, GuestAddress};

        let root = std::env::temp_dir().join(format!(
            "libkrun-guardian-restore-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let dir = root.join("a".repeat(80)).join("b".repeat(80));
        std::fs::create_dir_all(&dir).unwrap();
        let size = 256 * 1024;
        let memory = vmm::GuestMemoryMmap::from_ranges(&[(GuestAddress(0), size)]).unwrap();
        memory
            .write_slice(&vec![0x5d_u8; size], GuestAddress(0))
            .unwrap();
        let guardian = vmm::generation_guardian::GenerationGuardian::start(
            &memory,
            &dir.join(GUARDIAN_SOCKET_NAME),
        )
        .unwrap();
        atomic_write_file(&dir.join("checkpoint.bin"), b"checkpoint").unwrap();
        write_guardian_manifest(&dir.join("manifest.bin"), guardian.description()).unwrap();
        assert_eq!(
            read_guardian_manifest(&dir.join("manifest.bin")).unwrap(),
            *guardian.description()
        );
        memory
            .write_slice(&vec![0xe2_u8; size], GuestAddress(0))
            .unwrap();

        // The host test policy disables kernel-originated faults. Supply the
        // same pre-opened descriptor path used by a privileged boot process,
        // but create it in user-mode-only form for this userspace read test.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_userfaultfd,
                libc::O_CLOEXEC | libc::O_NONBLOCK | 1,
            ) as libc::c_int
        };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        assert!(
            unsafe {
                libc::dup3(
                    fd,
                    vmm::demand_paging::PREOPENED_USERFAULTFD_FD,
                    libc::O_CLOEXEC,
                )
            } >= 0
        );
        unsafe { libc::close(fd) };

        let restore = build_restore_ctx(&dir).expect("build guardian restore");
        let mut actual = vec![0_u8; size];
        restore
            .guest_memory
            .read_slice(&mut actual, GuestAddress(0))
            .unwrap();
        assert!(actual.iter().all(|byte| *byte == 0x5d));
        assert!(restore.demand_pager.as_ref().unwrap().failure().is_none());
        drop(restore);
        drop(guardian);
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(not(target_os = "windows"))]
fn start_control_socket(path: PathBuf, vmm: Arc<Mutex<vmm::Vmm>>) -> std::io::Result<()> {
    let _ = std::fs::remove_file(&path);
    let address = utils::SocketPath::new(&path)?;
    let listener = UnixListener::bind(address.path())?;

    std::thread::Builder::new()
        .name("krun control".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => handle_control_stream(stream, &vmm),
                    Err(e) => {
                        error!("control socket accept failed: {e}");
                        break;
                    }
                }
            }
        })?;

    Ok(())
}

/// Windows has no `AF_UNIX` in `std`, so the control channel is a TCP listener
/// bound to loopback. The OS-assigned port is written (as decimal text) to
/// `path`, which a client reads to discover where to connect — keeping the
/// `krun_set_control_socket(path)` C API identical across platforms.
#[cfg(target_os = "windows")]
fn start_control_socket(path: PathBuf, vmm: Arc<Mutex<vmm::Vmm>>) -> std::io::Result<()> {
    use std::net::TcpListener;

    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    std::fs::write(&path, port.to_string())?;

    std::thread::Builder::new()
        .name("krun control".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => handle_control_stream(stream, &vmm),
                    Err(e) => {
                        error!("control socket accept failed: {e}");
                        break;
                    }
                }
            }
        })?;

    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn krun_set_log_level(level: u32) -> i32 {
    let filter = log_level_to_filter_str(level);
    env_logger::Builder::from_env(Env::default().default_filter_or(filter))
        .format_timestamp_micros()
        .init();

    #[cfg(feature = "aws-nitro")]
    {
        // Notify krun-awsnitro to enable debug for log level.
        if level == 4 {
            let mut debug = KRUN_NITRO_DEBUG.lock().unwrap();

            *debug = true;
        }
    }

    KRUN_SUCCESS
}

mod log_defs {
    pub const KRUN_LOG_STYLE_AUTO: u32 = 0;
    pub const KRUN_LOG_STYLE_ALWAYS: u32 = 1;
    pub const KRUN_LOG_STYLE_NEVER: u32 = 2;
    pub const KRUN_LOG_OPTION_NO_ENV: u32 = 1;
}

#[allow(clippy::missing_safety_doc)]
// On Windows the FromRawFd pipe arm is gated out, leaving the unsafe block empty.
#[cfg_attr(target_os = "windows", allow(unused_unsafe))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_init_log(target: i32, level: u32, style: u32, options: u32) -> i32 {
    unsafe {
        let target = match target {
        ..-1 => return -libc::EINVAL,
        -1 => Target::default(),
        0 /* stdin */ => return -libc::EINVAL,
        1 /* stdout */ => Target::Stdout,
        2 /* stderr */ => Target::Stderr,
        // Arbitrary pipe fds are reattached via FromRawFd (Unix only).
        // TODO(whp-host): support a Windows HANDLE pipe target.
        #[cfg(not(target_os = "windows"))]
        fd => Target::Pipe(Box::new(File::from_raw_fd(fd))),
        #[cfg(target_os = "windows")]
        _fd => return -libc::EINVAL,
    };

        let filter = log_level_to_filter_str(level);

        let write_style = match style {
            log_defs::KRUN_LOG_STYLE_AUTO => "auto",
            log_defs::KRUN_LOG_STYLE_ALWAYS => "always",
            log_defs::KRUN_LOG_STYLE_NEVER => "never",
            _ => return -libc::EINVAL,
        };

        let use_env = match options {
            0 => true,
            log_defs::KRUN_LOG_OPTION_NO_ENV => false,
            _ => return -libc::EINVAL,
        };

        let mut builder = if use_env {
            env_logger::Builder::from_env(
                Env::new()
                    .default_filter_or(filter)
                    .default_write_style_or(write_style),
            )
        } else {
            let mut builder = env_logger::Builder::new();
            builder.parse_filters(filter).parse_write_style(write_style);
            builder
        };
        builder.format_timestamp_micros().target(target).init();

        #[cfg(feature = "aws-nitro")]
        {
            // Notify krun-awsnitro to enable debug for log level.
            if level >= 4 {
                *KRUN_NITRO_DEBUG.lock().unwrap() = true;
            }
        }

        KRUN_SUCCESS
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn krun_create_ctx() -> i32 {
    let shutdown_efd = if cfg!(target_arch = "aarch64") && cfg!(target_os = "macos") {
        Some(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap())
    } else {
        None
    };

    let ctx_cfg = {
        ContextConfig {
            krunfw: KrunfwBindings::new(),
            shutdown_efd,
            ..Default::default()
        }
    };

    let ctx_id = CTX_IDS.fetch_add(1, Ordering::SeqCst);
    if ctx_id == i32::MAX || CTX_MAP.lock().unwrap().contains_key(&(ctx_id as u32)) {
        // libkrun is not intended to be used as a daemon for managing VMs.
        panic!("Context ID namespace exhausted");
    }
    CTX_MAP.lock().unwrap().insert(ctx_id as u32, ctx_cfg);

    ctx_id
}

#[unsafe(no_mangle)]
pub extern "C" fn krun_free_ctx(ctx_id: u32) -> i32 {
    match CTX_MAP.lock().unwrap().remove(&ctx_id) {
        Some(_) => KRUN_SUCCESS,
        None => -libc::ENOENT,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn krun_set_vm_config(ctx_id: u32, num_vcpus: u8, ram_mib: u32) -> i32 {
    let mem_size_mib: usize = match ram_mib.try_into() {
        Ok(size) => size,
        Err(e) => {
            warn!("Error parsing the amount of RAM: {e:?}");
            return -libc::EINVAL;
        }
    };

    let vm_config = VmConfig {
        vcpu_count: Some(num_vcpus),
        mem_size_mib: Some(mem_size_mib),
        ht_enabled: Some(false),
        cpu_template: None,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            if ctx_cfg.get_mut().vmr.set_vm_config(&vm_config).is_err() {
                return -libc::EINVAL;
            }
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

/// Configure live resource growth before boot; existing checkpoints retain
/// their captured device topology regardless of these fresh-boot settings.
#[unsafe(no_mangle)]
pub extern "C" fn krun_set_live_resize(ctx_id: u32, flags: u32) -> i32 {
    if flags & !3 != 0 {
        return -libc::EINVAL;
    }
    if flags & 1 != 0
        && !cfg!(all(
            any(
                all(target_os = "linux", target_arch = "x86_64"),
                all(target_os = "macos", target_arch = "aarch64")
            ),
            not(feature = "tee")
        ))
    {
        return -libc::ENOTSUP;
    }
    if flags & 2 != 0
        && !cfg!(all(
            any(target_os = "linux", target_os = "macos"),
            any(target_arch = "x86_64", target_arch = "aarch64"),
            not(feature = "tee")
        ))
    {
        return -libc::ENOTSUP;
    }
    let mut contexts = CTX_MAP.lock().unwrap();
    let Some(context) = contexts.get_mut(&ctx_id) else {
        return -libc::ENOENT;
    };
    context.vmr.live_cpu_growth = flags & 1 != 0;
    context.vmr.live_memory_growth = flags & 2 != 0;
    KRUN_SUCCESS
}

/// Select a stable virtual CPU contract for live migration.
///
/// This is deliberately explicit instead of changing libkrun's host-feature
/// default for every embedder. Callers that need portable checkpoints opt the
/// VM into the stable profile before `krun_start_enter`.
#[unsafe(no_mangle)]
pub extern "C" fn krun_set_cpu_template(ctx_id: u32, cpu_template: u32) -> i32 {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let template = match cpu_template {
        1 => vmm::vmm_config::machine_config::CpuFeaturesTemplate::Portable,
        _ => return -libc::EINVAL,
    };

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        // The portable profile is an Intel architectural contract. Applying its model
        // and MSR expectations to AMD would make a checkpoint look portable
        // when it is not; leave those VMs on libkrun's host CPU contract.
        let leaf = std::arch::x86_64::__cpuid(0);
        let mut vendor = [0_u8; 12];
        vendor[..4].copy_from_slice(&leaf.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&leaf.edx.to_le_bytes());
        vendor[8..].copy_from_slice(&leaf.ecx.to_le_bytes());
        if &vendor != b"GenuineIntel" {
            return -libc::ENOTSUP;
        }
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (ctx_id, cpu_template);
        -libc::ENOTSUP
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let current = ctx_cfg.get().vmr.vm_config();
            let vm_config = VmConfig {
                vcpu_count: current.vcpu_count,
                mem_size_mib: current.mem_size_mib,
                ht_enabled: current.ht_enabled,
                cpu_template: Some(template),
            };
            if ctx_cfg.get_mut().vmr.set_vm_config(&vm_config).is_err() {
                return -libc::EINVAL;
            }
            KRUN_SUCCESS
        }
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub unsafe extern "C" fn krun_add_virtiofs(
    ctx_id: u32,
    c_tag: *const c_char,
    c_path: *const c_char,
) -> i32 {
    unsafe { krun_add_virtiofs3(ctx_id, c_tag, c_path, 0, false) }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub unsafe extern "C" fn krun_add_virtiofs2(
    ctx_id: u32,
    c_tag: *const c_char,
    c_path: *const c_char,
    shm_size: u64,
) -> i32 {
    unsafe { krun_add_virtiofs3(ctx_id, c_tag, c_path, shm_size, false) }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub unsafe extern "C" fn krun_add_virtiofs3(
    ctx_id: u32,
    c_tag: *const c_char,
    c_path: *const c_char,
    shm_size: u64,
    read_only: bool,
) -> i32 {
    unsafe { krun_add_virtiofs4(ctx_id, c_tag, c_path, shm_size, read_only, 0) }
}

/// Serve ownership and mode from the `user.containers.override_stat` xattr
/// on each file instead of the host inode (and record the guest's chown,
/// chmod and mknod there). Lets an unprivileged host share an image tree with
/// its exact owners, setuid bits and whiteouts. Always in effect on macOS and
/// Windows; on Linux only with this flag.
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub const KRUN_VIRTIOFS_FLAG_OVERRIDE_STAT: u32 = 1 << 0;
/// Serve host directories attached and detached at runtime through the control
/// socket (`SHARE_ADD`, `SHARE_REMOVE`, `SHARE_LIST`). `c_path` must name an empty
/// host directory the device uses as its root, and `shm_size` must be 0.
pub const KRUN_VIRTIOFS_FLAG_LIVE: u32 = 1 << 1;
/// Let the guest keep a missing name for one second (see `KRUN_VIRTIOFS_FLAG_NEGATIVE_ENTRIES`).
pub const KRUN_VIRTIOFS_FLAG_NEGATIVE_ENTRIES: u32 = 1 << 2;

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub unsafe extern "C" fn krun_add_virtiofs4(
    ctx_id: u32,
    c_tag: *const c_char,
    c_path: *const c_char,
    shm_size: u64,
    read_only: bool,
    flags: u32,
) -> i32 {
    if flags
        & !(KRUN_VIRTIOFS_FLAG_OVERRIDE_STAT
            | KRUN_VIRTIOFS_FLAG_LIVE
            | KRUN_VIRTIOFS_FLAG_NEGATIVE_ENTRIES)
        != 0
    {
        return -libc::EINVAL;
    }
    let override_stat = flags & KRUN_VIRTIOFS_FLAG_OVERRIDE_STAT != 0;
    let negative_entries = flags & KRUN_VIRTIOFS_FLAG_NEGATIVE_ENTRIES != 0;
    let live = flags & KRUN_VIRTIOFS_FLAG_LIVE != 0;
    // A live device's mappings into guest memory could not be revoked on
    // detach, so it has no DAX window, and it needs a host root to serve from.
    if live && (shm_size > 0 || c_path.is_null()) {
        return -libc::EINVAL;
    }
    if live && cfg!(target_os = "windows") {
        return -libc::ENOTSUP;
    }
    unsafe {
        if c_tag.is_null() {
            return -libc::EINVAL;
        }

        let tag = match CStr::from_ptr(c_tag).to_str() {
            Ok(tag) => tag,
            Err(_) => return -libc::EINVAL,
        };

        // NULL path means NullFs (virtual-only filesystem, no host directory).
        let path = if c_path.is_null() {
            None
        } else {
            match CStr::from_ptr(c_path).to_str() {
                Ok(path) => Some(path),
                Err(_) => return -libc::EINVAL,
            }
        };

        let shm = if shm_size > 0 {
            match shm_size.try_into() {
                Ok(s) => Some(s),
                Err(_) => return -libc::EINVAL,
            }
        } else {
            None
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                #[allow(unused_mut)]
                let mut virtual_entries = Vec::new();
                #[cfg(feature = "init-blob")]
                if tag == "/dev/root" && !cfg.disable_implicit_init {
                    virtual_entries.push(init_virtual_entry());
                }
                cfg.vmr.add_fs_device(FsDeviceConfig {
                    fs_id: tag.to_string(),
                    shared_dir: path.map(|p| p.to_string()),
                    shm_size: shm,
                    read_only,
                    override_stat,
                    negative_entries,
                    live,
                    virtual_entries,
                });
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(feature = "blk")]
pub unsafe extern "C" fn krun_add_disk(
    ctx_id: u32,
    c_block_id: *const c_char,
    c_disk_path: *const c_char,
    read_only: bool,
) -> i32 {
    unsafe {
        let disk_path = match CStr::from_ptr(c_disk_path).to_str() {
            Ok(disk) => disk,
            Err(_) => return -libc::EINVAL,
        };

        let block_id = match CStr::from_ptr(c_block_id).to_str() {
            Ok(block_id) => block_id,
            Err(_) => return -libc::EINVAL,
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                let block_device_config = BlockDeviceConfig {
                    block_id: block_id.to_string(),
                    cache_type: CacheType::auto(disk_path),
                    disk_image_path: disk_path.to_string(),
                    disk_image_format: ImageType::Raw,
                    is_disk_read_only: read_only,
                    direct_io: false,
                    #[cfg(not(target_os = "macos"))]
                    sync_mode: SyncMode::Full,
                    #[cfg(target_os = "macos")]
                    sync_mode: SyncMode::Relaxed,
                    io_engine: devices::virtio::block::BlockIoEngine::Sync,
                    prepared_async: None,
                };
                cfg.add_block_cfg(block_device_config);
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(feature = "blk")]
pub unsafe extern "C" fn krun_add_disk2(
    ctx_id: u32,
    c_block_id: *const c_char,
    c_disk_path: *const c_char,
    disk_format: u32,
    read_only: bool,
) -> i32 {
    unsafe {
        let disk_path = match CStr::from_ptr(c_disk_path).to_str() {
            Ok(disk) => disk,
            Err(_) => return -libc::EINVAL,
        };

        let block_id = match CStr::from_ptr(c_block_id).to_str() {
            Ok(block_id) => block_id,
            Err(_) => return -libc::EINVAL,
        };

        let format = match ImageType::try_from(disk_format) {
            Ok(format) => format,
            Err(_) => return -libc::EINVAL,
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                let block_device_config = BlockDeviceConfig {
                    block_id: block_id.to_string(),
                    cache_type: CacheType::auto(disk_path),
                    disk_image_path: disk_path.to_string(),
                    disk_image_format: format,
                    is_disk_read_only: read_only,
                    direct_io: false,
                    #[cfg(not(target_os = "macos"))]
                    sync_mode: SyncMode::Full,
                    #[cfg(target_os = "macos")]
                    sync_mode: SyncMode::Relaxed,
                    io_engine: devices::virtio::block::BlockIoEngine::Sync,
                    prepared_async: None,
                };
                cfg.add_block_cfg(block_device_config);
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

/// Create a copy-on-write qcow2 overlay at `c_overlay_path` whose backing image
/// is `c_base_path`. `base_format` uses the same values as `krun_add_disk2`
/// (0 = raw, 1 = qcow2). The overlay starts near-empty and grows only with
/// writes; reads fall through to the read-only backing image. The base path is
/// written verbatim into the overlay header, so it must be absolute. This is a
/// pure filesystem operation and is not tied to a VM context. Returns 0 on
/// success or a negative errno on failure.
#[allow(clippy::missing_safety_doc)]
#[allow(unsafe_op_in_unsafe_fn)]
#[unsafe(no_mangle)]
#[cfg(feature = "blk")]
pub unsafe extern "C" fn krun_create_disk_overlay(
    c_overlay_path: *const c_char,
    c_base_path: *const c_char,
    base_format: u32,
) -> i32 {
    let overlay_path = match CStr::from_ptr(c_overlay_path).to_str() {
        Ok(path) => path,
        Err(_) => return -libc::EINVAL,
    };

    let base_path = match CStr::from_ptr(c_base_path).to_str() {
        Ok(path) => path,
        Err(_) => return -libc::EINVAL,
    };

    let format = match ImageType::try_from(base_format) {
        Ok(fmt) => fmt,
        Err(_) => return -libc::EINVAL,
    };

    match devices::virtio::block::create_overlay(overlay_path, base_path, format) {
        Ok(()) => KRUN_SUCCESS,
        Err(e) => {
            error!("Error creating disk overlay {overlay_path}: {e}");
            -libc::EIO
        }
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(feature = "blk")]
pub unsafe extern "C" fn krun_add_disk3(
    ctx_id: u32,
    c_block_id: *const c_char,
    c_disk_path: *const c_char,
    disk_format: u32,
    read_only: bool,
    direct_io: bool,
    sync_mode: u32,
) -> i32 {
    unsafe {
        let disk_path = match CStr::from_ptr(c_disk_path).to_str() {
            Ok(disk) => disk,
            Err(_) => return -libc::EINVAL,
        };

        let block_id = match CStr::from_ptr(c_block_id).to_str() {
            Ok(block_id) => block_id,
            Err(_) => return -libc::EINVAL,
        };

        let format = match ImageType::try_from(disk_format) {
            Ok(fmt) => fmt,
            Err(_) => return -libc::EINVAL,
        };

        let sync_mode = match SyncMode::try_from(sync_mode) {
            Ok(mode) => mode,
            Err(_) => return -libc::EINVAL,
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                let block_device_config = BlockDeviceConfig {
                    block_id: block_id.to_string(),
                    cache_type: CacheType::auto(disk_path),
                    disk_image_path: disk_path.to_string(),
                    disk_image_format: format,
                    is_disk_read_only: read_only,
                    direct_io,
                    sync_mode,
                    io_engine: devices::virtio::block::BlockIoEngine::Sync,
                    prepared_async: None,
                };
                cfg.add_block_cfg(block_device_config);
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

/// Add a disk with an explicit host I/O engine.
///
/// `io_engine` is 0 for the historical synchronous worker and 1 for restricted
/// io_uring reads on buffered raw images. Buffered writes remain synchronous.
/// The async engine intentionally rejects direct I/O, whose alignment contract
/// it cannot currently preserve.
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(feature = "blk")]
pub unsafe extern "C" fn krun_add_disk4(
    ctx_id: u32,
    c_block_id: *const c_char,
    c_disk_path: *const c_char,
    disk_format: u32,
    read_only: bool,
    direct_io: bool,
    sync_mode: u32,
    io_engine: u32,
) -> i32 {
    unsafe {
        let disk_path = match CStr::from_ptr(c_disk_path).to_str() {
            Ok(disk) => disk,
            Err(_) => return -libc::EINVAL,
        };
        let block_id = match CStr::from_ptr(c_block_id).to_str() {
            Ok(block_id) => block_id,
            Err(_) => return -libc::EINVAL,
        };
        let format = match ImageType::try_from(disk_format) {
            Ok(format) => format,
            Err(_) => return -libc::EINVAL,
        };
        let sync_mode = match SyncMode::try_from(sync_mode) {
            Ok(mode) => mode,
            Err(_) => return -libc::EINVAL,
        };
        let io_engine = match devices::virtio::block::BlockIoEngine::try_from(io_engine) {
            Ok(engine) => engine,
            Err(_) => return -libc::EINVAL,
        };
        if io_engine == devices::virtio::block::BlockIoEngine::Async && direct_io {
            return -libc::ENOTSUP;
        }

        // Ring setup and file registration must happen before the launcher
        // installs its final seccomp filter. Structured formats retain the
        // synchronous metadata path and therefore need no ring.
        let prepared_async = if io_engine == devices::virtio::block::BlockIoEngine::Async
            && format == ImageType::Raw
        {
            match devices::virtio::block::prepare_async_io(disk_path, !read_only) {
                Ok(prepared) => Some(prepared),
                Err(error) => {
                    let errno = error.raw_os_error().unwrap_or(libc::EIO);
                    error!("Error preparing async block I/O for {disk_path}: {error}");
                    set_last_error(format!(
                        "prepare restricted async block I/O for {disk_path}: {error}"
                    ));
                    return -errno;
                }
            }
        } else {
            None
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                ctx_cfg.get_mut().add_block_cfg(BlockDeviceConfig {
                    block_id: block_id.to_string(),
                    cache_type: CacheType::auto(disk_path),
                    disk_image_path: disk_path.to_string(),
                    disk_image_format: format,
                    is_disk_read_only: read_only,
                    direct_io,
                    sync_mode,
                    io_engine,
                    prepared_async,
                });
            }
            Entry::Vacant(_) => {
                if let Some(prepared) = prepared_async {
                    devices::virtio::block::discard_prepared_async_io(prepared);
                }
                return -libc::ENOENT;
            }
        }
        KRUN_SUCCESS
    }
}

/*
 * Send the VFKIT magic after establishing the connection,
 * as required by gvproxy in vfkit mode.
 */
// VFKIT magic / NET_FLAG_ALL are consumed only by the Unix unixgram backend.
#[cfg(all(feature = "net", unix))]
const NET_FLAG_VFKIT: u32 = 1 << 0;
#[cfg(feature = "net")]
const NET_FLAG_DHCP_CLIENT: u32 = 1 << 1;
#[cfg(all(feature = "net", unix))]
const NET_FLAG_ALL: u32 = NET_FLAG_VFKIT | NET_FLAG_DHCP_CLIENT;

/* Taken from uapi/linux/virtio_net.h */
#[cfg(feature = "net")]
const NET_FEATURE_CSUM: u32 = 1 << 0;
#[cfg(feature = "net")]
const NET_FEATURE_GUEST_CSUM: u32 = 1 << 1;
#[cfg(feature = "net")]
const NET_FEATURE_GUEST_TSO4: u32 = 1 << 7;
#[cfg(feature = "net")]
const NET_FEATURE_GUEST_TSO6: u32 = 1 << 8;
#[cfg(feature = "net")]
const NET_FEATURE_GUEST_UFO: u32 = 1 << 10;
#[cfg(feature = "net")]
const NET_FEATURE_HOST_TSO4: u32 = 1 << 11;
#[cfg(feature = "net")]
const NET_FEATURE_HOST_TSO6: u32 = 1 << 12;
#[cfg(feature = "net")]
const NET_FEATURE_HOST_UFO: u32 = 1 << 14;

#[cfg(feature = "net")]
const NET_ALL_FEATURES: u32 = NET_FEATURE_CSUM
    | NET_FEATURE_GUEST_CSUM
    | NET_FEATURE_GUEST_TSO4
    | NET_FEATURE_GUEST_TSO6
    | NET_FEATURE_GUEST_UFO
    | NET_FEATURE_HOST_TSO4
    | NET_FEATURE_HOST_TSO6
    | NET_FEATURE_HOST_UFO;

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(feature = "net")]
pub unsafe extern "C" fn krun_add_net_unixstream(
    ctx_id: u32,
    c_path: *const c_char,
    fd: c_int,
    c_mac: *const u8,
    features: u32,
    flags: u32,
) -> i32 {
    unsafe {
        let path = if !c_path.is_null() {
            match CStr::from_ptr(c_path).to_str() {
                Ok(path) => Some(PathBuf::from(path)),
                Err(_) => None,
            }
        } else {
            None
        };

        if fd >= 0 && path.is_some() {
            return -libc::EINVAL;
        }
        if fd < 0 && path.is_none() {
            return -libc::EINVAL;
        }
        // Passing a raw fd is Unix-only; on Windows use the path form.
        let backend = match (path, fd) {
            (Some(path), _) => VirtioNetBackend::UnixstreamPath(path),
            #[cfg(unix)]
            (None, fd) => VirtioNetBackend::UnixstreamFd(fd),
            #[cfg(not(unix))]
            (None, _) => return -libc::EINVAL,
        };

        let mac: [u8; 6] = match slice::from_raw_parts(c_mac, 6).try_into() {
            Ok(m) => m,
            Err(_) => return -libc::EINVAL,
        };

        if (flags & !NET_FLAG_DHCP_CLIENT) != 0 {
            return -libc::EINVAL;
        }
        let enable_dhcp_client: bool = flags & NET_FLAG_DHCP_CLIENT != 0;

        if (features & !NET_ALL_FEATURES) != 0 {
            return -libc::EINVAL;
        }

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                create_virtio_net(cfg, backend, mac, features);
                if enable_dhcp_client {
                    cfg.vmr.dhcp_client = true;
                }
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }
        KRUN_SUCCESS
    }
}

// AF_UNIX datagram sockets are Unix-only (Windows AF_UNIX is stream-only); use
// krun_add_net_unixstream on Windows.
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(all(feature = "net", windows))]
pub unsafe extern "C" fn krun_add_net_unixgram(
    _ctx_id: u32,
    _c_path: *const c_char,
    _fd: c_int,
    _c_mac: *const u8,
    _features: u32,
    _flags: u32,
) -> i32 {
    -libc::ENOTSUP
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(all(feature = "net", unix))]
pub unsafe extern "C" fn krun_add_net_unixgram(
    ctx_id: u32,
    c_path: *const c_char,
    fd: c_int,
    c_mac: *const u8,
    features: u32,
    flags: u32,
) -> i32 {
    unsafe {
        let path = if !c_path.is_null() {
            match CStr::from_ptr(c_path).to_str() {
                Ok(path) => Some(PathBuf::from(path)),
                Err(_) => None,
            }
        } else {
            None
        };

        if fd >= 0 && path.is_some() {
            return -libc::EINVAL;
        }
        if fd < 0 && path.is_none() {
            return -libc::EINVAL;
        }

        let mac: [u8; 6] = match slice::from_raw_parts(c_mac, 6).try_into() {
            Ok(m) => m,
            Err(_) => return -libc::EINVAL,
        };

        if (features & !NET_ALL_FEATURES) != 0 {
            return -libc::EINVAL;
        }

        if (flags & !NET_FLAG_ALL) != 0 {
            return -libc::EINVAL;
        }
        let send_vfkit_magic: bool = flags & NET_FLAG_VFKIT != 0;
        let enable_dhcp_client: bool = flags & NET_FLAG_DHCP_CLIENT != 0;

        let backend = if let Some(path) = path {
            VirtioNetBackend::UnixgramPath(path, send_vfkit_magic)
        } else {
            VirtioNetBackend::UnixgramFd(fd)
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                create_virtio_net(cfg, backend, mac, features);
                if enable_dhcp_client {
                    cfg.vmr.dhcp_client = true;
                }
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }
        KRUN_SUCCESS
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(all(target_os = "linux", feature = "net"))]
pub unsafe extern "C" fn krun_add_net_tap(
    ctx_id: u32,
    c_tap_name: *const c_char,
    c_mac: *const u8,
    features: u32,
    flags: u32,
) -> i32 {
    unsafe {
        let tap_name = match CStr::from_ptr(c_tap_name).to_str() {
            Ok(tap_name) => tap_name.to_string(),
            Err(e) => {
                debug!("Error parsing tap_name: {e:?}");
                return -libc::EINVAL;
            }
        };

        let mac: [u8; 6] = match slice::from_raw_parts(c_mac, 6).try_into() {
            Ok(m) => m,
            Err(_) => return -libc::EINVAL,
        };

        if (features & !NET_ALL_FEATURES) != 0 {
            return -libc::EINVAL;
        }

        if features & (NET_FEATURE_GUEST_TSO4 | NET_FEATURE_GUEST_TSO6 | NET_FEATURE_GUEST_UFO) != 0
            && features & NET_FEATURE_GUEST_CSUM == 0
        {
            debug!(
                "Network tap backend requires GUEST_CSUM to be requested if any of GUEST_TSO4, GUEST_TSO6 and/or GUEST_UFO are required"
            );
            return -libc::EINVAL;
        }

        if (flags & !NET_FLAG_DHCP_CLIENT) != 0 {
            return -libc::EINVAL;
        }
        let enable_dhcp_client: bool = flags & NET_FLAG_DHCP_CLIENT != 0;

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                create_virtio_net(cfg, VirtioNetBackend::Tap(tap_name), mac, features);
                if enable_dhcp_client {
                    cfg.vmr.dhcp_client = true;
                }
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }
        KRUN_SUCCESS
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(all(not(target_os = "linux"), feature = "net"))]
pub unsafe extern "C" fn krun_add_net_tap(
    _ctx_id: u32,
    _c_tap_name: *const c_char,
    _c_mac: *const u8,
    _features: u32,
    _flags: u32,
) -> i32 {
    -libc::EINVAL
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_port_map(ctx_id: u32, c_port_map: *const *const c_char) -> i32 {
    unsafe {
        let mut port_map = HashMap::new();
        let port_map_array: &[*const c_char] = slice::from_raw_parts(c_port_map, MAX_ARGS);
        for item in port_map_array.iter().take(MAX_ARGS) {
            if item.is_null() {
                break;
            } else {
                let s = match CStr::from_ptr(*item).to_str() {
                    Ok(s) => s,
                    Err(_) => return -libc::EINVAL,
                };
                let port_tuple: Vec<&str> = s.split(':').collect();
                if port_tuple.len() != 2 {
                    return -libc::EINVAL;
                }
                let host_port: u16 = match port_tuple[0].parse() {
                    Ok(p) => p,
                    Err(_) => return -libc::EINVAL,
                };
                let guest_port: u16 = match port_tuple[1].parse() {
                    Ok(p) => p,
                    Err(_) => return -libc::EINVAL,
                };

                if port_map.contains_key(&guest_port) {
                    return -libc::EINVAL;
                }
                for hp in port_map.values() {
                    if *hp == host_port {
                        return -libc::EINVAL;
                    }
                }
                port_map.insert(guest_port, host_port);
            }
        }

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                if cfg.vsock_config == VsockConfig::Disabled {
                    return -libc::ENODEV;
                }
                if cfg.set_port_map(port_map).is_err() {
                    return -libc::EINVAL;
                }
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn parse_egress_cidrs(
    c_cidrs: *const *const c_char,
) -> Result<Option<Vec<(std::net::IpAddr, u8)>>, i32> {
    use std::net::IpAddr;

    if c_cidrs.is_null() {
        return Ok(None);
    }

    let mut parsed = Vec::new();
    let array: &[*const c_char] = slice::from_raw_parts(c_cidrs, MAX_ARGS);
    for item in array
        .iter()
        .take(MAX_ARGS)
        .take_while(|item| !item.is_null())
    {
        let s = CStr::from_ptr(*item).to_str().map_err(|_| -libc::EINVAL)?;

        // Parse "IP/prefix" or bare "IP"
        let (ip, prefix_len) = if let Some((ip_part, prefix_part)) = s.split_once('/') {
            let prefix: u8 = prefix_part.parse().map_err(|_| -libc::EINVAL)?;
            let ip: IpAddr = ip_part.parse().map_err(|_| -libc::EINVAL)?;
            (ip, prefix)
        } else {
            let ip: IpAddr = s.parse().map_err(|_| -libc::EINVAL)?;
            let prefix = if ip.is_ipv4() { 32u8 } else { 128u8 };
            (ip, prefix)
        };

        match ip {
            IpAddr::V4(_) if prefix_len > 32 => return Err(-libc::EINVAL),
            IpAddr::V6(_) if prefix_len > 128 => return Err(-libc::EINVAL),
            _ => {}
        }

        parsed.push((ip, prefix_len));
    }

    Ok(Some(parsed))
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn parse_egress_hosts(c_hosts: *const *const c_char) -> Result<Option<Vec<String>>, i32> {
    if c_hosts.is_null() {
        return Ok(None);
    }

    let mut hosts = Vec::new();
    let array: &[*const c_char] = slice::from_raw_parts(c_hosts, MAX_ARGS);
    for item in array
        .iter()
        .take(MAX_ARGS)
        .take_while(|item| !item.is_null())
    {
        let host = CStr::from_ptr(*item)
            .to_str()
            .map_err(|_| -libc::EINVAL)?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        // A hostname can never contain ':' — reject obvious garbage (e.g. an
        // "ip:port" passed by mistake) instead of treating it as a host.
        if host.is_empty() || host.contains(':') {
            return Err(-libc::EINVAL);
        }
        hosts.push(host);
    }

    Ok(Some(hosts))
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn parse_egress_resolvers(
    c_resolvers: *const *const c_char,
) -> Result<Option<Vec<std::net::IpAddr>>, i32> {
    use std::net::IpAddr;

    if c_resolvers.is_null() {
        return Ok(None);
    }

    let mut resolvers = Vec::new();
    let array: &[*const c_char] = slice::from_raw_parts(c_resolvers, MAX_ARGS);
    for item in array
        .iter()
        .take(MAX_ARGS)
        .take_while(|item| !item.is_null())
    {
        let ip: IpAddr = CStr::from_ptr(*item)
            .to_str()
            .map_err(|_| -libc::EINVAL)?
            .parse()
            .map_err(|_| -libc::EINVAL)?;
        resolvers.push(ip);
    }

    Ok(Some(resolvers))
}

/// Set the egress policy for TSI networking.
///
/// Accepts optional null-terminated arrays of CIDR strings, allowed DNS
/// hostnames, and trusted DNS resolver IPs. Explicit CIDRs are always allowed.
/// Hostnames enable interception of guest UDP DNS queries (port 53): allowed
/// names are forwarded ONLY to the trusted resolvers (never the resolver the
/// guest chose), and A/AAAA answers are learned as temporary allowed IPs.
///
/// Bare IPs without a prefix are treated as /32 (IPv4) or /128 (IPv6). Any of
/// the three pointers may be NULL ("not set"). Returns -EINVAL if both CIDRs
/// and hostnames are NULL, if any entry is invalid, or if hostnames are given
/// without at least one resolver (hostname allow-listing is unsafe without a
/// trusted upstream).
#[allow(clippy::missing_safety_doc)]
#[allow(unsafe_op_in_unsafe_fn)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_egress_policy(
    ctx_id: u32,
    c_cidrs: *const *const c_char,
    c_egress_hosts: *const *const c_char,
    c_dns_resolvers: *const *const c_char,
) -> i32 {
    use std::net::IpAddr;

    let cidrs = match parse_egress_cidrs(c_cidrs) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let hosts = match parse_egress_hosts(c_egress_hosts) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let resolvers: Option<Vec<IpAddr>> = match parse_egress_resolvers(c_dns_resolvers) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if cidrs.is_none() && hosts.is_none() {
        return -libc::EINVAL;
    }

    // Hostname allow-listing is meaningless (and unsafe) without a trusted
    // resolver: the guest could otherwise dictate name->IP mappings. Refuse the
    // configuration rather than silently degrade.
    let hosts_present = hosts.as_ref().is_some_and(|h| !h.is_empty());
    let resolvers_present = resolvers.as_ref().is_some_and(|r| !r.is_empty());
    if hosts_present && !resolvers_present {
        return -libc::EINVAL;
    }

    let mut map = match CTX_MAP.lock() {
        Ok(map) => map,
        Err(_) => return -libc::EINVAL,
    };
    match map.entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            if cfg.vsock_config == VsockConfig::Disabled {
                return -libc::ENODEV;
            }
            cfg.egress_cidrs = cidrs;
            cfg.egress_hosts = hosts;
            cfg.egress_resolvers = resolvers;
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

/// Route every guest UDP DNS query (destination port 53, whatever resolver
/// the guest chose) to a host DNS forwarder on loopback, and relay its answers
/// back. The forwarder decides the upstream and may cache. With an allow-host
/// egress policy the name is still checked here first and the answer's
/// addresses learned; the forwarder only replaces the trusted resolvers.
///
/// `c_addr` is an `ip:port` on the host's loopback. Returns -EINVAL for any
/// other address, -ENOENT for an unknown context and -ENODEV without vsock.
#[allow(clippy::missing_safety_doc)]
#[allow(unsafe_op_in_unsafe_fn)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_dns_forwarder(ctx_id: u32, c_addr: *const c_char) -> i32 {
    if c_addr.is_null() {
        return -libc::EINVAL;
    }
    let addr: std::net::SocketAddr = match CStr::from_ptr(c_addr).to_str().map(str::parse) {
        Ok(Ok(addr)) => addr,
        _ => return -libc::EINVAL,
    };
    if !addr.ip().is_loopback() || addr.port() == 0 {
        return -libc::EINVAL;
    }
    let mut map = match CTX_MAP.lock() {
        Ok(map) => map,
        Err(_) => return -libc::EINVAL,
    };
    match map.entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            if cfg.vsock_config == VsockConfig::Disabled {
                return -libc::ENODEV;
            }
            cfg.dns_forwarder = Some(addr);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }
    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_stream_intercept(
    ctx_id: u32,
    c_endpoint: *const c_char,
    c_token_hex: *const c_char,
    port: u16,
) -> i32 {
    use devices::virtio::vsock::StreamIntercept;

    if c_endpoint.is_null() || c_token_hex.is_null() || port == 0 {
        return -libc::EINVAL;
    }
    let endpoint: std::net::SocketAddr = match unsafe { CStr::from_ptr(c_endpoint) }
        .to_str()
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(addr) => addr,
        None => return -libc::EINVAL,
    };
    // The interceptor must be a listener the VMM owner runs on this host; a
    // routable endpoint would let the preamble token leave the machine.
    if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
        return -libc::EINVAL;
    }
    let token_hex = match unsafe { CStr::from_ptr(c_token_hex) }.to_str() {
        Ok(hex) if hex.len() == 64 => hex,
        _ => return -libc::EINVAL,
    };
    let mut token = [0u8; 32];
    for (i, byte) in token.iter_mut().enumerate() {
        match u8::from_str_radix(&token_hex[2 * i..2 * i + 2], 16) {
            Ok(value) => *byte = value,
            Err(_) => return -libc::EINVAL,
        }
    }

    let mut map = match CTX_MAP.lock() {
        Ok(map) => map,
        Err(_) => return -libc::EINVAL,
    };
    match map.entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            if cfg.vsock_config == VsockConfig::Disabled {
                return -libc::ENODEV;
            }
            cfg.stream_intercept = Some(StreamIntercept {
                endpoint,
                token,
                port,
            });
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_rlimits(ctx_id: u32, c_rlimits: *const *const c_char) -> i32 {
    unsafe {
        let rlimits = if c_rlimits.is_null() {
            return -libc::EINVAL;
        } else {
            let mut strvec = Vec::new();

            let array: &[*const c_char] = slice::from_raw_parts(c_rlimits, MAX_ARGS);
            for item in array.iter().take(MAX_ARGS) {
                if item.is_null() {
                    break;
                } else {
                    let s = match CStr::from_ptr(*item).to_str() {
                        Ok(s) => s,
                        Err(_) => return -libc::EINVAL,
                    };
                    strvec.push(s);
                }
            }

            format!("\"{}\"", strvec.join(","))
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                ctx_cfg.get_mut().set_rlimits(rlimits);
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_workdir(ctx_id: u32, c_workdir_path: *const c_char) -> i32 {
    unsafe {
        let workdir_path = match CStr::from_ptr(c_workdir_path).to_str() {
            Ok(workdir) => workdir,
            Err(_) => return -libc::EINVAL,
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                ctx_cfg.get_mut().set_workdir(workdir_path.to_string());
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

unsafe fn collapse_str_array(array: &[*const c_char]) -> Result<String, std::str::Utf8Error> {
    unsafe {
        let mut strvec = Vec::new();

        for item in array.iter().take(MAX_ARGS) {
            if item.is_null() {
                break;
            } else {
                let s = CStr::from_ptr(*item).to_str()?;
                strvec.push(format!("\"{s}\""));
            }
        }

        Ok(strvec.join(" "))
    }
}

#[allow(clippy::format_collect)]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_exec(
    ctx_id: u32,
    c_exec_path: *const c_char,
    c_argv: *const *const c_char,
    c_envp: *const *const c_char,
) -> i32 {
    unsafe {
        let exec_path = match CStr::from_ptr(c_exec_path).to_str() {
            Ok(path) => path,
            Err(e) => {
                debug!("Error parsing exec_path: {e:?}");
                return -libc::EINVAL;
            }
        };

        let args = if !c_argv.is_null() {
            let argv_array: &[*const c_char] = slice::from_raw_parts(c_argv, MAX_ARGS);
            match collapse_str_array(argv_array) {
                Ok(s) => s,
                Err(e) => {
                    debug!("Error parsing args: {e:?}");
                    return -libc::EINVAL;
                }
            }
        } else {
            "".to_string()
        };

        let env = if !c_envp.is_null() {
            let envp_array: &[*const c_char] = slice::from_raw_parts(c_envp, MAX_ARGS);
            match collapse_str_array(envp_array) {
                Ok(s) => s,
                Err(e) => {
                    debug!("Error parsing args: {e:?}");
                    return -libc::EINVAL;
                }
            }
        } else {
            env::vars()
                .map(|(key, value)| format!(" {key}=\"{value}\""))
                .collect()
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                cfg.set_exec_path(exec_path.to_string());
                cfg.set_env(env);
                cfg.set_args(args);
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

#[allow(clippy::format_collect)]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_env(ctx_id: u32, c_envp: *const *const c_char) -> i32 {
    unsafe {
        let env = if !c_envp.is_null() {
            let envp_array: &[*const c_char] = slice::from_raw_parts(c_envp, MAX_ARGS);
            match collapse_str_array(envp_array) {
                Ok(s) => s,
                Err(e) => {
                    debug!("Error parsing args: {e:?}");
                    return -libc::EINVAL;
                }
            }
        } else {
            env::vars()
                .map(|(key, value)| format!(" {key}=\"{value}\""))
                .collect()
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                cfg.set_env(env);
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(feature = "tee")]
pub unsafe extern "C" fn krun_set_tee_config_file(ctx_id: u32, c_filepath: *const c_char) -> i32 {
    unsafe {
        let filepath = match CStr::from_ptr(c_filepath).to_str() {
            Ok(f) => f,
            Err(_) => return -libc::EINVAL,
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                cfg.set_tee_config_file(PathBuf::from(filepath.to_string()));
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_vsock_port(
    ctx_id: u32,
    port: u32,
    c_filepath: *const c_char,
) -> i32 {
    unsafe { krun_add_vsock_port2(ctx_id, port, c_filepath, false) }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_vsock_port2(
    ctx_id: u32,
    port: u32,
    c_filepath: *const c_char,
    listen: bool,
) -> i32 {
    unsafe {
        #[cfg(feature = "aws-nitro")]
        if listen {
            return -libc::EINVAL;
        }

        let filepath = match CStr::from_ptr(c_filepath).to_str() {
            Ok(f) => PathBuf::from(f.to_string()),
            Err(_) => return -libc::EINVAL,
        };

        if listen {
            match filepath.try_exists() {
                Ok(true) => return -libc::EEXIST,
                Err(_) => return -libc::EINVAL,
                _ => {}
            }
        }

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                if cfg.vsock_config == VsockConfig::Disabled {
                    return -libc::ENODEV;
                }
                cfg.add_vsock_port(port, filepath, listen);
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_gpu_options(ctx_id: u32, virgl_flags: u32) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_gpu_virgl_flags(virgl_flags);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_gpu_options2(
    ctx_id: u32,
    virgl_flags: u32,
    shm_size: u64,
) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_gpu_virgl_flags(virgl_flags);
            cfg.set_gpu_shm_size(shm_size.try_into().unwrap());
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[cfg(not(feature = "gpu"))]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub extern "C" fn krun_set_display_backend(
    _ctx_id: u32,
    _features: u32,
    _vtable: *const c_void,
    _vtable_size: usize,
) -> i32 {
    -libc::ENOTSUP
}

#[cfg(feature = "gpu")]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub extern "C" fn krun_set_display_backend(
    ctx_id: u32,
    vtable: *const c_void,
    vtable_size: usize,
) -> i32 {
    // Callers built against an older header pass a struct that ends at the basic vtable; the
    // cursor vtable that follows is optional and stays zero for them.
    let basic_len = std::mem::offset_of!(DisplayBackend, cursor);
    if vtable_size < basic_len {
        return -libc::EINVAL;
    }

    // SAFETY: the struct is plain data (integers, pointers and optional function pointers), so an
    // all-zero value is valid, and only `vtable_size` bytes are read from the caller.
    let mut display_backend: DisplayBackend = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            vtable as *const u8,
            (&raw mut display_backend) as *mut u8,
            vtable_size.min(size_of::<DisplayBackend>()),
        )
    };

    if !display_backend.verify() {
        return -libc::EINVAL;
    }

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.vmr.display_backend = Some(display_backend);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[cfg(not(feature = "input"))]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub extern "C" fn krun_add_input_device(
    _ctx_id: u32,
    _config_backend: *const c_void,
    _config_backend_size: size_t,
    _event_provider_backend: *const c_void,
    _event_provider_backend_size: size_t,
) -> i32 {
    -libc::ENOTSUP
}

#[cfg(feature = "input")]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub extern "C" fn krun_add_input_device_fd(ctx_id: u32, input_fd: i32) -> i32 {
    use devices::virtio::input::passthrough::PassthroughInputBackend;
    use krun_input::{IntoInputConfig, IntoInputEvents};

    if input_fd < 0 {
        return -libc::EINVAL;
    }
    // TODO: currently we let the fd (and it's Box allocation) live forever, we should eventually fix
    //       this
    let input_fd = unsafe {
        // SAFETY: The user provided fd should be valid. Its lifetime is 'static because it will
        //         exist until libkrun _exits the process
        BorrowedFd::borrow_raw(input_fd)
    };
    let borrowed_fd: &'static BorrowedFd<'static> = Box::leak(Box::new(input_fd));

    let config_backend = PassthroughInputBackend::into_input_config(Some(borrowed_fd));
    let events_backend = PassthroughInputBackend::into_input_events(Some(borrowed_fd));

    with_cfg(ctx_id, |cfg| {
        cfg.vmr
            .input_backends
            .push((config_backend, events_backend));
        KRUN_SUCCESS
    })
}

#[cfg(feature = "input")]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_input_device(
    ctx_id: u32,
    config_backend: *const InputConfigBackend<'static>,
    config_backend_size: size_t,
    event_provider_backend: *const InputEventProviderBackend<'static>,
    event_provider_backend_size: size_t,
) -> i32 {
    if config_backend.is_null() || event_provider_backend.is_null() {
        return -libc::EINVAL;
    }

    if config_backend_size < size_of::<InputConfigBackend>()
        || event_provider_backend_size < size_of::<InputEventProviderBackend>()
    {
        return -libc::EINVAL;
    }

    let config_backend = unsafe { *config_backend };
    let events_backend = unsafe { *event_provider_backend };

    if !config_backend.verify() || !events_backend.verify() {
        return -libc::EINVAL;
    }

    with_cfg(ctx_id, |cfg| {
        cfg.vmr
            .input_backends
            .push((config_backend, events_backend));
        KRUN_SUCCESS
    })
}

#[cfg(not(feature = "input"))]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_input_device_fd(_ctx_id: u32, _input_fd: i32) -> i32 {
    -libc::ENOTSUP
}

#[cfg(feature = "gpu")]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_display(ctx_id: u32, width: u32, height: u32) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            if cfg.vmr.displays.len() >= MAX_DISPLAYS {
                return -libc::ENOMEM;
            }

            cfg.vmr.displays.push(DisplayInfo::new(width, height));
            (cfg.vmr.displays.len() - 1) as i32
        }
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

#[cfg(not(feature = "gpu"))]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_display(_ctx_id: u32, _width: u32, _height: u32) -> i32 {
    -libc::ENOTSUP
}

#[cfg(feature = "gpu")]
#[unsafe(no_mangle)]
pub extern "C" fn krun_display_set_refresh_rate(
    ctx_id: u32,
    display_id: u32,
    refresh_rate: u32,
) -> i32 {
    with_cfg(ctx_id, |cfg| {
        let Some(display_info) = cfg.vmr.displays.get_mut(display_id as usize) else {
            return -libc::EINVAL;
        };

        let DisplayInfoEdid::Generated(ref mut edid_params) = display_info.edid else {
            return -libc::EALREADY;
        };

        edid_params.refresh_rate = refresh_rate;
        KRUN_SUCCESS
    })
}

#[cfg(not(feature = "gpu"))]
#[unsafe(no_mangle)]
pub extern "C" fn krun_display_set_refresh_rate(
    _ctx_id: u32,
    _display_id: u32,
    _refresh_rate: u32,
) -> i32 {
    -libc::ENOTSUP
}

#[cfg(feature = "gpu")]
#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn krun_display_set_edid(
    ctx_id: u32,
    display_id: u32,
    edid: *const u8,
    size: size_t,
) -> i32 {
    with_cfg(ctx_id, |cfg| {
        let Some(display_info) = cfg.vmr.displays.get_mut(display_id as usize) else {
            return -libc::EINVAL;
        };

        if edid.is_null() {
            return -libc::EINVAL;
        }

        let blob = unsafe { slice::from_raw_parts(edid, size) };

        display_info.edid = DisplayInfoEdid::Provided(Box::from(blob));
        KRUN_SUCCESS
    })
}

#[cfg(not(feature = "gpu"))]
#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn krun_display_set_edid(
    _ctx_id: u32,
    _display_id: u32,
    _edid: *const u8,
    _size: size_t,
) -> i32 {
    -libc::ENOTSUP
}

#[cfg(feature = "gpu")]
#[unsafe(no_mangle)]
pub extern "C" fn krun_display_set_physical_size(
    ctx_id: u32,
    display_id: u32,
    width_mm: u16,
    height_mm: u16,
) -> i32 {
    with_cfg(ctx_id, |cfg| {
        let Some(display_info) = cfg.vmr.displays.get_mut(display_id as usize) else {
            return -libc::EINVAL;
        };
        let DisplayInfoEdid::Generated(ref mut edid_params) = display_info.edid else {
            return -libc::EALREADY;
        };
        edid_params.physical_size = PhysicalSize::DimensionsMillimeters(width_mm, height_mm);
        KRUN_SUCCESS
    })
}

#[cfg(not(feature = "gpu"))]
#[unsafe(no_mangle)]
pub extern "C" fn krun_display_set_physical_size(
    _ctx_id: u32,
    _display_id: u32,
    _width_mm: u16,
    _height_mm: u16,
) -> i32 {
    -libc::ENOTSUP
}

#[cfg(feature = "gpu")]
#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub extern "C" fn krun_display_set_dpi(ctx_id: u32, display_id: u32, dpi: u32) -> i32 {
    with_cfg(ctx_id, |cfg| {
        let Some(display_info) = cfg.vmr.displays.get_mut(display_id as usize) else {
            return -libc::EINVAL;
        };
        let DisplayInfoEdid::Generated(ref mut edid_params) = display_info.edid else {
            return -libc::EINVAL;
        };
        edid_params.physical_size = PhysicalSize::Dpi(dpi);
        KRUN_SUCCESS
    })
}

#[cfg(not(feature = "gpu"))]
#[unsafe(no_mangle)]
pub extern "C" fn krun_display_set_dpi(_ctx_id: u32, _display_id: u32, _dpi: u32) -> i32 {
    -libc::ENOTSUP
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(feature = "vhost-user")]
pub unsafe extern "C" fn krun_add_vhost_user_device(
    ctx_id: u32,
    device_type: u32,
    socket_path: *const c_char,
    name: *const c_char,
    num_queues: u16,
    queue_sizes: *const u16,
) -> i32 {
    use vmm::resources::VhostUserDeviceConfig;

    let socket_path_str = match unsafe { CStr::from_ptr(socket_path) }.to_str() {
        Ok(s) => s,
        Err(_) => return -libc::EINVAL,
    };

    if socket_path_str.is_empty() {
        return -libc::EINVAL;
    }

    let name_opt = if name.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(name) }.to_str() {
            Ok(s) if !s.is_empty() => Some(s.to_string()),
            _ => None,
        }
    };

    let queue_sizes_vec = if queue_sizes.is_null() {
        Vec::new()
    } else if num_queues == 0 {
        // Auto-detect mode: read queue_sizes until we hit 0 (sentinel)
        let mut sizes = Vec::new();
        let mut i = 0;
        loop {
            let size = unsafe { *queue_sizes.add(i) };
            if size == 0 {
                break;
            }
            sizes.push(size);
            i += 1;

            // Safety: prevent infinite loop if user forgets sentinel terminator
            if i >= VIRTIO_MAX_QUEUES {
                return -libc::EINVAL;
            }
        }
        sizes
    } else {
        unsafe { std::slice::from_raw_parts(queue_sizes, num_queues as usize) }.to_vec()
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.vmr.vhost_user_devices.push(VhostUserDeviceConfig {
                device_type,
                socket_path: socket_path_str.to_string(),
                name: name_opt,
                num_queues,
                queue_sizes: queue_sizes_vec,
            });
            KRUN_SUCCESS
        }
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(not(feature = "vhost-user"))]
pub unsafe extern "C" fn krun_add_vhost_user_device(
    _ctx_id: u32,
    _device_type: u32,
    _socket_path: *const c_char,
    _name: *const c_char,
    _num_queues: u16,
    _queue_sizes: *const u16,
) -> i32 {
    -libc::ENOTSUP
}

// FIXME: aws-nitro builds its own NitroEnclave from ContextConfig and needs
// the console output path directly. This should be replaced with a proper
// console configuration in the nitro path.
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(feature = "aws-nitro")]
pub unsafe extern "C" fn krun_set_console_output(ctx_id: u32, c_filepath: *const c_char) -> i32 {
    unsafe {
        let filepath = match CStr::from_ptr(c_filepath).to_str() {
            Ok(f) => f,
            Err(_) => return -libc::EINVAL,
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                if cfg.nitro_console_output.is_some() {
                    -libc::EINVAL
                } else {
                    cfg.nitro_console_output = Some(PathBuf::from(filepath.to_string()));
                    KRUN_SUCCESS
                }
            }
            Entry::Vacant(_) => -libc::ENOENT,
        }
    }
}

#[allow(unused_assignments)]
#[unsafe(no_mangle)]
pub extern "C" fn krun_get_shutdown_eventfd(ctx_id: u32) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            if let Some(efd) = cfg.shutdown_efd.as_ref() {
                #[cfg(target_os = "macos")]
                return efd.get_write_fd();
                #[cfg(target_os = "linux")]
                return efd.as_raw_fd();
                // TODO(whp-host): exposing the shutdown eventfd's HANDLE as a C
                // int isn't meaningful on Windows; returning it is left for the
                // Windows event-handle story.
                #[cfg(target_os = "windows")]
                {
                    let _ = efd;
                    -libc::ENOTSUP
                }
            } else {
                -libc::EINVAL
            }
        }
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_control_socket(ctx_id: u32, c_socket_path: *const c_char) -> i32 {
    unsafe {
        if c_socket_path.is_null() {
            return -libc::EINVAL;
        }

        let socket_path = match CStr::from_ptr(c_socket_path).to_str() {
            Ok(path) => PathBuf::from(path),
            Err(_) => return -libc::EINVAL,
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                ctx_cfg.get_mut().control_socket_path = Some(socket_path);
                KRUN_SUCCESS
            }
            Entry::Vacant(_) => -libc::ENOENT,
        }
    }
}

/// Boot this context as a **fork clone** from a snapshot directory produced by a
/// golden VM's `FORK` control command (containing `checkpoint.bin` +
/// `manifest.bin`). The clone CoW-maps the golden VM's guest-RAM memfd and
/// restores VM/device/vCPU state instead of cold-booting. The rest of the
/// context (rootfs, vsock socket, mem/cpu config) must be configured to match
/// the golden VM, with fresh host-side resources (a new vsock socket, etc.).
/// Supported on hosts where libkrun enables VM forking.
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_snapshot(ctx_id: u32, c_snapshot_dir: *const c_char) -> i32 {
    unsafe {
        if c_snapshot_dir.is_null() {
            return -libc::EINVAL;
        }
        let dir = match CStr::from_ptr(c_snapshot_dir).to_str() {
            Ok(path) => PathBuf::from(path),
            Err(_) => return -libc::EINVAL,
        };
        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                ctx_cfg.get_mut().snapshot_dir = Some(dir);
                KRUN_SUCCESS
            }
            Entry::Vacant(_) => -libc::ENOENT,
        }
    }
}

/// Use a read-only regular-file descriptor for portable snapshot RAM.
/// The library duplicates the descriptor; the caller retains ownership.
/// Supported only by Linux branchable restores, which create private memfds.
#[unsafe(no_mangle)]
pub extern "C" fn krun_set_snapshot_memory_fd(ctx_id: u32, fd: i32) -> i32 {
    set_snapshot_memory_input(ctx_id, fd, false)
}

/// Provide read-only checkpoint RAM with explicit lifetime guarantees.
/// Flag 1 opts into immutable backing shared by this VM and its descendants;
/// the caller must not change or truncate that inode during their lifetime.
/// Flag 0 preserves the original API's eager-copy behavior.
#[unsafe(no_mangle)]
pub extern "C" fn krun_set_snapshot_memory_fd2(ctx_id: u32, fd: i32, flags: u32) -> i32 {
    if flags & !1 != 0 {
        return -libc::EINVAL;
    }
    set_snapshot_memory_input(ctx_id, fd, flags == 1)
}

fn set_snapshot_memory_input(ctx_id: u32, fd: i32, immutable: bool) -> i32 {
    #[cfg(all(target_os = "linux", fork_supported))]
    {
        use std::os::fd::BorrowedFd;
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return -libc::EBADF;
        }
        if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & libc::O_PATH != 0 {
            return -libc::EINVAL;
        }
        // Safety: F_GETFL validated the descriptor; it is borrowed only for dup.
        let owned = match unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned() {
            Ok(fd) => fd,
            Err(error) => return -error.raw_os_error().unwrap_or(libc::EIO),
        };
        let file = std::fs::File::from(owned);
        if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
            return -libc::EINVAL;
        }
        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut config) => {
                config.get_mut().snapshot_memory = Some(file);
                config.get_mut().snapshot_memory_immutable = immutable;
                KRUN_SUCCESS
            }
            Entry::Vacant(_) => -libc::ENOENT,
        }
    }
    #[cfg(not(all(target_os = "linux", fork_supported)))]
    {
        let _ = (ctx_id, fd, immutable);
        -libc::ENOTSUP
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_nested_virt(ctx_id: u32, enabled: bool) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.vmr.nested_enabled = enabled;
            KRUN_SUCCESS
        }
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_check_nested_virt() -> i32 {
    #[cfg(target_os = "macos")]
    match hvf::check_nested_virt() {
        Ok(supp) => supp as i32,
        Err(_) => -libc::EINVAL,
    }

    #[cfg(target_os = "linux")]
    {
        let paths = [
            "/sys/module/kvm_intel/parameters/nested",
            "/sys/module/kvm_amd/parameters/nested",
        ];
        if paths.iter().any(|path| {
            std::fs::read_to_string(path).is_ok_and(|contents| {
                let val = contents.trim();
                val == "1" || val.eq_ignore_ascii_case("Y")
            })
        }) {
            1
        } else {
            0
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    -libc::EOPNOTSUPP
}

const KRUN_FEATURE_NET: u64 = 0;
const KRUN_FEATURE_BLK: u64 = 1;
const KRUN_FEATURE_GPU: u64 = 2;
const KRUN_FEATURE_INPUT: u64 = 4;
const KRUN_FEATURE_TEE: u64 = 6;
const KRUN_FEATURE_AMD_SEV: u64 = 7;
const KRUN_FEATURE_INTEL_TDX: u64 = 8;
const KRUN_FEATURE_AWS_NITRO: u64 = 9;
const KRUN_FEATURE_VIRGL_RESOURCE_MAP2: u64 = 10;
const KRUN_FEATURE_INIT_BLOB: u64 = 11;

#[unsafe(no_mangle)]
pub extern "C" fn krun_has_feature(feature: u64) -> c_int {
    let supported = match feature {
        KRUN_FEATURE_NET => cfg!(feature = "net"),
        KRUN_FEATURE_BLK => cfg!(feature = "blk"),
        KRUN_FEATURE_GPU => cfg!(feature = "gpu"),
        KRUN_FEATURE_INPUT => cfg!(feature = "input"),
        KRUN_FEATURE_TEE => cfg!(feature = "tee"),
        KRUN_FEATURE_AMD_SEV => cfg!(feature = "amd-sev"),
        KRUN_FEATURE_INTEL_TDX => cfg!(feature = "tdx"),
        KRUN_FEATURE_AWS_NITRO => cfg!(feature = "aws-nitro"),
        KRUN_FEATURE_VIRGL_RESOURCE_MAP2 => cfg!(feature = "virgl_resource_map2"),
        KRUN_FEATURE_INIT_BLOB => cfg!(feature = "init-blob"),
        _ => return -libc::EINVAL,
    };

    supported as c_int
}

/// Gets the maximum number of vCPUs supported by the hypervisor.
///
/// Returns the maximum number of vCPUs that can be created by this hypervisor,
/// or a negative error code on failure.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[unsafe(no_mangle)]
pub extern "C" fn krun_get_max_vcpus() -> i32 {
    #[cfg(target_os = "macos")]
    {
        use hvf::bindings::{HV_SUCCESS, hv_vm_get_max_vcpu_count};
        let mut max_vcpu_count: u32 = 0;
        let ret = unsafe { hv_vm_get_max_vcpu_count(&mut max_vcpu_count as *mut u32) };
        if ret == HV_SUCCESS {
            max_vcpu_count as i32
        } else {
            error!("Error retrieving max vcpu count: {ret:?}");
            -libc::EINVAL
        }
    }

    #[cfg(target_os = "linux")]
    {
        use kvm_ioctls::Kvm;
        match Kvm::new() {
            Ok(kvm) => kvm.get_max_vcpus() as i32,
            Err(e) => {
                error!("Error retrieving max vcpu count: {e:?}");
                -libc::EINVAL
            }
        }
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub extern "C" fn krun_split_irqchip(ctx_id: u32, enable: bool) -> i32 {
    if enable && !cfg!(target_arch = "x86_64") {
        return -libc::EINVAL;
    }
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.vmr.split_irqchip = enable;
            KRUN_SUCCESS
        }
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_smbios_oem_strings(
    ctx_id: u32,
    oem_strings: *const *const c_char,
) -> i32 {
    unsafe {
        if oem_strings.is_null() {
            return -libc::EINVAL;
        }

        let cstr_ptr_slice = slice::from_raw_parts(oem_strings, MAX_ARGS);

        let mut oem_strings = Vec::new();

        for cstr_ptr in cstr_ptr_slice.iter().take_while(|p| !p.is_null()) {
            let Ok(s) = CStr::from_ptr(*cstr_ptr).to_str() else {
                return -libc::EINVAL;
            };
            oem_strings.push(s.to_string());
        }

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                ctx_cfg.get_mut().vmr.smbios_oem_strings =
                    (!oem_strings.is_empty()).then_some(oem_strings)
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

#[cfg(feature = "net")]
fn create_virtio_net(
    ctx_cfg: &mut ContextConfig,
    backend: VirtioNetBackend,
    mac: [u8; 6],
    features: u32,
) {
    let network_interface_config = NetworkInterfaceConfig {
        iface_id: format!("eth{}", ctx_cfg.net_index),
        backend,
        mac,
        features,
    };
    ctx_cfg.net_index += 1;
    ctx_cfg
        .vmr
        .add_network_interface(network_interface_config)
        .expect("Failed to create network interface");
}

#[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
fn map_kernel(ctx_id: u32, kernel_path: &PathBuf) -> i32 {
    let file = match File::options().read(true).write(false).open(kernel_path) {
        Ok(file) => file,
        Err(err) => {
            error!("Error opening external kernel: {err}");
            return -libc::EINVAL;
        }
    };

    let kernel_size = file.metadata().unwrap().len();

    #[cfg(not(target_os = "windows"))]
    let kernel_host_addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            kernel_size as usize,
            libc::PROT_READ,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0_i64,
        )
    };
    #[cfg(not(target_os = "windows"))]
    if std::ptr::eq(kernel_host_addr, libc::MAP_FAILED) {
        error!("Can't load kernel into process map");
        return -libc::EINVAL;
    }

    // No mmap on Windows: read the kernel into a leaked buffer so its pointer
    // stays valid for the process lifetime, the way an mmap'd region would.
    #[cfg(target_os = "windows")]
    let kernel_host_addr = {
        use std::io::Read;
        let mut file = file;
        let mut buf: Vec<u8> = Vec::with_capacity(kernel_size as usize);
        if file.read_to_end(&mut buf).is_err() {
            error!("Can't load kernel into process map");
            return -libc::EINVAL;
        }
        let ptr = buf.as_ptr() as *mut std::ffi::c_void;
        std::mem::forget(buf);
        ptr
    };

    let kernel_bundle = KernelBundle {
        host_addr: kernel_host_addr as u64,
        guest_addr: 0x8000_0000,
        entry_addr: 0x8000_0000,
        size: kernel_size as usize,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => ctx_cfg
            .get_mut()
            .vmr
            .set_kernel_bundle(kernel_bundle)
            .unwrap(),
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[cfg(feature = "tee")]
#[allow(clippy::format_collect)]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_kernel(_ctx_id: u32, _c_kernel_path: *const c_char) -> i32 {
    -libc::EOPNOTSUPP
}

#[cfg(not(feature = "tee"))]
#[allow(clippy::format_collect)]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_kernel(
    ctx_id: u32,
    c_kernel_path: *const c_char,
    kernel_format: u32,
    c_initramfs_path: *const c_char,
    c_cmdline: *const c_char,
) -> i32 {
    unsafe {
        let path = match CStr::from_ptr(c_kernel_path).to_str() {
            Ok(path) => PathBuf::from(path),
            Err(e) => {
                error!("Error parsing kernel_path: {e:?}");
                return -libc::EINVAL;
            }
        };

        let format = match kernel_format {
            // For raw kernels in x86_64, we map the kernel into the
            // process and treat it as a bundled kernel.
            #[cfg(all(target_arch = "x86_64", not(feature = "tee")))]
            0 => return map_kernel(ctx_id, &path),
            #[cfg(target_arch = "aarch64")]
            0 => KernelFormat::Raw,
            1 => KernelFormat::Elf,
            2 => KernelFormat::PeGz,
            3 => KernelFormat::ImageBz2,
            4 => KernelFormat::ImageGz,
            5 => KernelFormat::ImageZstd,
            _ => {
                return -libc::EINVAL;
            }
        };

        let (initramfs_path, initramfs_size) = if !c_initramfs_path.is_null() {
            match CStr::from_ptr(c_initramfs_path).to_str() {
                Ok(path) => {
                    let path = PathBuf::from(path);
                    let size = match std::fs::metadata(&path) {
                        Ok(metadata) => metadata.len(),
                        Err(e) => {
                            error!("Can't read initramfs metadata: {e:?}");
                            return -libc::EINVAL;
                        }
                    };
                    (Some(path), size)
                }
                Err(e) => {
                    error!("Error parsing initramfs path: {e:?}");
                    return -libc::EINVAL;
                }
            }
        } else {
            (None, 0)
        };

        let cmdline = if !c_cmdline.is_null() {
            match CStr::from_ptr(c_cmdline).to_str() {
                Ok(cmdline) => Some(cmdline.to_string()),
                Err(e) => {
                    error!("Error parsing kernel cmdline: {e:?}");
                    return -libc::EINVAL;
                }
            }
        } else {
            None
        };

        let external_kernel = ExternalKernel {
            path,
            format,
            initramfs_path,
            initramfs_size,
            cmdline,
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                ctx_cfg.get_mut().vmr.set_external_kernel(external_kernel)
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

#[cfg(not(feature = "tee"))]
#[allow(clippy::format_collect)]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_firmware(ctx_id: u32, c_firmware_path: *const c_char) -> i32 {
    unsafe {
        let path = match CStr::from_ptr(c_firmware_path).to_str() {
            Ok(path) => PathBuf::from(path),
            Err(e) => {
                error!("Error parsing firmware_path: {e:?}");
                return -libc::EINVAL;
            }
        };

        let firmware_config = FirmwareConfig { path };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                ctx_cfg.get_mut().vmr.set_firmware_config(firmware_config)
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

unsafe fn load_krunfw_payload(
    krunfw: &KrunfwBindings,
    vmr: &mut VmResources,
) -> Result<(), libloading::Error> {
    let mut kernel_guest_addr: u64 = 0;
    let mut kernel_entry_addr: u64 = 0;
    let mut kernel_size: usize = 0;
    let kernel_host_addr = unsafe {
        (krunfw.get_kernel)(
            &mut kernel_guest_addr as *mut u64,
            &mut kernel_entry_addr as *mut u64,
            &mut kernel_size as *mut usize,
        )
    };
    let kernel_bundle = KernelBundle {
        host_addr: kernel_host_addr as u64,
        guest_addr: kernel_guest_addr,
        entry_addr: kernel_entry_addr,
        size: kernel_size,
    };
    vmr.set_kernel_bundle(kernel_bundle).unwrap();

    #[cfg(feature = "tee")]
    {
        let mut qboot_size: usize = 0;
        let qboot_host_addr = unsafe { (krunfw.get_qboot)(&mut qboot_size as *mut usize) };
        let qboot_bundle = QbootBundle {
            host_addr: qboot_host_addr as u64,
            size: qboot_size,
        };
        vmr.set_qboot_bundle(qboot_bundle).unwrap();

        let mut initrd_size: usize = 0;
        let initrd_host_addr = unsafe { (krunfw.get_initrd)(&mut initrd_size as *mut usize) };
        let initrd_bundle = InitrdBundle {
            host_addr: initrd_host_addr as u64,
            size: initrd_size,
        };
        vmr.set_initrd_bundle(initrd_bundle).unwrap();
    }

    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn krun_setuid(ctx_id: u32, uid: u32) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_vmm_uid(uid);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn krun_setgid(ctx_id: u32, gid: u32) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_vmm_gid(gid);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[cfg(all(feature = "blk", not(any(feature = "tee", feature = "aws-nitro"))))]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_root_disk_remount(
    ctx_id: u32,
    c_device: *const c_char,
    c_fstype: *const c_char,
    c_options: *const c_char,
) -> i32 {
    unsafe {
        let device = match CStr::from_ptr(c_device).to_str() {
            Ok(device) => device.to_string(),
            Err(e) => {
                error!("Error parsing device path: {e:?}");
                return -libc::EINVAL;
            }
        };

        let fstype = if !c_fstype.is_null() {
            match CStr::from_ptr(c_fstype).to_str() {
                Ok(fstype) => {
                    if fstype == "auto" {
                        None
                    } else {
                        Some(fstype.to_string())
                    }
                }
                Err(e) => {
                    error!("Error parsing fstype: {e:?}");
                    return -libc::EINVAL;
                }
            }
        } else {
            None
        };

        let options = if !c_options.is_null() {
            match CStr::from_ptr(c_options).to_str() {
                Ok(options) => Some(options.to_string()),
                Err(e) => {
                    error!("Error parsing options: {e:?}");
                    return -libc::EINVAL;
                }
            }
        } else {
            None
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let ctx_cfg = ctx_cfg.get_mut();

                if ctx_cfg.vmr.fs.iter().any(|fs| fs.fs_id == "/dev/root") {
                    error!("Root filesystem already configured");
                    return -libc::EINVAL;
                }

                if ctx_cfg.block_cfgs.is_empty() {
                    error!("No block devices configured");
                    return -libc::EINVAL;
                }

                // Boot from a block device: the virtiofs root only needs to
                // serve init.krun and provide mount points for /dev, /proc, /sys.
                // Use a NullFs (no host directory) with the inode overlay.
                let mut virtual_entries = Vec::new();
                #[cfg(feature = "init-blob")]
                if !ctx_cfg.disable_implicit_init {
                    virtual_entries.push(init_virtual_entry());
                }
                // init.c needs these directories as mount points before
                // pivoting to the block device root.
                for name in ["dev", "proc", "sys", "newroot"] {
                    virtual_entries.push(VirtualDirEntry {
                        name: CString::new(name).unwrap(),
                        entry: VirtualEntry {
                            mode: 0o755,
                            one_shot: false,
                            content: VirtualEntryContent::Dir {
                                children: Vec::new(),
                            },
                        },
                    });
                }

                ctx_cfg.vmr.add_fs_device(FsDeviceConfig {
                    fs_id: "/dev/root".into(),
                    shared_dir: None,
                    // Default to a conservative 512 MB window.
                    shm_size: Some(1 << 29),
                    read_only: false,
                    override_stat: false,
                    negative_entries: false,
                    live: false,
                    virtual_entries,
                });

                ctx_cfg.set_block_root(device, fstype, options);
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        };

        KRUN_SUCCESS
    }
}

#[unsafe(no_mangle)]
#[cfg(all(
    feature = "init-blob",
    not(any(feature = "tee", feature = "aws-nitro"))
))]
pub extern "C" fn krun_disable_implicit_init(ctx_id: u32) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            ctx_cfg.get_mut().disable_implicit_init = true;
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[unsafe(no_mangle)]
#[cfg(all(
    not(feature = "init-blob"),
    not(any(feature = "tee", feature = "aws-nitro"))
))]
pub extern "C" fn krun_disable_implicit_init(_ctx_id: u32) -> i32 {
    KRUN_SUCCESS
}

/// Resolve a path like "a/b/c" into parent directory children + leaf name.
/// Errors with a libc errno if any intermediate component is missing or not a Dir.
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
fn resolve_overlay_path<'a>(
    entries: &'a mut Vec<VirtualDirEntry>,
    path: &str,
) -> Result<(&'a mut Vec<VirtualDirEntry>, CString), i32> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let components: Vec<&str> = path.split('/').collect();
    let (leaf, parents) = components.split_last().ok_or(-libc::EINVAL)?;
    if leaf.is_empty() {
        return Err(-libc::EINVAL);
    }

    let mut current = entries;
    for component in parents {
        let dir = current
            .iter_mut()
            .find(|e| e.name.as_c_str().to_bytes() == component.as_bytes())
            .ok_or(-libc::ENOENT)?;
        match &mut dir.entry.content {
            VirtualEntryContent::Dir { children } => current = children,
            _ => return Err(-libc::ENOTDIR),
        }
    }

    let name = CString::new(*leaf).map_err(|_| -libc::EINVAL)?;
    Ok((current, name))
}

/// Add a virtual overlay entry to a virtiofs device, resolving paths with `/`.
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
fn fs_add_overlay_entry(ctx_id: u32, fs_tag: &str, path: &str, entry: VirtualEntry) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            let fs_cfg = match cfg.vmr.fs.iter_mut().find(|fs| fs.fs_id == fs_tag) {
                Some(fs) => fs,
                None => return -libc::ENOENT,
            };
            let (parent_children, name) =
                match resolve_overlay_path(&mut fs_cfg.virtual_entries, path) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
            parent_children.push(VirtualDirEntry { name, entry });
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }
    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub unsafe extern "C" fn krun_fs_add_overlay_file(
    ctx_id: u32,
    c_fs_tag: *const c_char,
    c_path: *const c_char,
    data: *const u8,
    data_len: size_t,
    mode: u32,
    one_shot: bool,
) -> i32 {
    if c_fs_tag.is_null() || c_path.is_null() {
        return -libc::EINVAL;
    }

    let fs_tag = match unsafe { CStr::from_ptr(c_fs_tag).to_str() } {
        Ok(s) => s,
        Err(_) => return -libc::EINVAL,
    };
    let path = match unsafe { CStr::from_ptr(c_path).to_str() } {
        Ok(s) => s,
        Err(_) => return -libc::EINVAL,
    };

    // SAFETY: The caller guarantees the memory remains valid for the VM
    // lifetime (see the C header contract).
    let payload: &'static [u8] = if data_len == 0 {
        &[]
    } else if !data.is_null() {
        unsafe { slice::from_raw_parts(data, data_len) }
    } else {
        return -libc::EINVAL;
    };

    fs_add_overlay_entry(
        ctx_id,
        fs_tag,
        path,
        VirtualEntry {
            mode,
            one_shot,
            content: VirtualEntryContent::File { data: payload },
        },
    )
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub unsafe extern "C" fn krun_fs_add_overlay_dir(
    ctx_id: u32,
    c_fs_tag: *const c_char,
    c_path: *const c_char,
    mode: u32,
) -> i32 {
    if c_fs_tag.is_null() || c_path.is_null() {
        return -libc::EINVAL;
    }

    let fs_tag = match unsafe { CStr::from_ptr(c_fs_tag).to_str() } {
        Ok(s) => s,
        Err(_) => return -libc::EINVAL,
    };
    let path = match unsafe { CStr::from_ptr(c_path).to_str() } {
        Ok(s) => s,
        Err(_) => return -libc::EINVAL,
    };

    fs_add_overlay_entry(
        ctx_id,
        fs_tag,
        path,
        VirtualEntry {
            mode,
            one_shot: false,
            content: VirtualEntryContent::Dir {
                children: Vec::new(),
            },
        },
    )
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(all(
    feature = "init-blob",
    not(any(feature = "tee", feature = "aws-nitro"))
))]
pub unsafe extern "C" fn krun_get_default_init(
    data_out: *mut *const u8,
    len_out: *mut size_t,
) -> i32 {
    if data_out.is_null() || len_out.is_null() {
        return -libc::EINVAL;
    }
    unsafe {
        *data_out = DEFAULT_INIT_PAYLOAD.as_ptr();
        *len_out = DEFAULT_INIT_PAYLOAD.len();
    }
    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(all(
    not(feature = "init-blob"),
    not(any(feature = "tee", feature = "aws-nitro"))
))]
pub unsafe extern "C" fn krun_get_default_init(
    _data_out: *mut *const u8,
    _len_out: *mut size_t,
) -> i32 {
    -libc::ENOTSUP
}

#[unsafe(no_mangle)]
pub extern "C" fn krun_add_vsock(ctx_id: u32, tsi_features: u32) -> i32 {
    let tsi_flags = match TsiFlags::from_bits(tsi_features) {
        Some(flags) => flags,
        None => return -libc::EINVAL,
    };

    // AF_UNIX hijacking needs host AF_UNIX sockets, which exist only on Unix
    // (and aren't yet wired on macOS).
    if !cfg!(target_os = "linux") && tsi_flags.contains(TsiFlags::HIJACK_UNIX) {
        error!("TSI hijacking of UNIX sockets is only supported on Linux");
        return -libc::EINVAL;
    }

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            if cfg.vsock_config != VsockConfig::Disabled {
                return -libc::EEXIST;
            }
            cfg.vsock_config = VsockConfig::Explicit { tsi_flags };
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[cfg(unix)]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_virtio_console_default(
    ctx_id: u32,
    input_fd: libc::c_int,
    output_fd: libc::c_int,
    err_fd: libc::c_int,
) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();

            cfg.vmr
                .virtio_consoles
                .push(VirtioConsoleConfigMode::Autoconfigure(
                    DefaultVirtioConsoleConfig {
                        input_fd,
                        output_fd,
                        err_fd,
                    },
                ));
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[cfg(target_os = "windows")]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_virtio_console_default(
    ctx_id: u32,
    input_handle: *mut c_void,
    output_handle: *mut c_void,
    err_handle: *mut c_void,
) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();

            cfg.vmr
                .virtio_consoles
                .push(VirtioConsoleConfigMode::Autoconfigure(
                    DefaultVirtioConsoleConfig {
                        input_handle: SendHandle::new(input_handle),
                        output_handle: SendHandle::new(output_handle),
                        err_handle: SendHandle::new(err_handle),
                    },
                ));
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_virtio_console_multiport(ctx_id: u32) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            let console_id = cfg.vmr.virtio_consoles.len() as i32;

            cfg.vmr
                .virtio_consoles
                .push(VirtioConsoleConfigMode::Explicit(Vec::new()));

            console_id
        }
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

#[cfg(unix)]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_console_port_tty(
    ctx_id: u32,
    console_id: u32,
    name: *const libc::c_char,
    tty_fd: libc::c_int,
) -> i32 {
    unsafe {
        if tty_fd < 0 {
            return -libc::EINVAL;
        }

        let name_str = if name.is_null() {
            String::new()
        } else {
            match CStr::from_ptr(name).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return -libc::EINVAL,
            }
        };

        if !BorrowedFd::borrow_raw(tty_fd).is_terminal() {
            return -libc::ENOTTY;
        }

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();

                match cfg.vmr.virtio_consoles.get_mut(console_id as usize) {
                    Some(VirtioConsoleConfigMode::Explicit(ports)) => {
                        ports.push(PortConfig::Tty {
                            name: name_str,
                            tty_fd,
                        });
                        KRUN_SUCCESS
                    }
                    _ => -libc::EINVAL,
                }
            }
            Entry::Vacant(_) => -libc::ENOENT,
        }
    }
}

#[cfg(target_os = "windows")]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_console_port_tty(
    ctx_id: u32,
    console_id: u32,
    name: *const libc::c_char,
    tty_handle: *mut c_void,
) -> i32 {
    unsafe {
        if tty_handle.is_null() {
            return -libc::EINVAL;
        }

        let name_str = if name.is_null() {
            String::new()
        } else {
            match CStr::from_ptr(name).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return -libc::EINVAL,
            }
        };

        if !BorrowedHandle::borrow_raw(tty_handle).is_terminal() {
            return -libc::ENOTTY;
        }

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();

                match cfg.vmr.virtio_consoles.get_mut(console_id as usize) {
                    Some(VirtioConsoleConfigMode::Explicit(ports)) => {
                        ports.push(PortConfig::Tty {
                            name: name_str,
                            tty_handle: SendHandle::new(tty_handle),
                        });
                        KRUN_SUCCESS
                    }
                    _ => -libc::EINVAL,
                }
            }
            Entry::Vacant(_) => -libc::ENOENT,
        }
    }
}

#[cfg(unix)]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_console_port_inout(
    ctx_id: u32,
    console_id: u32,
    name: *const c_char,
    input_fd: c_int,
    output_fd: c_int,
) -> i32 {
    unsafe {
        let name_str = if name.is_null() {
            String::new()
        } else {
            match CStr::from_ptr(name).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return -libc::EINVAL,
            }
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();

                match cfg.vmr.virtio_consoles.get_mut(console_id as usize) {
                    Some(VirtioConsoleConfigMode::Explicit(ports)) => {
                        ports.push(PortConfig::InOut {
                            name: name_str,
                            input_fd,
                            output_fd,
                        });
                        KRUN_SUCCESS
                    }
                    _ => -libc::EINVAL,
                }
            }
            Entry::Vacant(_) => -libc::ENOENT,
        }
    }
}

#[cfg(target_os = "windows")]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_console_port_inout(
    ctx_id: u32,
    console_id: u32,
    name: *const c_char,
    input_handle: *mut c_void,
    output_handle: *mut c_void,
) -> i32 {
    unsafe {
        let name_str = if name.is_null() {
            String::new()
        } else {
            match CStr::from_ptr(name).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return -libc::EINVAL,
            }
        };

        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();

                match cfg.vmr.virtio_consoles.get_mut(console_id as usize) {
                    Some(VirtioConsoleConfigMode::Explicit(ports)) => {
                        ports.push(PortConfig::InOut {
                            name: name_str,
                            input_handle: SendHandle::new(input_handle),
                            output_handle: SendHandle::new(output_handle),
                        });
                        KRUN_SUCCESS
                    }
                    _ => -libc::EINVAL,
                }
            }
            Entry::Vacant(_) => -libc::ENOENT,
        }
    }
}

#[cfg(unix)]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_serial_console_default(
    ctx_id: u32,
    input_fd: c_int,
    output_fd: c_int,
) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.vmr.serial_consoles.push(SerialConsoleConfig {
                input_fd,
                output_fd,
            });
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[cfg(target_os = "windows")]
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_add_serial_console_default(
    ctx_id: u32,
    input_handle: *mut c_void,
    output_handle: *mut c_void,
) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.vmr.serial_consoles.push(SerialConsoleConfig {
                input_handle: SendHandle::new(input_handle),
                output_handle: SendHandle::new(output_handle),
            });
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_set_kernel_console(ctx_id: u32, console_id: *const c_char) -> i32 {
    unsafe {
        let console_id = match CStr::from_ptr(console_id).to_str() {
            Ok(id) => id.to_string(),
            Err(_) => return -libc::EINVAL,
        };
        match CTX_MAP.lock().unwrap().entry(ctx_id) {
            Entry::Occupied(mut ctx_cfg) => {
                let cfg = ctx_cfg.get_mut();
                cfg.vmr.kernel_console = Some(console_id);
            }
            Entry::Vacant(_) => return -libc::ENOENT,
        }

        KRUN_SUCCESS
    }
}

/// The errno `krun_start_enter` returns when the VM could not be built or its
/// checkpoint could not be restored. Every failure used to be `EINVAL`, which
/// told the caller nothing when the host was
/// simply full: a batch of branches on a saturated node got "invalid
/// configuration" for what was KVM or the memory mapping answering ENOMEM, or a
/// process out of file descriptors. Resource exhaustion is returned as itself,
/// found by the `os error N` / `Error(N)` / `code: N` an io, KVM or errno error
/// prints anywhere in the error's chain; everything else stays `EINVAL`.
fn start_errno(debug: &str) -> i32 {
    fn number_after(text: &str, marker: &str) -> Vec<i32> {
        text.match_indices(marker)
            .filter_map(|(i, _)| {
                let digits: String = text[i + marker.len()..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                digits.parse().ok()
            })
            .collect()
    }
    let found: Vec<i32> = ["os error ", "Error(", "code: "]
        .iter()
        .flat_map(|m| number_after(debug, m))
        .collect();
    found
        .into_iter()
        .find(|n| {
            matches!(
                *n,
                libc::EAGAIN
                    | libc::ENOMEM
                    | libc::EMFILE
                    | libc::ENFILE
                    | libc::ENOSPC
                    | libc::EBUSY
            )
        })
        .unwrap_or(libc::EINVAL)
}

#[unsafe(no_mangle)]
#[allow(unreachable_code)]
pub extern "C" fn krun_start_enter(ctx_id: u32) -> i32 {
    clear_last_error();
    #[cfg(target_os = "linux")]
    {
        let prname = match env::var("HOSTNAME") {
            Ok(val) => CString::new(format!("VM:{val}")).unwrap(),
            Err(_) => CString::new("libkrun VM").unwrap(),
        };
        unsafe { libc::prctl(libc::PR_SET_NAME, prname.as_ptr()) };
    }

    #[cfg(feature = "aws-nitro")]
    return krun_start_enter_nitro(ctx_id);

    let t_libkrun = std::time::Instant::now();
    let lk_timing_on = std::env::var("LIBKRUN_TIMING").is_ok();
    macro_rules! lk_timing {
        ($label:expr) => {
            if lk_timing_on {
                eprintln!(
                    "[libkrun] {:28} {}ms",
                    $label,
                    t_libkrun.elapsed().as_millis()
                );
            }
        };
    }
    lk_timing!("krun_start_enter");

    let mut event_manager = match EventManager::new() {
        Ok(em) => em,
        Err(e) => {
            error!("Unable to create EventManager: {e:?}");
            set_last_error(format!("unable to create event manager: {e:?}"));
            return -libc::EINVAL;
        }
    };

    let mut ctx_cfg = match CTX_MAP.lock().unwrap().remove(&ctx_id) {
        Some(ctx_cfg) => ctx_cfg,
        None => return -libc::ENOENT,
    };

    if ctx_cfg.vmr.external_kernel.is_none()
        && ctx_cfg.vmr.kernel_bundle.is_none()
        && ctx_cfg.vmr.firmware_config.is_none()
    {
        if let Some(ref krunfw) = ctx_cfg.krunfw {
            if let Err(err) = unsafe { load_krunfw_payload(krunfw, &mut ctx_cfg.vmr) } {
                eprintln!("Can't load libkrunfw symbols: {err}");
                return -libc::ENOENT;
            }
        } else {
            eprintln!("Couldn't find or load {KRUNFW_NAME}");
            return -libc::ENOENT;
        }
    }
    lk_timing!("krunfw loaded");

    #[cfg(feature = "blk")]
    for block_cfg in ctx_cfg.get_block_cfg() {
        if ctx_cfg.vmr.add_block_device(block_cfg).is_err() {
            error!("Error configuring virtio-blk for block");
            return -libc::EINVAL;
        }
    }

    /*
     * Before krun_start_enter() is called in an encrypted context, the TEE
     * config must have been set via krun_set_tee_config_file(). If the TEE
     * config is not set by this point, print the relevant error message and
     * fail.
     */
    #[cfg(feature = "tee")]
    if let Some(tee_config) = ctx_cfg.get_tee_config_file() {
        if let Err(e) = ctx_cfg.vmr.set_tee_config(tee_config) {
            error!("Error setting up TEE config: {e:?}");
            return -libc::EINVAL;
        }
    } else {
        error!("Missing TEE config file");
        return -libc::EINVAL;
    }

    let kernel_cmdline = KernelCmdlineConfig {
        prolog: Some(format!("{DEFAULT_KERNEL_CMDLINE} init={INIT_PATH}")),
        krun_env: Some(format!(
            " {} {} {} {} {}",
            ctx_cfg.get_exec_path(),
            ctx_cfg.get_workdir(),
            ctx_cfg.get_block_root(),
            ctx_cfg.get_rlimits(),
            ctx_cfg.get_env(),
        )),
        epilog: Some(format!(" -- {}", ctx_cfg.get_args())),
    };

    if ctx_cfg.vmr.set_kernel_cmdline(kernel_cmdline).is_err() {
        return -libc::EINVAL;
    }

    let egress_cidrs = ctx_cfg.egress_cidrs.take();
    let egress_hosts = ctx_cfg.egress_hosts.take();
    let egress_resolvers = ctx_cfg.egress_resolvers.take();
    let dns_forwarder = ctx_cfg.dns_forwarder.take();
    let stream_intercept = ctx_cfg.stream_intercept.take();

    match &ctx_cfg.vsock_config {
        VsockConfig::Disabled => (),
        VsockConfig::Explicit { tsi_flags } => {
            let vsock_device_config = VsockDeviceConfig {
                vsock_id: "vsock0".to_string(),
                guest_cid: 3,
                host_port_map: ctx_cfg.tsi_port_map,
                unix_ipc_port_map: ctx_cfg.unix_ipc_port_map.clone(),
                tsi_flags: *tsi_flags,
                egress_cidrs,
                egress_hosts,
                egress_resolvers,
                dns_forwarder,
                stream_intercept,
            };
            ctx_cfg.vmr.set_vsock_device(vsock_device_config).unwrap();
        }
    }

    if let Some(virgl_flags) = ctx_cfg.gpu_virgl_flags {
        ctx_cfg.vmr.set_gpu_virgl_flags(virgl_flags);
    }
    if let Some(shm_size) = ctx_cfg.gpu_shm_size {
        ctx_cfg.vmr.set_gpu_shm_size(shm_size);
    }

    // setuid/setgid privilege dropping is Unix-only.
    #[cfg(not(target_os = "windows"))]
    if let Some(gid) = ctx_cfg.vmm_gid
        && unsafe { libc::setgid(gid) } != 0
    {
        error!("Failed to set gid {gid}");
        return -std::io::Error::last_os_error().raw_os_error().unwrap();
    }

    #[cfg(not(target_os = "windows"))]
    if let Some(uid) = ctx_cfg.vmm_uid
        && unsafe { libc::setuid(uid) } != 0
    {
        error!("Failed to set uid {uid}");
        return -std::io::Error::last_os_error().raw_os_error().unwrap();
    }

    let (sender, _receiver) = unbounded();

    // Fork clone: build a RestoreCtx from the snapshot dir (CoW-map the golden
    // VM's guest RAM + load its checkpoint) so build_microvm restores instead of
    // cold-booting.
    #[cfg(all(target_os = "linux", fork_supported))]
    if ctx_cfg.snapshot_memory.is_some() && ctx_cfg.snapshot_dir.is_none() {
        set_last_error("read-only restore memory requires a snapshot directory");
        return -libc::EINVAL;
    }
    #[cfg(fork_supported)]
    let restore_ctx = match ctx_cfg.snapshot_dir.take() {
        Some(dir) => {
            #[cfg(target_os = "linux")]
            let result = build_restore_ctx_with_memory(
                &dir,
                ctx_cfg.snapshot_memory.take().as_ref(),
                ctx_cfg.snapshot_memory_immutable,
            );
            #[cfg(not(target_os = "linux"))]
            let result = build_restore_ctx(&dir);
            match result {
                Ok(rc) => Some(rc),
                Err(e) => {
                    // Restore errors are io::Error text. On Windows its
                    // `os error N` is a Win32 code, not an errno, so it stays EINVAL.
                    #[cfg(unix)]
                    let errno = start_errno(&e);
                    #[cfg(not(unix))]
                    let errno = libc::EINVAL;
                    error!("fork restore from {} (errno {errno}): {e}", dir.display());
                    set_last_error(format!("restore checkpoint from {}: {e}", dir.display()));
                    return -errno;
                }
            }
        }
        None => None,
    };
    #[cfg(not(fork_supported))]
    let restore_ctx: Option<vmm::builder::RestoreCtx> = None;

    lk_timing!("before build_microvm");
    let _vmm = match vmm::builder::build_microvm(
        &ctx_cfg.vmr,
        &mut event_manager,
        ctx_cfg.shutdown_efd,
        sender,
        restore_ctx,
    ) {
        Ok(vmm) => vmm,
        Err(e) => {
            let errno = start_errno(&format!("{e:?}"));
            error!("Building the microVM failed (errno {errno}): {e:?}");
            set_last_error(format!("build microVM: {e}"));
            return -errno;
        }
    };
    lk_timing!("build_microvm done");

    // Publish the guest-RAM host mapping so an in-process embedder (e.g. a CUDA
    // forwarding server on another thread) can read guest memory directly for
    // zero-copy transfers. Best-effort; a failure just leaves callers on the
    // byte-shipping path.
    let ram_regions = _vmm.lock().unwrap().guest_ram_regions();
    if !ram_regions.is_empty() {
        GUEST_RAM.lock().unwrap().insert(ctx_id, ram_regions);
    }

    #[cfg(any(unix, target_os = "windows"))]
    if let Some(control_socket_path) = ctx_cfg.control_socket_path.take()
        && let Err(e) = start_control_socket(control_socket_path, _vmm.clone())
    {
        error!("Unable to start control socket: {e}");
        return -libc::EINVAL;
    }

    #[cfg(target_os = "macos")]
    if ctx_cfg.gpu_virgl_flags.is_some() {
        vmm::worker::start_worker_thread(_vmm.clone(), _receiver).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    if ctx_cfg.vmr.split_irqchip {
        vmm::worker::start_worker_thread(_vmm.clone(), _receiver.clone()).unwrap();
    }

    // On Windows the worker services virtiofs DAX remap requests (see
    // Vm::add_mapping); it must run whenever the fs device might issue them,
    // independent of split_irqchip.
    #[cfg(target_os = "windows")]
    if !ctx_cfg.vmr.split_irqchip {
        vmm::worker::start_worker_thread(_vmm.clone(), _receiver.clone()).unwrap();
    }

    #[cfg(any(feature = "amd-sev", feature = "tdx"))]
    vmm::worker::start_worker_thread(_vmm.clone(), _receiver.clone()).unwrap();

    loop {
        match event_manager.run() {
            Ok(_) => {}
            Err(e) => {
                error!("Error in EventManager loop: {e:?}");
                return -libc::EINVAL;
            }
        }
    }
}

/// Retrieve the guest RAM regions for the running context `ctx_id` so a caller
/// sharing this process (e.g. a GPU-forwarding server) can read guest memory
/// directly at `host_va + (gpa - gpa_start)` for zero-copy transfers.
///
/// `regions` is filled with up to `max_regions` triples, each three consecutive
/// `uint64_t` — `gpa_start`, `host_va`, `len`. `*count` receives the *total*
/// region count (which may exceed `max_regions`; call again with a larger buffer
/// if so). Pass `regions == NULL` / `max_regions == 0` to query the count only.
///
/// Valid only after `krun_start_enter` has built the VM (call it from another
/// thread once the guest is up). Returns 0 on success, `-EINVAL` if `count` is
/// NULL, `-ENOENT` if the context has no published mapping yet.
///
/// # Safety
/// `count` must be a valid writable `uint64_t`; `regions` (if non-NULL) must
/// point to at least `max_regions * 3` writable `uint64_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn krun_get_guest_ram(
    ctx_id: u32,
    regions: *mut u64,
    max_regions: u32,
    count: *mut u64,
) -> i32 {
    if count.is_null() {
        return -libc::EINVAL;
    }
    let map = GUEST_RAM.lock().unwrap();
    let regs = match map.get(&ctx_id) {
        Some(r) => r,
        None => return -libc::ENOENT,
    };
    unsafe { *count = regs.len() as u64 };
    if !regions.is_null() {
        let n = (max_regions as usize).min(regs.len());
        for (i, &(gpa, hva, len)) in regs.iter().take(n).enumerate() {
            unsafe {
                *regions.add(i * 3) = gpa;
                *regions.add(i * 3 + 1) = hva;
                *regions.add(i * 3 + 2) = len;
            }
        }
    }
    0
}

#[cfg(feature = "aws-nitro")]
#[unsafe(no_mangle)]
fn krun_start_enter_nitro(ctx_id: u32) -> i32 {
    let ctx_cfg = match CTX_MAP.lock().unwrap().remove(&ctx_id) {
        Some(ctx_cfg) => ctx_cfg,
        None => return -libc::ENOENT,
    };

    let Ok(enclave) = NitroEnclave::try_from(ctx_cfg) else {
        return -libc::EINVAL;
    };

    match enclave.run() {
        Ok(ret) => ret,
        Err(e) => {
            error!("Error running nitro enclave: {e}");

            -libc::EINVAL
        }
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod test_cpu_template {
    use super::*;
    use vmm::vmm_config::machine_config::CpuFeaturesTemplate;

    // There is one portable profile and it is Intel's: an AMD host is told
    // ENOTSUP and its VMs keep the host's CPUID.
    #[test]
    fn only_intel_hosts_take_the_portable_profile() {
        let ctx = krun_create_ctx() as u32;
        let leaf = std::arch::x86_64::__cpuid(0);
        let intel = [leaf.ebx, leaf.edx, leaf.ecx] == [0x756e_6547, 0x4965_6e69, 0x6c65_746e];
        assert_eq!(krun_set_cpu_template(ctx, 2), -libc::EINVAL);
        let result = krun_set_cpu_template(ctx, 1);
        let template = CTX_MAP.lock().unwrap()[&ctx].vmr.vm_config().cpu_template;
        if intel {
            assert_eq!(result, KRUN_SUCCESS);
            assert_eq!(template, Some(CpuFeaturesTemplate::Portable));
        } else {
            assert_eq!(result, -libc::ENOTSUP);
            assert_eq!(template, None);
        }
        assert_eq!(krun_free_ctx(ctx), KRUN_SUCCESS);
    }
}

#[cfg(test)]
mod test_live_resize_config {
    use super::*;

    #[test]
    fn live_resize_is_explicit_per_context_and_validated() {
        let first = krun_create_ctx();
        let second = krun_create_ctx();
        assert!(first >= 0 && second >= 0);
        let (first, second) = (first as u32, second as u32);
        assert_eq!(krun_set_live_resize(first, 4), -libc::EINVAL);
        assert_eq!(krun_set_live_resize(u32::MAX, 0), -libc::ENOENT);
        let supported = cfg!(all(
            any(
                all(target_os = "linux", target_arch = "x86_64"),
                all(target_os = "macos", target_arch = "aarch64")
            ),
            not(feature = "tee")
        ));
        assert_eq!(
            krun_set_live_resize(first, 3),
            if supported { 0 } else { -libc::ENOTSUP }
        );
        {
            let contexts = CTX_MAP.lock().unwrap();
            assert_eq!(contexts[&first].vmr.live_cpu_growth, supported);
            assert_eq!(contexts[&first].vmr.live_memory_growth, supported);
            assert!(!contexts[&second].vmr.live_cpu_growth);
            assert!(!contexts[&second].vmr.live_memory_growth);
        }
        let memory_supported = cfg!(all(
            any(target_os = "linux", target_os = "macos"),
            any(target_arch = "x86_64", target_arch = "aarch64"),
            not(feature = "tee")
        ));
        assert_eq!(
            krun_set_live_resize(first, 2),
            if memory_supported { 0 } else { -libc::ENOTSUP }
        );
        {
            let contexts = CTX_MAP.lock().unwrap();
            assert!(!contexts[&first].vmr.live_cpu_growth);
            assert_eq!(contexts[&first].vmr.live_memory_growth, memory_supported);
            assert!(!contexts[&second].vmr.live_memory_growth);
        }
        if memory_supported && !supported {
            assert_eq!(krun_set_live_resize(first, 3), -libc::ENOTSUP);
            let contexts = CTX_MAP.lock().unwrap();
            assert!(!contexts[&first].vmr.live_cpu_growth);
            assert!(contexts[&first].vmr.live_memory_growth);
        }
        assert_eq!(krun_set_live_resize(first, 0), 0);
        {
            let contexts = CTX_MAP.lock().unwrap();
            assert!(!contexts[&first].vmr.live_cpu_growth);
            assert!(!contexts[&first].vmr.live_memory_growth);
        }
        assert_eq!(krun_free_ctx(first), 0);
        assert_eq!(krun_free_ctx(second), 0);
    }
}

#[cfg(all(test, target_os = "linux", fork_supported))]
mod test_snapshot_memory_fd {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn immutable_input_is_explicit_per_context_and_legacy_resets_it() {
        use std::os::unix::fs::FileExt;
        let id = krun_create_ctx() as u32;
        let other = krun_create_ctx() as u32;
        let backing = utils::tempfile::TempFile::new().unwrap();
        backing.as_file().write_all_at(&[0x37; 4096], 0).unwrap();
        let input = std::fs::File::open(backing.as_path()).unwrap();
        assert_eq!(krun_set_snapshot_memory_fd2(id, input.as_raw_fd(), 1), 0);
        assert_eq!(krun_set_snapshot_memory_fd(other, input.as_raw_fd()), 0);
        assert_eq!(
            krun_set_snapshot_memory_fd2(id, input.as_raw_fd(), 2),
            -libc::EINVAL
        );
        assert_eq!(krun_set_snapshot_memory_fd2(id, -1, 0), -libc::EBADF);
        {
            let contexts = CTX_MAP.lock().unwrap();
            assert!(contexts.get(&id).unwrap().snapshot_memory_immutable);
            assert!(!contexts.get(&other).unwrap().snapshot_memory_immutable);
        }
        // Legacy callers can explicitly replace the input and always recover
        // their copy semantics, even after an earlier immutable opt-in.
        assert_eq!(krun_set_snapshot_memory_fd(id, input.as_raw_fd()), 0);
        assert!(
            !CTX_MAP
                .lock()
                .unwrap()
                .get(&id)
                .unwrap()
                .snapshot_memory_immutable
        );
        assert_eq!(krun_set_snapshot_memory_fd2(id, input.as_raw_fd(), 1), 0);
        drop(input);
        drop(backing);
        {
            let contexts = CTX_MAP.lock().unwrap();
            let retained = contexts.get(&id).unwrap().snapshot_memory.as_ref().unwrap();
            let mut bytes = [0; 4096];
            retained.read_exact_at(&mut bytes, 0).unwrap();
            assert_eq!(bytes, [0x37; 4096]);
            assert_ne!(
                unsafe { libc::fcntl(retained.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
        assert_eq!(krun_free_ctx(id), 0);
        assert_eq!(krun_free_ctx(other), 0);
    }

    #[test]
    fn readonly_descriptor_is_duplicated_and_validated() {
        let id = krun_create_ctx() as u32;
        assert_eq!(krun_set_snapshot_memory_fd(id, -1), -libc::EBADF);
        let writable = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        assert_eq!(
            krun_set_snapshot_memory_fd(id, writable.as_raw_fd()),
            -libc::EINVAL
        );
        let directory = std::fs::File::open("/tmp").unwrap();
        assert_eq!(
            krun_set_snapshot_memory_fd(id, directory.as_raw_fd()),
            -libc::EINVAL
        );
        let input = std::fs::File::open("/proc/self/exe").unwrap();
        let len = input.metadata().unwrap().len();
        assert_eq!(krun_set_snapshot_memory_fd(id, input.as_raw_fd()), 0);
        drop(input);
        {
            let map = CTX_MAP.lock().unwrap();
            let retained = map.get(&id).unwrap().snapshot_memory.as_ref().unwrap();
            assert_eq!(retained.metadata().unwrap().len(), len);
            assert_eq!(
                unsafe { libc::fcntl(retained.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
                libc::O_RDONLY
            );
        }
        assert_eq!(krun_free_ctx(id), 0);
        let input = std::fs::File::open("/proc/self/exe").unwrap();
        assert_eq!(
            krun_set_snapshot_memory_fd(id, input.as_raw_fd()),
            -libc::ENOENT
        );
    }
}

#[cfg(all(test, feature = "init-blob", not(feature = "tee")))]
mod test_disable_implicit_init {
    use super::*;

    #[test]
    fn test_disable_implicit_init() {
        let ctx = krun_create_ctx() as u32;
        unsafe {
            krun_disable_implicit_init(ctx);
            krun_add_virtiofs3(ctx, c"/dev/root".as_ptr(), c"/tmp".as_ptr(), 0, false);
        }

        let ctx_map = CTX_MAP.lock().unwrap();
        let cfg = ctx_map.get(&ctx).unwrap();
        assert_eq!(cfg.vmr.fs.len(), 1);
        assert!(
            cfg.vmr.fs[0].virtual_entries.is_empty(),
            "root virtiofs should not inject init.krun after krun_disable_implicit_init()"
        );
        drop(ctx_map);

        assert_eq!(krun_free_ctx(ctx), KRUN_SUCCESS);
    }
}

#[cfg(all(test, feature = "blk"))]
mod block_io_engine_tests {
    use super::*;
    use devices::virtio::block::BlockIoEngine;

    #[test]
    fn legacy_disk_api_remains_sync_and_disk4_is_explicitly_async() {
        let ctx = krun_create_ctx() as u32;
        unsafe {
            assert_eq!(
                krun_add_disk2(
                    ctx,
                    c"legacy".as_ptr(),
                    c"/tmp/legacy.raw".as_ptr(),
                    0,
                    false
                ),
                KRUN_SUCCESS
            );
            assert_eq!(
                krun_add_disk4(
                    ctx,
                    c"queued".as_ptr(),
                    c"/tmp/queued.qcow2".as_ptr(),
                    1,
                    false,
                    false,
                    2,
                    1,
                ),
                KRUN_SUCCESS
            );
        }

        let engines = {
            let contexts = CTX_MAP.lock().unwrap();
            contexts
                .get(&ctx)
                .unwrap()
                .block_cfgs
                .iter()
                .map(|disk| disk.io_engine)
                .collect::<Vec<_>>()
        };
        assert_eq!(engines, vec![BlockIoEngine::Sync, BlockIoEngine::Async]);
        assert_eq!(krun_free_ctx(ctx), KRUN_SUCCESS);
    }

    #[test]
    fn async_disk_rejects_direct_io() {
        let ctx = krun_create_ctx() as u32;
        let result = unsafe {
            krun_add_disk4(
                ctx,
                c"queued".as_ptr(),
                c"/tmp/queued.raw".as_ptr(),
                0,
                false,
                true,
                2,
                1,
            )
        };
        assert_eq!(result, -libc::ENOTSUP);
        assert!(
            CTX_MAP
                .lock()
                .unwrap()
                .get(&ctx)
                .unwrap()
                .block_cfgs
                .is_empty()
        );
        assert_eq!(krun_free_ctx(ctx), KRUN_SUCCESS);
    }

    #[test]
    fn async_raw_disk_prepares_its_restricted_ring_before_start() {
        let backing = utils::tempfile::TempFile::new().unwrap();
        backing.as_file().set_len(1024 * 1024).unwrap();
        let path = std::ffi::CString::new(backing.as_path().to_str().unwrap()).unwrap();
        let ctx = krun_create_ctx() as u32;
        let result = unsafe {
            krun_add_disk4(
                ctx,
                c"queued".as_ptr(),
                path.as_ptr(),
                0,
                false,
                false,
                2,
                1,
            )
        };
        assert_eq!(result, KRUN_SUCCESS);
        assert!(
            CTX_MAP.lock().unwrap().get(&ctx).unwrap().block_cfgs[0]
                .prepared_async
                .is_some()
        );
        assert_eq!(krun_free_ctx(ctx), KRUN_SUCCESS);
    }
}

#[cfg(test)]
mod start_errno_tests {
    use super::start_errno;

    #[test]
    fn resource_exhaustion_is_returned_as_itself() {
        // vstate / kvm-ioctls errors print as `Error(N)`
        assert_eq!(
            start_errno("Internal(Vcpu(VcpuFd(Error(12))))"),
            libc::ENOMEM
        );
        // io::Error inside a device or memory error prints `os error N`
        assert_eq!(
            start_errno("GuestMemoryMmap(\"mmap failed: Cannot allocate memory (os error 12)\")"),
            libc::ENOMEM
        );
        assert_eq!(
            // EAGAIN is 11 on Linux but 35 on macOS
            start_errno(&format!(
                "VcpuSpawn(Os {{ code: {}, kind: WouldBlock, message: \"Resource temporarily unavailable\" }})",
                libc::EAGAIN
            )),
            libc::EAGAIN
        );
        assert_eq!(
            start_errno(
                "OpenBlockDevice(Os { code: 24, kind: Uncategorized, message: \"Too many open files\" })"
            ),
            libc::EMFILE
        );
        assert_eq!(
            start_errno(
                "AttachBlockDevice(Os { code: 16, kind: ResourceBusy, message: \"Device or resource busy\" })"
            ),
            libc::EBUSY
        );
    }

    #[test]
    fn restore_failures_carry_the_io_errno() {
        // restore errors are `{io::Error}` Display text, which ends in `(os error N)`
        assert_eq!(
            start_errno("map guest memory: Cannot allocate memory (os error 12)"),
            libc::ENOMEM
        );
        assert_eq!(
            start_errno("memory: Too many open files (os error 24)"),
            libc::EMFILE
        );
        assert_eq!(
            start_errno("cow-map guest memory: No space left on device (os error 28)"),
            libc::ENOSPC
        );
        // a missing or malformed checkpoint is not a full host
        assert_eq!(
            start_errno("checkpoint: No such file or directory (os error 2)"),
            libc::EINVAL
        );
        assert_eq!(
            start_errno("manifest: unrecognized snapshot format"),
            libc::EINVAL
        );
    }

    #[test]
    fn everything_else_stays_einval() {
        assert_eq!(start_errno("MissingKernelConfig"), libc::EINVAL);
        assert_eq!(start_errno("KernelCmdline(\"too long\")"), libc::EINVAL);
        // a permission error is a configuration problem for the caller, not a full host
        assert_eq!(
            start_errno(
                "ElfOpenKernel(Os { code: 13, kind: PermissionDenied, message: \"Permission denied\" })"
            ),
            libc::EINVAL
        );
        // the first resource errno wins over later unrelated numbers
        assert_eq!(
            start_errno("Internal(Vm(Error(2))) then Error(12)"),
            libc::ENOMEM
        );
    }
}
