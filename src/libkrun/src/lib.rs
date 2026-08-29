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
#[cfg(target_os = "linux")]
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
fn handle_checkpoint(vmm: &Arc<Mutex<vmm::Vmm>>, id: &str) -> String {
    if id.is_empty() {
        return "ERR EINVAL checkpoint id required\n".to_string();
    }
    // Pauses the vCPUs + drains device workers at a clean boundary, then captures
    // state + an eager guest-RAM image (correct for rewind — see StashedCheckpoint).
    // The VM remains paused (workers re-armed) on success.
    let mut memory = Vec::new();
    let (checkpoint, mem_descs) = match vmm.lock().unwrap().checkpoint(&mut memory) {
        Ok(v) => v,
        Err(e) => return format!("ERR EIO checkpoint failed: {e}\n"),
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

/// Persist a self-contained VM checkpoint to a newly-created directory. The
/// manifest is renamed into place last, so a reader never accepts a partial
/// checkpoint. The VM remains paused on success to let the caller capture its
/// disks at the same consistency boundary; failures resume it automatically.
#[cfg(snapshot_supported)]
fn handle_save(vmm: &Arc<Mutex<vmm::Vmm>>, dir: &str) -> String {
    if dir.is_empty() {
        return "ERR EINVAL snapshot dir required\n".to_string();
    }
    let dir = std::path::Path::new(dir);
    if let Err(error) = std::fs::create_dir(dir) {
        return format!("ERR EIO create {}: {error}\n", dir.display());
    }

    let memory_partial = dir.join("memory.bin.partial");
    let checkpoint_partial = dir.join("checkpoint.bin.partial");
    let manifest_partial = dir.join("manifest.bin.partial");
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
        memory
            .sync_all()
            .map_err(|error| format!("sync memory image: {error}"))?;

        let checkpoint_bytes = checkpoint.serialize();
        let checkpoint_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&checkpoint_partial)
            .map_err(|error| format!("create checkpoint state: {error}"))?;
        (&checkpoint_file)
            .write_all(&checkpoint_bytes)
            .map_err(|error| format!("write checkpoint state: {error}"))?;
        checkpoint_file
            .sync_all()
            .map_err(|error| format!("sync checkpoint state: {error}"))?;

        let manifest_bytes = encode_portable_manifest(&descs);
        let manifest_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&manifest_partial)
            .map_err(|error| format!("create snapshot manifest: {error}"))?;
        (&manifest_file)
            .write_all(&manifest_bytes)
            .map_err(|error| format!("write snapshot manifest: {error}"))?;
        manifest_file
            .sync_all()
            .map_err(|error| format!("sync snapshot manifest: {error}"))?;

        std::fs::rename(&memory_partial, dir.join("memory.bin"))
            .map_err(|error| format!("publish memory image: {error}"))?;
        std::fs::rename(&checkpoint_partial, dir.join("checkpoint.bin"))
            .map_err(|error| format!("publish checkpoint state: {error}"))?;
        // Publish the manifest last: its presence is the completeness marker.
        std::fs::rename(&manifest_partial, dir.join("manifest.bin"))
            .map_err(|error| format!("publish snapshot manifest: {error}"))?;

        Ok((vmm::snapshot::memory_image_len(&descs), descs.len()))
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

/// Magic for the fork manifest ("SMOLFORK").
#[cfg(fork_supported)]
const FORK_MANIFEST_MAGIC: u64 = 0x534d4f4c464f524b;

/// Magic for a guardian-backed fork manifest ("SMOLGRDN").
#[cfg(all(fork_supported, target_os = "linux"))]
const GUARDIAN_MANIFEST_MAGIC: u64 = 0x534d4f4c4752444e;
#[cfg(all(fork_supported, target_os = "linux"))]
const GUARDIAN_MANIFEST_VERSION: u32 = 1;

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
    any(test, all(target_arch = "x86_64", feature = "blk"))
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
    if socket_len == 0 || socket_len > 100 || region_count == 0 || region_count > 256 {
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
    // Capture + freeze (the VM stays paused as the CoW base).
    let (checkpoint, descs) = match vmm.lock().unwrap().checkpoint_for_fork() {
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
    if let Err(e) = write_fork_manifest(&dir.join("manifest.bin"), pid, &descs) {
        return rollback_failed_fork(vmm, dir, checkpoint, format!("write manifest: {e}"));
    }
    format!(
        "OK forked (frozen base, pid {pid}, {} regions)\n",
        descs.len()
    )
}

#[cfg(all(
    fork_supported,
    any(all(target_os = "linux", target_arch = "x86_64"), target_os = "macos"),
    feature = "blk"
))]
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
#[cfg(all(
    fork_supported,
    any(all(target_os = "linux", target_arch = "x86_64"), target_os = "macos"),
    feature = "blk"
))]
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

#[cfg(all(
    fork_supported,
    any(all(target_os = "linux", target_arch = "x86_64"), target_os = "macos"),
    feature = "blk"
))]
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
    let guardian_socket = demand_paged.then(|| dir.join("ram-guardian.sock"));
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
#[cfg(fork_supported)]
fn build_restore_ctx(
    dir: &std::path::Path,
) -> std::result::Result<vmm::builder::RestoreCtx, String> {
    let manifest_path = dir.join("manifest.bin");
    let manifest = std::fs::read(&manifest_path).map_err(|e| format!("manifest: {e}"))?;
    let magic_bytes = manifest
        .get(..8)
        .ok_or_else(|| "manifest: truncated".to_string())?;
    let magic = u64::from_le_bytes(magic_bytes.try_into().unwrap());
    if magic == PORTABLE_MANIFEST_MAGIC {
        let descs = decode_portable_manifest(&manifest).map_err(|e| format!("manifest: {e}"))?;
        let checkpoint =
            std::fs::read(dir.join("checkpoint.bin")).map_err(|e| format!("checkpoint: {e}"))?;
        let memory_path = dir.join("memory.bin");
        let memory_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&memory_path)
            .map_err(|e| format!("memory: {e}"))?;
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
        let guest_memory = if std::env::var_os("SMOLVM_FORKABLE").is_some_and(|value| value == "1")
        {
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
            guest_memory,
            fork_backed_regions: vec![true; descs.len()],
            checkpoint,
            portable_clock: true,
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
    let guest_memory = vmm::snapshot::open_cow_memory_from_pid(_owner_pid, &descs)
        .map_err(|e| format!("cow-map guest memory: {e}"))?;
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let guest_memory = vmm::snapshot::open_cow_memory_from_paths(&descs)
        .map_err(|e| format!("cow-map guest memory: {e}"))?;
    Ok(vmm::builder::RestoreCtx {
        #[cfg(target_os = "linux")]
        demand_pager: None,
        guest_memory,
        fork_backed_regions: descs
            .iter()
            .map(|desc| desc.fd >= 0 || !desc.path.is_empty())
            .collect(),
        checkpoint,
        portable_clock: false,
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

fn handle_control_stream<S: std::io::Read + std::io::Write>(
    mut stream: S,
    vmm: &Arc<Mutex<vmm::Vmm>>,
) {
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
                "SAVE" => handle_save(vmm, _arg),
                // FORK <dir>: capture a fork checkpoint to <dir> (checkpoint.bin +
                // manifest.bin) and leave this VM FROZEN as the CoW base. A clone
                // process then boots from <dir> via krun_set_snapshot, mapping this
                // VM's guest-RAM memfd MAP_PRIVATE. Requires memfd-backed RAM
                // (SMOLVM_FORKABLE=1).
                #[cfg(fork_supported)]
                "FORK" => handle_fork(vmm, _arg),
                #[cfg(all(
                    fork_supported,
                    any(all(target_os = "linux", target_arch = "x86_64"), target_os = "macos"),
                    feature = "blk"
                ))]
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

        let dir = std::env::temp_dir().join(format!(
            "libkrun-guardian-restore-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let size = 256 * 1024;
        let memory = vmm::GuestMemoryMmap::from_ranges(&[(GuestAddress(0), size)]).unwrap();
        memory
            .write_slice(&vec![0x5d_u8; size], GuestAddress(0))
            .unwrap();
        let guardian = vmm::generation_guardian::GenerationGuardian::start(
            &memory,
            &dir.join("ram-guardian.sock"),
        )
        .unwrap();
        atomic_write_file(&dir.join("checkpoint.bin"), b"checkpoint").unwrap();
        write_guardian_manifest(&dir.join("manifest.bin"), guardian.description()).unwrap();
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
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(not(target_os = "windows"))]
fn start_control_socket(path: PathBuf, vmm: Arc<Mutex<vmm::Vmm>>) -> std::io::Result<()> {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;

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

/// Select a stable virtual CPU contract for live migration.
///
/// This is deliberately explicit instead of changing libkrun's host-feature
/// default for every embedder. Callers that need portable checkpoints opt the
/// VM into the stable profile before `krun_start_enter`.
#[unsafe(no_mangle)]
pub extern "C" fn krun_set_cpu_template(ctx_id: u32, cpu_template: u32) -> i32 {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let template = match cpu_template {
        1 => vmm::vmm_config::machine_config::CpuFeaturesTemplate::PortableV1,
        _ => return -libc::EINVAL,
    };

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        // PortableV1 is an Intel architectural contract. Applying its model
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
                };
                cfg.add_block_cfg(block_device_config);
            }
            Entry::Vacant(_) => return -libc::ENOENT,
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
    if vtable_size < size_of::<DisplayBackend>() {
        return -libc::EINVAL;
    }

    // SAFETY: We have checked the vtable size is fine, otherwise we have to trust the user. Just
    // to be extra careful, this uses read_unaligned, but we could probably get away with ptr::read.
    let display_backend: DisplayBackend =
        unsafe { std::ptr::read_unaligned(vtable as *const DisplayBackend) };

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
                    return -libc::ENOTSUP;
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
    #[cfg(fork_supported)]
    let restore_ctx = match ctx_cfg.snapshot_dir.take() {
        Some(dir) => match build_restore_ctx(&dir) {
            Ok(rc) => Some(rc),
            Err(e) => {
                error!("fork restore from {}: {e}", dir.display());
                set_last_error(format!("restore checkpoint from {}: {e}", dir.display()));
                return -libc::EINVAL;
            }
        },
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
            error!("Building the microVM failed: {e:?}");
            set_last_error(format!("build microVM: {e}"));
            return -libc::EINVAL;
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
