#[macro_use]
extern crate log;

use crossbeam_channel::unbounded;
#[cfg(feature = "blk")]
use devices::virtio::block::{ImageType, SyncMode};
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use devices::virtio::fs::passthrough::PermissionSemantics;
#[cfg(feature = "gpu")]
use devices::virtio::gpu::display::DisplayInfo;
#[cfg(feature = "net")]
use devices::virtio::net::device::VirtioNetBackend;
#[cfg(feature = "blk")]
use devices::virtio::CacheType;
use env_logger::{Env, Target};
#[cfg(feature = "gpu")]
use krun_display::DisplayBackend;

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use devices::virtio::fs::virtual_entry::{VirtualDirEntry, VirtualEntry, VirtualEntryContent};
use libc::{c_char, c_int, size_t};
use once_cell::sync::Lazy;
use polly::event_manager::EventManager;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::ffi::CString;
use std::ffi::{c_void, CStr};
use std::fs::File;
use std::io::IsTerminal;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::os::fd::{BorrowedFd, FromRawFd, RawFd};
use std::path::PathBuf;
use std::slice;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::LazyLock;
use std::sync::Mutex;
use utils::eventfd::EventFd;
use vmm::resources::{
    DefaultVirtioConsoleConfig, PortConfig, SerialConsoleConfig, TsiFlags, VirtioConsoleConfigMode,
    VmResources, VsockConfig,
};
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
use vmm::vmm_config::kernel_cmdline::{KernelCmdlineConfig, DEFAULT_KERNEL_CMDLINE};
use vmm::vmm_config::machine_config::VmConfig;
#[cfg(feature = "net")]
use vmm::vmm_config::net::NetworkInterfaceConfig;
use vmm::vmm_config::vsock::VsockDeviceConfig;

#[cfg(feature = "aws-nitro")]
use aws_nitro::enclave::NitroEnclave;

#[cfg(feature = "gpu")]
use devices::virtio::display::{DisplayInfoEdid, PhysicalSize, MAX_DISPLAYS};
#[cfg(feature = "input")]
use krun_input::{InputConfigBackend, InputEventProviderBackend};

// Value returned on success. We use libc's errors otherwise.
const KRUN_SUCCESS: i32 = 0;
// Maximum number of arguments/environment variables we allow
const MAX_ARGS: usize = 4096;

// krunfw library name for each context
#[cfg(all(target_os = "linux", not(feature = "tee")))]
const KRUNFW_NAME: &str = "libkrunfw.so.5";
#[cfg(all(target_os = "linux", feature = "amd-sev"))]
const KRUNFW_NAME: &str = "libkrunfw-sev.so.5";
#[cfg(all(target_os = "linux", feature = "tdx"))]
const KRUNFW_NAME: &str = "libkrunfw-tdx.so.5";
#[cfg(target_os = "macos")]
const KRUNFW_NAME: &str = "libkrunfw.5.dylib";

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

#[derive(Clone)]
#[cfg(feature = "net")]
enum LegacyNetworkConfig {
    VirtioNetPasst(RawFd),
    VirtioNetGvproxy(PathBuf),
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
    #[cfg(feature = "net")]
    legacy_net_cfg: Option<LegacyNetworkConfig>,
    #[cfg(feature = "net")]
    legacy_mac: Option<[u8; 6]>,
    net_index: u8,
    tsi_port_map: Option<HashMap<u16, u16>>,
    vsock_config: VsockConfig,
    #[cfg(feature = "blk")]
    block_cfgs: Vec<BlockDeviceConfig>,
    #[cfg(feature = "blk")]
    root_block_cfg: Option<BlockDeviceConfig>,
    #[cfg(feature = "blk")]
    data_block_cfg: Option<BlockDeviceConfig>,
    #[cfg(feature = "blk")]
    block_root: Option<BlockRootConfig>,
    #[cfg(feature = "tee")]
    tee_config_file: Option<PathBuf>,
    unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
    shutdown_efd: Option<EventFd>,
    gpu_virgl_flags: Option<u32>,
    gpu_shm_size: Option<usize>,
    enable_snd: bool,
    console_output: Option<PathBuf>,
    vmm_uid: Option<libc::uid_t>,
    vmm_gid: Option<libc::gid_t>,
    #[cfg(all(
        feature = "init-blob",
        not(any(feature = "tee", feature = "aws-nitro"))
    ))]
    disable_implicit_init: bool,
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
    fn set_root_block_cfg(&mut self, block_cfg: BlockDeviceConfig) {
        self.root_block_cfg = Some(block_cfg);
    }

    #[cfg(feature = "blk")]
    fn set_data_block_cfg(&mut self, block_cfg: BlockDeviceConfig) {
        self.data_block_cfg = Some(block_cfg);
    }

    #[cfg(feature = "blk")]
    fn get_block_cfg(&self) -> Vec<BlockDeviceConfig> {
        // For backwards compat, when cfgs is empty (the new API is not used), this needs to be
        // root and then data, in that order. Also for backwards compat, root/data are setters and
        // need to discard redundant calls. So we have simple setters above and fix up here.
        //
        // When the new API is used, this is simpler.
        if self.block_cfgs.is_empty() {
            [&self.root_block_cfg, &self.data_block_cfg]
                .into_iter()
                .filter_map(|cfg| cfg.clone())
                .collect()
        } else {
            self.block_cfgs.clone()
        }
    }

    #[cfg(feature = "net")]
    fn set_net_mac(&mut self, mac: [u8; 6]) {
        self.legacy_mac = Some(mac);
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
        if let Some(ref mut map) = &mut self.unix_ipc_port_map {
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

    fn set_vmm_uid(&mut self, vmm_uid: libc::uid_t) {
        self.vmm_uid = Some(vmm_uid);
    }

    fn set_vmm_gid(&mut self, vmm_gid: libc::gid_t) {
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
                        VirtioNetBackend::UnixstreamFd(fd) => RawFd::from(fd),
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

        let Some(output_path) = ctx.console_output else {
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

#[no_mangle]
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
#[no_mangle]
pub unsafe extern "C" fn krun_init_log(target: RawFd, level: u32, style: u32, options: u32) -> i32 {
    let target = match target {
        ..-1 => return -libc::EINVAL,
        -1 => Target::default(),
        0 /* stdin */ => return -libc::EINVAL,
        1 /* stdout */ => Target::Stdout,
        2 /* stderr */ => Target::Stderr,
        fd => Target::Pipe(Box::new(File::from_raw_fd(fd))),
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

    KRUN_SUCCESS
}

#[no_mangle]
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

#[no_mangle]
pub extern "C" fn krun_free_ctx(ctx_id: u32) -> i32 {
    match CTX_MAP.lock().unwrap().remove(&ctx_id) {
        Some(_) => KRUN_SUCCESS,
        None => -libc::ENOENT,
    }
}

#[no_mangle]
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub unsafe extern "C" fn krun_set_root(ctx_id: u32, c_root_path: *const c_char) -> i32 {
    let root_path = match CStr::from_ptr(c_root_path).to_str() {
        Ok(root) => root,
        Err(_) => return -libc::EINVAL,
    };

    let fs_id = "/dev/root".to_string();
    let shared_dir = root_path.to_string();

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.vmr.add_fs_device(FsDeviceConfig {
                fs_id,
                shared_dir: Some(shared_dir),
                semantics: PermissionSemantics::LinuxComplete,
                // Default to a conservative 512 MB window.
                shm_size: Some(1 << 29),
                read_only: false,
                virtual_entries: {
                    #[allow(unused_mut)]
                    let mut v = Vec::new();
                    #[cfg(feature = "init-blob")]
                    if !cfg.disable_implicit_init {
                        v.push(init_virtual_entry());
                    }
                    v
                },
            });
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub unsafe extern "C" fn krun_add_virtiofs(
    ctx_id: u32,
    c_tag: *const c_char,
    c_path: *const c_char,
) -> i32 {
    krun_add_virtiofs4(ctx_id, c_tag, c_path, 0, false, 0)
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub unsafe extern "C" fn krun_add_virtiofs2(
    ctx_id: u32,
    c_tag: *const c_char,
    c_path: *const c_char,
    shm_size: u64,
) -> i32 {
    krun_add_virtiofs4(ctx_id, c_tag, c_path, shm_size, false, 0)
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub unsafe extern "C" fn krun_add_virtiofs3(
    ctx_id: u32,
    c_tag: *const c_char,
    c_path: *const c_char,
    shm_size: u64,
    read_only: bool,
) -> i32 {
    krun_add_virtiofs4(ctx_id, c_tag, c_path, shm_size, read_only, 0)
}

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub unsafe extern "C" fn krun_add_virtiofs4(
    ctx_id: u32,
    c_tag: *const c_char,
    c_path: *const c_char,
    shm_size: u64,
    read_only: bool,
    semantics: u32,
) -> i32 {
    let semantics = match PermissionSemantics::try_from(semantics) {
        Ok(semantics) => semantics,
        Err(_) => return -libc::EINVAL,
    };

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
                semantics,
                shm_size: shm,
                read_only,
                virtual_entries,
            });
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(not(feature = "tee"))]
pub unsafe extern "C" fn krun_set_mapped_volumes(
    _ctx_id: u32,
    _c_mapped_volumes: *const *const c_char,
) -> i32 {
    -libc::EINVAL
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "blk")]
pub unsafe extern "C" fn krun_add_disk(
    ctx_id: u32,
    c_block_id: *const c_char,
    c_disk_path: *const c_char,
    read_only: bool,
) -> i32 {
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "blk")]
pub unsafe extern "C" fn krun_add_disk2(
    ctx_id: u32,
    c_block_id: *const c_char,
    c_disk_path: *const c_char,
    disk_format: u32,
    read_only: bool,
) -> i32 {
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "blk")]
pub unsafe extern "C" fn krun_set_root_disk(ctx_id: u32, c_disk_path: *const c_char) -> i32 {
    let disk_path = match CStr::from_ptr(c_disk_path).to_str() {
        Ok(disk) => disk,
        Err(_) => return -libc::EINVAL,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            let block_device_config = BlockDeviceConfig {
                block_id: "root".to_string(),
                cache_type: CacheType::auto(disk_path),
                disk_image_path: disk_path.to_string(),
                disk_image_format: ImageType::Raw,
                is_disk_read_only: false,
                direct_io: false,
                #[cfg(not(target_os = "macos"))]
                sync_mode: SyncMode::Full,
                #[cfg(target_os = "macos")]
                sync_mode: SyncMode::Relaxed,
            };
            cfg.set_root_block_cfg(block_device_config);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "blk")]
pub unsafe extern "C" fn krun_set_data_disk(ctx_id: u32, c_disk_path: *const c_char) -> i32 {
    let disk_path = match CStr::from_ptr(c_disk_path).to_str() {
        Ok(disk) => disk,
        Err(_) => return -libc::EINVAL,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            let block_device_config = BlockDeviceConfig {
                block_id: "data".to_string(),
                cache_type: CacheType::auto(disk_path),
                disk_image_path: disk_path.to_string(),
                disk_image_format: ImageType::Raw,
                is_disk_read_only: false,
                direct_io: false,
                #[cfg(not(target_os = "macos"))]
                sync_mode: SyncMode::Full,
                #[cfg(target_os = "macos")]
                sync_mode: SyncMode::Relaxed,
            };
            cfg.set_data_block_cfg(block_device_config);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

/*
 * Send the VFKIT magic after establishing the connection,
 * as required by gvproxy in vfkit mode.
 */
#[cfg(feature = "net")]
const NET_FLAG_VFKIT: u32 = 1 << 0;
#[cfg(feature = "net")]
const NET_FLAG_DHCP_CLIENT: u32 = 1 << 1;
#[cfg(feature = "net")]
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
/*
 * These are the flags enabled by default on each virtio-net instance
 * before the introduction of "krun_add_net_*". They are now used in
 * the legacy API ("krun_set_passt_fd" and "krun_set_gvproxy_path")
 * for compatiblity reasons.
 */
#[cfg(feature = "net")]
const NET_COMPAT_FEATURES: u32 = NET_FEATURE_CSUM
    | NET_FEATURE_GUEST_CSUM
    | NET_FEATURE_GUEST_TSO4
    | NET_FEATURE_GUEST_UFO
    | NET_FEATURE_HOST_TSO4
    | NET_FEATURE_HOST_UFO;
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
#[no_mangle]
#[cfg(feature = "net")]
pub unsafe extern "C" fn krun_add_net_unixstream(
    ctx_id: u32,
    c_path: *const c_char,
    fd: c_int,
    c_mac: *const u8,
    features: u32,
    flags: u32,
) -> i32 {
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
    let backend = if let Some(path) = path {
        VirtioNetBackend::UnixstreamPath(path)
    } else {
        VirtioNetBackend::UnixstreamFd(fd)
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "net")]
pub unsafe extern "C" fn krun_add_net_unixgram(
    ctx_id: u32,
    c_path: *const c_char,
    fd: c_int,
    c_mac: *const u8,
    features: u32,
    flags: u32,
) -> i32 {
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(all(target_os = "linux", feature = "net"))]
pub unsafe extern "C" fn krun_add_net_tap(
    ctx_id: u32,
    c_tap_name: *const c_char,
    c_mac: *const u8,
    features: u32,
    flags: u32,
) -> i32 {
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
        debug!("Network tap backend requires GUEST_CSUM to be requested if any of GUEST_TSO4, GUEST_TSO6 and/or GUEST_UFO are required");
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
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
#[no_mangle]
#[cfg(feature = "net")]
pub unsafe extern "C" fn krun_set_passt_fd(ctx_id: u32, fd: c_int) -> i32 {
    if fd < 0 {
        return -libc::EINVAL;
    }

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            // The legacy interface only supports a single network interface.
            if cfg.net_index != 0 {
                return -libc::EINVAL;
            }
            cfg.legacy_net_cfg = Some(LegacyNetworkConfig::VirtioNetPasst(fd));
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }
    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "net")]
pub unsafe extern "C" fn krun_set_gvproxy_path(ctx_id: u32, c_path: *const c_char) -> i32 {
    let path_str = match CStr::from_ptr(c_path).to_str() {
        Ok(path) => path,
        Err(e) => {
            debug!("Error parsing gvproxy_path: {e:?}");
            return -libc::EINVAL;
        }
    };

    let path = PathBuf::from(path_str);

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            // The legacy interface only supports a single network interface.
            if cfg.net_index != 0 {
                return -libc::EINVAL;
            }
            cfg.legacy_net_cfg = Some(LegacyNetworkConfig::VirtioNetGvproxy(path));
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }
    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "net")]
pub unsafe extern "C" fn krun_set_net_mac(ctx_id: u32, c_mac: *const u8) -> i32 {
    let mac: [u8; 6] = match slice::from_raw_parts(c_mac, 6).try_into() {
        Ok(m) => m,
        Err(_) => return -libc::EINVAL,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_net_mac(mac);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }
    KRUN_SUCCESS
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_port_map(ctx_id: u32, c_port_map: *const *const c_char) -> i32 {
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_rlimits(ctx_id: u32, c_rlimits: *const *const c_char) -> i32 {
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_workdir(ctx_id: u32, c_workdir_path: *const c_char) -> i32 {
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

unsafe fn collapse_str_array(array: &[*const c_char]) -> Result<String, std::str::Utf8Error> {
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

#[allow(clippy::format_collect)]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_exec(
    ctx_id: u32,
    c_exec_path: *const c_char,
    c_argv: *const *const c_char,
    c_envp: *const *const c_char,
) -> i32 {
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

#[allow(clippy::format_collect)]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_env(ctx_id: u32, c_envp: *const *const c_char) -> i32 {
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "tee")]
pub unsafe extern "C" fn krun_set_tee_config_file(ctx_id: u32, c_filepath: *const c_char) -> i32 {
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_add_vsock_port(
    ctx_id: u32,
    port: u32,
    c_filepath: *const c_char,
) -> i32 {
    krun_add_vsock_port2(ctx_id, port, c_filepath, false)
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_add_vsock_port2(
    ctx_id: u32,
    port: u32,
    c_filepath: *const c_char,
    listen: bool,
) -> i32 {
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
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
#[no_mangle]
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
#[no_mangle]
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
#[no_mangle]
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
#[no_mangle]
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
#[no_mangle]
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
#[no_mangle]
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
#[no_mangle]
pub unsafe extern "C" fn krun_add_input_device_fd(_ctx_id: u32, _input_fd: i32) -> i32 {
    -libc::ENOTSUP
}

#[cfg(feature = "gpu")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
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
#[no_mangle]
pub unsafe extern "C" fn krun_add_display(_ctx_id: u32, _width: u32, _height: u32) -> i32 {
    -libc::ENOTSUP
}

#[cfg(feature = "gpu")]
#[no_mangle]
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
#[no_mangle]
pub extern "C" fn krun_display_set_refresh_rate(
    _ctx_id: u32,
    _display_id: u32,
    _refresh_rate: u32,
) -> i32 {
    -libc::ENOTSUP
}

#[cfg(feature = "gpu")]
#[no_mangle]
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
#[no_mangle]
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
#[no_mangle]
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
#[no_mangle]
pub extern "C" fn krun_display_set_physical_size(
    _ctx_id: u32,
    _display_id: u32,
    _width_mm: u16,
    _height_mm: u16,
) -> i32 {
    -libc::ENOTSUP
}

#[cfg(feature = "gpu")]
#[no_mangle]
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
#[no_mangle]
pub extern "C" fn krun_display_set_dpi(_ctx_id: u32, _display_id: u32, _dpi: u32) -> i32 {
    -libc::ENOTSUP
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_snd_device(ctx_id: u32, enable: bool) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.enable_snd = enable;
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[allow(unused_assignments)]
#[no_mangle]
pub extern "C" fn krun_get_shutdown_eventfd(ctx_id: u32) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            if let Some(efd) = cfg.shutdown_efd.as_ref() {
                #[cfg(target_os = "macos")]
                return efd.get_write_fd();
                #[cfg(target_os = "linux")]
                return efd.as_raw_fd();
            } else {
                -libc::EINVAL
            }
        }
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_console_output(ctx_id: u32, c_filepath: *const c_char) -> i32 {
    let filepath = match CStr::from_ptr(c_filepath).to_str() {
        Ok(f) => f,
        Err(_) => return -libc::EINVAL,
    };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            if cfg.console_output.is_some() {
                -libc::EINVAL
            } else {
                cfg.console_output = Some(PathBuf::from(filepath.to_string()));
                KRUN_SUCCESS
            }
        }
        Entry::Vacant(_) => -libc::ENOENT,
    }
}

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
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
#[no_mangle]
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
const KRUN_FEATURE_SND: u64 = 3;
const KRUN_FEATURE_INPUT: u64 = 4;
const KRUN_FEATURE_EFI: u64 = 5;
const KRUN_FEATURE_TEE: u64 = 6;
const KRUN_FEATURE_AMD_SEV: u64 = 7;
const KRUN_FEATURE_INTEL_TDX: u64 = 8;
const KRUN_FEATURE_AWS_NITRO: u64 = 9;
const KRUN_FEATURE_VIRGL_RESOURCE_MAP_FIXED: u64 = 10;
const KRUN_FEATURE_INIT_BLOB: u64 = 11;

#[no_mangle]
pub extern "C" fn krun_has_feature(feature: u64) -> c_int {
    let supported = match feature {
        KRUN_FEATURE_NET => cfg!(feature = "net"),
        KRUN_FEATURE_BLK => cfg!(feature = "blk"),
        KRUN_FEATURE_GPU => cfg!(feature = "gpu"),
        KRUN_FEATURE_SND => cfg!(feature = "snd"),
        KRUN_FEATURE_INPUT => cfg!(feature = "input"),
        KRUN_FEATURE_EFI => cfg!(feature = "efi"),
        KRUN_FEATURE_TEE => cfg!(feature = "tee"),
        KRUN_FEATURE_AMD_SEV => cfg!(feature = "amd-sev"),
        KRUN_FEATURE_INTEL_TDX => cfg!(feature = "tdx"),
        KRUN_FEATURE_AWS_NITRO => cfg!(feature = "aws-nitro"),
        KRUN_FEATURE_VIRGL_RESOURCE_MAP_FIXED => {
            #[cfg(feature = "gpu")]
            {
                devices::supports_virgl_renderer_resource_map_fixed()
            }

            #[cfg(not(feature = "gpu"))]
            {
                false
            }
        }
        KRUN_FEATURE_INIT_BLOB => cfg!(feature = "init-blob"),
        _ => return -libc::EINVAL,
    };

    supported as c_int
}

#[cfg(test)]
mod test_has_feature {
    use super::*;

    #[test]
    fn virgl_resource_map_fixed_matches_runtime_support() {
        #[cfg(feature = "gpu")]
        let expected = devices::supports_virgl_renderer_resource_map_fixed() as c_int;
        #[cfg(not(feature = "gpu"))]
        let expected = 0;

        assert_eq!(
            krun_has_feature(KRUN_FEATURE_VIRGL_RESOURCE_MAP_FIXED),
            expected
        );
    }
}

/// Gets the maximum number of vCPUs supported by the hypervisor.
///
/// Returns the maximum number of vCPUs that can be created by this hypervisor,
/// or a negative error code on failure.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[no_mangle]
pub extern "C" fn krun_get_max_vcpus() -> i32 {
    #[cfg(target_os = "macos")]
    {
        use hvf::bindings::{hv_vm_get_max_vcpu_count, HV_SUCCESS};
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
#[no_mangle]
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
#[no_mangle]
pub unsafe extern "C" fn krun_set_smbios_oem_strings(
    ctx_id: u32,
    oem_strings: *const *const c_char,
) -> i32 {
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
    if std::ptr::eq(kernel_host_addr, libc::MAP_FAILED) {
        error!("Can't load kernel into process map");
        return -libc::EINVAL;
    }

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
#[no_mangle]
pub unsafe extern "C" fn krun_set_kernel(_ctx_id: u32, _c_kernel_path: *const c_char) -> i32 {
    -libc::EOPNOTSUPP
}

#[cfg(not(feature = "tee"))]
#[allow(clippy::format_collect)]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_kernel(
    ctx_id: u32,
    c_kernel_path: *const c_char,
    kernel_format: u32,
    c_initramfs_path: *const c_char,
    c_cmdline: *const c_char,
) -> i32 {
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
        Entry::Occupied(mut ctx_cfg) => ctx_cfg.get_mut().vmr.set_external_kernel(external_kernel),
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[cfg(not(feature = "tee"))]
#[allow(clippy::format_collect)]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_firmware(ctx_id: u32, c_firmware_path: *const c_char) -> i32 {
    let path = match CStr::from_ptr(c_firmware_path).to_str() {
        Ok(path) => PathBuf::from(path),
        Err(e) => {
            error!("Error parsing firmware_path: {e:?}");
            return -libc::EINVAL;
        }
    };

    let firmware_config = FirmwareConfig { path };

    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => ctx_cfg.get_mut().vmr.set_firmware_config(firmware_config),
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
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

#[no_mangle]
pub extern "C" fn krun_setuid(ctx_id: u32, uid: libc::uid_t) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.set_vmm_uid(uid);
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[no_mangle]
pub extern "C" fn krun_setgid(ctx_id: u32, gid: libc::gid_t) -> i32 {
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
#[no_mangle]
pub unsafe extern "C" fn krun_set_root_disk_remount(
    ctx_id: u32,
    c_device: *const c_char,
    c_fstype: *const c_char,
    c_options: *const c_char,
) -> i32 {
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
                semantics: PermissionSemantics::LinuxComplete,
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
#[no_mangle]
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

    let fs_tag = match CStr::from_ptr(c_fs_tag).to_str() {
        Ok(s) => s,
        Err(_) => return -libc::EINVAL,
    };
    let path = match CStr::from_ptr(c_path).to_str() {
        Ok(s) => s,
        Err(_) => return -libc::EINVAL,
    };

    // SAFETY: The caller guarantees the memory remains valid for the VM
    // lifetime (see the C header contract).
    let payload: &'static [u8] = if data_len == 0 {
        &[]
    } else if !data.is_null() {
        slice::from_raw_parts(data, data_len)
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
#[no_mangle]
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

    let fs_tag = match CStr::from_ptr(c_fs_tag).to_str() {
        Ok(s) => s,
        Err(_) => return -libc::EINVAL,
    };
    let path = match CStr::from_ptr(c_path).to_str() {
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
    *data_out = DEFAULT_INIT_PAYLOAD.as_ptr();
    *len_out = DEFAULT_INIT_PAYLOAD.len();
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
pub extern "C" fn krun_disable_implicit_console(ctx_id: u32) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.vmr.disable_implicit_console = true;
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[no_mangle]
pub extern "C" fn krun_disable_implicit_vsock(ctx_id: u32) -> i32 {
    match CTX_MAP.lock().unwrap().entry(ctx_id) {
        Entry::Occupied(mut ctx_cfg) => {
            let cfg = ctx_cfg.get_mut();
            cfg.vsock_config = VsockConfig::Disabled;
        }
        Entry::Vacant(_) => return -libc::ENOENT,
    }

    KRUN_SUCCESS
}

#[no_mangle]
pub extern "C" fn krun_add_vsock(ctx_id: u32, tsi_features: u32) -> i32 {
    let tsi_flags = match TsiFlags::from_bits(tsi_features) {
        Some(flags) => flags,
        None => return -libc::EINVAL,
    };

    if cfg!(target_os = "macos") && tsi_flags.contains(TsiFlags::HIJACK_UNIX) {
        error!("TSI hijacking of UNIX sockets is not yet supported on macOS");
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_add_console_port_tty(
    ctx_id: u32,
    console_id: u32,
    name: *const libc::c_char,
    tty_fd: libc::c_int,
) -> i32 {
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_add_console_port_inout(
    ctx_id: u32,
    console_id: u32,
    name: *const c_char,
    input_fd: c_int,
    output_fd: c_int,
) -> i32 {
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
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

#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn krun_set_kernel_console(ctx_id: u32, console_id: *const c_char) -> i32 {
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

#[no_mangle]
#[allow(unreachable_code)]
pub extern "C" fn krun_start_enter(ctx_id: u32) -> i32 {
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

    let mut event_manager = match EventManager::new() {
        Ok(em) => em,
        Err(e) => {
            error!("Unable to create EventManager: {e:?}");
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
        && cfg!(not(feature = "efi"))
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

    #[cfg(feature = "net")]
    {
        if let Some(legacy_net_cfg) = ctx_cfg.legacy_net_cfg.clone() {
            let backend = match legacy_net_cfg {
                LegacyNetworkConfig::VirtioNetGvproxy(path) => {
                    VirtioNetBackend::UnixgramPath(path, true)
                }
                LegacyNetworkConfig::VirtioNetPasst(fd) => VirtioNetBackend::UnixstreamFd(fd),
            };
            let mac = ctx_cfg
                .legacy_mac
                .unwrap_or([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee]);
            create_virtio_net(&mut ctx_cfg, backend, mac, NET_COMPAT_FEATURES);
        }
    }

    match &ctx_cfg.vsock_config {
        VsockConfig::Disabled => (),
        VsockConfig::Explicit { tsi_flags } => {
            let vsock_device_config = VsockDeviceConfig {
                vsock_id: "vsock0".to_string(),
                guest_cid: 3,
                host_port_map: ctx_cfg.tsi_port_map,
                unix_ipc_port_map: ctx_cfg.unix_ipc_port_map.clone(),
                tsi_flags: *tsi_flags,
            };
            ctx_cfg.vmr.set_vsock_device(vsock_device_config).unwrap();
        }
        VsockConfig::Implicit => {
            // Implicit vsock configuration - use heuristics
            // Check if TSI should be enabled based on network configuration
            #[cfg(feature = "net")]
            let enable_tsi = ctx_cfg.vmr.net.list.is_empty() && ctx_cfg.legacy_net_cfg.is_none();
            #[cfg(not(feature = "net"))]
            let enable_tsi = true;

            let has_ipc_map = ctx_cfg.unix_ipc_port_map.is_some();

            if enable_tsi || has_ipc_map {
                let (tsi_flags, host_port_map) = if enable_tsi {
                    (TsiFlags::HIJACK_INET, ctx_cfg.tsi_port_map)
                } else {
                    (TsiFlags::empty(), None)
                };

                let vsock_device_config = VsockDeviceConfig {
                    vsock_id: "vsock0".to_string(),
                    guest_cid: 3,
                    host_port_map,
                    unix_ipc_port_map: ctx_cfg.unix_ipc_port_map.clone(),
                    tsi_flags,
                };
                ctx_cfg.vmr.set_vsock_device(vsock_device_config).unwrap();
            }
        }
    }

    if let Some(virgl_flags) = ctx_cfg.gpu_virgl_flags {
        ctx_cfg.vmr.set_gpu_virgl_flags(virgl_flags);
    }
    if let Some(shm_size) = ctx_cfg.gpu_shm_size {
        ctx_cfg.vmr.set_gpu_shm_size(shm_size);
    }

    #[cfg(feature = "snd")]
    ctx_cfg.vmr.set_snd_device(ctx_cfg.enable_snd);

    if let Some(console_output) = ctx_cfg.console_output {
        ctx_cfg.vmr.set_console_output(console_output);
    }

    if let Some(gid) = ctx_cfg.vmm_gid {
        if unsafe { libc::setgid(gid) } != 0 {
            error!("Failed to set gid {gid}");
            return -std::io::Error::last_os_error().raw_os_error().unwrap();
        }
    }

    if let Some(uid) = ctx_cfg.vmm_uid {
        if unsafe { libc::setuid(uid) } != 0 {
            error!("Failed to set uid {uid}");
            return -std::io::Error::last_os_error().raw_os_error().unwrap();
        }
    }

    let (sender, _receiver) = unbounded();

    let _vmm = match vmm::builder::build_microvm(
        &ctx_cfg.vmr,
        &mut event_manager,
        ctx_cfg.shutdown_efd,
        sender,
    ) {
        Ok(vmm) => vmm,
        Err(e) => {
            error!("Building the microVM failed: {e:?}");
            return -libc::EINVAL;
        }
    };

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

#[cfg(feature = "aws-nitro")]
#[no_mangle]
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
        let ctx = unsafe { krun_create_ctx() } as u32;
        unsafe {
            krun_disable_implicit_init(ctx);
            krun_set_root(ctx, c"/tmp".as_ptr());
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
