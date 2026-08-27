use std::collections::HashMap;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use std::ffi::CString;
use std::io::IsTerminal;
use std::marker::PhantomData;
#[cfg(target_os = "linux")]
use std::os::fd::RawFd;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};

#[cfg(feature = "gpu")]
use devices::display::{DisplayInfo, DisplayInfoEdid, PhysicalSize};
use devices::legacy::IrqChip;
#[cfg(feature = "blk")]
use devices::virtio::block::{DiskFormat, SyncMode};
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use devices::virtio::fs::virtual_entry::{VirtualDirEntry, VirtualEntry, VirtualEntryContent};
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use devices::virtio::passthrough::PermissionSemantics;
use devices::virtio::{PortDescription, VirtioDevice, VirtioShmRegion, VmmExitObserver, port_io};
#[cfg(feature = "input")]
use krun_input;
use polly::event_manager::{EventManager, Subscriber};
use vm_memory::GuestMemoryMmap;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
use vm_memory::{Address, GuestMemory};
use vmm::Vmm;
use vmm::builder::{attach_mmio_device, setup_terminal_raw_mode};
use vmm::device_manager::shm::ShmManager;

use super::error::Error;
use super::export_bitflags;

/// Requirements a device declares before the VM's memory layout is fixed.
/// `#[non_exhaustive]` allows adding new fields in minor releases.
#[derive(Default)]
#[non_exhaustive]
pub struct DeviceRequirements {
    /// Size of shared memory (DAX) window needed, if any.
    pub shm_size: Option<usize>,
    // TODO: unify fs and gpu shm into a single SHM abstraction
    /// GPU shared memory size, if this is a GPU device.
    #[cfg(feature = "gpu")]
    pub gpu_shm: Option<usize>,
    /// Whether this device needs process-shareable memory (vhost-user).
    pub process_shareable_memory: bool,
}

/// Context provided to devices during attachment.
///
/// This struct wraps internal VMM state and exposes a stable set of capability
/// methods. Adding new methods is a non-breaking (semver-minor) change.
/// Devices call these methods in their [`AttachDevice::attach`] implementation
/// instead of interacting with VMM internals directly.
#[allow(clippy::type_complexity)]
pub struct AttachContext<'a> {
    vmm: &'a mut Vmm,
    event_manager: &'a mut EventManager,
    #[allow(dead_code)]
    shm_manager: &'a ShmManager,
    intc: IrqChip,
    device_index: usize,
    register_fn: Box<
        dyn Fn(&mut Vmm, String, IrqChip, Arc<Mutex<dyn VirtioDevice>>) -> Result<(), Error> + 'a,
    >,
    #[cfg(target_os = "macos")]
    map_sender: Option<crossbeam_channel::Sender<utils::worker_message::WorkerMessage>>,
}

impl<'a> AttachContext<'a> {
    pub(crate) fn new_mmio(
        vmm: &'a mut Vmm,
        event_manager: &'a mut EventManager,
        shm_manager: &'a ShmManager,
        intc: IrqChip,
        device_index: usize,
        #[cfg(target_os = "macos")] map_sender: Option<
            crossbeam_channel::Sender<utils::worker_message::WorkerMessage>,
        >,
    ) -> Self {
        Self {
            vmm,
            event_manager,
            shm_manager,
            intc,
            device_index,
            register_fn: Box::new(|vmm, id, intc, device| {
                attach_mmio_device(vmm, id, intc, device)
                    .map_err(|e| Error::Internal(format!("{e:?}")))?;
                Ok(())
            }),
            #[cfg(target_os = "macos")]
            map_sender,
        }
    }

    /// Register a virtio device on the transport bus.
    ///
    /// The actual transport (MMIO, future PCIe) is determined by which
    /// [`DeviceManager`] the device was added to.
    pub fn register(
        &mut self,
        id: &str,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> Result<(), Error> {
        (self.register_fn)(self.vmm, id.to_string(), self.intc.clone(), device)
    }

    /// Subscribe a device to the event loop for epoll-based I/O.
    pub fn subscribe_events(
        &mut self,
        subscriber: Arc<Mutex<dyn Subscriber>>,
    ) -> Result<(), Error> {
        self.event_manager
            .add_subscriber(subscriber)
            .map_err(|e| Error::Internal(format!("{e:?}")))
    }

    /// Register a cleanup callback invoked on VM shutdown.
    pub fn push_exit_observer(&mut self, observer: Arc<Mutex<dyn VmmExitObserver>>) {
        self.vmm.exit_observers.push(observer);
    }

    /// The VM's exit code. Devices (e.g. virtiofs) can write to this
    /// to communicate an exit code to the host.
    pub fn exit_code(&self) -> &Arc<AtomicI32> {
        &self.vmm.exit_code
    }

    /// The VM's guest memory map.
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.vmm.guest_memory
    }

    /// The resolved SHM region for the current device index, if one was
    /// allocated based on [`DeviceRequirements::shm_size`].
    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    pub fn resolved_shm_region(&self) -> Option<ResolvedShmRegion> {
        self.shm_manager.fs_region(self.device_index).map(|r| {
            let host_addr = self
                .vmm
                .guest_memory
                .get_host_address(r.guest_addr)
                .expect("shm region host address");
            ResolvedShmRegion {
                host_addr: host_addr as u64,
                guest_addr: r.guest_addr.raw_value(),
                size: r.size,
            }
        })
    }

    /// The resolved GPU SHM region, if GPU is enabled and a region was allocated.
    #[cfg(feature = "gpu")]
    pub fn resolved_gpu_shm_region(&self) -> Option<ResolvedShmRegion> {
        self.shm_manager.gpu_region().map(|r| {
            let host_addr = self
                .vmm
                .guest_memory
                .get_host_address(r.guest_addr)
                .expect("gpu shm region host address");
            ResolvedShmRegion {
                host_addr: host_addr as u64,
                guest_addr: r.guest_addr.raw_value(),
                size: r.size,
            }
        })
    }

    /// The index of the current device within its device manager.
    pub fn device_index(&self) -> usize {
        self.device_index
    }

    /// Register a SIGWINCH signal handler that writes to the given fd.
    /// Typically used by the console device.
    #[cfg(target_os = "linux")]
    pub fn register_sigwinch(&mut self, fd: RawFd) -> Result<(), Error> {
        vmm::signal_handler::register_sigwinch_handler(fd)
            .map_err(|e| Error::Internal(format!("{e:?}")))
    }

    /// Set up terminal raw mode for the given fd, registering a cleanup
    /// observer to restore the terminal on VM shutdown.
    pub fn setup_terminal_raw_mode(&mut self, fd: BorrowedFd<'_>) {
        setup_terminal_raw_mode(self.vmm, Some(fd), false);
    }

    /// Get the macOS memory mapping channel sender, if available.
    /// Used by GPU and Fs devices for DAX memory mapping on macOS.
    #[cfg(target_os = "macos")]
    pub fn map_sender(
        &self,
    ) -> Option<crossbeam_channel::Sender<utils::worker_message::WorkerMessage>> {
        self.map_sender.clone()
    }

    /// Append a string to the kernel command line.
    /// Used by devices that need to pass parameters to the guest kernel
    /// (e.g., vsock TSI flags).
    pub fn append_kernel_cmdline(&mut self, s: &str) {
        self.vmm
            .kernel_cmdline
            .insert_str(s)
            .unwrap_or_else(|e| log::error!("failed to append '{s}' to cmdline: {e}"));
    }
}

/// A resolved shared memory region with both host and guest addresses.
///
/// Returned by [`AttachContext::resolved_shm_region`] after guest memory has been
/// created and the SHM region mapped.
pub struct ResolvedShmRegion {
    /// Host virtual address of the start of the SHM region.
    pub host_addr: u64,
    /// Guest physical address of the start of the SHM region.
    pub guest_addr: u64,
    /// Size of the SHM region in bytes.
    pub size: usize,
}

impl From<ResolvedShmRegion> for VirtioShmRegion {
    fn from(r: ResolvedShmRegion) -> Self {
        VirtioShmRegion {
            host_addr: r.host_addr,
            guest_addr: r.guest_addr,
            size: r.size,
        }
    }
}

/// Trait implemented by devices that can be attached to a VM.
///
/// Built-in devices (`FsDevice`, `ConsoleDevice`, etc.) implement this.
/// Future users can implement this for custom virtio devices.
///
/// The [`attach`](AttachDevice::attach) method receives an [`AttachContext`]
/// with all VMM capabilities. Adding new methods to `AttachContext` is a
/// non-breaking change, so the trait signature never needs to change.
pub trait AttachDevice<'a>: Send + 'a {
    /// Declare requirements before guest memory is created.
    fn requirements(&self) -> DeviceRequirements {
        DeviceRequirements::default()
    }

    /// Attach this device to the VM.
    ///
    /// The device should:
    /// 1. Perform any device-specific setup using `ctx` methods
    /// 2. Call [`ctx.register()`](AttachContext::register) to register on the transport bus
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), Error>;
}

mod sealed {
    pub trait Sealed {}
}

/// A device manager that owns a set of devices and knows how to attach them
/// to a VM using a specific transport (e.g. MMIO, future PCIe).
///
/// This trait is sealed — only libkrun-provided managers can implement it.
/// The seal may be lifted in a future major version.
pub trait DeviceManager<'a>: sealed::Sealed + Send + 'a {
    /// Collect requirements from all devices (called before guest memory creation).
    #[doc(hidden)]
    fn requirements(&self) -> Vec<DeviceRequirements>;

    /// Attach all devices using the given VMM context.
    #[doc(hidden)]
    fn attach_all(
        self: Box<Self>,
        vmm: &mut Vmm,
        event_manager: &mut EventManager,
        shm_manager: &ShmManager,
        intc: IrqChip,
        #[cfg(target_os = "macos")] map_sender: Option<
            crossbeam_channel::Sender<utils::worker_message::WorkerMessage>,
        >,
    ) -> Result<(), Error>;
}

/// Device manager using the virtio-mmio transport.
///
/// Devices added to this manager will be registered on the MMIO bus
/// during VM construction.
#[derive(Default)]
pub struct MmioDeviceManager<'a> {
    devices: Vec<Box<dyn AttachDevice<'a> + 'a>>,
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl<'a> MmioDeviceManager<'a> {
    /// Create an empty device manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a device to this manager.
    ///
    /// Devices are attached in the order they are added. The device must
    /// implement [`AttachDevice`] — all built-in device types
    /// (`FsDevice`, `ConsoleDevice`, etc.) implement this trait.
    pub fn add(&mut self, device: impl AttachDevice<'a>) -> &mut Self {
        self.devices.push(Box::new(device));
        self
    }
}

impl sealed::Sealed for MmioDeviceManager<'_> {}

impl<'a> DeviceManager<'a> for MmioDeviceManager<'a> {
    fn requirements(&self) -> Vec<DeviceRequirements> {
        self.devices.iter().map(|d| d.requirements()).collect()
    }

    fn attach_all(
        self: Box<Self>,
        vmm: &mut Vmm,
        event_manager: &mut EventManager,
        shm_manager: &ShmManager,
        intc: IrqChip,
        #[cfg(target_os = "macos")] map_sender: Option<
            crossbeam_channel::Sender<utils::worker_message::WorkerMessage>,
        >,
    ) -> Result<(), Error> {
        for (i, device) in self.devices.into_iter().enumerate() {
            let mut ctx = AttachContext::new_mmio(
                vmm,
                event_manager,
                shm_manager,
                intc.clone(),
                i,
                #[cfg(target_os = "macos")]
                map_sender.clone(),
            );
            device.attach(&mut ctx)?;
        }
        Ok(())
    }
}

/// A set of virtual filesystem entries to overlay on a virtiofs device.
///
/// Entries are synthetic files/directories that exist only in memory,
/// overlaid on top of the real (or null) host filesystem. They are
/// visible to the guest but do not exist on the host.
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
#[derive(Default)]
pub struct FsOverlay {
    entries: Vec<VirtualDirEntry>,
}

#[cfg_attr(
    feature = "ffi",
    ffier::export(cfg = "not(any(feature = \"tee\", feature = \"aws-nitro\"))")
)]
#[cfg_attr(
    not(feature = "ffi"),
    cfg(not(any(feature = "tee", feature = "aws-nitro")))
)]
impl FsOverlay {
    /// Create a new empty overlay.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a virtual directory entry.
    ///
    /// `path` may contain `/` separators for nested entries (e.g. `"etc/nested"`).
    /// Intermediate directories must already exist in the overlay.
    pub fn add_dir(&mut self, path: &str, mode: u32) {
        let entry = VirtualEntry {
            mode,
            one_shot: false,
            content: VirtualEntryContent::Dir {
                children: Vec::new(),
            },
        };
        self.add_at_path(path, entry);
    }

    /// Add a virtual file entry.
    ///
    /// `path` may contain `/` separators for nested entries (e.g. `"etc/nested/file.txt"`).
    /// Intermediate directories must already exist in the overlay.
    pub fn add_file(&mut self, path: &str, data: &[u8], mode: u32, one_shot: bool) {
        let data: &'static [u8] = Box::leak(data.to_vec().into_boxed_slice());
        let entry = VirtualEntry {
            mode,
            one_shot,
            content: VirtualEntryContent::File { data },
        };
        self.add_at_path(path, entry);
    }
}

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
impl FsOverlay {
    /// Consume the overlay and return the raw virtual directory entries.
    pub fn into_entries(self) -> Vec<VirtualDirEntry> {
        self.entries
    }

    fn add_at_path(&mut self, path: &str, entry: VirtualEntry) {
        let path = path.strip_prefix('/').unwrap_or(path);
        let components: Vec<&str> = path.split('/').collect();
        let (leaf, parents) = components
            .split_last()
            .expect("overlay path must not be empty");

        let target = resolve_parent_dirs(&mut self.entries, parents);
        target.push(VirtualDirEntry {
            name: CString::new(*leaf).unwrap(),
            entry,
        });
    }
}

/// A virtio-fs (virtiofs) shared filesystem device.
///
/// Exposes a host directory to the guest as a shared filesystem.
/// The `tag` is used by the guest to mount the filesystem
/// (e.g. `mount -t virtiofs /dev/root /mnt`).
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub struct FsDevice<'a> {
    pub(crate) inner: Arc<Mutex<devices::virtio::Fs>>,
    #[allow(dead_code)]
    pub(crate) tag: String,
    pub(crate) shm_size: Option<usize>,
    pub(crate) overlay: Option<FsOverlay>,
    _lifetime: PhantomData<&'a ()>,
}

#[cfg_attr(
    feature = "ffi",
    ffier::export(cfg = "not(any(feature = \"tee\", feature = \"aws-nitro\"))")
)]
#[cfg_attr(
    not(feature = "ffi"),
    cfg(not(any(feature = "tee", feature = "aws-nitro")))
)]
impl<'a> FsDevice<'a> {
    /// Create a new virtiofs device sharing a host directory.
    ///
    /// # Arguments
    ///
    /// - `tag`: the filesystem tag visible to the guest (e.g. `"/dev/root"`).
    /// - `host_path`: the host directory to share.
    pub fn new(tag: &str, host_path: &str) -> Result<Self, Error> {
        Self::new_inner(tag, Some(host_path.to_string()), false)
    }

    /// Create a read-only virtiofs device sharing a host directory.
    pub fn new_read_only(tag: &str, host_path: &str) -> Result<Self, Error> {
        Self::new_inner(tag, Some(host_path.to_string()), true)
    }

    /// Create a virtiofs device with no host directory (NullFs).
    ///
    /// The guest sees an empty filesystem. Use [`FsOverlay`] to build
    /// virtual entries and [`set_overlay`](Self::set_overlay) to attach
    /// them.
    pub fn new_null(tag: &str) -> Result<Self, Error> {
        Self::new_inner(tag, None, false)
    }

    /// Set a pre-built [`FsOverlay`] on this device.
    ///
    /// The overlay entries are resolved (applied to the underlying
    /// virtiofs device) during [`attach`](AttachDevice::attach).
    pub fn set_overlay(&mut self, overlay: FsOverlay) {
        self.overlay = Some(overlay);
    }

    /// Set the size of the DAX (direct access) shared memory window.
    ///
    /// When set, the guest can memory-map files from the shared filesystem
    /// directly into its address space, avoiding data copies. If not set,
    /// no DAX window is allocated.
    pub fn set_dax_window_size(&mut self, bytes: u64) {
        self.shm_size = Some(bytes as usize);
    }
}

#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
impl<'a> FsDevice<'a> {
    fn new_inner(tag: &str, host_path: Option<String>, read_only: bool) -> Result<Self, Error> {
        let exit_code = Arc::new(AtomicI32::new(i32::MAX));
        let fs = devices::virtio::Fs::new(
            tag.to_string(),
            PermissionSemantics::LinuxComplete,
            host_path,
            exit_code.clone(),
            read_only,
            Vec::new(),
        )
        .map_err(|e| Error::Internal(format!("fs device: {e:?}")))?;

        Ok(Self {
            inner: Arc::new(Mutex::new(fs)),
            tag: tag.to_string(),
            shm_size: None,
            overlay: None,
            _lifetime: PhantomData,
        })
    }
}

#[cfg_attr(
    feature = "ffi",
    ffier::export(cfg = "not(any(feature = \"tee\", feature = \"aws-nitro\"))")
)]
#[cfg_attr(
    not(feature = "ffi"),
    cfg(not(any(feature = "tee", feature = "aws-nitro")))
)]
impl<'a> AttachDevice<'a> for FsDevice<'a> {
    #[cfg_attr(feature = "ffi", ffier(skip))]
    fn requirements(&self) -> DeviceRequirements {
        DeviceRequirements {
            shm_size: self.shm_size,
            ..Default::default()
        }
    }

    #[cfg_attr(feature = "ffi", ffier(skip))]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), Error> {
        {
            let mut fs = self.inner.lock().unwrap();
            // Wire exit code from VMM into the fs device
            fs.set_exit_code(ctx.exit_code().clone());
            // Resolve overlay entries
            if let Some(overlay) = self.overlay {
                for entry in overlay.into_entries() {
                    fs.add_virtual_entry(entry);
                }
            }
            // Set up SHM region if allocated
            #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
            if let Some(region) = ctx.resolved_shm_region() {
                fs.set_shm_region(region.into());
            }
        }

        ctx.register(&format!("virtiofs{}", ctx.device_index()), self.inner)
    }
}

/// A virtio multiport console device.
///
/// The console provides one or more serial ports to the guest, each
/// backed by a host file descriptor (typically a TTY). The guest kernel
/// sees these as `/dev/hvcN` devices.
///
/// Use [`ConsoleDevice::builder`] to configure ports, then
/// [`ConsoleBuilder::build`] to finalize.
pub struct ConsoleDevice<'a> {
    pub(crate) ports: Vec<PortDescription>,
    pub(crate) tty_fds: Vec<i32>,
    _lifetime: PhantomData<&'a ()>,
}

/// Builder for configuring a [`ConsoleDevice`].
///
/// Add one or more ports with [`add_tty_port`](ConsoleBuilder::add_tty_port),
/// then call [`build`](ConsoleBuilder::build) to create the device.
pub struct ConsoleBuilder<'a> {
    ports: Vec<PortDescription>,
    tty_fds: Vec<i32>,
    _lifetime: PhantomData<&'a ()>,
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl<'a> ConsoleDevice<'a> {
    /// Create a new console builder.
    pub fn builder() -> ConsoleBuilder<'a> {
        ConsoleBuilder {
            ports: Vec::new(),
            tty_fds: Vec::new(),
            _lifetime: PhantomData,
        }
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl<'a> ConsoleBuilder<'a> {
    /// Add a TTY-backed port to the console.
    ///
    /// If the fd refers to a real terminal, raw mode will be enabled on it
    /// when the VM starts, and restored on shutdown.
    ///
    /// # Arguments
    ///
    /// - `name`: the port name visible to the guest (e.g. `"tty0"`).
    /// - `tty_fd`: borrowed fd for the host TTY; duplicated internally, caller retains ownership.
    ///
    /// # Returns
    ///
    /// The zero-based port index.
    pub fn add_tty_port(&mut self, name: &str, tty_fd: BorrowedFd<'a>) -> Result<u32, Error> {
        let index = self.ports.len() as u32;
        self.add_tty_port_inner(name, tty_fd)?;
        Ok(index)
    }

    /// Add a port with separate input and output fds (no terminal properties).
    /// Pass `None` to disable that direction.
    pub fn add_inout_port(
        &mut self,
        name: &str,
        input_fd: Option<OwnedFd>,
        output_fd: Option<OwnedFd>,
    ) -> Result<u32, Error> {
        let index = self.ports.len() as u32;
        let input = input_fd
            .map(|fd| {
                port_io::input_to_raw_fd_dup(fd.as_raw_fd()).map_err(|e| {
                    log::error!("dup input fd: {e}");
                    Error::BadFd()
                })
            })
            .transpose()?;
        let output = output_fd
            .map(|fd| {
                port_io::output_to_raw_fd_dup(fd.as_raw_fd()).map_err(|e| {
                    log::error!("dup output fd: {e}");
                    Error::BadFd()
                })
            })
            .transpose()?;
        self.ports.push(PortDescription {
            name: name.to_string().into(),
            input,
            output,
            terminal: None,
        });
        Ok(index)
    }

    /// Build the console device. At least one port must have been added.
    pub fn build(self) -> Result<ConsoleDevice<'a>, Error> {
        if self.ports.is_empty() {
            return Err(Error::MissingConfig("no ports added to console".into()));
        }
        Ok(ConsoleDevice {
            ports: self.ports,
            tty_fds: self.tty_fds,
            _lifetime: PhantomData,
        })
    }

    /// Set up the default console: port 0 (hvc0) plus named redirect ports.
    ///
    /// Replicates the v1 `krun_add_virtio_console_default` behaviour:
    ///
    /// - If any fd is a terminal, port 0 becomes a full TTY console
    ///   (raw mode enabled), and that fd is NOT added as a redirect port.
    /// - Otherwise, port 0 gets log output and named redirect ports
    ///   (`krun-stdin`, `krun-stdout`, `krun-stderr`) are added.
    ///
    /// Pass `None` to skip a stream.
    pub fn add_default_console(
        &mut self,
        stdin: Option<OwnedFd>,
        stdout: Option<OwnedFd>,
        stderr: Option<OwnedFd>,
    ) -> Result<(), Error> {
        let stdin_is_tty = stdin.as_ref().is_some_and(|fd| fd.as_fd().is_terminal());
        let stdout_is_tty = stdout.as_ref().is_some_and(|fd| fd.as_fd().is_terminal());
        let stderr_is_tty = stderr.as_ref().is_some_and(|fd| fd.as_fd().is_terminal());

        let term_fd = if stdin_is_tty {
            stdin.as_ref()
        } else if stdout_is_tty {
            stdout.as_ref()
        } else if stderr_is_tty {
            stderr.as_ref()
        } else {
            None
        };

        let console_input = if stdin_is_tty {
            if let Some(ref fd) = stdin {
                let raw_fd = fd.as_raw_fd();
                if !self.tty_fds.contains(&raw_fd) {
                    self.tty_fds.push(raw_fd);
                }
                Some(port_io::input_to_raw_fd_dup(raw_fd).map_err(|e| {
                    log::error!("dup input fd: {e}");
                    Error::BadFd()
                })?)
            } else {
                None
            }
        } else {
            None
        };

        let console_output = if stdout_is_tty {
            if let Some(ref fd) = stdout {
                let raw_fd = fd.as_raw_fd();
                if !self.tty_fds.contains(&raw_fd) {
                    self.tty_fds.push(raw_fd);
                }
                Some(port_io::output_to_raw_fd_dup(raw_fd).map_err(|e| {
                    log::error!("dup output fd: {e}");
                    Error::BadFd()
                })?)
            } else {
                Some(port_io::output_to_log_as_err())
            }
        } else {
            Some(port_io::output_to_log_as_err())
        };

        let terminal: Option<Box<dyn devices::virtio::port_io::PortTerminalProperties>> =
            if let Some(tfd) = term_fd {
                let raw_fd = tfd.as_raw_fd();
                if !self.tty_fds.contains(&raw_fd) {
                    self.tty_fds.push(raw_fd);
                }
                Some(port_io::term_fd(raw_fd).map_err(|e| {
                    log::error!("term fd: {e}");
                    Error::BadFd()
                })?)
            } else {
                Some(port_io::term_fixed_size(0, 0))
            };

        // Port 0: default console (hvc0)
        self.ports.push(PortDescription {
            name: "".into(),
            input: console_input,
            output: console_output,
            terminal,
        });

        // Named redirect ports for non-terminal fds
        if stdin.is_some() && !stdin_is_tty {
            self.add_inout_port("krun-stdin", stdin, None)?;
        }
        if stdout.is_some() && !stdout_is_tty {
            self.add_inout_port("krun-stdout", None, stdout)?;
        }
        if stderr.is_some() && !stderr_is_tty {
            self.add_inout_port("krun-stderr", None, stderr)?;
        }

        Ok(())
    }
}

#[allow(dead_code)]
impl ConsoleBuilder<'_> {
    /// Add an output-only port (no input, no terminal).
    pub(crate) fn add_output_port(
        &mut self,
        name: &str,
        output: Box<dyn devices::virtio::port_io::PortOutput + Send>,
    ) -> u32 {
        let index = self.ports.len() as u32;
        self.ports.push(PortDescription {
            name: name.to_string().into(),
            input: None,
            output: Some(output),
            terminal: None,
        });
        index
    }

    /// Add an output-only console port with fake terminal properties.
    pub fn add_console_port(
        &mut self,
        name: &str,
        output: Box<dyn devices::virtio::port_io::PortOutput + Send>,
    ) -> u32 {
        let index = self.ports.len() as u32;
        self.ports.push(PortDescription {
            name: name.to_string().into(),
            input: None,
            output: Some(output),
            terminal: Some(port_io::term_fixed_size(80, 24)),
        });
        index
    }

    fn add_tty_port_inner(&mut self, name: &str, tty_fd: BorrowedFd<'_>) -> Result<(), Error> {
        let raw_fd = tty_fd.as_raw_fd();

        let input = Some(port_io::input_to_raw_fd_dup(raw_fd).map_err(|e| {
            log::error!("dup input fd: {e}");
            Error::BadFd()
        })?);
        let output = Some(port_io::output_to_raw_fd_dup(raw_fd).map_err(|e| {
            log::error!("dup output fd: {e}");
            Error::BadFd()
        })?);

        let is_term = tty_fd.is_terminal();
        let terminal: Option<Box<dyn devices::virtio::port_io::PortTerminalProperties>> = if is_term
        {
            Some(port_io::term_fd(raw_fd).map_err(|e| {
                log::error!("term fd: {e}");
                Error::BadFd()
            })?)
        } else {
            None
        };

        if is_term {
            self.tty_fds.push(raw_fd);
        }

        self.ports.push(PortDescription {
            name: name.to_string().into(),
            input,
            output,
            terminal,
        });
        Ok(())
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl<'a> AttachDevice<'a> for ConsoleDevice<'a> {
    #[cfg_attr(feature = "ffi", ffier(skip))]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), Error> {
        let tty_fds = self.tty_fds.clone();

        let console_dev = Arc::new(Mutex::new(
            devices::virtio::Console::new(self.ports)
                .map_err(|e| Error::Internal(format!("console: {e:?}")))?,
        ));

        ctx.push_exit_observer(console_dev.clone());
        ctx.subscribe_events(console_dev.clone())?;

        #[cfg(target_os = "linux")]
        ctx.register_sigwinch(console_dev.lock().unwrap().get_sigwinch_fd())?;

        ctx.register(&format!("hvc{}", ctx.device_index()), console_dev)?;

        for fd in &tty_fds {
            let borrowed = unsafe { BorrowedFd::borrow_raw(*fd) };
            ctx.setup_terminal_raw_mode(borrowed);
        }
        Ok(())
    }
}

/// A virtio balloon device for dynamic memory management.
#[cfg(not(feature = "tee"))]
pub struct BalloonDevice {
    pub(crate) inner: Arc<Mutex<devices::virtio::Balloon>>,
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "not(feature = \"tee\")"))]
#[cfg_attr(not(feature = "ffi"), cfg(not(feature = "tee")))]
impl BalloonDevice {
    pub fn new() -> Result<Self, Error> {
        let balloon = devices::virtio::Balloon::new()
            .map_err(|e| Error::Internal(format!("balloon: {e:?}")))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(balloon)),
        })
    }
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "not(feature = \"tee\")"))]
#[cfg_attr(not(feature = "ffi"), cfg(not(feature = "tee")))]
impl<'a> AttachDevice<'a> for BalloonDevice {
    #[cfg_attr(feature = "ffi", ffier(skip))]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), Error> {
        ctx.subscribe_events(self.inner.clone())?;
        ctx.register("balloon", self.inner)
    }
}

/// A virtio entropy source (RNG) device.
#[cfg(not(feature = "tee"))]
pub struct RngDevice {
    pub(crate) inner: Arc<Mutex<devices::virtio::Rng>>,
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "not(feature = \"tee\")"))]
#[cfg_attr(not(feature = "ffi"), cfg(not(feature = "tee")))]
impl RngDevice {
    pub fn new() -> Result<Self, Error> {
        let rng =
            devices::virtio::Rng::new().map_err(|e| Error::Internal(format!("rng: {e:?}")))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(rng)),
        })
    }
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "not(feature = \"tee\")"))]
#[cfg_attr(not(feature = "ffi"), cfg(not(feature = "tee")))]
impl<'a> AttachDevice<'a> for RngDevice {
    #[cfg_attr(feature = "ffi", ffier(skip))]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), Error> {
        ctx.subscribe_events(self.inner.clone())?;
        ctx.register("rng", self.inner)
    }
}

/// A virtio vsock device for host-guest communication.
pub struct VsockDevice {
    cid: u64,
    tsi_flags: devices::virtio::TsiFlags,
    host_port_map: HashMap<u16, u16>,
    unix_ipc_port_map: HashMap<u32, (PathBuf, bool)>,
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl VsockDevice {
    /// Create a new vsock device.
    ///
    /// `tsi_features` is a bitmask of TSI flags (0 to disable).
    pub fn new(cid: u64, tsi_features: u32) -> Result<Self, Error> {
        let tsi_flags =
            devices::virtio::TsiFlags::from_bits(tsi_features).ok_or(Error::InvalidParam())?;
        Ok(Self {
            cid,
            tsi_flags,
            host_port_map: HashMap::new(),
            unix_ipc_port_map: HashMap::new(),
        })
    }

    /// Add a host port forwarding: `"guest_port:host_port"`.
    // TODO: accept proper typed params once ffier supports something like
    // an array of by-value FFI-transparent structs (or tuples?)
    pub fn add_port_forward(&mut self, mapping: &str) -> Result<(), Error> {
        let (guest, host) = mapping.split_once(':').ok_or(Error::InvalidParam())?;
        let g = guest.parse::<u16>().map_err(|_| Error::InvalidParam())?;
        let h = host.parse::<u16>().map_err(|_| Error::InvalidParam())?;
        self.host_port_map.insert(g, h);
        Ok(())
    }

    /// Add a Unix socket port mapping.
    pub fn add_unix_port(&mut self, port: u32, path: &str, listen: bool) {
        self.unix_ipc_port_map
            .insert(port, (PathBuf::from(path), listen));
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl<'a> AttachDevice<'a> for VsockDevice {
    #[cfg_attr(feature = "ffi", ffier(skip))]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), Error> {
        let host_port_map = (!self.host_port_map.is_empty()).then_some(self.host_port_map);
        let unix_ipc_port_map =
            (!self.unix_ipc_port_map.is_empty()).then_some(self.unix_ipc_port_map);

        let vsock =
            devices::virtio::Vsock::new(self.cid, host_port_map, unix_ipc_port_map, self.tsi_flags)
                .map_err(|e| Error::Internal(format!("vsock: {e:?}")))?;

        let inner = Arc::new(Mutex::new(vsock));
        ctx.subscribe_events(inner.clone())?;

        let id = inner.lock().unwrap().id().to_string();
        ctx.register(&id, inner)?;

        if self
            .tsi_flags
            .contains(devices::virtio::TsiFlags::HIJACK_INET)
        {
            ctx.append_kernel_cmdline("tsi_hijack");
        }
        if self
            .tsi_flags
            .contains(devices::virtio::TsiFlags::HIJACK_UNIX)
        {
            ctx.append_kernel_cmdline("tsi_hijack_unix");
        }

        Ok(())
    }
}

/// A virtio block device backed by a disk image.
#[cfg(feature = "blk")]
pub struct BlockDevice {
    id: String,
    disk_image_path: String,
    format: DiskFormat,
    is_read_only: bool,
    direct_io: bool,
    sync_mode: SyncMode,
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "feature = \"blk\""))]
#[cfg_attr(not(feature = "ffi"), cfg(feature = "blk"))]
impl BlockDevice {
    /// Create a new block device.
    ///
    /// Defaults to read-write (`read_only = false`), cached I/O (`direct_io = false`),
    /// and [`SyncMode::Relaxed`].
    pub fn new(id: &str, disk_image_path: &str, format: DiskFormat) -> Result<Self, Error> {
        Ok(Self {
            id: id.to_string(),
            disk_image_path: disk_image_path.to_string(),
            format,
            is_read_only: false,
            direct_io: false,
            sync_mode: SyncMode::default(),
        })
    }

    /// Set whether the block device is read-only.
    pub fn set_read_only(&mut self, read_only: bool) {
        self.is_read_only = read_only;
    }

    /// Set whether to bypass the host caches.
    pub fn set_direct_io(&mut self, direct_io: bool) {
        self.direct_io = direct_io;
    }

    /// Set whether to enable VIRTIO_BLK_F_FLUSH.
    ///
    /// On macOS, an additional relaxed sync mode is available, which is enabled by default,
    /// and will not ask the drive to flush its buffered data.
    pub fn set_sync_mode(&mut self, sync_mode: SyncMode) {
        self.sync_mode = sync_mode;
    }
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "feature = \"blk\""))]
#[cfg_attr(not(feature = "ffi"), cfg(feature = "blk"))]
impl<'a> AttachDevice<'a> for BlockDevice {
    #[cfg_attr(feature = "ffi", ffier(skip))]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), Error> {
        use devices::virtio::CacheType;

        let block = devices::virtio::Block::new(
            self.id,
            None,
            CacheType::auto(&self.disk_image_path),
            self.disk_image_path,
            self.format,
            self.is_read_only,
            self.direct_io,
            self.sync_mode,
        )
        .map_err(|e| Error::Internal(format!("block: {e}")))?;

        let inner = Arc::new(Mutex::new(block));
        let id = inner.lock().unwrap().id().to_string();
        ctx.register(&id, inner)
    }
}

export_bitflags! {
    #[cfg(feature = "net")]
    bitflags::bitflags! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct NetFlags: u32 {
            const VFKIT = 1;
        }
    }
}

/// A virtio network device.
#[cfg(feature = "net")]
pub struct NetDevice {
    pub(crate) inner: Arc<Mutex<devices::virtio::Net>>,
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "feature = \"net\""))]
#[cfg_attr(not(feature = "ffi"), cfg(feature = "net"))]
impl NetDevice {
    /// Create a net device backed by a Unix datagram socket path.
    pub fn new_unixgram_path(
        id: &str,
        path: &str,
        mac: &[u8],
        features: u32,
        flags: NetFlags,
    ) -> Result<Self, Error> {
        use devices::virtio::net::device::VirtioNetBackend;
        Self::new_inner(
            id,
            VirtioNetBackend::UnixgramPath(PathBuf::from(path), flags.contains(NetFlags::VFKIT)),
            mac,
            features,
        )
    }

    /// Create a net device backed by a Unix datagram socket fd.
    ///
    /// Takes ownership of `fd`; the caller must not close it after this call.
    pub fn new_unixgram_fd(
        id: &str,
        fd: OwnedFd,
        mac: &[u8],
        features: u32,
        flags: NetFlags,
    ) -> Result<Self, Error> {
        use devices::virtio::net::device::VirtioNetBackend;
        let _ = flags;
        Self::new_inner(
            id,
            VirtioNetBackend::UnixgramFd(std::os::fd::IntoRawFd::into_raw_fd(fd)),
            mac,
            features,
        )
    }

    /// Create a net device backed by a Unix stream socket path.
    pub fn new_unixstream_path(
        id: &str,
        path: &str,
        mac: &[u8],
        features: u32,
        flags: NetFlags,
    ) -> Result<Self, Error> {
        use devices::virtio::net::device::VirtioNetBackend;
        let _ = flags;
        Self::new_inner(
            id,
            VirtioNetBackend::UnixstreamPath(PathBuf::from(path)),
            mac,
            features,
        )
    }

    /// Create a net device backed by a Unix stream socket fd.
    ///
    /// Takes ownership of `fd`; the caller must not close it after this call.
    pub fn new_unixstream_fd(
        id: &str,
        fd: OwnedFd,
        mac: &[u8],
        features: u32,
        flags: NetFlags,
    ) -> Result<Self, Error> {
        use devices::virtio::net::device::VirtioNetBackend;
        let _ = flags;
        Self::new_inner(
            id,
            VirtioNetBackend::UnixstreamFd(std::os::fd::IntoRawFd::into_raw_fd(fd)),
            mac,
            features,
        )
    }

    // FIXME: use #[cfg(target_os = "linux")] on the method once ffier supports
    // per-method cfg inside #[cfg_attr(feature = "ffi", ffier::export)] impl blocks.
    pub fn new_tap(id: &str, tap_name: &str, mac: &[u8], features: u32) -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        {
            use devices::virtio::net::device::VirtioNetBackend;
            Self::new_inner(
                id,
                VirtioNetBackend::Tap(tap_name.to_string()),
                mac,
                features,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (id, tap_name, mac, features);
            Err(Error::FeatureDisabled())
        }
    }
}

#[cfg(feature = "net")]
impl NetDevice {
    fn new_inner(
        id: &str,
        backend: devices::virtio::net::device::VirtioNetBackend,
        mac: &[u8],
        features: u32,
    ) -> Result<Self, Error> {
        let mac: [u8; 6] = mac.try_into().map_err(|_| Error::InvalidParam())?;
        let net = devices::virtio::Net::new(id.to_string(), backend, mac, features)
            .map_err(|e| Error::Internal(format!("net: {e:?}")))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(net)),
        })
    }
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "feature = \"net\""))]
#[cfg_attr(not(feature = "ffi"), cfg(feature = "net"))]
impl<'a> AttachDevice<'a> for NetDevice {
    #[cfg_attr(feature = "ffi", ffier(skip))]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), Error> {
        let id = self.inner.lock().unwrap().id().to_string();
        ctx.register(&id, self.inner)
    }
}

/// Builder for display configuration.
#[cfg(feature = "gpu")]
pub struct DisplayInfoBuilder {
    pub(crate) inner: DisplayInfo,
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "feature = \"gpu\""))]
#[cfg_attr(not(feature = "ffi"), cfg(feature = "gpu"))]
impl DisplayInfoBuilder {
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            inner: DisplayInfo::new(width, height),
        }
    }

    pub fn edid(mut self, edid: &[u8]) -> Self {
        self.inner.edid = DisplayInfoEdid::Provided(edid.to_vec().into_boxed_slice());
        self
    }

    pub fn dpi(mut self, dpi: u32) -> Self {
        match &mut self.inner.edid {
            DisplayInfoEdid::Generated(params) => {
                params.physical_size = PhysicalSize::Dpi(dpi);
            }
            DisplayInfoEdid::Provided(_) => {}
        }
        self
    }

    pub fn physical_size(mut self, width_mm: u16, height_mm: u16) -> Self {
        match &mut self.inner.edid {
            DisplayInfoEdid::Generated(params) => {
                params.physical_size = PhysicalSize::DimensionsMillimeters(width_mm, height_mm);
            }
            DisplayInfoEdid::Provided(_) => {}
        }
        self
    }

    pub fn refresh_rate(mut self, rate: u32) -> Self {
        match &mut self.inner.edid {
            DisplayInfoEdid::Generated(params) => {
                params.refresh_rate = rate;
            }
            DisplayInfoEdid::Provided(_) => {}
        }
        self
    }
}

/// Wraps the pre-ffier display backend and owns the list of displays.
#[cfg(feature = "gpu")]
#[allow(dead_code)]
pub struct DisplayBackend {
    pub(crate) inner: krun_display::DisplayBackend<'static>,
    pub(crate) displays: Vec<DisplayInfo>,
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "feature = \"gpu\""))]
#[cfg_attr(not(feature = "ffi"), cfg(feature = "gpu"))]
impl DisplayBackend {
    /// Create from the opaque pre-ffier `krun_display_backend` vtable pointer.
    ///
    /// # Safety
    ///
    /// `vtable` must point to a valid `krun_display_backend` struct of at least
    /// `vtable_size` bytes. The struct is copied — the caller retains ownership
    /// of the original.
    pub unsafe fn new(vtable: *const std::ffi::c_void, vtable_size: usize) -> Result<Self, Error> {
        if vtable_size < std::mem::size_of::<krun_display::DisplayBackend>() {
            return Err(Error::InvalidParam());
        }
        let backend: krun_display::DisplayBackend =
            unsafe { std::ptr::read_unaligned(vtable as *const krun_display::DisplayBackend) };
        if !backend.verify() {
            return Err(Error::InvalidParam());
        }
        Ok(Self {
            inner: backend,
            displays: Vec::new(),
        })
    }

    pub fn add_display(&mut self, display: DisplayInfoBuilder) {
        self.displays.push(display.inner);
    }
}

export_bitflags! {
    #[cfg(feature = "gpu")]
    bitflags::bitflags! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct VirglRendererFlags: u32 {
            const USE_EGL            = 0x001;
            const THREAD_SYNC        = 0x002;
            const VENUS              = 0x040;
            const USE_ASYNC_FENCE_CB = 0x100;
            const RENDER_SERVER      = 0x200;
        }
    }
}

/// A virtio GPU device with virgl 3D acceleration.
#[cfg(feature = "gpu")]
pub struct GpuDevice {
    virgl_flags: u32,
    backend: DisplayBackend,
    shm_size: usize,
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "feature = \"gpu\""))]
#[cfg_attr(not(feature = "ffi"), cfg(feature = "gpu"))]
impl GpuDevice {
    const DEFAULT_SHM_SIZE: usize = 1 << 33;

    pub fn new(virgl_flags: VirglRendererFlags, backend: DisplayBackend) -> Self {
        Self {
            virgl_flags: virgl_flags.bits(),
            backend,
            shm_size: Self::DEFAULT_SHM_SIZE,
        }
    }

    pub fn shm_size(mut self, size: usize) -> Self {
        self.shm_size = size;
        self
    }
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "feature = \"gpu\""))]
#[cfg_attr(not(feature = "ffi"), cfg(feature = "gpu"))]
impl<'a> AttachDevice<'a> for GpuDevice {
    #[cfg_attr(feature = "ffi", ffier(skip))]
    fn requirements(&self) -> DeviceRequirements {
        DeviceRequirements {
            gpu_shm: Some(self.shm_size),
            ..Default::default()
        }
    }

    #[cfg_attr(feature = "ffi", ffier(skip))]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), Error> {
        let displays: Box<[DisplayInfo]> = self.backend.displays.into_boxed_slice();

        let gpu = devices::virtio::Gpu::new(
            self.virgl_flags,
            displays,
            self.backend.inner,
            #[cfg(target_os = "macos")]
            ctx.map_sender().expect("macOS requires map_sender for GPU"),
        )
        .map_err(|e| Error::Internal(format!("gpu: {e:?}")))?;

        let inner = Arc::new(Mutex::new(gpu));

        if let Some(region) = ctx.resolved_gpu_shm_region() {
            inner.lock().unwrap().set_shm_region(region.into());
        }

        let id = inner.lock().unwrap().id().to_string();
        ctx.register(&id, inner)
    }
}

/// A vhost-user device that connects to an external backend via a Unix socket.
///
/// The backend process handles device I/O on behalf of the guest. Because the
/// backend must access guest memory directly, this device requires
/// process-shareable (file-backed) guest memory — the requirement is declared
/// via [`AttachDevice::requirements`] and flows into
/// `create_guest_memory`'s `use_vhost_user` argument automatically.
#[cfg(all(feature = "vhost-user", target_os = "linux"))]
pub struct VhostUserDevice {
    device_type: u32,
    socket_path: String,
    name: String,
    num_queues: u16,
    queue_sizes: Vec<u16>,
}

#[cfg_attr(
    feature = "ffi",
    ffier::export(cfg = "all(feature = \"vhost-user\", target_os = \"linux\")")
)]
#[cfg_attr(
    not(feature = "ffi"),
    cfg(all(feature = "vhost-user", target_os = "linux"))
)]
impl VhostUserDevice {
    /// Create a new vhost-user device.
    ///
    /// # Arguments
    ///
    /// - `device_type`: virtio device type ID (e.g. 4 for RNG, 32 for Sound).
    /// - `socket_path`: path to the vhost-user Unix domain socket.
    /// - `name`: human-readable name for logging. If empty, defaults to
    ///   `"vhost-user-{device_type}"`.
    /// - `num_queues`: number of queues (0 = query backend via MQ protocol).
    /// - `queue_sizes`: size for each queue (empty slice = use default of 256).
    pub fn new(
        device_type: u32,
        socket_path: &str,
        name: &str,
        num_queues: u16,
        queue_sizes: &[u16],
    ) -> Result<Self, Error> {
        let name = if name.is_empty() {
            format!("vhost-user-{device_type}")
        } else {
            name.to_string()
        };
        Ok(Self {
            device_type,
            socket_path: socket_path.to_string(),
            name,
            num_queues,
            queue_sizes: queue_sizes.to_vec(),
        })
    }
}

#[cfg_attr(
    feature = "ffi",
    ffier::export(cfg = "all(feature = \"vhost-user\", target_os = \"linux\")")
)]
#[cfg_attr(
    not(feature = "ffi"),
    cfg(all(feature = "vhost-user", target_os = "linux"))
)]
impl<'a> AttachDevice<'a> for VhostUserDevice {
    #[cfg_attr(feature = "ffi", ffier(skip))]
    fn requirements(&self) -> DeviceRequirements {
        DeviceRequirements {
            process_shareable_memory: true,
            ..Default::default()
        }
    }

    #[cfg_attr(feature = "ffi", ffier(skip))]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), Error> {
        let device = devices::virtio::VhostUserDevice::new(
            &self.socket_path,
            self.device_type,
            self.name.clone(),
            self.num_queues,
            &self.queue_sizes,
            None,
        )
        .map_err(|e| Error::Internal(format!("vhost-user: {e}")))?;
        let inner = Arc::new(Mutex::new(device));
        ctx.subscribe_events(inner.clone())?;
        ctx.register(&self.name, inner)
    }
}

/// A virtio input device forwarding host input events to the guest.
#[cfg(feature = "input")]
pub struct InputDevice {
    config_backend: krun_input::InputConfigBackend<'static>,
    events_backend: krun_input::InputEventProviderBackend<'static>,
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "feature = \"input\""))]
#[cfg_attr(not(feature = "ffi"), cfg(feature = "input"))]
impl InputDevice {
    /// Create from opaque config/events backend vtables.
    ///
    /// # Safety
    ///
    /// `config_backend` must point to a valid `InputConfigBackend` struct of at
    /// least `config_backend_size` bytes, and `event_provider_backend` must
    /// point to a valid `InputEventProviderBackend` struct of at least
    /// `event_provider_backend_size` bytes. Both structs are copied — the
    /// caller retains ownership of the originals.
    pub unsafe fn new(
        config_backend: *const std::ffi::c_void,
        config_backend_size: usize,
        event_provider_backend: *const std::ffi::c_void,
        event_provider_backend_size: usize,
    ) -> Result<Self, Error> {
        if config_backend_size < std::mem::size_of::<krun_input::InputConfigBackend<'_>>() {
            return Err(Error::InvalidParam());
        }
        if event_provider_backend_size
            < std::mem::size_of::<krun_input::InputEventProviderBackend<'_>>()
        {
            return Err(Error::InvalidParam());
        }
        let config_backend: krun_input::InputConfigBackend<'static> =
            unsafe { std::ptr::read_unaligned(config_backend as *const _) };
        if !config_backend.verify() {
            return Err(Error::InvalidParam());
        }
        let events_backend: krun_input::InputEventProviderBackend<'static> =
            unsafe { std::ptr::read_unaligned(event_provider_backend as *const _) };
        if !events_backend.verify() {
            return Err(Error::InvalidParam());
        }
        Ok(Self {
            config_backend,
            events_backend,
        })
    }

    /// Create a passthrough input device from an evdev fd.
    ///
    /// The fd must refer to a Linux `/dev/input/eventN` device. It is
    /// duplicated internally; the caller retains ownership.
    #[cfg(target_os = "linux")]
    pub fn new_from_fd(input_fd: BorrowedFd<'_>) -> Result<Self, Error> {
        use devices::virtio::input::passthrough::PassthroughInputBackend;
        use krun_input::{IntoInputConfig, IntoInputEvents};

        let borrowed: BorrowedFd<'static> = unsafe { BorrowedFd::borrow_raw(input_fd.as_raw_fd()) };
        let leaked: &'static BorrowedFd<'static> = Box::leak(Box::new(borrowed));

        let config_backend = PassthroughInputBackend::into_input_config(Some(leaked));
        let events_backend = PassthroughInputBackend::into_input_events(Some(leaked));

        Ok(Self {
            config_backend,
            events_backend,
        })
    }
}

#[cfg_attr(feature = "ffi", ffier::export(cfg = "feature = \"input\""))]
#[cfg_attr(not(feature = "ffi"), cfg(feature = "input"))]
impl<'a> AttachDevice<'a> for InputDevice {
    #[cfg_attr(feature = "ffi", ffier(skip))]
    fn attach(self: Box<Self>, ctx: &mut AttachContext) -> Result<(), Error> {
        use devices::virtio::input::Input;
        let input = Input::new(self.config_backend, self.events_backend)
            .map_err(|e| Error::Internal(format!("input: {e:?}")))?;
        let inner = Arc::new(Mutex::new(input));
        let id = inner.lock().unwrap().id().to_string();
        ctx.register(&id, inner)
    }
}

/// Walk parent directory components in a virtual entry tree, returning the
/// children vec of the deepest parent.
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
fn resolve_parent_dirs<'a>(
    entries: &'a mut Vec<VirtualDirEntry>,
    parents: &[&str],
) -> &'a mut Vec<VirtualDirEntry> {
    let mut current = entries;
    for component in parents {
        let dir = current
            .iter_mut()
            .find(|e| e.name.as_c_str().to_bytes() == component.as_bytes())
            .unwrap_or_else(|| panic!("overlay parent directory {component:?} not found"));
        match &mut dir.entry.content {
            VirtualEntryContent::Dir { children } => current = children,
            _ => panic!("overlay path component {component:?} is not a directory"),
        }
    }
    current
}
