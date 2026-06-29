// Virtual inode overlay for virtiofs.
//
// `AugmentFs<T>` wraps an inner `FileSystem` implementation and intercepts
// FUSE operations for virtual inodes — synthetic read-only files that exist
// only in memory. All other operations are delegated to the inner filesystem.
//
// Virtual inodes are injected into the root directory (parent = ROOT_ID) and
// are currently only accessible via lookup (they do not appear in readdir).
//
// One-shot files can only be looked up once — the name is removed from the
// directory on first lookup so subsequent lookups return ENOENT.

#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

use super::filesystem::{
    Context, DirEntry, Entry, Extensions, FileSystem, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use super::fuse;
use super::inode_alloc::InodeAllocator;
use super::virtual_entry::{VIRTUAL_BLKSIZE, VirtualDirEntry, VirtualEntry, VirtualEntryContent};
#[cfg(target_os = "windows")]
use super::windows::fs_utils;
use crate::virtio::bindings;
use crate::virtio::linux_errno;

type Inode = u64;
type Handle = u64;

/// Sentinel handle returned for all virtual file opens. This works because
/// virtual file operations dispatch on inode, not handle — there is no
/// per-open state. If per-fd state is ever needed (e.g. writable virtual
/// files), this must be replaced with a real handle allocator.
const VIRTUAL_HANDLE: Handle = 0;

/// Persistent virtual entries never change.
const VIRTUAL_TIMEOUT: Duration = Duration::MAX;

/// Overlay that injects virtual inodes into an inner `FileSystem`.
pub struct AugmentFs<T> {
    inner: T,
    /// Maps (parent_inode, name) → child inode number. One-shot entries
    /// are removed on first lookup so the file can only be opened once.
    name_to_inode: RwLock<HashMap<(Inode, CString), Inode>>,
    /// Maps virtual inode number → (mode, inode data). One-shot entries are
    /// removed from this map on release.
    inodes: RwLock<HashMap<Inode, VirtualEntry>>,
}

impl<T: FileSystem<Inode = Inode, Handle = Handle>> AugmentFs<T> {
    /// Create a new overlay.
    ///
    /// `entries` are registered as virtual inodes in the root directory.
    /// Inode numbers are obtained from `inode_alloc`, the same allocator
    /// used by the inner filesystem.
    pub fn new(inner: T, inode_alloc: &InodeAllocator, entries: Vec<VirtualDirEntry>) -> Self {
        let mut name_to_inode = HashMap::new();
        let mut inodes = HashMap::new();

        Self::register_entries(
            fuse::ROOT_ID,
            entries,
            inode_alloc,
            &mut name_to_inode,
            &mut inodes,
        );

        Self {
            inner,
            name_to_inode: RwLock::new(name_to_inode),
            inodes: RwLock::new(inodes),
        }
    }

    fn register_entries(
        parent: Inode,
        entries: Vec<VirtualDirEntry>,
        inode_alloc: &InodeAllocator,
        name_to_inode: &mut HashMap<(Inode, CString), Inode>,
        inodes: &mut HashMap<Inode, VirtualEntry>,
    ) {
        for entry in entries {
            let ino = inode_alloc.next();
            name_to_inode.insert((parent, entry.name), ino);

            // Recurse into directory children before moving the node.
            if let VirtualEntryContent::Dir { children } = entry.entry.content {
                Self::register_entries(ino, children, inode_alloc, name_to_inode, inodes);
                inodes.insert(
                    ino,
                    VirtualEntry {
                        mode: entry.entry.mode,
                        one_shot: entry.entry.one_shot,
                        content: VirtualEntryContent::Dir {
                            children: Vec::new(),
                        },
                    },
                );
            } else {
                inodes.insert(ino, entry.entry);
            }
        }
    }

    fn is_virtual(&self, inode: Inode) -> bool {
        self.inodes.read().unwrap().contains_key(&inode)
    }

    fn virtual_stat(ino: Inode, vnode: &VirtualEntry) -> (bindings::stat64, Duration) {
        let mut st: bindings::stat64 = unsafe { mem::zeroed() };
        st.st_ino = ino;
        st.st_mode = vnode.st_mode() as _;
        st.st_blksize = VIRTUAL_BLKSIZE as _;
        let timeout = if vnode.one_shot {
            Duration::ZERO
        } else {
            VIRTUAL_TIMEOUT
        };
        match &vnode.content {
            VirtualEntryContent::File { data, .. } => {
                st.st_size = data.len() as i64;
                st.st_nlink = 1;
                st.st_blocks = ((data.len() as i64) + 511) / 512;
            }
            VirtualEntryContent::Dir { .. } => {
                st.st_nlink = 2;
            }
        }
        (st, timeout)
    }
}

impl<T: FileSystem<Inode = Inode, Handle = Handle>> FileSystem for AugmentFs<T> {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        self.inner.init(capable)
    }

    fn destroy(&self) {
        self.inner.destroy()
    }

    fn lookup(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let key = (parent, CString::from(name));
        let inode = self.name_to_inode.read().unwrap().get(&key).copied();
        if let Some(inode) = inode {
            let inodes = self.inodes.read().unwrap();
            if let Some(vnode) = inodes.get(&inode) {
                let one_shot = vnode.one_shot;
                let (st, timeout) = Self::virtual_stat(inode, vnode);

                if one_shot {
                    drop(inodes);
                    self.name_to_inode.write().unwrap().remove(&key);
                }

                return Ok(Entry {
                    inode,
                    generation: 0,
                    attr: st,
                    attr_flags: 0,
                    attr_timeout: timeout,
                    entry_timeout: timeout,
                });
            }
        }
        self.inner.lookup(ctx, parent, name)
    }

    fn forget(&self, ctx: Context, inode: Inode, count: u64) {
        if !self.is_virtual(inode) {
            self.inner.forget(ctx, inode, count)
        }
    }

    fn batch_forget(&self, ctx: Context, mut requests: Vec<(Inode, u64)>) {
        requests.retain(|(ino, _)| !self.is_virtual(*ino));
        self.inner.batch_forget(ctx, requests);
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Option<Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        {
            let inodes = self.inodes.read().unwrap();
            if let Some(vnode) = inodes.get(&inode) {
                return Ok(Self::virtual_stat(inode, vnode));
            }
        }
        self.inner.getattr(ctx, inode, handle)
    }

    fn setattr(
        &self,
        ctx: Context,
        inode: Inode,
        attr: bindings::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        if self.is_virtual(inode) {
            return Err(linux_errno::eperm());
        }
        self.inner.setattr(ctx, inode, attr, handle, valid)
    }

    fn readlink(&self, ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        if self.is_virtual(inode) {
            return Err(linux_errno::einval());
        }
        self.inner.readlink(ctx, inode)
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.inner.symlink(ctx, linkname, parent, name, extensions)
    }

    fn mknod(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.inner
            .mknod(ctx, inode, name, mode, rdev, umask, extensions)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let key = (parent, CString::from(name));
        if self.name_to_inode.read().unwrap().contains_key(&key) {
            return Err(linux_errno::eexist());
        }
        self.inner.mkdir(ctx, parent, name, mode, umask, extensions)
    }

    fn unlink(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.inner.unlink(ctx, parent, name)
    }

    fn rmdir(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.inner.rmdir(ctx, parent, name)
    }

    fn rename(
        &self,
        ctx: Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        self.inner
            .rename(ctx, olddir, oldname, newdir, newname, flags)
    }

    fn link(
        &self,
        ctx: Context,
        inode: Inode,
        newparent: Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        if self.is_virtual(inode) {
            return Err(linux_errno::eperm());
        }
        self.inner.link(ctx, inode, newparent, newname)
    }

    fn open(
        &self,
        ctx: Context,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        {
            let inodes = self.inodes.read().unwrap();
            if let Some(vnode) = inodes.get(&inode) {
                if vnode.is_dir() {
                    return Err(linux_errno::eisdir());
                }
                #[cfg(not(target_os = "windows"))]
                let acc_mode = libc::O_ACCMODE;
                #[cfg(target_os = "windows")]
                let acc_mode = fs_utils::O_ACCMODE;
                if (flags as i32 & acc_mode) != libc::O_RDONLY {
                    return Err(linux_errno::eacces());
                }
                return Ok((Some(VIRTUAL_HANDLE), OpenOptions::empty()));
            }
        }
        self.inner.open(ctx, inode, kill_priv, flags)
    }

    fn create(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        kill_priv: bool,
        flags: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        self.inner
            .create(ctx, parent, name, mode, kill_priv, flags, umask, extensions)
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        mut w: W,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        {
            let inodes = self.inodes.read().unwrap();
            if let Some(vnode) = inodes.get(&inode) {
                let data = vnode.data().ok_or_else(linux_errno::eisdir)?;
                let off: usize = offset.try_into().map_err(|_| linux_errno::einval())?;
                if off >= data.len() {
                    return Ok(0);
                }
                let remaining = data.len() - off;
                let len = remaining.min(size as usize);
                return w.write(&data[off..(off + len)]);
            }
        }
        self.inner
            .read(ctx, inode, handle, w, size, offset, lock_owner, flags)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        r: R,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<usize> {
        if self.is_virtual(inode) {
            return Err(linux_errno::eperm());
        }
        self.inner.write(
            ctx,
            inode,
            handle,
            r,
            size,
            offset,
            lock_owner,
            delayed_write,
            kill_priv,
            flags,
        )
    }

    fn flush(&self, ctx: Context, inode: Inode, handle: Handle, lock_owner: u64) -> io::Result<()> {
        if self.is_virtual(inode) {
            return Ok(());
        }
        self.inner.flush(ctx, inode, handle, lock_owner)
    }

    fn fsync(&self, ctx: Context, inode: Inode, datasync: bool, handle: Handle) -> io::Result<()> {
        if self.is_virtual(inode) {
            return Ok(());
        }
        self.inner.fsync(ctx, inode, datasync, handle)
    }

    fn fallocate(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        if self.is_virtual(inode) {
            return Err(linux_errno::eperm());
        }
        self.inner
            .fallocate(ctx, inode, handle, mode, offset, length)
    }

    fn release(
        &self,
        ctx: Context,
        inode: Inode,
        flags: u32,
        handle: Handle,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        {
            let mut inodes = self.inodes.write().unwrap();
            if let Some(vnode) = inodes.get(&inode) {
                if vnode.one_shot {
                    inodes.remove(&inode);
                }
                return Ok(());
            }
        }
        self.inner
            .release(ctx, inode, flags, handle, flush, flock_release, lock_owner)
    }

    fn statfs(&self, ctx: Context, inode: Inode) -> io::Result<bindings::statvfs64> {
        self.inner.statfs(ctx, inode)
    }

    fn getxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        if self.is_virtual(inode) {
            return Err(linux_errno::enodata());
        }
        self.inner.getxattr(ctx, inode, name, size)
    }

    fn listxattr(&self, ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        if self.is_virtual(inode) {
            if size == 0 {
                return Ok(ListxattrReply::Count(0));
            }
            return Ok(ListxattrReply::Names(Vec::new()));
        }
        self.inner.listxattr(ctx, inode, size)
    }

    fn setxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        if self.is_virtual(inode) {
            return Err(linux_errno::eperm());
        }
        self.inner.setxattr(ctx, inode, name, value, flags)
    }

    fn removexattr(&self, ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        if self.is_virtual(inode) {
            return Err(linux_errno::eperm());
        }
        self.inner.removexattr(ctx, inode, name)
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.inner.opendir(ctx, inode, flags)
    }

    fn readdir<F>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        self.inner
            .readdir(ctx, inode, handle, size, offset, add_entry)
    }

    fn readdirplus<F>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        self.inner
            .readdirplus(ctx, inode, handle, size, offset, add_entry)
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.inner.fsyncdir(ctx, inode, datasync, handle)
    }

    fn releasedir(&self, ctx: Context, inode: Inode, flags: u32, handle: Handle) -> io::Result<()> {
        self.inner.releasedir(ctx, inode, flags, handle)
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        if self.is_virtual(inode) {
            #[cfg(not(target_os = "windows"))]
            let w_ok = libc::W_OK;
            #[cfg(target_os = "windows")]
            let w_ok = fs_utils::W_OK;
            if mask & (w_ok as u32) != 0 {
                return Err(linux_errno::eacces());
            }
            return Ok(());
        }
        self.inner.access(ctx, inode, mask)
    }

    fn lseek(
        &self,
        ctx: Context,
        inode: Inode,
        _handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        {
            let inodes = self.inodes.read().unwrap();
            if let Some(vnode) = inodes.get(&inode) {
                let size = vnode.data().ok_or_else(linux_errno::eisdir)?.len() as u64;
                // FUSE lseek is only called for SEEK_DATA/SEEK_HOLE.
                #[cfg(not(target_os = "windows"))]
                let (seek_data, seek_hole) = (libc::SEEK_DATA, libc::SEEK_HOLE);
                #[cfg(target_os = "windows")]
                let (seek_data, seek_hole) = (fs_utils::SEEK_DATA, fs_utils::SEEK_HOLE);
                return match whence as i32 {
                    w if w == seek_data => {
                        if offset < size {
                            Ok(offset)
                        } else {
                            Err(linux_errno::enxio())
                        }
                    }
                    w if w == seek_hole => {
                        if offset < size {
                            Ok(size)
                        } else {
                            Err(linux_errno::enxio())
                        }
                    }
                    _ => Err(linux_errno::einval()),
                };
            }
        }
        self.inner.lseek(ctx, inode, _handle, offset, whence)
    }

    fn copyfilerange(
        &self,
        ctx: Context,
        inode_in: Inode,
        handle_in: Handle,
        offset_in: u64,
        inode_out: Inode,
        handle_out: Handle,
        offset_out: u64,
        len: u64,
        flags: u64,
    ) -> io::Result<usize> {
        // Virtual inodes don't have real file descriptors, so copy_file_range
        // cannot work. Return EXDEV to tell the kernel to fall back to
        // read+write.
        if self.is_virtual(inode_in) || self.is_virtual(inode_out) {
            return Err(linux_errno::exdev());
        }
        self.inner.copyfilerange(
            ctx, inode_in, handle_in, offset_in, inode_out, handle_out, offset_out, len, flags,
        )
    }

    fn setupmapping(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        host_shm_base: u64,
        shm_size: u64,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        {
            let inodes = self.inodes.read().unwrap();
            if let Some(vnode) = inodes.get(&inode) {
                let data = vnode.data().ok_or_else(linux_errno::eisdir)?;
                #[cfg(target_os = "linux")]
                {
                    if (moffset + len) > shm_size {
                        return Err(linux_errno::einval());
                    }

                    let addr = host_shm_base + moffset;
                    let ret = unsafe {
                        libc::mmap(
                            addr as *mut libc::c_void,
                            len as usize,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                            -1,
                            0,
                        )
                    };
                    if std::ptr::eq(ret, libc::MAP_FAILED) {
                        return Err(io::Error::last_os_error());
                    }

                    let foff = foffset as usize;
                    if foff < data.len() {
                        let available = data.len() - foff;
                        let to_copy = (len as usize).min(available);
                        unsafe {
                            libc::memcpy(
                                addr as *mut libc::c_void,
                                data.as_ptr().add(foff) as *const _,
                                to_copy,
                            )
                        };
                    }

                    return Ok(());
                }

                // TODO: implement DAX for virtual files on macOS.
                // Needs a shared memory region manager (see setupmapping
                // in macos/passthrough.rs for the real-file DAX path).
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = data;
                    return Err(linux_errno::enosys());
                }
            }
        }
        self.inner.setupmapping(
            ctx,
            inode,
            handle,
            foffset,
            len,
            flags,
            moffset,
            host_shm_base,
            shm_size,
            #[cfg(target_os = "macos")]
            map_sender,
        )
    }

    fn removemapping(
        &self,
        ctx: Context,
        requests: Vec<fuse::RemovemappingOne>,
        host_shm_base: u64,
        shm_size: u64,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        self.inner.removemapping(
            ctx,
            requests,
            host_shm_base,
            shm_size,
            #[cfg(target_os = "macos")]
            map_sender,
        )
    }

    fn ioctl(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        flags: u32,
        cmd: u32,
        arg: u64,
        in_size: u32,
        out_size: u32,
        exit_code: &Arc<AtomicI32>,
    ) -> io::Result<Vec<u8>> {
        // We can't use nix::request_code_none here since it's system-dependent
        // and we need the value from Linux.
        const VIRTIO_IOC_EXIT_CODE_REQ: u32 = 0x7602;

        match cmd {
            VIRTIO_IOC_EXIT_CODE_REQ => {
                exit_code.store(arg as i32, Ordering::SeqCst);
                Ok(Vec::new())
            }
            _ => self.inner.ioctl(
                ctx, inode, handle, flags, cmd, arg, in_size, out_size, exit_code,
            ),
        }
    }
}
