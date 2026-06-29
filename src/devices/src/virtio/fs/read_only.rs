// Read-only wrapper for PassthroughFs.
//
// Delegates all read-only FUSE operations to the inner PassthroughFs and
// rejects all mutating operations with EROFS (read-only filesystem).
//
// IMPORTANT: When adding new methods to the FileSystem trait, review this
// wrapper to ensure mutating operations are explicitly blocked with EROFS.
// Unoverridden methods fall back to the trait defaults (which return ENOSYS),
// so the wrapper fails closed -- but new methods should still be explicitly
// handled here for correct error semantics.
#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
use std::ffi::CStr;
use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::time::Duration;

#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

use super::filesystem::{
    Context, DirEntry, Entry, Extensions, FileSystem, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use super::fuse;
use super::inode_alloc::InodeAllocator;
use super::passthrough::{self, PassthroughFs};
#[cfg(target_os = "windows")]
use super::windows::fs_utils;
use crate::virtio::bindings;
use crate::virtio::linux_errno;

type Inode = u64;
type Handle = u64;

fn read_only_open_flags(flags: u32) -> io::Result<u32> {
    let f = flags as i32;
    #[cfg(not(target_os = "windows"))]
    let o_accmode = libc::O_ACCMODE;
    #[cfg(target_os = "windows")]
    let o_accmode = fs_utils::O_ACCMODE;
    if f & o_accmode != libc::O_RDONLY {
        return Err(linux_errno::erofs());
    }
    if f & libc::O_TRUNC != 0 {
        return Err(linux_errno::erofs());
    }
    #[cfg(target_os = "linux")]
    if f & libc::O_TMPFILE != 0 {
        return Err(linux_errno::erofs());
    }

    Ok((flags & !(o_accmode as u32)) | (libc::O_RDONLY as u32))
}

pub struct PassthroughFsRo {
    inner: PassthroughFs,
}

impl PassthroughFsRo {
    pub fn new(cfg: passthrough::Config, inode_alloc: Arc<InodeAllocator>) -> io::Result<Self> {
        Ok(Self {
            inner: PassthroughFs::new(cfg, inode_alloc)?,
        })
    }
}

impl FileSystem for PassthroughFsRo {
    type Inode = Inode;
    type Handle = Handle;

    // --- Delegated read-only operations ---

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        let opts = self.inner.init(capable)?;
        // Strip WRITEBACK_CACHE to prevent the guest kernel from buffering writes.
        Ok(opts & !FsOptions::WRITEBACK_CACHE)
    }

    fn destroy(&self) {
        self.inner.destroy()
    }

    fn lookup(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        self.inner.lookup(ctx, parent, name)
    }

    fn forget(&self, ctx: Context, inode: Inode, count: u64) {
        self.inner.forget(ctx, inode, count)
    }

    fn batch_forget(&self, ctx: Context, requests: Vec<(Inode, u64)>) {
        self.inner.batch_forget(ctx, requests)
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Option<Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        self.inner.getattr(ctx, inode, handle)
    }

    fn readlink(&self, ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        self.inner.readlink(ctx, inode)
    }

    fn open(
        &self,
        ctx: Context,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        let ro_flags = read_only_open_flags(flags)?;
        self.inner.open(ctx, inode, kill_priv, ro_flags)
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        w: W,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        self.inner
            .read(ctx, inode, handle, w, size, offset, lock_owner, flags)
    }

    fn flush(&self, ctx: Context, inode: Inode, handle: Handle, lock_owner: u64) -> io::Result<()> {
        self.inner.flush(ctx, inode, handle, lock_owner)
    }

    fn fsync(&self, ctx: Context, inode: Inode, datasync: bool, handle: Handle) -> io::Result<()> {
        self.inner.fsync(ctx, inode, datasync, handle)
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
        self.inner
            .release(ctx, inode, flags, handle, flush, flock_release, lock_owner)
    }

    fn statfs(&self, ctx: Context, inode: Inode) -> io::Result<bindings::statvfs64> {
        let mut st = self.inner.statfs(ctx, inode)?;
        #[cfg(not(target_os = "windows"))]
        let st_rdonly = libc::ST_RDONLY;
        #[cfg(target_os = "windows")]
        let st_rdonly = fs_utils::ST_RDONLY;
        st.f_flag |= st_rdonly;
        Ok(st)
    }

    fn getxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        self.inner.getxattr(ctx, inode, name, size)
    }

    fn listxattr(&self, ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        self.inner.listxattr(ctx, inode, size)
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        let f = flags as i32;
        #[cfg(not(target_os = "windows"))]
        let o_accmode = libc::O_ACCMODE;
        #[cfg(target_os = "windows")]
        let o_accmode = fs_utils::O_ACCMODE;
        if f & o_accmode != libc::O_RDONLY {
            return Err(linux_errno::erofs());
        }
        // Force O_RDONLY on the underlying call.
        let ro_flags = (flags & !(o_accmode as u32)) | (libc::O_RDONLY as u32);
        self.inner.opendir(ctx, inode, ro_flags)
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
        #[cfg(not(target_os = "windows"))]
        let w_ok = libc::W_OK;
        #[cfg(target_os = "windows")]
        let w_ok = fs_utils::W_OK;
        if mask & (w_ok as u32) != 0 {
            return Err(linux_errno::erofs());
        }
        self.inner.access(ctx, inode, mask)
    }

    fn lseek(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        self.inner.lseek(ctx, inode, handle, offset, whence)
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
        // Reject writable mappings.
        if (flags & fuse::SetupmappingFlags::WRITE.bits()) != 0 {
            return Err(linux_errno::erofs());
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
        self.inner.ioctl(
            ctx, inode, handle, flags, cmd, arg, in_size, out_size, exit_code,
        )
    }

    // --- Write operations rejected with EROFS ---

    fn setattr(
        &self,
        _ctx: Context,
        _inode: Inode,
        _attr: bindings::stat64,
        _handle: Option<Handle>,
        _valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        Err(linux_errno::erofs())
    }

    fn symlink(
        &self,
        _ctx: Context,
        _linkname: &CStr,
        _parent: Inode,
        _name: &CStr,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        Err(linux_errno::erofs())
    }

    fn mknod(
        &self,
        _ctx: Context,
        _inode: Inode,
        _name: &CStr,
        _mode: u32,
        _rdev: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        Err(linux_errno::erofs())
    }

    fn mkdir(
        &self,
        _ctx: Context,
        _parent: Inode,
        _name: &CStr,
        _mode: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        Err(linux_errno::erofs())
    }

    fn unlink(&self, _ctx: Context, _parent: Inode, _name: &CStr) -> io::Result<()> {
        Err(linux_errno::erofs())
    }

    fn rmdir(&self, _ctx: Context, _parent: Inode, _name: &CStr) -> io::Result<()> {
        Err(linux_errno::erofs())
    }

    fn rename(
        &self,
        _ctx: Context,
        _olddir: Inode,
        _oldname: &CStr,
        _newdir: Inode,
        _newname: &CStr,
        _flags: u32,
    ) -> io::Result<()> {
        Err(linux_errno::erofs())
    }

    fn link(
        &self,
        _ctx: Context,
        _inode: Inode,
        _newparent: Inode,
        _newname: &CStr,
    ) -> io::Result<Entry> {
        Err(linux_errno::erofs())
    }

    fn create(
        &self,
        _ctx: Context,
        _parent: Inode,
        _name: &CStr,
        _mode: u32,
        _kill_priv: bool,
        _flags: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        Err(linux_errno::erofs())
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        _inode: Inode,
        _handle: Handle,
        _r: R,
        _size: u32,
        _offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        Err(linux_errno::erofs())
    }

    fn fallocate(
        &self,
        _ctx: Context,
        _inode: Inode,
        _handle: Handle,
        _mode: u32,
        _offset: u64,
        _length: u64,
    ) -> io::Result<()> {
        Err(linux_errno::erofs())
    }

    fn setxattr(
        &self,
        _ctx: Context,
        _inode: Inode,
        _name: &CStr,
        _value: &[u8],
        _flags: u32,
    ) -> io::Result<()> {
        Err(linux_errno::erofs())
    }

    fn removexattr(&self, _ctx: Context, _inode: Inode, _name: &CStr) -> io::Result<()> {
        Err(linux_errno::erofs())
    }

    fn copyfilerange(
        &self,
        _ctx: Context,
        _inode_in: Inode,
        _handle_in: Handle,
        _offset_in: u64,
        _inode_out: Inode,
        _handle_out: Handle,
        _offset_out: u64,
        _len: u64,
        _flags: u64,
    ) -> io::Result<usize> {
        Err(linux_errno::erofs())
    }
}

#[cfg(test)]
mod tests {
    use super::linux_errno;
    use super::read_only_open_flags;
    #[cfg(target_os = "windows")]
    use super::windows::fs_utils;

    #[test]
    fn read_only_open_flags_allow_append() {
        let flags = (libc::O_RDONLY | libc::O_APPEND) as u32;
        let ro_flags = read_only_open_flags(flags).unwrap();

        #[cfg(not(target_os = "windows"))]
        let o_accmode = libc::O_ACCMODE;
        #[cfg(target_os = "windows")]
        let o_accmode = fs_utils::O_ACCMODE;
        assert_eq!((ro_flags as i32) & o_accmode, libc::O_RDONLY);
        assert_ne!((ro_flags as i32) & libc::O_APPEND, 0);
    }

    #[test]
    fn read_only_open_flags_reject_write_access() {
        let err = read_only_open_flags(libc::O_WRONLY as u32).unwrap_err();

        assert_eq!(err.raw_os_error(), linux_errno::erofs().raw_os_error());
    }

    #[test]
    fn read_only_open_flags_reject_truncate() {
        let err = read_only_open_flags((libc::O_RDONLY | libc::O_TRUNC) as u32).unwrap_err();

        assert_eq!(err.raw_os_error(), linux_errno::erofs().raw_os_error());
    }
}
