use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use super::confined::{Root, check_result, error, open_at, read_link, validate_name};
use super::passthrough::{DirStream, InodeAltKey, PermissionSemantics, fstat, parse_open_flags};
use crate::virtio::bindings;
use crate::virtio::fs::filesystem::{
    Context, DirEntry, Entry, Extensions, FileSystem, FsOptions, OpenOptions, SetattrValid,
    ZeroCopyReader, ZeroCopyWriter,
};
use crate::virtio::fs::fuse;
use crate::virtio::fs::inode_alloc::InodeAllocator;
use crate::virtio::fs::multikey::MultikeyBTreeMap;

fn check_simplified_access(mode: libc::mode_t, uid: u32, mask: u32) -> io::Result<()> {
    if mask & !7 != 0 {
        return Err(error(libc::EINVAL));
    }
    let mut permissions = u32::from(mode | (mode >> 3) | (mode >> 6)) & 7;
    if uid == 0 {
        permissions |= (libc::R_OK | libc::W_OK) as u32;
    }
    if mask & !permissions != 0 {
        return Err(error(libc::EACCES));
    }
    Ok(())
}

struct InodeData {
    inode: u64,
    file: File,
    refcount: AtomicU64,
}

struct HandleData {
    source: Arc<InodeData>,
    file: File,
    directory: Mutex<Option<DirStream>>,
}

pub(super) struct RestrictedFs {
    root: Root,
    inodes: RwLock<MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>>,
    inode_alloc: Arc<InodeAllocator>,
    handles: RwLock<BTreeMap<u64, Arc<HandleData>>>,
    next_handle: AtomicU64,
}

impl RestrictedFs {
    pub(super) fn new(path: &Path, inode_alloc: Arc<InodeAllocator>) -> io::Result<Self> {
        Ok(Self {
            root: Root::new(path)?,
            inodes: RwLock::new(MultikeyBTreeMap::new()),
            inode_alloc,
            handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
        })
    }

    fn inode(&self, inode: u64) -> io::Result<Arc<InodeData>> {
        self.inode_with_stat(inode).map(|(data, _)| data)
    }

    fn inode_with_stat(&self, inode: u64) -> io::Result<(Arc<InodeData>, libc::stat)> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(|| error(libc::EBADF))?;
        let st = self.root.check(&data.file)?;
        Ok((data, st))
    }

    fn entry(&self, ctx: Context, file: File) -> io::Result<Entry> {
        let st = self.root.check(&file)?;
        let key = InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
        };
        let mut inodes = self.inodes.write().unwrap();
        let data = if let Some(data) = inodes.get_alt(&key) {
            data.refcount.fetch_add(1, Ordering::Relaxed);
            data.clone()
        } else {
            let inode = self.inode_alloc.next();
            let data = Arc::new(InodeData {
                inode,
                file,
                refcount: AtomicU64::new(1),
            });
            inodes.insert(inode, key, data.clone());
            data
        };
        Ok(Entry {
            inode: data.inode,
            generation: 0,
            attr: fstat(
                &ctx,
                PermissionSemantics::LinuxSimplified,
                data.file.as_raw_fd(),
                false,
            )?,
            attr_flags: 0,
            attr_timeout: Duration::ZERO,
            entry_timeout: Duration::ZERO,
        })
    }

    fn handle(&self, inode: u64, handle: u64) -> io::Result<Arc<HandleData>> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|data| data.source.inode == inode)
            .cloned()
            .ok_or_else(|| error(libc::EBADF))?;
        self.root.check(&data.source.file)?;
        self.root.check(&data.file)?;
        Ok(data)
    }

    fn insert_handle(&self, source: Arc<InodeData>, file: File) -> u64 {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles.write().unwrap().insert(
            handle,
            Arc::new(HandleData {
                source,
                file,
                directory: Mutex::new(None),
            }),
        );
        handle
    }

    fn directory(&self, parent: u64, name: &CStr) -> io::Result<Arc<InodeData>> {
        validate_name(name)?;
        let (data, st) = self.inode_with_stat(parent)?;
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(error(libc::ENOTDIR));
        }
        Ok(data)
    }

    fn check_extensions(&self, extensions: &Extensions) -> io::Result<()> {
        if extensions.secctx.is_some() {
            return Err(error(libc::EOPNOTSUPP));
        }
        Ok(())
    }

    fn unlink_name(&self, parent: u64, name: &CStr, flags: i32) -> io::Result<()> {
        let dir = self.directory(parent, name)?;
        let _file = self.root.child(&dir.file, name)?;
        check_result(unsafe { libc::unlinkat(dir.file.as_raw_fd(), name.as_ptr(), flags) })
    }

    fn open_file(
        &self,
        inode: u64,
        flags: i32,
        kill_priv: bool,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        let source = self.inode(inode)?;
        let file = self.root.reopen(&source.file, flags)?;
        let directory = self.root.check(&file)?.st_mode & libc::S_IFMT == libc::S_IFDIR;
        if flags & libc::O_TRUNC != 0 {
            check_result(unsafe { libc::ftruncate(file.as_raw_fd(), 0) })?;
            if kill_priv {
                self.clear_privileges(&file)?;
            }
        }
        let handle = self.insert_handle(source, file);
        let options = if directory {
            OpenOptions::empty()
        } else {
            OpenOptions::DIRECT_IO
        };
        Ok((Some(handle), options))
    }

    fn clear_privileges(&self, file: &File) -> io::Result<()> {
        let st = self.root.check(file)?;
        let mode = st.st_mode & !(libc::S_ISUID | libc::S_ISGID);
        if mode != st.st_mode {
            check_result(unsafe { libc::fchmod(file.as_raw_fd(), mode) })?;
        }
        Ok(())
    }

    fn release_handle(&self, inode: u64, handle: u64) -> io::Result<()> {
        let mut handles = self.handles.write().unwrap();
        if handles
            .get(&handle)
            .is_none_or(|data| data.source.inode != inode)
        {
            return Err(error(libc::EBADF));
        }
        handles.remove(&handle);
        Ok(())
    }

    fn directory_entries<F>(
        &self,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        mut add: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        let data = self.handle(inode, handle)?;
        if size == 0 {
            return Ok(());
        }
        let mut stream = data.directory.lock().unwrap();
        if offset == 0 || stream.is_none() {
            let result = unsafe { libc::lseek(data.file.as_raw_fd(), 0, libc::SEEK_SET) };
            if result < 0 {
                return Err(error(libc::ENOTDIR));
            }
            let mut fresh = DirStream::new();
            fresh.fill_from_fd(data.file.as_raw_fd())?;
            *stream = Some(fresh);
        }
        let mut offset = offset;
        while let Some(entry) = stream.as_ref().unwrap().get_entry(offset) {
            offset = entry.offset;
            let name = CString::new(entry.name).map_err(|_| error(libc::EINVAL))?;
            let (_file, st) = match self.root.child_with_stat(&data.file, &name) {
                Ok(child) => child,
                Err(err)
                    if [
                        libc::EPERM,
                        libc::EACCES,
                        libc::ENOENT,
                        libc::ESTALE,
                        libc::EXDEV,
                        libc::EOPNOTSUPP,
                    ]
                    .into_iter()
                    .any(|errno| error(errno).raw_os_error() == err.raw_os_error()) =>
                {
                    continue;
                }
                Err(err) => return Err(err),
            };
            let entry = DirEntry {
                ino: st.st_ino,
                type_: u32::from((st.st_mode & libc::S_IFMT) >> 12),
                ..entry
            };
            if add(entry)? == 0 {
                break;
            }
        }
        Ok(())
    }
}

impl FileSystem for RestrictedFs {
    type Inode = u64;
    type Handle = u64;

    fn init(&self, _capable: FsOptions) -> io::Result<FsOptions> {
        let file = self.root.resolve(Path::new(""), false)?;
        let st = self.root.check(&file)?;
        self.inodes.write().unwrap().insert(
            fuse::ROOT_ID,
            InodeAltKey {
                ino: st.st_ino,
                dev: st.st_dev,
            },
            Arc::new(InodeData {
                inode: fuse::ROOT_ID,
                file,
                refcount: AtomicU64::new(2),
            }),
        );
        Ok(FsOptions::empty())
    }

    fn destroy(&self) {
        self.handles.write().unwrap().clear();
        self.inodes.write().unwrap().clear();
    }

    fn lookup(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        let dir = self.inode(parent)?;
        self.entry(ctx, self.root.child(&dir.file, name)?)
    }

    fn forget(&self, _ctx: Context, inode: u64, count: u64) {
        let mut inodes = self.inodes.write().unwrap();
        if let Some(data) = inodes.get(&inode) {
            let remaining = data.refcount.load(Ordering::Relaxed).saturating_sub(count);
            data.refcount.store(remaining, Ordering::Relaxed);
            if remaining == 0 {
                inodes.remove(&inode);
            }
        }
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: u64,
        handle: Option<u64>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        let data = self.inode(inode)?;
        if let Some(handle) = handle {
            self.handle(inode, handle)?;
        }
        Ok((
            fstat(
                &ctx,
                PermissionSemantics::LinuxSimplified,
                data.file.as_raw_fd(),
                false,
            )?,
            Duration::ZERO,
        ))
    }

    fn readlink(&self, _ctx: Context, inode: u64) -> io::Result<Vec<u8>> {
        let data = self.inode(inode)?;
        read_link(&data.file)
    }

    fn statfs(&self, _ctx: Context, inode: u64) -> io::Result<bindings::statvfs64> {
        let data = self.inode(inode)?;
        let mut st = MaybeUninit::uninit();
        check_result(unsafe { bindings::fstatvfs64(data.file.as_raw_fd(), st.as_mut_ptr()) })?;
        Ok(unsafe { st.assume_init() })
    }

    fn link(
        &self,
        _ctx: Context,
        _inode: u64,
        _newparent: u64,
        _newname: &CStr,
    ) -> io::Result<Entry> {
        Err(error(libc::EPERM))
    }

    fn create(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        kill_priv: bool,
        flags: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        self.check_extensions(&extensions)?;
        if mode as u16 & libc::S_IFMT != 0 && mode as u16 & libc::S_IFMT != libc::S_IFREG {
            return Err(error(libc::EOPNOTSUPP));
        }
        let dir = self.directory(parent, name)?;
        let flags = parse_open_flags(flags as i32);
        let file = match self.root.child(&dir.file, name) {
            Ok(file) => {
                if flags & libc::O_EXCL != 0 {
                    return Err(error(libc::EEXIST));
                }
                self.root.reopen(&file, flags | libc::O_NOFOLLOW)?
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let file = open_at(
                    dir.file.as_raw_fd(),
                    name,
                    (flags & !libc::O_TRUNC) | libc::O_CREAT | libc::O_EXCL,
                    mode as u16 & !umask as u16 & 0o7777,
                )?;
                self.root.check(&file)?;
                check_result(unsafe {
                    libc::fchmod(file.as_raw_fd(), mode as u16 & !umask as u16 & 0o7777)
                })?;
                file
            }
            Err(err) => return Err(err),
        };
        if flags & libc::O_TRUNC != 0 {
            check_result(unsafe { libc::ftruncate(file.as_raw_fd(), 0) })?;
            if kill_priv {
                self.clear_privileges(&file)?;
            }
        }
        let entry = self.entry(ctx, file.try_clone()?)?;
        let source = self.inode(entry.inode)?;
        let handle = self.insert_handle(source, file);
        Ok((entry, Some(handle), OpenOptions::DIRECT_IO))
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.check_extensions(&extensions)?;
        let dir = self.directory(parent, name)?;
        let mode = mode as u16 & !umask as u16 & 0o7777;
        check_result(unsafe { libc::mkdirat(dir.file.as_raw_fd(), name.as_ptr(), mode) })?;
        let file = self.root.child(&dir.file, name)?;
        check_result(unsafe { libc::fchmod(file.as_raw_fd(), mode) })?;
        self.entry(ctx, file)
    }

    fn mknod(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        _rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        if mode as u16 & libc::S_IFMT != libc::S_IFREG {
            return Err(error(libc::EOPNOTSUPP));
        }
        let (entry, handle, _) = self.create(
            ctx,
            parent,
            name,
            mode,
            false,
            (bindings::LINUX_O_CREAT | bindings::LINUX_O_EXCL | 1) as u32,
            umask,
            extensions,
        )?;
        self.release_handle(entry.inode, handle.unwrap())?;
        Ok(entry)
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.check_extensions(&extensions)?;
        let dir = self.directory(parent, name)?;
        check_result(unsafe {
            libc::symlinkat(linkname.as_ptr(), dir.file.as_raw_fd(), name.as_ptr())
        })?;
        self.entry(ctx, self.root.child(&dir.file, name)?)
    }

    fn unlink(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.unlink_name(parent, name, 0)
    }

    fn rmdir(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.unlink_name(parent, name, libc::AT_REMOVEDIR)
    }

    fn rename(
        &self,
        _ctx: Context,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        let exclusive = bindings::LINUX_RENAME_NOREPLACE as u32;
        let exchange = bindings::LINUX_RENAME_EXCHANGE as u32;
        if flags & !(exclusive | exchange) != 0 || flags == exclusive | exchange {
            return Err(error(libc::EINVAL));
        }
        let olddir = self.directory(olddir, oldname)?;
        let newdir = self.directory(newdir, newname)?;
        let _source = self.root.child(&olddir.file, oldname)?;
        let _destination = match self.root.child(&newdir.file, newname) {
            Ok(file) => Some(file),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
        let host_flags = if flags & exclusive != 0 {
            libc::RENAME_EXCL
        } else if flags & exchange != 0 {
            libc::RENAME_SWAP
        } else {
            0
        };
        check_result(unsafe {
            libc::renameatx_np(
                olddir.file.as_raw_fd(),
                oldname.as_ptr(),
                newdir.file.as_raw_fd(),
                newname.as_ptr(),
                host_flags,
            )
        })
    }

    fn open(
        &self,
        _ctx: Context,
        inode: u64,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        self.open_file(inode, parse_open_flags(flags as i32), kill_priv)
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: u64,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        self.open_file(
            inode,
            parse_open_flags(flags as i32) | libc::O_DIRECTORY,
            false,
        )
    }

    fn release(
        &self,
        _ctx: Context,
        inode: u64,
        _flags: u32,
        handle: u64,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.release_handle(inode, handle)
    }

    fn releasedir(&self, _ctx: Context, inode: u64, _flags: u32, handle: u64) -> io::Result<()> {
        self.release_handle(inode, handle)
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        mut writer: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        let data = self.handle(inode, handle)?;
        writer.write_from(&data.file, size as usize, offset)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        mut reader: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        let data = self.handle(inode, handle)?;
        if kill_priv {
            self.clear_privileges(&data.file)?;
        }
        reader.read_to(&data.file, size as usize, offset)
    }

    fn setattr(
        &self,
        ctx: Context,
        inode: u64,
        attr: bindings::stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        let data = self.inode(inode)?;
        let opened = handle.map(|h| self.handle(inode, h)).transpose()?;
        let st = self.root.check(&data.file)?;
        if st.st_mode & libc::S_IFMT == libc::S_IFLNK
            && valid.intersects(SetattrValid::MODE | SetattrValid::SIZE)
        {
            return Err(error(libc::EOPNOTSUPP));
        }
        if valid.contains(SetattrValid::MODE) {
            check_result(unsafe { libc::fchmod(data.file.as_raw_fd(), attr.st_mode & 0o7777) })?;
        }
        if valid.contains(SetattrValid::SIZE) {
            let file = if let Some(opened) = &opened {
                &opened.file
            } else {
                &self
                    .root
                    .reopen(&data.file, libc::O_RDWR | libc::O_NOFOLLOW)?
            };
            check_result(unsafe { libc::ftruncate(file.as_raw_fd(), attr.st_size) })?;
            self.clear_privileges(file)?;
        }
        if valid.intersects(SetattrValid::UID | SetattrValid::GID) {
            self.clear_privileges(&data.file)?;
        }
        if valid.intersects(
            SetattrValid::ATIME
                | SetattrValid::MTIME
                | SetattrValid::ATIME_NOW
                | SetattrValid::MTIME_NOW,
        ) {
            let times = [
                libc::timespec {
                    tv_sec: attr.st_atime,
                    tv_nsec: if valid.contains(SetattrValid::ATIME_NOW) {
                        libc::UTIME_NOW
                    } else if valid.contains(SetattrValid::ATIME) {
                        attr.st_atime_nsec
                    } else {
                        libc::UTIME_OMIT
                    },
                },
                libc::timespec {
                    tv_sec: attr.st_mtime,
                    tv_nsec: if valid.contains(SetattrValid::MTIME_NOW) {
                        libc::UTIME_NOW
                    } else if valid.contains(SetattrValid::MTIME) {
                        attr.st_mtime_nsec
                    } else {
                        libc::UTIME_OMIT
                    },
                },
            ];
            check_result(unsafe { libc::futimens(data.file.as_raw_fd(), times.as_ptr()) })?;
        }
        self.getattr(ctx, inode, handle)
    }

    fn flush(&self, _ctx: Context, inode: u64, handle: u64, _lock_owner: u64) -> io::Result<()> {
        self.handle(inode, handle)?;
        Ok(())
    }

    fn fsync(&self, _ctx: Context, inode: u64, _datasync: bool, handle: u64) -> io::Result<()> {
        let data = self.handle(inode, handle)?;
        check_result(unsafe { libc::fsync(data.file.as_raw_fd()) })
    }

    fn fsyncdir(&self, ctx: Context, inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        self.fsync(ctx, inode, datasync, handle)
    }

    fn access(&self, ctx: Context, inode: u64, mask: u32) -> io::Result<()> {
        let (_data, st) = self.inode_with_stat(inode)?;
        check_simplified_access(st.st_mode, ctx.uid, mask)
    }

    fn readdir<F>(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        self.directory_entries(inode, handle, size, offset, add_entry)
    }

    fn readdirplus<F>(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        self.directory_entries(inode, handle, size, offset, |dir_entry| {
            let name = CString::new(dir_entry.name).map_err(|_| error(libc::EINVAL))?;
            let entry = self.lookup(ctx, inode, &name)?;
            let looked_up = entry.inode;
            match add_entry(dir_entry, entry) {
                Ok(0) => {
                    self.forget(ctx, looked_up, 1);
                    Ok(0)
                }
                Err(err) => {
                    self.forget(ctx, looked_up, 1);
                    Err(err)
                }
                result => result,
            }
        })
    }

    fn lseek(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        let data = self.handle(inode, handle)?;
        let offset = i64::try_from(offset).map_err(|_| error(libc::EINVAL))?;
        let whence = match whence {
            3 => return Ok(offset as u64),
            4 => libc::SEEK_END,
            0..=2 => whence as i32,
            _ => return Err(error(libc::EINVAL)),
        };
        let result = unsafe { libc::lseek(data.file.as_raw_fd(), offset, whence) };
        if result < 0 {
            Err(error(libc::EINVAL))
        } else {
            Ok(result as u64)
        }
    }

    fn fallocate(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let data = self.handle(inode, handle)?;
        let end = offset
            .checked_add(length)
            .and_then(|n| i64::try_from(n).ok())
            .ok_or_else(|| error(libc::EINVAL))?;
        let keep = bindings::LINUX_FALLOC_FL_KEEP_SIZE as u32;
        let punch = bindings::LINUX_FALLOC_FL_PUNCH_HOLE as u32;
        if mode & !(keep | punch) != 0 || (mode & punch != 0 && mode & keep == 0) {
            return Err(error(libc::EOPNOTSUPP));
        }
        let fd = data.file.as_raw_fd();
        if mode & punch != 0 {
            let mut hole = libc::fpunchhole_t {
                fp_offset: offset as i64,
                fp_flags: 0,
                reserved: 0,
                fp_length: length as i64,
            };
            check_result(unsafe { libc::fcntl(fd, libc::F_PUNCHHOLE, &mut hole) })
        } else if mode & keep != 0 {
            let disk_size = self.root.check(&data.file)?.st_blocks * 512;
            if disk_size >= end {
                return Ok(());
            }
            let mut store = libc::fstore_t {
                fst_flags: libc::F_ALLOCATEALL,
                fst_posmode: libc::F_PEOFPOSMODE,
                fst_offset: 0,
                fst_length: end - disk_size,
                fst_bytesalloc: 0,
            };
            check_result(unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut store) })
        } else if self.root.check(&data.file)?.st_size < end {
            check_result(unsafe { libc::ftruncate(fd, end) })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::TestDir;
    use super::*;
    use std::fs;
    use std::io::{Cursor, Read, Write};
    use std::os::unix::fs::{FileExt, PermissionsExt, symlink};

    #[derive(Default)]
    struct Buffer(Cursor<Vec<u8>>);

    impl Read for Buffer {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ZeroCopyWriter for Buffer {
        fn write_from(&mut self, file: &File, count: usize, offset: u64) -> io::Result<usize> {
            let mut buf = vec![0; count];
            let len = file.read_at(&mut buf, offset)?;
            self.write_all(&buf[..len])?;
            Ok(len)
        }
    }

    impl ZeroCopyReader for Buffer {
        fn read_to(&mut self, file: &File, count: usize, offset: u64) -> io::Result<usize> {
            let mut buf = vec![0; count];
            let len = self.read(&mut buf)?;
            file.write_at(&buf[..len], offset)
        }
    }

    fn ctx() -> Context {
        Context {
            uid: 1000,
            gid: 1000,
            pid: 1,
        }
    }

    fn filesystem(dir: &TestDir) -> RestrictedFs {
        let fs = RestrictedFs::new(&dir.0, Arc::new(InodeAllocator::new())).unwrap();
        fs.init(FsOptions::all()).unwrap();
        fs
    }

    #[test]
    fn access_accepts_permissions_from_all_simplified_classes() {
        let cases = [
            (0o000, 0),
            (0o400, 4),
            (0o040, 4),
            (0o004, 4),
            (0o200, 2),
            (0o020, 2),
            (0o002, 2),
            (0o100, 1),
            (0o010, 1),
            (0o001, 1),
            (0o070, 7),
            (0o007, 7),
            (0o421, 7),
            (0o140, 5),
        ];
        for uid in [1000, 2000] {
            for (mode, allowed) in cases {
                for mask in 0..=7 {
                    assert_eq!(
                        check_simplified_access(mode, uid, mask).is_ok(),
                        mask & allowed == mask,
                        "mode={mode:o} mask={mask} uid={uid}"
                    );
                }
            }
        }
    }

    #[test]
    fn access_preserves_root_execute_checks_and_rejects_invalid_masks() {
        for (mode, executable) in [
            (0o000, false),
            (0o666, false),
            (0o100, true),
            (0o010, true),
            (0o001, true),
        ] {
            check_simplified_access(mode, 0, (libc::R_OK | libc::W_OK) as u32).unwrap();
            assert_eq!(
                check_simplified_access(mode, 0, libc::X_OK as u32).is_ok(),
                executable
            );
            for invalid in [8, u32::MAX] {
                assert_eq!(
                    check_simplified_access(mode, 0, invalid)
                        .unwrap_err()
                        .raw_os_error(),
                    error(libc::EINVAL).raw_os_error()
                );
            }
        }
    }

    #[test]
    fn access_revalidates_inode_containment_and_hardlinks() {
        let dir = TestDir::new();
        let outside = TestDir::new();
        let path = dir.0.join("file");
        fs::write(&path, b"contents").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let fs = filesystem(&dir);
        let inode = fs.lookup(ctx(), fuse::ROOT_ID, c"file").unwrap().inode;
        fs.access(ctx(), inode, libc::R_OK as u32).unwrap();
        fs::hard_link(&path, outside.0.join("linked")).unwrap();
        assert!(fs.access(ctx(), inode, libc::F_OK as u32).is_err());
        fs::remove_file(outside.0.join("linked")).unwrap();
        fs::rename(&path, outside.0.join("moved")).unwrap();
        assert!(fs.access(ctx(), inode, libc::F_OK as u32).is_err());
    }

    #[test]
    fn namespace_operations_reject_non_directory_parents() {
        let dir = TestDir::new();
        fs::write(dir.0.join("file"), b"contents").unwrap();
        symlink("/", dir.0.join("link")).unwrap();
        let fs = filesystem(&dir);
        for name in [c"file", c"link"] {
            let parent = fs.lookup(ctx(), fuse::ROOT_ID, name).unwrap().inode;
            assert_eq!(
                fs.mkdir(ctx(), parent, c"child", 0o700, 0, Extensions::default())
                    .err()
                    .unwrap()
                    .raw_os_error(),
                error(libc::ENOTDIR).raw_os_error()
            );
        }
        assert!(!dir.0.join("child").exists());
    }

    #[test]
    fn rejects_existing_and_new_hardlinks() {
        let dir = TestDir::new();
        fs::write(dir.0.join("file"), b"contents").unwrap();
        let fs = filesystem(&dir);
        let file = fs.lookup(ctx(), fuse::ROOT_ID, c"file").unwrap();
        assert!(fs.link(ctx(), file.inode, fuse::ROOT_ID, c"new").is_err());
        fs::hard_link(dir.0.join("file"), dir.0.join("other")).unwrap();
        assert!(fs.lookup(ctx(), fuse::ROOT_ID, c"file").is_err());
        assert!(fs.lookup(ctx(), fuse::ROOT_ID, c"other").is_err());
        assert!(fs.getattr(ctx(), file.inode, None).is_err());
        assert!(!dir.0.join("new").exists());
    }

    #[test]
    fn preserves_symlink_identity_and_rejects_symlink_parents() {
        let dir = TestDir::new();
        fs::create_dir(dir.0.join("directory")).unwrap();
        symlink("directory", dir.0.join("link")).unwrap();
        let fs = filesystem(&dir);
        let entry = fs.lookup(ctx(), fuse::ROOT_ID, c"link").unwrap();
        assert_eq!(entry.attr.st_mode & libc::S_IFMT, libc::S_IFLNK);
        assert_eq!(fs.readlink(ctx(), entry.inode).unwrap(), b"directory");
        assert!(fs.lookup(ctx(), entry.inode, c"file").is_err());
        assert_eq!(entry.attr.st_uid, ctx().uid);
        assert_eq!(entry.attr_timeout, Duration::ZERO);
    }

    #[test]
    fn rejects_unlinked_inode_even_after_name_reuse() {
        let dir = TestDir::new();
        fs::write(dir.0.join("file"), b"original").unwrap();
        let fs = filesystem(&dir);
        let entry = fs.lookup(ctx(), fuse::ROOT_ID, c"file").unwrap();
        fs::remove_file(dir.0.join("file")).unwrap();
        fs::write(dir.0.join("file"), b"replacement").unwrap();
        assert!(fs.getattr(ctx(), entry.inode, None).is_err());
        let replacement = fs.lookup(ctx(), fuse::ROOT_ID, c"file").unwrap();
        assert_ne!(entry.inode, replacement.inode);
    }

    #[test]
    fn file_operations_use_checked_descriptors() {
        let dir = TestDir::new();
        fs::write(dir.0.join("file"), b"original").unwrap();
        let fs = filesystem(&dir);
        let entry = fs.lookup(ctx(), fuse::ROOT_ID, c"file").unwrap();
        let (handle, options) = fs
            .open(ctx(), entry.inode, false, libc::O_RDWR as u32)
            .unwrap();
        let handle = handle.unwrap();
        assert!(options.contains(OpenOptions::DIRECT_IO));
        let mut input = Buffer(Cursor::new(b"updated".to_vec()));
        assert_eq!(
            fs.write(
                ctx(),
                entry.inode,
                handle,
                &mut input,
                7,
                0,
                None,
                false,
                true,
                0
            )
            .unwrap(),
            7
        );
        let mut attrs = entry.attr;
        attrs.st_size = 7;
        attrs.st_mode = 0o640;
        fs.setattr(
            ctx(),
            entry.inode,
            attrs,
            None,
            SetattrValid::SIZE | SetattrValid::MODE | SetattrValid::MTIME_NOW,
        )
        .unwrap();
        let mut output = Buffer::default();
        fs.read(ctx(), entry.inode, handle, &mut output, 20, 0, None, 0)
            .unwrap();
        assert_eq!(output.0.into_inner(), b"updated");
        assert_eq!(
            fs.getattr(ctx(), entry.inode, Some(handle))
                .unwrap()
                .0
                .st_mode
                & 0o777,
            0o640
        );
        fs.fallocate(ctx(), entry.inode, handle, 0, 0, 32).unwrap();
        assert_eq!(fs.lseek(ctx(), entry.inode, handle, 0, 2).unwrap(), 32);
        assert!(
            fs.fallocate(ctx(), entry.inode, handle, 0, u64::MAX, 1)
                .is_err()
        );
        fs.fsync(ctx(), entry.inode, false, handle).unwrap();
        fs.flush(ctx(), entry.inode, handle, 0).unwrap();
        assert!(fs.getattr(ctx(), fuse::ROOT_ID, Some(handle)).is_err());
        fs.release_handle(entry.inode, handle).unwrap();
        assert!(fs.handle(entry.inode, handle).is_err());
    }

    #[test]
    fn open_handles_are_rechecked_after_hardlink_creation_and_move() {
        let dir = TestDir::new();
        let outside = TestDir::new();
        fs::write(dir.0.join("file"), b"original").unwrap();
        let fs = filesystem(&dir);
        let entry = fs.lookup(ctx(), fuse::ROOT_ID, c"file").unwrap();
        let handle = fs
            .open(ctx(), entry.inode, false, libc::O_RDWR as u32)
            .unwrap()
            .0
            .unwrap();
        fs::hard_link(dir.0.join("file"), outside.0.join("linked")).unwrap();
        let mut output = Buffer::default();
        assert!(
            fs.read(ctx(), entry.inode, handle, &mut output, 8, 0, None, 0)
                .is_err()
        );
        let mut input = Buffer(Cursor::new(b"changed".to_vec()));
        assert!(
            fs.write(
                ctx(),
                entry.inode,
                handle,
                &mut input,
                7,
                0,
                None,
                false,
                false,
                0
            )
            .is_err()
        );
        assert!(
            fs.open(ctx(), entry.inode, false, bindings::LINUX_O_TRUNC as u32)
                .is_err()
        );
        fs::remove_file(outside.0.join("linked")).unwrap();
        fs::rename(dir.0.join("file"), outside.0.join("moved")).unwrap();
        assert!(fs.flush(ctx(), entry.inode, handle, 0).is_err());
        assert!(fs.fallocate(ctx(), entry.inode, handle, 0, 0, 50).is_err());
        assert_eq!(fs::read(outside.0.join("moved")).unwrap(), b"original");
        fs.release_handle(entry.inode, handle).unwrap();
    }

    #[test]
    fn symlink_targets_are_resolved_inside_the_export() {
        let dir = TestDir::new();
        let outside = TestDir::new();
        fs::write(dir.0.join("file"), b"inside").unwrap();
        fs::write(outside.0.join("file"), b"outside").unwrap();
        symlink("/file", dir.0.join("internal")).unwrap();
        symlink(outside.0.join("file"), dir.0.join("external")).unwrap();
        let fs = filesystem(&dir);
        let internal = fs.lookup(ctx(), fuse::ROOT_ID, c"internal").unwrap();
        let handle = fs.open(ctx(), internal.inode, false, 0).unwrap().0.unwrap();
        let mut output = Buffer::default();
        fs.read(ctx(), internal.inode, handle, &mut output, 20, 0, None, 0)
            .unwrap();
        assert_eq!(output.0.into_inner(), b"inside");
        assert!(
            fs.open(
                ctx(),
                internal.inode,
                false,
                bindings::LINUX_O_NOFOLLOW as u32
            )
            .is_err()
        );
        let external = fs.lookup(ctx(), fuse::ROOT_ID, c"external").unwrap();
        assert!(
            fs.open(
                ctx(),
                external.inode,
                false,
                (bindings::LINUX_O_TRUNC | 1) as u32
            )
            .is_err()
        );
        assert!(
            fs.setattr(
                ctx(),
                external.inode,
                external.attr,
                None,
                SetattrValid::SIZE
            )
            .is_err()
        );
        assert_eq!(fs::read(outside.0.join("file")).unwrap(), b"outside");
    }

    #[test]
    fn directory_reads_validate_handles_and_build_valid_names() {
        let dir = TestDir::new();
        fs::write(dir.0.join("file"), b"contents").unwrap();
        let fs = filesystem(&dir);
        let handle = fs.opendir(ctx(), fuse::ROOT_ID, 0).unwrap().0.unwrap();
        let mut names = Vec::new();
        fs.readdirplus(ctx(), fuse::ROOT_ID, handle, 4096, 0, |entry, attr| {
            assert_eq!(attr.attr.st_size, 8);
            names.push(entry.name.to_vec());
            Ok(1)
        })
        .unwrap();
        assert_eq!(names, [b"file".to_vec()]);
        assert!(
            fs.readdir(ctx(), fuse::ROOT_ID + 1, handle, 4096, 0, |_| Ok(1))
                .is_err()
        );
    }

    #[test]
    fn directory_reads_do_not_expose_rejected_inodes() {
        let dir = TestDir::new();
        fs::write(dir.0.join("blocked"), b"contents").unwrap();
        fs::hard_link(dir.0.join("blocked"), dir.0.join("hardlink")).unwrap();
        fs::write(dir.0.join("allowed"), b"contents").unwrap();
        let fs = filesystem(&dir);
        let handle = fs.opendir(ctx(), fuse::ROOT_ID, 0).unwrap().0.unwrap();
        let mut names = Vec::new();
        fs.readdir(ctx(), fuse::ROOT_ID, handle, 4096, 0, |entry| {
            names.push(entry.name.to_vec());
            Ok(1)
        })
        .unwrap();
        assert_eq!(names, [b"allowed".to_vec()]);
    }

    #[test]
    fn creates_and_renames_entries_using_checked_parents() {
        let dir = TestDir::new();
        let fs = filesystem(&dir);
        let directory = fs
            .mkdir(
                ctx(),
                fuse::ROOT_ID,
                c"directory",
                0o750,
                0,
                Extensions::default(),
            )
            .unwrap();
        let (entry, handle, _) = fs
            .create(
                ctx(),
                directory.inode,
                c"file",
                0o640,
                false,
                2,
                0,
                Extensions::default(),
            )
            .unwrap();
        let handle = handle.unwrap();
        let mut input = Buffer(Cursor::new(b"contents".to_vec()));
        fs.write(
            ctx(),
            entry.inode,
            handle,
            &mut input,
            8,
            0,
            None,
            false,
            false,
            0,
        )
        .unwrap();
        fs.rename(ctx(), directory.inode, c"file", fuse::ROOT_ID, c"moved", 0)
            .unwrap();
        assert_eq!(fs.getattr(ctx(), entry.inode, None).unwrap().0.st_size, 8);
        fs.flush(ctx(), entry.inode, handle, 0).unwrap();
        fs.rmdir(ctx(), fuse::ROOT_ID, c"directory").unwrap();
        fs.unlink(ctx(), fuse::ROOT_ID, c"moved").unwrap();
        assert!(fs.flush(ctx(), entry.inode, handle, 0).is_err());
        fs.release_handle(entry.inode, handle).unwrap();
    }

    #[test]
    fn deleting_and_renaming_symlinks_leave_targets_untouched() {
        let dir = TestDir::new();
        let outside = TestDir::new();
        fs::write(outside.0.join("file"), b"outside").unwrap();
        let fs = filesystem(&dir);
        let target = CString::new(outside.0.join("file").as_os_str().as_encoded_bytes()).unwrap();
        let link = fs
            .symlink(
                ctx(),
                &target,
                fuse::ROOT_ID,
                c"link",
                Extensions::default(),
            )
            .unwrap();
        assert_eq!(fs.readlink(ctx(), link.inode).unwrap(), target.to_bytes());
        fs.rename(ctx(), fuse::ROOT_ID, c"link", fuse::ROOT_ID, c"renamed", 0)
            .unwrap();
        fs.unlink(ctx(), fuse::ROOT_ID, c"renamed").unwrap();
        assert_eq!(fs::read(outside.0.join("file")).unwrap(), b"outside");
    }

    #[test]
    fn namespace_operations_reject_hardlinks_before_modifying_files() {
        let dir = TestDir::new();
        fs::write(dir.0.join("file"), b"original").unwrap();
        fs::write(dir.0.join("other"), b"other").unwrap();
        fs::hard_link(dir.0.join("file"), dir.0.join("linked")).unwrap();
        let fs = filesystem(&dir);
        assert!(
            fs.create(
                ctx(),
                fuse::ROOT_ID,
                c"file",
                0o600,
                false,
                (bindings::LINUX_O_TRUNC | 1) as u32,
                0,
                Extensions::default()
            )
            .is_err()
        );
        assert!(fs.unlink(ctx(), fuse::ROOT_ID, c"file").is_err());
        assert!(
            fs.rename(ctx(), fuse::ROOT_ID, c"file", fuse::ROOT_ID, c"other", 0)
                .is_err()
        );
        assert!(
            fs.rename(ctx(), fuse::ROOT_ID, c"other", fuse::ROOT_ID, c"file", 0)
                .is_err()
        );
        assert_eq!(fs::read(dir.0.join("file")).unwrap(), b"original");
        assert_eq!(fs::read(dir.0.join("other")).unwrap(), b"other");
    }

    #[test]
    fn rejects_invalid_names_and_moved_directory_parents() {
        let dir = TestDir::new();
        let outside = TestDir::new();
        fs::create_dir(dir.0.join("directory")).unwrap();
        let fs = filesystem(&dir);
        for name in [c"", c".", c"..", c"a/b", c"../escape", c"/escape"] {
            assert!(
                fs.create(
                    ctx(),
                    fuse::ROOT_ID,
                    name,
                    0o600,
                    false,
                    2,
                    0,
                    Extensions::default()
                )
                .is_err()
            );
            assert!(
                fs.mkdir(ctx(), fuse::ROOT_ID, name, 0o700, 0, Extensions::default())
                    .is_err()
            );
            assert!(fs.unlink(ctx(), fuse::ROOT_ID, name).is_err());
            assert!(
                fs.symlink(ctx(), c"target", fuse::ROOT_ID, name, Extensions::default())
                    .is_err()
            );
        }
        let directory = fs.lookup(ctx(), fuse::ROOT_ID, c"directory").unwrap();
        fs::rename(dir.0.join("directory"), outside.0.join("directory")).unwrap();
        assert!(
            fs.create(
                ctx(),
                directory.inode,
                c"file",
                0o600,
                false,
                2,
                0,
                Extensions::default()
            )
            .is_err()
        );
        assert!(
            fs.mkdir(
                ctx(),
                directory.inode,
                c"new",
                0o700,
                0,
                Extensions::default()
            )
            .is_err()
        );
        assert!(!outside.0.join("directory/file").exists());
        assert!(!outside.0.join("directory/new").exists());
    }

    #[test]
    fn rename_flags_and_overwrite_preserve_inode_identity() {
        let dir = TestDir::new();
        fs::write(dir.0.join("first"), b"first").unwrap();
        fs::write(dir.0.join("second"), b"second").unwrap();
        let fs = filesystem(&dir);
        let first = fs.lookup(ctx(), fuse::ROOT_ID, c"first").unwrap();
        let second = fs.lookup(ctx(), fuse::ROOT_ID, c"second").unwrap();
        assert!(
            fs.rename(
                ctx(),
                fuse::ROOT_ID,
                c"first",
                fuse::ROOT_ID,
                c"second",
                bindings::LINUX_RENAME_NOREPLACE as u32
            )
            .is_err()
        );
        assert!(
            fs.rename(
                ctx(),
                fuse::ROOT_ID,
                c"first",
                fuse::ROOT_ID,
                c"second",
                bindings::LINUX_RENAME_WHITEOUT as u32
            )
            .is_err()
        );
        fs.rename(
            ctx(),
            fuse::ROOT_ID,
            c"first",
            fuse::ROOT_ID,
            c"second",
            bindings::LINUX_RENAME_EXCHANGE as u32,
        )
        .unwrap();
        assert_eq!(
            fs.lookup(ctx(), fuse::ROOT_ID, c"first").unwrap().inode,
            second.inode
        );
        fs.rename(ctx(), fuse::ROOT_ID, c"first", fuse::ROOT_ID, c"second", 0)
            .unwrap();
        assert!(fs.getattr(ctx(), first.inode, None).is_err());
        assert!(fs.getattr(ctx(), second.inode, None).is_ok());
    }

    #[test]
    fn rejects_special_files_and_security_contexts_before_creation() {
        use crate::virtio::fs::filesystem::SecContext;

        let dir = TestDir::new();
        let fs = filesystem(&dir);
        for kind in [libc::S_IFIFO, libc::S_IFSOCK, libc::S_IFCHR, libc::S_IFBLK] {
            assert!(
                fs.mknod(
                    ctx(),
                    fuse::ROOT_ID,
                    c"special",
                    u32::from(kind | 0o600),
                    0,
                    0,
                    Extensions::default()
                )
                .is_err()
            );
        }
        let extensions = Extensions {
            secctx: Some(SecContext {
                name: CString::from(c"security.test"),
                secctx: b"context".to_vec(),
            }),
            ..Default::default()
        };
        assert!(
            fs.create(
                ctx(),
                fuse::ROOT_ID,
                c"file",
                0o600,
                false,
                2,
                0,
                extensions
            )
            .is_err()
        );
        assert!(fs::read_dir(&dir.0).unwrap().next().is_none());
    }
}
