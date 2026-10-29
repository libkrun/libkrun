use std::collections::VecDeque;
use std::ffi::{CStr, CString, OsString};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};

use crate::virtio::linux_errno::linux_error;

const METADATA_FLAGS: i32 = libc::O_EVTONLY | libc::O_SYMLINK;

pub(super) fn error(errno: i32) -> io::Error {
    linux_error(io::Error::from_raw_os_error(errno))
}

pub(super) fn check_result(result: i32) -> io::Result<()> {
    if result < 0 {
        Err(linux_error(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

pub(super) fn open_at(dir: RawFd, name: &CStr, flags: i32, mode: u16) -> io::Result<File> {
    // O_SYMLINK opens the link itself; adding O_NOFOLLOW would reject that open.
    let nofollow = if flags & (libc::O_NOFOLLOW_ANY | libc::O_SYMLINK) == 0 {
        libc::O_NOFOLLOW
    } else {
        0
    };
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            flags | nofollow | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    check_result(fd)?;
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn stat(file: &File) -> io::Result<libc::stat> {
    let mut st = MaybeUninit::uninit();
    check_result(unsafe { libc::fstat(file.as_raw_fd(), st.as_mut_ptr()) })?;
    Ok(unsafe { st.assume_init() })
}

fn same_inode(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

fn check_inode(st: &libc::stat) -> io::Result<()> {
    if st.st_nlink == 0 {
        return Err(error(libc::ESTALE));
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR && st.st_nlink > 1 {
        return Err(error(libc::EPERM));
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFREG | libc::S_IFDIR | libc::S_IFLNK => Ok(()),
        _ => Err(error(libc::EOPNOTSUPP)),
    }
}

fn file_path(file: &File) -> io::Result<PathBuf> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    check_result(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) })?;
    let path = CStr::from_bytes_until_nul(&buf).map_err(|_| error(libc::EINVAL))?;
    Ok(PathBuf::from(OsString::from_vec(path.to_bytes().to_vec())))
}

pub(super) fn read_link(file: &File) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let len = unsafe { libc::freadlink(file.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    check_result(len)?;
    if len as usize == buf.len() {
        return Err(error(libc::ENAMETOOLONG));
    }
    buf.truncate(len as usize);
    Ok(buf)
}

pub(super) fn validate_name(name: &CStr) -> io::Result<()> {
    let bytes = name.to_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(error(libc::EINVAL));
    }
    Ok(())
}

fn components(path: &Path) -> VecDeque<Vec<u8>> {
    let mut parts: VecDeque<_> = path
        .as_os_str()
        .as_bytes()
        .split(|b| *b == b'/')
        .filter(|part| !part.is_empty())
        .map(Vec::from)
        .collect();
    if path.as_os_str().as_bytes().ends_with(b"/") {
        parts.push_back(b".".to_vec());
    }
    parts
}

pub(super) struct Root {
    file: File,
    dev: i32,
}

impl Root {
    pub(super) fn new(path: &Path) -> io::Result<Self> {
        let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| error(libc::EINVAL))?;
        let file = open_at(
            libc::AT_FDCWD,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW_ANY,
            0,
        )?;
        let dev = stat(&file)?.st_dev;
        Ok(Self { file, dev })
    }

    pub(super) fn resolve(&self, path: &Path, follow_final: bool) -> io::Result<File> {
        let mut pending = components(path);
        let mut dirs = vec![self.file.try_clone()?];
        let mut links = 0;

        while let Some(part) = pending.pop_front() {
            match part.as_slice() {
                b"." => continue,
                b".." => {
                    if dirs.len() == 1 {
                        return Err(error(libc::EACCES));
                    }
                    dirs.pop();
                    continue;
                }
                _ => {}
            }

            let name = CString::new(part).map_err(|_| error(libc::EINVAL))?;
            let file = open_at(dirs.last().unwrap().as_raw_fd(), &name, METADATA_FLAGS, 0)?;
            let st = stat(&file)?;
            check_inode(&st)?;
            if st.st_dev != self.dev {
                return Err(error(libc::EXDEV));
            }
            if st.st_mode & libc::S_IFMT == libc::S_IFLNK && (follow_final || !pending.is_empty()) {
                links += 1;
                if links > 40 {
                    return Err(error(libc::ELOOP));
                }
                let target = PathBuf::from(OsString::from_vec(read_link(&file)?));
                if target.is_absolute() {
                    dirs.truncate(1);
                }
                let mut expanded = components(&target);
                expanded.append(&mut pending);
                pending = expanded;
            } else if pending.is_empty() {
                return Ok(file);
            } else {
                if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                    return Err(error(libc::ENOTDIR));
                }
                dirs.push(file);
            }
        }
        Ok(dirs.pop().unwrap())
    }

    pub(super) fn relative_path(&self, file: &File) -> io::Result<PathBuf> {
        let st = stat(file)?;
        check_inode(&st)?;
        let root_path = file_path(&self.file)?;
        let path = file_path(file)?;
        let relative = path
            .strip_prefix(root_path)
            .map_err(|_| error(libc::EACCES))?;
        let resolved = self.resolve(relative, false)?;
        if !same_inode(&st, &stat(&resolved)?) {
            return Err(error(libc::ESTALE));
        }
        Ok(relative.to_owned())
    }

    pub(super) fn check(&self, file: &File) -> io::Result<libc::stat> {
        self.relative_path(file)?;
        stat(file)
    }

    pub(super) fn child(&self, dir: &File, name: &CStr) -> io::Result<File> {
        self.child_with_stat(dir, name).map(|(file, _)| file)
    }

    pub(super) fn child_with_stat(
        &self,
        dir: &File,
        name: &CStr,
    ) -> io::Result<(File, libc::stat)> {
        validate_name(name)?;
        if self.check(dir)?.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(error(libc::ENOTDIR));
        }
        let file = open_at(dir.as_raw_fd(), name, METADATA_FLAGS, 0)?;
        let st = self.check(&file)?;
        Ok((file, st))
    }

    pub(super) fn parent(&self, file: &File) -> io::Result<(File, CString)> {
        let relative = self.relative_path(file)?;
        let name = relative.file_name().ok_or_else(|| error(libc::EBUSY))?;
        let name = CString::new(name.as_bytes()).map_err(|_| error(libc::EINVAL))?;
        let parent = self.resolve(relative.parent().unwrap(), false)?;
        Ok((parent, name))
    }

    pub(super) fn reopen(&self, file: &File, flags: i32) -> io::Result<File> {
        let relative = self.relative_path(file)?;
        let resolved = self.resolve(&relative, flags & libc::O_NOFOLLOW == 0)?;
        let st = self.check(&resolved)?;
        match st.st_mode & libc::S_IFMT {
            libc::S_IFREG | libc::S_IFDIR => {}
            libc::S_IFLNK => return Err(error(libc::ELOOP)),
            _ => return Err(error(libc::EOPNOTSUPP)),
        }
        let (parent, name) = if self.relative_path(&resolved)?.as_os_str().is_empty() {
            (self.file.try_clone()?, CString::from(c"."))
        } else {
            self.parent(&resolved)?
        };
        let flags = flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC);
        let opened = open_at(parent.as_raw_fd(), &name, flags | libc::O_NONBLOCK, 0)?;
        if !same_inode(&st, &self.check(&opened)?) {
            return Err(error(libc::ESTALE));
        }
        Ok(opened)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_utils::TestDir;
    use super::*;
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::symlink;

    #[test]
    fn resolves_links_without_host_dereferencing() {
        let dir = TestDir::new();
        fs::create_dir(dir.0.join("sub")).unwrap();
        fs::write(dir.0.join("file"), b"inside").unwrap();
        symlink("../file", dir.0.join("sub/relative")).unwrap();
        symlink("/file", dir.0.join("absolute")).unwrap();
        symlink("/sub/relative", dir.0.join("chain")).unwrap();
        let root = Root::new(&dir.0).unwrap();
        for path in ["sub/relative", "absolute", "chain"] {
            let link = root.resolve(Path::new(path), false).unwrap();
            assert_eq!(stat(&link).unwrap().st_mode & libc::S_IFMT, libc::S_IFLNK);
            assert!(
                root.reopen(&link, libc::O_RDONLY | libc::O_NOFOLLOW)
                    .is_err()
            );
            let mut opened = root.reopen(&link, libc::O_RDONLY).unwrap();
            let mut contents = String::new();
            opened.read_to_string(&mut contents).unwrap();
            assert_eq!(contents, "inside");
        }
    }

    #[test]
    fn rejects_escape_loops_and_invalid_names() {
        let dir = TestDir::new();
        symlink("../outside", dir.0.join("escape")).unwrap();
        symlink("loop", dir.0.join("loop")).unwrap();
        let root = Root::new(&dir.0).unwrap();
        for path in ["../outside", "escape", "loop"] {
            assert!(root.resolve(Path::new(path), true).is_err());
        }
        let directory = root.resolve(Path::new(""), false).unwrap();
        for name in [c"", c".", c"..", c"../outside", c"/outside", c"a/b"] {
            assert!(root.child(&directory, name).is_err());
        }
    }

    #[test]
    fn rejects_moved_replaced_and_unlinked_objects() {
        let dir = TestDir::new();
        fs::create_dir(dir.0.join("root")).unwrap();
        fs::create_dir(dir.0.join("root-sibling")).unwrap();
        fs::write(dir.0.join("root/file"), b"inside").unwrap();
        let root = Root::new(&dir.0.join("root")).unwrap();
        let file = root.resolve(Path::new("file"), false).unwrap();
        fs::rename(dir.0.join("root/file"), dir.0.join("root-sibling/file")).unwrap();
        fs::write(dir.0.join("root/file"), b"replacement").unwrap();
        assert!(root.check(&file).is_err());
        fs::remove_file(dir.0.join("root-sibling/file")).unwrap();
        assert!(root.check(&file).is_err());
    }

    #[test]
    fn root_descriptor_survives_export_path_replacement() {
        let dir = TestDir::new();
        fs::create_dir(dir.0.join("root")).unwrap();
        fs::write(dir.0.join("root/file"), b"inside").unwrap();
        let root = Root::new(&dir.0.join("root")).unwrap();
        let file = root.resolve(Path::new("file"), false).unwrap();
        fs::rename(dir.0.join("root"), dir.0.join("moved-root")).unwrap();
        fs::create_dir(dir.0.join("root")).unwrap();
        assert!(root.check(&file).is_ok());
    }
}
