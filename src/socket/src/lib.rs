// SPDX-License-Identifier: Apache-2.0
//! Reach sockets in deep directories without moving them or changing cwd.

use std::io;
use std::path::{Path, PathBuf};

/// An address and the private directory that keeps it resolvable.
///
/// Keep this value while advertising its address: a datagram peer may reply
/// to the address returned by recv_from. A connect-only address can be dropped
/// after connecting; a stream listener that publishes the original path can
/// drop it after binding. The actual socket remains in its original parent;
/// dropping this value removes only our temporary directory and symlink.
#[derive(Debug)]
pub struct SocketPath {
    path: PathBuf,
    #[cfg(unix)]
    _directory: Option<tempfile::TempDir>,
}

impl SocketPath {
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            use std::os::unix::{
                ffi::OsStrExt,
                fs::{PermissionsExt, symlink},
            };
            let limit = if cfg!(target_os = "macos") { 103 } else { 107 };
            if path.as_os_str().as_bytes().contains(&0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "socket path contains NUL",
                ));
            }
            if path.as_os_str().len() <= limit {
                return Ok(Self {
                    path: path.into(),
                    _directory: None,
                });
            }
            let name = path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "socket path has no filename")
            })?;
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let parent = parent.canonicalize()?;
            // Ignore TMPDIR: on macOS it is itself often longer than sun_path.
            // tempfile atomically creates an unpredictable, mode-0700 directory.
            let directory = tempfile::Builder::new()
                .prefix("ks-")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in("/tmp")?;
            let alias = directory.path().join("d");
            let address = alias.join(name);
            if address.as_os_str().len() > limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "socket filename exceeds the host address limit",
                ));
            }
            symlink(parent, alias)?;
            Ok(Self {
                path: address,
                _directory: Some(directory),
            })
        }
        #[cfg(not(unix))]
        Ok(Self { path: path.into() })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};

    fn deep_parent() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("a".repeat(80)).join("b".repeat(80))).unwrap();
        root
    }

    fn socket(root: &tempfile::TempDir, name: &str) -> PathBuf {
        root.path()
            .join("a".repeat(80))
            .join("b".repeat(80))
            .join(name)
    }

    #[test]
    fn streams_keep_the_original_inode_and_cleanup_only_the_alias() {
        let root = deep_parent();
        let path = socket(&root, "control.sock");
        let address = SocketPath::new(&path).unwrap();
        let private = address
            .path()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        assert_eq!(
            std::fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let listener = UnixListener::bind(address.path()).unwrap();
        assert!(path.exists());
        let connection = SocketPath::new(&path).unwrap();
        let mut client = UnixStream::connect(connection.path()).unwrap();
        drop(connection);
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(b"hello").unwrap();
        let mut bytes = [0; 5];
        server.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"hello");
        let duplicate = SocketPath::new(&path).unwrap();
        assert_eq!(
            UnixListener::bind(duplicate.path()).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        drop(listener);
        drop(address);
        assert!(!private.exists());
        assert!(path.exists());
        assert!(root.path().exists());
    }

    #[test]
    fn datagram_reply_addresses_remain_reachable_while_bound() {
        let root = deep_parent();
        let left_path = SocketPath::new(socket(&root, "left.sock")).unwrap();
        let right_path = SocketPath::new(socket(&root, "right.sock")).unwrap();
        let left = UnixDatagram::bind(left_path.path()).unwrap();
        let right = UnixDatagram::bind(right_path.path()).unwrap();
        left.set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        right
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        left.send_to(b"ping", right_path.path()).unwrap();
        let mut bytes = [0; 4];
        let (_, peer) = right.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ping");
        right.send_to(b"pong", peer.as_pathname().unwrap()).unwrap();
        left.recv(&mut bytes).unwrap();
        assert_eq!(&bytes, b"pong");
    }

    #[test]
    fn short_and_missing_paths_do_not_create_aliases() {
        let path = Path::new("/tmp/ordinary.sock");
        let address = SocketPath::new(path).unwrap();
        assert_eq!(address.path(), path);
        assert!(address._directory.is_none());
        let root = deep_parent();
        let missing = socket(&root, "absent").join("socket");
        assert_eq!(
            SocketPath::new(missing).err().unwrap().kind(),
            io::ErrorKind::NotFound
        );
    }
}
