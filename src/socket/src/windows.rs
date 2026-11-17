// SPDX-License-Identifier: Apache-2.0
use super::SocketPath;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{CreateDirectoryW, GetShortPathNameW};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath};

const LIMIT: usize = 107;

/// Only remove our junction and empty parent, never recurse into the target.
#[derive(Debug)]
pub(super) struct Alias(PathBuf);

impl Drop for Alias {
    fn drop(&mut self) {
        let _ = fs::remove_dir(self.0.join("d"));
        let _ = fs::remove_dir(&self.0);
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn local_data_directory() -> io::Result<PathBuf> {
    let mut path = ptr::null_mut();
    // SAFETY: valid known-folder identifier and output; null token selects the
    // current user, independently of TEMP and application state overrides.
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, ptr::null_mut(), &mut path) };
    if result < 0 {
        // SAFETY: the API permits freeing a null output on failure.
        unsafe { CoTaskMemFree(path.cast()) };
        return Err(io::Error::other(format!(
            "Windows local application directory unavailable: HRESULT {result:#x}"
        )));
    }
    // SAFETY: on success the API returns a terminated UTF-16 allocation.
    let directory = unsafe {
        let mut length = 0;
        while *path.add(length) != 0 {
            length += 1;
        }
        let directory = OsString::from_wide(std::slice::from_raw_parts(path, length));
        CoTaskMemFree(path.cast());
        directory
    };
    Ok(directory.into())
}

fn short_path(path: &Path) -> io::Result<PathBuf> {
    let input = wide(path);
    // SAFETY: input is terminated; a null output requests the required length.
    let size = unsafe { GetShortPathNameW(input.as_ptr(), ptr::null_mut(), 0) };
    if size == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0; size as usize];
    // SAFETY: buffer has exactly the advertised capacity in UTF-16 units.
    let written = unsafe { GetShortPathNameW(input.as_ptr(), buffer.as_mut_ptr(), size) };
    if written == 0 {
        return Err(io::Error::last_os_error());
    }
    if written >= size {
        return Err(io::Error::other("socket alias directory changed length"));
    }
    Ok(OsString::from_wide(&buffer[..written as usize]).into())
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    // Protected DACL: only the owner and SYSTEM, including inherited children.
    // Install it atomically at creation, before putting a junction inside.
    let sddl: Vec<u16> = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)\0"
        .encode_utf16()
        .collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: terminated SDDL and a valid output pointer; LocalFree below owns
    // the returned allocation on both success and directory-creation failure.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let path = wide(path);
    // SAFETY: path and security descriptor remain valid during the call.
    let result = unsafe { CreateDirectoryW(path.as_ptr(), &attributes) };
    let error = (result == 0).then(io::Error::last_os_error);
    // SAFETY: descriptor was allocated by the conversion API above.
    unsafe { LocalFree(descriptor) };
    error.map_or(Ok(()), Err)
}

pub(super) fn address(path: &Path) -> io::Result<SocketPath> {
    if path.as_os_str().encode_wide().any(|c| c == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path contains NUL",
        ));
    }
    if path.as_os_str().len() <= LIMIT {
        return Ok(SocketPath {
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
    // Use the actual Windows known folder, not TEMP or an application's state
    // override, either of which may itself be arbitrarily deep.
    let mut root = local_data_directory()?;
    let mut random = [0u8; 12];
    getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let directory_name = format!("ks-{suffix}");
    if root
        .join(&directory_name)
        .join("d")
        .join(name)
        .as_os_str()
        .len()
        > LIMIT
    {
        root = short_path(&root)?;
    }
    let directory = root.join(directory_name);
    let address = directory.join("d").join(name);
    if address.as_os_str().len() > LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket filename and Windows alias directory exceed the host address limit",
        ));
    }
    create_private_directory(&directory)?;
    let alias = Alias(directory);
    // Junction creation needs neither Developer Mode nor symlink privilege.
    junction::create(&parent, alias.0.join("d"))?;
    Ok(SocketPath {
        path: address,
        _directory: Some(alias),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::{Domain, SockAddr, Socket, Type};
    use std::io::{Read, Write};
    use std::time::Duration;

    fn assert_private_directory(path: &Path) {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT,
        };
        use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

        let path = wide(path);
        let mut descriptor = ptr::null_mut();
        // SAFETY: valid terminated path and output pointer. The result owns
        // one allocation, released below after converting the actual DACL.
        let result = unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(result, 0);
        let mut text = ptr::null_mut();
        let mut length = 0;
        // SAFETY: descriptor was returned above; text and length are outputs.
        let result = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                &mut length,
            )
        };
        unsafe { LocalFree(descriptor) };
        assert_ne!(result, 0);
        // SAFETY: returned length includes the terminating NUL.
        let sddl = unsafe {
            String::from_utf16_lossy(std::slice::from_raw_parts(text, length as usize - 1))
        };
        unsafe { LocalFree(text.cast()) };
        assert!(sddl.starts_with("D:P"), "{sddl}");
        assert!(sddl.contains(";;;OW)"), "{sddl}");
        assert!(sddl.contains(";;;SY)"), "{sddl}");
        assert_eq!(sddl.matches('(').count(), 2, "{sddl}");
    }

    #[test]
    fn independent_aliases_keep_the_socket_and_remove_only_the_junction() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("long workspace-é".repeat(8));
        fs::create_dir(&target).unwrap();
        let path = target.join("agent.sock");
        assert!(path.as_os_str().len() > LIMIT);
        fs::write(target.join("keep"), "machine data").unwrap();
        let address = SocketPath::new(&path).unwrap();
        let directory = address._directory.as_ref().unwrap().0.clone();
        assert_private_directory(&directory);
        assert!(address.path().as_os_str().len() <= LIMIT);
        let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        listener
            .bind(&SockAddr::unix(address.path()).unwrap())
            .unwrap();
        listener.listen(2).unwrap();
        drop(address);
        assert!(!directory.exists());
        assert!(path.exists());
        let connection = SocketPath::new(&path).unwrap();
        let mut client = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        client
            .connect_timeout(
                &SockAddr::unix(connection.path()).unwrap(),
                Duration::from_secs(2),
            )
            .unwrap();
        drop(connection);
        let (mut server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"ping").unwrap();
        let mut bytes = [0; 4];
        server.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ping");
        let duplicate = SocketPath::new(&path).unwrap();
        let duplicate_listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        assert_eq!(
            duplicate_listener
                .bind(&SockAddr::unix(duplicate.path()).unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrInUse
        );
        drop(duplicate);
        drop(server);
        drop(client);
        drop(listener);
        assert_eq!(
            fs::read_to_string(target.join("keep")).unwrap(),
            "machine data"
        );
        assert!(path.exists());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn short_paths_stay_unchanged_and_invalid_paths_fail_before_aliasing() {
        let path = Path::new(r"C:\ordinary.sock");
        let address = SocketPath::new(path).unwrap();
        assert_eq!(address.path(), path);
        assert!(address._directory.is_none());
        assert_eq!(
            SocketPath::new("bad\0socket").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing".repeat(20)).join("agent.sock");
        assert_eq!(
            SocketPath::new(missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let too_long = root.path().join("s".repeat(110));
        assert_eq!(
            SocketPath::new(too_long).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
