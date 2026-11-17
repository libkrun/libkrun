//! Guest RAM files this VMM created, whose surrendered pages may be released
//! back to the host by punching them out of the file.
//!
//! A branchable machine's RAM is a file (a memfd on Linux, a temp file on
//! macOS) mapped shared, so dropping a page table entry frees nothing: the page
//! lives on in the file. Releasing it means removing it from the file, which is
//! only safe while no other process maps that file. Checkpoint generations are
//! independent copies (a sealed memfd, an APFS clone) and restored clones map
//! someone else's file, so neither is ever released here. The one way another
//! process maps a live RAM file is a frozen-golden fork, which marks the RAM
//! shared before it freezes, and from then on nothing is punched.

use std::fs::File;
use std::sync::{Mutex, RwLock};

/// `(device, inode)` of every guest-RAM file this VMM created.
static OWNED: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());

/// Set once this VMM's live RAM files are mapped by another process.
static SHARED: RwLock<bool> = RwLock::new(false);

#[cfg(unix)]
fn identity(file: &File) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().ok()?;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn identity(_file: &File) -> Option<(u64, u64)> {
    None
}

/// Record a guest-RAM file this VMM created and maps shared.
pub fn register_owned_guest_ram_file(file: &File) {
    if let Some(id) = identity(file) {
        OWNED.lock().unwrap_or_else(|e| e.into_inner()).push(id);
    }
}

/// Stop releasing pages from owned RAM files: another process is about to map
/// them. Waits for any release already in progress.
pub fn mark_guest_ram_shared() {
    *SHARED.write().unwrap_or_else(|e| e.into_inner()) = true;
}

/// Run `release` if `file` is a RAM file this VMM owns and has not shared,
/// holding off [`mark_guest_ram_shared`] until it returns. `None` otherwise.
#[cfg(unix)]
pub(crate) fn with_owned_backing<R>(file: &File, release: impl FnOnce() -> R) -> Option<R> {
    let shared = SHARED.read().unwrap_or_else(|e| e.into_inner());
    if *shared {
        return None;
    }
    let id = identity(file)?;
    if !OWNED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&id)
    {
        return None;
    }
    Some(release())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // One test owns the statics: they are process-wide.
    #[test]
    fn only_owned_unshared_files_are_released() {
        let owned = tempfile_in_tmp("owned");
        let foreign = tempfile_in_tmp("foreign");
        register_owned_guest_ram_file(&owned);
        assert_eq!(with_owned_backing(&owned, || 1), Some(1));
        assert_eq!(
            with_owned_backing(&foreign, || 1),
            None,
            "a clone maps another's file"
        );
        mark_guest_ram_shared();
        assert_eq!(
            with_owned_backing(&owned, || 1),
            None,
            "shared with a frozen fork"
        );
    }

    fn tempfile_in_tmp(tag: &str) -> File {
        let path =
            std::env::temp_dir().join(format!("owned-ram-test-{tag}-{}", std::process::id()));
        let file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let _ = std::fs::remove_file(&path);
        file
    }
}
