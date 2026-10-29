pub mod fs_utils;
pub mod passthrough;

mod confined;
mod restricted;

#[cfg(test)]
mod test_utils {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    pub(super) struct TestDir(pub PathBuf);

    impl TestDir {
        pub(super) fn new() -> Self {
            let path = env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("libkrun-fs-{:016x}", rand::random::<u64>()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
