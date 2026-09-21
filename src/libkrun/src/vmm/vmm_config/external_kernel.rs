// Copyright 2024, Red Hat Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[cfg_attr(feature = "ffi", ffier::export)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(unused)]
pub enum KernelFormat {
    // ELF image, need to locale sections be loaded.
    Elf = 0,
    // Raw image, ready to be loaded into the VM.
    #[default]
    Raw = 1,
    // Raw image compressed with GZIP, embedded into a PE file.
    PeGz = 2,
    // ELF image compressed with BZIP2, embedded into an Image file.
    ImageBz2 = 3,
    // ELF image compressed with GZIP, embedded into an Image file.
    ImageGz = 4,
    // ELF image compressed with ZSTD, embedded into an Image file.
    ImageZstd = 5,
}

/// Data structure holding the attributes read from the `libkrunfw` kernel config.
#[derive(Clone, Debug, Default)]
#[allow(unused)]
pub struct ExternalKernel {
    pub path: PathBuf,
    pub format: KernelFormat,
    pub initramfs_path: Option<PathBuf>,
    pub initramfs_size: u64,
    pub cmdline: Option<String>,
}
