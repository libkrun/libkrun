// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Helper for loading a kernel image in the guest memory.

use std;
use std::ffi::CString;
use std::fmt;

use super::cmdline::Error as CmdlineError;
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    BigEndianElfOnLittle,
    InvalidElfMagicNumber,
    InvalidEntryAddress,
    InvalidProgramHeaderSize,
    InvalidProgramHeaderOffset,
    InvalidProgramHeaderAddress,
    ReadKernelDataStruct(&'static str),
    ReadKernelImage,
    SeekKernelStart,
    SeekKernelImage,
    SeekProgramHeader,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Error::BigEndianElfOnLittle => "Unsupported ELF File byte order",
                Error::InvalidElfMagicNumber => "Invalid ELF magic number",
                Error::InvalidEntryAddress => "Invalid entry address found in ELF header",
                Error::InvalidProgramHeaderSize => "Invalid ELF program header size",
                Error::InvalidProgramHeaderOffset => "Invalid ELF program header offset",
                Error::InvalidProgramHeaderAddress => "Invalid ELF program header address",
                Error::ReadKernelDataStruct(e) => e,
                Error::ReadKernelImage => "Failed to write kernel image to guest memory",
                Error::SeekKernelStart => {
                    "Failed to seek to file offset as pointed by the ELF program header"
                }
                Error::SeekKernelImage => "Failed to seek to offset of kernel image",
                Error::SeekProgramHeader => "Failed to seek to ELF program header",
            }
        )
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Writes the command line string to the given memory slice.
///
/// # Arguments
///
/// * `guest_mem` - A u8 slice that will be partially overwritten by the command line.
/// * `guest_addr` - The address in `guest_mem` at which to load the command line.
/// * `cmdline` - The kernel command line as CString.
pub fn load_cmdline(
    guest_mem: &GuestMemoryMmap,
    guest_addr: GuestAddress,
    cmdline: &CString,
) -> std::result::Result<(), CmdlineError> {
    let raw_cmdline = cmdline.as_bytes_with_nul();
    if raw_cmdline.len() <= 1 {
        return Ok(());
    }

    let cmdline_last_addr = guest_addr
        .checked_add(raw_cmdline.len() as u64 - 1)
        .ok_or(CmdlineError::CommandLineOverflow)?; // Extra for null termination.

    if cmdline_last_addr > guest_mem.last_addr() {
        return Err(CmdlineError::CommandLineOverflow);
    }

    guest_mem
        .write_slice(raw_cmdline, guest_addr)
        .map_err(|_| CmdlineError::CommandLineCopy)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::cmdline::Cmdline;
    use super::*;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    const MEM_SIZE: usize = 0x18_0000;

    fn create_guest_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), MEM_SIZE)]).unwrap()
    }

    #[test]
    fn test_cmdline_overflow() {
        let gm = create_guest_mem();
        let cmdline_address = GuestAddress((MEM_SIZE - 5) as u64);
        let mut cmdline = Cmdline::new(10);
        cmdline.insert_str("12345").unwrap();
        let cmdline = cmdline.as_cstring().unwrap();
        assert_eq!(
            Err(CmdlineError::CommandLineOverflow),
            load_cmdline(&gm, cmdline_address, &cmdline)
        );
    }

    #[test]
    fn test_cmdline_write_end() {
        let gm = create_guest_mem();
        let mut cmdline_address = GuestAddress(45);
        let mut cmdline = Cmdline::new(10);
        cmdline.insert_str("1234").unwrap();
        let cmdline = cmdline.as_cstring().unwrap();
        assert_eq!(Ok(()), load_cmdline(&gm, cmdline_address, &cmdline));
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'1');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'2');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'3');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'4');
        cmdline_address = cmdline_address.unchecked_add(1);
        let val: u8 = gm.read_obj(cmdline_address).unwrap();
        assert_eq!(val, b'\0');
    }
}
