// SPDX-License-Identifier: Apache-2.0
//
//! Control protocol between the host and the guest init.
//!
//! The guest init listens on a vsock port; the VMM maps that port to a Unix
//! socket on the host. Every connection starts with a [`Request::Hello`] /
//! [`Response::Hello`] exchange and then carries exactly one of:
//!
//! - an [`Request::Exec`] followed by a stream of stdin, resize and signal
//!   requests, answered by a stream of output messages ending in
//!   [`Response::Exited`];
//! - a [`Request::SignalEntrypoint`], answered by [`Response::Ok`].
//!
//! Messages are bincode-encoded serde values, one after the other, with no
//! extra framing: the decoder knows where each message ends.

use std::io::{self, Read, Write};

use bincode::config::{Configuration, Limit, LittleEndian, Varint};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

/// Default guest vsock port of the control server (ASCII "KRUN").
pub const DEFAULT_VSOCK_PORT: u32 = 0x4b52554e;

/// Upper bound for a single message, so a misbehaving peer cannot make the
/// other side allocate arbitrary amounts of memory.
pub const MAX_MESSAGE_LEN: usize = 1 << 20;

/// Payload size used for stdio chunks, comfortably below [`MAX_MESSAGE_LEN`].
pub const IO_CHUNK_LEN: usize = 64 * 1024;

const CONFIG: Configuration<LittleEndian, Varint, Limit<MAX_MESSAGE_LEN>> =
    bincode::config::standard().with_limit::<MAX_MESSAGE_LEN>();

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowSize {
    pub rows: u16,
    pub cols: u16,
}

/// What to run and how, mirroring the OCI process spec as far as the guest
/// applies it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecSpec {
    /// Path of the executable; `args[0]` is only what the process sees as argv[0].
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub additional_gids: Vec<u32>,
    pub umask: Option<u32>,
    /// Allocate a pseudo-terminal of this size instead of pipes.
    pub tty: Option<WindowSize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Hello { version: u32 },
    Exec(ExecSpec),
    SignalEntrypoint { signal: i32 },
    Stdin(Vec<u8>),
    StdinEof,
    Resize(WindowSize),
    Signal { signal: i32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitStatus {
    Exited(i32),
    Signaled(i32),
}

impl ExitStatus {
    /// The code a shell would report: the exit code, or 128 plus the signal.
    pub fn shell_code(self) -> i32 {
        match self {
            ExitStatus::Exited(code) => code & 0xff,
            ExitStatus::Signaled(signal) => 128 + signal,
        }
    }
}

/// Why the guest could not carry out a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub errno: i32,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Hello { version: u32 },
    Started { pid: i32 },
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exited(ExitStatus),
    Failed(Failure),
    Ok,
}

pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    bincode::serde::encode_to_vec(value, CONFIG).expect("control messages always encode")
}

pub fn write<T: Serialize>(writer: &mut impl Write, value: &T) -> io::Result<()> {
    writer.write_all(&encode(value))
}

pub fn read<T: for<'de> Deserialize<'de>>(reader: &mut impl Read) -> io::Result<T> {
    bincode::serde::decode_from_std_read(reader, CONFIG).map_err(|e| match e {
        bincode::error::DecodeError::Io { inner, .. } => inner,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_through_a_stream() {
        let spec = ExecSpec {
            program: "/bin/sh".into(),
            args: vec!["sh".into(), "-c".into(), "exit 7".into()],
            env: vec!["FOO=bar".into()],
            cwd: Some("/tmp".into()),
            uid: Some(1000),
            gid: None,
            additional_gids: vec![10, 20],
            umask: Some(0o22),
            tty: Some(WindowSize { rows: 24, cols: 80 }),
        };
        let mut buf = Vec::new();
        write(
            &mut buf,
            &Request::Hello {
                version: PROTOCOL_VERSION,
            },
        )
        .unwrap();
        write(&mut buf, &Request::Exec(spec.clone())).unwrap();
        write(&mut buf, &Request::Stdin(vec![0u8; 3])).unwrap();

        let mut reader = buf.as_slice();
        assert_eq!(
            read::<Request>(&mut reader).unwrap(),
            Request::Hello {
                version: PROTOCOL_VERSION
            }
        );
        assert_eq!(read::<Request>(&mut reader).unwrap(), Request::Exec(spec));
        assert_eq!(
            read::<Request>(&mut reader).unwrap(),
            Request::Stdin(vec![0u8; 3])
        );
        assert_eq!(
            read::<Request>(&mut reader).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn oversized_message_is_rejected() {
        let msg = encode(&Response::Stdout(vec![1u8; MAX_MESSAGE_LEN + 1]));
        let err = read::<Response>(&mut msg.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn shell_codes() {
        assert_eq!(ExitStatus::Exited(7).shell_code(), 7);
        assert_eq!(ExitStatus::Signaled(15).shell_code(), 143);
    }
}
