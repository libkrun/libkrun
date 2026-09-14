use std::io;
use std::os::windows::io::{AsRawSocket, FromRawSocket, OwnedSocket, RawSocket};
use std::path::PathBuf;

use vm_memory::{Bytes, GuestMemory, GuestMemoryMmap, Permissions};
use windows_sys::Win32::Networking::WinSock::{
    AF_UNIX, FIONBIO, INVALID_SOCKET, SO_RCVBUF, SO_SNDBUF, SOCK_STREAM, SOCKADDR_UN, SOCKET,
    SOCKET_ERROR, SOL_SOCKET, WSACleanup, WSADATA, WSAEWOULDBLOCK, WSAGetLastError, WSAStartup,
    connect, ioctlsocket, recv, send, setsockopt, socket,
};

use super::super::backend::{ReadError, WriteError, WriteStatus};
use super::super::{MAX_BUFFER_SIZE, VNET_HDR_LEN};
use super::Unixstream;
use crate::virtio::net::backend::ConnectError;

pub type RawStreamHandle = OwnedSocket;

const FRAME_HEADER_LEN: usize = 4;
const MAX_PROXY_PAYLOAD_SIZE: usize = MAX_BUFFER_SIZE - VNET_HDR_LEN;
const SOCKET_BUFFER_SIZE: i32 = 8 * 1024 * 1024;
const TX_BUFFER_SIZE: usize = FRAME_HEADER_LEN + MAX_PROXY_PAYLOAD_SIZE;
const RX_BUFFER_SIZE: usize = FRAME_HEADER_LEN + MAX_PROXY_PAYLOAD_SIZE;

pub(crate) enum RxTerminal {
    Closed,
    Error(io::Error),
}

pub(crate) struct WinsockGuard;

impl WinsockGuard {
    fn new() -> io::Result<Self> {
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        let result = unsafe { WSAStartup(0x0202, &mut data) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        Ok(Self)
    }
}

impl Drop for WinsockGuard {
    fn drop(&mut self) {
        unsafe {
            WSACleanup();
        }
    }
}

fn last_socket_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

fn set_nonblocking(socket: &OwnedSocket) -> io::Result<()> {
    let mut mode = 1;
    let result = unsafe { ioctlsocket(socket.as_raw_socket() as SOCKET, FIONBIO, &mut mode) };
    if result == SOCKET_ERROR {
        return Err(last_socket_error());
    }
    Ok(())
}

fn set_socket_buffer(socket: &OwnedSocket, option: i32, name: &str) {
    let value = SOCKET_BUFFER_SIZE;
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            SOL_SOCKET,
            option,
            &value as *const i32 as *const u8,
            size_of_val(&value) as i32,
        )
    };
    if result == SOCKET_ERROR {
        log::warn!("failed to increase {name}: {}", last_socket_error());
    }
}

pub(crate) fn create(socket: OwnedSocket) -> Result<Unixstream, ConnectError> {
    let winsock = WinsockGuard::new().map_err(ConnectError::CreateSocket)?;
    if let Err(error) = set_nonblocking(&socket) {
        drop(socket);
        drop(winsock);
        return Err(ConnectError::CreateSocket(error));
    }
    set_socket_buffer(&socket, SO_RCVBUF, "SO_RCVBUF");
    set_socket_buffer(&socket, SO_SNDBUF, "SO_SNDBUF");
    Ok(Unixstream {
        fd: socket,
        _winsock: winsock,
        tx_buffer: vec![0; TX_BUFFER_SIZE].into_boxed_slice(),
        tx_len: 0,
        tx_offset: 0,
        rx_buffer: vec![0; RX_BUFFER_SIZE],
        rx_frame_buffer: vec![0; MAX_BUFFER_SIZE].into_boxed_slice(),
        rx_buf_end: 0,
        rx_terminal: None,
    })
}

pub(crate) fn open(path: PathBuf) -> Result<Unixstream, ConnectError> {
    let path = path.to_str().ok_or_else(|| {
        ConnectError::InvalidAddress(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AF_UNIX path is not UTF-8",
        ))
    })?;
    let path_bytes = path.as_bytes();
    let path_capacity = unsafe { std::mem::zeroed::<SOCKADDR_UN>() }.sun_path.len();
    if path_bytes.contains(&0) || path_bytes.len() >= path_capacity {
        return Err(ConnectError::InvalidAddress(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AF_UNIX path is too long or contains a NUL byte",
        )));
    }

    let _winsock = WinsockGuard::new().map_err(ConnectError::CreateSocket)?;
    let raw_socket = unsafe { socket(AF_UNIX as i32, SOCK_STREAM, 0) };
    if raw_socket == INVALID_SOCKET {
        return Err(ConnectError::CreateSocket(last_socket_error()));
    }
    let socket = unsafe { OwnedSocket::from_raw_socket(raw_socket as RawSocket) };

    let mut address: SOCKADDR_UN = unsafe { std::mem::zeroed() };
    address.sun_family = AF_UNIX;
    for (destination, source) in address.sun_path.iter_mut().zip(path_bytes) {
        *destination = *source as i8;
    }
    let result = unsafe {
        connect(
            socket.as_raw_socket() as SOCKET,
            &address as *const SOCKADDR_UN as *const _,
            size_of::<SOCKADDR_UN>() as i32,
        )
    };
    if result == SOCKET_ERROR {
        return Err(ConnectError::Binding(last_socket_error()));
    }

    create(socket)
}

fn terminal_error(stream: &mut Unixstream) -> ReadError {
    match stream
        .rx_terminal
        .take()
        .expect("terminal state must exist")
    {
        RxTerminal::Closed => ReadError::ProcessNotRunning,
        RxTerminal::Error(error) => ReadError::Internal(error),
    }
}

fn receive(stream: &mut Unixstream) {
    while stream.rx_terminal.is_none() && stream.rx_buf_end < stream.rx_buffer.len() {
        let available = stream.rx_buffer.len() - stream.rx_buf_end;
        let result = unsafe {
            recv(
                stream.fd.as_raw_socket() as SOCKET,
                stream.rx_buffer.as_mut_ptr().add(stream.rx_buf_end),
                available as i32,
                0,
            )
        };
        if result > 0 {
            stream.rx_buf_end += result as usize;
        } else if result == 0 {
            stream.rx_terminal = Some(RxTerminal::Closed);
        } else {
            let error = unsafe { WSAGetLastError() };
            if error != WSAEWOULDBLOCK {
                stream.rx_terminal = Some(RxTerminal::Error(io::Error::from_raw_os_error(error)));
            }
            break;
        }
    }
}

pub(crate) fn read_frames_to_guest(
    stream: &mut Unixstream,
    mem: &GuestMemoryMmap,
    rx_queue: &mut crate::virtio::queue::Queue,
) -> Result<u32, ReadError> {
    receive(stream);

    let mut cursor = 0;
    let mut frames_processed = 0;
    while cursor + FRAME_HEADER_LEN <= stream.rx_buf_end {
        let payload_len = u32::from_be_bytes(
            stream.rx_buffer[cursor..cursor + FRAME_HEADER_LEN]
                .try_into()
                .expect("frame header has a fixed length"),
        ) as usize;
        if payload_len > MAX_PROXY_PAYLOAD_SIZE {
            stream.rx_buf_end = 0;
            return Err(ReadError::Internal(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("network proxy frame is too large: {payload_len} bytes"),
            )));
        }
        let framed_len = FRAME_HEADER_LEN + payload_len;
        if stream.rx_buf_end - cursor < framed_len {
            break;
        }

        let head = match rx_queue.pop(mem) {
            Some(head) => head,
            None => {
                if cursor != 0 {
                    stream.rx_buffer.copy_within(cursor..stream.rx_buf_end, 0);
                    stream.rx_buf_end -= cursor;
                }
                return if frames_processed == 0 {
                    Err(ReadError::DescriptorStarvation)
                } else {
                    Ok(frames_processed)
                };
            }
        };
        let head_index = head.index;
        let required_len = VNET_HDR_LEN + payload_len;
        let mut descriptors = Vec::new();
        let mut capacity = 0usize;
        let mut valid = true;
        let mut descriptor = Some(head);
        while let Some(current) = descriptor {
            let len = current.len as usize;
            if !current.is_write_only()
                || !mem.check_range(current.addr, len, Permissions::Write)
                || capacity.checked_add(len).is_none()
            {
                valid = false;
            } else {
                capacity += len;
                descriptors.push((current.addr, len));
            }
            descriptor = current.next_descriptor();
        }

        if !valid || capacity < required_len {
            rx_queue
                .add_used(mem, head_index, 0)
                .map_err(ReadError::Queue)?;
            cursor += framed_len;
            frames_processed += 1;
            continue;
        }

        let payload =
            &stream.rx_buffer[cursor + FRAME_HEADER_LEN..cursor + FRAME_HEADER_LEN + payload_len];
        let frame = &mut stream.rx_frame_buffer[..required_len];
        frame.fill(0);
        frame[VNET_HDR_LEN..].copy_from_slice(payload);
        let mut written = 0;
        for (address, len) in descriptors {
            if written == required_len {
                break;
            }
            let count = len.min(required_len - written);
            if let Err(error) = mem.write_slice(&frame[written..written + count], address) {
                rx_queue
                    .add_used(mem, head_index, 0)
                    .map_err(ReadError::Queue)?;
                return Err(ReadError::Internal(io::Error::other(error.to_string())));
            }
            written += count;
        }
        rx_queue
            .add_used(mem, head_index, required_len as u32)
            .map_err(ReadError::Queue)?;
        cursor += framed_len;
        frames_processed += 1;
    }

    if cursor != 0 {
        stream.rx_buffer.copy_within(cursor..stream.rx_buf_end, 0);
        stream.rx_buf_end -= cursor;
    }
    if frames_processed != 0 {
        return Ok(frames_processed);
    }
    if stream.rx_terminal.is_some() {
        if stream.rx_buf_end != 0 {
            stream.rx_buf_end = 0;
            return match stream
                .rx_terminal
                .take()
                .expect("terminal state must exist")
            {
                RxTerminal::Closed => Err(ReadError::Internal(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "network proxy closed with an incomplete frame",
                ))),
                RxTerminal::Error(error) => Err(ReadError::Internal(error)),
            };
        }
        return Err(terminal_error(stream));
    }
    Err(ReadError::NothingRead)
}

pub(crate) fn prepare_tx_buffer(stream: &mut Unixstream) -> &mut [u8] {
    &mut stream.tx_buffer
}

fn flush_tx(stream: &mut Unixstream) -> Result<WriteStatus, WriteError> {
    while stream.tx_offset < stream.tx_len {
        let remaining = &stream.tx_buffer[stream.tx_offset..stream.tx_len];
        let result = unsafe {
            send(
                stream.fd.as_raw_socket() as SOCKET,
                remaining.as_ptr(),
                remaining.len() as i32,
                0,
            )
        };
        if result > 0 {
            stream.tx_offset += result as usize;
        } else if result == 0 {
            return Err(WriteError::ProcessNotRunning);
        } else {
            let error = unsafe { WSAGetLastError() };
            if error == WSAEWOULDBLOCK {
                return Ok(WriteStatus::Pending);
            }
            return Err(WriteError::Internal(io::Error::from_raw_os_error(error)));
        }
    }
    stream.tx_len = 0;
    stream.tx_offset = 0;
    Ok(WriteStatus::Complete)
}

pub(crate) fn start_tx(
    stream: &mut Unixstream,
    total_bytes: usize,
) -> Result<WriteStatus, WriteError> {
    if stream.tx_len != 0 || total_bytes > stream.tx_buffer.len() {
        return Err(WriteError::Internal(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid TX buffer state",
        )));
    }
    stream.tx_len = total_bytes;
    stream.tx_offset = 0;
    flush_tx(stream)
}

pub(crate) fn resume_tx(stream: &mut Unixstream) -> Result<WriteStatus, WriteError> {
    flush_tx(stream)
}

pub(crate) fn raw_socket_fd(socket: &OwnedSocket) -> RawSocket {
    socket.as_raw_socket()
}
