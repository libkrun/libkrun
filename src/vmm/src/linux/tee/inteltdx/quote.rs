use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{Ordering, fence};
use std::time::Duration;

use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

pub const TDVMCALL_GET_QUOTE: u64 = 0x10002;
pub const TDVMCALL_STATUS_SUCCESS: u64 = 0;
pub const TDVMCALL_STATUS_INVALID_OPERAND: u64 = 0x8000_0000_0000_0000;
pub const TDVMCALL_STATUS_ALIGN_ERROR: u64 = 0x8000_0000_0000_0002;

const GET_QUOTE_STRUCTURE_VERSION: u64 = 1;
const GET_QUOTE_HEADER_SIZE: usize = 24;
const GET_QUOTE_MAX_BUFFER_SIZE: usize = 128 * 1024;
const GET_QUOTE_SUCCESS: u64 = 0;
const GET_QUOTE_IN_FLIGHT: u64 = u64::MAX;
const GET_QUOTE_ERROR: u64 = 0x8000_0000_0000_0000;
const GET_QUOTE_QGS_UNAVAILABLE: u64 = 0x8000_0000_0000_0001;

const QGS_FRAME_HEADER_SIZE: usize = 4;
const QGS_GET_QUOTE_MESSAGE_SIZE: usize = 24;
const QGS_MAJOR_VERSION: u16 = 1;
const QGS_MINOR_VERSION: u16 = 1;
const QGS_GET_QUOTE_REQUEST: u32 = 0;
const QGS_GET_QUOTE_RESPONSE: u32 = 1;
const QGS_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct QuoteGenerator {
    socket: PathBuf,
}

impl QuoteGenerator {
    pub fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    fn generate(&self, report: &[u8], quote_capacity: usize) -> Result<Vec<u8>, QuoteError> {
        let mut stream = UnixStream::connect(&self.socket).map_err(QuoteError::Connect)?;
        stream
            .set_read_timeout(Some(QGS_TIMEOUT))
            .map_err(QuoteError::ConfigureSocket)?;
        stream
            .set_write_timeout(Some(QGS_TIMEOUT))
            .map_err(QuoteError::ConfigureSocket)?;

        let request = encode_request(report)?;
        stream.write_all(&request).map_err(QuoteError::Write)?;
        read_response(&mut stream, quote_capacity)
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

#[derive(Debug)]
enum QuoteError {
    Connect(io::Error),
    ConfigureSocket(io::Error),
    Write(io::Error),
    Read(io::Error),
    InvalidMessage,
    MessageTooLarge,
}

impl QuoteError {
    fn status(&self) -> u64 {
        if matches!(self, Self::Connect(_)) {
            GET_QUOTE_QGS_UNAVAILABLE
        } else {
            GET_QUOTE_ERROR
        }
    }
}

impl std::fmt::Display for QuoteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(error) => write!(formatter, "connect to QGS: {error}"),
            Self::ConfigureSocket(error) => write!(formatter, "configure QGS socket: {error}"),
            Self::Write(error) => write!(formatter, "write QGS request: {error}"),
            Self::Read(error) => write!(formatter, "read QGS response: {error}"),
            Self::InvalidMessage => write!(formatter, "QGS returned an invalid response"),
            Self::MessageTooLarge => write!(formatter, "QGS message exceeds the GetQuote buffer"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GetQuoteHeader {
    structure_version: u64,
    error_code: u64,
    in_len: u32,
    out_len: u32,
}

impl GetQuoteHeader {
    fn decode(bytes: &[u8; GET_QUOTE_HEADER_SIZE]) -> Self {
        Self {
            structure_version: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            error_code: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            in_len: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            out_len: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
        }
    }

    fn encode(self) -> [u8; GET_QUOTE_HEADER_SIZE] {
        let mut bytes = [0; GET_QUOTE_HEADER_SIZE];
        bytes[0..8].copy_from_slice(&self.structure_version.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.error_code.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.in_len.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.out_len.to_le_bytes());
        bytes
    }
}

pub fn handle_get_quote(
    guest_memory: &GuestMemoryMmap,
    generator: Option<&QuoteGenerator>,
    gpa: u64,
    size: u64,
) -> u64 {
    let Ok(size) = usize::try_from(size) else {
        return TDVMCALL_STATUS_INVALID_OPERAND;
    };
    if size == 0 || size > GET_QUOTE_MAX_BUFFER_SIZE {
        return TDVMCALL_STATUS_INVALID_OPERAND;
    }
    if gpa & 4095 != 0 || size & 4095 != 0 {
        return TDVMCALL_STATUS_ALIGN_ERROR;
    }

    let address = GuestAddress(gpa);
    let mut header_bytes = [0; GET_QUOTE_HEADER_SIZE];
    if guest_memory.read_slice(&mut header_bytes, address).is_err() {
        return TDVMCALL_STATUS_INVALID_OPERAND;
    }
    let mut header = GetQuoteHeader::decode(&header_bytes);
    let input_size = header.in_len as usize;
    let payload_capacity = size - GET_QUOTE_HEADER_SIZE;
    if header.structure_version != GET_QUOTE_STRUCTURE_VERSION
        || header.error_code != 0
        || header.out_len != 0
        || input_size == 0
        || input_size > payload_capacity
    {
        return TDVMCALL_STATUS_INVALID_OPERAND;
    }

    let payload_address = address.unchecked_add(GET_QUOTE_HEADER_SIZE as u64);
    let mut report = vec![0; input_size];
    if guest_memory
        .read_slice(&mut report, payload_address)
        .is_err()
    {
        return TDVMCALL_STATUS_INVALID_OPERAND;
    }

    let Some(generator) = generator else {
        header.error_code = GET_QUOTE_QGS_UNAVAILABLE;
        return publish_header(guest_memory, address, header);
    };

    header.error_code = GET_QUOTE_IN_FLIGHT;
    if guest_memory.write_slice(&header.encode(), address).is_err() {
        return TDVMCALL_STATUS_INVALID_OPERAND;
    }

    match generator.generate(&report, payload_capacity) {
        Ok(quote) => {
            if guest_memory.write_slice(&quote, payload_address).is_err() {
                return TDVMCALL_STATUS_INVALID_OPERAND;
            }
            header.out_len = quote.len() as u32;
            header.error_code = GET_QUOTE_SUCCESS;
        }
        Err(error) => {
            log::error!(
                "TDX GetQuote through {} failed: {error}",
                generator.socket().display()
            );
            header.error_code = error.status();
        }
    }

    fence(Ordering::Release);
    publish_header(guest_memory, address, header)
}

fn publish_header(
    guest_memory: &GuestMemoryMmap,
    address: GuestAddress,
    header: GetQuoteHeader,
) -> u64 {
    if guest_memory.write_slice(&header.encode(), address).is_err() {
        TDVMCALL_STATUS_INVALID_OPERAND
    } else {
        TDVMCALL_STATUS_SUCCESS
    }
}

fn encode_request(report: &[u8]) -> Result<Vec<u8>, QuoteError> {
    let report_size = u32::try_from(report.len()).map_err(|_| QuoteError::MessageTooLarge)?;
    let message_size = QGS_GET_QUOTE_MESSAGE_SIZE
        .checked_add(report.len())
        .ok_or(QuoteError::MessageTooLarge)?;
    let message_size = u32::try_from(message_size).map_err(|_| QuoteError::MessageTooLarge)?;

    let mut request = Vec::with_capacity(QGS_FRAME_HEADER_SIZE + message_size as usize);
    request.extend_from_slice(&message_size.to_be_bytes());
    request.extend_from_slice(&QGS_MAJOR_VERSION.to_le_bytes());
    request.extend_from_slice(&QGS_MINOR_VERSION.to_le_bytes());
    request.extend_from_slice(&QGS_GET_QUOTE_REQUEST.to_le_bytes());
    request.extend_from_slice(&message_size.to_le_bytes());
    request.extend_from_slice(&0u32.to_le_bytes());
    request.extend_from_slice(&report_size.to_le_bytes());
    request.extend_from_slice(&0u32.to_le_bytes());
    request.extend_from_slice(report);
    Ok(request)
}

fn read_response(stream: &mut UnixStream, quote_capacity: usize) -> Result<Vec<u8>, QuoteError> {
    let mut frame_header = [0; QGS_FRAME_HEADER_SIZE];
    stream
        .read_exact(&mut frame_header)
        .map_err(QuoteError::Read)?;
    let message_size = u32::from_be_bytes(frame_header) as usize;
    let maximum_message_size = QGS_GET_QUOTE_MESSAGE_SIZE
        .checked_add(quote_capacity)
        .ok_or(QuoteError::MessageTooLarge)?;
    if message_size < QGS_GET_QUOTE_MESSAGE_SIZE || message_size > maximum_message_size {
        return Err(QuoteError::MessageTooLarge);
    }

    let mut response = vec![0; message_size];
    stream.read_exact(&mut response).map_err(QuoteError::Read)?;
    let major = u16::from_le_bytes(response[0..2].try_into().unwrap());
    let minor = u16::from_le_bytes(response[2..4].try_into().unwrap());
    let message_type = u32::from_le_bytes(response[4..8].try_into().unwrap());
    let declared_size = u32::from_le_bytes(response[8..12].try_into().unwrap()) as usize;
    let error_code = u32::from_le_bytes(response[12..16].try_into().unwrap());
    let selected_id_size = u32::from_le_bytes(response[16..20].try_into().unwrap());
    let quote_size = u32::from_le_bytes(response[20..24].try_into().unwrap()) as usize;
    if major != QGS_MAJOR_VERSION
        || minor != QGS_MINOR_VERSION
        || message_type != QGS_GET_QUOTE_RESPONSE
        || declared_size != message_size
        || error_code != 0
        || selected_id_size != 0
        || quote_size == 0
        || quote_size != message_size - QGS_GET_QUOTE_MESSAGE_SIZE
    {
        return Err(QuoteError::InvalidMessage);
    }

    Ok(response[QGS_GET_QUOTE_MESSAGE_SIZE..].to_vec())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::net::UnixListener;
    use std::process;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::*;

    fn memory() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 256 * 1024)]).unwrap()
    }

    fn request_header(input_size: u32) -> GetQuoteHeader {
        GetQuoteHeader {
            structure_version: GET_QUOTE_STRUCTURE_VERSION,
            error_code: 0,
            in_len: input_size,
            out_len: 0,
        }
    }

    #[test]
    fn rejects_unaligned_and_oversized_buffers() {
        let memory = memory();
        assert_eq!(
            handle_get_quote(&memory, None, 1, 4096),
            TDVMCALL_STATUS_ALIGN_ERROR
        );
        assert_eq!(
            handle_get_quote(&memory, None, 0, (GET_QUOTE_MAX_BUFFER_SIZE + 4096) as u64),
            TDVMCALL_STATUS_INVALID_OPERAND
        );
    }

    #[test]
    fn reports_unavailable_qgs_in_the_shared_header() {
        let memory = memory();
        let header = request_header(8);
        memory
            .write_slice(&header.encode(), GuestAddress(0))
            .unwrap();
        memory
            .write_slice(&[7; 8], GuestAddress(GET_QUOTE_HEADER_SIZE as u64))
            .unwrap();

        assert_eq!(
            handle_get_quote(&memory, None, 0, 4096),
            TDVMCALL_STATUS_SUCCESS
        );
        let mut actual = [0; GET_QUOTE_HEADER_SIZE];
        memory.read_slice(&mut actual, GuestAddress(0)).unwrap();
        assert_eq!(
            GetQuoteHeader::decode(&actual).error_code,
            GET_QUOTE_QGS_UNAVAILABLE
        );
    }

    #[test]
    fn relays_report_and_publishes_quote() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("libkrun-tdx-quote-{}-{nonce}", process::id()));
        fs::create_dir(&directory).unwrap();
        let socket = directory.join("qgs.socket");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut frame_header = [0; QGS_FRAME_HEADER_SIZE];
            stream.read_exact(&mut frame_header).unwrap();
            let size = u32::from_be_bytes(frame_header) as usize;
            let mut request = vec![0; size];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request[QGS_GET_QUOTE_MESSAGE_SIZE..], &[9; 16]);

            let quote = [5; 64];
            let response_size = QGS_GET_QUOTE_MESSAGE_SIZE + quote.len();
            let mut response = Vec::new();
            response.extend_from_slice(&(response_size as u32).to_be_bytes());
            response.extend_from_slice(&QGS_MAJOR_VERSION.to_le_bytes());
            response.extend_from_slice(&QGS_MINOR_VERSION.to_le_bytes());
            response.extend_from_slice(&QGS_GET_QUOTE_RESPONSE.to_le_bytes());
            response.extend_from_slice(&(response_size as u32).to_le_bytes());
            response.extend_from_slice(&0u32.to_le_bytes());
            response.extend_from_slice(&0u32.to_le_bytes());
            response.extend_from_slice(&(quote.len() as u32).to_le_bytes());
            response.extend_from_slice(&quote);
            stream.write_all(&response).unwrap();
        });

        let memory = memory();
        memory
            .write_slice(&request_header(16).encode(), GuestAddress(0))
            .unwrap();
        memory
            .write_slice(&[9; 16], GuestAddress(GET_QUOTE_HEADER_SIZE as u64))
            .unwrap();
        let generator = QuoteGenerator::new(socket.clone());

        assert_eq!(
            handle_get_quote(&memory, Some(&generator), 0, 4096),
            TDVMCALL_STATUS_SUCCESS
        );
        server.join().unwrap();

        let mut actual_header = [0; GET_QUOTE_HEADER_SIZE];
        memory
            .read_slice(&mut actual_header, GuestAddress(0))
            .unwrap();
        let actual_header = GetQuoteHeader::decode(&actual_header);
        assert_eq!(actual_header.error_code, GET_QUOTE_SUCCESS);
        assert_eq!(actual_header.out_len, 64);
        let mut quote = [0; 64];
        memory
            .read_slice(&mut quote, GuestAddress(GET_QUOTE_HEADER_SIZE as u64))
            .unwrap();
        assert_eq!(quote, [5; 64]);
        fs::remove_file(socket).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
