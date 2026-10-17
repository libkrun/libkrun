use std::io::{ErrorKind, Read, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn expect_msg(stream: &mut TcpStream, expected: &[u8]) {
    let mut buf = vec![0; expected.len()];
    stream.read_exact(&mut buf[..]).unwrap();
    assert_eq!(&buf[..], expected);
}

fn expect_wouldblock(stream: &mut TcpStream) {
    stream.set_nonblocking(true).unwrap();
    let err = stream.read(&mut [0u8; 1]).unwrap_err();
    stream.set_nonblocking(false).unwrap();
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
}

fn set_timeouts(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
}

fn connect(server_ip: Ipv4Addr, port: u16) -> TcpStream {
    let addr = SocketAddr::new(IpAddr::V4(server_ip), port);
    let mut tries = 0;
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return stream,
            Err(err) => {
                if tries == 12 {
                    panic!("Couldn't connect to server after {tries} retries: {err}");
                }
                tries += 1;
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct TcpTester {
    server_ip: Ipv4Addr,
    port: u16,
}

impl TcpTester {
    pub const fn new(server_ip: Ipv4Addr, port: u16) -> Self {
        Self { server_ip, port }
    }

    pub fn create_server_socket(&self) -> TcpListener {
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), self.port)).unwrap()
    }

    pub fn run_server(&self, listener: TcpListener) {
        let (mut stream, _addr) = listener.accept().unwrap();
        set_timeouts(&mut stream);
        stream.write_all(b"ping!").unwrap();
        expect_msg(&mut stream, b"pong!");
        expect_wouldblock(&mut stream);
        stream.write_all(b"bye!").unwrap();
        // We leak the file descriptor for now, since there is no easy way to close it on libkrun exit
        mem::forget(listener);
        mem::forget(stream);
    }

    pub fn run_client(&self) {
        // Retry connect + first read until the proxy/guest bridge is fully wired up.
        // gvproxy (and libkrun's TSI) accept the host-side connection immediately,
        // but the upstream dial to the guest only succeeds once the guest has
        // reached listen()/accept(). Until then the host either reads zero bytes
        // (timeout/WouldBlock) or sees an EOF from a forced close. Once the first
        // byte arrives, the bridge is live; any later error is a real bug.
        const MAX_RETRIES: u32 = 50; // 50 × 200 ms = 10 s
        let mut retries = 0u32;
        let mut stream = loop {
            let mut stream = connect(self.server_ip, self.port);
            set_timeouts(&mut stream);
            let mut buf = [0u8; 5];
            match stream.read_exact(&mut buf) {
                Ok(()) => {
                    assert_eq!(&buf[..], b"ping!");
                    break stream;
                }
                Err(e) => {
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        panic!("server did not send 'ping!' after {MAX_RETRIES} retries: {e}");
                    }
                    drop(stream);
                    thread::sleep(Duration::from_millis(200));
                }
            }
        };
        expect_wouldblock(&mut stream);
        stream.write_all(b"pong!").unwrap();
        expect_msg(&mut stream, b"bye!");
    }
}
