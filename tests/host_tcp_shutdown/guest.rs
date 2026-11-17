use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    time::{Duration, Instant},
};

fn main() {
    for line in fs::read_to_string("close-config").unwrap().lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let mut stream = TcpStream::connect(fields[1]).unwrap();
        let limit: usize = fields[3].parse().unwrap();
        let both = fields[4] == "both";
        stream.set_nonblocking(true).unwrap();
        let bytes = [0x53; 32768];
        let mut sent = 0;
        let mut last_progress = Instant::now();
        while sent < limit {
            match stream.write(&bytes[..bytes.len().min(limit - sent)]) {
                Ok(0) => panic!("zero-length send"),
                Ok(n) => {
                    sent += n;
                    last_progress = Instant::now();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // A first WouldBlock can mean only the guest transport is
                    // full. Allow it to forward until the host also stalls.
                    if last_progress.elapsed() >= Duration::from_millis(100) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("send: {e}"),
            }
        }
        if limit > 8192 {
            assert!(sent < limit, "connection never reached backpressure");
        }
        if limit > 0 {
            assert!(sent > 0);
        }
        stream
            .shutdown(if both {
                Shutdown::Both
            } else {
                Shutdown::Write
            })
            .unwrap();
        // The host starts reading only after this separate connection reports
        // that shutdown has happened, so queued bytes cannot drain beforehand.
        let mut control = TcpStream::connect(fields[2]).unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        control.write_all(&(sent as u64).to_le_bytes()).unwrap();
        let mut count = [0; 8];
        control.read_exact(&mut count).unwrap();
        assert_eq!(u64::from_le_bytes(count), sent as u64);
        if !both {
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream.read_exact(&mut count).unwrap();
            assert_eq!(u64::from_le_bytes(count), sent as u64);
            assert_eq!(stream.read(&mut count).unwrap(), 0);
        }
        println!("CLOSE_CASE {} PASS {}", fields[0], sent);
    }
}
