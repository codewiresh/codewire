//! Fixed workload-side TCP client for the opt-in macOS two-VM fixture.
//!
//! This is not a general network client. It accepts no runtime configuration,
//! uses one numeric destination and one finite transcript, and writes no
//! success marker. The host verifier's fixed shell owns that marker after this
//! function returns successfully.

use std::io::{self, ErrorKind, Read as _, Write as _};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

/// The exact guest-local endpoint selected by the product-network fixture.
pub const DESTINATION: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443);
/// The exact request and response size used by both fixture guests.
pub const PAYLOAD_LEN: usize = 4096;
/// SHA-256 of [`request_payload`], pinned for cross-crate golden comparison.
pub const REQUEST_SHA256: [u8; 32] = [
    0xc8, 0xf5, 0xd0, 0x34, 0x1d, 0x54, 0xd9, 0x51, 0xa7, 0x1b, 0x13, 0x6e, 0x6e, 0x2a, 0xfc, 0xb1,
    0x4d, 0x11, 0xed, 0x84, 0x89, 0xa7, 0xae, 0x12, 0x6a, 0x8f, 0xee, 0x0d, 0xf6, 0xec, 0xf1, 0x93,
];
/// SHA-256 of [`response_payload`], pinned for cross-crate golden comparison.
pub const RESPONSE_SHA256: [u8; 32] = [
    0x8f, 0x04, 0xc2, 0x74, 0x07, 0xf8, 0x08, 0x2f, 0xaf, 0x5e, 0x54, 0xb8, 0x53, 0xca, 0xf7, 0x88,
    0x9a, 0x5f, 0xcc, 0xca, 0x35, 0x7e, 0x8f, 0x65, 0x37, 0x99, 0xab, 0x5a, 0x10, 0xd0, 0xd1, 0x14,
];

const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(2);

/// Construct the exact finite request without consulting ambient input.
pub fn request_payload() -> [u8; PAYLOAD_LEN] {
    std::array::from_fn(|index| index as u8)
}

/// Construct the exact expected response without consulting ambient input.
pub fn response_payload() -> [u8; PAYLOAD_LEN] {
    std::array::from_fn(|index| (index as u8) ^ 0x5a)
}

/// Run the one fixed workload-side exchange.
pub fn run_client() -> io::Result<()> {
    run_to(
        SocketAddr::V4(DESTINATION),
        Bounds {
            operation: OPERATION_TIMEOUT,
            total: TOTAL_TIMEOUT,
        },
    )
}

#[derive(Clone, Copy)]
struct Bounds {
    operation: Duration,
    total: Duration,
}

fn run_to(destination: SocketAddr, bounds: Bounds) -> io::Result<()> {
    let total_deadline = Instant::now()
        .checked_add(bounds.total)
        .ok_or_else(timed_out)?;
    let connect_deadline = operation_deadline(total_deadline, bounds.operation)?;
    let mut stream = TcpStream::connect_timeout(&destination, remaining(connect_deadline)?)?;
    require_active(total_deadline)?;
    if stream.peer_addr()? != destination {
        return Err(invalid_data());
    }

    write_all_bounded(
        &mut stream,
        &request_payload(),
        operation_deadline(total_deadline, bounds.operation)?,
    )?;
    require_active(total_deadline)?;
    stream.shutdown(Shutdown::Write)?;
    require_active(total_deadline)?;

    let mut response = [0_u8; PAYLOAD_LEN];
    read_exact_bounded(
        &mut stream,
        &mut response,
        operation_deadline(total_deadline, bounds.operation)?,
    )?;
    if response != response_payload() {
        return Err(invalid_data());
    }
    require_eof(
        &mut stream,
        operation_deadline(total_deadline, bounds.operation)?,
    )?;
    require_active(total_deadline)
}

fn write_all_bounded(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::Error::from(ErrorKind::WriteZero)),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    require_active(deadline)
}

fn read_exact_bounded(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    require_active(deadline)
}

fn require_eof(stream: &mut TcpStream, deadline: Instant) -> io::Result<()> {
    let mut extra = [0_u8; 1];
    stream.set_read_timeout(Some(remaining(deadline)?))?;
    loop {
        match stream.read(&mut extra) {
            Ok(0) => return require_active(deadline),
            Ok(_) => return Err(invalid_data()),
            Err(error) if error.kind() == ErrorKind::Interrupted => {
                stream.set_read_timeout(Some(remaining(deadline)?))?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn operation_deadline(total: Instant, operation: Duration) -> io::Result<Instant> {
    let now = Instant::now();
    if now >= total {
        return Err(timed_out());
    }
    Ok(now.checked_add(operation).unwrap_or(total).min(total))
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(timed_out)
}

fn require_active(deadline: Instant) -> io::Result<()> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(timed_out())
    }
}

fn timed_out() -> io::Error {
    io::Error::new(
        ErrorKind::TimedOut,
        "fixed workload-network operation timed out",
    )
}

fn invalid_data() -> io::Error {
    io::Error::new(
        ErrorKind::InvalidData,
        "fixed workload-network response is invalid",
    )
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;

    use sha2::{Digest as _, Sha256};

    use super::*;

    const TEST_BOUNDS: Bounds = Bounds {
        operation: Duration::from_millis(250),
        total: Duration::from_millis(750),
    };

    #[derive(Clone, Copy)]
    enum Reply {
        Exact,
        Wrong,
        Short,
        Extra,
        MissingEof,
        Stalled(Duration),
    }

    #[test]
    fn transcript_and_hashes_are_pinned() {
        let request = request_payload();
        let response = response_payload();
        assert_eq!(request.len(), PAYLOAD_LEN);
        assert_eq!(response.len(), PAYLOAD_LEN);
        assert!(
            request
                .iter()
                .zip(response)
                .all(|(left, right)| *left ^ 0x5a == right)
        );
        assert_eq!(<[u8; 32]>::from(Sha256::digest(request)), REQUEST_SHA256);
        assert_eq!(
            DESTINATION,
            SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443)
        );
        assert_eq!(<[u8; 32]>::from(Sha256::digest(response)), RESPONSE_SHA256);
    }

    #[test]
    fn client_sends_exact_request_and_fin_before_accepting_response() {
        let (destination, server) = server(Reply::Exact);
        run_to(destination, TEST_BOUNDS).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn client_rejects_wrong_short_and_extra_responses() {
        for reply in [Reply::Wrong, Reply::Short, Reply::Extra] {
            let (destination, server) = server(reply);
            assert!(run_to(destination, TEST_BOUNDS).is_err());
            server.join().unwrap();
        }
    }

    #[test]
    fn client_requires_response_eof() {
        let (destination, server) = server(Reply::MissingEof);
        let error = run_to(destination, TEST_BOUNDS).unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::TimedOut | ErrorKind::WouldBlock
        ));
        server.join().unwrap();
    }

    #[test]
    fn client_bounds_a_stalled_peer() {
        let (destination, server) = server(Reply::Stalled(Duration::from_millis(400)));
        let started = Instant::now();
        assert!(run_to(destination, TEST_BOUNDS).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        server.join().unwrap();
    }

    #[test]
    fn total_budget_bounds_an_individually_longer_operation() {
        let (destination, server) = server(Reply::Stalled(Duration::from_secs(1)));
        let started = Instant::now();
        let error = run_to(
            destination,
            Bounds {
                operation: Duration::from_secs(2),
                total: Duration::from_millis(150),
            },
        )
        .unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::TimedOut | ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_millis(750));
        server.join().unwrap();
    }

    #[test]
    fn client_rejects_connect_failure() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let destination = listener.local_addr().unwrap();
        drop(listener);
        assert!(run_to(destination, TEST_BOUNDS).is_err());
    }

    fn server(reply: Reply) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let destination = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let accept_deadline = Instant::now() + Duration::from_secs(1);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == ErrorKind::WouldBlock
                            && Instant::now() < accept_deadline =>
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("bounded synthetic accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = [0_u8; PAYLOAD_LEN];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(request, request_payload());
            let mut extra = [0_u8; 1];
            assert_eq!(
                stream.read(&mut extra).unwrap(),
                0,
                "client omitted request FIN"
            );

            match reply {
                Reply::Exact => stream.write_all(&response_payload()).unwrap(),
                Reply::Wrong => {
                    let mut response = response_payload();
                    response[PAYLOAD_LEN / 2] ^= 1;
                    stream.write_all(&response).unwrap();
                }
                Reply::Short => stream
                    .write_all(&response_payload()[..PAYLOAD_LEN - 1])
                    .unwrap(),
                Reply::Extra => {
                    stream.write_all(&response_payload()).unwrap();
                    stream.write_all(&[0]).unwrap();
                }
                Reply::MissingEof => {
                    stream.write_all(&response_payload()).unwrap();
                    thread::sleep(Duration::from_millis(400));
                }
                Reply::Stalled(duration) => thread::sleep(duration),
            }
        });
        (destination, server)
    }
}
