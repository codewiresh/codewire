use std::sync::Mutex;

use super::*;

/// RFC 5769 section 2.2: a binding success with XOR-MAPPED-ADDRESS
/// 192.0.2.1:32853, after SOFTWARE and before MESSAGE-INTEGRITY and FINGERPRINT.
const RFC5769_IPV4: [u8; 80] = [
    0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63,
    0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
    0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9,
    0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7, 0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96,
];
/// RFC 5769 section 2.3: the same with XOR-MAPPED-ADDRESS
/// [2001:db8:1234:5678:11:2233:4455:6677]:32853.
const RFC5769_IPV6: [u8; 92] = [
    0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63,
    0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa,
    0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9, 0x00, 0x08, 0x00, 0x14,
    0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6, 0x7b, 0xf1, 0x17, 0x84, 0xc9, 0x7c, 0x82, 0x92, 0xc2, 0x75,
    0xbf, 0xe3, 0xed, 0x41, 0x80, 0x28, 0x00, 0x04, 0xc8, 0xfb, 0x0b, 0x4c,
];
const RFC5769_TRANSACTION: [u8; 12] = [
    0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
];

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn stun_responses_are_read_as_rfc_5769_specifies() {
    assert_eq!(
        mapped_address(&RFC5769_IPV4, &RFC5769_TRANSACTION),
        Some(v4(192, 0, 2, 1))
    );
    assert_eq!(
        mapped_address(&RFC5769_IPV6, &RFC5769_TRANSACTION),
        Some("2001:db8:1234:5678:11:2233:4455:6677".parse().unwrap())
    );
    // Another transaction, a truncated message or a request is not an answer.
    let mut other = RFC5769_TRANSACTION;
    other[11] ^= 1;
    assert_eq!(mapped_address(&RFC5769_IPV4, &other), None);
    assert_eq!(
        mapped_address(&RFC5769_IPV4[..46], &RFC5769_TRANSACTION),
        None
    );
    assert_eq!(
        mapped_address(&binding_request(&RFC5769_TRANSACTION), &RFC5769_TRANSACTION),
        None
    );
    let request = binding_request(&RFC5769_TRANSACTION);
    assert_eq!(
        &request[..8],
        &[0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42]
    );
    assert_eq!(&request[8..], &RFC5769_TRANSACTION);
}

/// A success for `request`'s transaction mapping to `address` (IPv4).
fn success(request: &[u8], address: Ipv4Addr) -> Vec<u8> {
    let mut response = vec![0x01, 0x01, 0x00, 0x0c];
    response.extend_from_slice(&request[4..20]);
    response.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0x12, 0x34]);
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    response.extend(
        address
            .octets()
            .iter()
            .zip(cookie)
            .map(|(byte, key)| byte ^ key),
    );
    response
}

#[tokio::test]
async fn a_stun_server_reports_the_mapped_address_of_this_transaction_only() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let answer = tokio::spawn(async move {
        let mut request = [0_u8; 64];
        let (length, peer) = server.recv_from(&mut request).await.unwrap();
        assert_eq!(length, STUN_HEADER_LEN);
        // A stale answer for another transaction first, then the real one.
        let mut stale = success(&request, Ipv4Addr::new(198, 51, 100, 9));
        stale[19] ^= 1;
        server.send_to(&stale, peer).await.unwrap();
        server
            .send_to(&success(&request, Ipv4Addr::new(87, 0, 0, 180)), peer)
            .await
            .unwrap();
    });
    assert_eq!(
        stun_mapped_address(address, Duration::from_secs(5)).await,
        Some(v4(87, 0, 0, 180))
    );
    answer.await.unwrap();

    // A silent server yields nothing once its tries time out.
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = silent.local_addr().unwrap();
    assert_eq!(
        stun_mapped_address(address, Duration::from_millis(50)).await,
        None
    );
}

#[tokio::test]
async fn control_frames_round_trip_and_anything_malformed_is_refused() {
    let set = HostAddressSet::new(
        [v4(203, 0, 114, 7), "2a01:4f8::1".parse().unwrap()],
        [v4(87, 0, 0, 180)],
    )
    .unwrap();
    let frame = encode_frame(&set);
    assert!(frame.len() <= MAX_FRAME_LEN);
    assert_eq!(read_frame(&mut frame.as_slice()).await.unwrap(), set);
    assert_eq!(
        read_frame(&mut encode_frame(&HostAddressSet::default()).as_slice())
            .await
            .unwrap(),
        HostAddressSet::default()
    );

    let mutate = |index: usize, value: u8| {
        let mut bad = frame.clone();
        bad[index] = value;
        bad
    };
    for bad in [
        mutate(0, b'X'),                   // magic
        mutate(4, 2),                      // version
        mutate(5, 0xff),                   // interface count over its bound
        mutate(7, 0xff),                   // public count over its bound
        mutate(FRAME_HEADER_LEN, 5),       // family
        mutate(FRAME_HEADER_LEN + 1, 1),   // an IPv4 entry that is not IPv4-mapped
        frame[..frame.len() - 1].to_vec(), // truncated
    ] {
        assert!(read_frame(&mut bad.as_slice()).await.is_err());
    }
}

#[test]
fn interface_addresses_exclude_the_fixed_protected_ranges() {
    for address in interface_addresses().unwrap() {
        assert_eq!(classify_address(address), None, "{address}");
    }
}

struct FakeSource {
    interfaces: Mutex<VecDeque<io::Result<Vec<IpAddr>>>>,
    last: Mutex<Vec<IpAddr>>,
    public: Mutex<VecDeque<Option<IpAddr>>>,
    learns: Mutex<usize>,
}

impl FakeSource {
    fn new(interfaces: Vec<io::Result<Vec<IpAddr>>>, public: Vec<Option<IpAddr>>) -> Self {
        Self {
            interfaces: Mutex::new(interfaces.into()),
            last: Mutex::new(Vec::new()),
            public: Mutex::new(public.into()),
            learns: Mutex::new(0),
        }
    }
}

#[async_trait::async_trait]
impl HostAddressSource for FakeSource {
    /// The next scripted read, then the last successful one forever.
    fn interfaces(&self) -> io::Result<Vec<IpAddr>> {
        match self.interfaces.lock().unwrap().pop_front() {
            Some(Ok(addresses)) => {
                *self.last.lock().unwrap() = addresses.clone();
                Ok(addresses)
            }
            Some(Err(error)) => Err(error),
            None => Ok(self.last.lock().unwrap().clone()),
        }
    }

    async fn public(&self) -> Option<IpAddr> {
        *self.learns.lock().unwrap() += 1;
        self.public.lock().unwrap().pop_front().flatten()
    }
}

#[tokio::test]
async fn the_monitor_pushes_interfaces_then_learned_and_changed_addresses() {
    let first = v4(203, 0, 114, 7);
    let second = v4(203, 0, 114, 8);
    let source = FakeSource::new(
        vec![
            Ok(vec![first]),                     // start
            Err(io::Error::other("unreadable")), // a failed read keeps the last
            Ok(vec![first, second]),             // an interface change
        ],
        vec![Some(v4(87, 0, 0, 180)), Some(v4(87, 0, 0, 181))],
    );
    let (monitor, initial) = HostAddressMonitor::start(source).unwrap();
    assert_eq!(initial, HostAddressSet::new([first], []).unwrap());

    let (writer, mut reader) = tokio::io::duplex(MAX_FRAME_LEN * 4);
    let task = tokio::spawn(monitor.run(
        writer,
        initial,
        Duration::from_millis(5),
        Duration::from_secs(3600),
    ));
    // The learned public address is pushed with the interfaces.
    assert_eq!(
        read_frame(&mut reader).await.unwrap(),
        HostAddressSet::new([first], [v4(87, 0, 0, 180)]).unwrap()
    );
    // An interface change pushes again and relearns; learned addresses accumulate.
    assert_eq!(
        read_frame(&mut reader).await.unwrap(),
        HostAddressSet::new([first, second], [v4(87, 0, 0, 180), v4(87, 0, 0, 181)]).unwrap()
    );
    // Nothing changes after that, so nothing more is pushed. The runner ends
    // the monitor with its broker.
    let mut header = [0_u8; FRAME_HEADER_LEN];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), reader.read_exact(&mut header))
            .await
            .is_err()
    );
    task.abort();
}

#[tokio::test]
async fn without_stun_only_interfaces_are_refused_and_nothing_is_lost() {
    let interface = v4(203, 0, 114, 7);
    let source = FakeSource::new(vec![Ok(vec![interface])], vec![None, None]);
    let (monitor, initial) = HostAddressMonitor::start(source).unwrap();
    let (writer, mut reader) = tokio::io::duplex(MAX_FRAME_LEN);
    let task = tokio::spawn(monitor.run(
        writer,
        initial.clone(),
        Duration::from_millis(5),
        Duration::from_millis(20),
    ));
    // Nothing new to push while STUN fails: the broker keeps the initial set.
    let mut header = [0_u8; FRAME_HEADER_LEN];
    assert!(
        tokio::time::timeout(Duration::from_millis(200), reader.read_exact(&mut header))
            .await
            .is_err()
    );
    task.abort();
    assert_eq!(initial, HostAddressSet::new([interface], []).unwrap());
}

#[tokio::test]
async fn learned_addresses_are_bounded_oldest_first() {
    let learned: Vec<Option<IpAddr>> = (0..20).map(|n| Some(v4(87, 0, 1, n))).collect();
    let mut monitor = HostAddressMonitor {
        source: FakeSource::new(vec![], learned),
        interfaces: vec![],
        learned: VecDeque::new(),
        warned: false,
    };
    for _ in 0..20 {
        monitor.learn().await;
    }
    let set = monitor.set().unwrap();
    let public: Vec<IpAddr> = set.public().collect();
    assert_eq!(public.len(), MAX_NETWORK_PUBLIC_ADDRESSES);
    assert!(!public.contains(&v4(87, 0, 1, 3)) && public.contains(&v4(87, 0, 1, 19)));
}
