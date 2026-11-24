//! The broker process's side of the front-door hand-off (#3999): its
//! inherited socket, its bindings at startup, and the syscall filter that
//! admits the one socket pair a hand-off makes.

use std::os::fd::{BorrowedFd, FromRawFd as _, OwnedFd, RawFd};

use codewire_egress_broker::handoff::StreamHandoff;
use codewire_egress_broker::{BrokerClock, DnsResolver, PolicyEgressBroker, TcpConnector};
use codewire_egress_policy::handoff::is_connected_unix_stream;
use uuid::Uuid;

use super::{ControlFrame, EgressBrokerProcessError, HANDSHAKE_TIMEOUT};

/// The inherited front-door socket. It must be an open socket, a connected
/// `AF_UNIX` `SOCK_STREAM` one, before the broker takes ownership of it; then
/// it is marked close-on-exec. Anything else refuses to start.
pub(super) fn inherited_handoff(
    descriptor: RawFd,
    environment_id: Uuid,
) -> Result<StreamHandoff, EgressBrokerProcessError> {
    if !is_inherited_unix_stream(descriptor) {
        return Err(EgressBrokerProcessError::InheritedDescriptor);
    }
    // SAFETY: the fixed descriptor is open (checked above), inherited for
    // this purpose and owned exactly once, here.
    let socket = unsafe { OwnedFd::from_raw_fd(descriptor) };
    rustix::io::fcntl_setfd(&socket, rustix::io::FdFlags::CLOEXEC)
        .map_err(|_| EgressBrokerProcessError::InheritedDescriptor)?;
    StreamHandoff::new(socket, environment_id.to_string())
        .map_err(|_| EgressBrokerProcessError::InheritedDescriptor)
}

fn is_inherited_unix_stream(descriptor: RawFd) -> bool {
    // SAFETY: `borrow_raw` needs the descriptor to stay open for the borrow's
    // life. The borrow lives only for this call, on the single thread that
    // owns the inherited descriptors, and nothing closes it meanwhile. A
    // descriptor that is closed or not a socket is no unsafety here: the
    // syscalls fail with EBADF or ENOTSOCK and it is refused.
    let borrowed = unsafe { BorrowedFd::borrow_raw(descriptor) };
    is_connected_unix_stream(borrowed)
}

/// The broker, handing intercepted dials to `handoff` when there is one.
pub(super) fn with_handoff<R, C, K>(
    broker: PolicyEgressBroker<R, C, K>,
    handoff: Option<StreamHandoff>,
) -> PolicyEgressBroker<R, C, K>
where
    R: DnsResolver,
    C: TcpConnector,
    K: BrokerClock,
{
    match handoff {
        Some(handoff) => broker.with_intercept_handoff(std::sync::Arc::new(handoff)),
        None => broker,
    }
}

/// The interception bindings, which arrive on the control channel before the
/// broker admits anything. A missing or late frame is a control-channel
/// failure; any other frame is a protocol failure.
pub(super) async fn receive_intercepts<R, C, K>(
    control: &mut tokio::net::UnixStream,
    broker: &PolicyEgressBroker<R, C, K>,
) -> Result<(), EgressBrokerProcessError>
where
    R: DnsResolver,
    C: TcpConnector,
    K: BrokerClock,
{
    let frame = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        crate::broker_control::read_control_frame(control),
    )
    .await
    .map_err(|_| EgressBrokerProcessError::HostAddresses)?
    .map_err(|_| EgressBrokerProcessError::HostAddresses)?;
    let ControlFrame::ReplaceIntercepts(intercepts) = frame else {
        return Err(EgressBrokerProcessError::Protocol);
    };
    broker.replace_intercepts(intercepts).await;
    Ok(())
}

/// The broker's syscall filter. A hand-off needs
/// `socketpair(AF_UNIX, SOCK_STREAM)` and nothing more: the filter admits
/// exactly that shape, and every other Unix socket stays refused.
#[cfg(target_os = "linux")]
pub(super) fn install_broker_syscalls(handing_off: bool) -> std::io::Result<()> {
    use super::{BROKER_ARCH_DENIED_SYSCALLS, BROKER_DENIED_SYSCALLS};
    use codewire_confinement::linux::{
        install_inet_and_unix_stream_pair_syscalls, install_inet_socket_only_syscalls,
    };
    if handing_off {
        let denied: Vec<libc::c_long> = BROKER_DENIED_SYSCALLS
            .iter()
            .copied()
            .filter(|syscall| *syscall != libc::SYS_socketpair)
            .collect();
        install_inet_and_unix_stream_pair_syscalls(&denied, BROKER_ARCH_DENIED_SYSCALLS)
    } else {
        install_inet_socket_only_syscalls(BROKER_DENIED_SYSCALLS, BROKER_ARCH_DENIED_SYSCALLS)
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, IntoRawFd};

    use super::*;

    const ENVIRONMENT: &str = "0f8c2f6e-2c1e-4a8e-9c55-3b1f0f7d9a11";

    // The broker's hand-off reads acknowledgements on a runtime task (#3999).
    #[tokio::test]
    async fn only_a_connected_unix_stream_is_taken() {
        let environment = Uuid::parse_str(ENVIRONMENT).unwrap();
        let (broker, _front_door) = codewire_egress_policy::handoff::stream_pair().unwrap();
        assert!(inherited_handoff(broker.into_raw_fd(), environment).is_ok());

        // Refused and left open: the broker never owned it.
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(inherited_handoff(file.as_raw_fd(), environment).is_err());
        let (datagram, _other) = std::os::unix::net::UnixDatagram::pair().unwrap();
        assert!(inherited_handoff(datagram.as_raw_fd(), environment).is_err());
        // A number at the soft descriptor limit can't be open, so no other
        // test thread can reuse it underneath this check.
        let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile)
            .current
            .expect("a finite descriptor limit");
        let unused = std::os::fd::RawFd::try_from(limit).unwrap_or(std::os::fd::RawFd::MAX);
        assert!(!is_inherited_unix_stream(unused));
    }

    /// A resolver that answers every name with one public address.
    struct OneAddress;

    #[async_trait::async_trait]
    impl codewire_egress_broker::DnsResolver for OneAddress {
        async fn resolve(
            &self,
            _request: codewire_egress_broker::DnsResolverRequest,
        ) -> Result<
            codewire_egress_broker::DnsResolverOutcome,
            codewire_egress_broker::BrokerAdapterFailure,
        > {
            let address = codewire_egress_policy::lease::DnsAddress::new(PUBLIC, 60).unwrap();
            Ok(codewire_egress_broker::DnsResolverOutcome::Positive(
                codewire_egress_policy::lease::DnsResolution::new(vec![], vec![address]).unwrap(),
            ))
        }
    }

    /// A connector that records every dial it is asked for.
    #[derive(Default)]
    struct Dials(std::sync::Mutex<Vec<std::net::SocketAddr>>);

    #[async_trait::async_trait]
    impl codewire_egress_broker::TcpConnector for Dials {
        type Stream = ();

        async fn connect(
            &self,
            destination: std::net::SocketAddr,
        ) -> Result<(), codewire_egress_broker::BrokerAdapterFailure> {
            self.0.lock().unwrap().push(destination);
            Ok(())
        }
    }

    const PUBLIC: std::net::IpAddr =
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34));

    /// #4001: a hosted broker whose Pod's bindings cannot be served has no
    /// front door, yet reads those bindings before it admits anything, so
    /// each dial to a bound host is refused `intercept_unavailable` and never
    /// dialled, while every other dial carries on. A binding on another port
    /// is refused on that port.
    #[tokio::test]
    async fn a_refusing_broker_reads_its_bindings_first_and_never_dials_them() {
        for port in [443, 8443] {
            refuses_a_bound_dial(port).await;
        }
    }

    async fn refuses_a_bound_dial(port: u16) {
        use codewire_egress_broker::{DnsRecordFamily, PolicyEgressBroker, SystemBrokerClock};
        use codewire_egress_policy::intercept::{InterceptBinding, InterceptSet};
        use codewire_egress_policy::lease::RefusalReason;
        use codewire_egress_policy::{CompiledPolicy, RouteClass};
        use std::io::Write as _;
        use std::sync::Arc;

        let dials = Arc::new(Dials::default());
        let broker = PolicyEgressBroker::new(
            CompiledPolicy::open(),
            RouteClass::General,
            Arc::new(OneAddress),
            Arc::clone(&dials),
            Arc::new(SystemBrokerClock::new()),
        );
        let (mut supervisor, control) = std::os::unix::net::UnixStream::pair().unwrap();
        let bound =
            InterceptSet::new([InterceptBinding::new("api.openai.com", port).unwrap()]).unwrap();
        supervisor
            .write_all(&crate::host_addresses::encode_frame(&Default::default()))
            .unwrap();
        supervisor
            .write_all(&crate::broker_control::encode_intercept_frame(&bound).unwrap())
            .unwrap();
        let _control = super::super::receive_startup_control(
            control,
            &broker,
            super::super::BrokerIntercepts::Refuse,
        )
        .await
        .unwrap();

        let destination = std::net::SocketAddr::new(PUBLIC, port);
        broker
            .resolve_dns("api.openai.com", DnsRecordFamily::Ipv4)
            .await
            .unwrap();
        assert!(broker.connect_tcp(destination).await.is_err());
        let counts = broker.refusal_counts().await;
        assert_eq!(counts.get(RefusalReason::InterceptUnavailable), 1);
        assert_eq!(
            RefusalReason::InterceptUnavailable.code(),
            "intercept_unavailable"
        );
        assert!(dials.0.lock().unwrap().is_empty());

        broker
            .resolve_dns("example.org", DnsRecordFamily::Ipv4)
            .await
            .unwrap();
        let other = std::net::SocketAddr::new(PUBLIC, 80);
        broker.connect_tcp(other).await.unwrap();
        assert_eq!(*dials.0.lock().unwrap(), [other]);
    }
}
