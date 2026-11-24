//! cw-egress's calls to orchestration's `EgressService` (#4000), on the
//! internal listener over TLS with its published roots. Every call presents
//! cw-egress's own projected token, re-read from its file each time because
//! the kubelet rotates it.
//!
//! An assignment is parsed once, here: cw-egress compiles the policy document
//! itself and refuses one whose digest is not the one it was sent with.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use codewire_egress_front_door_bridge::{INTERCEPT_PORT, RouteTable};
use codewire_egress_policy::{CompiledPolicy, PolicyDigest, PolicyDocument};
use codewire_network_session::{EgressTrust, MAX_EGRESS_TRUST_BYTES};
use codewire_proto::codewire::internal::v1::__buffa::oneof::egress_assignment::Binding;
use codewire_proto::codewire::internal::v1::{
    AdmitRequest, EgressAssignment, EgressServiceClient, InterceptionBinding,
    SignInterceptionLeavesRequest, WatchAssignmentRequest, WatchAssignmentResponse,
};
use codewire_tls::ConnectOriginTransport;
use connectrpc::client::{CallOptions, ClientConfig};
use connectrpc::{ConnectError, ErrorCode};
use http::HeaderValue;
use http::header::AUTHORIZATION;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::interception::{Interception, interception};

/// The longest one unary call to orchestration may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one assignment watch stream runs before cw-egress opens it again.
/// Orchestration sends only on change, so this bounds how long a connection
/// that died without a word goes unnoticed. A stream that reaches it after
/// delivering is opened again at once (#4000).
pub const WATCH_LIFETIME: Duration = Duration::from_secs(60);

/// A destination every sandbox may reach whatever its policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformAllow {
    pub host: String,
    pub port: u16,
}

/// The policy a bound sandbox enforces, compiled here from its document.
#[derive(Debug, Clone)]
pub struct AssignedPolicy {
    pub reference: String,
    pub revision: u32,
    pub policy: CompiledPolicy,
}

/// What orchestration assigned a Pod.
#[derive(Debug, Clone)]
pub enum Assignment {
    /// An identity-free warm member: platform allows only.
    Unbound { platform: Vec<PlatformAllow> },
    Bound {
        environment_id: String,
        operation_generation: i64,
        /// Boxed: a compiled policy, with its platform peers, outweighs the
        /// unbound variant.
        policy: Box<AssignedPolicy>,
        platform: Vec<PlatformAllow>,
        /// Boxed: with its route table it outweighs the rest of the variant.
        interception: Box<Interception>,
    },
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AssignmentError {
    #[error("the assignment names neither a bound nor an unbound Pod")]
    Missing,
    #[error("a platform allow is not a host and port")]
    PlatformAllow,
    #[error("the policy document does not compile")]
    Document,
    #[error("the policy document does not reproduce its digest")]
    DigestMismatch,
}

/// Parses an assignment as orchestration sent it.
pub fn assignment(assignment: &EgressAssignment) -> Result<Assignment, AssignmentError> {
    let platform = assignment
        .platform_allows
        .iter()
        .map(|allow| {
            let port = u16::try_from(allow.port)
                .ok()
                .filter(|port| *port != 0)
                .ok_or(AssignmentError::PlatformAllow)?;
            if allow.host.is_empty() {
                return Err(AssignmentError::PlatformAllow);
            }
            Ok(PlatformAllow {
                host: allow.host.clone(),
                port,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    match assignment
        .binding
        .as_ref()
        .ok_or(AssignmentError::Missing)?
    {
        Binding::Unbound(_) => Ok(Assignment::Unbound { platform }),
        Binding::Bound(bound) => {
            let revision = bound.policy.as_option().ok_or(AssignmentError::Missing)?;
            let document: PolicyDocument = serde_json::from_slice(&revision.document)
                .map_err(|_| AssignmentError::Document)?;
            let policy =
                CompiledPolicy::compile(document).map_err(|_| AssignmentError::Document)?;
            let digest: [u8; 32] = revision
                .digest
                .as_slice()
                .try_into()
                .map_err(|_| AssignmentError::DigestMismatch)?;
            if policy.digest() != PolicyDigest::from_bytes(digest) {
                return Err(AssignmentError::DigestMismatch);
            }
            Ok(Assignment::Bound {
                environment_id: bound.environment_id.clone(),
                operation_generation: bound.operation_generation,
                policy: Box::new(AssignedPolicy {
                    reference: revision.reference.clone(),
                    revision: revision.revision,
                    policy,
                }),
                platform,
                interception: Box::new(interception(bound)),
            })
        }
    }
}

/// An admitted stream's Pod.
#[derive(Debug, Clone)]
pub struct Admitted {
    pub pod_uid: String,
    pub pod_name: String,
    pub assignment: Result<Assignment, AssignmentError>,
    /// The guest's trust frame: the Pod's interception CA, or none (#4001).
    pub trust: EgressTrust,
}

/// The trust frame for the CA `Admit` returned: none when it is empty, or
/// `None` for one the frame cannot carry, which refuses the stream rather
/// than start the guest on a trust it would keep for the Pod's life (#5006).
fn trust(ca_certificate_der: &[u8]) -> Option<EgressTrust> {
    match ca_certificate_der {
        [] => Some(EgressTrust::None),
        der if der.len() <= MAX_EGRESS_TRUST_BYTES => Some(EgressTrust::Ca(der.to_vec())),
        _ => None,
    }
}

#[derive(Debug, Error)]
pub enum CallError {
    /// Orchestration refused: the stream is not admitted, or the Pod is not
    /// on this node. The stream is closed.
    #[error("orchestration refused the egress stream")]
    Refused,
    /// Too many starts from this peer; the guest retries later.
    #[error("egress stream starts from this peer are limited")]
    Limited,
    /// Orchestration could not answer; a new stream fails closed, an
    /// established one keeps its last assignment.
    #[error("orchestration is unavailable: {0}")]
    Unavailable(String),
    /// The call reached its deadline. For an assignment watch that has
    /// delivered, that is its [`WATCH_LIFETIME`], not an outage.
    #[error("the call to orchestration reached its deadline")]
    Expired,
}

impl From<ConnectError> for CallError {
    fn from(error: ConnectError) -> Self {
        match error.code {
            ErrorCode::PermissionDenied
            | ErrorCode::Unauthenticated
            | ErrorCode::InvalidArgument => Self::Refused,
            ErrorCode::ResourceExhausted => Self::Limited,
            ErrorCode::DeadlineExceeded => Self::Expired,
            _ => Self::Unavailable(format!("{:?}", error.code)),
        }
    }
}

/// Where orchestration is and how cw-egress proves who it is.
#[derive(Debug, Clone)]
pub struct Orchestration {
    pub url: String,
    pub address: IpAddr,
    pub roots: PathBuf,
    pub token_path: PathBuf,
}

impl Orchestration {
    fn client(&self) -> Result<EgressServiceClient<ConnectOriginTransport>, CallError> {
        let config = ClientConfig::new(
            self.url
                .parse()
                .map_err(|_| CallError::Unavailable("orchestration URL".into()))?,
        )
        .with_default_timeout(CALL_TIMEOUT);
        let transport = ConnectOriginTransport::for_origin(&self.url, &self.roots)
            .map_err(|_| CallError::Unavailable("orchestration TLS roots".into()))?
            .dialing(self.address);
        Ok(EgressServiceClient::new(transport, config))
    }

    fn options(&self) -> Result<CallOptions, CallError> {
        let token = Zeroizing::new(
            std::fs::read_to_string(&self.token_path)
                .map_err(|_| CallError::Unavailable("egress-node token".into()))?,
        );
        let mut value = HeaderValue::from_str(&format!("Bearer {}", token.trim()))
            .map_err(|_| CallError::Unavailable("egress-node token".into()))?;
        value.set_sensitive(true);
        CallOptions::default()
            .try_with_header(AUTHORIZATION, value)
            .map_err(|_| CallError::Unavailable("egress-node token".into()))
    }

    /// Asks orchestration to admit a guest's stream from `peer`.
    pub async fn admit(&self, guest_token: &str, peer: IpAddr) -> Result<Admitted, CallError> {
        let response = self
            .client()?
            .admit_with_options(
                AdmitRequest {
                    guest_token: guest_token.to_owned(),
                    peer_ip: peer.to_string(),
                    front_door_hosts: front_door_hosts(),
                    ..Default::default()
                },
                self.options()?,
            )
            .await?
            .into_owned();
        let assignment = response
            .assignment
            .as_option()
            .ok_or(AssignmentError::Missing)
            .and_then(assignment);
        let trust = trust(&response.ca_certificate_der).ok_or(CallError::Refused)?;
        Ok(Admitted {
            pod_uid: response.pod_uid.clone(),
            pod_name: response.pod_name.clone(),
            assignment,
            trust,
        })
    }

    /// Follows an admitted Pod's assignment. `on_change` gets each one, the
    /// current first; the call returns when orchestration ends the stream,
    /// or with [`CallError::Expired`] after [`WATCH_LIFETIME`].
    pub async fn watch(
        &self,
        pod_uid: &str,
        pod_name: &str,
        mut on_change: impl FnMut(Result<Assignment, AssignmentError>),
    ) -> Result<(), CallError> {
        let mut stream = self
            .client()?
            .watch_assignment_with_options(
                WatchAssignmentRequest {
                    pod_uid: pod_uid.to_owned(),
                    pod_name: pod_name.to_owned(),
                    ..Default::default()
                },
                // A deadline bounds the whole stream, so the unary one would
                // end it at 5 s.
                self.options()?.with_timeout(WATCH_LIFETIME),
            )
            .await?;
        while let Some(message) = stream.message::<WatchAssignmentResponse>().await? {
            let message = message.to_owned_message();
            on_change(
                message
                    .assignment
                    .as_option()
                    .ok_or(AssignmentError::Missing)
                    .and_then(assignment),
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod front_door;
mod report;

impl crate::leaves::LeafSigner for Orchestration {
    async fn sign(
        &self,
        pod_uid: &str,
        pod_name: &str,
        public_key: &[u8],
    ) -> Result<crate::leaves::IssuedLeaves, CallError> {
        let response = self
            .client()?
            .sign_interception_leaves_with_options(
                SignInterceptionLeavesRequest {
                    pod_uid: pod_uid.to_owned(),
                    pod_name: pod_name.to_owned(),
                    leaf_public_key: public_key.to_vec(),
                    ..Default::default()
                },
                self.options()?,
            )
            .await?
            .into_owned();
        Ok(crate::leaves::IssuedLeaves {
            certificates: response
                .leaves
                .into_iter()
                .map(|leaf| leaf.certificate_der)
                .collect(),
            renew_at_unix: response.renew_at_unix,
        })
    }
}

pub use report::{Enforcement, RECORDS_PER_CALL, wire_record};

/// Every name this build's front door has a route for, on its port, as the
/// admission reports it (#6290): its own built-in route table, each exact
/// host and each suffix route, never a list it was sent.
fn front_door_hosts() -> Vec<InterceptionBinding> {
    let table = RouteTable::built_in();
    let binding = |host: &str, suffix: bool| InterceptionBinding {
        host: host.to_owned(),
        port: u32::from(INTERCEPT_PORT),
        suffix,
        ..Default::default()
    };
    table
        .hosts()
        .into_iter()
        .map(|host| binding(host, false))
        .chain(
            table
                .suffixes()
                .into_iter()
                .map(|suffix| binding(suffix, true)),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use codewire_egress_policy::BuiltinPolicy;
    use codewire_proto::codewire::internal::v1::{
        BoundAssignment, EgressPolicyRevision, PlatformAllow as WireAllow,
    };

    use super::*;

    /// The admission reports exactly the routes this build's front door can
    /// serve, each exact host and each suffix, on its port (#6290).
    #[test]
    fn the_admission_reports_every_name_the_front_door_routes() {
        let reported = front_door_hosts();
        let table = RouteTable::built_in();
        let exact: Vec<&str> = reported
            .iter()
            .filter(|binding| !binding.suffix)
            .map(|binding| binding.host.as_str())
            .collect();
        let suffixes: Vec<&str> = reported
            .iter()
            .filter(|binding| binding.suffix)
            .map(|binding| binding.host.as_str())
            .collect();
        assert_eq!(exact, table.hosts());
        assert_eq!(suffixes, table.suffixes());
        assert!(reported.iter().all(|binding| binding.port == 443));
        for host in [
            "api.anthropic.com",
            "api.openai.com",
            "chatgpt.com",
            "github.com",
        ] {
            assert!(exact.contains(&host), "{host}");
        }
        assert_eq!(suffixes, ["chatgpt.com"]);
    }

    #[test]
    fn the_admitted_ca_is_the_trust_frame_and_one_it_cannot_carry_refuses_the_stream() {
        // `EgressTrust` has no `Debug`, so it can't be printed by a failure.
        assert!(trust(&[]) == Some(EgressTrust::None));
        assert!(trust(b"synthetic-ca") == Some(EgressTrust::Ca(b"synthetic-ca".to_vec())));
        assert!(trust(&vec![1; MAX_EGRESS_TRUST_BYTES + 1]).is_none());
    }

    fn platform() -> Vec<WireAllow> {
        vec![WireAllow {
            host: "control.example.com".into(),
            port: 443,
            ..Default::default()
        }]
    }

    fn bound(document: Vec<u8>, digest: Vec<u8>) -> EgressAssignment {
        EgressAssignment {
            binding: Some(Binding::Bound(Box::new(BoundAssignment {
                environment_id: "env".into(),
                operation_generation: 3,
                policy: Some(EgressPolicyRevision {
                    reference: "locked".into(),
                    revision: 0,
                    document,
                    digest,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }))),
            platform_allows: platform(),
            ..Default::default()
        }
    }

    #[test]
    fn a_bound_assignment_is_compiled_and_its_digest_checked() {
        let locked = BuiltinPolicy::Locked.compile();
        let document = locked.canonical_json().unwrap();
        let digest = locked.digest().as_bytes().to_vec();
        let Assignment::Bound {
            policy, platform, ..
        } = assignment(&bound(document.clone(), digest)).unwrap()
        else {
            panic!("bound");
        };
        assert_eq!(policy.policy.digest(), locked.digest());
        assert_eq!(platform[0].port, 443);

        assert_eq!(
            assignment(&bound(document, vec![9; 32])).unwrap_err(),
            AssignmentError::DigestMismatch
        );
        assert_eq!(
            assignment(&bound(b"{".to_vec(), vec![9; 32])).unwrap_err(),
            AssignmentError::Document
        );
    }

    #[test]
    fn an_unbound_assignment_carries_only_platform_allows() {
        let unbound = EgressAssignment {
            binding: Some(Binding::Unbound(Box::default())),
            platform_allows: platform(),
            ..Default::default()
        };
        let Assignment::Unbound { platform } = assignment(&unbound).unwrap() else {
            panic!("unbound");
        };
        assert_eq!(platform.len(), 1);
        assert_eq!(
            assignment(&EgressAssignment::default()).unwrap_err(),
            AssignmentError::Missing
        );
    }

    #[test]
    fn a_platform_allow_without_a_port_or_host_is_refused() {
        let mut bad = EgressAssignment {
            binding: Some(Binding::Unbound(Box::default())),
            platform_allows: vec![WireAllow {
                host: "control.example.com".into(),
                port: 0,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            assignment(&bad).unwrap_err(),
            AssignmentError::PlatformAllow
        );
        bad.platform_allows[0] = WireAllow {
            host: String::new(),
            port: 443,
            ..Default::default()
        };
        assert_eq!(
            assignment(&bad).unwrap_err(),
            AssignmentError::PlatformAllow
        );
    }

    #[test]
    fn refusals_and_limits_are_told_apart_from_an_outage() {
        assert!(matches!(
            CallError::from(ConnectError::permission_denied("no")),
            CallError::Refused
        ));
        assert!(matches!(
            CallError::from(ConnectError::resource_exhausted("later")),
            CallError::Limited
        ));
        assert!(matches!(
            CallError::from(ConnectError::unavailable("down")),
            CallError::Unavailable(_)
        ));
        assert!(matches!(
            CallError::from(ConnectError::deadline_exceeded("lifetime")),
            CallError::Expired
        ));
    }
}
