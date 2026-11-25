//! A hosted Sandbox's audit log (#6189) through the canonical generated
//! client: one environment's events, a page at a time.

pub use codewire_proto::codewire::v1::{
    AuditAccess, AuditActor, AuditApiKey, AuditCredentials, AuditEnvironment, AuditEvent,
    AuditEventKind, AuditLifecycle, AuditPlatform, AuditPlatformReason, AuditPolicyChange,
    AuditPolicyRevision, AuditProtocol, AuditRefusal, AuditRefusalOverflow, AuditRole,
    AuditSandbox, AuditSize, AuditSurface, AuditUser, ListAuditEventsRequest,
    ListAuditEventsResponse, audit_actor, audit_credentials, audit_event, audit_lifecycle,
    audit_policy_change, list_audit_events_request,
};

use crate::{ClientError, CodewireClient};

impl CodewireClient {
    pub async fn list_audit_events(
        &self,
        request: ListAuditEventsRequest,
    ) -> Result<ListAuditEventsResponse, ClientError> {
        self.audit
            .list_audit_events_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }
}

#[cfg(test)]
mod tests {
    use buffa::{EnumValue, Message as _, MessageField};
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::{ClientConfig, StaticTokenProvider, Timestamp};

    fn event(
        id: &str,
        kind: AuditEventKind,
        actor: audit_actor::Actor,
        detail: audit_event::Detail,
    ) -> AuditEvent {
        AuditEvent {
            id: id.into(),
            kind: kind.into(),
            first: MessageField::some(Timestamp {
                seconds: 1_795_510_800,
                nanos: 5,
                ..Default::default()
            }),
            count: 1,
            actor: MessageField::some(AuditActor {
                actor: Some(actor),
                ..Default::default()
            }),
            detail: Some(detail),
            ..Default::default()
        }
    }

    fn events() -> Vec<AuditEvent> {
        let sandbox = || audit_actor::Actor::from(AuditSandbox::default());
        vec![
            event(
                "event-access",
                AuditEventKind::AUDIT_EVENT_KIND_ACCESS,
                AuditUser {
                    id: "user-one".into(),
                    email: "one@example.com".into(),
                    role: AuditRole::AUDIT_ROLE_ADMIN.into(),
                    ..Default::default()
                }
                .into(),
                AuditAccess {
                    surface: AuditSurface::AUDIT_SURFACE_SSH.into(),
                    client_ip: "203.0.113.7".into(),
                    ..Default::default()
                }
                .into(),
            ),
            event(
                "event-lifecycle",
                AuditEventKind::AUDIT_EVENT_KIND_LIFECYCLE,
                AuditPlatform::default().into(),
                AuditLifecycle {
                    action: audit_lifecycle::Action::ACTION_STOPPED.into(),
                    reason: AuditPlatformReason::AUDIT_PLATFORM_REASON_IDLE.into(),
                    preset: "go".into(),
                    from_snapshot: "snap-one".into(),
                    from: MessageField::some(AuditSize {
                        vcpu: 2,
                        memory_mib: 4096,
                        ..Default::default()
                    }),
                    to: MessageField::some(AuditSize {
                        vcpu: 4,
                        memory_mib: 8192,
                        ..Default::default()
                    }),
                    snapshot: "snap-two".into(),
                    idle_stop_seconds: 1800,
                    ..Default::default()
                }
                .into(),
            ),
            event(
                "event-policy",
                AuditEventKind::AUDIT_EVENT_KIND_POLICY,
                AuditApiKey {
                    id: "key-one".into(),
                    name: "ci".into(),
                    ..Default::default()
                }
                .into(),
                AuditPolicyChange {
                    action: audit_policy_change::Action::ACTION_EDITED.into(),
                    from: "open".into(),
                    to: "web".into(),
                    policy: "web".into(),
                    from_revision: 2,
                    to_revision: 3,
                    added: vec!["github.com:443".into()],
                    removed: vec!["example.com:80".into()],
                    revision: 3,
                    failure_code: "self_check_failed".into(),
                    ..Default::default()
                }
                .into(),
            ),
            event(
                "event-refused",
                AuditEventKind::AUDIT_EVENT_KIND_REFUSED,
                sandbox(),
                AuditRefusal {
                    destination: "evil.example".into(),
                    address: "198.51.100.9".into(),
                    port: Some(443),
                    protocol: AuditProtocol::AUDIT_PROTOCOL_TCP.into(),
                    reason: "name_not_allowed".into(),
                    source: "egress".into(),
                    policy: "web".into(),
                    revision: 3,
                    allowed_since_revision: Some(4),
                    ..Default::default()
                }
                .into(),
            ),
            event(
                "event-dns",
                AuditEventKind::AUDIT_EVENT_KIND_REFUSED,
                sandbox(),
                AuditRefusal {
                    withheld: true,
                    protocol: AuditProtocol::AUDIT_PROTOCOL_DNS.into(),
                    reason: "host_check_failed".into(),
                    ..Default::default()
                }
                .into(),
            ),
            event(
                "event-credentials",
                AuditEventKind::AUDIT_EVENT_KIND_CREDENTIALS,
                sandbox(),
                AuditCredentials {
                    action: audit_credentials::Action::ACTION_USED.into(),
                    provider: "github".into(),
                    name: "work".into(),
                    host: "api.github.com".into(),
                    withheld: true,
                    ..Default::default()
                }
                .into(),
            ),
            event(
                "event-overflow",
                AuditEventKind::AUDIT_EVENT_KIND_REFUSED,
                sandbox(),
                AuditRefusalOverflow {
                    subjects: 1000,
                    at_least: true,
                    ..Default::default()
                }
                .into(),
            ),
        ]
    }

    #[tokio::test]
    async fn the_read_sends_its_exact_request_and_every_kind_arrives_whole() {
        let server = MockServer::start().await;
        let client = CodewireClient::with_http(
            ClientConfig::new(server.uri()).unwrap(),
            StaticTokenProvider::new("synthetic-audit-token").unwrap(),
            reqwest::Client::new(),
        )
        .unwrap();
        let request = ListAuditEventsRequest {
            org_id: "org-one".into(),
            environment: Some(list_audit_events_request::Environment::EnvironmentName(
                "web".into(),
            )),
            kinds: vec![
                AuditEventKind::AUDIT_EVENT_KIND_REFUSED.into(),
                AuditEventKind::AUDIT_EVENT_KIND_CREDENTIALS.into(),
            ],
            since: MessageField::some(Timestamp {
                seconds: 1_795_507_200,
                ..Default::default()
            }),
            limit: 50,
            cursor: "cursor-one".into(),
            group_by_subject: true,
            ..Default::default()
        };
        let mut future = AuditEvent {
            id: "event-future".into(),
            kind: EnumValue::from(99),
            ..Default::default()
        };
        future.actor = MessageField::some(AuditActor::default());
        let mut all = events();
        all.push(future);
        let response = ListAuditEventsResponse {
            environment: MessageField::some(AuditEnvironment {
                id: "env-one".into(),
                name: "web".into(),
                deleted: true,
                ..Default::default()
            }),
            policy: MessageField::some(AuditPolicyRevision {
                name: "web".into(),
                revision: 3,
                ..Default::default()
            }),
            events: all,
            next_cursor: "cursor-two".into(),
            left_out: 5,
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path("/codewire.v1.AuditService/ListAuditEvents"))
            .and(header("authorization", "Bearer synthetic-audit-token"))
            .and(body_bytes(request.encode_to_vec()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(response.encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;

        let answered = client.list_audit_events(request).await.unwrap();
        assert_eq!(answered, response);
        let details: Vec<_> = answered
            .events
            .iter()
            .map(|event| match &event.detail {
                Some(audit_event::Detail::Access(_)) => "access",
                Some(audit_event::Detail::Lifecycle(value)) => {
                    assert_eq!(value.idle_stop_seconds, 1800);
                    "lifecycle"
                }
                Some(audit_event::Detail::Policy(_)) => "policy",
                Some(audit_event::Detail::Refused(value)) if value.port.is_none() => "dns",
                Some(audit_event::Detail::Refused(_)) => "refused",
                Some(audit_event::Detail::Credentials(_)) => "credentials",
                Some(audit_event::Detail::RefusedOverflow(value)) => {
                    assert_eq!((value.subjects, value.at_least), (1000, true));
                    "refused_overflow"
                }
                None => "none",
            })
            .collect();
        assert_eq!(
            details,
            [
                "access",
                "lifecycle",
                "policy",
                "refused",
                "dns",
                "credentials",
                "refused_overflow",
                "none"
            ]
        );
        // A kind this client does not know yet still decodes.
        assert_eq!(answered.events[7].kind, EnumValue::Unknown(99));
    }
}
