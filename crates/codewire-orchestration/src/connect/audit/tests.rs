//! The read's answer: each stored kind as its typed proto, the actor as it
//! was, and a row this build can't read left out.

use chrono::{TimeZone, Utc};
use serde_json::json;

use super::*;

fn stored(kind: &str, action: &str, detail: serde_json::Value) -> StoredEvent {
    StoredEvent {
        id: "aud-1".into(),
        kind: kind.into(),
        action: action.into(),
        first_at: Utc
            .with_ymd_and_hms(2026, 11, 23, 14, 2, 7)
            .single()
            .expect("a time"),
        last_at: None,
        count: 1,
        actor_type: "user".into(),
        actor_id: Some("usr-1".into()),
        actor_label: Some("lee@example.com".into()),
        actor_role: Some("admin".into()),
        client_ip: Some("192.0.2.44".into()),
        detail,
    }
}

#[test]
fn an_admins_open_desktop_reads_with_its_role_address_and_no_end() {
    let event = proto_event(&stored("access", "desktop", json!({}))).expect("readable");
    assert_eq!(
        event.kind.as_known(),
        Some(AuditEventKind::AUDIT_EVENT_KIND_ACCESS)
    );
    assert!(event.last.as_option().is_none());
    let Some(audit_actor::Actor::User(user)) = &event.actor.as_option().expect("an actor").actor
    else {
        panic!("a user");
    };
    assert_eq!(user.email, "lee@example.com");
    assert_eq!(user.role.as_known(), Some(AuditRole::AUDIT_ROLE_ADMIN));
    let Some(codewire_proto::codewire::v1::__buffa::oneof::audit_event::Detail::Access(access)) =
        &event.detail
    else {
        panic!("access");
    };
    assert_eq!(
        access.surface.as_known(),
        Some(AuditSurface::AUDIT_SURFACE_DESKTOP)
    );
    assert_eq!(access.client_ip, "192.0.2.44");
}

#[test]
fn an_idle_stop_carries_its_timeout_and_a_refusal_its_port() {
    let mut stop = stored(
        "lifecycle",
        "stopped",
        json!({"reason": "idle", "idle_stop_seconds": 1800}),
    );
    stop.actor_type = "platform".into();
    stop.actor_id = None;
    stop.actor_label = None;
    stop.actor_role = None;
    let event = proto_event(&stop).expect("readable");
    let Some(codewire_proto::codewire::v1::__buffa::oneof::audit_event::Detail::Lifecycle(
        lifecycle,
    )) = &event.detail
    else {
        panic!("lifecycle");
    };
    assert_eq!(
        lifecycle.action.as_known(),
        Some(audit_lifecycle::Action::ACTION_STOPPED)
    );
    assert_eq!(
        lifecycle.reason.as_known(),
        Some(AuditPlatformReason::AUDIT_PLATFORM_REASON_IDLE)
    );
    assert_eq!(lifecycle.idle_stop_seconds, 1800);

    let refused = proto_event(&stored(
        "refused",
        "refused",
        json!({"destination": null, "withheld": true, "address": null, "port": null,
               "protocol": "dns", "reason": "name_not_allowed", "source": "network",
               "policy": "walk-docs", "revision": 1}),
    ))
    .expect("readable");
    let Some(codewire_proto::codewire::v1::__buffa::oneof::audit_event::Detail::Refused(refusal)) =
        &refused.detail
    else {
        panic!("refused");
    };
    assert!(refusal.withheld && refusal.destination.is_empty());
    assert_eq!(refusal.port, None);
    assert_eq!(refusal.reason, "name_not_allowed");
}

#[test]
fn a_row_this_build_cant_read_is_left_out() {
    assert!(proto_event(&stored("lifecycle", "exploded", json!({}))).is_none());
    assert!(proto_event(&stored("weather", "rain", json!({}))).is_none());
}

#[test]
fn a_person_reads_with_their_own_sign_in_and_no_other_clients_token() {
    use codewire_server_core::auth::CredentialContext;
    let token = |client: &str| CredentialContext::OidcAccessToken {
        client_id: client.into(),
        scopes: vec!["codewire.api".into()],
    };
    for allowed in [
        CredentialContext::SessionCookie {
            session_id: "s-1".into(),
        },
        CredentialContext::ApiKey {
            key_id: "k-1".into(),
            scopes: Vec::new(),
        },
        token("codewire-cli"),
        token("codewire-desktop"),
        token("codewire-ios"),
    ] {
        assert!(
            read::require_reader_credential(&allowed).is_ok(),
            "{allowed:?}"
        );
    }
    for refused in [token("some-integration"), token("codewire-cli-")] {
        assert!(
            read::require_reader_credential(&refused).is_err(),
            "{refused:?}"
        );
    }
}
