use super::*;

const LOCAL: &str = "9b2e7c1a-0d4f-4e8b-a6c3-5f1d2e3a4b5c";

fn named(generation: u64) -> Named<'static> {
    Named {
        request_id: "6f1d2e3a-4b5c-4d6e-8f70-819203a4b5c6",
        environment_id: "env",
        local_environment_id: LOCAL,
        generation,
    }
}

fn facts() -> Facts {
    Facts {
        current: true,
        state: "running".into(),
        desired_state: "started".into(),
        operation_generation: 7,
        local_environment_id: Some(LOCAL.into()),
        reported_generation: Some(3),
        reported_state: Some("running".into()),
    }
}

/// The operation generation is the environment's, never the host's boot
/// generation the call names.
#[test]
fn a_call_on_the_current_session_for_the_reported_running_vm_gets_the_operation_generation() {
    assert_eq!(admitted(Some(facts()), &named(3)), Ok(7));
}

#[test]
fn every_other_call_is_refused_with_its_reason() {
    let cases: [(&str, Option<Facts>, u64, Refused); 9] = [
        ("not placed on this host", None, 3, Refused::NotHeld),
        (
            "a superseded session",
            Some(Facts {
                current: false,
                ..facts()
            }),
            3,
            Refused::NotHeld,
        ),
        (
            "another local environment",
            Some(Facts {
                local_environment_id: Some("other".into()),
                ..facts()
            }),
            3,
            Refused::NotHeld,
        ),
        (
            "no report yet",
            Some(Facts {
                local_environment_id: None,
                reported_generation: None,
                reported_state: None,
                ..facts()
            }),
            3,
            Refused::NotRunning,
        ),
        (
            "a boot generation the host did not report",
            Some(facts()),
            4,
            Refused::StaleGeneration,
        ),
        (
            "reported starting",
            Some(Facts {
                reported_state: Some("starting".into()),
                ..facts()
            }),
            3,
            Refused::NotRunning,
        ),
        (
            "not running here",
            Some(Facts {
                state: "stopping".into(),
                ..facts()
            }),
            3,
            Refused::NotRunning,
        ),
        (
            "asked to stop",
            Some(Facts {
                desired_state: "stopped".into(),
                ..facts()
            }),
            3,
            Refused::NotRunning,
        ),
        (
            "no operation generation",
            Some(Facts {
                operation_generation: 0,
                ..facts()
            }),
            3,
            Refused::Unavailable,
        ),
    ];
    for (case, facts, generation, refused) in cases {
        assert_eq!(admitted(facts, &named(generation)), Err(refused), "{case}");
    }
}

#[test]
fn only_a_wait_or_an_outage_is_retryable() {
    for (refused, code, retryable) in [
        (Refused::NotHeld, "not_held", false),
        (Refused::NotRunning, "not_running", true),
        (Refused::StaleGeneration, "stale_generation", false),
        (Refused::KeyConflict, "key_conflict", false),
        (Refused::InvalidKey, "invalid_key", false),
        (Refused::Unsupported, "unsupported", false),
        (Refused::Unavailable, "unavailable", true),
    ] {
        assert_eq!((refused.code(), refused.retryable()), (code, retryable));
        assert!(code.len() <= 64);
    }
}

#[test]
fn a_request_id_is_a_uuid() {
    assert!(request_id("6f1d2e3a-4b5c-4d6e-8f70-819203a4b5c6").is_ok());
    for bad in ["", "not-a-uuid", &"a".repeat(65)] {
        assert!(request_id(bad).is_err(), "{bad:?}");
    }
}

/// A grant's peer token never shows in its Debug output, which is how a log
/// line or an error would print it (cw-security, #6412).
#[test]
fn a_grant_prints_no_peer_token() {
    let token = "synthetic-peer-token-that-must-not-print";
    let grant = HostAccessGrant {
        request_id: "6f1d2e3a-4b5c-4d6e-8f70-819203a4b5c6".into(),
        peer_token: token.into(),
        peer_token_expires_at: 1,
        operation_generation: 7,
        coordinator_url: "https://coordinator.example.test".into(),
        ..Default::default()
    };
    let output = attach_host_response::Output::AccessGrant(Box::new(grant.clone()));
    for printed in [
        format!("{grant:?}"),
        format!("{grant:#?}"),
        format!("{output:?}"),
    ] {
        assert!(!printed.contains(token), "{printed}");
        assert!(printed.contains("operation_generation"), "{printed}");
    }
}
