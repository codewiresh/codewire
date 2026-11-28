//! A boot's record is refused by name, with the codes a hosted first bind
//! uses, before anything starts (#4003). Synthetic records only.

use super::*;

fn secret(key: &str, hosts: &[&str]) -> FirstBindSecret {
    FirstBindSecret {
        path: "local:user:0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b".into(),
        key: key.into(),
        binding_id: "00000000-0000-0000-0000-000000000007".into(),
        binding_generation: 1,
        prefix: None,
        hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
    }
}

fn interception(state: v1::InterceptionState, reason: v1::InterceptionReason) -> v1::Interception {
    v1::Interception {
        state: state as i32,
        reason: reason as i32,
    }
}

fn intercepted() -> v1::Interception {
    interception(
        v1::InterceptionState::Intercepted,
        v1::InterceptionReason::Unspecified,
    )
}

fn anthropic() -> InterceptSet {
    credential_intercepts(
        true,
        codewire_access::ManagedCredentialClients::from_profile_slots(["anthropic"]).unwrap(),
    )
}

#[test]
fn a_record_that_holds_is_admitted() {
    let record = [
        secret("FANCY_TOKEN", &["api.fancy.com"]),
        secret("OTHER_TOKEN", &["api.other.com", "upload.other.com"]),
    ];
    assert_eq!(admit(&record, &intercepted(), &anthropic()), Ok(()));
    let off = interception(
        v1::InterceptionState::Off,
        v1::InterceptionReason::Unspecified,
    );
    assert_eq!(admit(&[], &off, &InterceptSet::default()), Ok(()));
}

/// A boot that would bind a secret's host and doesn't intercept is refused
/// by the first key, never started with the value in reach.
#[test]
fn a_boot_that_cannot_intercept_is_refused_by_the_secrets_name() {
    let record = [secret("FANCY_TOKEN", &["api.fancy.com"])];
    for (state, reason) in [
        (
            v1::InterceptionState::Off,
            v1::InterceptionReason::Unspecified,
        ),
        (
            v1::InterceptionState::NotIntercepted,
            v1::InterceptionReason::NoCredentials,
        ),
        (
            v1::InterceptionState::NotIntercepted,
            v1::InterceptionReason::CredentialServiceOutdated,
        ),
        (
            v1::InterceptionState::NotIntercepted,
            v1::InterceptionReason::PlatformCredentials,
        ),
    ] {
        let refusal = admit(&record, &interception(state, reason), &anthropic()).unwrap_err();
        assert_eq!(
            refusal.code(),
            "bound_secret_not_interceptable",
            "{reason:?}"
        );
        assert_eq!(
            refusal.create_code(),
            "create_bound_secret_not_interceptable"
        );
        assert!(refusal.to_string().contains("FANCY_TOKEN"), "{refusal}");
    }
}

/// Two secrets on one host, more than 16 hosts, and a host a built-in
/// credential names are each refused by its code, naming the host and keys.
#[test]
fn a_record_whose_hosts_do_not_hold_is_refused_by_name() {
    let conflict = admit(
        &[
            secret("FANCY_TOKEN", &["api.fancy.com"]),
            secret("OTHER_TOKEN", &["api.fancy.com"]),
        ],
        &intercepted(),
        &anthropic(),
    )
    .unwrap_err();
    assert_eq!(conflict.code(), "bound_host_conflict");
    for named in ["api.fancy.com", "FANCY_TOKEN", "OTHER_TOKEN"] {
        assert!(conflict.to_string().contains(named), "{conflict}");
    }

    let hosts: Vec<String> = (0..17)
        .map(|index| format!("api{index}.many.com"))
        .collect();
    let many: Vec<&str> = hosts.iter().map(String::as_str).collect();
    let too_many = admit(&[secret("MANY_TOKEN", &many)], &intercepted(), &anthropic()).unwrap_err();
    assert_eq!(too_many.code(), "too_many_bound_hosts");
    assert!(too_many.to_string().contains("MANY_TOKEN"), "{too_many}");
    let sixteen = admit(
        &[secret("MANY_TOKEN", &many[..16])],
        &intercepted(),
        &anthropic(),
    );
    assert_eq!(sixteen, Ok(()));

    for host in ["api.anthropic.com", "api.fancy.example"] {
        let reserved = admit(
            &[secret("FANCY_TOKEN", &[host])],
            &intercepted(),
            &InterceptSet::default(),
        )
        .unwrap_err();
        assert_eq!(reserved.code(), "bound_host_reserved");
        assert!(reserved.to_string().contains(host), "{reserved}");
    }
}
