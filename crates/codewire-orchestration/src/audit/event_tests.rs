//! How each kind of event is stored: its action, whether it folds, what a
//! fold is keyed by, and its fields under the names the read returns.

use codewire_egress_policy::lease::RefusalReason;
use serde_json::json;

use super::event::{
    Columns, Credentials, Kind, Lifecycle, PlatformReason, Policy, Protocol, Refusal,
    RefusalOverflow, RefusalSource, Size, Surface, What,
};

fn columns(what: &What) -> Columns {
    what.columns("user:u1|203.0.113.7")
        .expect("every event encodes")
}

#[test]
fn a_platform_stop_names_its_reason_and_does_not_fold() {
    let stored = columns(&What::Lifecycle(Lifecycle::Stopped {
        reason: Some(PlatformReason::Idle),
        idle_stop_seconds: Some(1800),
    }));
    assert_eq!(
        stored,
        Columns {
            kind: Kind::Lifecycle,
            action: "stopped".into(),
            subject: "stopped".into(),
            folds: false,
            detail: json!({"reason": "idle", "idle_stop_seconds": 1800}),
        }
    );
    let by_hand = columns(&What::Lifecycle(Lifecycle::Stopped {
        reason: None,
        idle_stop_seconds: None,
    }));
    assert_eq!(by_hand.detail, json!({}));
}

#[test]
fn a_resize_keeps_both_sizes() {
    let stored = columns(&What::Lifecycle(Lifecycle::Resized {
        from: Size {
            vcpu: 2,
            memory_mib: 4096,
        },
        to: Size {
            vcpu: 4,
            memory_mib: 8192,
        },
    }));
    assert_eq!(stored.action, "resized");
    assert_eq!(
        stored.detail,
        json!({"from": {"vcpu": 2, "memory_mib": 4096}, "to": {"vcpu": 4, "memory_mib": 8192}})
    );
}

#[test]
fn a_policy_edit_names_both_revisions_and_the_rules() {
    let stored = columns(&What::Policy(Policy::Edited {
        policy: "walk-docs".into(),
        from_revision: 1,
        to_revision: 2,
        added: vec!["crates.io:443".into()],
        removed: vec![],
    }));
    assert_eq!(
        (stored.kind, stored.action.as_str(), stored.folds),
        (Kind::Policy, "edited", false)
    );
    assert_eq!(
        stored.detail,
        json!({"policy": "walk-docs", "from_revision": 1, "to_revision": 2,
               "added": ["crates.io:443"], "removed": []})
    );
}

#[test]
fn a_refusal_folds_by_everything_a_local_row_is_keyed_by() {
    let refusal = |port, revision| {
        What::Refused(Refusal {
            destination: Some("crates.io".into()),
            withheld: false,
            address: Some("192.0.2.80".into()),
            port,
            protocol: Protocol::Tcp,
            reason: RefusalReason::NameNotAllowed,
            source: RefusalSource::Network,
            policy: Some("walk-docs".into()),
            revision,
        })
    };
    let stored = columns(&refusal(Some(443), Some(1)));
    assert!(stored.folds);
    assert_eq!(
        stored.subject,
        "crates.io|tcp|443|name_not_allowed|walk-docs|1"
    );
    assert_ne!(stored.subject, columns(&refusal(Some(80), Some(1))).subject);
    assert_ne!(
        stored.subject,
        columns(&refusal(Some(443), Some(2))).subject
    );
    assert_eq!(stored.detail["withheld"], json!(false));
    assert_eq!(stored.detail["protocol"], json!("tcp"));
}

#[test]
fn a_credential_use_folds_by_provider_and_host_and_an_attach_does_not() {
    let used = columns(&What::Credentials(Credentials::Used {
        provider: "github".into(),
        name: "work".into(),
        host: "api.github.com".into(),
        withheld: false,
    }));
    assert_eq!((used.action.as_str(), used.folds), ("used", true));
    assert_eq!(used.subject, "github|work|api.github.com");
    assert_eq!(
        used.detail,
        json!({"provider": "github", "name": "work", "host": "api.github.com"})
    );
    let attached = columns(&What::Credentials(Credentials::Attached {
        provider: "github".into(),
        name: "work".into(),
    }));
    assert_eq!(
        (attached.action.as_str(), attached.folds),
        ("attached", false)
    );
}

#[test]
fn exec_and_preview_fold_per_actor_and_address_and_the_rest_do_not() {
    for (surface, folds) in [
        (Surface::Exec, true),
        (Surface::Preview, true),
        (Surface::Terminal, false),
        (Surface::Ssh, false),
        (Surface::Desktop, false),
    ] {
        let stored = columns(&What::Access(surface));
        assert_eq!(stored.folds, folds, "{surface:?}");
        assert_eq!(
            stored.subject,
            format!("{}|user:u1|203.0.113.7", surface.as_str())
        );
    }
}

#[test]
fn a_name_the_workload_chose_passes_the_host_check_before_it_is_stored() {
    let refusal = |destination: &str| {
        What::Refused(Refusal {
            destination: Some(destination.into()),
            withheld: false,
            address: Some("not an address".into()),
            port: Some(443),
            protocol: Protocol::Tcp,
            reason: RefusalReason::NameNotAllowed,
            source: RefusalSource::Network,
            policy: Some("walk-docs".into()),
            revision: Some(2),
        })
    };
    let hostile = columns(&refusal("evil\u{1b}[31m.example"));
    assert_eq!(hostile.detail["destination"], json!(null));
    assert_eq!(hostile.detail["withheld"], json!(true));
    assert_eq!(hostile.detail["address"], json!(null));
    assert!(!hostile.subject.contains('\u{1b}'), "{}", hostile.subject);
    assert!(hostile.subject.starts_with("(withheld)|"));

    let named = columns(&refusal("PyPI.org."));
    assert_eq!(named.detail["destination"], json!("pypi.org"));
    assert_eq!(named.detail["withheld"], json!(false));
    let address = columns(&refusal("2001:db8::1"));
    assert_eq!(address.detail["destination"], json!("2001:db8::1"));

    let used = columns(&What::Credentials(Credentials::Used {
        provider: "github".into(),
        name: "work".into(),
        host: "api.github.com\u{7}".into(),
        withheld: false,
    }));
    assert_eq!(
        used.detail,
        json!({"provider": "github", "name": "work", "host": "", "withheld": true})
    );
    assert_eq!(used.subject, "github|work|");
}

#[test]
fn a_refusals_reason_is_only_the_engines_own_code() {
    let stored = columns(&What::Refused(Refusal {
        destination: Some("crates.io".into()),
        withheld: false,
        address: None,
        port: Some(443),
        protocol: Protocol::Tcp,
        reason: RefusalReason::UdpNotCarried,
        source: RefusalSource::FrontDoor,
        policy: None,
        revision: None,
    }));
    assert_eq!(stored.detail["reason"], json!("udp_not_carried"));
    assert_eq!(stored.detail["source"], json!("front_door"));
    let mut forged = stored.detail.clone();
    forged["reason"] = json!("\u{1b}]0;owned\u{7}");
    assert!(serde_json::from_value::<Refusal>(forged).is_err());
    assert!(serde_json::from_value::<Refusal>(stored.detail).is_ok());
}

#[test]
fn every_kind_reads_back_as_it_was_stored() {
    for what in [
        What::Access(Surface::Desktop),
        What::Lifecycle(Lifecycle::Stopped {
            reason: Some(PlatformReason::Idle),
            idle_stop_seconds: Some(1800),
        }),
        What::Lifecycle(Lifecycle::Started),
        What::Policy(Policy::Selected {
            from: "open".into(),
            to: "walk-docs".into(),
        }),
        What::Refused(Refusal {
            destination: Some("pypi.org".into()),
            withheld: false,
            address: Some("192.0.2.91".into()),
            port: Some(443),
            protocol: Protocol::Tcp,
            reason: RefusalReason::NameNotAllowed,
            source: RefusalSource::Network,
            policy: Some("walk-docs".into()),
            revision: Some(2),
        }),
        What::Credentials(Credentials::Used {
            provider: "github".into(),
            name: "work".into(),
            host: "api.github.com".into(),
            withheld: false,
        }),
    ] {
        let stored = columns(&what);
        let read = What::from_stored(stored.kind.as_str(), &stored.action, &stored.detail)
            .expect("a stored event reads back");
        assert_eq!(read, what);
    }
    assert!(What::from_stored("lifecycle", "exploded", &json!({})).is_err());
}

#[test]
fn an_overflow_reads_back_without_the_subjects_the_writer_keeps() {
    let detail = json!({"subjects": 1000, "at_least": true, "seen": ["9f86d081884c7d65"]});
    assert_eq!(
        What::from_stored("refused", "overflow", &detail).expect("an overflow reads"),
        What::RefusedOverflow(RefusalOverflow {
            subjects: 1000,
            at_least: true,
        })
    );
}
