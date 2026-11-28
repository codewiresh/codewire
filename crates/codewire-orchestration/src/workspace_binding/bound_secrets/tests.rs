use codewire_access::ManagedCredentialClients;

use super::*;
use crate::egress::assignment::interception_bindings;

fn secret(key: &str, hosts: &[&str]) -> FirstBindSecret {
    FirstBindSecret {
        path: "/org-secrets/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b".into(),
        key: key.into(),
        binding_id: "7d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6".into(),
        binding_generation: 1,
        prefix: None,
        hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
    }
}

/// [`bound_hosts`] under a deployment that reserves none of the names here.
fn union(
    secrets: &[FirstBindSecret],
    credentials: &[Intercept],
) -> Result<BTreeSet<String>, BoundSecretsRefusal> {
    bound_hosts(secrets, credentials, &ReservedHosts::default())
}

fn credentials(slots: &[&str]) -> Vec<Intercept> {
    interception_bindings(
        true,
        ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap(),
    )
    .unwrap()
}

/// The union is every bound host once, and holds beside credentials that
/// name other hosts.
#[test]
fn distinct_hosts_are_bound_beside_the_selected_credentials() {
    let secrets = [
        secret(
            "FANCY_TOKEN",
            &["api.fancy.example", "uploads.fancy.example"],
        ),
        secret("OTHER_TOKEN", &["api.other.example"]),
    ];
    assert_eq!(
        union(&secrets, &credentials(&["anthropic", "codex"])),
        Ok(BTreeSet::from([
            "api.fancy.example".to_owned(),
            "api.other.example".to_owned(),
            "uploads.fancy.example".to_owned(),
        ]))
    );
    assert_eq!(
        union(&[], &credentials(&["anthropic"])),
        Ok(BTreeSet::new())
    );
}

/// Two bound secrets on one host are refused, naming the host and both keys.
#[test]
fn two_secrets_naming_one_host_are_refused_by_name() {
    let refusal = union(
        &[
            secret("FANCY_TOKEN", &["api.fancy.example"]),
            secret("OTHER_TOKEN", &["api.other.example", "api.fancy.example"]),
        ],
        &[],
    )
    .unwrap_err();
    assert_eq!(refusal.code(), "bound_host_conflict");
    assert_eq!(
        refusal.to_string(),
        "api.fancy.example is named by both FANCY_TOKEN and OTHER_TOKEN; \
         one host carries only one of them"
    );
}

/// A bound secret on a host a selected credential binds is refused, on an
/// exact name and on any name under a suffix route; a look-alike that isn't
/// under the suffix is not the credential's.
#[test]
fn a_secret_on_a_selected_credentials_host_is_refused_by_name() {
    let codex = credentials(&["codex"]);
    for host in ["chatgpt.com", "workspace.chatgpt.com", "a.b.chatgpt.com"] {
        let refusal = union(&[secret("FANCY_TOKEN", &[host])], &codex).unwrap_err();
        assert_eq!(refusal.code(), "bound_host_conflict", "{host}");
        assert_eq!(
            refusal.to_string(),
            format!(
                "{host} is named by both a selected credential and FANCY_TOKEN; \
                 one host carries only one of them"
            )
        );
    }
    for host in ["xchatgpt.com", "chatgpt.com.example"] {
        assert!(
            union(&[secret("FANCY_TOKEN", &[host])], &codex).is_ok(),
            "{host}"
        );
    }
}

/// Sixteen bound-secret hosts are carried; a seventeenth is refused, naming
/// every bound key.
#[test]
fn more_than_sixteen_bound_hosts_are_refused_naming_the_keys() {
    let hosts = |prefix: &str, count: usize| -> Vec<String> {
        (0..count)
            .map(|index| format!("{prefix}{index}.fancy.example"))
            .collect()
    };
    let with = |first: usize, second: usize| {
        let first = hosts("a", first);
        let second = hosts("b", second);
        let first: Vec<&str> = first.iter().map(String::as_str).collect();
        let second: Vec<&str> = second.iter().map(String::as_str).collect();
        [
            secret("FANCY_TOKEN", &first),
            secret("OTHER_TOKEN", &second),
        ]
    };
    assert_eq!(union(&with(10, 6), &[]).map(|hosts| hosts.len()), Ok(16));
    let refusal = union(&with(10, 7), &[]).unwrap_err();
    assert_eq!(refusal.code(), "too_many_bound_hosts");
    assert_eq!(
        refusal.to_string(),
        "the bound secrets FANCY_TOKEN, OTHER_TOKEN name 17 hosts; \
         an environment carries at most 16"
    );
}

/// A bound secret on a name the deployment reserves now, exact or under a
/// reserved suffix, is refused by name; the same selection holds under a
/// deployment that doesn't reserve it.
#[test]
fn a_secret_on_a_name_the_deployment_now_reserves_is_refused_by_name() {
    let reserved =
        ReservedHosts::new(["openbao.sandbox.example.dev", "*.preview.example.dev"]).unwrap();
    for host in ["openbao.sandbox.example.dev", "app.preview.example.dev"] {
        let secrets = [
            secret("OTHER_TOKEN", &["api.other.example"]),
            secret("FANCY_TOKEN", &[host]),
        ];
        let refusal = bound_hosts(&secrets, &[], &reserved).unwrap_err();
        assert_eq!(refusal.code(), "bound_host_reserved", "{host}");
        assert_eq!(
            refusal.to_string(),
            format!("{host}, which FANCY_TOKEN is sent to, is one of this deployment's own names")
        );
        assert!(union(&secrets, &[]).is_ok(), "{host}");
    }
}
