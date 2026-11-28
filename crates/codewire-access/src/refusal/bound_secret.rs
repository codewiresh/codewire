//! The refusals of a host-bound secret's swap (#4003;
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "The swap" step 4, "Hints" and
//! "Refusals an agent or a person can read"). Each is 403, rendered like
//! every other refusal: `Codewire:`, the sentence, and a `Fix:` line where
//! the row has one. A body names the key (the variable the environment
//! already reads it under), the bound host and the header, never a value, a
//! placeholder, an ID or anything else the request carried.

use super::{REFUSAL_HEADER, RefusalCode};
use crate::SecretKind;

/// Where a request carried a bound secret's placeholder outside its binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutsideBinding {
    /// In a header the binding doesn't name, or in the bound header in
    /// another shape. `scheme` is the word the request put before it, `None`
    /// for the placeholder alone, and the header's shape is anything else
    /// when `exact` is false: then no command can bind it there.
    Header {
        name: String,
        scheme: Option<String>,
        exact: bool,
    },
    Query,
    Body,
}

/// One refusal of a request on a bound secret's host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoundSecretRefusal {
    /// `placeholder_outside_binding`: `key`'s placeholder elsewhere on
    /// `host`, whose binding sends it in `bound_header`. `kind` names the
    /// set it is stored in, for the command that would bind it there.
    OutsideBinding {
        key: String,
        kind: SecretKind,
        host: String,
        bound_header: String,
        sent: OutsideBinding,
    },
    /// `secret_not_bound_to_host`: `key`'s placeholder on a host its binding
    /// no longer names, or never named for this environment.
    NotBoundToHost {
        key: String,
        kind: SecretKind,
        host: String,
    },
    /// `secret_binding_changed`: a placeholder from before `key`'s binding
    /// changed, or for a secret that is plain now.
    BindingChanged { key: String },
    /// `secret_deleted`: `key` was deleted.
    Deleted { key: String },
}

impl BoundSecretRefusal {
    pub fn code(&self) -> RefusalCode {
        match self {
            Self::OutsideBinding { .. } => RefusalCode::PlaceholderOutsideBinding,
            Self::NotBoundToHost { .. } => RefusalCode::SecretNotBoundToHost,
            Self::BindingChanged { .. } => RefusalCode::SecretBindingChanged,
            Self::Deleted { .. } => RefusalCode::SecretDeleted,
        }
    }

    /// Every one is final: a retry changes nothing.
    pub const fn status(&self) -> u16 {
        403
    }

    /// The headers every refusal carries besides its length.
    pub fn headers(&self) -> [(&'static str, &'static str); 3] {
        [
            ("content-type", "text/plain; charset=utf-8"),
            ("cache-control", "no-store"),
            (REFUSAL_HEADER, self.code().as_str()),
        ]
    }

    /// The plain-text body: the sentence, then the hint.
    pub fn body(&self) -> String {
        let (sentence, fix) = match self {
            Self::OutsideBinding {
                key,
                kind,
                host,
                bound_header,
                sent,
            } => (
                format!(
                    "{key} is bound to {bound_header} on {host}; this request sent it elsewhere, so it was not sent."
                ),
                Some(outside_binding_hint(key, *kind, host, sent)),
            ),
            Self::NotBoundToHost { key, kind, host } => (
                format!("{key} is not bound to {host}."),
                Some(format!(
                    "Fix: bind it with `cw secrets --cloud {} set {key} --host {host}` (it asks for the value again), then restart the environment.",
                    scope_flag(*kind)
                )),
            ),
            Self::BindingChanged { key } => (
                format!("{key}'s binding changed since this environment started."),
                Some("Fix: restart the environment.".to_owned()),
            ),
            Self::Deleted { key } => (format!("{key} was deleted."), None),
        };
        match fix {
            Some(fix) => format!("Codewire: {sentence}\n{fix}\n"),
            None => format!("Codewire: {sentence}\n"),
        }
    }
}

/// The hint for a placeholder sent outside its binding. In a header, the
/// exact command that binds it there; it never advises making the secret
/// plain, since a package in the environment can send the placeholder there
/// on purpose to produce that advice.
fn outside_binding_hint(key: &str, kind: SecretKind, host: &str, sent: &OutsideBinding) -> String {
    const UNPROTECTED: &str = "Codewire can't protect a value sent there, and a plain secret is readable by every process in the environment.";
    match sent {
        OutsideBinding::Header {
            name,
            scheme,
            exact: true,
        } => format!(
            "Fix: to send it in {name}, run `cw secrets --cloud {} set {key} --host {host} --header {name} --scheme {}`; it asks for the value again.",
            scope_flag(kind),
            scheme.as_deref().unwrap_or("none"),
        ),
        OutsideBinding::Header { name, .. } => format!(
            "Codewire sends {key} in {name} only as a scheme and the value, or the value alone."
        ),
        OutsideBinding::Query => format!("It was in the query string. {UNPROTECTED}"),
        OutsideBinding::Body => format!("It was in the body. {UNPROTECTED}"),
    }
}

/// The `cw secrets` scope flag of a set. A project is named by `PROJECT`:
/// the body never carries its ID, and the front door doesn't know its name.
fn scope_flag(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::Project => "--project=PROJECT",
        SecretKind::Organization => "--organization",
        SecretKind::User | SecretKind::Local => "--user",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "api.fancy.example";

    fn outside(sent: OutsideBinding) -> BoundSecretRefusal {
        BoundSecretRefusal::OutsideBinding {
            key: "FANCY_TOKEN".into(),
            kind: SecretKind::Project,
            host: HOST.into(),
            bound_header: "Authorization".into(),
            sent,
        }
    }

    /// Each body, as the spec's table writes it.
    #[test]
    fn each_refusal_renders_its_row() {
        assert_eq!(
            outside(OutsideBinding::Header {
                name: "X-Api-Key".into(),
                scheme: None,
                exact: true,
            })
            .body(),
            "Codewire: FANCY_TOKEN is bound to Authorization on api.fancy.example; this request sent it elsewhere, so it was not sent.\nFix: to send it in X-Api-Key, run `cw secrets --cloud --project=PROJECT set FANCY_TOKEN --host api.fancy.example --header X-Api-Key --scheme none`; it asks for the value again.\n"
        );
        assert_eq!(
            outside(OutsideBinding::Header {
                name: "X-Api-Key".into(),
                scheme: Some("Token".into()),
                exact: true,
            })
            .body()
            .lines()
            .nth(1),
            Some(
                "Fix: to send it in X-Api-Key, run `cw secrets --cloud --project=PROJECT set FANCY_TOKEN --host api.fancy.example --header X-Api-Key --scheme Token`; it asks for the value again."
            )
        );
        for (sent, line) in [
            (
                OutsideBinding::Query,
                "It was in the query string. Codewire can't protect a value sent there, and a plain secret is readable by every process in the environment.",
            ),
            (
                OutsideBinding::Body,
                "It was in the body. Codewire can't protect a value sent there, and a plain secret is readable by every process in the environment.",
            ),
        ] {
            let body = outside(sent).body();
            assert_eq!(body.lines().nth(1), Some(line));
            assert!(!body.contains("cw secrets"), "{body}");
        }
        assert_eq!(
            BoundSecretRefusal::NotBoundToHost {
                key: "FANCY_TOKEN".into(),
                kind: SecretKind::Organization,
                host: HOST.into(),
            }
            .body(),
            "Codewire: FANCY_TOKEN is not bound to api.fancy.example.\nFix: bind it with `cw secrets --cloud --organization set FANCY_TOKEN --host api.fancy.example` (it asks for the value again), then restart the environment.\n"
        );
        assert_eq!(
            BoundSecretRefusal::BindingChanged {
                key: "FANCY_TOKEN".into()
            }
            .body(),
            "Codewire: FANCY_TOKEN's binding changed since this environment started.\nFix: restart the environment.\n"
        );
        assert_eq!(
            BoundSecretRefusal::Deleted {
                key: "FANCY_TOKEN".into()
            }
            .body(),
            "Codewire: FANCY_TOKEN was deleted.\n"
        );
    }

    /// Never a hint to make the secret plain.
    #[test]
    fn no_hint_advises_making_a_secret_plain() {
        for sent in [
            OutsideBinding::Query,
            OutsideBinding::Body,
            OutsideBinding::Header {
                name: "Cookie".into(),
                scheme: None,
                exact: false,
            },
        ] {
            assert!(!outside(sent).body().contains("--plain"));
        }
    }

    #[test]
    fn each_refusal_is_a_403_with_its_code() {
        for (refusal, code) in [
            (
                outside(OutsideBinding::Query),
                "placeholder_outside_binding",
            ),
            (
                BoundSecretRefusal::NotBoundToHost {
                    key: "K".into(),
                    kind: SecretKind::User,
                    host: HOST.into(),
                },
                "secret_not_bound_to_host",
            ),
            (
                BoundSecretRefusal::BindingChanged { key: "K".into() },
                "secret_binding_changed",
            ),
            (
                BoundSecretRefusal::Deleted { key: "K".into() },
                "secret_deleted",
            ),
        ] {
            assert_eq!(refusal.status(), 403);
            assert_eq!(refusal.headers()[2], (REFUSAL_HEADER, code));
            assert_eq!(RefusalCode::from_code(code), Some(refusal.code()));
        }
    }
}
