//! A secret's binding as `cw` shows it (`list --output json`; #4003), and
//! to and from the cloud's wire form (docs/dev/SECRETS-AND-CREDENTIALS.md,
//! "Host-bound application secrets").

use codewire_access::{
    BindingWrite, DEFAULT_BASIC_USERNAME, DEFAULT_BOUND_HEADER, DEFAULT_BOUND_SCHEME,
    StoredBinding, StoredPresentation,
};
use codewire_client as rpc;
use serde::{Deserialize, Serialize};

/// The scheme word for a header that holds the value alone.
pub(crate) const NO_SCHEME: &str = "none";

/// How a bound value is presented, as JSON names it.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PresentationKind {
    Header,
    Basic,
    BasicUser,
}

/// A secret's binding in `list --output json`. A field that doesn't apply to
/// its presentation is `null`; a header with no scheme has the scheme
/// `none`, as `--scheme none` sets it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SecretBindingView {
    pub hosts: Vec<String>,
    pub presentation: PresentationKind,
    pub headers: Option<Vec<String>>,
    pub scheme: Option<String>,
    pub prefix: Option<String>,
    pub username: Option<String>,
    pub preset: Option<String>,
    pub binding_generation: u64,
}

impl SecretBindingView {
    pub fn new(binding: &StoredBinding, binding_generation: u64) -> Self {
        let (presentation, headers, scheme, username) = match &binding.presentation {
            StoredPresentation::Header { headers, scheme } => (
                PresentationKind::Header,
                Some(headers.clone()),
                Some(scheme.clone().unwrap_or_else(|| NO_SCHEME.to_owned())),
                None,
            ),
            StoredPresentation::Basic { username } => {
                (PresentationKind::Basic, None, None, Some(username.clone()))
            }
            StoredPresentation::BasicUser => (PresentationKind::BasicUser, None, None, None),
        };
        Self {
            hosts: binding.hosts.clone(),
            presentation,
            headers,
            scheme,
            prefix: binding.prefix.clone(),
            username,
            preset: binding.preset.clone(),
            binding_generation,
        }
    }

    /// The binding as the stores keep it.
    pub fn stored(&self) -> StoredBinding {
        let presentation = match self.presentation {
            PresentationKind::Header => StoredPresentation::Header {
                headers: self
                    .headers
                    .clone()
                    .unwrap_or_else(|| vec![DEFAULT_BOUND_HEADER.to_owned()]),
                scheme: match self.scheme.as_deref() {
                    None => Some(DEFAULT_BOUND_SCHEME.to_owned()),
                    Some(word) if word.eq_ignore_ascii_case(NO_SCHEME) => None,
                    Some(word) => Some(word.to_owned()),
                },
            },
            PresentationKind::Basic => StoredPresentation::Basic {
                username: self
                    .username
                    .clone()
                    .unwrap_or_else(|| DEFAULT_BASIC_USERNAME.to_owned()),
            },
            PresentationKind::BasicUser => StoredPresentation::BasicUser,
        };
        StoredBinding {
            hosts: self.hosts.clone(),
            presentation,
            prefix: self.prefix.clone(),
            preset: self.preset.clone(),
        }
    }
}

/// The cloud's binding as `cw` shows it, with the wire's defaults filled in
/// as the service fills them.
pub(super) fn view_from_proto(binding: &rpc::SecretBinding) -> SecretBindingView {
    let presentation = match &binding.presentation {
        Some(rpc::secret_binding::Presentation::Header(header)) => StoredPresentation::Header {
            headers: if header.headers.is_empty() {
                vec![DEFAULT_BOUND_HEADER.to_owned()]
            } else {
                header.headers.clone()
            },
            scheme: match header.scheme.as_deref() {
                None => Some(DEFAULT_BOUND_SCHEME.to_owned()),
                Some(word) if word.eq_ignore_ascii_case(NO_SCHEME) => None,
                Some(word) => Some(word.to_owned()),
            },
        },
        Some(rpc::secret_binding::Presentation::Basic(basic)) => StoredPresentation::Basic {
            username: if basic.username.is_empty() {
                DEFAULT_BASIC_USERNAME.to_owned()
            } else {
                basic.username.clone()
            },
        },
        Some(rpc::secret_binding::Presentation::BasicUser(_)) => StoredPresentation::BasicUser,
        None => StoredPresentation::Header {
            headers: vec![DEFAULT_BOUND_HEADER.to_owned()],
            scheme: Some(DEFAULT_BOUND_SCHEME.to_owned()),
        },
    };
    let stored = StoredBinding {
        hosts: binding.hosts.clone(),
        presentation,
        prefix: non_empty(&binding.prefix),
        preset: non_empty(&binding.preset),
    };
    SecretBindingView::new(&stored, binding.binding_generation)
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

/// A write's `binding` and `plain` fields on the wire. A header binding
/// always names its scheme, `none` included, so the service never reads the
/// default into a binding that has none.
pub(super) fn write_fields(binding: &BindingWrite) -> (Option<rpc::SecretBinding>, bool) {
    match binding {
        BindingWrite::Keep => (None, false),
        BindingWrite::Plain => (None, true),
        BindingWrite::Bind(stored) => (Some(proto_binding(stored)), false),
    }
}

fn proto_binding(binding: &StoredBinding) -> rpc::SecretBinding {
    let presentation = match &binding.presentation {
        StoredPresentation::Header { headers, scheme } => {
            rpc::secret_binding::Presentation::from(rpc::SecretHeaderPresentation {
                headers: headers.clone(),
                scheme: Some(scheme.clone().unwrap_or_else(|| NO_SCHEME.to_owned())),
                ..Default::default()
            })
        }
        StoredPresentation::Basic { username } => {
            rpc::secret_binding::Presentation::from(rpc::SecretBasicPresentation {
                username: username.clone(),
                ..Default::default()
            })
        }
        StoredPresentation::BasicUser => {
            rpc::secret_binding::Presentation::from(rpc::SecretBasicUserPresentation::default())
        }
    };
    rpc::SecretBinding {
        hosts: binding.hosts.clone(),
        presentation: Some(presentation),
        prefix: binding.prefix.clone().unwrap_or_default(),
        preset: binding.preset.clone().unwrap_or_default(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(presentation: StoredPresentation, prefix: Option<&str>) -> StoredBinding {
        StoredBinding {
            hosts: vec!["api.fancy.com".into()],
            presentation,
            prefix: prefix.map(str::to_owned),
            preset: None,
        }
    }

    /// The design's `list --output json` row for a bound secret.
    #[test]
    fn a_header_binding_shows_as_the_design_lists_it() {
        let view = SecretBindingView::new(
            &stored(
                StoredPresentation::Header {
                    headers: vec!["Authorization".into()],
                    scheme: Some("Bearer".into()),
                },
                Some("ft_"),
            ),
            3,
        );
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            serde_json::json!({
                "hosts": ["api.fancy.com"],
                "presentation": "header",
                "headers": ["Authorization"],
                "scheme": "Bearer",
                "prefix": "ft_",
                "username": null,
                "preset": null,
                "binding_generation": 3
            })
        );
    }

    #[test]
    fn every_presentation_survives_the_wire_and_the_view() {
        for presentation in [
            StoredPresentation::Header {
                headers: vec!["X-Api-Key".into(), "Authorization".into()],
                scheme: None,
            },
            StoredPresentation::Header {
                headers: vec!["Authorization".into()],
                scheme: Some("token".into()),
            },
            StoredPresentation::Basic {
                username: "x-access-token".into(),
            },
            StoredPresentation::BasicUser,
        ] {
            let binding = stored(presentation, Some("sk_"));
            let (wire, plain) = write_fields(&BindingWrite::Bind(binding.clone()));
            assert!(!plain);
            let view = view_from_proto(&wire.unwrap());
            assert_eq!(view.stored(), binding);
            let json = serde_json::to_string(&view).unwrap();
            let back: SecretBindingView = serde_json::from_str(&json).unwrap();
            assert_eq!(back.stored(), binding);
        }
        assert_eq!(
            SecretBindingView::new(&stored(StoredPresentation::BasicUser, None), 1).presentation,
            PresentationKind::BasicUser
        );
        assert_eq!(
            serde_json::to_value(PresentationKind::BasicUser).unwrap(),
            "basic-user"
        );
    }

    #[test]
    fn keep_and_plain_send_no_binding() {
        assert_eq!(write_fields(&BindingWrite::Keep), (None, false));
        assert_eq!(write_fields(&BindingWrite::Plain), (None, true));
    }

    #[test]
    fn the_wire_defaults_are_filled_as_the_service_fills_them() {
        let view = view_from_proto(&rpc::SecretBinding {
            hosts: vec!["api.fancy.com".into()],
            ..Default::default()
        });
        assert_eq!(
            view.stored().presentation,
            StoredPresentation::Header {
                headers: vec!["Authorization".into()],
                scheme: Some("Bearer".into()),
            }
        );
    }
}
