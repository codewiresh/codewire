//! A secret's binding on the wire (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md,
//! "Host-bound application secrets"): what a set request asks of it, in the
//! store's form, and a stored binding back as metadata. The store validates
//! what this builds; only the wire's defaults are filled in here.

use codewire_access::{
    DEFAULT_BASIC_USERNAME, DEFAULT_BOUND_HEADER, DEFAULT_BOUND_SCHEME, StoredBinding,
    StoredPresentation,
};
use codewire_proto::codewire::v1::{
    SecretBasicPresentation, SecretBasicUserPresentation, SecretBinding, SecretBindingView,
    SecretHeaderPresentation, secret_binding,
};
use codewire_server_core::{AppError, AppResult};

use crate::worker::secrets::BindingWrite;

/// The scheme word that sends the value alone.
const NO_SCHEME: &str = "none";

/// What a set request does to the secret's binding: a binding binds or
/// rebinds it, `plain` removes every host, and neither keeps what it has.
pub(super) fn binding_write(
    binding: Option<&SecretBindingView<'_>>,
    plain: bool,
) -> AppResult<BindingWrite> {
    match (binding, plain) {
        (Some(_), true) => Err(AppError::BadRequest(
            "a request binds a secret to hosts or makes it plain, not both".into(),
        )),
        (Some(binding), false) => Ok(BindingWrite::Bind(stored_binding(binding))),
        (None, true) => Ok(BindingWrite::Plain),
        (None, false) => Ok(BindingWrite::Keep),
    }
}

fn stored_binding(binding: &SecretBindingView<'_>) -> StoredBinding {
    let presentation = match &binding.presentation {
        Some(secret_binding::PresentationView::Header(header)) => StoredPresentation::Header {
            headers: if header.headers.is_empty() {
                vec![DEFAULT_BOUND_HEADER.to_owned()]
            } else {
                header
                    .headers
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect()
            },
            scheme: match header.scheme {
                None => Some(DEFAULT_BOUND_SCHEME.to_owned()),
                Some(word) if word.eq_ignore_ascii_case(NO_SCHEME) => None,
                Some(word) => Some(word.to_owned()),
            },
        },
        Some(secret_binding::PresentationView::Basic(basic)) => StoredPresentation::Basic {
            username: if basic.username.is_empty() {
                DEFAULT_BASIC_USERNAME
            } else {
                basic.username
            }
            .to_owned(),
        },
        Some(secret_binding::PresentationView::BasicUser(_)) => StoredPresentation::BasicUser,
        // `header` is the default presentation.
        None => StoredPresentation::Header {
            headers: vec![DEFAULT_BOUND_HEADER.to_owned()],
            scheme: Some(DEFAULT_BOUND_SCHEME.to_owned()),
        },
    };
    StoredBinding {
        hosts: binding
            .hosts
            .iter()
            .map(|host| (*host).to_owned())
            .collect(),
        presentation,
        prefix: non_empty(binding.prefix),
        preset: non_empty(binding.preset),
    }
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

/// A stored binding as metadata, with the generation its placeholder is
/// derived from. A header binding always names its scheme, `none` included,
/// so a client never reads the default into a binding that has none.
pub(super) fn proto_binding(binding: StoredBinding, binding_generation: u64) -> SecretBinding {
    let presentation = match binding.presentation {
        StoredPresentation::Header { headers, scheme } => {
            secret_binding::Presentation::from(SecretHeaderPresentation {
                headers,
                scheme: Some(scheme.unwrap_or_else(|| NO_SCHEME.to_owned())),
                ..Default::default()
            })
        }
        StoredPresentation::Basic { username } => {
            secret_binding::Presentation::from(SecretBasicPresentation {
                username,
                ..Default::default()
            })
        }
        StoredPresentation::BasicUser => {
            secret_binding::Presentation::from(SecretBasicUserPresentation::default())
        }
    };
    SecretBinding {
        hosts: binding.hosts,
        presentation: Some(presentation),
        prefix: binding.prefix.unwrap_or_default(),
        preset: binding.preset.unwrap_or_default(),
        binding_generation,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use buffa::{Message, MessageView};
    use codewire_proto::codewire::v1::{SetSecretRequest, SetSecretRequestView};

    use super::*;

    fn write_of(request: &SetSecretRequest) -> AppResult<BindingWrite> {
        let bytes = request.encode_to_vec();
        let view = SetSecretRequestView::decode_view(&bytes).unwrap();
        binding_write(view.binding.as_option(), view.plain)
    }

    fn bound(binding: SecretBinding) -> StoredBinding {
        let request = SetSecretRequest {
            binding: Some(binding).into(),
            ..Default::default()
        };
        match write_of(&request).unwrap() {
            BindingWrite::Bind(stored) => stored,
            other => panic!("expected a binding, got {other:?}"),
        }
    }

    fn header(headers: &[&str], scheme: Option<&str>) -> secret_binding::Presentation {
        SecretHeaderPresentation {
            headers: headers.iter().map(|name| (*name).to_owned()).collect(),
            scheme: scheme.map(str::to_owned),
            ..Default::default()
        }
        .into()
    }

    #[test]
    fn neither_binding_nor_plain_keeps_the_binding() {
        assert!(matches!(
            write_of(&SetSecretRequest::default()),
            Ok(BindingWrite::Keep)
        ));
        assert!(matches!(
            write_of(&SetSecretRequest {
                plain: true,
                ..Default::default()
            }),
            Ok(BindingWrite::Plain)
        ));
    }

    #[test]
    fn a_binding_and_plain_together_are_refused() {
        let error = write_of(&SetSecretRequest {
            binding: Some(SecretBinding {
                hosts: vec!["api.example.com".into()],
                ..Default::default()
            })
            .into(),
            plain: true,
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(error.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_header_binding_fills_the_wire_defaults() {
        let bearer = StoredPresentation::Header {
            headers: vec!["Authorization".into()],
            scheme: Some("Bearer".into()),
        };
        let no_presentation = bound(SecretBinding {
            hosts: vec!["api.example.com".into()],
            ..Default::default()
        });
        assert_eq!(no_presentation.hosts, ["api.example.com"]);
        assert_eq!(no_presentation.presentation, bearer);
        assert_eq!(no_presentation.prefix, None);
        assert_eq!(no_presentation.preset, None);
        let empty_header = bound(SecretBinding {
            presentation: Some(header(&[], None)),
            ..Default::default()
        });
        assert_eq!(empty_header.presentation, bearer);
        for none in ["none", "None"] {
            assert_eq!(
                bound(SecretBinding {
                    presentation: Some(header(&["X-Api-Key"], Some(none))),
                    ..Default::default()
                })
                .presentation,
                StoredPresentation::Header {
                    headers: vec!["X-Api-Key".into()],
                    scheme: None,
                }
            );
        }
        assert_eq!(
            bound(SecretBinding {
                presentation: Some(header(&["X-Api-Key", "Authorization"], Some("token"))),
                prefix: "sk_".into(),
                preset: "fancy".into(),
                ..Default::default()
            }),
            StoredBinding {
                hosts: Vec::new(),
                presentation: StoredPresentation::Header {
                    headers: vec!["X-Api-Key".into(), "Authorization".into()],
                    scheme: Some("token".into()),
                },
                prefix: Some("sk_".into()),
                preset: Some("fancy".into()),
            }
        );
    }

    #[test]
    fn basic_bindings_fill_the_user_name() {
        let basic = |username: &str| {
            bound(SecretBinding {
                presentation: Some(
                    SecretBasicPresentation {
                        username: username.into(),
                        ..Default::default()
                    }
                    .into(),
                ),
                ..Default::default()
            })
            .presentation
        };
        assert_eq!(
            basic(""),
            StoredPresentation::Basic {
                username: "x-access-token".into()
            }
        );
        assert_eq!(
            basic("git"),
            StoredPresentation::Basic {
                username: "git".into()
            }
        );
        assert_eq!(
            bound(SecretBinding {
                presentation: Some(SecretBasicUserPresentation::default().into()),
                ..Default::default()
            })
            .presentation,
            StoredPresentation::BasicUser
        );
    }

    #[test]
    fn metadata_names_every_field_and_the_generation() {
        let proto = proto_binding(
            StoredBinding {
                hosts: vec!["api.example.com".into(), "uploads.example.com".into()],
                presentation: StoredPresentation::Header {
                    headers: vec!["X-Api-Key".into()],
                    scheme: None,
                },
                prefix: Some("sk_".into()),
                preset: None,
            },
            3,
        );
        assert_eq!(proto.hosts, ["api.example.com", "uploads.example.com"]);
        assert_eq!(
            proto.presentation,
            Some(header(&["X-Api-Key"], Some("none")))
        );
        assert_eq!(proto.prefix, "sk_");
        assert_eq!(proto.preset, "");
        assert_eq!(proto.binding_generation, 3);
        let basic_user = proto_binding(
            StoredBinding {
                hosts: vec!["api.example.com".into()],
                presentation: StoredPresentation::BasicUser,
                prefix: None,
                preset: Some("payments".into()),
            },
            0,
        );
        assert_eq!(
            basic_user.presentation,
            Some(SecretBasicUserPresentation::default().into())
        );
        assert_eq!(basic_user.preset, "payments");
    }

    #[test]
    fn an_empty_value_keeps_a_refused_change_and_only_names_the_value_when_plain() {
        let required = AppError::Coded {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: crate::api::secrets::SECRET_VALUE_REQUIRED,
            detail: "adding a host needs the secret's value again".into(),
        };
        assert!(matches!(
            super::super::secret_write_validation(required, "TOKEN", ""),
            AppError::Coded {
                code: "secret_value_required",
                ..
            }
        ));
        let plain = AppError::BadRequest("secret value must be non-empty".into());
        assert!(matches!(
            super::super::secret_write_validation(plain, "TOKEN", ""),
            AppError::Validation { errors } if errors[0].path == "/value"
        ));
    }

    #[test]
    fn metadata_read_back_as_a_request_binds_the_same() {
        let stored = StoredBinding {
            hosts: vec!["api.example.com".into()],
            presentation: StoredPresentation::Header {
                headers: vec!["Authorization".into()],
                scheme: None,
            },
            prefix: None,
            preset: None,
        };
        assert_eq!(bound(proto_binding(stored.clone(), 7)), stored);
    }
}
