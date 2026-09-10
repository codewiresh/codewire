use super::*;
use codewire_proto::codewire::bridge::v1 as public_bridge;

fn opening() -> proto::CredentialDelegationOpen {
    proto::CredentialDelegationOpen {
        runtime: Some(public_bridge::CredentialBridgeOpen {
            protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
            environment_id: Uuid::new_v4().to_string(),
            environment_generation: 7,
            ..Default::default()
        })
        .into(),
        org_id: "synthetic-organization".into(),
        selection_sha256: vec![7; 32],
        project_id: Some(Uuid::new_v4().to_string()),
        user_secrets: true,
        ordinary_environment_keys: vec!["ORDINARY".into()],
        reserved_environment_keys: codewire_project::platform_projection_reserved_keys([])
            .unwrap()
            .into_iter()
            .chain(["CODEX_HOME".into()])
            .collect(),
        ..Default::default()
    }
}

#[test]
fn delegation_selection_is_exact_names_only_and_owner_comes_from_authentication() {
    let open = opening();
    let source = selection(open.clone(), "synthetic-owner").unwrap();
    let mut other = open.clone();
    other.runtime.get_or_insert_default().environment_generation += 1;
    assert_ne!(source, selection(other, "synthetic-owner").unwrap());
    assert_ne!(
        source,
        selection(open, "another-authenticated-owner").unwrap()
    );
}

#[test]
fn delegation_selection_rejects_malformed_identity_digest_and_name_sets() {
    for attack in [
        "no runtime",
        "protocol",
        "nil",
        "noncanonical",
        "zero generation",
        "large generation",
        "org",
        "project",
        "hash length",
        "zero hash",
        "duplicate keys",
        "invalid key",
        "too many keys",
        "reserved collision",
        "profile revision",
    ] {
        let mut open = opening();
        match attack {
            "no runtime" => open.runtime = None.into(),
            "protocol" => open.runtime.get_or_insert_default().protocol_version += 1,
            "nil" => open.runtime.get_or_insert_default().environment_id = Uuid::nil().to_string(),
            "noncanonical" => {
                open.runtime.get_or_insert_default().environment_id = "not-a-native-uuid".into()
            }
            "zero generation" => open.runtime.get_or_insert_default().environment_generation = 0,
            "large generation" => {
                open.runtime.get_or_insert_default().environment_generation = u64::MAX
            }
            "org" => open.org_id.clear(),
            "project" => open.project_id = Some(String::new()),
            "hash length" => {
                open.selection_sha256.pop();
            }
            "zero hash" => open.selection_sha256.fill(0),
            "duplicate keys" => open.ordinary_environment_keys = vec!["DUPLICATE".into(); 2],
            "invalid key" => open.ordinary_environment_keys = vec!["NOT=AN_ENVIRONMENT_KEY".into()],
            "too many keys" => {
                open.ordinary_environment_keys = (0..=MAX_WORKLOAD_SECRETS)
                    .map(|i| format!("KEY_{i}"))
                    .collect()
            }
            "reserved collision" => open.ordinary_environment_keys = vec!["CODEX_HOME".into()],
            "profile revision" => {
                open.profile = Some(proto::CredentialDelegationProfile {
                    profile_id: Uuid::new_v4().to_string(),
                    profile_revision: 0,
                    ..Default::default()
                })
                .into()
            }
            _ => unreachable!(),
        }
        assert!(selection(open, "synthetic-owner").is_err(), "{attack}");
    }
}

fn request(
    frame: public_bridge::CredentialBridgeGuestMessage,
) -> proto::DelegateCredentialsRequest {
    proto::DelegateCredentialsRequest {
        input: Some(proto::delegate_credentials_request::Input::Frame(Box::new(
            frame,
        ))),
        ..Default::default()
    }
}

#[test]
fn delegation_frame_conversion_preserves_protocol_bytes_for_ready_http_ssh_and_projection() {
    use bridge::credential_bridge_guest_message::Payload;
    for payload in [
        Payload::Ready(bridge::CredentialBridgeReady {
            protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
            environment_id: Uuid::new_v4().to_string(),
            environment_generation: 7,
        }),
        Payload::Request(bridge::CredentialBridgeRequest {
            request_id: Uuid::new_v4().to_string(),
            method: "POST".into(),
            path: "/v1/responses".into(),
            body: b"synthetic-body".to_vec(),
            capability_slot: "codex".into(),
            route: "openai-api".into(),
            ..Default::default()
        }),
        Payload::Cancel(bridge::CredentialBridgeCancel {
            request_id: Uuid::new_v4().to_string(),
        }),
        Payload::Ssh(bridge::CredentialSshRequest {
            request_id: Uuid::new_v4().to_string(),
            deadline_unix_ms: 123456,
            operation: Some(bridge::credential_ssh_request::Operation::Sign(
                bridge::CredentialSshSignRequest {
                    public_key_blob: b"synthetic-public".to_vec(),
                    data: b"synthetic-signing-data".to_vec(),
                    flags: 2,
                },
            )),
        }),
        Payload::EnvironmentProjection(bridge::EnvironmentProjectionRequest {
            request_id: Uuid::new_v4().to_string(),
            selection_sha256: vec![7; 32],
            recipient_public_key: vec![9; 32],
            deadline_unix_ms: 123456,
            local_inventories: Vec::new(),
        }),
    ] {
        let original = bridge::CredentialBridgeGuestMessage {
            payload: Some(payload),
        };
        let bytes = original.encode_to_vec();
        let public =
            public_bridge::CredentialBridgeGuestMessage::decode_from_slice(&bytes).unwrap();
        assert_eq!(public.encode_to_vec(), bytes);
        assert_eq!(decode_frame(request(public)).unwrap(), original);
    }
}

#[test]
fn delegation_rejects_second_open_empty_unknown_and_oversized_frames() {
    assert!(
        decode_frame(proto::DelegateCredentialsRequest {
            input: Some(proto::delegate_credentials_request::Input::Open(Box::new(
                opening()
            ))),
            ..Default::default()
        })
        .is_err()
    );
    assert!(decode_frame(proto::DelegateCredentialsRequest::default()).is_err());
    assert!(
        decode_frame(request(
            public_bridge::CredentialBridgeGuestMessage::default()
        ))
        .is_err()
    );
    let unknown =
        public_bridge::CredentialBridgeGuestMessage::decode_from_slice(&[0xfa, 0x07, 0]).unwrap();
    assert!(decode_frame(request(unknown)).is_err());
    let oversized = public_bridge::CredentialBridgeGuestMessage {
        payload: Some(
            public_bridge::credential_bridge_guest_message::Payload::Request(Box::new(
                public_bridge::CredentialBridgeRequest {
                    body: vec![0; CREDENTIAL_BRIDGE_MAX_GRPC_MESSAGE_BYTES + 1],
                    ..Default::default()
                },
            )),
        ),
        ..Default::default()
    };
    assert!(decode_frame(request(oversized)).is_err());
}

#[test]
fn delegation_response_preserves_sealed_bytes_and_rejects_open_or_empty() {
    let response = bridge::CredentialBridgeHostMessage {
        payload: Some(
            bridge::credential_bridge_host_message::Payload::EnvironmentProjection(
                bridge::EnvironmentProjectionResponse {
                    request_id: Uuid::new_v4().to_string(),
                    result: Some(
                        bridge::environment_projection_response::Result::SealedProjection(
                            b"synthetic-recipient-ciphertext".to_vec(),
                        ),
                    ),
                },
            ),
        ),
    };
    let encoded = response.encode_to_vec();
    let wire = encode_frame(response).unwrap();
    let Some(proto::delegate_credentials_response::Output::Frame(frame)) = wire.output else {
        panic!("operation response must not be an admission acknowledgment");
    };
    assert_eq!(frame.encode_to_vec(), encoded);
    assert!(encode_frame(bridge::CredentialBridgeHostMessage::default()).is_err());
    assert!(
        encode_frame(bridge::CredentialBridgeHostMessage {
            payload: Some(bridge::credential_bridge_host_message::Payload::Open(
                bridge::CredentialBridgeOpen::default()
            ))
        })
        .is_err()
    );
}

#[test]
fn delegation_error_mapping_discards_upstream_diagnostics() {
    for status in [
        Status::permission_denied("synthetic-provider-secret-canary"),
        Status::unavailable("synthetic-provider-secret-canary"),
        Status::resource_exhausted("synthetic-provider-secret-canary"),
    ] {
        let error = wire_error(status);
        assert!(!format!("{error:?}").contains("synthetic-provider-secret-canary"));
    }
}
