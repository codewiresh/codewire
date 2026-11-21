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

// Placeholders are orchestration's to give a hosted Sandbox (#4001): an
// Open from a delegation client that carries any is refused.
#[test]
fn delegation_selection_refuses_placeholders_from_a_client() {
    let mut open = opening();
    open.runtime.get_or_insert_default().placeholders.push(
        public_bridge::CredentialBridgePlaceholder {
            capability_slot: "anthropic".into(),
            placeholder: codewire_access::known_answer::PLACEHOLDER.into(),
            ..Default::default()
        },
    );
    assert!(matches!(
        selection(open, "synthetic-owner"),
        Err(PlatformBridgeAuthenticationError::Denied)
    ));
    assert!(selection(opening(), "synthetic-owner").is_ok());
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

/// A front-door session's frames cross the delegation in neither direction:
/// each is refused exactly as an unknown or empty frame is.
#[test]
fn delegation_refuses_front_door_frames_as_unknown_frames() {
    use bridge::credential_bridge_guest_message::Payload as Guest;
    use bridge::credential_bridge_host_message::Payload as Host;
    let request_id = Uuid::new_v4().to_string();
    for payload in [
        Guest::Upgrade(bridge::CredentialBridgeUpgrade {
            request_id: request_id.clone(),
            method: "GET".into(),
            path: "/v1/responses".into(),
            intercepted_host: "chatgpt.com".into(),
            initial_credit_bytes: 65_536,
            ..Default::default()
        }),
        Guest::StreamData(bridge::CredentialBridgeStreamData {
            request_id: request_id.clone(),
            data: b"frame".to_vec(),
        }),
        Guest::StreamCredit(bridge::CredentialBridgeStreamCredit {
            request_id: request_id.clone(),
            credit_bytes: 1024,
        }),
        Guest::StreamClose(bridge::CredentialBridgeStreamClose {
            request_id: request_id.clone(),
            kind: bridge::CredentialBridgeStreamCloseKind::Reset as i32,
        }),
    ] {
        let bytes = bridge::CredentialBridgeGuestMessage {
            payload: Some(payload),
        }
        .encode_to_vec();
        let public =
            public_bridge::CredentialBridgeGuestMessage::decode_from_slice(&bytes).unwrap();
        assert_eq!(
            decode_frame(request(public)).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
    }
    for payload in [
        Host::UpgradeAccepted(bridge::CredentialBridgeUpgradeAccepted {
            request_id: request_id.clone(),
            headers: Vec::new(),
        }),
        Host::StreamData(bridge::CredentialBridgeStreamData {
            request_id: request_id.clone(),
            data: b"frame".to_vec(),
        }),
        Host::StreamCredit(bridge::CredentialBridgeStreamCredit {
            request_id: request_id.clone(),
            credit_bytes: 1024,
        }),
        Host::StreamClose(bridge::CredentialBridgeStreamClose {
            request_id: request_id.clone(),
            kind: bridge::CredentialBridgeStreamCloseKind::HalfClose as i32,
        }),
        Host::InterceptionHint(bridge::CredentialBridgeInterceptionHint {
            request_id: request_id.clone(),
            origin: "https://chatgpt.com".into(),
        }),
    ] {
        assert!(
            encode_frame(bridge::CredentialBridgeHostMessage {
                payload: Some(payload)
            })
            .is_err()
        );
    }
}

#[test]
fn delegation_error_mapping_discards_upstream_diagnostics() {
    for status in [
        Status::permission_denied("synthetic-provider-secret-canary"),
        Status::unavailable("synthetic-provider-secret-canary"),
        Status::resource_exhausted("synthetic-provider-secret-canary"),
        Status::already_exists("synthetic-provider-secret-canary"),
    ] {
        let error = wire_error(status);
        assert!(!format!("{error:?}").contains("synthetic-provider-secret-canary"));
    }
}

fn keepalive() -> proto::DelegateCredentialsRequest {
    proto::DelegateCredentialsRequest {
        input: Some(proto::delegate_credentials_request::Input::Keepalive(
            Box::default(),
        )),
        ..Default::default()
    }
}

#[test]
fn delegation_keepalive_is_answered_only_after_admission_one_at_a_time_and_never_bridged() {
    let (keepalives, mut answers) = Keepalives::new();
    // Before admission (the client has not seen `admitted`): the stream ends.
    assert_eq!(
        decode_input(keepalive(), &keepalives).unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    assert!(answers.try_recv().is_err());
    keepalives.admit();
    // Admitted: answered here, nothing for the bridge.
    assert_eq!(decode_input(keepalive(), &keepalives).unwrap(), None);
    // A second before the first answer went out: the stream ends.
    assert_eq!(
        decode_input(keepalive(), &keepalives).unwrap_err().code(),
        tonic::Code::ResourceExhausted
    );
    answers.try_recv().unwrap();
    assert!(answers.try_recv().is_err());
    assert_eq!(decode_input(keepalive(), &keepalives).unwrap(), None);
    answers.try_recv().unwrap();
    // Frames still reach the bridge unchanged, and a keepalive is not a frame
    // to a reader that predates it.
    let cancel = public_bridge::CredentialBridgeGuestMessage {
        payload: Some(
            public_bridge::credential_bridge_guest_message::Payload::Cancel(Box::new(
                public_bridge::CredentialBridgeCancel {
                    request_id: Uuid::new_v4().to_string(),
                    ..Default::default()
                },
            )),
        ),
        ..Default::default()
    };
    assert!(matches!(
        decode_input(request(cancel), &keepalives),
        Ok(Some(bridge::CredentialBridgeGuestMessage {
            payload: Some(bridge::credential_bridge_guest_message::Payload::Cancel(_))
        }))
    ));
    assert!(decode_frame(keepalive()).is_err());
    // After the response ended, a late keepalive changes nothing.
    drop(answers);
    assert_eq!(decode_input(keepalive(), &keepalives).unwrap(), None);
}

#[tokio::test]
async fn delegation_response_merges_keepalive_answers_and_ends_with_the_bridge() {
    let (keepalives, answers) = Keepalives::new();
    keepalives.admit();
    let (frames_tx, frames_rx) = mpsc::channel(4);
    let frames = Box::pin(futures::stream::unfold(
        frames_rx,
        |mut frames| async move { frames.recv().await.map(|frame| (frame, frames)) },
    ));
    let mut responses = Box::pin(with_keepalive_answers(frames, answers));
    let frame = |id: &str| {
        let mut response = keepalive_answer();
        response.output = Some(proto::delegate_credentials_response::Output::Frame(
            Box::new(public_bridge::CredentialBridgeHostMessage {
                payload: Some(
                    public_bridge::credential_bridge_host_message::Payload::ResponseEnd(Box::new(
                        public_bridge::CredentialBridgeResponseEnd {
                            request_id: id.into(),
                            ..Default::default()
                        },
                    )),
                ),
                ..Default::default()
            }),
        ));
        response
    };
    decode_input(keepalive(), &keepalives).unwrap();
    let answer = responses.next().await.unwrap().unwrap();
    assert!(matches!(
        answer.output,
        Some(proto::delegate_credentials_response::Output::Keepalive(_))
    ));
    assert!(!answer.accepts_keepalive);
    frames_tx.send(Ok(frame("first"))).await.unwrap();
    assert_eq!(responses.next().await.unwrap().unwrap(), frame("first"));
    // The bridge's end ends the response although keepalives could still come.
    drop(frames_tx);
    assert!(responses.next().await.is_none());
    drop(keepalives);
}

/// A front-door delegation carries front-door frames both ways unchanged,
/// and the same bounds as a delegation: no empty frame, and never a host
/// Open, which the local relay writes itself (#4909).
#[test]
fn front_door_delegation_carries_front_door_frames_and_refuses_open_or_empty() {
    use bridge::credential_bridge_guest_message::Payload as Guest;
    use bridge::credential_bridge_host_message::Payload as Host;
    let request_id = Uuid::new_v4().to_string();
    let guest = bridge::CredentialBridgeGuestMessage {
        payload: Some(Guest::StreamData(bridge::CredentialBridgeStreamData {
            request_id: request_id.clone(),
            data: b"frame".to_vec(),
        })),
    };
    let bytes = guest.encode_to_vec();
    let public = public_bridge::CredentialBridgeGuestMessage::decode_from_slice(&bytes).unwrap();
    let decoded = decode_front_door_frame(proto::FrontDoorDelegationRequest {
        frame: Some(public).into(),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(decoded.encode_to_vec(), bytes);
    for empty in [
        proto::FrontDoorDelegationRequest::default(),
        proto::FrontDoorDelegationRequest {
            frame: Some(public_bridge::CredentialBridgeGuestMessage::default()).into(),
            ..Default::default()
        },
    ] {
        assert_eq!(
            decode_front_door_frame(empty).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
    }

    let host = bridge::CredentialBridgeHostMessage {
        payload: Some(Host::StreamData(bridge::CredentialBridgeStreamData {
            request_id,
            data: b"answer".to_vec(),
        })),
    };
    let encoded = host.encode_to_vec();
    let wire = encode_front_door_frame(host).unwrap();
    let Some(proto::front_door_delegation_response::Output::Frame(frame)) = wire.output else {
        panic!("a front-door frame must not be an admission");
    };
    assert_eq!(frame.encode_to_vec(), encoded);
    for refused in [
        bridge::CredentialBridgeHostMessage::default(),
        bridge::CredentialBridgeHostMessage {
            payload: Some(Host::Open(bridge::CredentialBridgeOpen::default())),
        },
    ] {
        assert!(encode_front_door_frame(refused).is_err());
    }
}

/// A refused join is logged by its code alone: an unknown, ended and other
/// owner's handle are one reason, and nothing presented is ever written.
#[test]
fn a_refused_front_door_join_is_counted_by_code_and_never_by_its_content() {
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let writer = {
        let lines = std::sync::Arc::clone(&lines);
        move || CaptureWriter(std::sync::Arc::clone(&lines))
    };
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        front_door_refused(&Status::permission_denied("synthetic-presented-handle"));
        front_door_refused(&Status::already_exists("synthetic-second-join"));
    });
    let logged = String::from_utf8(lines.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("reason=\"no_live_epoch\""), "{logged}");
    assert!(logged.contains("reason=\"already_joined\""), "{logged}");
    assert!(!logged.contains("synthetic"), "{logged}");
}

struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
