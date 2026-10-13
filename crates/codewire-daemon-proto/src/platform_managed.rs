//! Closed framing for the original-channel platform managed service. No lookup,
//! credentials, process execution, local state or public authorization lives here.
use crate::daemon::v1;
use prost::Message;
use sha2::{Digest, Sha256};

pub const CAPABILITY: &str = "platform_managed_session.v1";
pub const PROTOCOL: u32 = 1;
pub const REQUEST_BYTES: usize = 512 * 1024;
pub const RECORD_BYTES: usize = 5 * 1024 * 1024;
pub const FRAME_BYTES: usize = 256 * 1024;
pub const TEXT_BYTES: usize = 64 * 1024;
pub const SUPPORT_BYTES: u64 = 256 * 1024 * 1024;
pub const PROVIDER_BYTES: u64 = 512 * 1024 * 1024;

pub fn valid_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && s.bytes().any(|b| matches!(b, b'1'..=b'9' | b'a'..=b'f'))
}
pub fn valid_session(s: &str) -> bool {
    s.strip_prefix("session-").is_some_and(valid_uuid)
}
pub fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && s.bytes().any(|b| b != b'0')
}
fn hash(b: &[u8]) -> bool {
    b.len() == 32 && b.iter().any(|b| *b != 0)
}
fn token(s: &str, bound: usize) -> bool {
    !s.is_empty() && s.len() <= bound && s.trim() == s && !s.chars().any(char::is_control)
}
fn text(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= TEXT_BYTES && !s.contains('\0')
}
pub fn validate_scope(s: &v1::PlatformManagedScope) -> Result<(), &'static str> {
    if valid_uuid(&s.environment_id)
        && token(&s.org_id, 256)
        && valid_uuid(&s.pod_uid)
        && s.binding_generation > 0
        && hash(&s.projection_selection_sha256)
        && hash(&s.support_image_sha256)
        && (4..=SUPPORT_BYTES).contains(&s.support_image_size)
    {
        Ok(())
    } else {
        Err("invalid platform scope")
    }
}
pub fn validate_info(r: &v1::PlatformManagedInfoRequest) -> Result<(), &'static str> {
    if valid_uuid(&r.environment_id)
        && r.binding_generation > 0
        && hash(&r.projection_selection_sha256)
    {
        Ok(())
    } else {
        Err("invalid platform info")
    }
}
pub fn provider_version(a: v1::PlatformManagedAgent) -> Option<&'static str> {
    match a {
        v1::PlatformManagedAgent::Codex => Some("0.160.0"),
        v1::PlatformManagedAgent::Claude => Some("2.1.288"),
        _ => None,
    }
}
pub fn validate_mutation(r: &v1::PlatformManagedMutationRequest) -> Result<(), &'static str> {
    use v1::platform_managed_mutation_request::Operation;
    if !valid_uuid(&r.request_id) || r.encoded_len() > REQUEST_BYTES {
        return Err("invalid platform mutation");
    }
    validate_scope(r.scope.as_ref().ok_or("missing platform scope")?)?;
    match r.operation.as_ref().ok_or("missing platform operation")? {
        Operation::Launch(l) => {
            let a = v1::PlatformManagedAgent::try_from(l.agent)
                .map_err(|_| "invalid platform agent")?;
            let parent = if l.parent_session_id.is_empty() {
                l.expected_parent_launch_generation == 0
            } else {
                valid_session(&l.parent_session_id) && l.expected_parent_launch_generation > 0
            };
            if provider_version(a) != Some(l.expected_provider_version.as_str())
                || !hash(&l.expected_provider_sha256)
                || !(4..=PROVIDER_BYTES).contains(&l.expected_provider_size)
                || !token(&l.model, 128)
                || l.effort.as_ref().is_some_and(|e| !token(e, 128))
                || !crate::valid_session_name(&l.name)
                || !parent
                || l.prompt.as_ref().is_some_and(|p| !text(p))
                || l.working_dir.len() > 4096
                || l.working_dir.contains('\0')
                || l.working_dir.chars().any(char::is_control)
                || (!l.working_dir.is_empty()
                    && !std::path::Path::new(&l.working_dir).is_absolute())
            {
                return Err("invalid platform launch");
            }
        }
        Operation::Control(c) => {
            use v1::PlatformManagedAction as A;
            let resume = c.action == A::Resume as i32;
            let resume_fields = if resume {
                let scope = r.scope.as_ref().ok_or("missing platform scope")?;
                let agent = v1::PlatformManagedAgent::try_from(c.agent)
                    .map_err(|_| "invalid platform agent")?;
                valid_uuid(&c.predecessor_pod_uid)
                    && c.predecessor_pod_uid != scope.pod_uid
                    && provider_version(agent) == Some(c.expected_provider_version.as_str())
                    && hash(&c.expected_provider_sha256)
                    && (4..=PROVIDER_BYTES).contains(&c.expected_provider_size)
            } else {
                c.predecessor_pod_uid.is_empty()
                    && c.agent == 0
                    && c.expected_provider_sha256.is_empty()
                    && c.expected_provider_size == 0
                    && c.expected_provider_version.is_empty()
            };
            if !resume_fields {
                return Err("invalid platform resume");
            }
            if !valid_uuid(&c.driver_id)
                || c.session_id != format!("session-{}", c.driver_id)
                || c.expected_launch_generation == 0
                || c.reply_to.as_ref().is_some_and(|s| !valid_uuid(s))
                || c.expected_active_message_id
                    .as_ref()
                    .is_some_and(|s| !valid_uuid(s))
                || c.expected_turn_id.as_ref().is_some_and(|s| !token(s, 128))
                || c.cleanup_of_request_id.as_ref().is_some_and(|id| {
                    !valid_uuid(id) || id == &r.request_id || c.action != A::Stop as i32
                })
            {
                return Err("invalid platform control");
            }
            let valid = match A::try_from(c.action) {
                Ok(A::Message) => {
                    text(&c.text)
                        && c.expected_turn_id.is_none()
                        && c.expected_active_message_id.is_none()
                }
                Ok(A::Steer) => {
                    text(&c.text)
                        && c.expected_turn_id.is_some()
                        && c.expected_active_message_id.is_some()
                }
                Ok(A::Interrupt) => {
                    c.text.is_empty()
                        && c.reply_to.is_none()
                        && c.expected_active_message_id.is_some()
                }
                Ok(A::Stop | A::Restart | A::Resume) => {
                    c.text.is_empty()
                        && c.reply_to.is_none()
                        && c.expected_turn_id.is_none()
                        && c.expected_active_message_id.is_none()
                }
                _ => false,
            };
            if !valid {
                return Err("invalid platform action");
            }
        }
    }
    Ok(())
}
pub fn platform_managed_request_fingerprint(
    r: &v1::PlatformManagedMutationRequest,
) -> Result<String, &'static str> {
    validate_mutation(r)?;
    let mut h = Sha256::new();
    h.update(b"codewire.platform-managed-mutation.v1\0");
    h.update(r.encode_to_vec());
    Ok(format!("{:x}", h.finalize()))
}
/// Deterministic initial prompt identity, disjoint from the launch request.
/// RFC9562 version8/variant10 from the first16 SHA256 bytes over the fixed
/// domain plus canonical ASCII request UUID; no v5 feature or random replay.
pub fn platform_managed_initial_prompt_id(request_id: &str) -> Result<String, &'static str> {
    if !valid_uuid(request_id) {
        return Err("invalid platform request");
    }
    let mut h = Sha256::new();
    h.update(b"codewire.platform-managed-initial-prompt.v1\0");
    h.update(request_id.as_bytes());
    let digest = h.finalize();
    let mut id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| "invalid prompt identity")?;
    id[6] = (id[6] & 0x0f) | 0x80;
    id[8] = (id[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        id[0],
        id[1],
        id[2],
        id[3],
        id[4],
        id[5],
        id[6],
        id[7],
        id[8],
        id[9],
        id[10],
        id[11],
        id[12],
        id[13],
        id[14],
        id[15]
    ))
}
pub fn validate_read(r: &v1::PlatformManagedReadRequest) -> Result<(), &'static str> {
    validate_scope(r.scope.as_ref().ok_or("missing platform scope")?)?;
    if !valid_uuid(&r.driver_id)
        || r.session_id != format!("session-{}", r.driver_id)
        || r.expected_launch_generation == 0
        || r.limit > 100
        || (!r.message_id.is_empty() && !valid_uuid(&r.message_id))
    {
        Err("invalid platform read")
    } else {
        Ok(())
    }
}

/// Exact private response grammar. Reasons describe ownership state only and
/// never carry child errors, commands, credentials or provider output.
pub fn validate_receipt(r: &v1::PlatformManagedReceipt) -> Result<(), &'static str> {
    validate_scope(r.scope.as_ref().ok_or("missing platform scope")?)?;
    let reason = match r.phase {
        1 => r.reason == "pending",
        2 => r.reason == "issued",
        3 => r.reason == "settled",
        // Refused before any effect, or an issued launch refused before its
        // agent ran, with cleanup confirmed.
        4 => matches!(
            r.reason.as_str(),
            "refused-before-issue" | "denied-before-run"
        ),
        5 => matches!(
            r.reason.as_str(),
            "issued-outcome-unknown" | "target-owner-lost"
        ),
        _ => false,
    };
    if !valid_uuid(&r.request_id)
        || !valid_hash(&r.fingerprint_sha256)
        || !valid_uuid(&r.driver_id)
        || r.session_id != format!("session-{}", r.driver_id)
        || r.launch_generation == 0
        || (!r.message_id.is_empty() && !valid_uuid(&r.message_id))
        || !reason
        || r.encoded_len() > FRAME_BYTES
        || v1::SessionLifecycleState::try_from(r.session_state).is_err()
        || (r.native_acknowledged && !r.pipe_acknowledged)
        || (r.phase != 3 && (r.pipe_acknowledged || r.native_acknowledged))
        || (r.phase == 4 && r.cleanup_unknown)
        || match &r.cleanup_of_request_id {
            None => r.cleanup_previous_generation != 0 || r.cleanup_previous_cleanup_known,
            Some(id) => {
                !valid_uuid(id)
                    || id == &r.request_id
                    || r.cleanup_previous_generation == 0
                    || (r.launch_generation != r.cleanup_previous_generation
                        && r.cleanup_previous_generation.checked_add(1)
                            != Some(r.launch_generation))
                    || r.cleanup_previous_cleanup_known != (r.phase == 3)
                    || (r.phase == 3
                        && (r.cleanup_unknown
                            || r.pipe_acknowledged
                            || r.native_acknowledged
                            || !((r.session_state == v1::SessionLifecycleState::Stopped as i32
                                && r.exit_code.is_none())
                                || (r.session_state == v1::SessionLifecycleState::Exited as i32
                                    && r.exit_code == Some(0)))))
            }
        }
    {
        Err("invalid platform receipt")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> v1::PlatformManagedMutationRequest {
        v1::PlatformManagedMutationRequest {
            request_id: "00000000-0000-4000-8000-000000000001".into(),
            scope: Some(v1::PlatformManagedScope {
                environment_id: "00000000-0000-4000-8000-000000000002".into(),
                org_id: "fixture".into(),
                pod_uid: "00000000-0000-4000-8000-000000000003".into(),
                binding_generation: u64::MAX,
                projection_selection_sha256: vec![1; 32],
                support_image_sha256: vec![2; 32],
                support_image_size: 1024,
            }),
            operation: Some(v1::platform_managed_mutation_request::Operation::Control(
                v1::PlatformManagedControl {
                    action: v1::PlatformManagedAction::Message as i32,
                    session_id: "session-00000000-0000-4000-8000-000000000004".into(),
                    expected_launch_generation: u64::MAX,
                    driver_id: "00000000-0000-4000-8000-000000000004".into(),
                    text: "\u{1}".repeat(TEXT_BYTES),
                    reply_to: None,
                    expected_turn_id: None,
                    expected_active_message_id: None,
                    cleanup_of_request_id: None,
                    ..Default::default()
                },
            )),
        }
    }
    #[test]
    fn platform_wire_closed_fingerprint_binds_full_u64_scope_and_escaped_text() {
        let mut r = request();
        let h = platform_managed_request_fingerprint(&r).unwrap();
        r.scope.as_mut().unwrap().binding_generation -= 1;
        assert_ne!(h, platform_managed_request_fingerprint(&r).unwrap());
        let v1::platform_managed_mutation_request::Operation::Control(c) =
            r.operation.as_mut().unwrap()
        else {
            panic!()
        };
        c.text.push('x');
        assert!(platform_managed_request_fingerprint(&r).is_err());
    }
    #[test]
    fn platform_wire_rejects_invalid_actions_parent_and_foreign_identity() {
        let mut r = request();
        r.request_id = "00000000-0000-0000-0000-000000000000".into();
        assert!(validate_mutation(&r).is_err());
        let mut r = request();
        let v1::platform_managed_mutation_request::Operation::Control(c) =
            r.operation.as_mut().unwrap()
        else {
            panic!()
        };
        c.action = v1::PlatformManagedAction::Stop as i32;
        assert!(validate_mutation(&r).is_err());
        let mut r = request();
        r.scope.as_mut().unwrap().support_image_sha256 = vec![0; 32];
        assert!(validate_mutation(&r).is_err());
    }

    #[test]
    fn platform_wire_receipt_rejects_reason_phase_actor_and_native_ack_drift() {
        let request = request();
        let mut row = v1::PlatformManagedReceipt {
            request_id: request.request_id.clone(),
            scope: request.scope.clone(),
            fingerprint_sha256: platform_managed_request_fingerprint(&request).unwrap(),
            phase: 1,
            session_id: "session-00000000-0000-4000-8000-000000000004".into(),
            driver_id: "00000000-0000-4000-8000-000000000004".into(),
            launch_generation: u64::MAX,
            cleanup_unknown: true,
            reason: "pending".into(),
            ..Default::default()
        };
        for (phase, reason) in [
            (1, "pending"),
            (2, "issued"),
            (3, "settled"),
            (5, "issued-outcome-unknown"),
            (5, "target-owner-lost"),
        ] {
            row.phase = phase;
            row.reason = reason.into();
            assert!(validate_receipt(&row).is_ok());
            let decoded =
                v1::PlatformManagedReceipt::decode(row.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded.launch_generation, u64::MAX);
        }
        for reason in ["", "arbitrary-child-error", "pending"] {
            row.reason = reason.into();
            assert!(validate_receipt(&row).is_err());
        }
        row.reason = "target-owner-lost".into();
        row.native_acknowledged = true;
        assert!(validate_receipt(&row).is_err());
        row.phase = 3;
        row.reason = "settled".into();
        assert!(validate_receipt(&row).is_err());
        row.pipe_acknowledged = true;
        assert!(validate_receipt(&row).is_ok());
        row.session_id.push('x');
        assert!(validate_receipt(&row).is_err());
    }
    #[test]
    fn platform_wire_cleanup_link_is_stop_only_canonical_and_never_self_or_empty() {
        let mut r = request();
        let linked = "00000000-0000-4000-8000-000000000009".to_string();
        let Some(v1::platform_managed_mutation_request::Operation::Control(c)) = &mut r.operation
        else {
            panic!()
        };
        c.cleanup_of_request_id = Some(linked);
        assert!(validate_mutation(&r).is_err());
        let Some(v1::platform_managed_mutation_request::Operation::Control(c)) = &mut r.operation
        else {
            panic!()
        };
        c.action = 4;
        c.text.clear();
        assert!(validate_mutation(&r).is_ok());
        for id in [String::new(), r.request_id.clone(), "invalid".into()] {
            let Some(v1::platform_managed_mutation_request::Operation::Control(c)) =
                &mut r.operation
            else {
                panic!()
            };
            c.cleanup_of_request_id = Some(id);
            assert!(validate_mutation(&r).is_err());
        }
    }

    #[test]
    fn platform_wire_link_codec_is_platform_only_and_preserves_host_control_bytes() {
        let host = v1::HostControlManagedControl {
            action: v1::HostManagedAction::Stop as i32,
            session_id: "s".into(),
            expected_launch_generation: 7,
            driver_id: "d".into(),
            text: String::new(),
            reply_to: None,
            expected_turn_id: None,
            expected_active_message_id: None,
        };
        let original_host_wire = b"\x08\x04\x12\x01s\x18\x07\x22\x01d";
        assert_eq!(host.encode_to_vec(), original_host_wire);
        assert_eq!(
            v1::HostControlManagedControl::decode(original_host_wire.as_slice()).unwrap(),
            host
        );

        let mut request = request();
        let Some(v1::platform_managed_mutation_request::Operation::Control(control)) =
            &mut request.operation
        else {
            panic!()
        };
        control.action = v1::PlatformManagedAction::Stop as i32;
        control.text.clear();
        control.cleanup_of_request_id = Some("00000000-0000-4000-8000-000000000009".into());
        let encoded = control.encode_to_vec();
        let decoded = v1::PlatformManagedControl::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded, *control);
        assert_eq!(
            decoded.cleanup_of_request_id.as_deref(),
            Some("00000000-0000-4000-8000-000000000009")
        );
        let linked = platform_managed_request_fingerprint(&request).unwrap();
        let Some(v1::platform_managed_mutation_request::Operation::Control(control)) =
            &mut request.operation
        else {
            panic!()
        };
        control.cleanup_of_request_id = None;
        assert_ne!(
            linked,
            platform_managed_request_fingerprint(&request).unwrap()
        );
    }
}
