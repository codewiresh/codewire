//! The runner requests' fields, each checked into the runner's own type once,
//! before the runner acts on the request.

use super::*;

pub(super) fn parse_environment_id(value: &str) -> Result<Uuid, Status> {
    let id =
        Uuid::parse_str(value).map_err(|_| Status::invalid_argument("invalid environment ID"))?;
    if id.is_nil() {
        return Err(Status::invalid_argument("invalid environment ID"));
    }
    Ok(id)
}

pub(super) fn parse_cw_runtime_catalog_generation(
    request: &v1::StartVmRequest,
) -> Result<Option<String>, Status> {
    let generation = &request.cw_runtime_catalog_generation;
    if generation.is_empty() {
        return Ok(None);
    }
    if !crate::state::valid_root_generation(generation) {
        return Err(Status::invalid_argument(
            "invalid cw runtime catalog generation",
        ));
    }
    Ok(Some(generation.clone()))
}

/// The catalog a move boots away from: only beside a catalog, never that one.
pub(super) fn parse_cw_runtime_moved_from_generation(
    request: &v1::StartVmRequest,
) -> Result<Option<String>, Status> {
    let generation = &request.cw_runtime_moved_from_generation;
    if generation.is_empty() {
        return Ok(None);
    }
    if !crate::state::valid_root_generation(generation)
        || request.cw_runtime_catalog_generation.is_empty()
        || *generation == request.cw_runtime_catalog_generation
    {
        return Err(Status::invalid_argument("invalid cw runtime move"));
    }
    Ok(Some(generation.clone()))
}

/// The boot's interception as its supervisor decided it (#4912): intercepted
/// exactly when `intercept` is set, a reason only beside not intercepted,
/// and never lost, which only the runner says. Absent from an older
/// supervisor.
pub(super) fn parse_interception(
    request: &v1::StartVmRequest,
) -> Result<Option<v1::Interception>, Status> {
    use v1::{InterceptionReason as Reason, InterceptionState as State};
    let Some(interception) = request.interception else {
        return Ok(None);
    };
    let reason = Reason::try_from(interception.reason);
    let valid = match (State::try_from(interception.state), reason) {
        (Ok(State::Intercepted), Ok(Reason::Unspecified)) => request.intercept,
        (Ok(State::Off), Ok(Reason::Unspecified)) => !request.intercept,
        (Ok(State::NotIntercepted), Ok(reason)) => {
            !request.intercept && reason != Reason::Unspecified
        }
        _ => false,
    };
    if valid {
        Ok(Some(interception))
    } else {
        Err(Status::invalid_argument("invalid interception"))
    }
}

pub(super) fn parse_setup_binding(
    request: &v1::StartVmRequest,
) -> Result<Option<SetupBinding>, Status> {
    match (
        request.setup_total_bytes,
        request.setup_header_sha256.as_str(),
        request.setup_root_generation.as_str(),
    ) {
        (0, "", "") => Ok(None),
        (total_bytes, header_sha256, setup_root_generation)
            if total_bytes > 0
                && !header_sha256.is_empty()
                && !setup_root_generation.is_empty() =>
        {
            let root_generation = Sha256Value::parse_hex(setup_root_generation)
                .map_err(|_| Status::invalid_argument("invalid setup root generation"))?;
            let header_sha256 = Sha256Value::parse_hex(header_sha256)
                .map_err(|_| Status::invalid_argument("invalid setup header digest"))?;
            Ok(Some(
                SetupBinding::new(total_bytes, root_generation, header_sha256)
                    .map_err(|_| Status::invalid_argument("invalid setup binding"))?,
            ))
        }
        _ => Err(Status::invalid_argument("incomplete setup binding")),
    }
}

pub(super) fn parse_host_ports(
    host_ports: &[v1::HostPortBinding],
) -> Result<Vec<HostPortBinding>, Status> {
    let provided = host_ports
        .iter()
        .map(|binding| {
            Ok(HostPortBinding {
                host_port: u16::try_from(binding.host_port)
                    .map_err(|_| Status::invalid_argument("invalid host-port binding"))?,
                guest_port: u16::try_from(binding.guest_port)
                    .map_err(|_| Status::invalid_argument("invalid host-port binding"))?,
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;
    let canonical = canonical_host_port_bindings(provided.clone())
        .map_err(|_| Status::invalid_argument("invalid host-port binding"))?;
    if canonical != provided {
        return Err(Status::invalid_argument(
            "host-port bindings are not canonical",
        ));
    }
    Ok(canonical)
}

pub(super) fn parse_mesh_attachment(
    request: &v1::StartVmRequest,
) -> Result<Option<MeshAttachment>, Status> {
    let Some(raw) = request.mesh.as_ref() else {
        return Ok(None);
    };
    let guest_ports = raw
        .guest_ports
        .iter()
        .map(|port| u16::try_from(*port).map_err(|_| Status::invalid_argument("invalid Mesh port")))
        .collect::<Result<Vec<_>, _>>()?;
    let auth_source = match v1::MeshEnrollmentAuthSource::try_from(raw.auth_source) {
        Ok(v1::MeshEnrollmentAuthSource::StandaloneLocal) => {
            MeshEnrollmentAuthSource::StandaloneLocal
        }
        Ok(v1::MeshEnrollmentAuthSource::HostedCurrent) => MeshEnrollmentAuthSource::HostedCurrent,
        Ok(v1::MeshEnrollmentAuthSource::Unspecified) | Err(_) => {
            return Err(Status::invalid_argument("invalid Mesh auth source"));
        }
    };
    let attachment = MeshAttachment::new_with_auth_source(
        auth_source,
        &raw.mesh_url,
        &raw.organization_id,
        &raw.network_id,
        &raw.node_name,
        guest_ports,
    )
    .map_err(|_| Status::invalid_argument("invalid Mesh attachment"))?;
    if attachment.mesh_url != raw.mesh_url
        || attachment.organization_id != raw.organization_id
        || attachment.network_id != raw.network_id
        || attachment.node_name != raw.node_name
        || match attachment.auth_source {
            MeshEnrollmentAuthSource::StandaloneLocal => {
                raw.auth_source != v1::MeshEnrollmentAuthSource::StandaloneLocal as i32
            }
            MeshEnrollmentAuthSource::HostedCurrent => {
                raw.auth_source != v1::MeshEnrollmentAuthSource::HostedCurrent as i32
            }
        }
        || attachment
            .guest_ports
            .iter()
            .copied()
            .map(u32::from)
            .ne(raw.guest_ports.iter().copied())
    {
        return Err(Status::invalid_argument("noncanonical Mesh attachment"));
    }
    Ok(Some(attachment))
}

pub(super) fn parse_direct_shares(
    request: &v1::StartVmRequest,
) -> Result<Vec<DirectShareRequest>, Status> {
    if request.direct_shares.len() > MAX_DIRECT_SHARES {
        return Err(Status::invalid_argument("too many direct shares"));
    }
    request
        .direct_shares
        .iter()
        .enumerate()
        .map(|(index, raw)| {
            if raw.source_path.is_empty() || raw.source_path.contains(&0) {
                return Err(Status::invalid_argument("invalid direct share"));
            }
            let identity = DirectShareIdentity::new(
                raw.device_major,
                raw.device_minor,
                raw.inode,
                raw.mount_id,
                raw.owner_uid,
                raw.filesystem_magic,
            )
            .map_err(|_| Status::invalid_argument("invalid direct share"))?;
            let mount = DirectShareMount::for_index(index, raw.destination.clone(), raw.read_only)
                .and_then(|mount| mount.with_vm_only(raw.vm_only.clone()))
                .map_err(|_| Status::invalid_argument("invalid direct share"))?;
            DirectShareRequest::new(
                PathBuf::from(OsString::from_vec(raw.source_path.clone())),
                identity,
                mount,
            )
            .map_err(|_| Status::invalid_argument("invalid direct share"))
        })
        .collect()
}

pub(super) fn parse_skill_snapshot(
    request: &v1::StartVmRequest,
) -> Result<Option<Sha256Value>, Status> {
    if request.skill_snapshot_sha256.is_empty() {
        Ok(None)
    } else {
        Sha256Value::parse_hex(&request.skill_snapshot_sha256)
            .map(Some)
            .map_err(|_| Status::invalid_argument("invalid skill snapshot digest"))
    }
}

pub(super) fn parse_environment_projection(
    request: &v1::StartVmRequest,
) -> Result<Option<Sha256Value>, Status> {
    if request.environment_projection_sha256.is_empty() {
        return Ok(None);
    }
    let digest = Sha256Value::parse_hex(&request.environment_projection_sha256)
        .map_err(|_| Status::invalid_argument("invalid environment projection digest"))?;
    if digest.as_bytes() == [0; 32] {
        return Err(Status::invalid_argument(
            "invalid environment projection digest",
        ));
    }
    Ok(Some(digest))
}

/// A busy port names itself after the stable code, so the supervisor can say
/// which one is taken.
pub(super) fn map_host_port_error(error: RunnerError) -> Status {
    match error {
        RunnerError::HostPortUnavailable(port) => {
            Status::failed_precondition(format!("{HOST_PORT_UNAVAILABLE} {port}"))
        }
        RunnerError::InvalidRequest => Status::invalid_argument("invalid host-port bindings"),
        _ => Status::internal("host-port update failed"),
    }
}

/// The policy a boot's egress broker enforces: the selected revision's
/// canonical document, or `open` when none is selected (#2537).
pub(super) fn start_network_policy(
    document: &[u8],
) -> Result<codewire_egress_policy::CompiledPolicy, Status> {
    if document.is_empty() {
        return Ok(codewire_egress_policy::CompiledPolicy::developer_baseline());
    }
    if document.len() > codewire_egress_policy::MAX_POLICY_DOCUMENT_BYTES {
        return Err(Status::invalid_argument(
            "network policy document is too large",
        ));
    }
    let document: codewire_egress_policy::PolicyDocument = serde_json::from_slice(document)
        .map_err(|_| Status::invalid_argument("network policy document is invalid"))?;
    codewire_egress_policy::CompiledPolicy::compile(document)
        .map_err(|_| Status::invalid_argument("network policy document is invalid"))
}

pub(super) fn parse_managed_credential_clients(
    request: &v1::StartVmRequest,
) -> Result<codewire_access::ManagedCredentialClients, Status> {
    codewire_access::ManagedCredentialClients::decode(&request.managed_credential_clients)
        .map_err(|_| Status::invalid_argument("invalid managed credential client selection"))
}

pub(super) fn daemon_ready_timeout(has_setup: bool) -> std::time::Duration {
    if has_setup {
        SETUP_DAEMON_READY_TIMEOUT
    } else {
        DAEMON_READY_TIMEOUT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A boot's interception agrees with `intercept`, carries a reason only
    /// when not intercepted, and is never lost (#4912); one that disagrees is
    /// refused as invalid_argument. An older supervisor sends none, and the
    /// boot starts as before: nothing is kept to report.
    #[test]
    fn a_boot_interception_agrees_with_intercept() {
        use v1::{InterceptionReason as Reason, InterceptionState as State};
        let request = |intercept: bool, interception: Option<(State, i32)>| v1::StartVmRequest {
            intercept,
            interception: interception.map(|(state, reason)| v1::Interception {
                state: state as i32,
                reason,
            }),
            ..v1::StartVmRequest::default()
        };
        let unspecified = Reason::Unspecified as i32;
        let platform = Reason::PlatformCredentials as i32;
        for intercept in [false, true] {
            assert_eq!(parse_interception(&request(intercept, None)).unwrap(), None);
        }
        for (intercept, interception) in [
            (true, (State::Intercepted, unspecified)),
            (false, (State::Off, unspecified)),
            (false, (State::NotIntercepted, platform)),
            (false, (State::NotIntercepted, Reason::NoCredentials as i32)),
            (
                false,
                (
                    State::NotIntercepted,
                    Reason::CredentialServiceOutdated as i32,
                ),
            ),
        ] {
            let parsed = parse_interception(&request(intercept, Some(interception))).unwrap();
            assert_eq!(
                parsed.map(|parsed| parsed.state),
                Some(interception.0 as i32)
            );
        }
        for (intercept, interception) in [
            (false, (State::Intercepted, unspecified)),
            (true, (State::Off, unspecified)),
            (true, (State::NotIntercepted, platform)),
            (false, (State::NotIntercepted, unspecified)),
            (true, (State::Intercepted, platform)),
            (false, (State::Off, platform)),
            (true, (State::Lost, unspecified)),
            (false, (State::Lost, unspecified)),
            (false, (State::Unspecified, unspecified)),
            (false, (State::NotIntercepted, 99)),
        ] {
            let refused = parse_interception(&request(intercept, Some(interception))).unwrap_err();
            assert_eq!(
                refused.code(),
                tonic::Code::InvalidArgument,
                "{intercept} {interception:?}"
            );
        }
    }

    #[test]
    fn a_move_names_another_catalog_beside_one() {
        let catalog = "a".repeat(64);
        let earlier = "b".repeat(64);
        let request = |catalog: &str, moved_from: &str| v1::StartVmRequest {
            cw_runtime_catalog_generation: catalog.to_owned(),
            cw_runtime_moved_from_generation: moved_from.to_owned(),
            ..v1::StartVmRequest::default()
        };
        assert_eq!(
            parse_cw_runtime_moved_from_generation(&request(&catalog, "")).unwrap(),
            None
        );
        assert_eq!(
            parse_cw_runtime_moved_from_generation(&request(&catalog, &earlier)).unwrap(),
            Some(earlier.clone())
        );
        for (catalog, moved_from) in [
            ("", earlier.as_str()),
            (catalog.as_str(), catalog.as_str()),
            (catalog.as_str(), "B".repeat(64).as_str()),
            (catalog.as_str(), &earlier[1..]),
        ] {
            assert_eq!(
                parse_cw_runtime_moved_from_generation(&request(catalog, moved_from))
                    .unwrap_err()
                    .code(),
                tonic::Code::InvalidArgument
            );
        }
    }
}
