use codewire_server_core::AppError;

use super::*;

fn caller() -> AuthUser {
    AuthUser {
        user_id: "caller".into(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

/// An online, providing, current host the caller owns, with room for one
/// small VM.
fn host() -> Candidate {
    Candidate {
        id: "host-1".into(),
        owner_user_id: "caller".into(),
        provide: true,
        organization_grant: false,
        capability_version: HOST_LIFECYCLE_CAPABILITY,
        state: "online".into(),
        max_vms: Some(2),
        max_vcpus: Some(4),
        max_memory_mib: Some(8192),
        max_disk_gib: Some(100),
        owner_is_member: true,
        caller_granted: false,
        placed_vms: 1,
        placed_cpu_millicores: 2000,
        placed_memory_mib: 4096,
        placed_disk_gib: 50,
    }
}

fn request() -> HostRequest<'static> {
    HostRequest {
        isolation_tier: "standard",
        image: "",
        repositories: 0,
        secrets: false,
        credentials: false,
        network: false,
        network_policy: false,
        source_snapshot: false,
        cpu_millicores: 2000,
        memory_mib: 4096,
        disk_gib: 50,
    }
}

fn code(result: AppResult<impl std::fmt::Debug>) -> String {
    match result.unwrap_err() {
        AppError::Coded { code, .. } => code.to_string(),
        other => panic!("not a coded error: {other:?}"),
    }
}

#[test]
fn a_request_id_is_16_to_64_safe_characters() {
    assert!(valid_request_id("abcdefghijklmnop"));
    assert!(valid_request_id(&"a".repeat(64)));
    assert!(valid_request_id("cw-create_0123456789AB"));
    assert!(!valid_request_id("abcdefghijklmno"));
    assert!(!valid_request_id(&"a".repeat(65)));
    assert!(!valid_request_id("abcdefghijklmnop "));
    assert!(!valid_request_id("abcdefghijklmnop/"));
}

#[test]
fn what_a_host_cant_run_yet_is_refused_by_name() {
    assert!(refuse_unsupported(&request()).is_ok());
    // The canonical image is accepted: the host replaces it with its own.
    assert!(
        refuse_unsupported(&HostRequest {
            image: crate::sandbox::canonical_workspace_runtime_image(),
            ..request()
        })
        .is_ok()
    );
    for (changed, expected) in [
        (
            HostRequest {
                isolation_tier: "confidential",
                ..request()
            },
            "host_isolation_unsupported",
        ),
        (
            HostRequest {
                repositories: 1,
                ..request()
            },
            "host_repository_unsupported",
        ),
        (
            HostRequest {
                image: "example.test/custom:1",
                ..request()
            },
            "host_image_unsupported",
        ),
        (
            HostRequest {
                secrets: true,
                ..request()
            },
            "host_credentials_unsupported",
        ),
        (
            HostRequest {
                credentials: true,
                ..request()
            },
            "host_credentials_unsupported",
        ),
        (
            HostRequest {
                network: true,
                ..request()
            },
            "host_network_unsupported",
        ),
        (
            HostRequest {
                network_policy: true,
                ..request()
            },
            "host_network_policy_unsupported",
        ),
        (
            HostRequest {
                source_snapshot: true,
                ..request()
            },
            "host_snapshot_unsupported",
        ),
    ] {
        assert_eq!(code(refuse_unsupported(&changed)), expected);
    }
}

#[test]
fn only_a_usable_host_is_admitted_and_each_refusal_names_why() {
    assert_eq!(admit(Some(host()), &caller(), "box").unwrap().id, "host-1");
    assert_eq!(code(admit(None, &caller(), "box")), "host_not_found");

    // Someone else's host, with no grant, reads as absent.
    let others = Candidate {
        owner_user_id: "owner".into(),
        ..host()
    };
    assert_eq!(
        code(admit(Some(others), &caller(), "box")),
        "host_not_found"
    );
    for granted in [
        Candidate {
            owner_user_id: "owner".into(),
            organization_grant: true,
            ..host()
        },
        Candidate {
            owner_user_id: "owner".into(),
            caller_granted: true,
            ..host()
        },
    ] {
        assert!(admit(Some(granted), &caller(), "box").is_ok());
    }

    for (changed, expected) in [
        (
            Candidate {
                state: "revoked".into(),
                ..host()
            },
            "host_revoked",
        ),
        (
            Candidate {
                owner_is_member: false,
                ..host()
            },
            "host_owner_left",
        ),
        (
            Candidate {
                provide: false,
                ..host()
            },
            "host_not_providing",
        ),
        (
            Candidate {
                state: "offline".into(),
                ..host()
            },
            "host_offline",
        ),
        (
            Candidate {
                capability_version: HOST_LIFECYCLE_CAPABILITY - 1,
                ..host()
            },
            "host_upgrade_required",
        ),
    ] {
        assert_eq!(code(admit(Some(changed), &caller(), "box")), expected);
    }
}

#[test]
fn a_host_admits_up_to_each_of_its_limits_and_no_further() {
    // Exactly at every limit fits.
    assert!(check_room(&host(), &request()).is_ok());
    for (changed, what) in [
        (
            Candidate {
                placed_vms: 2,
                ..host()
            },
            "VM",
        ),
        (
            Candidate {
                placed_cpu_millicores: 2001,
                ..host()
            },
            "vCPU",
        ),
        (
            Candidate {
                placed_memory_mib: 4097,
                ..host()
            },
            "memory",
        ),
        (
            Candidate {
                placed_disk_gib: 51,
                ..host()
            },
            "disk",
        ),
    ] {
        let error = check_room(&changed, &request()).unwrap_err();
        assert!(format!("{error}").contains(what), "{error}");
        assert_eq!(code(Err::<(), _>(error)), "host_full");
    }
    // Absent resource limits bound nothing but the VM count.
    let unbounded = Candidate {
        max_vcpus: None,
        max_memory_mib: None,
        max_disk_gib: None,
        placed_cpu_millicores: 1 << 40,
        ..host()
    };
    assert!(check_room(&unbounded, &request()).is_ok());
}
