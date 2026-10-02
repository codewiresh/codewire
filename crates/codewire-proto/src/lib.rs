//! Generated Connect-RPC contract types for the audience-packaged Codewire
//! control-plane API.
//!
//! Message types (buffa), Connect service traits, and — behind the default
//! `client` feature — Connect client stubs are generated at build time by
//! `connectrpc-build` from the schema-of-record protos. Packages map to modules:
//! `codewire.v1` is [`codewire::v1`]; material-free shared frames in
//! `codewire.bridge.v1` are [`codewire::bridge::v1`]; `codewire.console.v1` is
//! [`codewire::console::v1`]; `codewire.internal.v1` is
//! [`codewire::internal::v1`]; `codewire.testing.v1` (the
//! never-routed Connect-infrastructure probe, doc 03 D8) is
//! [`codewire::testing::v1`].
//! The vendored `google.rpc` error-detail types
//! (doc 01 D1: `BadRequest`, `ErrorInfo`, `RetryInfo`) compile to
//! [`google::rpc`] for the Connect error renderer's wire encoding
//! (doc 03 WI-2).
//!
//! Program docs: `docs/plans/connect-rpc/00-MASTER.md` (master plan) and
//! `docs/plans/connect-rpc/02-proto-authoring-guide.md` (this crate's
//! workstream).

connectrpc::include_generated!();

#[cfg(test)]
mod tests {
    use prost::Message as _;

    #[test]
    fn shared_ssh_frames_redact_signing_inputs_and_signatures() {
        use super::codewire::bridge::v1::{CredentialSshSignRequest, CredentialSshSignature};

        let marker = b"synthetic-ssh-signing-debug-canary".to_vec();
        let numeric = format!("{marker:?}");
        for rendered in [
            format!(
                "{:?}",
                CredentialSshSignRequest {
                    data: marker.clone(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                CredentialSshSignature {
                    signature_blob: marker,
                    ..Default::default()
                }
            ),
        ] {
            assert!(!rendered.contains("synthetic-ssh-signing-debug-canary"));
            assert!(!rendered.contains(&numeric));
            assert!(rendered.contains("[REDACTED]"));
        }
    }

    use super::codewire::console::v1::{
        ACCOUNT_SERVICE_SERVICE_NAME, BILLING_SERVICE_SERVICE_NAME,
        ENVIRONMENT_SETUP_SERVICE_SERVICE_NAME, GetEnvironmentCreateOptionsResponse,
        GetEnvironmentUsageResponse, ResourcePlan, UpdateGitIdentityRequest,
    };
    use super::codewire::internal::v1::{
        BindWorkspaceResponse, COORDINATOR_SERVICE_SERVICE_NAME, CoordinateNode,
        GATEWAY_BINDING_SERVICE_SERVICE_NAME, IssueGatewayBindingResponse,
        IssueGatewayDaemonCredentialResponse, MESH_AUTHORIZATION_SERVICE_SERVICE_NAME,
        MESH_COORDINATOR_SERVICE_SERVICE_NAME, MeshAuthorizationContext,
        MeshAuthorizationCredentialKind, MeshAuthorizationPrincipalKind, MeshCoordinateHello,
        MeshCoordinateRole, MeshCoordinatorServiceCoordinateRequest,
        ResolveMeshAuthorizationResponse, WORKSPACE_BINDING_SERVICE_SERVICE_NAME,
    };
    use super::codewire::v1::{
        AcceptInvitationRequest, ApiKey, ApplicationPort, CreateApiKeyResponse,
        CreateInvitationResponse, CreateMeshInviteResponse, CreateMeshNodeEnrollmentResponse,
        CreatePortRequest, GetInvitationByTokenRequest, GetOrganizationResponse, InvitationStatus,
        JoinMeshNetworkRequest, ListSecretProjectsResponse, ListSecretsResponse,
        MESH_GROUP_SERVICE_SERVICE_NAME, MESH_INVITE_SERVICE_SERVICE_NAME,
        MESH_KEY_VALUE_SERVICE_SERVICE_NAME, MESH_NETWORK_SERVICE_SERVICE_NAME,
        MESH_NODE_SERVICE_SERVICE_NAME, MeshInvite, MeshKeyValue, MeshNetwork, MeshNode,
        MeshNodeEnrollment, ORGANIZATION_SERVICE_SERVICE_NAME, OrgMember, OrgRole, Organization,
        OrganizationDeletionState, PORT_SERVICE_SERVICE_NAME, PRESET_SERVICE_SERVICE_NAME, Port,
        PortAccess, Preset, PreviewWorkloadSecretResolutionResponse, ProjectAgents,
        ProjectCredentialBinding, ProjectResources, ProjectSecretBindings, ProjectSkillSelection,
        ProjectSkillSource, ProjectSpec, ProjectStoragePlacement, RedeemMeshNodeEnrollmentRequest,
        RedeemMeshNodeEnrollmentResponse, RepositorySpec, ResolvedWorkloadSecretMetadata,
        SECRET_SERVICE_PREVIEW_WORKLOAD_SECRET_RESOLUTION_SPEC, SECRET_SERVICE_SERVICE_NAME,
        SecretMetadata, SetMeshKeyValueRequest, SetProjectSecretRequest, SetSecretRequest,
        SetUserSecretRequest, UpdatePresetRequest, WorkloadSecretSource,
    };

    #[test]
    fn mesh_contracts_are_owned_by_the_audience_packages() {
        for (actual, expected) in [
            (
                MESH_NETWORK_SERVICE_SERVICE_NAME,
                "codewire.v1.MeshNetworkService",
            ),
            (
                MESH_NODE_SERVICE_SERVICE_NAME,
                "codewire.v1.MeshNodeService",
            ),
            (
                MESH_INVITE_SERVICE_SERVICE_NAME,
                "codewire.v1.MeshInviteService",
            ),
            (
                MESH_GROUP_SERVICE_SERVICE_NAME,
                "codewire.v1.MeshGroupService",
            ),
            (
                MESH_KEY_VALUE_SERVICE_SERVICE_NAME,
                "codewire.v1.MeshKeyValueService",
            ),
            (
                MESH_AUTHORIZATION_SERVICE_SERVICE_NAME,
                "codewire.internal.v1.MeshAuthorizationService",
            ),
            (
                COORDINATOR_SERVICE_SERVICE_NAME,
                "codewire.internal.v1.CoordinatorService",
            ),
            (
                MESH_COORDINATOR_SERVICE_SERVICE_NAME,
                "codewire.internal.v1.MeshCoordinatorService",
            ),
            (
                GATEWAY_BINDING_SERVICE_SERVICE_NAME,
                "codewire.internal.v1.GatewayBindingService",
            ),
            (
                WORKSPACE_BINDING_SERVICE_SERVICE_NAME,
                "codewire.internal.v1.WorkspaceBindingService",
            ),
        ] {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn mesh_product_json_pins_org_ownership_and_secret_free_redemption() {
        let network = MeshNetwork {
            id: "network-alpha".into(),
            org_id: "org-alpha".into(),
            node_count: 2,
            invite_count: 1,
            ..Default::default()
        };
        let json = serde_json::to_value(network).expect("Mesh network proto3 JSON");
        assert_eq!(json["id"], "network-alpha");
        assert_eq!(json["orgId"], "org-alpha");
        assert_eq!(json["nodeCount"], "2");
        assert_eq!(json["inviteCount"], "1");
        assert!(json.get("org_id").is_none(), "unexpected JSON: {json}");

        let enrollment = MeshNodeEnrollment {
            id: "enrollment-alpha".into(),
            org_id: "org-alpha".into(),
            network_id: "network-alpha".into(),
            node_name: "node-alpha".into(),
            ..Default::default()
        };
        let created = CreateMeshNodeEnrollmentResponse {
            enrollment: Some(enrollment.clone()).into(),
            enrollment_code: "cw_enr_example".into(),
            ..Default::default()
        };
        let created_json =
            serde_json::to_value(created).expect("Mesh enrollment create proto3 JSON");
        assert_eq!(created_json["enrollmentCode"], "cw_enr_example");
        assert!(created_json.get("enrollment_token").is_none());

        let invite = CreateMeshInviteResponse {
            invite: Some(MeshInvite {
                id: "invite-alpha".into(),
                org_id: "org-alpha".into(),
                network_id: "network-alpha".into(),
                ..Default::default()
            })
            .into(),
            invite_code: "cw_inv_example".into(),
            ..Default::default()
        };
        let invite_json = serde_json::to_value(invite).expect("Mesh invite create proto3 JSON");
        assert_eq!(invite_json["invite"]["id"], "invite-alpha");
        assert_eq!(invite_json["inviteCode"], "cw_inv_example");
        assert!(invite_json["invite"].get("inviteCode").is_none());
        assert!(invite_json["invite"].get("usesRemaining").is_none());

        let redeemed = RedeemMeshNodeEnrollmentResponse {
            node: Some(MeshNode {
                org_id: "org-alpha".into(),
                network_id: "network-alpha".into(),
                name: "node-alpha".into(),
                ..Default::default()
            })
            .into(),
            enrollment: Some(enrollment).into(),
            ..Default::default()
        };
        let redeemed_json =
            serde_json::to_value(redeemed).expect("Mesh enrollment redeem proto3 JSON");
        assert_eq!(redeemed_json["node"]["orgId"], "org-alpha");
        assert_eq!(redeemed_json["enrollment"]["id"], "enrollment-alpha");
        for forbidden in [
            "credential",
            "enrollmentCode",
            "nodeToken",
            "runtimeCredential",
        ] {
            assert!(
                redeemed_json.get(forbidden).is_none(),
                "unexpected {forbidden}: {redeemed_json}"
            );
        }
    }

    #[test]
    fn mesh_capability_and_value_debug_output_is_redacted() {
        const MARKER: &str = "do-not-print-this-mesh-capability-or-value";
        let marker_bytes = MARKER.as_bytes().to_vec();
        let unredacted_bytes = format!("{marker_bytes:?}");

        for rendered in [
            format!(
                "{:?}",
                CreateMeshNodeEnrollmentResponse {
                    enrollment_code: MARKER.into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                RedeemMeshNodeEnrollmentRequest {
                    enrollment_code: MARKER.into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                CreateMeshInviteResponse {
                    invite_code: MARKER.into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                JoinMeshNetworkRequest {
                    invite_code: MARKER.into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                MeshKeyValue {
                    value: marker_bytes.clone(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                SetMeshKeyValueRequest {
                    value: marker_bytes.clone(),
                    ..Default::default()
                }
            ),
        ] {
            assert!(
                !rendered.contains(MARKER),
                "Mesh material leaked through Debug"
            );
            assert!(
                !rendered.contains(&unredacted_bytes),
                "Mesh value bytes leaked through Debug"
            );
            assert!(rendered.contains("[REDACTED]"));
        }
    }

    #[test]
    fn mesh_internal_json_is_typed_without_raw_authorization_material() {
        let resolved = ResolveMeshAuthorizationResponse {
            context: Some(MeshAuthorizationContext {
                principal_id: "user-alpha".into(),
                principal_kind: MeshAuthorizationPrincipalKind::User.into(),
                org_id: "org-alpha".into(),
                role: OrgRole::Admin.into(),
                credential_kind: MeshAuthorizationCredentialKind::ApiKey.into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let json = serde_json::to_value(resolved).expect("Mesh authorization context proto3 JSON");
        assert_eq!(json["context"]["principalId"], "user-alpha");
        assert_eq!(
            json["context"]["principalKind"],
            "MESH_AUTHORIZATION_PRINCIPAL_KIND_USER"
        );
        assert_eq!(json["context"]["role"], "ORG_ROLE_ADMIN");
        assert_eq!(
            json["context"]["credentialKind"],
            "MESH_AUTHORIZATION_CREDENTIAL_KIND_API_KEY"
        );
        for forbidden in ["authorized", "credential", "scope", "token"] {
            assert!(
                json["context"].get(forbidden).is_none(),
                "unexpected {forbidden}: {json}"
            );
        }

        let hello = MeshCoordinatorServiceCoordinateRequest {
            msg: Some(
                MeshCoordinateHello {
                    org_id: "org-alpha".into(),
                    network_id: "network-alpha".into(),
                    role: MeshCoordinateRole::Dial.into(),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
        let hello_json = serde_json::to_value(hello).expect("Mesh coordinate proto3 JSON");
        assert_eq!(hello_json["hello"]["orgId"], "org-alpha");
        assert_eq!(hello_json["hello"]["networkId"], "network-alpha");
        assert_eq!(hello_json["hello"]["role"], "MESH_COORDINATE_ROLE_DIAL");

        let node = CoordinateNode {
            id: "peer-alpha".into(),
            disco_key: "discokey:test".into(),
            ..Default::default()
        };
        let node_json = serde_json::to_value(node).expect("coordinate node proto3 JSON");
        assert_eq!(node_json["id"], "peer-alpha");
        assert_eq!(node_json["discoKey"], "discokey:test");
        assert!(
            node_json.get("disco_key").is_none(),
            "unexpected JSON: {node_json}"
        );
    }

    #[test]
    fn generated_project_type_is_importable_and_json_serializable() {
        let project = ProjectSpec {
            schema_version: 1,
            working_directory: "/workspace".into(),
            environment: [("RUST_LOG".into(), "info".into())].into_iter().collect(),
            agents: Some(ProjectAgents {
                install: Some(false),
                tools: vec!["claude-code".into()],
                ..Default::default()
            })
            .into(),
            application_ports: vec![ApplicationPort {
                port: 8080,
                label: "web".into(),
                access: "public".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(&project).expect("proto3 JSON serialization");

        assert_eq!(json["workingDirectory"], "/workspace");
        assert_eq!(json["environment"]["RUST_LOG"], "info");
        assert_eq!(json["agents"]["tools"][0], "claude-code");
        assert_eq!(json["agents"]["install"], false);
        assert_eq!(json["applicationPorts"][0]["port"], 8080);
        assert!(
            json.get("working_directory").is_none(),
            "unexpected JSON: {json}"
        );
    }

    #[test]
    fn portable_project_json_contains_only_opaque_placement_bindings() {
        let project = ProjectSpec {
            schema_version: 1,
            repositories: vec![RepositorySpec {
                source: "https://git.example/org/app.git".into(),
                revision: "deadbeef".into(),
                destination: "/workspace/app".into(),
                ..Default::default()
            }],
            working_directory: "/workspace/app".into(),
            agents: Some(ProjectAgents {
                tools: vec!["codex".into()],
                ..Default::default()
            })
            .into(),
            skills: vec![ProjectSkillSelection {
                source: ProjectSkillSource::Repository.into(),
                reference: ".agents/skills/rust".into(),
                agents: vec!["codex".into()],
                ..Default::default()
            }],
            resources: Some(ProjectResources {
                cpu_millicores: Some(2_000),
                memory_mib: Some(16_384),
                ..Default::default()
            })
            .into(),
            secrets: Some(ProjectSecretBindings {
                project: "platform:development".into(),
                user: Some(ProjectStoragePlacement::Platform.into()),
                ..Default::default()
            })
            .into(),
            credentials: Some(ProjectCredentialBinding {
                profile: "platform:work".into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let json = serde_json::to_value(project).expect("portable project proto JSON");
        assert_eq!(json["schemaVersion"], 1);
        assert_eq!(
            json["repositories"][0]["source"],
            "https://git.example/org/app.git"
        );
        assert_eq!(json["repositories"][0]["destination"], "/workspace/app");
        assert_eq!(json["repositories"][0]["revision"], "deadbeef");
        assert!(json["repositories"][0].get("url").is_none());
        assert!(json["repositories"][0].get("mountPath").is_none());
        assert_eq!(json["credentials"]["profile"], "platform:work");
        assert_eq!(json["secrets"]["project"], "platform:development");
        assert_eq!(
            json["secrets"]["user"],
            "PROJECT_STORAGE_PLACEMENT_PLATFORM"
        );
        assert!(json.get("access").is_none());
        let encoded = json.to_string();
        for forbidden in [
            "hostPath",
            "credentialValue",
            "providerToken",
            "backendSocket",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "unexpected {forbidden}: {encoded}"
            );
        }
    }

    #[test]
    fn account_proto_json_surface_and_presence_are_pinned() {
        assert_eq!(
            ACCOUNT_SERVICE_SERVICE_NAME,
            "codewire.console.v1.AccountService"
        );

        let clear = UpdateGitIdentityRequest::default();
        let clear_json = serde_json::to_value(clear).expect("optional fields serialize");
        assert!(clear_json.get("gitName").is_none());
        assert!(clear_json.get("gitEmail").is_none());

        let set = UpdateGitIdentityRequest {
            git_name: Some(String::new()),
            git_email: Some("git@example.com".into()),
            ..Default::default()
        };
        let set_json = serde_json::to_value(set).expect("present optional fields serialize");
        assert_eq!(set_json["gitName"], "");
        assert_eq!(set_json["gitEmail"], "git@example.com");
    }

    #[test]
    fn account_contract_excludes_retired_credential_products() {
        let source = include_str!("../../../proto/codewire/console/v1/account.proto");
        for removed in [
            "LoginKey",
            "ListLoginKeys",
            "CreateLoginKey",
            "DeleteLoginKey",
            "SshKey",
            "EnsureSshKey",
            "GetSshKey",
            "RegenerateSshKey",
            "GitCredential",
            "ListGitCredentials",
            "CreateGitCredential",
            "UpdateGitCredential",
            "DeleteGitCredential",
        ] {
            assert!(
                !source.contains(removed),
                "retired symbol remains: {removed}"
            );
        }
        for preserved in ["GetGitIdentity", "UpdateGitIdentity"] {
            assert!(
                source.contains(preserved),
                "required symbol missing: {preserved}"
            );
        }
    }

    #[test]
    fn billing_proto_json_surface_money_and_repeated_semantics_are_pinned() {
        assert_eq!(
            BILLING_SERVICE_SERVICE_NAME,
            "codewire.console.v1.BillingService"
        );

        let plan = ResourcePlan {
            display_name: "Standard".into(),
            cpu_overage_millicents: 500,
            mem_overage_millicents: 250,
            disk_overage_millicents: 125,
            ..Default::default()
        };
        let json = serde_json::to_value(plan).expect("billing proto3 JSON serialization");
        assert_eq!(json["cpuOverageMillicents"], "500");
        assert_eq!(json["memOverageMillicents"], "250");
        assert_eq!(json["diskOverageMillicents"], "125");
        assert!(json.get("cpu_overage_millicents").is_none());

        let usage = GetEnvironmentUsageResponse::default();
        let json = serde_json::to_value(usage).expect("billing repeated JSON serialization");
        assert_ne!(json.get("hourlyBreakdown"), Some(&serde_json::Value::Null));
        assert_ne!(json.get("perEnvironment"), Some(&serde_json::Value::Null));
    }

    #[test]
    fn environment_setup_create_options_include_preview_domain_and_reserve_removed_fields() {
        assert_eq!(
            ENVIRONMENT_SETUP_SERVICE_SERVICE_NAME,
            "codewire.console.v1.EnvironmentSetupService"
        );

        let options = GetEnvironmentCreateOptionsResponse {
            preview_base_domain: "preview.example.test".into(),
            ..Default::default()
        };
        let json = serde_json::to_value(options).expect("environment setup options JSON");
        assert_ne!(json.get("presets"), Some(&serde_json::Value::Null));
        assert_eq!(json["previewBaseDomain"], "preview.example.test");
        assert!(json.get("secretProjects").is_none());
        assert!(json.get("githubStatus").is_none());

        let descriptor = prost_types::FileDescriptorSet::decode(
            include_bytes!("../codewire_descriptor.bin").as_slice(),
        )
        .expect("decode public descriptor");
        let response = descriptor
            .file
            .iter()
            .find(|file| {
                file.name.as_deref() == Some("codewire/console/v1/environment_setup.proto")
            })
            .and_then(|file| {
                file.message_type.iter().find(|message| {
                    message.name.as_deref() == Some("GetEnvironmentCreateOptionsResponse")
                })
            })
            .expect("environment create options response descriptor");
        assert_eq!(
            response
                .field
                .iter()
                .map(|field| (field.number, field.name.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                (Some(2), Some("presets")),
                (Some(4), Some("preview_base_domain")),
            ]
        );
        for (number, name) in [(1, "github_status"), (3, "secret_projects")] {
            assert!(
                response
                    .reserved_range
                    .iter()
                    .any(|range| range.start == Some(number) && range.end == Some(number + 1))
            );
            assert!(
                response
                    .reserved_name
                    .iter()
                    .any(|reserved| reserved == name)
            );
        }
    }

    #[test]
    fn repository_analysis_contract_is_absent_and_reserved() {
        let descriptor = prost_types::FileDescriptorSet::decode(
            include_bytes!("../codewire_descriptor.bin").as_slice(),
        )
        .expect("decode public descriptor");
        let file = descriptor
            .file
            .iter()
            .find(|file| file.name.as_deref() == Some("codewire/v1/environment.proto"))
            .expect("environment descriptor");

        for removed in ["RepoFetched", "DetectionResult"] {
            assert!(
                file.message_type
                    .iter()
                    .all(|message| message.name.as_deref() != Some(removed)),
                "retired analysis message remains: {removed}"
            );
        }

        for (message_name, field_number, field_name) in [
            ("WatchEnvironmentCreateRequest", 3, "analyze"),
            ("WatchEnvironmentCreateResponse", 2, "repo_fetched"),
            ("PrepareComplete", 2, "detection"),
        ] {
            let message = file
                .message_type
                .iter()
                .find(|message| message.name.as_deref() == Some(message_name))
                .unwrap_or_else(|| panic!("missing descriptor message {message_name}"));
            assert!(
                message.reserved_range.iter().any(|range| {
                    range.start == Some(field_number) && range.end == Some(field_number + 1)
                }),
                "{message_name} does not reserve field {field_number}"
            );
            assert!(
                message.reserved_name.iter().any(|name| name == field_name),
                "{message_name} does not reserve name {field_name}"
            );
        }
    }

    #[test]
    fn preset_and_port_proto_json_surfaces_are_pinned() {
        assert_eq!(PRESET_SERVICE_SERVICE_NAME, "codewire.v1.PresetService");
        assert_eq!(PORT_SERVICE_SERVICE_NAME, "codewire.v1.PortService");

        let created_at = buffa_types::Timestamp::from_unix_secs(1_735_689_600);
        let preset = Preset {
            id: "preset_123".into(),
            org_id: Some("org_123".into()),
            name: "Rust".into(),
            slug: Some("rust".into()),
            official: true,
            build_status: "ready".into(),
            default_ttl_seconds: Some(3_600),
            project_spec: Some(ProjectSpec {
                schema_version: 1,
                image: "ghcr.io/example/workspace:1".into(),
                resources: Some(ProjectResources {
                    cpu_millicores: Some(2_000),
                    memory_mib: Some(4_096),
                    disk_gib: Some(10),
                    ..Default::default()
                })
                .into(),
                startup_script: "cargo run".into(),
                working_directory: "/workspace".into(),
                ..Default::default()
            })
            .into(),
            created_at: Some(created_at.clone()).into(),
            ..Default::default()
        };
        let preset_json = serde_json::to_value(&preset).expect("preset proto3 JSON serialization");

        assert_eq!(preset_json["orgId"], "org_123");
        assert_eq!(preset_json["buildStatus"], "ready");
        assert_eq!(
            preset_json["projectSpec"]["resources"]["cpuMillicores"],
            2_000
        );
        assert_eq!(preset_json["defaultTtlSeconds"], 3_600);
        assert_eq!(preset_json["projectSpec"]["startupScript"], "cargo run");
        assert_eq!(preset_json["createdAt"], "2025-01-01T00:00:00Z");
        assert!(
            preset_json.get("build_status").is_none(),
            "unexpected JSON: {preset_json}"
        );

        let port = Port {
            id: "port_123".into(),
            environment_id: "env_123".into(),
            port: 8_080,
            label: "web".into(),
            access: PortAccess::Public.into(),
            preview_url: Some("https://web.example".into()),
            created_at: Some(created_at).into(),
            ..Default::default()
        };
        let port_json = serde_json::to_value(&port).expect("port proto3 JSON serialization");

        assert_eq!(port_json["environmentId"], "env_123");
        assert_eq!(port_json["access"], "PORT_ACCESS_PUBLIC");
        assert_eq!(port_json["previewUrl"], "https://web.example");
        assert_eq!(port_json["createdAt"], "2025-01-01T00:00:00Z");
        assert!(
            port_json.get("environment_id").is_none(),
            "unexpected JSON: {port_json}"
        );

        let create_port = serde_json::to_value(CreatePortRequest {
            org_id: "org_123".into(),
            environment_id: "env_123".into(),
            port: 8_080,
            label: "web".into(),
            access: PortAccess::Public.into(),
            ..Default::default()
        })
        .expect("create port proto3 JSON serialization");
        assert_eq!(create_port["environmentId"], "env_123");
        assert_eq!(create_port["access"], "PORT_ACCESS_PUBLIC");

        let absent = serde_json::to_value(UpdatePresetRequest::default())
            .expect("absent preset patch serialization");
        for field in ["slug", "projectSpec"] {
            assert!(absent.get(field).is_none(), "unexpected {field}: {absent}");
        }

        let empty = serde_json::to_value(UpdatePresetRequest {
            slug: Some(String::new()),
            project_spec: Some(ProjectSpec {
                schema_version: 1,
                working_directory: "/workspace".into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
        .expect("present-empty preset patch serialization");
        assert_eq!(empty["slug"], "");
        assert_eq!(empty["projectSpec"]["workingDirectory"], "/workspace");
    }

    #[test]
    fn organization_deletion_operation_json_surface_is_pinned() {
        use super::codewire::v1::DeleteOrganizationResponse;

        let response = DeleteOrganizationResponse {
            operation_id: "org-delete-org_123-1".into(),
            state: OrganizationDeletionState::Deleting.into(),
            ..Default::default()
        };
        let json =
            serde_json::to_value(response).expect("organization deletion response serialization");

        assert_eq!(json["operationId"], "org-delete-org_123-1");
        assert_eq!(json["state"], "ORGANIZATION_DELETION_STATE_DELETING");
        assert!(
            json.get("operation_id").is_none(),
            "unexpected JSON: {json}"
        );
    }

    #[test]
    fn organization_proto_composition_and_json_surface_are_pinned() {
        assert_eq!(
            ORGANIZATION_SERVICE_SERVICE_NAME,
            "codewire.v1.OrganizationService"
        );

        let response = GetOrganizationResponse {
            organization: Some(Organization {
                id: "org_123".into(),
                name: "Acme".into(),
                slug: "acme".into(),
                created_by: "user_123".into(),
                deletion_state: Some(OrganizationDeletionState::Deleting.into()),
                deletion_operation_id: Some("op_123".into()),
                ..Default::default()
            })
            .into(),
            members: vec![OrgMember {
                id: "member_123".into(),
                org_id: "org_123".into(),
                user_id: "user_123".into(),
                role: OrgRole::Owner.into(),
                assignments: vec!["viewer".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(response).expect("organization proto3 JSON serialization");
        assert_eq!(json["organization"]["createdBy"], "user_123");
        assert_eq!(
            json["organization"]["deletionState"],
            "ORGANIZATION_DELETION_STATE_DELETING"
        );
        assert_eq!(json["organization"]["deletionOperationId"], "op_123");
        assert_eq!(json["members"][0]["role"], "ORG_ROLE_OWNER");
        assert_eq!(json["members"][0]["assignments"][0], "viewer");
        assert_eq!(
            serde_json::to_value(InvitationStatus::Pending).unwrap(),
            "INVITATION_STATUS_PENDING"
        );
    }

    #[test]
    fn secret_proto_surface_is_write_only_and_debug_redacted() {
        assert_eq!(SECRET_SERVICE_SERVICE_NAME, "codewire.v1.SecretService");

        let listed = ListSecretsResponse {
            secrets: vec![SecretMetadata {
                key: "DATABASE_URL".into(),
                created_at: Some(buffa_types::Timestamp::from_unix_secs(1_735_689_600)).into(),
                updated_at: None.into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(listed).expect("secret proto3 JSON serialization");
        assert_eq!(json["secrets"][0]["key"], "DATABASE_URL");
        assert_eq!(json["secrets"][0]["createdAt"], "2025-01-01T00:00:00Z");
        assert!(json["secrets"][0].get("updatedAt").is_none());
        assert!(json["secrets"][0].get("value").is_none());
        assert_ne!(
            serde_json::to_value(ListSecretProjectsResponse::default())
                .expect("empty secret-project list serialization")
                .get("secretProjects"),
            Some(&serde_json::Value::Null)
        );

        const MARKER: &str = "do-not-print-this-secret";
        for rendered in [
            format!(
                "{:?}",
                SetSecretRequest {
                    value: MARKER.into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                SetUserSecretRequest {
                    value: MARKER.into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                SetProjectSecretRequest {
                    value: MARKER.into(),
                    ..Default::default()
                }
            ),
        ] {
            assert!(!rendered.contains(MARKER), "secret leaked through Debug");
            assert!(rendered.contains("[REDACTED]"));
        }
    }

    #[test]
    fn workload_secret_preview_contract_is_metadata_only_and_no_side_effects() {
        assert_eq!(
            SECRET_SERVICE_PREVIEW_WORKLOAD_SECRET_RESOLUTION_SPEC.procedure,
            "/codewire.v1.SecretService/PreviewWorkloadSecretResolution"
        );
        assert_eq!(
            SECRET_SERVICE_PREVIEW_WORKLOAD_SECRET_RESOLUTION_SPEC.idempotency_level,
            connectrpc::IdempotencyLevel::NoSideEffects
        );

        let response = PreviewWorkloadSecretResolutionResponse {
            secrets: vec![ResolvedWorkloadSecretMetadata {
                key: "DATABASE_URL".into(),
                source: WorkloadSecretSource::ExplicitEnvironment.into(),
                overridden_sources: vec![
                    WorkloadSecretSource::Organization.into(),
                    WorkloadSecretSource::Project.into(),
                    WorkloadSecretSource::User.into(),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(response).expect("workload secret preview proto3 JSON");
        assert_eq!(
            json,
            serde_json::json!({
                "secrets": [{
                    "key": "DATABASE_URL",
                    "source": "WORKLOAD_SECRET_SOURCE_EXPLICIT_ENVIRONMENT",
                    "overriddenSources": [
                        "WORKLOAD_SECRET_SOURCE_ORGANIZATION",
                        "WORKLOAD_SECRET_SOURCE_PROJECT",
                        "WORKLOAD_SECRET_SOURCE_USER"
                    ]
                }]
            })
        );
        assert!(json["secrets"][0].get("value").is_none());
    }

    #[test]
    fn google_rpc_detail_types_encode_and_decode() {
        use buffa::Message;

        use super::google::rpc::ErrorInfo;

        let mut info = ErrorInfo {
            reason: "SESSION_EXPIRED".into(),
            domain: "codewire.sh".into(),
            ..Default::default()
        };
        info.metadata.insert("request_id".into(), "req_123".into());

        let bytes = info.encode_to_vec();
        let decoded = ErrorInfo::decode_from_slice(&bytes).expect("protobuf round-trip");
        assert_eq!(decoded.reason, "SESSION_EXPIRED");
        assert_eq!(decoded.domain, "codewire.sh");
        assert_eq!(
            decoded.metadata.get("request_id").map(String::as_str),
            Some("req_123")
        );
    }

    #[test]
    fn testing_package_generates_messages_and_service() {
        use super::codewire::testing::v1::{PING_SERVICE_SERVICE_NAME, PingRequest};

        assert_eq!(PING_SERVICE_SERVICE_NAME, "codewire.testing.v1.PingService");
        let ping = PingRequest {
            message: "probe".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&ping).expect("proto3 JSON serialization");
        assert!(json.contains("probe"), "unexpected JSON: {json}");
    }

    #[test]
    fn api_key_create_response_proto_json_surface_is_pinned() {
        let response = CreateApiKeyResponse {
            api_key: Some(ApiKey {
                id: "key_123".into(),
                user_id: "user_123".into(),
                org_id: "org_123".into(),
                name: "deploy".into(),
                key_prefix: "01234567".into(),
                scopes: vec!["environments:read".into()],
                last_used_at: None.into(),
                expires_at: Some(buffa_types::Timestamp::from_unix_secs(1_767_225_600)).into(),
                disabled_at: None.into(),
                created_at: Some(buffa_types::Timestamp::from_unix_secs(1_735_689_600)).into(),
                created_by_name: "Ada Lovelace".into(),
                created_by_email: "ada@example.com".into(),
                ..Default::default()
            })
            .into(),
            key: "cw_0123456789abcdef".into(),
            ..Default::default()
        };

        let json = serde_json::to_value(response).expect("proto3 JSON serialization");
        assert_eq!(json["key"], "cw_0123456789abcdef");
        assert_eq!(json["apiKey"]["keyPrefix"], "01234567");
        assert_eq!(json["apiKey"]["userId"], "user_123");
        assert_eq!(json["apiKey"]["orgId"], "org_123");
        assert_eq!(
            json["apiKey"]["scopes"],
            serde_json::json!(["environments:read"])
        );
        assert_eq!(json["apiKey"]["expiresAt"], "2026-01-01T00:00:00Z");
        assert_eq!(json["apiKey"]["createdAt"], "2025-01-01T00:00:00Z");
        assert_eq!(json["apiKey"]["createdByName"], "Ada Lovelace");
        assert_eq!(json["apiKey"]["createdByEmail"], "ada@example.com");

        let object = json.as_object().expect("response object");
        assert!(object.contains_key("apiKey"));
        assert!(!object.contains_key("api_key"));
    }

    #[test]
    fn one_time_capability_debug_is_redacted() {
        const MARKER: &str = "synthetic-one-use-service-capability-canary";
        for debug in [
            format!(
                "{:?}",
                CreateApiKeyResponse {
                    key: MARKER.into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                IssueGatewayBindingResponse {
                    sidecar_token: MARKER.into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                BindWorkspaceResponse {
                    environment_id: "550e8400-e29b-41d4-a716-446655440000".into(),
                    daemon_credential: MARKER.into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                IssueGatewayDaemonCredentialResponse {
                    daemon_credential: MARKER.into(),
                    workspace_pod_uid: "7e7b20f6-0bd2-4f11-8b16-9c239851eb52".into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                CreateInvitationResponse {
                    token: MARKER.into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                AcceptInvitationRequest {
                    token: MARKER.into(),
                    ..Default::default()
                }
            ),
            format!(
                "{:?}",
                GetInvitationByTokenRequest {
                    token: MARKER.into(),
                    ..Default::default()
                }
            ),
        ] {
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains(MARKER));
        }
    }
}
