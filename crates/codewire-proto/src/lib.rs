//! Generated Connect-RPC contract types for the audience-packaged Codewire
//! control-plane API.
//!
//! Message types (buffa), Connect service traits, and — behind the default
//! `client` feature — Connect client stubs are generated at build time by
//! `connectrpc-build` from the schema-of-record protos. Packages map to modules:
//! `codewire.v1` is [`codewire::v1`]; `codewire.console.v1` is
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
    use super::codewire::console::v1::{
        ACCOUNT_SERVICE_SERVICE_NAME, BILLING_SERVICE_SERVICE_NAME, CreateGitCredentialRequest,
        DetectRepoRequest, ENVIRONMENT_SETUP_SERVICE_SERVICE_NAME, GIT_HUB_SERVICE_SERVICE_NAME,
        GetEnvironmentCreateOptionsResponse, GetEnvironmentUsageResponse, GetGitHubStatusResponse,
        GitHubConnection, ListGitHubReposResponse, ResourcePlan, SaveGitHubTokenRequest, SshKey,
        UpdateGitIdentityRequest,
    };
    use super::codewire::internal::v1::{
        COORDINATOR_SERVICE_SERVICE_NAME, CoordinateNode, MESH_AUTHORIZATION_SERVICE_SERVICE_NAME,
        MESH_COORDINATOR_SERVICE_SERVICE_NAME, MeshAuthorizationContext,
        MeshAuthorizationCredentialKind, MeshAuthorizationPrincipalKind, MeshCoordinateHello,
        MeshCoordinateRole, MeshCoordinatorServiceCoordinateRequest,
        ResolveMeshAuthorizationResponse,
    };
    use super::codewire::v1::{
        AgentEnvMap, AgentList, ApiKey, AppPort, AppPortList, CreateApiKeyResponse,
        CreateMeshInviteResponse, CreateMeshNodeEnrollmentResponse, CreatePortRequest, EnvVarMap,
        GetOrganizationResponse, InvitationStatus, ListSecretProjectsResponse, ListSecretsResponse,
        MESH_GROUP_SERVICE_SERVICE_NAME, MESH_INVITE_SERVICE_SERVICE_NAME,
        MESH_KEY_VALUE_SERVICE_SERVICE_NAME, MESH_NETWORK_SERVICE_SERVICE_NAME,
        MESH_NODE_SERVICE_SERVICE_NAME, MeshInvite, MeshNetwork, MeshNode, MeshNodeEnrollment,
        ORGANIZATION_SERVICE_SERVICE_NAME, OrgMember, OrgRole, Organization,
        OrganizationDeletionState, PORT_SERVICE_SERVICE_NAME, PRESET_SERVICE_SERVICE_NAME, Port,
        PortAccess, Preset, PreviewWorkloadSecretResolutionResponse, ProjectAccessBinding,
        ProjectAgents, ProjectResources, ProjectSecretBindings, ProjectSkillSelection,
        ProjectSkillSource, ProjectSpec, RedeemMeshNodeEnrollmentResponse, RepoEntry,
        ResolvedWorkloadSecretMetadata, SECRET_SERVICE_PREVIEW_WORKLOAD_SECRET_RESOLUTION_SPEC,
        SECRET_SERVICE_SERVICE_NAME, SecretMetadata, SetProjectSecretRequest, SetSecretRequest,
        SetUserSecretRequest, SetupAgent, SetupConfig, UpdatePresetRequest, WorkloadSecretSource,
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
    fn generated_types_are_importable_and_json_serializable() {
        let setup = SetupConfig {
            repo_url: "https://git.example/repo.git".into(),
            repos: vec![RepoEntry {
                url: "https://git.example/second.git".into(),
                branch: "main".into(),
                ..Default::default()
            }],
            env_vars: [("RUST_LOG".into(), "info".into())].into_iter().collect(),
            agents: vec![SetupAgent {
                r#type: "claude".into(),
                ..Default::default()
            }],
            install_agents: Some(false),
            app_ports: vec![AppPort {
                port: 8080,
                label: "web".into(),
                access: "public".into(),
                ..Default::default()
            }],
            include_org_secrets: Some(true),
            ..Default::default()
        };
        let json = serde_json::to_value(&setup).expect("proto3 JSON serialization");

        assert_eq!(json["repoUrl"], "https://git.example/repo.git");
        assert_eq!(json["repos"][0]["branch"], "main");
        assert_eq!(json["envVars"]["RUST_LOG"], "info");
        assert_eq!(json["agents"][0]["type"], "claude");
        assert_eq!(json["installAgents"], false);
        assert_eq!(json["appPorts"][0]["port"], 8080);
        assert_eq!(json["includeOrgSecrets"], true);
        assert!(json.get("repo_url").is_none(), "unexpected JSON: {json}");
    }

    #[test]
    fn portable_project_json_contains_only_opaque_placement_bindings() {
        let project = ProjectSpec {
            schema_version: 1,
            repositories: vec![RepoEntry {
                url: "https://git.example/org/app.git".into(),
                revision: "deadbeef".into(),
                mount_path: "/workspace/app".into(),
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
                project: "development".into(),
                user: true,
                ..Default::default()
            })
            .into(),
            access: Some(ProjectAccessBinding {
                profile: "user/work".into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let json = serde_json::to_value(project).expect("portable project proto JSON");
        assert_eq!(json["schemaVersion"], 1);
        assert_eq!(json["repositories"][0]["revision"], "deadbeef");
        assert_eq!(json["access"]["profile"], "user/work");
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

        let create = CreateGitCredentialRequest {
            name: "forge".into(),
            host: "git.example.com".into(),
            auth_type: "basic".into(),
            username: "octocat".into(),
            password: "secret".into(),
            ..Default::default()
        };
        let json = serde_json::to_value(create).expect("account proto3 JSON serialization");
        assert_eq!(json["authType"], "basic");
        assert!(json.get("auth_type").is_none(), "unexpected JSON: {json}");

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

        let ssh = SshKey {
            public_key: "ssh-ed25519 AAAA\n".into(),
            fingerprint: "SHA256:test".into(),
            created_at: Some(buffa_types::Timestamp::from_unix_secs(1_735_689_600)).into(),
            regenerated_at: None.into(),
            ..Default::default()
        };
        let ssh_json = serde_json::to_value(ssh).expect("SSH key proto3 JSON serialization");
        assert_eq!(ssh_json["createdAt"], "2025-01-01T00:00:00Z");
        assert!(ssh_json.get("regeneratedAt").is_none());
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
    fn github_proto_json_surface_presence_and_empty_repeated_are_pinned() {
        assert_eq!(
            GIT_HUB_SERVICE_SERVICE_NAME,
            "codewire.console.v1.GitHubService"
        );

        let disconnected = GetGitHubStatusResponse::default();
        let json = serde_json::to_value(disconnected).expect("GitHub status JSON serialization");
        assert!(json.get("installationId").is_none());
        assert!(json.get("connectedAt").is_none());

        let save = SaveGitHubTokenRequest {
            access_token: "gho_test".into(),
            installation_id: Some(42),
            ..Default::default()
        };
        let json = serde_json::to_value(save).expect("GitHub token JSON serialization");
        assert_eq!(json["accessToken"], "gho_test");
        assert_eq!(json["installationId"], "42");
        assert!(json.get("access_token").is_none());

        let repos = ListGitHubReposResponse::default();
        let json = serde_json::to_value(repos).expect("GitHub repos JSON serialization");
        assert_ne!(json.get("repos"), Some(&serde_json::Value::Null));
    }

    #[test]
    fn environment_setup_proto_reuses_product_messages_and_has_no_raw_token() {
        assert_eq!(
            ENVIRONMENT_SETUP_SERVICE_SERVICE_NAME,
            "codewire.console.v1.EnvironmentSetupService"
        );

        let detect = DetectRepoRequest {
            repo_url: "https://git.example/codewire/codewire".into(),
            branch: "main".into(),
            ..Default::default()
        };
        let json = serde_json::to_value(detect).expect("environment setup proto3 JSON");
        assert_eq!(json["repoUrl"], "https://git.example/codewire/codewire");
        assert_eq!(json["branch"], "main");
        assert!(json.get("githubToken").is_none(), "unexpected JSON: {json}");

        let options = GetEnvironmentCreateOptionsResponse {
            github_status: Some(GitHubConnection::default()).into(),
            ..Default::default()
        };
        let json = serde_json::to_value(options).expect("environment setup options JSON");
        assert_ne!(json.get("presets"), Some(&serde_json::Value::Null));
        assert_ne!(json.get("secretProjects"), Some(&serde_json::Value::Null));
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
            default_cpu_millicores: 2_000,
            default_memory_mb: 4_096,
            default_disk_gb: 10,
            default_ttl_seconds: Some(3_600),
            image: Some("ghcr.io/example/workspace:1".into()),
            default_setup_config: Some(SetupConfig {
                startup_script: "cargo run".into(),
                ..Default::default()
            })
            .into(),
            secret_project_id: Some("project_123".into()),
            created_at: Some(created_at.clone()).into(),
            ..Default::default()
        };
        let preset_json = serde_json::to_value(&preset).expect("preset proto3 JSON serialization");

        assert_eq!(preset_json["orgId"], "org_123");
        assert_eq!(preset_json["buildStatus"], "ready");
        assert_eq!(preset_json["defaultCpuMillicores"], 2_000);
        assert_eq!(preset_json["defaultTtlSeconds"], 3_600);
        assert_eq!(
            preset_json["defaultSetupConfig"]["startupScript"],
            "cargo run"
        );
        assert_eq!(preset_json["secretProjectId"], "project_123");
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
        for field in [
            "slug",
            "secretProjectId",
            "envVars",
            "agents",
            "agentEnv",
            "appPorts",
        ] {
            assert!(absent.get(field).is_none(), "unexpected {field}: {absent}");
        }

        let empty = serde_json::to_value(UpdatePresetRequest {
            slug: Some(String::new()),
            secret_project_id: Some(String::new()),
            env_vars: Some(EnvVarMap::default()).into(),
            agents: Some(AgentList::default()).into(),
            agent_env: Some(AgentEnvMap::default()).into(),
            app_ports: Some(AppPortList::default()).into(),
            ..Default::default()
        })
        .expect("present-empty preset patch serialization");
        assert_eq!(empty["slug"], "");
        assert_eq!(empty["secretProjectId"], "");
        for field in ["envVars", "agents", "agentEnv", "appPorts"] {
            assert!(empty.get(field).is_some(), "missing {field}: {empty}");
        }
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
}
