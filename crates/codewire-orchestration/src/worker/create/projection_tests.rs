use super::*;
use codewire_project::{
    PlatformProjectionSelection, PlatformProjectionSelectionError, ProjectSpec,
};

fn environment() -> EnvironmentRow {
    EnvironmentRow {
        id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
        org_id: "synthetic-org".into(),
        preset_id: None,
        env_type: "sandbox".into(),
        state: "creating".into(),
        desired_state: "started".into(),
        external_cleanup_completed_at: None,
        cpu_millicores: 1000,
        memory_mb: 2048,
        disk_gb: 10,
        source_snapshot_id: None,
        isolation_tier: "standard".into(),
        dedicated_cpu: false,
        ttl_seconds: None,
        project_spec: ProjectSpec::default(),
        operation_generation: 7,
        projection_selection: Ok(None),
        managed_credential_clients: Ok(Default::default()),
    }
}

fn app_selection() -> PlatformProjectionSelection {
    PlatformProjectionSelection {
        creator: "synthetic-creator".into(),
        organization: "synthetic-org".into(),
        organization_selected: true,
        project_id: None,
        user_selected: false,
        profile: None,
        ordinary_keys: ["APP_MODE".into()].into(),
        reserved_keys: codewire_project::platform_projection_reserved_keys([]).unwrap(),
    }
}

fn opts(cfg: &SandboxWorkerCfg, env: &EnvironmentRow) -> anyhow::Result<TemplateOpts> {
    environment_template_opts(
        cfg,
        "ghcr.io/codewiresh/workspace:synthetic",
        "workspace",
        env,
        7,
    )
}

#[test]
fn template_admission_requires_current_capture_and_trust_for_app_only_selection() {
    let mut env = environment();
    let mut cfg = SandboxWorkerCfg::default();
    assert!(
        opts(&cfg, &env)
            .unwrap()
            .projection_selection_sha256
            .is_none()
    );
    for generation in [0, 6, 8] {
        env.operation_generation = generation;
        assert!(opts(&cfg, &env).is_err());
    }
    env.operation_generation = 7;
    env.projection_selection = Err(PlatformProjectionSelectionError);
    assert!(opts(&cfg, &env).is_err());
    let selection = app_selection();
    env.projection_selection = Ok(Some(selection.clone()));
    assert!(
        opts(&cfg, &env).is_err(),
        "app-only still requires protected runtime trust"
    );
    cfg.credential_runtime =
        Some(crate::sandbox::template::CredentialRuntimeTemplateConfig::synthetic("dev-sandboxes"));
    assert_eq!(
        opts(&cfg, &env).unwrap().projection_selection_sha256,
        Some(selection.sha256().unwrap())
    );
    assert!(
        selection.profile.is_none(),
        "application selection must not need a provider"
    );
}

#[test]
fn publication_revalidation_rejects_changed_identity_selection_and_cleanup_only_rows() {
    let mut env = environment();
    env.projection_selection = Ok(Some(app_selection()));
    let cfg = SandboxWorkerCfg {
        credential_runtime: Some(
            crate::sandbox::template::CredentialRuntimeTemplateConfig::synthetic("dev-sandboxes"),
        ),
        ..Default::default()
    };
    let rendered = opts(&cfg, &env).unwrap();
    validate_template_metadata(&env, &rendered).unwrap();
    for field in 0..7 {
        let mut changed = env.clone();
        match field {
            0 => changed.id = "other-environment".into(),
            1 => changed.org_id = "other-org".into(),
            2 => changed.operation_generation = 8,
            3 => changed.operation_generation = 0,
            4 => changed.projection_selection = Ok(None),
            5 => changed.projection_selection = Err(PlatformProjectionSelectionError),
            _ => {
                changed
                    .projection_selection
                    .as_mut()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .organization_selected = false
            }
        }
        let error = validate_template_metadata(&changed, &rendered).unwrap_err();
        assert!(
            super::super::activity_authority::is_authority_lost(&error),
            "field {field}"
        );
    }
    let empty = environment();
    let empty_opts = opts(&SandboxWorkerCfg::default(), &empty).unwrap();
    validate_template_metadata(&empty, &empty_opts).unwrap();
    assert!(validate_template_metadata(&env, &empty_opts).is_err());
    assert!(validate_template_metadata(&empty, &rendered).is_err());
}

#[test]
fn publication_fences_exact_client_selection_separately_from_projection_digest() {
    let mut env = environment();
    let mut selection = app_selection();
    selection.profile = Some(("98657d60-ce77-40c7-897c-6323b52e3a96".into(), 3));
    env.projection_selection = Ok(Some(selection));
    env.managed_credential_clients =
        Ok(codewire_access::ManagedCredentialClients::from_profile_slots(["codex"]).unwrap());
    let cfg = SandboxWorkerCfg {
        credential_runtime: Some(
            crate::sandbox::template::CredentialRuntimeTemplateConfig::synthetic("dev-sandboxes"),
        ),
        ..Default::default()
    };
    let rendered = opts(&cfg, &env).unwrap();
    validate_template_metadata(&env, &rendered).unwrap();
    env.managed_credential_clients =
        Ok(codewire_access::ManagedCredentialClients::from_profile_slots(["openai"]).unwrap());
    assert!(validate_template_metadata(&env, &rendered).is_err());
    env.managed_credential_clients = Err(PlatformProjectionSelectionError);
    assert!(validate_template_metadata(&env, &rendered).is_err());
    assert!(opts(&cfg, &env).is_err());
}

#[test]
fn administrator_runtime_configuration_does_not_select_a_stock_client() {
    let env = environment();
    let cfg = SandboxWorkerCfg {
        credential_runtime: Some(
            crate::sandbox::template::CredentialRuntimeTemplateConfig::synthetic("dev-sandboxes"),
        ),
        ..Default::default()
    };
    assert_eq!(
        opts(&cfg, &env).unwrap().managed_credential_clients,
        Default::default()
    );
}
