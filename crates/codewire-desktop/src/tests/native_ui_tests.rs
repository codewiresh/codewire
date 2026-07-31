use codewire_client::{DesiredState, Environment, EnvironmentState, Port, PortAccess};
use gpui::Keystroke;

use crate::workspace::{WorkspaceIdentity, WorkspaceSource};
use crate::{PRIMARY_QUIT_KEY, environment_summary};

#[test]
fn typed_environment_becomes_wire_independent_native_ui_data() {
    let environment = Environment {
        id: "env-1".to_string(),
        org_id: "org-1".to_string(),
        name: "design-system".to_string(),
        state: EnvironmentState::Running.into(),
        desired_state: DesiredState::Started.into(),
        setup_phase: 4,
        setup_complete: true,
        ttl_seconds: Some(3_600),
        cpu_millicores: 2_000,
        memory_mb: 4_096,
        disk_gb: 40,
        total_running_seconds: 7_380,
        protected: true,
        preset_name: "large".to_string(),
        network: "default".to_string(),
        ports: vec![Port {
            port: 3_000,
            label: "web".to_string(),
            access: PortAccess::OrgMembers.into(),
            preview_url: Some("https://preview.invalid".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };

    let summary = environment_summary(environment);
    assert_eq!(summary.state, "running");
    assert_eq!(summary.desired_state, "started");
    assert_eq!(summary.preset_name, "large");
    assert_eq!(summary.ports.len(), 1);
    assert_eq!(summary.ports[0].access, "organization");

    let identity =
        WorkspaceIdentity::codewire_environment("org-1".to_string(), "acme".to_string(), summary);
    assert_eq!(identity.id, "codewire:env:org-1:env-1");
    assert_eq!(identity.name, "design-system");
    let WorkspaceSource::CodewireEnvironment {
        environment: live_environment,
        ..
    } = &identity.source
    else {
        panic!("expected a Codewire environment workspace");
    };
    assert!(live_environment.is_some());

    let saved = serde_json::to_string(&identity).expect("workspace identity should serialize");
    assert!(!saved.contains("preview.invalid"));
    assert!(!saved.contains("\"environment\":"));

    let restored: WorkspaceIdentity =
        serde_json::from_str(&saved).expect("workspace identity should deserialize");
    let WorkspaceSource::CodewireEnvironment {
        env_id,
        env_name,
        environment,
        ..
    } = restored.source
    else {
        panic!("expected a restored Codewire environment workspace");
    };
    assert_eq!(env_id, "env-1");
    assert_eq!(env_name, "design-system");
    assert!(environment.is_none());
}

#[test]
fn quit_shortcut_uses_the_platform_primary_modifier() {
    let keystroke = Keystroke::parse(PRIMARY_QUIT_KEY).expect("quit shortcut should parse");
    assert_eq!(keystroke.key, "q");
    assert!(
        keystroke.modifiers.secondary(),
        "quit must be Cmd+Q on macOS and Ctrl+Q on Linux/Windows"
    );
}
