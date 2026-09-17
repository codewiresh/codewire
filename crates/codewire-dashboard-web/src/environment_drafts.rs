//! Closed, metadata-only selections for explicit per-tab Create recovery.
//! Drafts are navigation conveniences, never source grants or saved secrets.

use axum::http::{HeaderMap, HeaderValue, header};
use connectrpc::{ConnectError, ErrorCode};
use serde::Deserialize;

use crate::{
    auth::{authenticated_identity, enforce_two_factor},
    environment_source_forms::SourceSubmission,
    state::AppState,
    view::{EnvironmentAppPortFormRow, EnvironmentCreateFormView},
};

pub(crate) const MAX_BYTES: usize = 8 * 1024;
pub(crate) const MAX_AGE_MS: u64 = 30 * 60 * 1000;

// No Debug: rejected input must never become a diagnostic representation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectionDraft {
    pub(crate) version: u8,
    pub(crate) actor: String,
    pub(crate) organization: String,
    pub(crate) draft: String,
    pub(crate) saved_at: u64,
    pub(crate) selections: Selections,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selections {
    preset_id: String,
    cpu: String,
    memory: String,
    disk: String,
    ttl: String,
    isolation_tier: String,
    agents: Vec<String>,
    ports: Vec<Preview>,
    secret_project: String,
    credential_profile: String,
    include_org_secrets: bool,
    include_user_secrets: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    port: String,
    access: String,
}

pub(crate) fn canonical_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

/// Reuse canonical cookie identity/2FA; only immutable public identity escapes.
pub(crate) async fn actor(state: &AppState, cookie: HeaderValue) -> Result<String, ConnectError> {
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, cookie);
    let identity = authenticated_identity(state, &headers)
        .await
        .map_err(|error| {
            let code = if matches!(error, crate::error::WebError::Unauthorized) {
                ErrorCode::Unauthenticated
            } else {
                ErrorCode::Unavailable
            };
            ConnectError::new(code, "draft identity is unavailable")
        })?;
    enforce_two_factor(&identity)
        .map_err(|_| ConnectError::permission_denied("draft identity requires two-factor setup"))?;
    if !canonical_id(&identity.id) {
        return Err(ConnectError::unavailable(
            "draft identity metadata is invalid",
        ));
    }
    Ok(identity.id)
}

impl SelectionDraft {
    pub(crate) fn parse(bytes: &[u8], now: u64) -> Result<Self, ()> {
        if bytes.len() > MAX_BYTES {
            return Err(());
        }
        let draft: Self = serde_json::from_slice(bytes).map_err(|_| ())?;
        if draft.version != 1
            || ![&draft.actor, &draft.organization, &draft.draft]
                .into_iter()
                .all(|id| canonical_id(id))
            || draft.saved_at > now
            || now - draft.saved_at >= MAX_AGE_MS
        {
            return Err(());
        }
        draft.selections.validate()?;
        Ok(draft)
    }

    pub(crate) fn matches(&self, actor: &str, organization: &str, draft: &str) -> bool {
        self.actor == actor && self.organization == organization && self.draft == draft
    }

    pub(crate) fn hydrate(&self, form: &mut EnvironmentCreateFormView) -> Result<(), ()> {
        let selections = &self.selections;
        if selections.isolation_tier == "confidential" && !form.confidential_available {
            return Err(());
        }
        if selections
            .agents
            .iter()
            .any(|id| !form.agents.iter().any(|agent| agent.id == id))
        {
            return Err(());
        }
        form.draft_id.clone_from(&self.draft);
        form.preset_id.clone_from(&selections.preset_id);
        form.cpu.clone_from(&selections.cpu);
        form.memory.clone_from(&selections.memory);
        form.disk.clone_from(&selections.disk);
        form.ttl.clone_from(&selections.ttl);
        form.isolation_tier.clone_from(&selections.isolation_tier);
        form.selected_agents.clone_from(&selections.agents);
        form.app_ports = selections
            .ports
            .iter()
            .enumerate()
            .map(|(index, port)| EnvironmentAppPortFormRow {
                index,
                port: port.port.clone(),
                label: String::new(),
                access: port.access.clone(),
                ..Default::default()
            })
            .collect();
        selections.sources()?.hydrate(&mut form.sources);
        if !selections.preset_id.is_empty()
            && !form
                .presets
                .iter()
                .any(|preset| preset.id == selections.preset_id)
        {
            form.form_error = "The saved configuration is unavailable. Choose a current configuration before creating a Sandbox.".into();
        }
        form.draft_restore_allowed = false;
        form.draft_restored = true;
        Ok(())
    }
}

impl Selections {
    fn validate(&self) -> Result<(), ()> {
        let number = |value: &str, minimum: u32, maximum: u32| {
            value.len() <= 7
                && value.bytes().all(|b| b.is_ascii_digit())
                && value
                    .parse::<u32>()
                    .is_ok_and(|value| (minimum..=maximum).contains(&value))
        };
        if !(self.preset_id.is_empty() || canonical_id(&self.preset_id))
            || !number(&self.cpu, 100, 128_000)
            || !number(&self.memory, 128, 1_048_576)
            || !number(&self.disk, 1, 16_384)
            || !valid_ttl(&self.ttl)
            || !matches!(self.isolation_tier.as_str(), "standard" | "confidential")
            || self.agents.len() > 6
            || self.agents.iter().any(|id| {
                !matches!(
                    id.as_str(),
                    "claude-code" | "codex" | "gemini-cli" | "kimi-code" | "pi" | "aider"
                )
            })
            || self
                .agents
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.agents.len()
            || self.ports.len() > 16
            || self.ports.iter().any(|port| {
                !number(&port.port, 1, 65_535)
                    || !matches!(port.access.as_str(), "creator" | "org_members" | "public")
            })
        {
            return Err(());
        }
        self.sources()?;
        Ok(())
    }

    fn sources(&self) -> Result<SourceSubmission, ()> {
        if !self.secret_project.is_empty() && !canonical_id(&self.secret_project) {
            return Err(());
        }
        if !self.credential_profile.is_empty() {
            let (id, revision) = self.credential_profile.split_once('@').ok_or(())?;
            if !canonical_id(id)
                || revision.is_empty()
                || revision.len() > 19
                || revision.starts_with('0')
                || !revision.bytes().all(|byte| byte.is_ascii_digit())
                || !revision
                    .parse::<u64>()
                    .is_ok_and(|value| value <= i64::MAX as u64)
            {
                return Err(());
            }
        }
        let mut fields = url::form_urlencoded::Serializer::new(String::new());
        fields
            .append_pair("secret_project", &self.secret_project)
            .append_pair("credential_profile", &self.credential_profile);
        if self.include_org_secrets {
            fields.append_pair("include_org_secrets", "platform");
        }
        if self.include_user_secrets {
            fields.append_pair("include_user_secrets", "platform");
        }
        SourceSubmission::parse(fields.finish().as_bytes())
    }
}

fn valid_ttl(value: &str) -> bool {
    if matches!(value, "" | "0" | "infinity") {
        return true;
    }
    if value.len() > 10 {
        return false;
    }
    let (digits, multiplier) = match value.as_bytes().last() {
        Some(b's') => (&value[..value.len() - 1], 1_u64),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 3_600),
        Some(b'd') => (&value[..value.len() - 1], 86_400),
        _ => (value, 60),
    };
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && digits
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(multiplier))
            .is_some_and(|seconds| (60..=31_536_000).contains(&seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 4_000_000;
    const ACTOR: &str = "00000000-0000-4000-8000-000000000001";
    const ORG: &str = "00000000-0000-4000-8000-000000000002";
    const DRAFT: &str = "00000000-0000-4000-8000-000000000003";

    fn metadata() -> serde_json::Value {
        serde_json::json!({
            "version": 1, "actor": ACTOR, "organization": ORG, "draft": DRAFT, "saved_at": NOW,
            "selections": {
                "preset_id": "", "cpu": "1250", "memory": "3072", "disk": "17", "ttl": "8h",
                "isolation_tier": "standard", "agents": ["codex"], "ports": [],
                "secret_project": "", "credential_profile": format!("{DRAFT}@9007199254740993"),
                "include_org_secrets": false, "include_user_secrets": true
            }
        })
    }

    fn parse(value: &serde_json::Value, now: u64) -> Result<SelectionDraft, ()> {
        SelectionDraft::parse(value.to_string().as_bytes(), now)
    }

    #[test]
    fn exact_namespace_and_large_decimal_profile_revision_are_preserved() {
        let draft = parse(&metadata(), NOW).ok().unwrap();
        assert!(draft.matches(ACTOR, ORG, DRAFT));
        assert!(!draft.matches(ORG, ORG, DRAFT));
        assert!(!draft.matches(ACTOR, ACTOR, DRAFT));
        assert!(!draft.matches(ACTOR, ORG, ACTOR));
        let source = draft.selections.sources().unwrap();
        assert_eq!(
            source.selection.profile_revision,
            Some(9_007_199_254_740_993)
        );
        assert_eq!(
            source.selection.credentials.as_option().unwrap().profile,
            format!("platform:id:{DRAFT}")
        );
        assert!(source.selection.secrets.as_option().unwrap().user.is_some());
    }

    #[test]
    fn expiry_future_versions_oversize_and_noncanonical_identities_fail_closed() {
        assert!(parse(&metadata(), NOW + MAX_AGE_MS - 1).is_ok());
        assert!(parse(&metadata(), NOW + MAX_AGE_MS).is_err());
        assert!(parse(&metadata(), NOW - 1).is_err());
        assert!(SelectionDraft::parse(&vec![b' '; MAX_BYTES + 1], NOW).is_err());
        for (key, value) in [
            ("version", serde_json::json!(2)),
            ("actor", serde_json::json!("user@example.test")),
            ("draft", serde_json::json!(uuid::Uuid::nil().to_string())),
        ] {
            let mut invalid = metadata();
            invalid[key] = value;
            assert!(parse(&invalid, NOW).is_err());
        }
        let mut invalid = metadata();
        invalid["organization"] = serde_json::json!("6BF8D155-E84C-4FC5-B479-B17022FE41DD");
        assert!(parse(&invalid, NOW).is_err());
    }

    #[test]
    fn free_form_fields_material_and_errors_are_not_draft_contracts() {
        for key in [
            "name",
            "image",
            "repositories",
            "git_url",
            "branch",
            "mount",
            "install_command",
            "startup_script",
            "environment",
            "password",
            "token",
            "_csrf",
            "errors",
            "transcript",
        ] {
            for nested in [false, true] {
                let mut invalid = metadata();
                let target = if nested {
                    &mut invalid["selections"]
                } else {
                    &mut invalid
                };
                target[key] = serde_json::json!("synthetic-private-canary");
                assert!(parse(&invalid, NOW).is_err(), "forbidden draft field {key}");
            }
        }
    }

    #[test]
    fn only_bounded_typed_selections_and_source_references_are_admitted() {
        for (key, value) in [
            ("cpu", serde_json::json!("129000")),
            ("memory", serde_json::json!("127")),
            ("disk", serde_json::json!("16385")),
            ("ttl", serde_json::json!("366d")),
            ("ttl", serde_json::json!("59s")),
            ("isolation_tier", serde_json::json!("unknown")),
            ("agents", serde_json::json!(["codex", "codex"])),
            ("agents", serde_json::json!(["custom-command"])),
            ("secret_project", serde_json::json!("project-name")),
            (
                "credential_profile",
                serde_json::json!(format!("{DRAFT}@9223372036854775808")),
            ),
            (
                "credential_profile",
                serde_json::json!(9_007_199_254_740_993_u64),
            ),
            (
                "credential_profile",
                serde_json::json!(format!("{DRAFT}@0007")),
            ),
            ("include_user_secrets", serde_json::json!("platform")),
            (
                "ports",
                serde_json::json!([{"port":"3000", "access":"internal"}]),
            ),
            (
                "ports",
                serde_json::json!([{"port":"3000", "access":"creator", "label":"private-canary"}]),
            ),
        ] {
            let mut invalid = metadata();
            invalid["selections"][key] = value;
            assert!(
                parse(&invalid, NOW).is_err(),
                "invalid draft selection {key}"
            );
        }
        for value in ["", "0", "infinity", "1m", "8h", "365d"] {
            let mut valid = metadata();
            valid["selections"]["ttl"] = serde_json::json!(value);
            assert!(parse(&valid, NOW).is_ok());
        }
    }
}
