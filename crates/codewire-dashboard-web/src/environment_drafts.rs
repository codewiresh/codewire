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

/// A Create navigation convenience, never a source selector or authorization.
/// Rejected input is replaced by a fixed marker, not retained or displayed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum DraftReturn {
    #[default]
    NoRequest,
    Exact(String),
    Unavailable,
}

impl DraftReturn {
    pub(crate) fn parse(raw: Option<&str>) -> Self {
        let Some(raw) = raw else {
            return Self::NoRequest;
        };
        if raw.len() > 1024 {
            // Inspect only bounded keys, never decode oversized values. A
            // handle beyond the budget is rejected, but ordinary inventory
            // queries retain their existing parsing and rejection behavior.
            let requested = raw.split('&').any(|field| {
                let key = field.split_once('=').map_or(field, |(key, _)| key);
                key.len() <= "creation_draft".len() * 3
                    && url::form_urlencoded::parse(key.as_bytes())
                        .next()
                        .is_some_and(|(key, _)| key == "creation_draft")
            });
            return if requested {
                Self::Unavailable
            } else {
                Self::NoRequest
            };
        }
        let mut requested = None;
        for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
            if key != "creation_draft" {
                continue;
            }
            if requested.is_some() {
                return Self::Unavailable;
            }
            requested = Some(value);
        }
        match requested {
            None => Self::NoRequest,
            Some(id) if canonical_id(&id) => Self::Exact(id.into_owned()),
            Some(_) => Self::Unavailable,
        }
    }

    pub(crate) fn requested(&self) -> bool {
        !matches!(self, Self::NoRequest)
    }

    pub(crate) fn query(&self) -> String {
        match self {
            Self::NoRequest => String::new(),
            Self::Exact(id) => format!("?creation_draft={id}"),
            Self::Unavailable => "?creation_draft=unavailable".into(),
        }
    }

    pub(crate) fn canonical_query(&self, raw: Option<&str>) -> bool {
        raw.unwrap_or_default() == self.query().trim_start_matches('?')
    }
}

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

// IdP account IDs and organization IDs are opaque (currently 32 hex bytes),
// not UUIDs. Match the existing terminal account boundary and preserve
// identity bytes unchanged.
fn opaque_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn actor_id(value: &str) -> bool {
    opaque_id(value)
}

pub(crate) fn organization_id(value: &str) -> bool {
    opaque_id(value)
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
    if !actor_id(&identity.id) {
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
            || !actor_id(&draft.actor)
            || !organization_id(&draft.organization)
            || !canonical_id(&draft.draft)
            || draft.saved_at > now
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
    const ACTOR: &str = "11111111111140008000000000000001";
    // Product organization IDs are opaque 32-hex strings, not UUIDs.
    const ORG: &str = "6bf8d155e84c4fc5b479b17022fe41dd";
    const DRAFT: &str = "00000000-0000-4000-8000-000000000003";

    #[test]
    fn exact_return_canonicalizes_without_echoing_other_navigation() {
        let exact = DraftReturn::Exact(DRAFT.into());
        let canonical = format!("creation_draft={DRAFT}");
        assert_eq!(DraftReturn::parse(Some(&canonical)), exact);
        assert!(exact.canonical_query(Some(&canonical)));
        for raw in [
            format!("sources={ORG}&{canonical}"),
            format!("{canonical}&ports={ORG}"),
            format!("destroyed=bogus&{canonical}"),
            canonical.replace("creation_draft=0", "creation_draft=%30"),
            canonical.replace("creation_draft", "%63reation_draft"),
        ] {
            assert_eq!(DraftReturn::parse(Some(&raw)), exact);
            assert!(!exact.canonical_query(Some(&raw)));
        }
        assert_eq!(exact.query(), format!("?{canonical}"));
    }

    #[test]
    fn invalid_duplicate_and_oversize_returns_keep_unavailable_intent() {
        for raw in [
            "creation_draft=".into(),
            "creation_draft=https%3A%2F%2Fcanary.invalid".into(),
            "creation_draft=00000000-0000-0000-0000-000000000000".into(),
            format!("creation_draft={DRAFT}&creation_draft={DRAFT}"),
            format!("creation_draft={DRAFT}&%63reation_draft={DRAFT}"),
            format!("creation_draft={DRAFT}&ignored={}", "x".repeat(1024)),
            format!("ignored={}&%63reation_draft={DRAFT}", "x".repeat(1024)),
            "creation_draft=unavailable".into(),
        ] {
            let rejected = DraftReturn::parse(Some(&raw));
            assert_eq!(rejected, DraftReturn::Unavailable);
            assert!(rejected.requested());
            assert_eq!(rejected.query(), "?creation_draft=unavailable");
        }
        assert!(DraftReturn::Unavailable.canonical_query(Some("creation_draft=unavailable")));
        assert_eq!(
            DraftReturn::parse(Some(&format!("search={}", "x".repeat(1024)))),
            DraftReturn::NoRequest
        );
        for raw in [None, Some(""), Some("search=app&state=running")] {
            let ordinary = DraftReturn::parse(raw);
            assert_eq!(ordinary, DraftReturn::NoRequest);
            assert!(!ordinary.requested());
            assert!(ordinary.query().is_empty());
        }
    }

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
        for id in [
            ACTOR,
            "legacy-idp_account-ID",
            "00000000-0000-4000-8000-000000000001",
        ] {
            assert!(actor_id(id));
        }
        for id in [
            "",
            "account:delimiter",
            "actor@example.test",
            "line\nbreak",
            "non-ascii-é",
        ] {
            assert!(!actor_id(id));
        }
        assert!(!actor_id(&"a".repeat(129)));
        let mut bounded = metadata();
        bounded["actor"] = serde_json::json!("a".repeat(128));
        assert!(parse(&bounded, NOW).is_ok());
        bounded["actor"] = serde_json::json!("a".repeat(129));
        assert!(parse(&bounded, NOW).is_err());
        bounded["actor"] = serde_json::json!("Legacy_Actor-ID");
        let exact = parse(&bounded, NOW).ok().unwrap();
        assert!(exact.matches("Legacy_Actor-ID", ORG, DRAFT));
        assert!(!exact.matches("legacy_actor-id", ORG, DRAFT));
        for id in [
            "",
            "account:delimiter",
            "actor@example.test",
            "line\nbreak",
            " actor",
            "non-ascii-é",
        ] {
            bounded["actor"] = serde_json::json!(id);
            assert!(parse(&bounded, NOW).is_err());
        }
    }

    #[test]
    fn future_versions_oversize_and_noncanonical_identities_fail_closed() {
        assert!(parse(&metadata(), NOW + 30 * 24 * 60 * 60 * 1000).is_ok());
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
        for id in [ORG, "00000000-0000-4000-8000-000000000002"] {
            assert!(organization_id(id));
            let mut exact = metadata();
            exact["organization"] = serde_json::json!(id);
            assert!(parse(&exact, NOW).ok().unwrap().matches(ACTOR, id, DRAFT));
        }
        for id in [
            String::new(),
            "organization:delimiter".into(),
            "org@example.test".into(),
            " org".into(),
            "non-ascii-é".into(),
            "a".repeat(129),
        ] {
            assert!(!organization_id(&id));
            let mut invalid = metadata();
            invalid["organization"] = serde_json::json!(id);
            assert!(parse(&invalid, NOW).is_err());
        }
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
