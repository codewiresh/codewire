use std::collections::BTreeSet;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const SKILL_SNAPSHOT_PLAN_PATH: &str = "/generation/codewire/skill-snapshot.json";
pub const SKILL_SNAPSHOT_PLAN_RELATIVE_PATH: &str = "codewire/skill-snapshot.json";
pub const SKILL_SNAPSHOT_CONTENT_PATH: &str = "/generation/codewire/skills";
pub const SKILL_SNAPSHOT_CONTENT_RELATIVE_PATH: &str = "codewire/skills";
pub const MAX_SKILL_SNAPSHOT_PLAN_BYTES: usize = 1024 * 1024;

const SKILL_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const MAX_SKILL_SNAPSHOTS: usize = codewire_project::MAX_SKILLS;
const MAX_VALUE_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillSnapshotSource {
    Repository,
    User,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillSnapshotMode {
    ReadOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillProjectionRoot {
    UserHome,
    CodexHome,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SkillProjection {
    agent: String,
    root: SkillProjectionRoot,
    relative_path: String,
}

impl SkillProjection {
    pub fn agent(&self) -> &str {
        &self.agent
    }

    pub fn root(&self) -> SkillProjectionRoot {
        self.root
    }

    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    fn for_agent(agent: &str, name: &str) -> Result<Self, SkillSnapshotError> {
        let (root, prefix) = match agent {
            "claude-code" => (SkillProjectionRoot::UserHome, ".claude/skills"),
            "codex" => (SkillProjectionRoot::CodexHome, "skills"),
            "gemini-cli" => (SkillProjectionRoot::UserHome, ".gemini/skills"),
            "kimi-code" => (SkillProjectionRoot::UserHome, ".kimi/skills"),
            "pi" => (SkillProjectionRoot::UserHome, ".pi/agent/skills"),
            "aider" => (SkillProjectionRoot::UserHome, ".aider/skills"),
            _ => return Err(SkillSnapshotError),
        };
        let projection = Self {
            agent: agent.to_owned(),
            root,
            relative_path: format!("{prefix}/{name}"),
        };
        projection.validate()?;
        Ok(projection)
    }

    fn validate(&self) -> Result<(), SkillSnapshotError> {
        let name = Path::new(&self.relative_path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(SkillSnapshotError)?;
        if Self::for_agent_unchecked(&self.agent, name)? != *self {
            return Err(SkillSnapshotError);
        }
        Ok(())
    }

    fn for_agent_unchecked(agent: &str, name: &str) -> Result<Self, SkillSnapshotError> {
        let (root, prefix) = match agent {
            "claude-code" => (SkillProjectionRoot::UserHome, ".claude/skills"),
            "codex" => (SkillProjectionRoot::CodexHome, "skills"),
            "gemini-cli" => (SkillProjectionRoot::UserHome, ".gemini/skills"),
            "kimi-code" => (SkillProjectionRoot::UserHome, ".kimi/skills"),
            "pi" => (SkillProjectionRoot::UserHome, ".pi/agent/skills"),
            "aider" => (SkillProjectionRoot::UserHome, ".aider/skills"),
            _ => return Err(SkillSnapshotError),
        };
        Ok(Self {
            agent: agent.to_owned(),
            root,
            relative_path: format!("{prefix}/{name}"),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SkillSnapshot {
    source: SkillSnapshotSource,
    source_identity: String,
    relative_path: String,
    digest: String,
    mode: SkillSnapshotMode,
    projections: Vec<SkillProjection>,
}

impl SkillSnapshot {
    pub fn new(
        source: SkillSnapshotSource,
        source_identity: String,
        relative_path: String,
        digest: String,
        name: &str,
        agents: &[String],
    ) -> Result<Self, SkillSnapshotError> {
        if !valid_name(name) || agents.is_empty() {
            return Err(SkillSnapshotError);
        }
        let mut projections = agents
            .iter()
            .map(|agent| SkillProjection::for_agent(agent, name))
            .collect::<Result<Vec<_>, _>>()?;
        projections.sort();
        let snapshot = Self {
            source,
            source_identity,
            relative_path,
            digest,
            mode: SkillSnapshotMode::ReadOnly,
            projections,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn source(&self) -> SkillSnapshotSource {
        self.source
    }

    pub fn source_identity(&self) -> &str {
        &self.source_identity
    }

    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn mode(&self) -> SkillSnapshotMode {
        self.mode
    }

    pub fn projections(&self) -> &[SkillProjection] {
        &self.projections
    }

    fn validate(&self) -> Result<(), SkillSnapshotError> {
        if self.source_identity.is_empty()
            || self.source_identity.len() > MAX_VALUE_BYTES
            || self
                .source_identity
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || !valid_relative_path(&self.relative_path)
            || !valid_sha256(&self.digest)
            || self.mode != SkillSnapshotMode::ReadOnly
            || self.projections.is_empty()
            || self.projections.len() > codewire_project::MAX_AGENTS
        {
            return Err(SkillSnapshotError);
        }
        let mut previous = None;
        for projection in &self.projections {
            projection.validate()?;
            if previous.is_some_and(|value| value >= projection) {
                return Err(SkillSnapshotError);
            }
            previous = Some(projection);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SkillSnapshotPlan {
    schema_version: u32,
    project_sha256: String,
    plan_generation: u64,
    skills: Vec<SkillSnapshot>,
}

impl SkillSnapshotPlan {
    pub fn new(
        project_sha256: String,
        plan_generation: u64,
        mut skills: Vec<SkillSnapshot>,
    ) -> Result<Self, SkillSnapshotError> {
        skills.sort();
        let plan = Self {
            schema_version: SKILL_SNAPSHOT_SCHEMA_VERSION,
            project_sha256,
            plan_generation,
            skills,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn project_sha256(&self) -> &str {
        &self.project_sha256
    }

    pub fn plan_generation(&self) -> u64 {
        self.plan_generation
    }

    pub fn skills(&self) -> &[SkillSnapshot] {
        &self.skills
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, SkillSnapshotError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| SkillSnapshotError)?;
        if bytes.is_empty() || bytes.len() > MAX_SKILL_SNAPSHOT_PLAN_BYTES {
            return Err(SkillSnapshotError);
        }
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SkillSnapshotError> {
        if bytes.is_empty() || bytes.len() > MAX_SKILL_SNAPSHOT_PLAN_BYTES {
            return Err(SkillSnapshotError);
        }
        let plan: Self = serde_json::from_slice(bytes).map_err(|_| SkillSnapshotError)?;
        plan.validate()?;
        if plan.encode_canonical()? != bytes {
            return Err(SkillSnapshotError);
        }
        Ok(plan)
    }

    pub fn sha256(&self) -> Result<String, SkillSnapshotError> {
        Ok(format!("{:x}", Sha256::digest(self.encode_canonical()?)))
    }

    fn validate(&self) -> Result<(), SkillSnapshotError> {
        if self.schema_version != SKILL_SNAPSHOT_SCHEMA_VERSION
            || !valid_sha256(&self.project_sha256)
            || self.plan_generation == 0
            || self.skills.is_empty()
            || self.skills.len() > MAX_SKILL_SNAPSHOTS
        {
            return Err(SkillSnapshotError);
        }
        let mut previous = None;
        let mut projections = BTreeSet::new();
        for skill in &self.skills {
            skill.validate()?;
            if previous.is_some_and(|value| value >= skill) {
                return Err(SkillSnapshotError);
            }
            previous = Some(skill);
            for projection in &skill.projections {
                if !projections.insert((projection.root, projection.relative_path.as_str())) {
                    return Err(SkillSnapshotError);
                }
            }
        }
        Ok(())
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "."
        && value != ".."
        && !value
            .bytes()
            .any(|byte| byte == b'/' || byte == 0 || byte.is_ascii_control())
}

fn valid_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= MAX_VALUE_BYTES
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("skill snapshot plan is invalid")]
pub struct SkillSnapshotError;

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(agent: &str, name: &str, seed: u8) -> SkillSnapshot {
        SkillSnapshot::new(
            SkillSnapshotSource::Repository,
            format!("workspace:/workspace@{seed}"),
            format!(".agents/skills/{name}"),
            format!("{seed:064x}"),
            name,
            &[agent.to_owned()],
        )
        .unwrap()
    }

    #[test]
    fn plan_round_trip_is_canonical_and_digest_bound() {
        let plan = SkillSnapshotPlan::new(
            "a".repeat(64),
            7,
            vec![
                snapshot("codex", "rust", 2),
                snapshot("claude-code", "go", 1),
            ],
        )
        .unwrap();
        let bytes = plan.encode_canonical().unwrap();
        assert_eq!(SkillSnapshotPlan::decode_canonical(&bytes).unwrap(), plan);
        assert_eq!(plan.sha256().unwrap().len(), 64);
        assert_eq!(plan.skills()[0].projections()[0].agent(), "claude-code");
        assert_eq!(
            plan.skills()[1].projections()[0].relative_path(),
            "skills/rust"
        );
    }

    #[test]
    fn plan_rejects_projection_collisions_and_noncanonical_bytes() {
        let first = snapshot("codex", "rust", 1);
        let second = SkillSnapshot::new(
            SkillSnapshotSource::User,
            "user:rust".to_owned(),
            "rust".to_owned(),
            "2".repeat(64),
            "rust",
            &["codex".to_owned()],
        )
        .unwrap();
        assert!(SkillSnapshotPlan::new("a".repeat(64), 1, vec![first, second]).is_err());

        let valid =
            SkillSnapshotPlan::new("a".repeat(64), 1, vec![snapshot("codex", "rust", 1)]).unwrap();
        assert!(
            SkillSnapshotPlan::decode_canonical(&serde_json::to_vec_pretty(&valid).unwrap())
                .is_err()
        );
    }

    #[test]
    fn every_canonical_agent_has_a_confined_projection() {
        for agent in [
            "claude-code",
            "codex",
            "gemini-cli",
            "kimi-code",
            "pi",
            "aider",
        ] {
            assert!(SkillProjection::for_agent(agent, "safe").is_ok());
        }
        assert!(SkillProjection::for_agent("unknown", "safe").is_err());
        assert!(SkillProjection::for_agent("codex", "../escape").is_err());
    }
}
