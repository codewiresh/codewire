//! What orchestration asks a driver to run, as intent (#3628 PR 8b).
//!
//! An environment's rendering is its intent here plus the driver's own
//! deployment configuration. Orchestration states the image, isolation,
//! shape and the environment's identity; how a driver turns that into
//! objects, and every deployment-wide setting it renders with, stays inside
//! the driver.

pub use crate::sandbox::warm_pool::WorkspaceShape;

/// The isolation an environment runs with, from its row. A driver that can't
/// provide one refuses it, naming that isolation as the reason (design §4.5),
/// rather than running it with less.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isolation {
    Standard,
    Confidential,
}

impl Isolation {
    /// The isolation an environment row's tier names.
    pub fn of_tier(tier: &str) -> anyhow::Result<Self> {
        match tier {
            "standard" => Ok(Self::Standard),
            "confidential" => Ok(Self::Confidential),
            other => anyhow::bail!("unsupported environment isolation tier {other:?}"),
        }
    }
}

/// Who the runtime is for, and the authority it is rendered under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderingIdentity {
    pub environment_id: String,
    pub organization_id: String,
    /// Captured existing environment operation authority, not a new generation.
    pub operation_generation: i64,
    /// Shared metadata-only selection captured for this operation, never values.
    pub projection_selection_sha256: Option<[u8; 32]>,
    /// Exact clients selected by the captured immutable profile revision.
    pub managed_credential_clients: codewire_access::ManagedCredentialClients,
    /// The hosted snapshot a new workspace volume restores from.
    pub source_snapshot_id: Option<String>,
    /// A confidential environment's storage manifest; empty otherwise.
    pub confidential_storage_manifest_uri: String,
}

/// One environment's runtime, as orchestration wants it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderingIntent {
    pub image: String,
    /// The preset's template base, which names the environment's template.
    pub template_base: String,
    pub isolation: Isolation,
    /// The environment's CPU is its own, never shared.
    pub dedicated_cpu: bool,
    pub shape: WorkspaceShape,
    pub identity: RenderingIdentity,
}
