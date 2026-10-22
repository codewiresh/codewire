//! Where this deployment pulls Codewire's runtime images from.
//!
//! A deployment names its own registries; nothing here defaults to one.
//! Orchestration reads them from its environment once, at startup, and
//! refuses to start without them. `docs/CONFIGURATION.md` documents each
//! variable.

use std::sync::OnceLock;

use codewire_server_core::runtime_images::workspace_image;

/// Repository the default workspace image is pulled from. The published
/// digest (`codewire-workspace-image`) is appended to it.
pub const WORKSPACE_IMAGE_REPOSITORY_ENV: &str = "CODEWIRE_WORKSPACE_IMAGE_REPOSITORY";
/// Comma-separated registry prefixes, each ending in `/`, that the
/// runtime-node image cache may hold images from. The image cache admission
/// policy reads the same value from the same ConfigMap.
pub const APPROVED_IMAGE_REGISTRIES_ENV: &str = "CODEWIRE_APPROVED_IMAGE_REGISTRIES";
/// The support image every workspace runs its daemon from.
pub const DAEMON_IMAGE_ENV: &str = "SANDBOX_DAEMON_IMAGE";
/// Where every configuration error points.
pub const CONFIGURATION_REFERENCE: &str = "docs/CONFIGURATION.md";

/// One approved registry prefix, as the admission policy matches it: a
/// registry host with an optional port and path, ending in `/`.
/// [`valid_registry_prefix`] implements it.
pub const APPROVED_REGISTRY_PATTERN: &str =
    "^[a-z0-9]+([.-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)*/$";

/// The deployment's runtime image configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeImages {
    workspace_repository: String,
    workspace_image: String,
    approved_registries: Vec<String>,
}

impl RuntimeImages {
    /// Validates both values. An error names the variable and
    /// [`CONFIGURATION_REFERENCE`].
    pub fn new(workspace_repository: &str, approved_registries: &str) -> Result<Self, String> {
        let workspace_repository = workspace_repository.trim();
        if workspace_repository.is_empty() {
            return Err(missing(WORKSPACE_IMAGE_REPOSITORY_ENV));
        }
        if !workspace_repository.contains('/')
            || !valid_registry_prefix(&format!("{workspace_repository}/"))
        {
            return Err(format!(
                "{WORKSPACE_IMAGE_REPOSITORY_ENV}={workspace_repository:?} must name an image \
                 repository without a tag or digest, such as \
                 registry.example.com/codewire/workspace; see {CONFIGURATION_REFERENCE}"
            ));
        }
        let approved_registries = approved_registries.trim();
        if approved_registries.is_empty() {
            return Err(missing(APPROVED_IMAGE_REGISTRIES_ENV));
        }
        let approved_registries: Vec<String> =
            approved_registries.split(',').map(str::to_owned).collect();
        if let Some(malformed) = approved_registries
            .iter()
            .find(|prefix| !valid_registry_prefix(prefix))
        {
            return Err(format!(
                "{APPROVED_IMAGE_REGISTRIES_ENV} entry {malformed:?} must be a registry prefix \
                 ending in /, such as registry.example.com/, with no spaces; see \
                 {CONFIGURATION_REFERENCE}"
            ));
        }
        Ok(Self {
            workspace_image: workspace_image::image_at(workspace_repository),
            workspace_repository: workspace_repository.to_owned(),
            approved_registries,
        })
    }

    pub fn from_env() -> Result<Self, String> {
        let read = |name: &str| std::env::var(name).unwrap_or_default();
        Self::new(
            &read(WORKSPACE_IMAGE_REPOSITORY_ENV),
            &read(APPROVED_IMAGE_REGISTRIES_ENV),
        )
    }

    /// The configuration `docs/CONFIGURATION.md` shows, at a reserved
    /// documentation host. Unit tests run with it.
    pub fn example() -> Self {
        Self::new(
            "registry.example.invalid/codewire/workspace",
            "registry.example.invalid/,docker.io/library/",
        )
        .expect("the documented example is valid")
    }

    /// The repository the workspace image is pulled from.
    pub fn workspace_repository(&self) -> &str {
        &self.workspace_repository
    }

    /// The published workspace digest at [`Self::workspace_repository`]: the
    /// image a Sandbox runs when it chooses none.
    pub fn workspace_image(&self) -> &str {
        &self.workspace_image
    }

    pub fn approved_registries(&self) -> &[String] {
        &self.approved_registries
    }

    /// Whether `image_ref` names the canonical workspace: the current digest,
    /// or one older clients and stored presets still send, at this
    /// deployment's repository or at the public mirror.
    pub fn is_canonical_workspace(&self, image_ref: &str) -> bool {
        workspace_image::is_canonical(image_ref, &self.workspace_repository)
    }
}

static CONFIGURED: OnceLock<RuntimeImages> = OnceLock::new();

/// Reads this process's configuration once. Orchestration calls it at
/// startup and refuses to start on an error.
pub fn init() -> Result<&'static RuntimeImages, String> {
    if let Some(configured) = CONFIGURED.get() {
        return Ok(configured);
    }
    let configured = RuntimeImages::from_env()?;
    Ok(CONFIGURED.get_or_init(|| configured))
}

/// This process's configuration. Unit tests use [`RuntimeImages::example`].
pub fn configured() -> &'static RuntimeImages {
    CONFIGURED.get_or_init(|| {
        if cfg!(test) {
            return RuntimeImages::example();
        }
        RuntimeImages::from_env().unwrap_or_else(|error| panic!("{error}"))
    })
}

pub fn missing(name: &str) -> String {
    format!("{name} is not set; see {CONFIGURATION_REFERENCE}")
}

/// [`APPROVED_REGISTRY_PATTERN`]: `host[:port][/segment...]/`.
pub fn valid_registry_prefix(prefix: &str) -> bool {
    let Some(name) = prefix.strip_suffix('/') else {
        return false;
    };
    let mut parts = name.split('/');
    let host = parts.next().unwrap_or_default();
    let (host, port) = match host.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (host, None),
    };
    separated(host, b".-")
        && port.is_none_or(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
        && parts.all(|segment| separated(segment, b"._-"))
}

/// `[a-z0-9]+([<separators>][a-z0-9]+)*`.
fn separated(text: &str, separators: &[u8]) -> bool {
    let mut previous_separator = true;
    for b in text.bytes() {
        let separator = separators.contains(&b);
        if separator {
            if previous_separator {
                return false;
            }
        } else if !(b.is_ascii_lowercase() || b.is_ascii_digit()) {
            return false;
        }
        previous_separator = separator;
    }
    !text.is_empty() && !previous_separator
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_values_name_the_variable_and_the_reference() {
        for (repository, registries, variable) in [
            (
                "",
                "registry.example.invalid/",
                WORKSPACE_IMAGE_REPOSITORY_ENV,
            ),
            (
                " ",
                "registry.example.invalid/",
                WORKSPACE_IMAGE_REPOSITORY_ENV,
            ),
            (
                "registry.example.invalid/codewire/workspace",
                "",
                APPROVED_IMAGE_REGISTRIES_ENV,
            ),
        ] {
            let error = RuntimeImages::new(repository, registries).unwrap_err();
            assert_eq!(
                error,
                format!("{variable} is not set; see docs/CONFIGURATION.md")
            );
        }
    }

    #[test]
    fn the_workspace_image_is_the_pinned_digest_at_the_configured_repository() {
        let images = RuntimeImages::new(
            " registry.example.invalid:5000/team/workspace ",
            "registry.example.invalid:5000/",
        )
        .unwrap();
        assert_eq!(
            images.workspace_image(),
            format!(
                "registry.example.invalid:5000/team/workspace@{}",
                workspace_image::DIGEST
            )
        );
        assert!(images.is_canonical_workspace(images.workspace_image()));
        assert!(images.is_canonical_workspace(workspace_image::PUBLIC_IMAGE));
        assert!(!images.is_canonical_workspace(&format!(
            "registry.example.invalid/team/workspace@{}",
            workspace_image::DIGEST
        )));
        for refused in [
            "registry.example.invalid",
            "registry.example.invalid/codewire/workspace:main",
            "registry.example.invalid/codewire/workspace@sha256:00",
            "Registry.example.invalid/codewire/workspace",
            "registry.example.invalid/codewire/workspace/",
        ] {
            let error = RuntimeImages::new(refused, "registry.example.invalid/").unwrap_err();
            assert!(error.starts_with(WORKSPACE_IMAGE_REPOSITORY_ENV), "{error}");
            assert!(error.ends_with(CONFIGURATION_REFERENCE), "{error}");
        }
    }

    #[test]
    fn approved_registries_are_exact_prefixes() {
        let images = RuntimeImages::example();
        assert_eq!(
            images.approved_registries(),
            ["registry.example.invalid/", "docker.io/library/"]
        );
        for accepted in [
            "registry.example.invalid/",
            "docker.io/library/",
            "localhost:5000/",
            "ghcr.io/codewiresh/",
            "a-b.c/d_e.f-g/",
        ] {
            assert!(valid_registry_prefix(accepted), "{accepted}");
        }
        for refused in [
            "",
            "/",
            "registry.example.invalid",
            " registry.example.invalid/",
            "Registry.example.invalid/",
            "registry..example/",
            "registry.example.invalid:/",
            "registry.example.invalid:x/",
            "registry.example.invalid//",
            "registry.example.invalid/-x/",
            "docker.io/library",
        ] {
            assert!(!valid_registry_prefix(refused), "{refused:?}");
        }
        // An empty entry would approve every registry; a value with one is
        // refused, like any other malformed entry.
        for value in [
            "registry.example.invalid/,",
            ",registry.example.invalid/",
            "registry.example.invalid/, docker.io/library/",
        ] {
            let error = RuntimeImages::new("registry.example.invalid/codewire/workspace", value)
                .unwrap_err();
            assert!(error.starts_with(APPROVED_IMAGE_REGISTRIES_ENV), "{error}");
        }
    }
}
