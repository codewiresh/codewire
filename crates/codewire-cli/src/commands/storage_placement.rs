use super::guided::{self, Choice};
use super::{OsEnv, OutputFormat, ResolvePaths};
use codewire_protected_store::ProtectedStoreBackend;

pub(crate) use codewire_project::StoragePlacement;

/// A management command's explicit store constrains a qualified reference; it
/// never permits fallback to another origin or changes execution placement.
pub(crate) fn require_reference_placement<'a>(
    reference: codewire_project::StorageReference<'a>,
    placement: StoragePlacement,
) -> anyhow::Result<&'a str> {
    anyhow::ensure!(
        reference.placement.is_none_or(|origin| origin == placement),
        "source origin conflicts with the explicitly selected storage placement"
    );
    Ok(reference.selector)
}

/// Storage is selected independently of the current execution environment.
/// Resolve it before connecting to an authority or reading protected material.
pub(crate) fn resolve_storage_placement(
    local: bool,
    platform: bool,
    json_output: bool,
) -> anyhow::Result<StoragePlacement> {
    resolve_with_title(
        local,
        platform,
        json_output,
        "Where should Codewire store these secrets?",
    )
}

pub(crate) fn resolve_credential_storage_placement(
    local: bool,
    platform: bool,
    json_output: bool,
) -> anyhow::Result<StoragePlacement> {
    resolve_with_title(
        local,
        platform,
        json_output,
        "Where should Codewire store this credential?",
    )
}

fn resolve_with_title(
    local: bool,
    platform: bool,
    json_output: bool,
    title: &str,
) -> anyhow::Result<StoragePlacement> {
    let output = if json_output {
        OutputFormat::Json
    } else {
        OutputFormat::Text
    };
    select_storage_placement(local, platform, guided::available(output), || {
        let backend = ResolvePaths::from_env(&OsEnv)
            .map_err(anyhow::Error::from)
            .and_then(|paths| {
                super::credential_input::configured_local_credential_store(&paths.mesh_data_dir)
            })
            .map_err(|error| error.to_string());
        let choices = storage_choices(backend.as_ref().copied());
        selected_storage(guided::choose(title, &choices)?, backend)
    })
}

fn select_storage_placement(
    local: bool,
    platform: bool,
    interactive: bool,
    prompt: impl FnOnce() -> anyhow::Result<StoragePlacement>,
) -> anyhow::Result<StoragePlacement> {
    match (local, platform) {
        (true, false) => Ok(StoragePlacement::Local),
        (false, true) => Ok(StoragePlacement::Platform),
        (true, true) => {
            anyhow::bail!("storage placement must be exactly one of --local or --cloud")
        }
        (false, false) if interactive => prompt(),
        (false, false) => anyhow::bail!(
            "storage placement is required: pass --local or --cloud (noninteractive and JSON commands never prompt)"
        ),
    }
}

fn selected_storage(
    index: usize,
    backend: Result<ProtectedStoreBackend, String>,
) -> anyhow::Result<StoragePlacement> {
    if index == 0 {
        backend.map_err(anyhow::Error::msg)?;
        Ok(StoragePlacement::Local)
    } else {
        Ok(StoragePlacement::Platform)
    }
}

fn storage_choices(backend: Result<ProtectedStoreBackend, &String>) -> Vec<Choice> {
    vec![
        Choice::new(
            if cfg!(target_os = "macos") {
                "On this Mac"
            } else {
                "On this computer"
            },
            match backend {
                Ok(backend) => backend_label(backend).to_owned(),
                Err(error) => format!("Unavailable: {error}"),
            },
        ),
        Choice::new("In your Codewire account", "Protected cloud storage"),
    ]
}

fn backend_label(backend: ProtectedStoreBackend) -> &'static str {
    match backend {
        ProtectedStoreBackend::Keychain => "macOS Keychain",
        ProtectedStoreBackend::SecretService => "Linux system keyring (Secret Service)",
        ProtectedStoreBackend::File => "Permission-restricted file storage",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_placement_never_prompts_and_conflicts_fail_before_input() {
        for interactive in [false, true] {
            for (local, platform, expected) in [
                (true, false, Some(StoragePlacement::Local)),
                (false, true, Some(StoragePlacement::Platform)),
                (true, true, None),
            ] {
                assert_eq!(
                    select_storage_placement(local, platform, interactive, || panic!(
                        "must not prompt"
                    ))
                    .ok(),
                    expected
                );
            }
        }
    }

    #[test]
    fn noninteractive_placement_never_consumes_piped_material() {
        let error = select_storage_placement(false, false, false, || panic!("must not read input"))
            .unwrap_err();
        assert!(error.to_string().contains("--local or --cloud"));
    }

    #[test]
    fn unavailable_local_backend_does_not_block_cloud_selection() {
        let error = "local keyring unavailable".to_owned();
        let choices = storage_choices(Err(&error));
        assert_eq!(
            choices[1],
            Choice::new("In your Codewire account", "Protected cloud storage")
        );
        assert_eq!(
            selected_storage(1, Err(error.clone())).unwrap(),
            StoragePlacement::Platform
        );
        assert!(selected_storage(0, Err(error)).is_err());
    }

    #[test]
    fn backend_labels_describe_the_configured_protection() {
        assert_eq!(
            backend_label(ProtectedStoreBackend::Keychain),
            "macOS Keychain"
        );
        assert!(backend_label(ProtectedStoreBackend::SecretService).contains("system keyring"));
        assert!(!backend_label(ProtectedStoreBackend::File).contains("Keychain"));
    }
}
