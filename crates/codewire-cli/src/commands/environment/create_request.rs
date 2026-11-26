//! A cloud create's request, from the flags and the selected codewire.yaml.

use super::*;

/// The request from the flags and the files `--file` names, if any. Nothing
/// is searched for: `cw init` and direct request construction use this; a
/// create selects its file first ([`project_file::select_from`]).
pub(crate) fn env_create_request_from_args(
    args: &EnvCreateArgs,
) -> anyhow::Result<CreateEnvironmentRequest> {
    let source = if args.file.is_empty() {
        project_file::ConfigSource::Flags
    } else {
        project_file::ConfigSource::Files(args.file.clone())
    };
    env_create_request_from_source(args, &source).map(|(request, _)| request)
}

/// The request from the selected file and the flags, which win over it, and
/// where its configuration came from. `cw use` never selects a source.
pub(crate) fn env_create_request_from_source(
    args: &EnvCreateArgs,
    source: &project_file::ConfigSource,
) -> anyhow::Result<(CreateEnvironmentRequest, project_file::Provenance)> {
    let ttl_seconds = args
        .ttl
        .as_deref()
        .and_then(trimmed_str)
        .map(parse_go_duration_seconds)
        .transpose()
        .context("invalid --ttl duration")?;
    let preset_id = trimmed_optional(args.preset_id.clone());
    let mut provenance = project_file::Provenance::new(source.clone());
    let (mut project_spec, file_idle_stop, file_idle_suspend) = match source.path() {
        Some(_) => {
            let document = sources::load_platform_document(&source.paths())?;
            provenance.unused_fields = document.unused_fields;
            let (stop, suspend) = (document.idle_stop_seconds, document.idle_suspend_seconds);
            (document.spec, stop, suspend)
        }
        None => (codewire_project::ProjectSpec::default(), None, None),
    };
    let idle_stop_seconds = match args.idle_stop.as_deref() {
        Some(value) => {
            Some(codewire_project::parse_idle_stop(value).context("invalid --idle-stop")?)
        }
        None => file_idle_stop,
    };
    let idle_suspend_seconds = match args.idle_suspend.as_deref() {
        Some(value) => {
            Some(codewire_project::parse_idle_suspend(value).context("invalid --idle-suspend")?)
        }
        None => file_idle_suspend,
    };
    if let Some(preset) = &args.preset_slug {
        project_spec.preset = preset.trim().to_owned();
    } else if preset_id.is_some() {
        project_spec.preset.clear();
    }
    if let Some(image) = args.image.as_deref().and_then(trimmed_str) {
        project_spec.image = if image.contains('/') {
            image.to_owned()
        } else {
            expand_image_ref(image)
        };
    }
    // Without a file, `cw init --branch` detects its repository after
    // constructing this draft, so a missing repository is not refused here.
    provenance.repositories_from_flags = project_file::apply_repository_flags(
        &mut project_spec,
        &args.repo_urls,
        &args.repo_flags,
        args.branch.as_deref().and_then(trimmed_str),
        source.path().is_some(),
    )?;
    if let Some(install) = &args.install {
        project_spec.install_command = install.trim().to_owned();
    }
    if let Some(startup) = &args.startup {
        project_spec.startup_script = startup.trim().to_owned();
    }
    project_spec
        .environment
        .extend(parse_env_settings(&args.env, "cw create")?);
    if let Some(agent) = args.coding_agent.as_deref().and_then(trimmed_str) {
        project_spec.agents = codewire_project::AgentsSpec {
            install: None,
            tools: vec![config::canonical_agent_id(agent)],
        };
    }
    if args.cpu.is_some() {
        project_spec.resources.cpu_millicores =
            positive_i32(args.cpu.as_deref().map(parse_resize_cpu).transpose()?)
                .map(|value| value as u32);
    }
    if args.memory.is_some() {
        project_spec.resources.memory_mib =
            positive_i32(parse_create_memory(args.memory.as_deref())?).map(|value| value as u64);
    }
    if args.disk.is_some() {
        project_spec.resources.disk_gib =
            positive_i32(parse_create_disk(args.disk.as_deref())?).map(|value| value as u64);
    }
    if let Some(project) = &args.secrets {
        codewire_project::StorageReference::project(project)?;
        project_spec.secrets.project = project.clone();
    }
    if let Some(user) = args.user_secrets {
        project_spec.secrets.user = Some(sources::cloud_user_secrets(user)?);
    }
    if args.org_secrets {
        project_spec.secrets.organization = true;
    }
    if let Some(profile) = &args.profile {
        codewire_project::StorageReference::profile(profile)?;
        project_spec.credentials = Some(codewire_project::CredentialBinding {
            profile: profile.clone(),
        });
    }
    if args.no_profile {
        project_spec.credentials = None;
    }
    project_spec.validate()?;
    Ok((
        CreateEnvironmentRequest {
            preset_id,
            name: trimmed_optional(args.name.clone()),
            ttl_seconds,
            idle_stop_seconds,
            idle_suspend_seconds,
            isolation_tier: args.isolation.clone().unwrap_or_default(),
            project_spec,
            ..Default::default()
        },
        provenance,
    ))
}

pub(crate) fn parse_create_memory(value: Option<&str>) -> anyhow::Result<Option<i32>> {
    value
        .map(|value| match value.parse::<i32>() {
            Ok(value) => Ok(value),
            Err(_) => parse_resize_memory(value)
                .context("memory must be an integer MiB value or use MB/GB units"),
        })
        .transpose()
}

fn parse_create_disk(value: Option<&str>) -> anyhow::Result<Option<i32>> {
    value
        .map(|value| match value.parse::<i32>() {
            Ok(value) => Ok(value),
            Err(_) => parse_resize_disk(value)
                .context("disk must be an integer GiB value or use GB units"),
        })
        .transpose()
}

/// The cloud create request and its provenance. With no image or preset
/// named, a file or a create without repositories gets the default workspace
/// image. Only a flags-only create with repositories leaves the image to the
/// defaults Codewire Cloud saved for its first repository, so those defaults
/// never fill settings a selected file left out.
pub(crate) fn prepare_platform_env_create(
    args: &EnvCreateArgs,
    source: &project_file::ConfigSource,
) -> anyhow::Result<(CreateEnvironmentRequest, project_file::Provenance)> {
    let (mut request, mut provenance) = env_create_request_from_source(args, source)?;
    request.project_spec.ensure_platform_compatible()?;
    if let project_file::ConfigSource::Discovered(found) = source
        && !args.no_local_file
    {
        provenance.skipped_local_file = project_file::local_file_beside(found)?;
    }
    if request.preset_id.is_none()
        && request.project_spec.preset.is_empty()
        && request.project_spec.image.is_empty()
    {
        match request.project_spec.repositories.first() {
            Some(repository) if source.path().is_none() => {
                provenance.repository_defaults = Some(repository.source.clone());
            }
            _ => {
                request.project_spec.image = CANONICAL_WORKSPACE_IMAGE.to_string();
                provenance.default_image = true;
            }
        }
    }
    Ok((request, provenance))
}
