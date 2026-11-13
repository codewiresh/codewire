//! Guided setup around the existing create and launch operations. Choosing an
//! existing environment never reapplies creation inputs or selects a host.
use super::guided::{self, Choice};
use super::*;

pub(crate) fn prepare_create(
    placement: Option<EnvironmentPlacement>,
    args: &mut EnvCreateArgs,
) -> anyhow::Result<Option<EnvironmentPlacement>> {
    if !guided_create_available(args) || args.name.is_some() {
        return Ok(placement);
    }
    let placement = choose_placement(placement)?;
    args.name = Some(guided::text(
        "Environment name",
        Some(&directory_name()),
        |name| match placement {
            EnvironmentPlacement::Local => environment_name(name),
            EnvironmentPlacement::Platform => guided::required(name),
        },
    )?);
    args.guided = true;
    Ok(Some(placement))
}

pub(crate) async fn edit_cloud_create(
    globals: &Globals,
    args: &mut EnvCreateArgs,
    resolved: &CreateEnvironmentRequest,
) -> anyhow::Result<()> {
    let resources = &resolved.project_spec.resources;
    let cpu = resources
        .cpu_millicores
        .map(|v| (f64::from(v) / 1000.0).to_string());
    let memory = resources.memory_mib.map(|v| v.to_string());
    let disk = resources.disk_gib.map(|v| v.to_string());
    loop {
        match guided::choose(
            "Environment settings",
            &[
                Choice::new(
                    "Continue to review",
                    "Configuration file and supplied flags are preserved",
                ),
                Choice::new("Resources", "CPU, memory and disk"),
                Choice::new("Container image", ""),
                Choice::new(
                    "Repository",
                    "Clone committed files; local edits are excluded",
                ),
                Choice::new("Credential profile", "Explicit profile reference"),
                Choice::new("Application secrets", "Explicit project reference"),
            ],
        )? {
            0 => return Ok(()),
            1 => {
                args.cpu = Some(guided::text(
                    "CPU cores",
                    args.cpu.as_deref().or(cpu.as_deref()),
                    |s| parse_resize_cpu(s).map(drop).map_err(|e| e.to_string()),
                )?);
                args.memory = Some(guided::text(
                    "Memory in MiB",
                    args.memory.as_deref().or(memory.as_deref()),
                    |s| {
                        environment::parse_create_memory(Some(s))
                            .map(drop)
                            .map_err(|e| e.to_string())
                    },
                )?);
                args.disk = Some(guided::text(
                    "Disk in GiB",
                    args.disk.as_deref().or(disk.as_deref()),
                    |s| {
                        let size = s
                            .parse::<i32>()
                            .map_err(|_| "Enter a whole number from 1 through 200".to_owned())?;
                        if (1..=200).contains(&size) {
                            Ok(())
                        } else {
                            Err("Enter a whole number from 1 through 200".into())
                        }
                    },
                )?);
            }
            2 => {
                args.image = Some(guided::text(
                    "Container image",
                    args.image.as_deref().or_else(|| {
                        let image = &resolved.project_spec.image;
                        (!image.is_empty()).then_some(image.as_str())
                    }),
                    guided::required,
                )?)
            }
            3 => {
                let repo = guided::text(
                    "Repository URL",
                    args.repo_flags.first().map(String::as_str),
                    |s| {
                        codewire_project::validate_repository_destinations([(s, "")])
                            .map(drop)
                            .map_err(|_| {
                                "Enter a repository URL without embedded credentials".into()
                            })
                    },
                )?;
                args.repo_urls.clear();
                args.repo_flags = vec![repo];
            }
            4 => {
                args.profile = choose_profile(globals, true).await?;
                args.no_profile = args.profile.is_none();
            }
            _ => args.secrets = Some(choose_secret_project(globals, true).await?),
        }
    }
}

pub(crate) async fn choose_profile(
    globals: &Globals,
    cloud_only: bool,
) -> anyhow::Result<Option<String>> {
    if guided::choose(
        "Credential profile",
        &[
            Choice::new(
                "Choose or set up a profile",
                "Select exactly which credential identities to use",
            ),
            Choice::new("No credential profile", ""),
        ],
    )? == 1
    {
        return Ok(None);
    }
    let store = if cloud_only {
        storage_placement::StoragePlacement::Platform
    } else {
        storage_placement::resolve_credential_storage_placement(false, false, false)?
    };
    if store == storage_placement::StoragePlacement::Platform {
        resolve_guided_platform(globals, &ResolvePaths::from_env(&OsEnv)?, true).await?;
    }
    guided_credentials::choose_profile_reference(globals, store)
        .await
        .map(Some)
}

pub(crate) async fn choose_secret_project(
    globals: &Globals,
    cloud_only: bool,
) -> anyhow::Result<String> {
    let store = if cloud_only {
        storage_placement::StoragePlacement::Platform
    } else {
        storage_placement::resolve_storage_placement(false, false, false)?
    };
    let located = if store == storage_placement::StoragePlacement::Platform {
        let platform =
            resolve_guided_platform(globals, &ResolvePaths::from_env(&OsEnv)?, true).await?;
        let client = organization_client(&platform)?;
        let orgs = client.list_orgs().await?;
        let org_id = if cloud_only {
            organization_for_setup(globals, &platform, &client, &orgs, true).await?
        } else {
            // A portable reference cannot retain a newly selected organization.
            // Resolve in the invocation's existing context so later creation
            // uses the same authority as this metadata inventory.
            resolve_org_id(&platform, &orgs, globals.org.as_deref()).context(
                "select the secret project's organization with `cw org set ID_OR_SLUG` before editing this configuration",
            )?
        };
        globals.with_org(Some(org_id))
    } else {
        globals.clone()
    };
    secrets::choose_secret_project_reference(&located, store).await
}

fn guided_create_available(args: &EnvCreateArgs) -> bool {
    !args.yes
        && args.environment_type == EnvironmentTypeArg::Sandbox
        && args.snapshot.is_none()
        && args.checkpoint.is_none()
        && args.spec.is_none()
        && guided::available(args.output)
}

fn choose_placement(
    placement: Option<EnvironmentPlacement>,
) -> anyhow::Result<EnvironmentPlacement> {
    match placement {
        Some(placement) => Ok(placement),
        None => match guided::choose(
            "Where would you like to work?",
            &[
                Choice::new("On this computer", "Create a local VM"),
                Choice::new("In Codewire cloud", "Create a cloud environment"),
            ],
        )? {
            0 => Ok(EnvironmentPlacement::Local),
            _ => Ok(EnvironmentPlacement::Platform),
        },
    }
}

pub(crate) fn directory_name() -> String {
    std::env::current_dir()
        .ok()
        .and_then(|path| path.file_name().map(|s| s.to_string_lossy().into_owned()))
        .map(|name| {
            name.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' {
                        c.to_ascii_lowercase()
                    } else {
                        '-'
                    }
                })
                .collect::<String>()
        })
        .map(|name| name.trim_matches('-').chars().take(48).collect::<String>())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "sandbox".to_owned())
}

pub(crate) fn environment_name(value: &str) -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if codewire_local_vmm::valid_environment_name(value) {
        return Ok(());
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    if guided::required(value).is_ok() {
        return Ok(());
    }
    Err("Use 1 to 63 letters, digits, '-', '_' or '.', starting with a letter or digit.".into())
}

pub(crate) async fn choose_run_environment(
    globals: &Globals,
    run: &EnvironmentRunArgs,
) -> anyhow::Result<(config::CurrentTargetConfig, Option<String>)> {
    loop {
        #[derive(Clone, Copy)]
        enum Action {
            Create(EnvironmentPlacement),
            Existing,
        }
        let mut choices = Vec::new();
        let mut actions = Vec::new();
        if globals.placement != Some(EnvironmentPlacement::Platform) {
            choices.push(Choice::new(
                "Create a local environment",
                "Review before creating a VM on this computer",
            ));
            actions.push(Action::Create(EnvironmentPlacement::Local));
        }
        choices.push(Choice::new(
            "Choose an existing environment",
            "Local or cloud sandbox",
        ));
        actions.push(Action::Existing);
        if globals.placement != Some(EnvironmentPlacement::Local) {
            choices.push(Choice::new(
                "Create a cloud environment",
                "Review before creating an environment in Codewire cloud",
            ));
            actions.push(Action::Create(EnvironmentPlacement::Platform));
        }
        let chosen = actions[guided::choose("Where would you like to work?", &choices)?];
        if matches!(chosen, Action::Existing) {
            let inventory = inventory::environment_inventory(
                globals,
                globals.placement,
                &inventory::InventoryOptions {
                    environment_type: Some("sandbox".into()),
                    ..Default::default()
                },
            )
            .await?;
            for (location, reason) in inventory.unavailable() {
                eprintln!(
                    "{} could not be listed: {}",
                    location.listing(),
                    progress::terminal_text(reason)
                );
            }
            if inventory.entries.is_empty() {
                eprintln!("No environments are available to choose. You can create one instead.");
                continue;
            }
            let choices = inventory
                .entries
                .iter()
                .map(|entry| {
                    Choice::new(
                        entry.name(),
                        format!("{} · {}", entry.location.kind(), entry.state()),
                    )
                })
                .collect::<Vec<_>>();
            let index = guided::choose("Choose an environment", &choices)?;
            let chosen = &inventory.entries[index];
            validate_run_placement(run, chosen.location == inventory::Location::Cloud)?;
            if chosen.state().eq_ignore_ascii_case("stopped") {
                if !guided::confirm(&format!(
                    "Start {} and open your session?",
                    progress::terminal_text(chosen.name())
                ))? {
                    anyhow::bail!("canceled; no environment started");
                }
                let placement = match chosen.location {
                    inventory::Location::Local => EnvironmentPlacement::Local,
                    inventory::Location::Cloud => EnvironmentPlacement::Platform,
                    inventory::Location::Host => unreachable!("sandbox-only inventory"),
                };
                let located = globals.with_org(chosen.organization_id.clone());
                Box::pin(handle_env_command(
                    &located,
                    Some(placement),
                    EnvCommand::Start(EnvTargetArgs {
                        environment: chosen.id().to_owned(),
                        output: OutputFormat::Text,
                    }),
                ))
                .await?;
            }
            return Ok((chosen.selection().target(), chosen.organization_id.clone()));
        }
        let Action::Create(placement) = chosen else {
            unreachable!("existing choice returned");
        };
        validate_run_placement(run, placement == EnvironmentPlacement::Platform)?;
        // Read defaults from the command's own parser rather than maintaining
        // a second set of defaults for first launch.
        let Command::Create(mut args) = Cli::try_parse_from(["cw", "create"])?.command else {
            unreachable!("static create command");
        };
        prepare_create(Some(placement), &mut args)?;
        args.guided = true;
        let mut located = globals.clone();
        located.placement = Some(placement);
        match placement {
            EnvironmentPlacement::Local => {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    let caps = lifecycle_output::capabilities(args.output);
                    let created = Box::pin(create_native_environment(&located, *args, &caps))
                        .await?
                        .context("canceled; no environment created")?;
                    return Ok((
                        config::CurrentTargetConfig {
                            kind: "local".into(),
                            target_ref: created.environment.id,
                            name: created.environment.name,
                        },
                        None,
                    ));
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                anyhow::bail!("local VMs require Linux or macOS");
            }
            EnvironmentPlacement::Platform => {
                let created = Box::pin(environment::create_platform_environment_for_run(
                    &located, args,
                ))
                .await?;
                return Ok((
                    config::CurrentTargetConfig {
                        kind: "env".into(),
                        target_ref: created.id.clone(),
                        name: created.name.unwrap_or(created.id),
                    },
                    Some(created.org_id),
                ));
            }
        }
    }
}

fn validate_run_placement(run: &EnvironmentRunArgs, cloud: bool) -> anyhow::Result<()> {
    #[cfg(unix)]
    if cloud && run.agent.is_some() {
        sessions::agents::platform_host::validate_run_request(run)?;
    }
    Ok(())
}

pub(crate) async fn prepare_init(globals: &Globals, args: &mut InitArgs) -> anyhow::Result<bool> {
    if args.yes
        || !guided::available(OutputFormat::Text)
        || init_has_direct_yaml_inputs(args)
        || !args.repo_urls.is_empty()
        || !args.repo_flags.is_empty()
        || args.preset_slug.is_some()
        || args.preset_id.is_some()
        || args.branch.is_some()
    {
        return Ok(false);
    }
    let chosen = guided::choose(
        "Which workspace image?",
        &[
            Choice::new("Codewire workspace", "Tools for common development tasks"),
            Choice::new("Custom image", "Enter a container image reference"),
        ],
    )?;
    args.image = Some(if chosen == 0 {
        "workspace".into()
    } else {
        guided::text("Container image", None, guided::required)?
    });
    loop {
        match guided::choose(
            "Configuration settings",
            &[
                Choice::new("Review and write", ""),
                Choice::new("Resources", "CPU, memory and disk"),
                Choice::new("Install command", "Runs when creating an environment"),
                Choice::new("Startup command", "Runs when starting an environment"),
                Choice::new("Credential profile", "Explicit profile reference"),
                Choice::new("Application secrets", "Explicit project reference"),
            ],
        )? {
            0 => break,
            1 => {
                args.cpu = Some(guided::text(
                    "CPU cores",
                    args.cpu.as_deref().or(Some("2")),
                    |s| parse_resize_cpu(s).map(drop).map_err(|e| e.to_string()),
                )?);
                let memory = guided::text(
                    "Memory in MiB",
                    Some(&args.memory.unwrap_or(4096).to_string()),
                    positive_quantity,
                )?;
                args.memory = Some(memory.parse()?);
                let disk = guided::text(
                    "Disk in GiB",
                    Some(&args.disk.unwrap_or(80).to_string()),
                    positive_quantity,
                )?;
                args.disk = Some(disk.parse()?);
            }
            2 => {
                args.install = Some(guided::text(
                    "Install command",
                    args.install.as_deref(),
                    guided::required,
                )?)
            }
            3 => {
                args.startup = Some(guided::text(
                    "Startup command",
                    args.startup.as_deref(),
                    guided::required,
                )?)
            }
            4 => {
                args.profile = choose_profile(globals, false).await?;
                args.no_profile = args.profile.is_none();
            }
            _ => args.secrets = Some(choose_secret_project(globals, false).await?),
        }
    }
    Ok(true)
}

fn positive_quantity(value: &str) -> Result<(), String> {
    value
        .parse::<i32>()
        .ok()
        .filter(|v| *v > 0)
        .map(drop)
        .ok_or_else(|| "Enter a positive whole number".into())
}

pub(crate) async fn organization_for_setup(
    globals: &Globals,
    platform: &config::ResolvedPlatformConfig,
    client: &OrganizationClient,
    orgs: &[OrgWithRole],
    can_ask: bool,
) -> anyhow::Result<String> {
    match resolve_org_id(platform, orgs, globals.org.as_deref()) {
        Ok(id) => return Ok(id),
        Err(error) if !can_ask || globals.org.is_some() => return Err(error),
        Err(_) => {}
    }
    // Setup already owns explicit creation and selection; using only its
    // organization step neither signs in again nor changes the saved default.
    let Command::Setup(args) = Cli::try_parse_from(["cw", "setup"])?.command else {
        unreachable!("static setup command");
    };
    setup_select_org(client, &args)
        .await?
        .map(|org| org.id)
        .context("canceled; no organization selected")
}

pub(crate) async fn resolve_guided_platform(
    globals: &Globals,
    paths: &ResolvePaths,
    guided_flow: bool,
) -> anyhow::Result<config::ResolvedPlatformConfig> {
    match resolve_platform(globals, paths, &OsEnv) {
        Ok(platform) => Ok(platform),
        Err(error)
            if guided_flow
                && matches!(
                    error.downcast_ref::<config::ConfigError>(),
                    Some(
                        config::ConfigError::NoPlatformToken { .. }
                            | config::ConfigError::NoPlatformServer { .. }
                    )
                ) =>
        {
            if !guided::confirm("Sign in to Codewire to continue cloud setup?")? {
                anyhow::bail!("canceled; no environment created");
            }
            handle_login_command(
                globals,
                LoginArgs {
                    org: globals.org.clone(),
                    ca_file: None,
                },
            )
            .await?;
            resolve_platform(globals, paths, &OsEnv)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn review_cloud_create(
    args: &EnvCreateArgs,
    request: &CreateEnvironmentRequest,
    org_id: &str,
) -> anyhow::Result<bool> {
    if !args.guided || !guided::available(args.output) || args.yes {
        return Ok(true);
    }
    eprintln!(
        "{}",
        configuration_summary("Create a cloud environment", request)
    );
    eprintln!("  Organization  {}", progress::terminal_text(org_id));
    if request.project_spec.repositories.is_empty() {
        eprintln!("  Workspace     Empty workspace; no local files are uploaded");
    } else {
        eprintln!("  Workspace     Repository clone; local uncommitted changes are excluded");
    }
    eprintln!(
        "  Network       {}",
        progress::terminal_text(request.network.as_deref().unwrap_or("none"))
    );
    guided::confirm("Create this environment?")
}

pub(crate) fn configuration_summary(title: &str, request: &CreateEnvironmentRequest) -> String {
    let spec = &request.project_spec;
    let resources = &spec.resources;
    let cpu = resources
        .cpu_millicores
        .map(|v| format!("{} CPU", f64::from(v) / 1000.0))
        .unwrap_or_else(|| "default CPU".into());
    let memory = resources
        .memory_mib
        .map(|v| format!("{v} MiB memory"))
        .unwrap_or_else(|| "default memory".into());
    let disk = resources
        .disk_gib
        .map(|v| format!("{v} GiB disk"))
        .unwrap_or_else(|| "default disk".into());
    let mut secrets = Vec::new();
    if !spec.secrets.project.is_empty() {
        secrets.push(spec.secrets.project.clone());
    }
    if spec.secrets.organization {
        secrets.push("organization secrets".into());
    }
    if let Some(store) = spec.secrets.user {
        secrets.push(format!("{store:?} user secrets"));
    }
    let name = request
        .name
        .as_deref()
        .map(|name| format!("  Name          {}\n", progress::terminal_text(name)))
        .unwrap_or_default();
    format!(
        "{title}\n{name}  Image         {}\n  Resources     {cpu} · {memory} · {disk}\n  Credentials   {}\n  App secrets   {}",
        progress::terminal_text(if spec.image.is_empty() {
            "Resolved by Codewire"
        } else {
            &spec.image
        }),
        progress::terminal_text(
            spec.credentials
                .as_ref()
                .map(|p| p.profile.as_str())
                .unwrap_or("none")
        ),
        progress::terminal_text(
            if secrets.is_empty() {
                "none".to_owned()
            } else {
                secrets.join(", ")
            }
            .as_str()
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_run_never_asks_even_when_a_terminal_is_available() {
        let facts = crate::output::TerminalFacts {
            stdin_tty: true,
            stdout_tty: true,
            stderr_tty: true,
            columns: Some(100),
            rows: Some(24),
        };
        let caps = crate::output::Capabilities::detect(
            crate::output::OutputMode::Text,
            &facts,
            &config::MapEnv::new([("TERM", "xterm")]),
        );
        let Command::Run(args) = Cli::try_parse_from(["cw", "run", "--output", "json"])
            .unwrap()
            .command
        else {
            panic!("run");
        };
        assert!(!sessions::run_can_ask(&args, &caps));
        assert!(sessions::check_run_request(&args, sessions::run_can_ask(&args, &caps)).is_err());
        let Command::Run(args) = Cli::try_parse_from(["cw", "run"]).unwrap().command else {
            panic!("run");
        };
        assert!(sessions::run_can_ask(&args, &caps));
        // --yes never asks, even on a terminal: a bare run names what to pass.
        for argv in [vec!["cw", "run", "-y"], vec!["cw", "run", "--yes"]] {
            let Command::Run(args) = Cli::try_parse_from(argv).unwrap().command else {
                panic!("run");
            };
            assert!(!sessions::run_can_ask(&args, &caps));
            let error = sessions::check_run_request(&args, sessions::run_can_ask(&args, &caps))
                .unwrap_err()
                .to_string();
            assert!(error.contains("needs a command or an agent"), "{error}");
        }
        for argv in [
            vec!["cw", "run", "--in", "pr-42", "-y", "--", "npm", "test"],
            vec!["cw", "run", "-y", "--in", "pr-42", "--", "npm", "test"],
            vec!["cw", "run", "claude", "--in", "pr-42", "--yes"],
        ] {
            let Command::Run(args) = Cli::try_parse_from(argv.clone()).unwrap().command else {
                panic!("run");
            };
            assert!(args.yes, "{argv:?}");
            assert!(
                sessions::check_run_request(&args, false).is_ok(),
                "{argv:?}"
            );
        }
    }

    #[tokio::test]
    async fn explicit_init_inputs_and_yes_skip_the_interview() {
        for argv in [
            vec!["cw", "init", "--image", "workspace"],
            vec!["cw", "init", "--yes"],
            vec!["cw", "init", "--preset", "rust"],
        ] {
            let Command::Init(mut args) = Cli::try_parse_from(argv).unwrap().command else {
                panic!("init");
            };
            assert!(
                !prepare_init(
                    &Globals {
                        server: None,
                        member: None,
                        placement: None,
                        org: None
                    },
                    &mut args
                )
                .await
                .unwrap()
            );
        }
    }

    #[test]
    fn init_preserves_explicit_source_references_in_the_written_model() {
        let Command::Init(args) = Cli::try_parse_from([
            "cw",
            "init",
            "--image",
            "workspace",
            "--profile",
            "local:work",
            "--secrets",
            "platform:app-dev",
        ])
        .unwrap()
        .command
        else {
            panic!("init");
        };
        let request = env_create_request_from_init_args(&args).unwrap();
        assert_eq!(
            request.project_spec.credentials.unwrap().profile,
            "local:work"
        );
        assert_eq!(request.project_spec.secrets.project, "platform:app-dev");
        assert!(!init_needs_platform_resolution(&args));
    }

    #[test]
    fn review_exposes_references_and_resources_without_environment_values() {
        let mut request = CreateEnvironmentRequest {
            name: Some("demo".into()),
            ..Default::default()
        };
        request
            .project_spec
            .environment
            .insert("TOKEN".into(), "synthetic-private-value".into());
        request.project_spec.credentials = Some(codewire_project::CredentialBinding {
            profile: "platform:work".into(),
        });
        request.project_spec.secrets.project = "platform:app-dev".into();
        request.project_spec.resources.cpu_millicores = Some(2000);
        let text = configuration_summary("Review", &request);
        assert!(text.contains("platform:work"));
        assert!(text.contains("platform:app-dev"));
        assert!(text.contains("2 CPU"));
        assert!(!text.contains("synthetic-private-value"));
    }

    #[test]
    fn environment_names_reject_empty_paths_control_characters_and_oversize() {
        for name in ["", "../app", "a\n", "-app", &"a".repeat(64)] {
            assert!(environment_name(name).is_err(), "{name:?}");
        }
        for name in ["app", "my-app_2.0"] {
            assert!(environment_name(name).is_ok());
        }
    }
}
