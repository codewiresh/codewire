use super::*;

/// The default workspace: the published pin at its public mirror, which local
/// environments pull anonymously and the platform resolves to Harbor.
pub(crate) const CANONICAL_WORKSPACE_IMAGE: &str = codewire_workspace_image::PUBLIC_IMAGE;

pub(crate) fn resolve_mesh(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
    mesh_url: Option<String>,
    network_id: Option<String>,
) -> anyhow::Result<config::ResolvedMeshConfig> {
    Ok(config::resolve_mesh(
        config::MeshResolveOptions {
            mesh_url,
            auth_token: None,
            network_id,
            platform_server_url: globals.server.clone(),
        },
        paths,
        env,
    )?)
}

pub(crate) fn resolve_platform(
    globals: &Globals,
    paths: &ResolvePaths,
    env: &impl config::Env,
) -> anyhow::Result<config::ResolvedPlatformConfig> {
    Ok(config::resolve_platform(
        config::PlatformResolveOptions {
            server_url: globals.server.clone(),
        },
        paths,
        env,
    )?)
}

pub(crate) fn trimmed_required<'a>(value: &'a str, label: &str) -> anyhow::Result<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("{label} must be non-empty");
    }
    Ok(value)
}

pub(crate) fn trimmed_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_string();
        (!value.is_empty()).then_some(value)
    })
}

pub(crate) fn print_platform_user(
    user: &PlatformUser,
    platform: &config::ResolvedPlatformConfig,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(user)?),
        OutputFormat::Text => print!(
            "{}",
            format_whoami_text(user, &platform.server_url, platform.default_org.as_deref())
        ),
    }
    Ok(())
}

pub(crate) fn format_whoami_text(
    user: &PlatformUser,
    server_url: &str,
    default_org: Option<&str>,
) -> String {
    let mut output = format!(
        "{:<10} {} ({})\n{:<10} {}\n",
        "User:", user.name, user.email, "Server:", server_url
    );
    if let Some(default_org) = default_org.and_then(trimmed_str) {
        output.push_str(&format!("{:<10} {}\n", "Org:", default_org));
    }
    output
}

pub(crate) fn time_ago_at(raw: &str, now: DateTime<Utc>) -> String {
    let Ok(parsed) = DateTime::parse_from_rfc3339(raw.trim()) else {
        return raw.to_string();
    };
    let seconds = now
        .signed_duration_since(parsed.with_timezone(&Utc))
        .num_seconds();
    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 60 * 60 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 24 * 60 * 60 {
        format!("{}h ago", seconds / (60 * 60))
    } else {
        format!("{}d ago", seconds / (24 * 60 * 60))
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct OrgCostReport {
    pub(crate) org: OrgWithRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) billing: Option<BillingOverview>,
}

pub(crate) async fn collect_cost_reports(
    client: &ConsoleClient,
    orgs: &[OrgWithRole],
    org_filter: Option<&str>,
) -> Vec<OrgCostReport> {
    let org_filter = org_filter.and_then(trimmed_str);
    let mut reports = Vec::new();
    for org in orgs.iter().filter(|org| cost_org_matches(org, org_filter)) {
        reports.push(OrgCostReport {
            org: org.clone(),
            billing: client.get_billing_overview(&org.id).await.ok(),
        });
    }
    reports
}

pub(crate) fn cost_org_matches(org: &OrgWithRole, org_filter: Option<&str>) -> bool {
    org_filter.is_none_or(|filter| org.slug == filter || org.id == filter)
}

pub(crate) fn print_cost_reports(
    reports: &[OrgCostReport],
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(reports)?),
        OutputFormat::Text => print!("{}", format_cost_text(reports)),
    }
    Ok(())
}

pub(crate) fn format_cost_text(reports: &[OrgCostReport]) -> String {
    let mut output = String::new();
    for report in reports {
        let org_slug = report.org.slug.as_str();
        let Some(overview) = report.billing.as_ref() else {
            output.push_str(&format!("# {org_slug} (billing unavailable)\n\n"));
            continue;
        };

        output.push_str(&format!("# {org_slug}\n\n"));
        output.push_str(&format!(
            "  {:<16} {:<12} {:<5} {:<8} {:<7} {:<10} {}\n",
            "Plan", "Status", "Seats", "$/mo", "CPU hrs", "Mem GB·hrs", "Storage GB·hrs"
        ));
        output.push_str(&format!(
            "  {:<16} {:<12} {:<5} {:<8} {:<7.1} {:<10.1} {:.1}\n",
            billing_plan_label(overview),
            overview.status,
            overview.seat_count,
            format_cents(overview.total_monthly_cost_cents),
            overview.current_month_usage.cpu_hours,
            overview.current_month_usage.memory_gb_hours,
            overview.current_month_usage.storage_gb_hours,
        ));
        output.push('\n');
        output.push_str(&format!(
            "  Included developers: {}\n",
            overview.included_devs
        ));
        output.push_str(&format!(
            "  Active subscriptions: {}\n\n",
            overview.active_subscriptions
        ));
    }
    output
}

pub(crate) fn billing_plan_label(overview: &BillingOverview) -> &str {
    trimmed_str(&overview.plan_display_name)
        .or_else(|| trimmed_str(&overview.plan))
        .unwrap_or("none")
}

pub(crate) fn format_cents(cents: i32) -> String {
    format!("${:.2}", cents as f64 / 100.0)
}

pub(crate) fn print_orgs(
    orgs: &[OrgWithRole],
    current_org: Option<&str>,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(orgs)?),
        OutputFormat::Text => print!("{}", format_org_list_text(orgs, current_org)),
    }
    Ok(())
}

pub(crate) fn format_org_list_text(orgs: &[OrgWithRole], current_org: Option<&str>) -> String {
    if orgs.is_empty() {
        return "No organizations found.\n".to_string();
    }

    let current_org = current_org.and_then(trimmed_str);
    let mut output = format!("{:<24} {:<24} ROLE\n", "NAME", "SLUG");
    for org in orgs {
        let marker = if current_org.is_some_and(|current| current == org.id.trim()) {
            " *"
        } else {
            ""
        };
        output.push_str(&format!(
            "{:<24} {:<24} {}\n",
            format!("{}{marker}", org.name),
            org.slug,
            org.role
        ));
    }
    output
}

pub(crate) fn print_org_current(org: &OrgWithRole) {
    print!("{}", format_org_current_text(org));
}

pub(crate) fn format_org_current_text(org: &OrgWithRole) -> String {
    format!(
        "{:<10} {}\n{:<10} {}\n{:<10} {}\n{:<10} {}\n",
        "Name:", org.name, "Slug:", org.slug, "ID:", org.id, "Role:", org.role
    )
}

pub(crate) fn current_org_id(
    platform: &config::ResolvedPlatformConfig,
    orgs: &[OrgWithRole],
) -> anyhow::Result<String> {
    if platform.used_config_token
        && let Some(configured_org) = platform.default_org.as_deref().and_then(trimmed_str)
    {
        return orgs
            .iter()
            .find(|org| org.id == configured_org || org.slug == configured_org)
            .map(|org| org.id.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "configured organization {configured_org:?} is not available to the authenticated user (run 'cw org set <id-or-slug>')"
                )
            });
    }

    match orgs {
        [] => anyhow::bail!("no organizations found"),
        [org] => Ok(org.id.clone()),
        _ => anyhow::bail!("no org selected (run 'cw org set <id-or-slug>')"),
    }
}

pub(crate) fn select_org<'a>(
    orgs: &'a [OrgWithRole],
    id_or_slug: Option<&str>,
) -> anyhow::Result<&'a OrgWithRole> {
    if orgs.is_empty() {
        anyhow::bail!("no organizations found");
    }

    let Some(id_or_slug) = id_or_slug.and_then(trimmed_str) else {
        if let [org] = orgs {
            return Ok(org);
        }
        anyhow::bail!("multiple organizations found; pass an ID or slug");
    };

    orgs.iter()
        .find(|org| org.id == id_or_slug || org.slug == id_or_slug)
        .ok_or_else(|| anyhow::anyhow!("organization {id_or_slug:?} not found"))
}

pub(crate) fn resolve_org_id(
    platform: &config::ResolvedPlatformConfig,
    orgs: &[OrgWithRole],
    id_or_slug: Option<&str>,
) -> anyhow::Result<String> {
    let Some(id_or_slug) = id_or_slug.and_then(trimmed_str) else {
        return current_org_id(platform, orgs);
    };

    if looks_like_org_id(id_or_slug) {
        return Ok(id_or_slug.to_string());
    }

    orgs.iter()
        .find(|org| org.id == id_or_slug || org.slug == id_or_slug)
        .map(|org| org.id.clone())
        .ok_or_else(|| anyhow::anyhow!("organization {id_or_slug:?} not found"))
}

pub(crate) fn looks_like_org_id(value: &str) -> bool {
    let value = value.trim();
    let lower = value.to_ascii_lowercase();
    is_hex_len(value, 32)
        || is_uuid_like(value)
        || lower
            .strip_prefix("org_")
            .is_some_and(|rest| !rest.is_empty() && rest.chars().all(is_org_id_char))
}

pub(crate) fn is_uuid_like(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|&idx| bytes[idx] == b'-')
        && value
            .chars()
            .enumerate()
            .all(|(idx, ch)| [8, 13, 18, 23].contains(&idx) || ch.is_ascii_hexdigit())
}

pub(crate) fn is_hex_len(value: &str, len: usize) -> bool {
    value.len() == len && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

pub(crate) fn is_org_id_char(ch: char) -> bool {
    ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-'
}

pub(crate) fn slugify(name: &str) -> String {
    let mut slug = String::new();
    let mut previous_dash = false;
    for ch in name.trim().chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            slug.push(ch);
            previous_dash = false;
        } else if !previous_dash {
            slug.push('-');
            previous_dash = true;
        }
    }
    let mut slug = slug.trim_matches('-').to_string();
    if slug.len() > 48 {
        slug.truncate(48);
        while slug.ends_with('-') {
            slug.pop();
        }
    }
    slug
}

pub(crate) fn confirm_delete(resource_type: &str, name: &str) -> anyhow::Result<()> {
    eprint!(
        "Type {:?} to confirm deletion of {resource_type} {:?}: ",
        name, name
    );
    std::io::stderr()
        .flush()
        .context("flush confirmation prompt")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("read confirmation")?;
    if input.trim() != name {
        anyhow::bail!("confirmation failed - aborting");
    }
    Ok(())
}

pub(crate) fn organization_deletion_started_message(operation_id: &str) -> String {
    format!("Organization deletion started (operation {operation_id}).")
}

pub(crate) fn organization_deletion_polling_stopped_message(operation_id: &str) -> String {
    format!(
        "Organization deletion {operation_id} is still in progress; polling stopped, but server work continues."
    )
}

pub(crate) fn prompt_confirm_default_yes(label: &str) -> anyhow::Result<bool> {
    eprint!("{label} [Y]: ");
    std::io::stderr()
        .flush()
        .context("flush confirmation prompt")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("read confirmation")?;
    let input = input.trim();
    Ok(matches!(input, "" | "Y" | "y" | "yes" | "Yes" | "YES"))
}

pub(crate) fn prompt_confirm_default_no(label: &str) -> anyhow::Result<bool> {
    eprint!("{label} [y/N]: ");
    std::io::stderr()
        .flush()
        .context("flush confirmation prompt")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("read confirmation")?;
    Ok(matches!(input.trim(), "Y" | "y" | "yes" | "Yes" | "YES"))
}

pub(crate) fn prompt_exact_confirmation(label: &str, expected: &str) -> anyhow::Result<bool> {
    eprint!("{label}");
    std::io::stderr()
        .flush()
        .context("flush confirmation prompt")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("read confirmation")?;
    Ok(input.trim() == expected)
}

pub(crate) fn prompt_default(label: &str, default: &str) -> anyhow::Result<String> {
    eprint!("{label} [{default}]: ");
    std::io::stderr().flush().context("flush prompt")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("read prompt")?;
    let input = input.trim();
    Ok(if input.is_empty() {
        default.to_string()
    } else {
        input.to_string()
    })
}

pub(crate) fn prompt_select_org(orgs: &[OrgWithRole]) -> anyhow::Result<&OrgWithRole> {
    eprintln!("Select organization:");
    for (index, org) in orgs.iter().enumerate() {
        eprintln!("  {}) {} ({})", index + 1, org.name, org.role);
    }
    let choice = prompt_text("Organization number: ")?;
    let index = choice
        .parse::<usize>()
        .ok()
        .and_then(|choice| choice.checked_sub(1))
        .ok_or_else(|| anyhow::anyhow!("invalid organization selection"))?;
    orgs.get(index)
        .ok_or_else(|| anyhow::anyhow!("invalid organization selection"))
}

pub(crate) fn stdin_is_interactive() -> bool {
    std::io::stdin().is_terminal()
}

pub(crate) fn prompt_text(label: &str) -> anyhow::Result<String> {
    eprint!("{label}");
    std::io::stderr().flush().context("flush prompt")?;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("read prompt")?;
    Ok(input.trim().to_string())
}

pub(crate) struct EchoGuard {
    pub(crate) restore: bool,
}

impl EchoGuard {
    pub(crate) fn disable_if_tty() -> anyhow::Result<Self> {
        if !std::io::stdin().is_terminal() {
            return Ok(Self { restore: false });
        }
        set_stty_echo(false).context("disable terminal echo")?;
        Ok(Self { restore: true })
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        if self.restore {
            let _ = set_stty_echo(true);
            eprintln!();
        }
    }
}

pub(crate) fn set_stty_echo(enabled: bool) -> anyhow::Result<()> {
    let status = ProcessCommand::new("stty")
        .arg(if enabled { "echo" } else { "-echo" })
        .status()
        .context("run stty")?;
    if !status.success() {
        anyhow::bail!("stty failed");
    }
    Ok(())
}

pub(crate) fn format_api_key_list_text(keys: &[ApiKey]) -> String {
    let mut output = format!("{:<16} {:<24} {:<36} CREATED\n", "PREFIX", "NAME", "ID");
    for key in keys {
        let created_at = key
            .created_at
            .as_option()
            .and_then(|timestamp| DateTime::from_timestamp(timestamp.seconds, 0))
            .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
            .unwrap_or_default();
        output.push_str(&format!(
            "{:<16} {:<24} {:<36} {}\n",
            key.key_prefix, key.name, key.id, created_at
        ));
    }
    output
}

pub(crate) fn print_secret_project_list(
    projects: &[SecretProject],
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(projects)?),
        OutputFormat::Text => print!("{}", format_secret_project_list_text(projects)),
    }
    Ok(())
}

pub(crate) fn print_secret_metadata_list(
    secrets: &[SecretMetadata],
    empty_message: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(secrets)?),
        OutputFormat::Text => print!(
            "{}",
            format_secret_metadata_list_text(secrets, empty_message)
        ),
    }
    Ok(())
}

pub(crate) fn format_secret_project_list_text(projects: &[SecretProject]) -> String {
    if projects.is_empty() {
        return "No secret projects found.\n".to_string();
    }

    let mut output = format!("{:<24} {:<8} CREATED\n", "NAME", "SECRETS");
    for project in projects {
        output.push_str(&format!(
            "{:<24} {:<8} {}\n",
            project.name, project.secret_count, project.created_at
        ));
    }
    output
}

pub(crate) fn format_secret_metadata_list_text(
    secrets: &[SecretMetadata],
    empty_message: &str,
) -> String {
    if secrets.is_empty() {
        return format!("{empty_message}\n");
    }

    let mut output = format!("{:<32} {:<24} UPDATED\n", "KEY", "CREATED");
    for secret in secrets {
        output.push_str(&format!(
            "{:<32} {:<24} {}\n",
            secret.key, secret.created_at, secret.updated_at
        ));
    }
    output
}

pub(crate) fn format_preset_list_text(presets: &[Preset]) -> String {
    if presets.is_empty() {
        return "No presets found.\n".to_string();
    }

    let image_width = presets
        .iter()
        .filter_map(|preset| trimmed_str(&preset.project_spec.image))
        .map(str::len)
        .chain([40])
        .max()
        .unwrap_or(40);
    let mut output = format!(
        "{:<24} {:<12} {:<image_width$} {:<8} CPU/MEM/DISK\n",
        "NAME", "LANGUAGE", "IMAGE", "OFFICIAL"
    );
    for preset in presets {
        let official = if preset.official { "yes" } else { "" };
        output.push_str(&format!(
            "{:<24} {:<12} {:<image_width$} {:<8} {}m/{}MB/{}GB\n",
            preset_label(preset),
            optional_label(preset.language.as_deref()),
            optional_label(trimmed_str(&preset.project_spec.image)),
            official,
            preset
                .project_spec
                .resources
                .cpu_millicores
                .map(|value| value.to_string())
                .unwrap_or_else(|| "--".to_string()),
            preset
                .project_spec
                .resources
                .memory_mib
                .map(|value| value.to_string())
                .unwrap_or_else(|| "--".to_string()),
            preset
                .project_spec
                .resources
                .disk_gib
                .map(|value| value.to_string())
                .unwrap_or_else(|| "--".to_string())
        ));
    }
    output
}

pub(crate) fn format_preset_info_text(preset: &Preset) -> String {
    let mut output = format!(
        "{:<10} {}\n{:<10} {}\n{:<10} {}\n{:<10} {}\n",
        "ID:",
        preset.id,
        "Name:",
        preset.name,
        "Slug:",
        optional_label(preset.slug.as_deref()),
        "Language:",
        optional_label(preset.language.as_deref())
    );
    if let Some(image) = trimmed_str(&preset.project_spec.image) {
        output.push_str(&format!("{:<10} {}\n", "Image:", image));
    }
    output.push_str(&format!(
        "{:<10} {}\n{:<10} {}\nCPU:      {}m\nMemory:   {}MB\nDisk:     {}GB\n",
        "Official:",
        preset.official,
        "Build:",
        preset.build_status,
        preset
            .project_spec
            .resources
            .cpu_millicores
            .map(|value| value.to_string())
            .unwrap_or_else(|| "--".to_string()),
        preset
            .project_spec
            .resources
            .memory_mib
            .map(|value| value.to_string())
            .unwrap_or_else(|| "--".to_string()),
        preset
            .project_spec
            .resources
            .disk_gib
            .map(|value| value.to_string())
            .unwrap_or_else(|| "--".to_string())
    ));
    output
}

pub(crate) fn preset_label(preset: &Preset) -> &str {
    preset.slug.as_deref().and_then(trimmed_str).unwrap_or("--")
}

pub(crate) fn optional_label(value: Option<&str>) -> &str {
    value.and_then(trimmed_str).unwrap_or("--")
}

pub(crate) fn find_preset<'a>(
    presets: &'a [Preset],
    org_id: &str,
    selector: &str,
) -> anyhow::Result<Option<&'a Preset>> {
    if let Some(id) = selector.strip_prefix("id:") {
        let id = trimmed_required(id, "preset id")?;
        return Ok(presets.iter().find(|preset| preset.id == id));
    }
    let slug = selector.strip_prefix("slug:").unwrap_or(selector);
    let slug = trimmed_required(slug, "preset slug")?;
    if slug.contains(':') {
        anyhow::bail!("preset selector must be a slug, slug:<slug>, or id:<id>");
    }

    let mut organization_matches = presets.iter().filter(|preset| {
        preset.org_id.as_deref() == Some(org_id) && preset.slug.as_deref() == Some(slug)
    });
    let organization_match = organization_matches.next();
    if organization_matches.next().is_some() {
        anyhow::bail!("organization preset slug {slug:?} is ambiguous");
    }
    if organization_match.is_some() {
        return Ok(organization_match);
    }

    let mut official_matches = presets.iter().filter(|preset| {
        preset.official && preset.org_id.is_none() && preset.slug.as_deref() == Some(slug)
    });
    let official_match = official_matches.next();
    if official_matches.next().is_some() {
        anyhow::bail!("official preset slug {slug:?} is ambiguous");
    }
    Ok(official_match)
}

pub(crate) fn positive_i32(value: Option<i32>) -> Option<i32> {
    value.filter(|value| *value > 0)
}

pub(crate) fn expand_image_ref(image: &str) -> String {
    if image == "workspace" {
        return CANONICAL_WORKSPACE_IMAGE.to_string();
    }
    let (name, tag) = match image.split_once(':') {
        Some((name, tag)) => (name, Some(tag)),
        None => (image, None),
    };

    let mut reference = if let Some((first, _)) = name.split_once('/') {
        if first.contains('.') || first.contains(':') {
            return image.to_string();
        }
        format!("docker.io/{name}")
    } else if matches!(name, "base" | "workspace") {
        format!("ghcr.io/codewiresh/{name}")
    } else {
        format!("docker.io/library/{name}")
    };
    reference.push(':');
    reference.push_str(tag.unwrap_or("latest"));
    reference
}

pub(crate) fn parse_go_duration_seconds(raw: &str) -> anyhow::Result<i32> {
    let raw = trimmed_required(raw, "duration")?;
    let mut rest = raw;
    let sign = if let Some(stripped) = rest.strip_prefix('-') {
        rest = stripped;
        -1.0
    } else if let Some(stripped) = rest.strip_prefix('+') {
        rest = stripped;
        1.0
    } else {
        1.0
    };
    if rest.is_empty() {
        anyhow::bail!("missing duration");
    }

    let mut total = 0.0_f64;
    let mut parsed_any = false;
    while !rest.is_empty() {
        let number_len = rest
            .char_indices()
            .take_while(|(_, ch)| ch.is_ascii_digit() || *ch == '.')
            .map(|(idx, ch)| idx + ch.len_utf8())
            .last()
            .unwrap_or(0);
        if number_len == 0 {
            anyhow::bail!("missing duration number");
        }
        let number: f64 = rest[..number_len].parse()?;
        rest = &rest[number_len..];
        let (multiplier, next) = if let Some(next) = rest.strip_prefix("ms") {
            (0.001, next)
        } else if let Some(next) = rest.strip_prefix("us") {
            (0.000_001, next)
        } else if let Some(next) = rest.strip_prefix("ns") {
            (0.000_000_001, next)
        } else if let Some(next) = rest.strip_prefix('h') {
            (3600.0, next)
        } else if let Some(next) = rest.strip_prefix('m') {
            (60.0, next)
        } else if let Some(next) = rest.strip_prefix('s') {
            (1.0, next)
        } else {
            anyhow::bail!("missing or invalid duration unit");
        };
        total += number * multiplier;
        rest = next;
        parsed_any = true;
    }

    if !parsed_any || !total.is_finite() {
        anyhow::bail!("invalid duration");
    }
    let seconds = (total * sign).trunc();
    if seconds < f64::from(i32::MIN) || seconds > f64::from(i32::MAX) {
        anyhow::bail!("duration out of range");
    }
    Ok(seconds as i32)
}

pub(crate) fn parse_env_overrides(entries: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    for entry in entries {
        let entry = trimmed_required(entry, "environment override")?;
        let Some((key, value)) = entry.split_once('=') else {
            anyhow::bail!("environment override must be KEY=VALUE");
        };
        let key = trimmed_required(key, "environment override key")?;
        env.insert(key.to_string(), value.to_string());
    }
    Ok(env)
}

pub(crate) fn trimmed_str(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

pub(crate) fn save_redeemed_node_enrollment(
    data_dir: &std::path::Path,
    redeemed: &RedeemedNodeEnrollment,
) -> anyhow::Result<()> {
    config::save_node_registration(data_dir, &redeemed.network_id, &redeemed.node_name)?;
    Ok(())
}

pub(crate) fn nodes_have_multiple_networks(nodes: &[Node]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    for node in nodes {
        let network = node.network_id.trim();
        if network.is_empty() {
            continue;
        }
        seen.insert(network);
        if seen.len() > 1 {
            return true;
        }
    }
    false
}
