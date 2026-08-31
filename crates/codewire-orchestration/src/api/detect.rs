//! Smart-create repository detection.
//!
//! Same pipeline as Go: parse the repo URL, fetch repo context from the
//! forge API (tree + README + known config files + first CI workflow),
//! then either honor an in-repo `codewire.yaml` or ask Claude Haiku for
//! a structured `analyze_repo` tool call, followed by deterministic
//! fixups (multi-language → monorepo, compose-port extraction).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::worker::github::{GitHubAppConfig, get_github_token_for_user};
use crate::worker::secrets::SecretStore;

use super::create::{AppPort, RepoEntry, SetupAgent};

/// Mirrors `api.DetectionResult` field-for-field.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct DetectionResult {
    #[serde(default)]
    pub project_type: String,
    #[serde(default)]
    pub preset_slug: String,
    #[serde(default)]
    pub preset_image: String,
    #[serde(default)]
    pub install_command: String,
    #[serde(default)]
    pub startup_script: String,
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub framework: String,
    #[serde(default)]
    pub suggested_name: String,
    #[serde(default)]
    pub needs_docker: bool,
    #[serde(default)]
    pub has_compose: bool,
    #[serde(default)]
    pub app_ports: Vec<AppPort>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<SetupAgent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_agents: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_project: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_org_secrets: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_user_secrets: Option<bool>,
    #[serde(default)]
    pub cpu: String,
    #[serde(default)]
    pub memory: String,
    #[serde(default)]
    pub setup_notes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<serde_json::Value>")]
    pub project_spec: Option<codewire_project::ProjectSpec>,
}

/// Mirrors `api.MultiRepoDetectionResult`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MultiRepoDetectionResult {
    #[serde(flatten)]
    pub detection: DetectionResult,
    #[serde(default)]
    pub repos: Vec<RepoRoleResult>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoRoleResult {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub install_command: String,
    #[serde(default)]
    pub startup_command: String,
    #[serde(default)]
    pub app_ports: Vec<AppPort>,
}

pub const DEFAULT_DETECTION_PRESET_SLUG: &str = "workspace";
pub const DEFAULT_DETECTION_PRESET_IMAGE: &str = "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467";

// ── Repo URL parsing ─────────────────────────────────────────────────

/// Mirrors `api.repoRef`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRef {
    pub host: String,
    pub owner: String,
    pub repo: String,
}

impl RepoRef {
    pub fn is_github(&self) -> bool {
        self.host == "github.com"
    }

    pub fn api_url(&self, path: &str) -> String {
        if self.is_github() {
            format!("https://api.github.com{path}")
        } else {
            format!("https://{}/api/v1{path}", self.host)
        }
    }
}

/// Mirrors `parseRepoURL` (SSH `git@host:owner/repo` plus https forms;
/// bare `owner/repo` paths default to github.com).
pub fn parse_repo_url(raw_url: &str) -> anyhow::Result<RepoRef> {
    let raw_url = raw_url.strip_suffix(".git").unwrap_or(raw_url);

    if let Some(rest) = raw_url.strip_prefix("git@") {
        let (host, path) = rest
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("invalid SSH URL"))?;
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        if parts.len() < 2 {
            anyhow::bail!("invalid SSH URL path");
        }
        return Ok(RepoRef {
            host: host.to_string(),
            owner: parts[0].to_string(),
            repo: parts[1].to_string(),
        });
    }

    // Go's url.Parse accepts scheme-less inputs (host ends up empty and
    // the whole string becomes the path); mirror that fallback.
    let (host, path) = match url::Url::parse(raw_url) {
        Ok(u) if u.has_host() => (
            u.host_str().unwrap_or_default().to_string(),
            u.path().to_string(),
        ),
        _ => (String::new(), raw_url.to_string()),
    };

    let parts: Vec<String> = path
        .trim_matches('/')
        .split('/')
        .map(str::to_string)
        .collect();
    if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
        anyhow::bail!("URL must contain owner/repo");
    }

    let host = if host.is_empty() {
        "github.com".to_string()
    } else {
        host
    };
    Ok(RepoRef {
        host,
        owner: parts[0].clone(),
        repo: parts[1].clone(),
    })
}

// ── Forge API ────────────────────────────────────────────────────────

/// Mirrors `api.repoContext`. BTreeMap keeps prompt assembly
/// deterministic (Go map iteration is random; the LLM doesn't care,
/// and stable ordering makes the Rust side testable).
#[derive(Debug, Default, Clone)]
pub struct RepoContext {
    pub file_tree: String,
    pub readme: String,
    pub config_files: BTreeMap<String, String>,
}

/// Mirrors `configFileNames`.
const CONFIG_FILE_NAMES: &[&str] = &[
    "codewire.yaml",
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "go.mod",
    "Cargo.toml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    ".devcontainer/devcontainer.json",
    "Makefile",
    "Gemfile",
    "pom.xml",
    "build.gradle",
    "Dockerfile",
];

const FORGE_USER_AGENT: &str = "codewire-orchestration";

fn forge_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?)
}

fn forge_request(client: &reqwest::Client, url: &str) -> reqwest::RequestBuilder {
    // GitHub rejects REST requests without a User-Agent. Go supplied one
    // implicitly; reqwest does not, so make the parity requirement explicit.
    client
        .get(url)
        .header(reqwest::header::USER_AGENT, FORGE_USER_AGENT)
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Byte-truncation mirroring Go's `s[:n] + suffix` slicing.
fn truncate_with(s: String, max_len: usize, suffix: &str) -> String {
    if s.len() > max_len {
        let mut cut = max_len;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}{}", &s[..cut], suffix)
    } else {
        s
    }
}

async fn forge_get(client: &reqwest::Client, url: &str, token: &str) -> anyhow::Result<Vec<u8>> {
    let mut req = forge_request(client, url).header("Accept", "application/json");
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().await?;
    let status = resp.status();
    let body = resp.bytes().await?;
    if status.as_u16() >= 400 {
        anyhow::bail!(
            "forge API returned {}: {}",
            status.as_u16(),
            truncate_str(&String::from_utf8_lossy(&body), 200)
        );
    }
    Ok(body.to_vec())
}

async fn forge_get_file_content(
    client: &reqwest::Client,
    r: &RepoRef,
    file_path: &str,
    branch_ref: &str,
    token: &str,
) -> anyhow::Result<String> {
    let mut api_url = r.api_url(&format!(
        "/repos/{}/{}/contents/{}",
        r.owner, r.repo, file_path
    ));
    if !branch_ref.is_empty() && branch_ref != "HEAD" {
        api_url.push_str(&format!("?ref={branch_ref}"));
    }
    let data = forge_get(client, &api_url, token).await?;

    #[derive(Deserialize)]
    struct FileResp {
        #[serde(default)]
        content: String,
        #[serde(default)]
        encoding: String,
    }
    let file: FileResp = serde_json::from_slice(&data)?;
    if file.encoding == "base64" {
        use base64::Engine;
        let cleaned = file.content.replace('\n', "");
        let decoded = base64::engine::general_purpose::STANDARD.decode(cleaned)?;
        return Ok(String::from_utf8_lossy(&decoded).into_owned());
    }
    Ok(file.content)
}

/// Mirrors `fetchRepoContext`: tree (≤2 levels) + README (3000 chars) +
/// known config files (2000 chars each) + the first CI workflow file.
pub async fn fetch_repo_context(
    r: &RepoRef,
    branch: &str,
    token: &str,
) -> anyhow::Result<RepoContext> {
    let client = forge_client()?;

    let branch_ref = if branch.is_empty() { "HEAD" } else { branch };
    let tree_raw = forge_get(
        &client,
        &r.api_url(&format!(
            "/repos/{}/{}/git/trees/{}?recursive=1",
            r.owner, r.repo, branch_ref
        )),
        token,
    )
    .await
    .map_err(|e| anyhow::anyhow!("fetch tree: {e}"))?;

    #[derive(Deserialize)]
    struct TreeResp {
        #[serde(default)]
        tree: Vec<TreeItem>,
    }
    #[derive(Deserialize)]
    struct TreeItem {
        #[serde(default)]
        path: String,
        #[serde(default, rename = "type")]
        item_type: String,
    }
    let tree: TreeResp =
        serde_json::from_slice(&tree_raw).map_err(|e| anyhow::anyhow!("parse tree: {e}"))?;

    let mut rc = RepoContext::default();
    let mut tree_paths = Vec::new();
    for item in &tree.tree {
        let depth = item.path.matches('/').count();
        if depth <= 2 {
            let prefix = if item.item_type == "tree" {
                "  📁 "
            } else {
                "  📄 "
            };
            tree_paths.push(format!("{prefix}{}", item.path));
        }
    }
    rc.file_tree = tree_paths.join("\n");

    if let Ok(readme) = forge_get_file_content(&client, r, "README.md", branch_ref, token).await {
        rc.readme = truncate_with(readme, 3000, "\n... (truncated)");
    }

    for name in CONFIG_FILE_NAMES {
        if let Ok(content) = forge_get_file_content(&client, r, name, branch_ref, token).await {
            rc.config_files.insert(
                name.to_string(),
                truncate_with(content, 2000, "\n... (truncated)"),
            );
        }
    }

    // First CI workflow file (ground-truth build/test commands).
    for item in &tree.tree {
        if item.item_type == "blob"
            && (item.path.starts_with(".github/workflows/")
                || item.path.starts_with(".gitea/workflows/"))
            && (item.path.ends_with(".yml") || item.path.ends_with(".yaml"))
        {
            if let Ok(content) =
                forge_get_file_content(&client, r, &item.path, branch_ref, token).await
            {
                rc.config_files.insert(
                    item.path.clone(),
                    truncate_with(content, 1000, "\n... (truncated)"),
                );
            }
            break;
        }
    }

    Ok(rc)
}

// ── Claude API ───────────────────────────────────────────────────────

/// Mirrors `callClaudeDetect`: Claude Haiku with a forced
/// `analyze_repo` tool call (model + prompt pinned to the Go bytes).
pub async fn call_claude_detect(
    api_key: &str,
    owner: &str,
    repo: &str,
    rc: &RepoContext,
) -> anyhow::Result<DetectionResult> {
    let mut suggested_name = repo.to_string();
    if suggested_name.len() > 32 {
        suggested_name.truncate(32);
    }

    let mut config_section = String::new();
    for (name, content) in &rc.config_files {
        config_section.push_str(&format!("\n--- {name} ---\n{content}\n"));
    }

    let prompt = format!(
        r#"ONLY output information that has direct evidence in the files above. If a field has no evidence, leave it empty or use the default.

Repository: {owner}/{repo}

## File Tree (top 2 levels)
{file_tree}

## README (first 3000 chars)
{readme}

## Config Files
{config_section}

Analyze this repository and call the analyze_repo tool.

## Step 1: Classify project_type
Look at the file tree and config files to determine what this project IS:
- "cli" — command-line tool (main.go with cobra/urfave, setup.py with console_scripts, bin/ scripts)
- "lib" — importable package with no main entrypoint
- "web" — serves HTML/UI (nextjs, react, vue, svelte, django templates)
- "api" — HTTP/gRPC server without UI
- "monorepo" — multiple independent packages/services

## Step 2: preset_slug + preset_image
Image selection is NOT repo-dependent in this system. Always return:
- preset_slug: "workspace"
- preset_image: "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467"

Do not make per-language image decisions. Focus your analysis effort on install_command, startup_script, and app_ports.

## Step 3: install_command
Deterministic from config files:
- Node.js with bun.lockb → "bun install"
- Node.js with pnpm-lock.yaml → "pnpm install"
- Node.js with yarn.lock → "yarn install"
- Node.js default → "npm install"
- Python with requirements.txt → "pip install -r requirements.txt"
- Python with pyproject.toml → "pip install -e ."
- Go → "go mod download"
- Rust → "cargo build"
- Ruby → "bundle install"
- Empty string if no dependencies

## Step 4: startup_script
This is the most important field. ONLY include commands with direct evidence in the config files (e.g. a "prisma generate" script in package.json, a "migrate" make target).
- Prefer the smallest startup/bootstrap script that gets the project ready to run in development.
- Do NOT invent migrations, seed commands, or build steps that are not explicitly referenced.
- Empty string if nothing is evidenced.

## Step 5: app_ports
Ports the APPLICATION exposes for the user to access.
- ONLY user-facing ports (web server, API, dashboard, docs).
- DO NOT include infrastructure from docker-compose (databases, caches, proxies, internal sidecars).
- Each needs a DNS-safe label (e.g., "web", "api", "docs").
- Empty array if no user-facing ports (CLIs, libraries).

## Step 6: Other fields
- language: primary language
- framework: primary framework, or empty string if none
- needs_docker: true only if Dockerfile or compose file exists
- has_compose: true only if docker-compose.yml/yaml or compose.yml/yaml exists in config files
- cpu: "2" for cli/lib, "4" for most projects, "8" for monorepos or heavy builds
- memory: "4" for cli/lib, "8" for most projects, "16" for monorepos
- setup_notes: one sentence describing what the project is"#,
        file_tree = rc.file_tree,
        readme = rc.readme,
    );

    let tool_def = serde_json::json!({
        "name": "analyze_repo",
        "description": "Provide structured analysis of a repository for workspace configuration. Only include fields with direct evidence from the repo files.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_type": {"type": "string", "enum": ["cli", "lib", "web", "api", "monorepo"], "description": "What this project IS based on its structure and entrypoints"},
                "preset_slug": {"type": "string", "description": "Always return full"},
                "preset_image": {"type": "string", "description": "Always return ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467"},
                "install_command": {"type": "string", "description": "Dependency install command"},
                "startup_script": {"type": "string", "description": "Post-install bash script. Empty string if no evidence of required setup steps."},
                "language": {"type": "string", "description": "Primary language"},
                "framework": {"type": "string", "description": "Primary framework, or empty string if none"},
                "needs_docker": {"type": "boolean", "description": "Whether Dockerfile or compose file exists in the repo"},
                "has_compose": {"type": "boolean", "description": "Whether docker-compose.yml/yaml or compose.yml/yaml exists"},
                "app_ports": {
                    "type": "array",
                    "description": "User-facing application ports (web, API, docs). NOT infrastructure (databases, caches). Empty for CLIs/libraries.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "port": {"type": "integer", "description": "Port number"},
                            "label": {"type": "string", "description": "DNS-safe label (e.g. web, api, docs)"},
                            "access": {"type": "string", "enum": ["creator", "org_members", "public"], "description": "Access level: creator (default), org_members, or public"}
                        },
                        "required": ["port", "label"]
                    }
                },
                "cpu": {"type": "string", "description": "Recommended CPU cores: 2, 4, 8, or 16"},
                "memory": {"type": "string", "description": "Recommended memory GB: 4, 8, 16, or 32"},
                "setup_notes": {"type": "string", "description": "One sentence describing what the project is"}
            },
            "required": ["project_type", "preset_slug", "preset_image", "install_command", "language", "needs_docker", "has_compose", "cpu", "memory", "setup_notes"]
        }
    });

    let request_body = serde_json::json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 1024,
        "tools": [tool_def],
        "tool_choice": {"type": "tool", "name": "analyze_repo"},
        "messages": [{"role": "user", "content": prompt}],
    });

    let input = call_claude_tool(api_key, &request_body, "analyze_repo", 60).await?;
    let mut result =
        unmarshal_detection_result(&input).map_err(|e| anyhow::anyhow!("parse tool input: {e}"))?;
    tracing::info!(
        project_type = result.project_type,
        preset_slug = result.preset_slug,
        preset_image = result.preset_image,
        language = result.language,
        "detect: result"
    );
    result.suggested_name = suggested_name;
    Ok(result)
}

/// Mirrors `callClaudeDetectMultiRepo`.
pub async fn call_claude_detect_multi_repo(
    api_key: &str,
    entries: &[RepoContextEntry],
) -> anyhow::Result<MultiRepoDetectionResult> {
    let mut repo_sections = String::new();
    for (i, e) in entries.iter().enumerate() {
        let (Some(r), Some(c)) = (&e.reference, &e.context) else {
            continue;
        };
        repo_sections.push_str(&format!(
            "\n## Repository {}: {}/{} ({})\n",
            i + 1,
            r.owner,
            r.repo,
            e.url
        ));
        repo_sections.push_str(&format!("\n### File Tree\n{}\n", c.file_tree));
        if !c.readme.is_empty() {
            repo_sections.push_str(&format!("\n### README (first 3000 chars)\n{}\n", c.readme));
        }
        for (name, content) in &c.config_files {
            repo_sections.push_str(&format!("\n### {name}\n{content}\n"));
        }
    }

    let mut repo_list = String::new();
    for (i, e) in entries.iter().enumerate() {
        if e.context.is_none() {
            continue;
        }
        repo_list.push_str(&format!("  {}. {}\n", i + 1, e.url));
    }

    let prompt = format!(
        r#"ONLY output information that has direct evidence in the files above. If a field has no evidence, leave it empty or use the default.

This is a MULTI-REPO workspace containing these repositories:
{repo_list}
{repo_sections}

Analyze ALL repositories together and call the analyze_multi_repo tool.

## Step 1: Classify each repo's role
For each repo, determine its role:
- "main" — primary application (web app, API server, CLI)
- "lib" — shared library or package used by other repos
- "service" — supporting microservice
- "config" — infrastructure/deployment configuration
- "docs" — documentation

## Step 2: Determine workspace-level config
Based on ALL repos together:
- project_type: use "monorepo" for multi-repo workspaces
- preset_slug / preset_image: this is fixed for repo detection, always use slug "workspace", image "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467"
- language: primary language across all repos
- framework: primary framework, or empty if mixed/none

## Step 3: Per-repo install and startup commands
For each repo, provide:
- install_command: the dependency install command for that repo
- startup_command: the startup/dev command for that repo (e.g. "npm run dev", "go run .", empty if lib/docs)

## Step 4: Workspace-level install_command
Compose a single install_command that runs all per-repo installs in dependency order:
- Libraries first, then services, then main app
- Format: cd /workspace/<repo-name> && <install> && cd /workspace/<repo-name2> && <install2>

## Step 5: Workspace-level startup_script
This is the most important field. Compose the smallest repo-evidenced startup/bootstrap script that starts all services/apps in the right order. Do not invent extra setup beyond commands supported by the repo files.

## Step 6: app_ports
Collect all user-facing ports from all repos. If two repos expose the same port, prefix the label with the repo name.

## Step 7: Other fields
- needs_docker: true if ANY repo has Dockerfile or compose
- has_compose: true if ANY repo has docker-compose/compose yaml
- cpu: "4" for 2 repos, "8" for 3+ repos
- memory: "8" for 2 repos, "16" for 3+ repos
- setup_notes: one sentence describing the workspace
- suggested_name: based on the main repo name"#,
    );

    let port_item_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "port": {"type": "integer", "description": "Port number"},
            "label": {"type": "string", "description": "DNS-safe label"},
            "access": {"type": "string", "enum": ["creator", "org_members", "public"]}
        },
        "required": ["port", "label"]
    });

    let repo_item_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Repository URL"},
            "role": {"type": "string", "enum": ["main", "lib", "service", "config", "docs"], "description": "Role of this repo in the workspace"},
            "install_command": {"type": "string", "description": "Install command for this repo"},
            "startup_command": {"type": "string", "description": "Startup/dev command for this repo (empty for libs/docs)"},
            "app_ports": {"type": "array", "items": port_item_schema}
        },
        "required": ["url", "role"]
    });

    let tool_def = serde_json::json!({
        "name": "analyze_multi_repo",
        "description": "Provide structured analysis of a multi-repo workspace. Only include fields with direct evidence from the repo files.",
        "input_schema": {
            "type": "object",
            "properties": {
                "project_type": {"type": "string", "enum": ["cli", "lib", "web", "api", "monorepo"], "description": "Workspace type based on combined repos"},
                "preset_slug": {"type": "string", "description": "Always return full"},
                "preset_image": {"type": "string", "description": "Always return ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467"},
                "install_command": {"type": "string", "description": "Combined install command (all repos, dependency order)"},
                "startup_script": {"type": "string", "description": "Combined startup script (all repos, correct order)"},
                "language": {"type": "string", "description": "Primary language across all repos"},
                "framework": {"type": "string", "description": "Primary framework, or empty"},
                "suggested_name": {"type": "string", "description": "Workspace name based on main repo"},
                "needs_docker": {"type": "boolean", "description": "Whether any repo has Dockerfile or compose"},
                "has_compose": {"type": "boolean", "description": "Whether any repo has docker-compose/compose yaml"},
                "app_ports": {"type": "array", "items": port_item_schema},
                "cpu": {"type": "string", "description": "Recommended CPU cores"},
                "memory": {"type": "string", "description": "Recommended memory GB"},
                "setup_notes": {"type": "string", "description": "One sentence describing the workspace"},
                "repos": {"type": "array", "description": "Per-repo analysis with roles and commands", "items": repo_item_schema}
            },
            "required": ["project_type", "preset_slug", "preset_image", "install_command", "language", "needs_docker", "has_compose", "cpu", "memory", "setup_notes", "repos"]
        }
    });

    let request_body = serde_json::json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 2048,
        "tools": [tool_def],
        "tool_choice": {"type": "tool", "name": "analyze_multi_repo"},
        "messages": [{"role": "user", "content": prompt}],
    });

    let input = call_claude_tool(api_key, &request_body, "analyze_multi_repo", 90).await?;
    let result: MultiRepoDetectionResult = match serde_json::from_value(input.clone()) {
        Ok(r) => r,
        Err(e) => {
            // Same fixup as Go: app_ports sometimes arrives as a string.
            let fixed = fix_app_ports_string(input)
                .ok_or_else(|| anyhow::anyhow!("parse tool input: {e}"))?;
            serde_json::from_value(fixed)
                .map_err(|e2| anyhow::anyhow!("parse tool input after fixup: {e2}"))?
        }
    };
    tracing::info!(
        project_type = result.detection.project_type,
        repos = result.repos.len(),
        "detect: multi-repo result"
    );
    Ok(result)
}

/// Shared Claude messages-API call returning the named tool's input.
async fn call_claude_tool(
    api_key: &str,
    request_body: &serde_json::Value,
    tool_name: &str,
    timeout_secs: u64,
) -> anyhow::Result<serde_json::Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()?;
    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("Content-Type", "application/json")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(request_body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("claude API: {e}"))?;

    let status = resp.status();
    let body = resp.bytes().await?;
    if status.as_u16() >= 400 {
        anyhow::bail!(
            "claude API returned {}: {}",
            status.as_u16(),
            truncate_str(&String::from_utf8_lossy(&body), 200)
        );
    }

    #[derive(Deserialize)]
    struct ClaudeResp {
        #[serde(default)]
        content: Vec<ContentBlock>,
    }
    #[derive(Deserialize)]
    struct ContentBlock {
        #[serde(default, rename = "type")]
        block_type: String,
        #[serde(default)]
        name: String,
        #[serde(default)]
        input: serde_json::Value,
    }
    let parsed: ClaudeResp =
        serde_json::from_slice(&body).map_err(|e| anyhow::anyhow!("parse claude response: {e}"))?;
    for block in parsed.content {
        if block.block_type == "tool_use" && block.name == tool_name {
            return Ok(block.input);
        }
    }
    anyhow::bail!("no tool_use response from Claude")
}

/// Mirrors `unmarshalDetectionResult`: LLMs sometimes return app_ports
/// as a string — replace with [] and retry.
pub fn unmarshal_detection_result(input: &serde_json::Value) -> anyhow::Result<DetectionResult> {
    if let Ok(r) = serde_json::from_value::<DetectionResult>(input.clone()) {
        return Ok(r);
    }
    let fixed = fix_app_ports_string(input.clone())
        .ok_or_else(|| anyhow::anyhow!("detection result is not an object"))?;
    Ok(serde_json::from_value(fixed)?)
}

fn fix_app_ports_string(mut input: serde_json::Value) -> Option<serde_json::Value> {
    let obj = input.as_object_mut()?;
    if let Some(v) = obj.get("app_ports")
        && v.is_string()
    {
        obj.insert("app_ports".to_string(), serde_json::json!([]));
    }
    Some(input)
}

// ── Deterministic fixups ─────────────────────────────────────────────

/// Mirrors `applyDetectionWorkspaceDefaults`.
pub fn apply_detection_workspace_defaults(r: &mut DetectionResult) {
    r.preset_slug = DEFAULT_DETECTION_PRESET_SLUG.to_string();
    r.preset_image = DEFAULT_DETECTION_PRESET_IMAGE.to_string();
}

/// Mirrors `fixupDetectionResult` (multi-language → monorepo;
/// compose-port extraction for empty app_ports).
pub fn fixup_detection_result(r: &mut DetectionResult, rc: &RepoContext) {
    apply_detection_workspace_defaults(r);

    let has_package_json = rc.config_files.contains_key("package.json");
    let has_go_mod = rc.config_files.contains_key("go.mod");
    let has_py = rc.config_files.contains_key("requirements.txt")
        || rc.config_files.contains_key("pyproject.toml");
    let has_cargo = rc.config_files.contains_key("Cargo.toml");
    let tree_has_go = rc.file_tree.contains("go.mod") || rc.file_tree.contains("apps/api");
    let tree_has_node = rc.file_tree.contains("package.json");

    let mut langs = 0;
    if has_package_json || tree_has_node {
        langs += 1;
    }
    if has_go_mod || tree_has_go {
        langs += 1;
    }
    if has_py {
        langs += 1;
    }
    if has_cargo {
        langs += 1;
    }
    if langs >= 2 && r.project_type != "monorepo" {
        tracing::info!(
            langs,
            was = r.project_type,
            "detect: fixup — multi-language repo, classifying as monorepo"
        );
        r.project_type = "monorepo".to_string();
    }

    if r.app_ports.is_empty() && r.project_type != "cli" && r.project_type != "lib" {
        for name in [
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ] {
            if let Some(content) = rc.config_files.get(name) {
                let ports = parse_compose_ports(content);
                if !ports.is_empty() {
                    tracing::info!(?ports, "detect: fixup — extracted ports from compose");
                    r.app_ports = ports;
                }
                break;
            }
        }
    }
}

/// Mirrors `infraPatterns`.
const INFRA_PATTERNS: &[&str] = &[
    "postgres",
    "mysql",
    "mariadb",
    "redis",
    "memcached",
    "nats",
    "rabbitmq",
    "kafka",
    "zookeeper",
    "etcd",
    "mongo",
    "minio",
    "vault",
    "consul",
    "elasticsearch",
    "prometheus",
    "grafana",
    "jaeger",
    "zipkin",
    "caddy",
    "nginx",
    "traefik",
    "haproxy",
    "envoy",
    "relay",
    "tailscale",
    "wireguard",
    "tunnel",
    "certbot",
    "letsencrypt",
];

/// Mirrors `parseComposePorts` (best-effort compose YAML parse; skips
/// infrastructure services; DNS-safe labels from service names).
/// BTreeMap ordering makes the output deterministic where Go's map
/// iteration is random — accepted drift (callers treat it as a set).
pub fn parse_compose_ports(content: &str) -> Vec<AppPort> {
    #[derive(Deserialize)]
    struct Compose {
        #[serde(default)]
        services: BTreeMap<String, ComposeService>,
    }
    #[derive(Deserialize)]
    struct ComposeService {
        #[serde(default)]
        image: String,
        // Go declares []string: a single unquoted-int port anywhere
        // fails the whole unmarshal (→ no ports). Same here.
        #[serde(default)]
        ports: Vec<String>,
    }

    let Ok(compose) = serde_yaml::from_str::<Compose>(content) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for (svc_name, svc) in &compose.services {
        let img_lower = svc.image.to_lowercase();
        let name_lower = svc_name.to_lowercase();
        if INFRA_PATTERNS
            .iter()
            .any(|p| img_lower.contains(p) || name_lower.contains(p))
        {
            continue;
        }

        for p in &svc.ports {
            let Some((host_part, _)) = p.split_once(':') else {
                continue;
            };
            let host_port = host_part.trim().trim_matches(|c| c == '"' || c == '\'');
            // Go uses Sscanf("%d") — parse the leading digits.
            let digits: String = host_port
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            let Ok(port) = digits.parse::<i32>() else {
                continue;
            };
            if port > 0 {
                let label: String = name_lower
                    .chars()
                    .map(|r| {
                        if r.is_ascii_lowercase() || r.is_ascii_digit() || r == '-' {
                            r
                        } else {
                            '-'
                        }
                    })
                    .collect();
                out.push(AppPort {
                    port,
                    label,
                    access: "creator".to_string(),
                });
            }
        }
    }
    out
}

// ── Forge token lookup ───────────────────────────────────────────────

/// Mirrors `userSecretPath`.
pub fn user_secret_path(user_id: &str) -> String {
    format!("/users/{user_id}")
}

/// Mirrors `orgSecretPath`.
pub fn org_secret_path(org_id: &str) -> String {
    format!("/org-secrets/{org_id}")
}

/// Mirrors `forgeTokenKey`.
fn forge_token_key(host: &str) -> &'static str {
    if host == "github.com" {
        "GITHUB_TOKEN"
    } else {
        "GITEA_TOKEN"
    }
}

/// Mirrors `normalizeHostKey` (git_credential_routes.go): uppercase,
/// non-alphanumerics → `_`, prefixed `GIT_TOKEN_`.
fn normalize_host_key(host: &str) -> String {
    let mapped: String = host
        .to_uppercase()
        .chars()
        .map(|c| {
            if c.is_ascii_uppercase() || c.is_ascii_digit() {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("GIT_TOKEN_{mapped}")
}

/// Mirrors `resolveForgeToken`: GitHub OAuth DB → user_git_credentials
/// + secret store → legacy user-level secrets → org-level secrets.
pub async fn resolve_forge_token(
    pool: &PgPool,
    github_cfg: &GitHubAppConfig,
    secrets: &SecretStore,
    user_id: &str,
    host: &str,
) -> String {
    if host == "github.com" {
        let token = get_github_token_for_user(pool, github_cfg, user_id).await;
        if !token.is_empty() {
            return token;
        }
    }

    if let Some(token) = resolve_git_credential_token(pool, secrets, user_id, host).await
        && !token.is_empty()
    {
        return token;
    }

    let secret_key = forge_token_key(host);
    if let Ok(user_secrets) = secrets
        .get_all_secrets_at_path(&user_secret_path(user_id))
        .await
        && let Some(token) = user_secrets.get(secret_key)
        && !token.is_empty()
    {
        return token.clone();
    }

    find_org_forge_token(pool, secrets, user_id, secret_key).await
}

async fn resolve_git_credential_token(
    pool: &PgPool,
    secrets: &SecretStore,
    user_id: &str,
    host: &str,
) -> Option<String> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_git_credentials WHERE user_id = $1 AND host = $2)",
    )
    .bind(user_id)
    .bind(host)
    .fetch_one(pool)
    .await
    .ok()?;
    if !exists {
        return None;
    }
    let secret_key = normalize_host_key(host);
    let user_secrets = secrets
        .get_all_secrets_at_path(&user_secret_path(user_id))
        .await
        .ok()?;
    user_secrets.get(&secret_key).cloned()
}

/// Mirrors `findOrgForgeToken`.
async fn find_org_forge_token(
    pool: &PgPool,
    secrets: &SecretStore,
    user_id: &str,
    secret_key: &str,
) -> String {
    let org_ids: Vec<(String,)> = sqlx::query_as(
        r#"SELECT o.id FROM organizations o
           JOIN organization_members om ON om.organization_id = o.id
           WHERE om.user_id = $1 LIMIT 5"#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    for (org_id,) in org_ids {
        if let Ok(org_secrets) = secrets
            .get_all_secrets_at_path(&org_secret_path(&org_id))
            .await
            && let Some(token) = org_secrets.get(secret_key)
            && !token.is_empty()
        {
            return token.clone();
        }
    }
    String::new()
}

// ── Multi-repo context fan-out ───────────────────────────────────────

/// Mirrors `api.repoContextEntry`.
#[derive(Debug, Default, Clone)]
pub struct RepoContextEntry {
    pub url: String,
    pub reference: Option<RepoRef>,
    pub context: Option<RepoContext>,
    pub error: Option<String>,
}

/// Mirrors `fetchAllRepoContexts` (concurrent fetch; per-repo errors
/// recorded, not fatal).
pub async fn fetch_all_repo_contexts(
    pool: &PgPool,
    github_cfg: &GitHubAppConfig,
    secrets: &SecretStore,
    user_id: &str,
    repos: &[RepoEntry],
) -> Vec<RepoContextEntry> {
    let mut futures = Vec::new();
    for repo in repos {
        let url = repo.url.clone();
        let branch = repo.branch.clone();
        futures.push(async move {
            let mut entry = RepoContextEntry {
                url: url.clone(),
                ..Default::default()
            };
            let r = match parse_repo_url(&url) {
                Ok(r) => r,
                Err(e) => {
                    entry.error = Some(format!("parse URL: {e}"));
                    return entry;
                }
            };
            let forge_token =
                resolve_forge_token(pool, github_cfg, secrets, user_id, &r.host).await;
            match fetch_repo_context(&r, &branch, &forge_token).await {
                Ok(rc) => entry.context = Some(rc),
                Err(e) => {
                    tracing::warn!(url, error = %e, "multi-repo: failed to fetch context");
                    entry.error = Some(format!("fetch context: {e}"));
                }
            }
            entry.reference = Some(r);
            entry
        });
    }
    futures::future::join_all(futures).await
}

// ── codewire.yaml ────────────────────────────────────────────────────

/// Mirrors `slugToImage`.
fn slug_to_image(slug: &str) -> Option<&'static str> {
    match slug {
        "workspace" => Some(DEFAULT_DETECTION_PRESET_IMAGE),
        "base" => Some(DEFAULT_DETECTION_PRESET_IMAGE),
        "openclaw" => Some("ghcr.io/codewiresh/openclaw:latest"),
        _ => None,
    }
}

/// Mirrors `parseCodewireYAML` (the in-repo config short-circuit).
pub fn parse_codewire_yaml(content: &str, repo_name: &str) -> anyhow::Result<DetectionResult> {
    let document = codewire_project::parse_project_yaml(content)
        .map_err(|error| anyhow::anyhow!("parse codewire.yaml: {error}"))?;
    document
        .ensure_platform_compatible()
        .map_err(|error| anyhow::anyhow!("parse codewire.yaml: {error}"))?;
    let cfg = document.spec;

    let (slug, image) = if !cfg.image.is_empty() {
        (String::new(), cfg.image.clone())
    } else if let Some(img) = slug_to_image(&cfg.preset) {
        (cfg.preset.clone(), img.to_string())
    } else if !cfg.preset.is_empty() {
        // Treat as full image ref.
        (String::new(), cfg.preset.clone())
    } else {
        (String::new(), String::new())
    };

    let cpu_str = cfg
        .resources
        .cpu_millicores
        .map(format_cpu_cores)
        .unwrap_or_else(|| "2".to_string());
    let mem_str = cfg
        .resources
        .memory_mib
        .map(format_memory_gib)
        .unwrap_or_else(|| "4".to_string());
    let project_spec = cfg.clone();

    let mut suggested_name = repo_name.to_string();
    if suggested_name.len() > 32 {
        suggested_name.truncate(32);
    }

    Ok(DetectionResult {
        project_type: "configured".to_string(),
        preset_slug: slug,
        preset_image: image,
        install_command: cfg.install_command.clone(),
        startup_script: cfg.startup_script.clone(),
        suggested_name,
        app_ports: cfg
            .application_ports
            .into_iter()
            .map(|port| AppPort {
                port: i32::from(port.port),
                label: port.label,
                access: port.access,
            })
            .collect(),
        agents: cfg
            .agents
            .tools
            .into_iter()
            .map(|agent_type| SetupAgent { agent_type })
            .collect(),
        install_agents: cfg.agents.install,
        secret_project: cfg.secrets.project.clone(),
        include_org_secrets: cfg.secrets.include_org,
        include_user_secrets: cfg.secrets.include_user,
        cpu: cpu_str,
        memory: mem_str,
        setup_notes: "Configured via codewire.yaml".to_string(),
        project_spec: Some(project_spec),
        ..Default::default()
    })
}

fn format_cpu_cores(millicores: u32) -> String {
    if millicores.is_multiple_of(1000) {
        return (millicores / 1000).to_string();
    }
    let mut value = format!("{:.3}", f64::from(millicores) / 1000.0);
    while value.ends_with('0') {
        value.pop();
    }
    value.trim_end_matches('.').to_string()
}

fn format_memory_gib(memory_mib: u64) -> String {
    if memory_mib.is_multiple_of(1024) {
        (memory_mib / 1024).to_string()
    } else {
        format!("{memory_mib}Mi")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_url_parsing_mirrors_go() {
        let r = parse_repo_url("https://github.com/foo/bar.git").unwrap();
        assert_eq!(
            r,
            RepoRef {
                host: "github.com".into(),
                owner: "foo".into(),
                repo: "bar".into()
            }
        );
        let r = parse_repo_url("git@github.com:foo/bar.git").unwrap();
        assert_eq!(r.owner, "foo");
        assert_eq!(r.repo, "bar");
        let r = parse_repo_url("https://gitea.example.com/org/proj").unwrap();
        assert_eq!(r.host, "gitea.example.com");
        assert!(!r.is_github());
        assert_eq!(r.api_url("/x"), "https://gitea.example.com/api/v1/x");
        assert!(parse_repo_url("https://github.com/onlyowner").is_err());
    }

    #[test]
    fn forge_client_identifies_codewire_to_public_forge_apis() {
        let client = forge_client().unwrap();
        let request = forge_request(&client, "https://api.github.com/repos/codewire/codewire")
            .build()
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            Some(FORGE_USER_AGENT)
        );
    }

    #[test]
    fn compose_port_extraction_mirrors_go() {
        let compose = r#"
services:
  web:
    image: node:20
    ports:
      - "3000:3000"
  db:
    image: postgres:16
    ports:
      - "5432:5432"
  My_App:
    image: custom/thing
    ports:
      - "8080:80/tcp"
"#;
        let ports = parse_compose_ports(compose);
        // postgres filtered as infrastructure; label DNS-safety.
        assert_eq!(ports.len(), 2);
        assert!(ports.iter().any(|p| p.port == 3000 && p.label == "web"));
        assert!(ports.iter().any(|p| p.port == 8080 && p.label == "my-app"));
        assert!(ports.iter().all(|p| p.access == "creator"));
    }

    #[test]
    fn codewire_yaml_parsing_mirrors_go() {
        let yaml = r#"
preset: workspace
install: bun install
startup: bun run db:migrate
cpu: 4000
memory: 8192
ports:
  - port: 3000
    label: web
agents:
  install: true
  tools: [claude, codex]
secrets:
  org: false
  project: myproj
"#;
        let r = parse_codewire_yaml(yaml, "a-very-long-repo-name-that-exceeds-32-chars").unwrap();
        assert_eq!(r.project_type, "configured");
        assert_eq!(r.preset_slug, "workspace");
        assert_eq!(r.preset_image, DEFAULT_DETECTION_PRESET_IMAGE);
        assert_eq!(r.install_command, "bun install");
        assert_eq!(r.cpu, "4");
        assert_eq!(r.memory, "8");
        assert_eq!(r.suggested_name.len(), 32);
        assert_eq!(r.app_ports.len(), 1);
        assert_eq!(r.install_agents, Some(true));
        assert_eq!(r.agents.len(), 2);
        assert_eq!(r.agents[0].agent_type, "claude-code");
        assert_eq!(r.include_org_secrets, Some(false));
        assert_eq!(r.secret_project, "myproj");

        // Custom image ref in preset field.
        let r = parse_codewire_yaml("preset: ghcr.io/x/y:1\n", "repo").unwrap();
        assert_eq!(r.preset_slug, "");
        assert_eq!(r.preset_image, "ghcr.io/x/y:1");

        // Scalar agent + scalar secrets forms.
        let r = parse_codewire_yaml("agent: gemini\nsecrets: proj2\n", "repo").unwrap();
        assert_eq!(r.agents[0].agent_type, "gemini-cli");
        assert_eq!(r.secret_project, "proj2");

        let r = parse_codewire_yaml("agents: [kimi, pi-coding-agent]\n", "repo").unwrap();
        assert_eq!(r.agents[0].agent_type, "kimi-code");
        assert_eq!(r.agents[1].agent_type, "pi");

        // Unsupported agent errors like Go.
        assert!(parse_codewire_yaml("agent: skynet\n", "repo").is_err());
    }

    #[test]
    fn platform_detection_preserves_the_complete_canonical_project_spec() {
        let yaml = r#"
version: 1
image: ghcr.io/example/workspace@sha256:abc
repositories:
  - source: https://example.test/org/api.git
    revision: deadbeef
    destination: /workspace/api
  - source: https://example.test/org/web.git
    branch: main
    destination: /workspace/web
working_directory: /workspace/api
install: cargo fetch
startup: cargo test
env: {RUST_LOG: info}
agents: [claude, codex]
agent_env: {CODEWIRE_AGENT_MODE: test}
skills:
  - {path: .agents/skills/rust, agents: [codex]}
  - user:personal
ports: [{port: 8080, label: api, access: private}]
cpu: 2
memory: 16Gi
disk: 40Gi
secrets: {project: development, org: false, user: true}
credentials:
  work: {provider: openai, account: acct-work}
  personal: {provider: anthropic, account: acct-personal}
"#;
        let direct = codewire_project::parse_project_yaml(yaml).unwrap().spec;
        let detected = parse_codewire_yaml(yaml, "codewire").unwrap();
        let platform = detected.project_spec.expect("portable project spec");
        assert_eq!(platform, direct);
        assert_eq!(
            platform.canonical_json().unwrap(),
            direct.canonical_json().unwrap()
        );
    }

    #[test]
    fn detection_fixups_mirror_go() {
        let mut rc = RepoContext::default();
        rc.config_files.insert("package.json".into(), "{}".into());
        rc.config_files.insert("go.mod".into(), "module x".into());
        let mut r = DetectionResult {
            project_type: "web".into(),
            preset_slug: "node".into(),
            preset_image: "node:20".into(),
            ..Default::default()
        };
        fixup_detection_result(&mut r, &rc);
        assert_eq!(r.project_type, "monorepo");
        // Workspace defaults always forced.
        assert_eq!(r.preset_slug, DEFAULT_DETECTION_PRESET_SLUG);
        assert_eq!(r.preset_image, DEFAULT_DETECTION_PRESET_IMAGE);

        // Compose ports fill empty app_ports for serving projects only.
        let mut rc = RepoContext::default();
        rc.config_files.insert(
            "docker-compose.yml".into(),
            "services:\n  app:\n    image: x\n    ports:\n      - \"4000:4000\"\n".into(),
        );
        let mut r = DetectionResult {
            project_type: "api".into(),
            ..Default::default()
        };
        fixup_detection_result(&mut r, &rc);
        assert_eq!(r.app_ports.len(), 1);
        let mut r = DetectionResult {
            project_type: "cli".into(),
            ..Default::default()
        };
        fixup_detection_result(&mut r, &rc);
        assert!(r.app_ports.is_empty());
    }

    #[test]
    fn app_ports_string_fixup_mirrors_go() {
        let v = serde_json::json!({
            "project_type": "web", "preset_slug": "s", "preset_image": "i",
            "install_command": "npm install", "startup_script": "",
            "language": "ts", "framework": "", "suggested_name": "",
            "needs_docker": false, "has_compose": false,
            "app_ports": "none", "cpu": "4", "memory": "8", "setup_notes": "x"
        });
        let r = unmarshal_detection_result(&v).unwrap();
        assert!(r.app_ports.is_empty());
        assert_eq!(r.install_command, "npm install");
    }

    #[test]
    fn host_key_normalization_mirrors_go() {
        assert_eq!(
            normalize_host_key("gitea.example-host.com"),
            "GIT_TOKEN_GITEA_EXAMPLE_HOST_COM"
        );
        assert_eq!(forge_token_key("github.com"), "GITHUB_TOKEN");
        assert_eq!(forge_token_key("gitea.io"), "GITEA_TOKEN");
    }
}
