//! `cw export ENV`: write an environment's saved declarative configuration
//! as codewire.yaml.
//!
//! Export only reads. It never starts, changes or checkpoints the
//! environment, and it writes references, never values: no declared
//! environment value, resolved secret, token or credential. What the file
//! cannot carry, and what applies only to this placement, is reported after
//! the file is written.

use std::fs;
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use sha2::{Digest as _, Sha256};

use super::*;
use crate::commands::progress::terminal_text;
use crate::output::{Capabilities, OutputMode, Status, Style};

/// The file `cw create` discovers, so an export in a project folder is read
/// back by the next create there.
const DEFAULT_FILE: &str = super::project_file::PROJECT_FILE_NAME;

pub(crate) async fn handle_export(globals: &Globals, args: ExportArgs) -> anyhow::Result<()> {
    let ExportArgs {
        environment,
        in_environment,
        file,
        stdout,
        force,
    } = args;
    let environment = flat::select_environment("export", environment, in_environment, &[])?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing environment: `cw export ENV` writes that environment's saved configuration as codewire.yaml"
            )
        })?;
    let destination = match stdout {
        true => None,
        false => {
            let path = file.unwrap_or_else(|| PathBuf::from(DEFAULT_FILE));
            // Refuse before any lookup; the write refuses again atomically.
            if !force && fs::symlink_metadata(&path).is_ok() {
                return Err(existing_file(&path));
            }
            Some(path)
        }
    };
    let export = read_export(globals, &environment).await?;
    let yaml = export
        .document
        .to_yaml()
        .context("render the saved configuration as codewire.yaml")?;
    let caps = Capabilities::from_process(OutputMode::Text);
    match destination {
        None => {
            let mut out = std::io::stdout().lock();
            out.write_all(yaml.as_bytes())?;
            out.flush()?;
            eprint!("{}", render_notes(&export.notes, caps.stderr_style()));
        }
        Some(path) => {
            write_file(&path, yaml.as_bytes(), force)?;
            print!("{}", render_written(&export, &path, caps.stdout_style()));
        }
    }
    Ok(())
}

/// The document export writes and what it reports about it.
#[derive(Debug)]
pub(crate) struct Export {
    /// For the result line, for example `local VM app`.
    source: String,
    document: codewire_project::ProjectDocument,
    notes: Vec<Note>,
}

/// One reported field, in the order the report prints them.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Note {
    /// Declared environment values, by name. Their values are never read
    /// into the file.
    EnvironmentValues(Vec<String>),
    /// Host folders the local workspace mounts or copies. Their paths and
    /// `workspace.vm_only` are not part of the saved spec.
    HostFolders {
        count: u32,
        /// The working directory left out because it follows that folder.
        working_directory: Option<String>,
    },
    MeshNetwork(String),
    /// A cloud environment's confidential isolation tier.
    ConfidentialIsolation,
    /// A cloud environment's time to live, in seconds.
    Ttl(u32),
    /// Docker off (`None`) or a non-default disk, in GiB.
    DockerDisk(Option<u64>),
    /// Host port bindings, written as `host_port`/`guest_port`.
    HostPorts(Vec<(u16, u16)>),
    /// Exact references as saved, with the profile's name when known.
    References {
        profile: Option<String>,
        local: bool,
    },
}

async fn read_export(globals: &Globals, target: &str) -> anyhow::Result<Export> {
    match resolve_unified_environment_target(globals, globals.placement, target, "export").await? {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        UnifiedEnvironmentTarget::NativeLocal(name) => {
            local_export(&get_native_environment(&name).await?)
        }
        UnifiedEnvironmentTarget::Platform(id) => {
            let (org_id, _, client) = resolve_platform_context(globals).await?;
            let environment = client
                .get_environment(&org_id, &id)
                .await
                .context("get environment")?;
            let (spec, withheld) = client
                .get_environment_project_spec(&org_id, &id)
                .await
                .context("read the environment's saved configuration")?;
            cloud_export(&environment, spec, withheld)
        }
    }
}

/// A cloud environment's saved configuration, which the platform returns
/// with its declared environment values withheld, at its current size.
pub(crate) fn cloud_export(
    environment: &Environment,
    mut spec: codewire_project::ProjectSpec,
    withheld: Vec<String>,
) -> anyhow::Result<Export> {
    anyhow::ensure!(
        spec.environment.is_empty(),
        "the saved configuration carried environment values; refusing to export them"
    );
    let mut notes = Vec::new();
    if !withheld.is_empty() {
        notes.push(Note::EnvironmentValues(withheld));
    }
    let positive = |value: i32| u64::try_from(value).ok().filter(|value| *value > 0);
    spec.resources = codewire_project::ResourceSpec {
        cpu_millicores: positive(environment.cpu_millicores)
            .and_then(|value| u32::try_from(value).ok()),
        memory_mib: positive(environment.memory_mb),
        disk_gib: positive(environment.disk_gb),
    };
    if environment.isolation_tier == "confidential" {
        notes.push(Note::ConfidentialIsolation);
    }
    if let Some(ttl) = environment.ttl_seconds.filter(|ttl| *ttl > 0) {
        notes.push(Note::Ttl(ttl.unsigned_abs()));
    }
    if let Some(network) = environment
        .network
        .as_deref()
        .map(str::trim)
        .filter(|network| !network.is_empty())
    {
        notes.push(Note::MeshNetwork(format!("cloud:{network}")));
    }
    if let Some(note) = references_note(&spec, "") {
        notes.push(note);
    }
    Ok(Export {
        source: format!(
            "cloud environment {}",
            environment.name.as_deref().unwrap_or(&environment.id)
        ),
        document: codewire_project::ProjectDocument::new(
            spec,
            codewire_project::LocalProjectIntent::default(),
            true,
        ),
        notes,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const GIB: u64 = 1024 * 1024 * 1024;

/// A local VM's saved configuration: its canonical project spec, which the
/// supervisor returns only to its owner, at the VM's current size.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn local_export(
    environment: &codewire_local_vmm::control::v1::Environment,
) -> anyhow::Result<Export> {
    let mut spec = saved_local_spec(environment)?;
    let mut notes = Vec::new();

    let withheld = std::mem::take(&mut spec.environment)
        .into_keys()
        .collect::<Vec<_>>();
    if !withheld.is_empty() {
        notes.push(Note::EnvironmentValues(withheld));
    }

    spec.resources = codewire_project::ResourceSpec {
        cpu_millicores: (environment.vcpus > 0).then(|| environment.vcpus.saturating_mul(1000)),
        memory_mib: (environment.memory_mib > 0).then_some(u64::from(environment.memory_mib)),
        disk_gib: (environment.disk_bytes >= GIB).then_some(environment.disk_bytes / GIB),
    };

    // Every workspace input that is not a declared repository is a host
    // folder: the project folder mounted or copied, a declared mount, or the
    // empty folder cw keeps. Without repositories the working directory
    // follows that folder, so `cw create` derives it again.
    let host_folders = environment
        .workspace_input_count
        .saturating_sub(u32::try_from(spec.repositories.len()).unwrap_or(u32::MAX));
    let derived_working_directory =
        spec.repositories.is_empty() && spec.working_directory != "/workspace";
    if host_folders > 0 {
        notes.push(Note::HostFolders {
            count: host_folders,
            working_directory: derived_working_directory.then(|| spec.working_directory.clone()),
        });
    }

    if let Some(network) = environment
        .mesh
        .as_ref()
        .map(|mesh| mesh.network_id.trim())
        .filter(|network| !network.is_empty())
    {
        notes.push(Note::MeshNetwork(network.to_owned()));
    }
    let docker = environment.docker_disk_bytes;
    if docker != codewire_local_vmm::state::DEFAULT_DOCKER_DISK_BYTES {
        notes.push(Note::DockerDisk((docker > 0).then(|| docker.div_ceil(GIB))));
    }

    let host_ports = environment
        .host_ports
        .iter()
        .map(|binding| {
            Ok(codewire_project::HostPortBinding {
                host_port: u16::try_from(binding.host_port)
                    .context("local VM reported an invalid host port")?,
                guest_port: u16::try_from(binding.guest_port)
                    .context("local VM reported an invalid guest port")?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if !host_ports.is_empty() {
        notes.push(Note::HostPorts(
            host_ports
                .iter()
                .map(|binding| (binding.host_port, binding.guest_port))
                .collect(),
        ));
    }

    if let Some(note) = references_note(&spec, environment.access_profile.trim()) {
        notes.push(note);
    }

    Ok(Export {
        source: format!("local VM {}", environment.name),
        document: codewire_project::ProjectDocument::new(
            spec,
            codewire_project::LocalProjectIntent {
                host_ports,
                ..Default::default()
            },
            !derived_working_directory,
        ),
        notes,
    })
}

/// The supervisor's canonical spec, verified against its digest.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn saved_local_spec(
    environment: &codewire_local_vmm::control::v1::Environment,
) -> anyhow::Result<codewire_project::ProjectSpec> {
    let json = &environment.project_spec_json;
    anyhow::ensure!(
        !json.is_empty() && json.len() <= codewire_project::MAX_PROJECT_DOCUMENT_BYTES,
        "local VM {} has no saved configuration to export",
        environment.name
    );
    let spec: codewire_project::ProjectSpec = serde_json::from_slice(json).with_context(|| {
        format!(
            "local VM {}'s saved configuration is invalid",
            environment.name
        )
    })?;
    anyhow::ensure!(
        spec.canonical_json()? == *json
            && format!("{:x}", Sha256::digest(json)) == environment.project_spec_sha256,
        "local VM {}'s saved configuration does not match its digest",
        environment.name
    );
    Ok(spec)
}

/// A duration `--ttl` accepts: whole hours, minutes or seconds.
fn ttl_text(seconds: u32) -> String {
    match seconds {
        seconds if seconds % 3600 == 0 => format!("{}h", seconds / 3600),
        seconds if seconds % 60 == 0 => format!("{}m", seconds / 60),
        seconds => format!("{seconds}s"),
    }
}

fn references_note(spec: &codewire_project::ProjectSpec, profile_name: &str) -> Option<Note> {
    let profile = spec
        .credentials
        .as_ref()
        .map(|binding| binding.profile.as_str());
    let project = (!spec.secrets.project.is_empty()).then_some(spec.secrets.project.as_str());
    let local = [profile, project]
        .into_iter()
        .flatten()
        .any(|reference| reference.starts_with("local:"))
        || spec.secrets.user == Some(codewire_project::StoragePlacement::Local);
    (profile.is_some() || project.is_some() || local).then(|| Note::References {
        profile: (profile.is_some() && !profile_name.is_empty()).then(|| profile_name.to_owned()),
        local,
    })
}

fn existing_file(path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "{} already exists (use --force to overwrite)",
        terminal_text(&path.display().to_string())
    )
}

/// Write without replacing an existing file unless `force`; with `force`,
/// replace it whole, so an interrupted export never leaves half a file.
fn write_file(path: &Path, data: &[u8], force: bool) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    if !force {
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(existing_file(path));
            }
            Err(error) => {
                return Err(error).with_context(|| format!("create {}", path.display()));
            }
        };
        if let Err(error) = file.write_all(data).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(error).with_context(|| format!("write {}", path.display()));
        }
        return Ok(());
    }
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} is not a file path", path.display()))?;
    let mut staged = name.to_os_string();
    staged.push(format!(".cw-export-{}", std::process::id()));
    let staged = path.with_file_name(staged);
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&staged, path)
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&staged);
        return Err(error).with_context(|| format!("write {}", path.display()));
    }
    Ok(())
}

fn render_written(export: &Export, path: &Path, style: Style) -> String {
    format!(
        "{} Exported {} to {}\n{}",
        style.status(Status::Done),
        terminal_text(&export.source),
        terminal_text(&path.display().to_string()),
        render_notes(&export.notes, style)
    )
}

fn render_notes(notes: &[Note], style: Style) -> String {
    let dash = match style.charset() {
        crate::output::Charset::Unicode => "—",
        crate::output::Charset::Ascii => "-",
    };
    let arrow = style.glyph(Status::Next);
    notes
        .iter()
        .map(|note| {
            let text = match note {
                Note::EnvironmentValues(names) => format!(
                    "Not exported: environment values {} {dash} add them to codewire.yaml, or keep sensitive ones in a secret project",
                    names
                        .iter()
                        .map(|name| terminal_text(name))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                Note::HostFolders {
                    count,
                    working_directory,
                } => {
                    let folders = match count {
                        1 => "the local workspace's host folder (mounted, copied or empty)".to_owned(),
                        count => format!("the local workspace's {count} host folders (mounted, copied or empty)"),
                    };
                    let working_directory = working_directory
                        .as_deref()
                        .map(|path| format!(", and the working directory {} that follows it", terminal_text(path)))
                        .unwrap_or_default();
                    format!(
                        "Not exported: {folders}{working_directory} {dash} host paths stay on this machine; run `cw create` in that folder, or pass --path"
                    )
                }
                Note::ConfidentialIsolation => format!(
                    "Not exported: confidential isolation {dash} pass --isolation confidential when creating"
                ),
                Note::Ttl(seconds) => format!(
                    "Not exported: time to live {ttl} {dash} pass --ttl {ttl} when creating",
                    ttl = ttl_text(*seconds)
                ),
                Note::MeshNetwork(network) => format!(
                    "Not exported: Mesh network {} {dash} pass --network when creating",
                    terminal_text(network)
                ),
                Note::DockerDisk(None) => {
                    format!("Not exported: Docker is off {dash} pass --no-docker when creating")
                }
                Note::DockerDisk(Some(gib)) => format!(
                    "Not exported: Docker disk {gib}Gi {dash} pass --docker-disk {gib}Gi when creating"
                ),
                Note::HostPorts(bindings) => format!(
                    "Local only: ports {} use host_port {dash} for a cloud environment, write `port: {}` instead",
                    bindings
                        .iter()
                        .map(|(host, guest)| format!("127.0.0.1:{host} {arrow} {guest}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    bindings.first().map(|(_, guest)| *guest).unwrap_or_default()
                ),
                Note::References { profile, local } => {
                    let profile = profile
                        .as_deref()
                        .map(|name| format!(" (profile {})", terminal_text(name)))
                        .unwrap_or_default();
                    if *local {
                        format!(
                            "Local only: secret and credential references are exact IDs as saved{profile}; local: references resolve only on the machine that created them"
                        )
                    } else {
                        format!("References: secret and credential references are exact IDs as saved{profile}")
                    }
                }
            };
            format!("{} {text}\n", style.status(Status::Attention))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain() -> Style {
        Style::new(false, crate::output::Charset::Unicode)
    }

    #[test]
    fn notes_name_fields_and_never_values() {
        let notes = [
            Note::EnvironmentValues(vec!["API_URL".to_owned(), "NODE_ENV".to_owned()]),
            Note::HostFolders {
                count: 1,
                working_directory: Some("/workspace/app".to_owned()),
            },
            Note::MeshNetwork("mesh-dev".to_owned()),
            Note::DockerDisk(None),
            Note::HostPorts(vec![(18080, 8080)]),
            Note::References {
                profile: Some("user/work".to_owned()),
                local: true,
            },
        ];
        assert_eq!(
            render_notes(&notes, plain()),
            "! Not exported: environment values API_URL, NODE_ENV — add them to codewire.yaml, or keep sensitive ones in a secret project\n\
             ! Not exported: the local workspace's host folder (mounted, copied or empty), and the working directory /workspace/app that follows it — host paths stay on this machine; run `cw create` in that folder, or pass --path\n\
             ! Not exported: Mesh network mesh-dev — pass --network when creating\n\
             ! Not exported: Docker is off — pass --no-docker when creating\n\
             ! Local only: ports 127.0.0.1:18080 → 8080 use host_port — for a cloud environment, write `port: 8080` instead\n\
             ! Local only: secret and credential references are exact IDs as saved (profile user/work); local: references resolve only on the machine that created them\n"
        );
        let ascii = render_notes(
            &[Note::DockerDisk(Some(16))],
            Style::new(false, crate::output::Charset::Ascii),
        );
        assert_eq!(
            ascii,
            "! Not exported: Docker disk 16Gi - pass --docker-disk 16Gi when creating\n"
        );
    }

    #[test]
    fn a_cloud_environment_exports_its_saved_spec_at_its_current_size() {
        let saved = codewire_project::parse_project_yaml(
            r#"
image: workspace
repositories:
  - {source: https://example.test/org/app.git, branch: main, destination: /workspace/app}
working_directory: /workspace/app
install_command: npm ci
ports: [{port: 3000, label: web, access: creator}]
cpu: "2"
secrets: {project: "platform:id:6bf8d155-e84c-4fc5-b479-b17022fe41dd", organization: true}
credentials: {profile: "platform:id:7c0e2a4b-3f1d-4e5a-9b8c-0d1e2f3a4b5c"}
"#,
        )
        .unwrap()
        .spec;
        let environment = Environment {
            id: "env_1".into(),
            name: Some("app-cloud".into()),
            cpu_millicores: 4000,
            memory_mb: 8192,
            disk_gb: 40,
            isolation_tier: "confidential".into(),
            ttl_seconds: Some(7200),
            ..Default::default()
        };
        let export = cloud_export(&environment, saved.clone(), vec!["NODE_ENV".into()]).unwrap();
        assert_eq!(export.source, "cloud environment app-cloud");
        let yaml = export.document.to_yaml().unwrap();
        let parsed = codewire_project::parse_project_yaml(&yaml).unwrap();
        let mut expected = saved.clone();
        expected.resources = codewire_project::ResourceSpec {
            cpu_millicores: Some(4000),
            memory_mib: Some(8192),
            disk_gib: Some(40),
        };
        assert_eq!(parsed.spec, expected);
        parsed.ensure_platform_compatible().unwrap();
        assert_eq!(
            export.notes,
            [
                Note::EnvironmentValues(vec!["NODE_ENV".into()]),
                Note::ConfidentialIsolation,
                Note::Ttl(7200),
                Note::References {
                    profile: None,
                    local: false
                },
            ]
        );

        // A network names its create flag, as for a local VM.
        let attached = Environment {
            network: Some("work".into()),
            ..environment.clone()
        };
        let notes = cloud_export(&attached, saved.clone(), Vec::new())
            .unwrap()
            .notes;
        assert!(
            notes.contains(&Note::MeshNetwork("cloud:work".into())),
            "{notes:?}"
        );
        assert!(
            render_notes(&notes, plain())
                .contains("Not exported: Mesh network cloud:work — pass --network when creating")
        );

        let mut leaked = saved;
        leaked
            .environment
            .insert("API_URL".into(), "synthetic-canary".into());
        let error = cloud_export(&environment, leaked, Vec::new()).unwrap_err();
        assert!(error.to_string().contains("refusing to export"), "{error}");
        assert!(!error.to_string().contains("synthetic-canary"), "{error}");
    }

    #[test]
    fn cloud_notes_name_their_create_flags() {
        assert_eq!(
            render_notes(
                &[Note::ConfidentialIsolation, Note::Ttl(5400), Note::Ttl(90)],
                plain()
            ),
            "! Not exported: confidential isolation — pass --isolation confidential when creating\n\
             ! Not exported: time to live 90m — pass --ttl 90m when creating\n\
             ! Not exported: time to live 90s — pass --ttl 90s when creating\n"
        );
    }

    #[test]
    fn report_text_is_sanitized() {
        let rendered = render_notes(&[Note::MeshNetwork("evil\u{1b}[2Jnet".to_owned())], plain());
        assert!(!rendered.contains('\u{1b}'), "{rendered:?}");
    }

    #[test]
    fn references_name_local_ids_only_when_present() {
        let mut spec = codewire_project::ProjectSpec::default();
        assert_eq!(references_note(&spec, ""), None);
        spec.credentials = Some(codewire_project::CredentialBinding {
            profile: format!("platform:id:{}", uuid::Uuid::new_v4()),
        });
        assert_eq!(
            references_note(&spec, "user/work"),
            Some(Note::References {
                profile: Some("user/work".to_owned()),
                local: false
            })
        );
        spec.secrets.project = format!("local:id:{}", uuid::Uuid::new_v4());
        assert_eq!(
            references_note(&spec, ""),
            Some(Note::References {
                profile: None,
                local: true
            })
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn local_environment(
        yaml: &str,
    ) -> (
        codewire_project::ProjectDocument,
        codewire_local_vmm::control::v1::Environment,
    ) {
        let document = codewire_project::parse_project_yaml(yaml).unwrap();
        let json = document.spec.canonical_json().unwrap();
        let environment = codewire_local_vmm::control::v1::Environment {
            name: "app".to_owned(),
            vcpus: 4,
            memory_mib: 8192,
            disk_bytes: 60 * GIB,
            docker_disk_bytes: codewire_local_vmm::state::DEFAULT_DOCKER_DISK_BYTES,
            project_spec_sha256: format!("{:x}", Sha256::digest(&json)),
            project_spec_json: json,
            ..Default::default()
        };
        (document, environment)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_local_vm_exports_its_saved_spec_without_values() {
        let (document, mut environment) = local_environment(
            r#"
repositories:
  - {source: https://example.test/org/api.git, branch: main, destination: /workspace/api}
working_directory: /workspace/api
install_command: npm ci
startup_script: npm run dev
environment: {API_URL: synthetic-value-never-exported}
agents: {tools: [claude-code]}
ports:
  - {port: 3000, label: web, access: creator}
  - {host_port: 18080, guest_port: 8080}
cpu: "2"
secrets: {project: "local:id:6bf8d155-e84c-4fc5-b479-b17022fe41dd"}
credentials: {profile: "local:id:7c0e2a4b-3f1d-4e5a-9b8c-0d1e2f3a4b5c"}
"#,
        );
        environment.workspace_input_count = 1;
        environment.access_profile = "user/work".to_owned();
        environment.host_ports = vec![codewire_local_vmm::control::v1::HostPortBinding {
            host_port: 18080,
            guest_port: 8080,
        }];

        let export = local_export(&environment).unwrap();
        let yaml = export.document.to_yaml().unwrap();
        assert!(!yaml.contains("synthetic-value-never-exported"), "{yaml}");
        assert!(!yaml.contains("API_URL"), "{yaml}");
        let parsed = codewire_project::parse_project_yaml(&yaml).unwrap();
        let mut expected = document.spec.clone();
        expected.environment.clear();
        // The VM's current size, not the size the file once asked for.
        expected.resources = codewire_project::ResourceSpec {
            cpu_millicores: Some(4000),
            memory_mib: Some(8192),
            disk_gib: Some(60),
        };
        assert_eq!(parsed.spec, expected);
        assert_eq!(parsed.local.host_ports, document.local.host_ports);
        assert!(parsed.working_directory_is_explicit());
        assert_eq!(
            export.notes,
            [
                Note::EnvironmentValues(vec!["API_URL".to_owned()]),
                Note::HostPorts(vec![(18080, 8080)]),
                Note::References {
                    profile: Some("user/work".to_owned()),
                    local: true
                },
            ]
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_mounted_project_folder_is_reported_not_turned_into_a_repository() {
        let spec = codewire_project::ProjectSpec {
            working_directory: "/workspace/app".to_owned(),
            ..Default::default()
        };
        spec.validate().unwrap();
        let (_, mut environment) = local_environment("version: 1\n");
        let json = spec.canonical_json().unwrap();
        environment.project_spec_sha256 = format!("{:x}", Sha256::digest(&json));
        environment.project_spec_json = json;
        environment.workspace_input_count = 1;
        environment.docker_disk_bytes = 0;
        environment.mesh = Some(codewire_local_vmm::control::v1::MeshAttachment {
            network_id: "mesh-dev".to_owned(),
            ..Default::default()
        });

        let export = local_export(&environment).unwrap();
        let yaml = export.document.to_yaml().unwrap();
        assert!(!yaml.contains("repositories"), "{yaml}");
        assert!(!yaml.contains("mounts"), "{yaml}");
        assert!(!yaml.contains("working_directory"), "{yaml}");
        assert_eq!(
            export.notes,
            [
                Note::HostFolders {
                    count: 1,
                    working_directory: Some("/workspace/app".to_owned()),
                },
                Note::MeshNetwork("mesh-dev".to_owned()),
                Note::DockerDisk(None),
            ]
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_saved_spec_that_does_not_match_its_digest_is_refused() {
        let (_, mut environment) = local_environment("install_command: make\n");
        environment.project_spec_sha256 = "0".repeat(64);
        let error = local_export(&environment).unwrap_err();
        assert!(
            error.to_string().contains("does not match its digest"),
            "{error}"
        );
        environment.project_spec_json.clear();
        let error = local_export(&environment).unwrap_err();
        assert!(
            error.to_string().contains("no saved configuration"),
            "{error}"
        );
    }

    fn parse(argv: &[&str]) -> Result<(crate::Cli, ExportArgs), clap::Error> {
        let cli = crate::Cli::try_parse_from(argv)?;
        let crate::Command::Export(args) = &cli.command else {
            panic!("not an export: {argv:?}");
        };
        let args = ExportArgs {
            environment: args.environment.clone(),
            in_environment: args.in_environment.clone(),
            file: args.file.clone(),
            stdout: args.stdout,
            force: args.force,
        };
        Ok((cli, args))
    }

    #[test]
    fn the_grammar_names_one_environment_and_one_destination() {
        let (_, args) = parse(&["cw", "export", "app"]).unwrap();
        assert_eq!(args.environment.as_deref(), Some("app"));
        assert!(args.file.is_none() && !args.stdout && !args.force);
        let (_, args) = parse(&[
            "cw",
            "export",
            "--in",
            "app",
            "--file",
            "out/app.yaml",
            "--force",
        ])
        .unwrap();
        assert_eq!(args.in_environment.as_deref(), Some("app"));
        assert_eq!(args.file, Some(PathBuf::from("out/app.yaml")));
        assert!(args.force);
        for placement in [
            ["cw", "--local", "export", "app"],
            ["cw", "export", "app", "--cloud"],
        ] {
            let (cli, _) = parse(&placement).unwrap();
            crate::validate_placement_scope(
                &cli.command,
                "export",
                cli.placement().unwrap(),
                false,
            )
            .unwrap();
        }
        for refused in [
            &["cw", "export", "app", "--stdout", "--file", "x.yaml"][..],
            &["cw", "export", "app", "--stdout", "--force"],
            &["cw", "export", "app", "extra"],
        ] {
            assert!(crate::Cli::try_parse_from(refused).is_err(), "{refused:?}");
        }
        let error = flat::select_environment("export", Some("a".into()), Some("b".into()), &[])
            .unwrap_err();
        assert!(
            error.to_string().contains("name the environment once"),
            "{error}"
        );
    }

    #[test]
    fn the_default_file_is_the_one_the_next_create_discovers() {
        let dir = tempfile::tempdir().unwrap();
        let folder = std::fs::canonicalize(dir.path()).unwrap();
        let document = codewire_project::ProjectDocument::new(
            codewire_project::ProjectSpec {
                install_command: "npm ci".to_owned(),
                ..Default::default()
            },
            codewire_project::LocalProjectIntent::default(),
            true,
        );
        write_file(
            &folder.join(DEFAULT_FILE),
            document.to_yaml().unwrap().as_bytes(),
            false,
        )
        .unwrap();
        let found = super::super::project_file::discover(&folder)
            .unwrap()
            .expect("create discovers the exported file");
        assert_eq!(found, folder.join(DEFAULT_FILE));
        let parsed =
            codewire_project::parse_project_yaml(&fs::read_to_string(found).unwrap()).unwrap();
        assert_eq!(parsed.spec, document.spec);
    }

    #[test]
    fn an_existing_file_is_refused_and_force_replaces_it_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("codewire.yaml");
        fs::write(&path, "keep: me\n").unwrap();
        let error = write_file(&path, b"version: 1\n", false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("already exists (use --force to overwrite)"),
            "{error}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "keep: me\n");

        write_file(&path, b"version: 1\n", true).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "version: 1\n");
        let leftovers = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(leftovers, 1, "a staged file was left behind");

        let nested = dir.path().join("nested/dir/out.yaml");
        write_file(&nested, b"version: 1\n", false).unwrap();
        assert_eq!(fs::read_to_string(&nested).unwrap(), "version: 1\n");
    }
}
