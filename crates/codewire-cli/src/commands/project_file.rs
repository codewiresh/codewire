//! Which `codewire.yaml` a create reads, and where its configuration came
//! from.
//!
//! Both placements search the same way: the nearest `codewire.yaml` from the
//! start directory (`--path` for a local create, otherwise the invoking
//! directory) up to the root of the Git worktree that holds it. Outside a Git
//! worktree only the start directory is checked. `--file` replaces the search.
//! Exactly one file is read: a nested repository's own file, and the files
//! inside declared repositories, are never read or merged. Start and attach
//! read no file: an existing environment keeps its saved configuration.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::Serialize;

use crate::commands::progress::terminal_text;

pub(crate) const PROJECT_FILE_NAME: &str = "codewire.yaml";

/// The file a create reads, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConfigSource {
    /// The nearest `codewire.yaml`, found by the search.
    Discovered(PathBuf),
    /// The file `--file` named.
    File(PathBuf),
    /// No file was found: flags and defaults only.
    Flags,
    /// `--no-file`: flags and defaults only, without a search.
    NoFile,
}

impl ConfigSource {
    pub(crate) fn path(&self) -> Option<&Path> {
        match self {
            ConfigSource::Discovered(path) | ConfigSource::File(path) => Some(path),
            ConfigSource::Flags | ConfigSource::NoFile => None,
        }
    }
}

/// The nearest `codewire.yaml` from `start` (a canonical directory) up to the
/// root of the Git worktree that holds it: the nearest directory with a
/// `.git` entry, a directory in a checkout or a file in a linked worktree or
/// submodule, so a nested repository is its own boundary. Outside a Git
/// worktree only `start` is checked.
pub(crate) fn discover(start: &Path) -> anyhow::Result<Option<PathBuf>> {
    let root = start
        .ancestors()
        .find(|directory| directory.join(".git").symlink_metadata().is_ok());
    for directory in start.ancestors() {
        let candidate = directory.join(PROJECT_FILE_NAME);
        match candidate.symlink_metadata() {
            Ok(_) => return Ok(Some(candidate)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("look for {}", candidate.display()));
            }
        }
        if root.is_none_or(|root| directory == root) {
            break;
        }
    }
    Ok(None)
}

/// The invoking directory, canonical, where a search without `--path`
/// starts.
pub(crate) fn invoking_directory() -> anyhow::Result<PathBuf> {
    let current = std::env::current_dir().context("resolve the current directory")?;
    std::fs::canonicalize(&current).with_context(|| format!("resolve {}", current.display()))
}

/// The configuration source for a create that has no `--path`: `--file`
/// relative to the invoking directory, none with `--no-file`, or the search
/// from it.
pub(crate) fn select_from(
    start: &Path,
    file: Option<&Path>,
    no_file: bool,
) -> anyhow::Result<ConfigSource> {
    match file {
        Some(file) => Ok(ConfigSource::File(start.join(file))),
        None if no_file => Ok(ConfigSource::NoFile),
        None => Ok(discover(start)?.map_or(ConfigSource::Flags, ConfigSource::Discovered)),
    }
}

/// Explicit repository inputs (positional URLs and `--repo`) replace the
/// file's repository list; they never add to it. `--branch` names the branch
/// of the one repository. Returns whether the flags replaced the list.
///
/// `require_repository` refuses `--branch` without any repository; only
/// `cw init` leaves it for the repository it detects afterwards.
pub(crate) fn apply_repository_flags(
    spec: &mut codewire_project::ProjectSpec,
    repo_urls: &[String],
    repo_flags: &[String],
    branch: Option<&str>,
    require_repository: bool,
) -> anyhow::Result<bool> {
    if !repo_urls.is_empty() || !repo_flags.is_empty() {
        spec.repositories = super::collect_env_create_repos(repo_urls, repo_flags, branch)?;
        spec.working_directory = match spec.repositories.as_slice() {
            [repository] => repository.destination.clone(),
            _ => "/workspace".to_owned(),
        };
        return Ok(true);
    }
    if let Some(branch) = branch {
        match spec.repositories.as_mut_slice() {
            [repository] => {
                repository.branch = branch.to_owned();
                repository.revision.clear();
            }
            [] if require_repository => anyhow::bail!("--branch requires a repository"),
            [] => {}
            _ => anyhow::bail!(
                "--branch is ambiguous with multiple YAML repositories; specify --repo"
            ),
        }
    }
    Ok(false)
}

/// Where a create's configuration came from, shown before it creates
/// anything and returned in its JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Provenance {
    pub(crate) source: ConfigSource,
    /// Explicit repository inputs replaced the file's repository list.
    pub(crate) repositories_from_flags: bool,
    /// Neither the file nor a flag named an image or preset, so the default
    /// workspace image applies.
    pub(crate) default_image: bool,
    /// A cloud create with repositories and no file, image or preset: Codewire
    /// Cloud fills omitted settings from the defaults saved for this, the
    /// first, repository.
    pub(crate) repository_defaults: Option<String>,
    /// File settings this placement does not use, such as
    /// `workspace.vm_only` on a cloud create.
    pub(crate) unused_fields: Vec<&'static str>,
}

impl Provenance {
    pub(crate) fn new(source: ConfigSource) -> Self {
        Self {
            source,
            repositories_from_flags: false,
            default_image: false,
            repository_defaults: None,
            unused_fields: Vec::new(),
        }
    }

    /// One line: the file (`~/src/app/codewire.yaml`, `… (--file)`) or
    /// `flags only`, then what else applies.
    pub(crate) fn text(&self) -> String {
        let mut parts = vec![match &self.source {
            ConfigSource::Discovered(path) => shown_path(path),
            ConfigSource::File(path) => format!("{} (--file)", shown_path(path)),
            ConfigSource::Flags => "flags only, no codewire.yaml found".to_owned(),
            ConfigSource::NoFile => "flags only (--no-file)".to_owned(),
        }];
        if self.repositories_from_flags && self.source.path().is_some() {
            parts.push("repositories from --repo, not the file".to_owned());
        }
        if self.default_image {
            parts.push("default workspace image".to_owned());
        }
        if let Some(repository) = &self.repository_defaults {
            parts.push(format!(
                "Codewire Cloud fills omitted settings from the defaults saved for {}",
                terminal_text(repository)
            ));
        }
        for field in &self.unused_fields {
            parts.push(format!("{field} applies to local VMs only"));
        }
        parts.join("; ")
    }

    /// The `configuration` object of a create's JSON result.
    pub(crate) fn json(&self) -> serde_json::Value {
        #[derive(Serialize)]
        struct PlatformDefaults<'a> {
            origin: &'static str,
            repository: &'a str,
        }
        #[derive(Serialize)]
        struct Json<'a> {
            source: &'static str,
            #[serde(skip_serializing_if = "Option::is_none")]
            path: Option<String>,
            repositories_from_flags: bool,
            default_image: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            platform_defaults: Option<PlatformDefaults<'a>>,
            #[serde(skip_serializing_if = "<[_]>::is_empty")]
            unused_fields: &'a [&'static str],
        }
        serde_json::to_value(Json {
            source: match self.source {
                ConfigSource::Discovered(_) => "discovered",
                ConfigSource::File(_) => "file",
                ConfigSource::Flags => "flags",
                ConfigSource::NoFile => "no_file",
            },
            path: self
                .source
                .path()
                .map(|path| path.to_string_lossy().into_owned()),
            repositories_from_flags: self.repositories_from_flags,
            default_image: self.default_image,
            platform_defaults: self.repository_defaults.as_deref().map(|repository| {
                PlatformDefaults {
                    origin: "saved_repository_configuration",
                    repository,
                }
            }),
            unused_fields: &self.unused_fields,
        })
        .expect("provenance is plain JSON")
    }

    /// `value`, a create's JSON object, with its `configuration`.
    pub(crate) fn add_to(&self, mut value: serde_json::Value) -> serde_json::Value {
        if let Some(object) = value.as_object_mut() {
            object.insert("configuration".to_owned(), self.json());
        }
        value
    }
}

/// A host path with the home directory shortened to `~`.
pub(crate) fn shown_path(path: &Path) -> String {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let shown = match home
        .as_deref()
        .filter(|home| !home.as_os_str().is_empty())
        .and_then(|home| path.strip_prefix(home).ok())
    {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    };
    terminal_text(&shown)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(path: &Path) -> PathBuf {
        std::fs::canonicalize(path).unwrap()
    }

    fn write(path: &Path, content: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn the_nearest_file_within_the_git_worktree_is_found_from_a_subdirectory() {
        let temp = tempfile::tempdir().unwrap();
        let root = canonical(temp.path()).join("app");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("crates/cli/src")).unwrap();
        write(&root.join("codewire.yaml"), "version: 1\n");

        for start in [
            root.clone(),
            root.join("crates"),
            root.join("crates/cli/src"),
        ] {
            assert_eq!(
                discover(&start).unwrap(),
                Some(root.join("codewire.yaml")),
                "{}",
                start.display()
            );
        }
        // A nearer file wins; the root file is not read with it.
        write(&root.join("crates/codewire.yaml"), "version: 1\n");
        assert_eq!(
            discover(&root.join("crates/cli/src")).unwrap(),
            Some(root.join("crates/codewire.yaml"))
        );
    }

    #[test]
    fn the_search_stops_at_the_worktree_root_and_a_nested_repository_is_its_own() {
        let temp = tempfile::tempdir().unwrap();
        let outer = canonical(temp.path());
        // A codewire.yaml in a directory above the worktree, such as a parent
        // directory that holds several checkouts.
        write(&outer.join("codewire.yaml"), "version: 1\n");
        let checkout = outer.join("codewire");
        std::fs::create_dir_all(checkout.join(".git")).unwrap();
        std::fs::create_dir_all(checkout.join("crates")).unwrap();
        assert_eq!(discover(&checkout.join("crates")).unwrap(), None);

        // A linked worktree or submodule marks its root with a .git file.
        let nested = checkout.join("vendor/lib");
        std::fs::create_dir_all(nested.join("src")).unwrap();
        std::fs::write(nested.join(".git"), "gitdir: ../../.git/modules/lib\n").unwrap();
        write(&checkout.join("codewire.yaml"), "version: 1\n");
        assert_eq!(discover(&nested.join("src")).unwrap(), None);
        write(&nested.join("codewire.yaml"), "version: 1\n");
        assert_eq!(
            discover(&nested.join("src")).unwrap(),
            Some(nested.join("codewire.yaml"))
        );
        // From the checkout, the nested repository's file is never found.
        assert_eq!(
            discover(&checkout.join("crates")).unwrap(),
            Some(checkout.join("codewire.yaml"))
        );
    }

    #[test]
    fn outside_a_git_worktree_only_the_start_directory_is_checked() {
        let temp = tempfile::tempdir().unwrap();
        let base = canonical(temp.path());
        // The temporary directory must not sit in a Git worktree itself.
        if base.ancestors().any(|dir| dir.join(".git").exists()) {
            return;
        }
        write(&base.join("codewire.yaml"), "version: 1\n");
        std::fs::create_dir_all(base.join("child")).unwrap();
        assert_eq!(discover(&base.join("child")).unwrap(), None);
        assert_eq!(discover(&base).unwrap(), Some(base.join("codewire.yaml")));
    }

    #[test]
    fn an_explicit_file_overrides_the_search() {
        let temp = tempfile::tempdir().unwrap();
        let root = canonical(temp.path());
        std::fs::create_dir_all(root.join(".git")).unwrap();
        write(&root.join("codewire.yaml"), "version: 1\n");
        assert_eq!(
            select_from(&root, Some(Path::new("ci.yaml")), false).unwrap(),
            ConfigSource::File(root.join("ci.yaml"))
        );
        assert_eq!(
            select_from(&root, None, false).unwrap(),
            ConfigSource::Discovered(root.join("codewire.yaml"))
        );
        assert_eq!(
            select_from(&root, None, true).unwrap(),
            ConfigSource::NoFile
        );
        std::fs::remove_file(root.join("codewire.yaml")).unwrap();
        assert_eq!(
            select_from(&root, None, false).unwrap(),
            ConfigSource::Flags
        );
    }

    #[test]
    fn this_repository_file_is_found_from_a_subdirectory() {
        let crate_directory = canonical(Path::new(env!("CARGO_MANIFEST_DIR")));
        let repository = crate_directory.parent().unwrap().parent().unwrap();
        // A source tree without its Git metadata has no worktree to search.
        if !repository.join(".git").exists() {
            return;
        }
        assert_eq!(
            discover(&crate_directory.join("src")).unwrap(),
            Some(repository.join("codewire.yaml"))
        );
    }

    #[test]
    fn explicit_repositories_replace_the_file_list_and_branch_needs_one() {
        let file = codewire_project::parse_project_yaml(
            "repositories:\n  - source: https://example.test/org/file.git\n    destination: /workspace/file\nworking_directory: /workspace/file\n",
        )
        .unwrap()
        .spec;
        let mut spec = file.clone();
        let replaced = apply_repository_flags(
            &mut spec,
            &[],
            &[
                "https://example.test/org/web.git::/workspace/web".to_owned(),
                "https://example.test/org/api.git@dev::/workspace/api".to_owned(),
            ],
            None,
            true,
        )
        .unwrap();
        assert!(replaced);
        let repositories = spec
            .repositories
            .iter()
            .map(|r| (r.source.as_str(), r.branch.as_str(), r.destination.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            repositories,
            [
                ("https://example.test/org/web.git", "", "/workspace/web"),
                ("https://example.test/org/api.git", "dev", "/workspace/api"),
            ]
        );
        assert_eq!(spec.working_directory, "/workspace");

        let mut spec = file.clone();
        assert!(!apply_repository_flags(&mut spec, &[], &[], Some("main"), true).unwrap());
        assert_eq!(spec.repositories[0].branch, "main");

        let mut spec = codewire_project::ProjectSpec::default();
        assert!(apply_repository_flags(&mut spec, &[], &[], Some("main"), true).is_err());
        assert!(apply_repository_flags(&mut spec, &[], &[], Some("main"), false).is_ok());

        // Two repositories may not share a destination.
        let mut spec = codewire_project::ProjectSpec::default();
        assert!(
            apply_repository_flags(
                &mut spec,
                &[],
                &[
                    "https://example.test/org/web.git::/workspace/app".to_owned(),
                    "https://example.test/org/api.git::/workspace/app".to_owned(),
                ],
                None,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn provenance_names_the_source_in_text_and_json() {
        let path = PathBuf::from("/srv/app/codewire.yaml");
        let mut provenance = Provenance::new(ConfigSource::Discovered(path.clone()));
        assert_eq!(provenance.text(), "/srv/app/codewire.yaml");
        assert_eq!(
            provenance.json(),
            serde_json::json!({
                "source": "discovered",
                "path": "/srv/app/codewire.yaml",
                "repositories_from_flags": false,
                "default_image": false,
            })
        );
        provenance.repositories_from_flags = true;
        provenance.default_image = true;
        provenance.unused_fields = vec!["workspace.vm_only"];
        assert_eq!(
            provenance.text(),
            "/srv/app/codewire.yaml; repositories from --repo, not the file; default workspace image; workspace.vm_only applies to local VMs only"
        );
        assert_eq!(
            provenance.json()["unused_fields"],
            serde_json::json!(["workspace.vm_only"])
        );

        let explicit = Provenance::new(ConfigSource::File(PathBuf::from("/srv/app/ci.yaml")));
        assert_eq!(explicit.text(), "/srv/app/ci.yaml (--file)");
        assert_eq!(explicit.json()["source"], "file");

        let mut flags = Provenance::new(ConfigSource::Flags);
        flags.repository_defaults = Some("https://example.test/org/app.git".to_owned());
        assert_eq!(
            flags.text(),
            "flags only, no codewire.yaml found; Codewire Cloud fills omitted settings from the defaults saved for https://example.test/org/app.git"
        );
        assert_eq!(
            flags.json(),
            serde_json::json!({
                "source": "flags",
                "repositories_from_flags": false,
                "default_image": false,
                "platform_defaults": {
                    "origin": "saved_repository_configuration",
                    "repository": "https://example.test/org/app.git",
                },
            })
        );
        let skipped = Provenance::new(ConfigSource::NoFile);
        assert_eq!(skipped.text(), "flags only (--no-file)");
        assert_eq!(skipped.json()["source"], "no_file");
        let result = flags.add_to(serde_json::json!({"id": "env-1"}));
        assert_eq!(result["id"], "env-1");
        assert_eq!(result["configuration"]["source"], "flags");
    }
}
