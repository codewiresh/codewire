//! `cw update ENV --file`: what it compares, what it says and what it
//! refuses (#5949; journey `sandbox-update-startup`).

use super::*;
use crate::output::Charset;

const PLAIN: Style = Style::new(false, Charset::Unicode);

fn document(yaml: &str) -> PlatformDocument {
    let parsed = codewire_project::parse_project_yaml(yaml).unwrap();
    PlatformDocument {
        working_directory_explicit: parsed.working_directory_is_explicit(),
        spec: parsed.spec,
        idle_stop_seconds: parsed.idle_stop_seconds,
        idle_suspend_seconds: parsed.idle_suspend_seconds,
        unused_fields: Vec::new(),
    }
}

/// A Sandbox created from `walk.yaml` with the workspace image the server
/// pinned, the sources resolved to IDs, and resized since.
const CREATED: &str = "\
image: ghcr.io/codewiresh/workspace@DIGEST
repositories:
  - source: https://example.test/org/app.git
install_command: npm ci
ports:
  - port: 3000
    label: web
secrets:
  project: platform:id:6bf8d155-e84c-4fc5-b479-b17022fe41dd
  organization: true
credentials:
  profile: platform:id:7c0e2a4b-3f1d-4e5a-9b8c-0d1e2f3a4b5c
";

fn saved_spec() -> codewire_project::ProjectSpec {
    document(&CREATED.replace("DIGEST", codewire_workspace_image::DIGEST)).spec
}

fn sandbox() -> Environment {
    Environment {
        id: "env_walk".into(),
        name: Some("walk-start".into()),
        cpu_millicores: 2000,
        memory_mb: 4096,
        disk_gb: 20,
        idle_stop_seconds: 21_600,
        ..Default::default()
    }
}

fn compare(yaml: &str) -> Vec<(&'static str, Route)> {
    let spec = saved_spec();
    let environment = sandbox();
    let withheld = vec!["API_URL".to_owned()];
    differences(
        &document(yaml),
        &Saved {
            spec: &spec,
            withheld: &withheld,
            environment: &environment,
        },
    )
    .into_iter()
    .map(|difference| (difference.field, difference.route))
    .collect()
}

fn target(files: &[&str]) -> Target<'static> {
    Target {
        name: "walk-start".into(),
        files: Box::leak(
            files
                .iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ),
    }
}

/// The file `cw export` writes compares equal, with a startup script added.
#[test]
fn an_exported_file_with_a_script_added_differs_only_in_its_script() {
    let exported = format!(
        "{}cpu: \"2\"\nmemory: 4Gi\ndisk: 20Gi\nidle_stop: 6h\nenvironment:\n  API_URL: withheld\nstartup_script: echo started > /workspace/started\n",
        CREATED.replace("DIGEST", codewire_workspace_image::DIGEST)
    );
    assert_eq!(compare(&exported), []);
    assert_eq!(
        script_change("", &document(&exported).spec.startup_script),
        Some(ScriptChange::Added("echo started > /workspace/started"))
    );
}

/// The file that created the Sandbox, before the server pinned its image
/// and resolved its sources by name, compares equal too; the sources
/// resolve before the comparison, so only the image is shown here.
#[test]
fn settings_the_file_leaves_out_are_not_compared() {
    assert_eq!(compare("startup_script: echo started\n"), []);
    assert_eq!(compare("install_command: npm ci\n"), []);
    assert_eq!(compare("image: workspace\n"), []);
}

#[test]
fn every_other_setting_the_file_states_differently_is_named_with_its_route() {
    assert_eq!(
        compare("install_command: pnpm install\n"),
        [("install_command", Route::NewSandbox)]
    );
    assert_eq!(compare("image: node:22\n"), [("image", Route::NewSandbox)]);
    assert_eq!(
        compare("repositories:\n  - source: https://example.test/org/other.git\n"),
        [("repositories", Route::NewSandbox)]
    );
    assert_eq!(
        compare("working_directory: /workspace\n"),
        [("working_directory", Route::NewSandbox)]
    );
    assert_eq!(
        compare("environment:\n  OTHER: value\n"),
        [("environment", Route::NewSandbox)]
    );
    assert_eq!(
        compare("ports:\n  - port: 8080\n"),
        [("ports", Route::NewSandbox)]
    );
    assert_eq!(
        compare(
            "secrets:\n  organization: false\n  project: platform:id:6bf8d155-e84c-4fc5-b479-b17022fe41dd\n"
        ),
        [("secrets", Route::Secrets)]
    );
    assert_eq!(
        compare("credentials:\n  profile: platform:id:11111111-2222-4333-8444-555555555555\n"),
        [("credentials", Route::Profile)]
    );
    assert_eq!(
        compare("cpu: \"4\"\nmemory: 4Gi\n"),
        [("cpu", Route::Resize)]
    );
    assert_eq!(
        compare("idle_stop: off\n"),
        [("idle_stop", Route::IdleStop)]
    );
    assert_eq!(
        compare("idle_suspend: 15m\n"),
        [("idle_suspend", Route::IdleSuspend)]
    );
    assert_eq!(compare("idle_suspend: off\n"), []);
}

#[test]
fn the_workspace_image_matches_at_any_published_digest_and_alias() {
    let current = format!(
        "ghcr.io/codewiresh/workspace@{}",
        codewire_workspace_image::DIGEST
    );
    let deployment = format!(
        "registry.example.invalid/codewire/workspace@{}",
        codewire_workspace_image::DIGEST
    );
    assert!(same_image("workspace", &deployment));
    assert!(same_image(&current, &deployment));
    if let Some(previous) = codewire_workspace_image::PREVIOUS_DIGESTS.first() {
        assert!(same_image(
            &format!("ghcr.io/codewiresh/workspace@{previous}"),
            &current
        ));
    }
    assert!(!same_image("node:22", &current));
    assert!(!same_image(
        "registry.example.invalid/codewire/workspace@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        &current
    ));
}

#[test]
fn the_script_is_added_changed_removed_or_left() {
    assert_eq!(script_change("", ""), None);
    assert_eq!(script_change("a", "a"), None);
    assert_eq!(script_change("", "a"), Some(ScriptChange::Added("a")));
    assert_eq!(
        script_change("a", "b"),
        Some(ScriptChange::Changed { from: "a", to: "b" })
    );
    assert_eq!(script_change("a", ""), Some(ScriptChange::Removed("a")));
    assert_eq!(ScriptChange::Removed("a").script(), "");
    assert_eq!(ScriptChange::Changed { from: "a", to: "b" }.script(), "b");
}

#[test]
fn a_refusal_names_each_setting_where_it_changes_and_the_next_step() {
    let error = refusal(
        &[Difference {
            field: "install_command",
            route: Route::NewSandbox,
        }],
        &target(&["codewire.yaml"]),
    );
    assert_eq!(
        crate::error_report::sentence(&error),
        "`cw update --file` changes only startup_script, and codewire.yaml also changes install_command (only a new Sandbox takes it, since create applies it once); nothing was saved"
    );
    assert_eq!(
        crate::error_report::next_step(&error).as_deref(),
        Some("cw --cloud create --file codewire.yaml")
    );

    let error = refusal(
        &[
            Difference {
                field: "secrets",
                route: Route::Secrets,
            },
            Difference {
                field: "image",
                route: Route::NewSandbox,
            },
            Difference {
                field: "repositories",
                route: Route::NewSandbox,
            },
        ],
        &target(&["codewire.yaml", "dev.yaml"]),
    );
    assert_eq!(
        crate::error_report::sentence(&error),
        "`cw update --file` changes only startup_script, and codewire.yaml + dev.yaml also changes secrets (change it with `cw update walk-start --secrets`); image and repositories (only a new Sandbox takes them, since create applies them once); nothing was saved"
    );
    assert_eq!(
        crate::error_report::next_step(&error).as_deref(),
        Some("cw update walk-start --secrets PROJECT")
    );
}

#[test]
fn the_preview_shows_the_script_and_when_it_runs() {
    let target = target(&["codewire.yaml"]);
    assert_eq!(
        preview(&target, &ScriptChange::Added("echo a\necho b"), PLAIN),
        "Adds this startup script to walk-start, from codewire.yaml:\n  echo a\n  echo b\nIt runs at the next start, not now.\n"
    );
    assert_eq!(
        preview(
            &target,
            &ScriptChange::Changed {
                from: "echo a",
                to: "echo b"
            },
            PLAIN
        ),
        "Changes walk-start's startup script, from codewire.yaml. Now:\n  echo a\nNew:\n  echo b\nThe new one runs at the next start, not now.\n"
    );
    assert_eq!(
        preview(&target, &ScriptChange::Removed("echo a"), PLAIN),
        "Removes walk-start's startup script, since codewire.yaml has none:\n  echo a\n"
    );
    // A script can't drive the terminal.
    assert_eq!(indented("echo \x1b[31mred"), "  echo [31mred\n");
}

#[test]
fn the_result_says_it_runs_at_the_next_start_and_how_to_get_there() {
    let target = target(&["codewire.yaml"]);
    assert_eq!(
        saved_text(&target, &ScriptChange::Added("echo a"), true, PLAIN),
        "✓ Startup script added to walk-start · it runs at the next start, not now\n→ cw --cloud stop walk-start && cw --cloud start walk-start\n"
    );
    assert_eq!(
        saved_text(
            &target,
            &ScriptChange::Changed { from: "a", to: "b" },
            false,
            PLAIN
        ),
        "✓ Startup script changed on walk-start · it runs at the next start\n→ cw --cloud start walk-start\n"
    );
    assert_eq!(
        saved_text(&target, &ScriptChange::Removed("a"), true, PLAIN),
        "✓ Startup script removed from walk-start · the next start runs none\n"
    );
    assert_eq!(
        unchanged_text(&target),
        "Nothing to change: walk-start's settings already match codewire.yaml.\n"
    );
}

#[test]
fn saving_asks_at_a_terminal_and_otherwise_needs_yes() {
    let refused =
        confirm_with(false, || unreachable!("never asked without a terminal")).unwrap_err();
    assert_eq!(
        refused.to_string(),
        "saving the startup script needs --yes when there's no terminal to confirm at; nothing was saved"
    );
    let declined = confirm_with(true, || Ok(false)).unwrap_err();
    assert_eq!(declined.to_string(), "canceled; nothing was saved");
    confirm_with(true, || Ok(true)).unwrap();
}
