use super::*;

fn selected() -> Option<ManagedCredentialClients> {
    Some(ManagedCredentialClients::from_profile_slots(["github"]).unwrap())
}

fn repository(source: &str) -> Repo {
    Repo {
        url: source.into(),
        mount_path: "/workspace/app".into(),
        ..Default::default()
    }
}

#[test]
fn clean_source_and_exact_loopback_rewrite_are_separate_arguments() {
    for source in [
        "https://github.com/Owner/app",
        "https://github.com/Owner/app.git",
        "git://github.com/Owner/app.git",
        "git@github.com:Owner/app.git",
        "ssh://git@github.com/Owner/app",
    ] {
        let repo = repository(source);
        let plan = commands(std::slice::from_ref(&repo), selected())
            .unwrap()
            .remove(0)
            .unwrap();
        assert_eq!(plan.clone.last().unwrap(), &repo.mount_path);
        assert_eq!(
            &plan.clone[plan.clone.len() - 6..],
            &[
                "clone",
                "--progress",
                "--template=",
                "--",
                source,
                "/workspace/app"
            ]
        );
        let path = codewire_project::github_repository_path(source).unwrap().0;
        assert!(path.starts_with("Owner/app"));
        assert!(plan.clone.contains(&format!(
            "url.http://127.0.0.1:38081/_codewire/github/{path}.insteadOf={source}"
        )));
        assert_eq!(repo.url, source);
        assert!(plan.checkout.is_none());
    }
}

#[test]
fn missing_selection_never_downgrades_github_but_explicit_unselected_preserves_public_checkout() {
    for source in [
        "https://github.com/owner/app.git",
        "git@github.com:owner/app.git",
    ] {
        let repo = repository(source);
        assert!(commands(std::slice::from_ref(&repo), None).is_err());
        for clients in [
            ManagedCredentialClients::default(),
            ManagedCredentialClients::from_profile_slots(["ssh"]).unwrap(),
        ] {
            assert!(commands(std::slice::from_ref(&repo), Some(clients)).unwrap()[0].is_none());
        }
    }
}

/// Other hosts, and other SSH spellings of github.com, are never the GitHub
/// connection's: they keep their existing checkout, which for SSH needs the
/// key (`ssh_checkout`).
#[test]
fn other_services_and_other_ssh_sources_keep_their_existing_checkout() {
    for source in [
        "https://gitlab.com/owner/app.git",
        "git@gitlab.com:owner/app.git",
        "ssh://git@gitlab.com/owner/app.git",
        "git://gitlab.com/owner/app.git",
        "ssh://git@github.com:2222/owner/app.git",
        "deploy@github.com:owner/app.git",
    ] {
        assert!(commands(&[repository(source)], selected()).unwrap()[0].is_none());
        assert!(commands(&[repository(source)], None).unwrap()[0].is_none());
    }
}

#[test]
fn github_authority_and_path_aliases_fail_before_returning_any_commands() {
    for source in [
        "http://github.com/owner/app.git",
        "https://GitHub.com/owner/app.git",
        "https://github.com./owner/app.git",
        "https://github.com:443/owner/app.git",
        "https://token@github.com/owner/app.git",
        "https://github.com/owner/app.git?ref=main",
        "https://github.com/owner/app.git#main",
        "https://github.com/owner/%61pp.git",
        "https://github.com/owner/app.git/",
        "https://github.com/owner/../app.git",
        "https://github.com/owner/.git",
        "https://github.com/owner/app.git/extra",
        "https://github.com/owner/app.git\\extra",
    ] {
        assert!(
            commands(
                &[
                    repository("https://github.com/owner/valid.git"),
                    repository(source)
                ],
                selected()
            )
            .is_err(),
            "{source}"
        );
    }
}

#[test]
fn selected_revision_and_branch_use_the_same_isolated_git_boundary() {
    for revision in [false, true] {
        let mut repo = repository("https://github.com/owner/app.git");
        repo.branch = "main".into();
        if revision {
            repo.revision = "a1b2c3".into();
        }
        let plan = commands(&[repo], selected()).unwrap().remove(0).unwrap();
        let checkout = plan.checkout.unwrap();
        assert!(checkout.starts_with(&isolated_git()));
        assert_eq!(checkout.iter().any(|arg| arg == "--detach"), revision);
        assert_eq!(
            checkout[checkout.len() - 2],
            if revision { "a1b2c3" } else { "main" }
        );
        assert_eq!(checkout.last().unwrap(), "--");
        assert!(!checkout.iter().any(|arg| arg.contains("insteadOf")));
    }
    let mut invalid = repository("https://github.com/owner/app.git");
    invalid.branch = "--orphan=unexpected".into();
    assert!(commands(&[invalid], selected()).is_err());
}

#[cfg(target_os = "linux")]
mod git {
    use super::*;
    use axum::{
        Router,
        body::{Body, to_bytes},
        extract::State,
        http::{Request, Response},
        routing::any,
    };
    use std::{
        io::Write,
        path::PathBuf,
        process::{Command, Stdio},
        sync::{Arc, Mutex},
    };

    #[derive(Clone)]
    struct Fixture {
        repositories: PathBuf,
        requests: Arc<Mutex<Vec<String>>>,
        redirect: bool,
    }

    fn git() -> Command {
        let mut command = Command::new("/usr/bin/git");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null");
        command
    }

    async fn bounded_output(command: &mut tokio::process::Command) -> std::process::Output {
        use tokio::io::AsyncReadExt;
        command
            .process_group(0)
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let group = child.id().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            tokio::try_join!(
                child.wait(),
                stdout.read_to_end(&mut out),
                stderr.read_to_end(&mut err)
            )
        })
        .await;
        match result {
            Ok(result) => {
                let (status, _, _) = result.unwrap();
                std::process::Output {
                    status,
                    stdout: out,
                    stderr: err,
                }
            }
            Err(_) => {
                // This fixture created and still owns this exact process group.
                // Kill helpers as well as Git; a blocked local firewall must not
                // leave detached curl processes or hang the test runner.
                let status = Command::new("/bin/kill")
                    .args(["-KILL", "--", &format!("-{group}")])
                    .status()
                    .unwrap();
                assert!(status.success());
                child.wait().await.unwrap();
                panic!(
                    "synthetic Git loopback fixture exceeded 20 seconds; verify local network permission"
                );
            }
        }
    }

    async fn serve(State(fixture): State<Fixture>, request: Request<Body>) -> Response<Body> {
        let (parts, body) = request.into_parts();
        fixture.requests.lock().unwrap().push(parts.uri.to_string());
        if fixture.redirect {
            return Response::builder()
                .status(302)
                .header("location", "http://127.0.0.1:1/forbidden")
                .body(Body::empty())
                .unwrap();
        }
        // Synthetic provider with real stock Git smart HTTP. No provider token,
        // broker authorization or hosted-network success is claimed by this test.
        let provider_path = parts.uri.path().strip_prefix("/_codewire/github").unwrap();
        let body = to_bytes(body, 1024 * 1024).await.unwrap();
        let mut child = git()
            .arg("http-backend")
            .env("GIT_PROJECT_ROOT", &fixture.repositories)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("PATH_INFO", provider_path)
            .env("REQUEST_METHOD", parts.method.as_str())
            .env("QUERY_STRING", parts.uri.query().unwrap_or_default())
            .env(
                "CONTENT_TYPE",
                parts
                    .headers
                    .get("content-type")
                    .map(|v| v.to_str().unwrap())
                    .unwrap_or_default(),
            )
            .env("CONTENT_LENGTH", body.len().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&body).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let boundary = output
            .stdout
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap();
        let mut response = Response::builder();
        for line in std::str::from_utf8(&output.stdout[..boundary])
            .unwrap()
            .split("\r\n")
        {
            let (name, value) = line.split_once(':').unwrap();
            if name.eq_ignore_ascii_case("status") {
                response = response.status(
                    value
                        .trim()
                        .split_once(' ')
                        .unwrap()
                        .0
                        .parse::<u16>()
                        .unwrap(),
                );
            } else {
                response = response.header(name, value.trim());
            }
        }
        response
            .body(Body::from(output.stdout[boundary + 4..].to_vec()))
            .unwrap()
    }

    async fn run(redirect: bool, source: &str) {
        let root = tempfile::tempdir().unwrap();
        let upstream = root.path().join("owner/app.git");
        let output = git()
            .args(["init", "--bare", "--initial-branch=main"])
            .arg(&upstream)
            .output()
            .unwrap();
        assert!(output.status.success());
        let mut import = git()
            .arg("--git-dir")
            .arg(&upstream)
            .args(["fast-import", "--quiet"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        import.stdin.take().unwrap().write_all(b"commit refs/heads/main\ncommitter Synthetic <synthetic@example.invalid> 1 +0000\ndata 7\nfixture\nM 100644 inline README\ndata 8\nfixture\n\n").unwrap();
        let output = import.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let fixture = Fixture {
            repositories: root.path().to_owned(),
            requests: Arc::default(),
            redirect,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new()
            .fallback(any(serve))
            .with_state(fixture.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let destination = root.path().join("checkout");
        let mut repo = repository(source);
        repo.mount_path = destination.to_str().unwrap().into();
        repo.branch = "main".into();
        let plan = commands(&[repo], selected()).unwrap().remove(0).unwrap();
        let mut clone = plan.clone;
        // The durable fixture owns a random loopback port, never a real
        // credential listener. Only the fixed ingress origin is substituted.
        for arg in &mut clone {
            *arg = arg.replace("http://127.0.0.1:38081", &format!("http://{address}"));
        }
        let output = bounded_output(
            tokio::process::Command::new(&clone[0])
                .args(&clone[1..])
                .env("GIT_CONFIG_COUNT", "999")
                .env("GIT_EXEC_PATH", "/ambient/forbidden")
                .env("GIT_DIR", "/ambient/forbidden")
                .env("GIT_WORK_TREE", "/ambient/forbidden")
                .env("GIT_ASKPASS", "/ambient/forbidden")
                .env("GIT_CONFIG_GLOBAL", "/ambient/forbidden")
                .env("HTTP_PROXY", "http://127.0.0.1:1")
                .env("http_proxy", "http://127.0.0.1:1")
                .env("ALL_PROXY", "http://127.0.0.1:1"),
        )
        .await;
        if redirect {
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("302"));
        } else {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                std::fs::read(destination.join("README")).unwrap(),
                b"fixture\n"
            );
            let origin = git()
                .arg("-C")
                .arg(&destination)
                .args(["config", "--get", "remote.origin.url"])
                .output()
                .unwrap();
            assert_eq!(origin.stdout, format!("{source}\n").as_bytes());
            let config = std::fs::read_to_string(destination.join(".git/config")).unwrap();
            assert!(!config.contains("127.0.0.1"));
            assert!(!config.contains("insteadOf"));
            let checkout = plan.checkout.unwrap();
            let output =
                bounded_output(tokio::process::Command::new(&checkout[0]).args(&checkout[1..]))
                    .await;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let requests = fixture.requests.lock().unwrap();
        assert!(!requests.is_empty());
        assert!(
            requests
                .iter()
                .all(|uri| uri.starts_with("/_codewire/github/owner/app.git/"))
        );
        if redirect {
            assert_eq!(requests.len(), 1);
        } else {
            assert!(requests.iter().any(|uri| uri.ends_with("git-upload-pack")));
        }
        server.abort();
    }

    /// Every GitHub form reaches the same bridge path, and the origin keeps
    /// the form the user wrote.
    #[tokio::test]
    async fn real_git_fetches_through_bridge_with_ambient_inputs_cleared_and_clean_origin() {
        for source in [
            "https://github.com/owner/app.git",
            "git://github.com/owner/app.git",
            "git@github.com:owner/app.git",
            "ssh://git@github.com/owner/app.git",
        ] {
            run(false, source).await;
        }
    }

    #[tokio::test]
    async fn real_git_rejects_redirects_without_following_them() {
        run(true, "https://github.com/owner/app.git").await;
        run(true, "git@github.com:owner/app.git").await;
    }
}
