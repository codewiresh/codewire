//! What to do about a failed local create, by the supervisor's closed
//! failure code (#4479).
//!
//! The supervisor adds fixed per-code hints of its own (`operation_error_hint`
//! in `codewire-local-vmm`), but its codes never carry a host or an image.
//! The registry hints here name the registry and the image this create asked
//! for, which only the CLI knows, so the CLI keeps them.

/// The image a create asked for: one named with `--image` or in
/// `codewire.yaml`, or the default workspace image.
pub(super) struct CreateImage(Option<String>);

impl CreateImage {
    /// From the project spec's image, empty for the default.
    pub(super) fn of(spec_image: &str) -> Self {
        Self((!spec_image.is_empty()).then(|| spec_image.to_owned()))
    }
}

/// A create's failed wait, as [`super::lifecycle::wait_failure`] gives it,
/// with the step that helps when the supervisor's code has one. The
/// supervisor's reason already says whether the failed environment was kept;
/// a lost wait (no stage) says what it knows on its own.
pub(super) fn wait_failure(
    progress: &super::NativeProgress,
    name: &str,
    status: tonic::Status,
    image: &CreateImage,
) -> (Option<&'static str>, anyhow::Error) {
    let code =
        codewire_local_vmm::supervisor_client::operation_error_code(&status).map(str::to_owned);
    match super::lifecycle::wait_failure(progress, "creation", name, status) {
        (Some(stage), error) => (Some(stage), explain(error, code.as_deref(), image)),
        lost => lost,
    }
}

/// The supervisor's failure, with the step that helps when its code has one.
pub(super) fn explain(
    error: anyhow::Error,
    code: Option<&str>,
    image: &CreateImage,
) -> anyhow::Error {
    match hint(code, image) {
        Some(hint) => {
            let failure = format!("{error:#}");
            anyhow::anyhow!(
                "the local VM runtime reported: {}; {hint}",
                failure.trim_end_matches('.')
            )
        }
        None => error,
    }
}

fn hint(code: Option<&str>, image: &CreateImage) -> Option<String> {
    let reference = image
        .0
        .as_deref()
        .unwrap_or(codewire_workspace_image::PUBLIC_IMAGE);
    let registry = registry_host(reference);
    Some(match code? {
        // The runtime's registry client honours the proxy environment, so a
        // proxy can be the cause; it never sends credentials.
        "create_registry_transport" => format!(
            "couldn't reach the image registry {registry}; check your connection, proxy or firewall, then create again"
        ),
        "create_registry_auth_required" | "create_registry_auth_failed" => format!(
            "{registry} refused {reference}: local environments pull images without credentials, so choose a public image"
        ),
        "create_registry_not_found" if image.0.is_some() => format!(
            "{registry} has no {reference}; check the image given with --image or in codewire.yaml"
        ),
        "create_registry_not_found" => format!(
            "{registry} has no {reference}, the default image; `cw upgrade` brings a cw that names a current one"
        ),
        "create_failed" => "it gave no cause; run `cw doctor`, then create again".to_owned(),
        _ => return None,
    })
}

/// The registry host of an image reference: its first component when that
/// names a host (it has a `.` or a `:`, or is `localhost`), otherwise Docker
/// Hub, as OCI clients read it.
fn registry_host(image: &str) -> &str {
    match image.split_once('/') {
        Some((first, _)) if first.contains('.') || first.contains(':') || first == "localhost" => {
            first
        }
        _ => "docker.io",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_create_names_the_registry_cause_and_next_step() {
        let ghcr = "ghcr.io/codewiresh/workspace@sha256:00";
        assert_eq!(registry_host(ghcr), "ghcr.io");
        assert_eq!(registry_host("localhost:5000/app"), "localhost:5000");
        assert_eq!(registry_host("ubuntu:24.04"), "docker.io");
        assert_eq!(registry_host("library/ubuntu"), "docker.io");
        let named = CreateImage::of(ghcr);
        assert_eq!(
            hint(Some("create_registry_transport"), &named).as_deref(),
            Some(
                "couldn't reach the image registry ghcr.io; check your connection, proxy or firewall, then create again"
            )
        );
        let auth = hint(Some("create_registry_auth_required"), &named).unwrap();
        assert!(auth.ends_with("so choose a public image"), "{auth}");
        assert!(
            !auth.contains("sign in"),
            "signing in can't help an anonymous pull"
        );
        assert_eq!(
            hint(
                Some("create_registry_not_found"),
                &CreateImage::of("registry.example/app:1")
            )
            .as_deref(),
            Some(
                "registry.example has no registry.example/app:1; check the image given with --image or in codewire.yaml"
            )
        );
        let default = hint(Some("create_registry_not_found"), &CreateImage::of("")).unwrap();
        assert!(default.contains("the default image"), "{default}");
        assert!(
            hint(Some("create_failed"), &named)
                .unwrap()
                .starts_with("it gave no cause")
        );
        assert_eq!(hint(Some("create_name_taken"), &named), None);
        assert_eq!(hint(None, &named), None);
    }

    #[test]
    fn the_hint_follows_the_failure_as_one_sentence() {
        let failure = anyhow::anyhow!("local lifecycle operation op-1 failed: create_failed.");
        assert_eq!(
            explain(failure, Some("create_failed"), &CreateImage::of("")).to_string(),
            "the local VM runtime reported: local lifecycle operation op-1 failed: create_failed; it gave no cause; run `cw doctor`, then create again"
        );
        let untouched = explain(
            anyhow::anyhow!("name taken"),
            Some("create_name_taken"),
            &CreateImage::of(""),
        );
        assert_eq!(untouched.to_string(), "name taken");
    }
}
