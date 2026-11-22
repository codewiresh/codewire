//! A delete of a secret key that isn't there. Both placements say nothing
//! was deleted, in one sentence, and exit 1 (docs/dev/CLI-PARITY.md, S3).

use codewire_client::{ClientError, ErrorCode};

use super::StoragePlacement;

/// Which keys a key command names.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SecretScope<'a> {
    User,
    Organization,
    Project(&'a str),
}

/// That `key` isn't in `scope` at `placement`, so nothing was deleted, and
/// the command that lists what is there.
pub(crate) fn nothing_deleted(
    placement: StoragePlacement,
    scope: SecretScope<'_>,
    key: &str,
) -> anyhow::Error {
    let word = match placement {
        StoragePlacement::Local => "local",
        StoragePlacement::Platform => "cloud",
    };
    let (what, list) = match scope {
        SecretScope::User => (format!("{word} user secret {key}"), "--user".to_owned()),
        SecretScope::Organization => (
            format!("{word} organization secret {key}"),
            "--organization".to_owned(),
        ),
        SecretScope::Project(project) => (
            format!("{word} secret {key} in project {project:?}"),
            format!("--project={project}"),
        ),
    };
    crate::error_report::with_next_step(
        anyhow::anyhow!("there is no {what}, so nothing was deleted"),
        format!("cw --{word} secrets {list} list"),
    )
}

/// A cloud delete's outcome: the service's not-found as [`nothing_deleted`].
pub(crate) fn cloud_deleted(
    result: anyhow::Result<()>,
    scope: SecretScope<'_>,
    key: &str,
) -> anyhow::Result<()> {
    result.map_err(|error| {
        let missing = error
            .chain()
            .filter_map(|cause| cause.downcast_ref::<ClientError>())
            .any(|cause| cause.code() == ErrorCode::NotFound);
        if missing {
            nothing_deleted(StoragePlacement::Platform, scope, key)
        } else {
            error.context("delete secret")
        }
    })
}

/// A local delete's outcome: the store's not-found as [`nothing_deleted`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn local_deleted(
    result: Result<(), tonic::Status>,
    scope: SecretScope<'_>,
    key: &str,
) -> anyhow::Result<()> {
    result.map_err(|status| {
        if status.code() == tonic::Code::NotFound {
            nothing_deleted(StoragePlacement::Local, scope, key)
        } else {
            anyhow::Error::new(status).context("delete local secret")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_report::NextStep;

    fn said(error: &anyhow::Error) -> (String, Option<String>) {
        (
            error.root_cause().to_string(),
            error.downcast_ref::<NextStep>().map(ToString::to_string),
        )
    }

    fn says(message: &str, step: &str) -> (String, Option<String>) {
        (message.to_owned(), Some(step.to_owned()))
    }

    #[test]
    fn a_missing_key_says_nothing_was_deleted_in_both_placements() {
        let missing = Err(anyhow::Error::new(ClientError::new(
            ErrorCode::NotFound,
            "secret not found",
        ))
        .context("delete user secret"));
        assert_eq!(
            said(&cloud_deleted(missing, SecretScope::User, "API_KEY").unwrap_err()),
            says(
                "there is no cloud user secret API_KEY, so nothing was deleted",
                "cw --cloud secrets --user list"
            )
        );
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert_eq!(
            said(
                &local_deleted(
                    Err(tonic::Status::not_found(
                        "local credential record was not found"
                    )),
                    SecretScope::Project("web"),
                    "API_KEY"
                )
                .unwrap_err()
            ),
            says(
                "there is no local secret API_KEY in project \"web\", so nothing was deleted",
                "cw --local secrets --project=web list"
            )
        );
        assert_eq!(
            said(&nothing_deleted(
                StoragePlacement::Platform,
                SecretScope::Organization,
                "API_KEY"
            )),
            says(
                "there is no cloud organization secret API_KEY, so nothing was deleted",
                "cw --cloud secrets --organization list"
            )
        );
    }

    #[test]
    fn other_failures_keep_their_reason() {
        let refused = Err(anyhow::Error::new(ClientError::new(
            ErrorCode::PermissionDenied,
            "only owners and admins can manage secrets",
        )));
        let error = cloud_deleted(refused, SecretScope::Organization, "API_KEY").unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "delete secret: only owners and admins can manage secrets"
        );
        assert!(error.downcast_ref::<NextStep>().is_none());
        assert!(cloud_deleted(Ok(()), SecretScope::User, "API_KEY").is_ok());
    }
}
