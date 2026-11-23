//! A secret key or project that isn't there, or a name already taken. Both
//! placements say so in one sentence that names it and the command that
//! lists what is there, and exit 1; no store error text reaches the user
//! (docs/dev/CLI-PARITY.md, S2 and S3).

use codewire_client::{ClientError, ErrorCode};

use super::StoragePlacement;

/// Which keys a key command names.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SecretScope<'a> {
    User,
    Organization,
    Project(&'a str),
}

/// What a key command was asked to change.
#[derive(Clone, Copy, Debug)]
pub(crate) enum KeyChange<'a> {
    Delete(&'a str),
    Rename { key: &'a str, new_key: &'a str },
}

impl<'a> KeyChange<'a> {
    pub(crate) fn rename(key: &'a str, new_key: &'a str) -> Self {
        KeyChange::Rename { key, new_key }
    }

    fn done(self) -> &'static str {
        match self {
            KeyChange::Delete(_) => "deleted",
            KeyChange::Rename { .. } => "renamed",
        }
    }

    fn context(self) -> &'static str {
        match self {
            KeyChange::Delete(_) => "delete secret",
            KeyChange::Rename { .. } => "rename secret",
        }
    }
}

fn word(placement: StoragePlacement) -> &'static str {
    match placement {
        StoragePlacement::Local => "local",
        StoragePlacement::Platform => "cloud",
    }
}

/// `key` in `scope` said in words, and the list flags that show the scope.
fn scoped(word: &str, scope: SecretScope<'_>, key: &str) -> (String, String) {
    match scope {
        SecretScope::User => (format!("{word} user secret {key}"), "--user".to_owned()),
        SecretScope::Organization => (
            format!("{word} organization secret {key}"),
            "--organization".to_owned(),
        ),
        SecretScope::Project(project) => (
            format!("{word} secret {key} in project {project:?}"),
            format!("--project={project}"),
        ),
    }
}

/// That the key `change` names isn't in `scope` at `placement` (or, for a
/// rename, that its new name is taken), so nothing changed, and the command
/// that lists what is there. A cloud refusal keeps the id of the trace its
/// answer named.
fn unchanged(
    placement: StoragePlacement,
    scope: SecretScope<'_>,
    change: KeyChange<'_>,
    taken: bool,
    trace_id: Option<&str>,
) -> anyhow::Error {
    let word = word(placement);
    let done = change.done();
    let message = match (change, taken) {
        (KeyChange::Rename { new_key, .. }, true) => {
            let (what, _) = scoped(word, scope, new_key);
            format!("{what} already exists, so nothing was {done}")
        }
        (KeyChange::Delete(key) | KeyChange::Rename { key, .. }, _) => {
            let (what, _) = scoped(word, scope, key);
            format!("there is no {what}, so nothing was {done}")
        }
    };
    let (_, list) = scoped(word, scope, "");
    crate::error_report::with_next_step(
        crate::reworded::reworded(message, trace_id),
        format!("cw --{word} secrets {list} list"),
    )
}

/// A cloud key change's outcome: the service's not-found or already-exists
/// as [`unchanged`].
pub(crate) fn cloud_changed(
    result: anyhow::Result<()>,
    scope: SecretScope<'_>,
    change: KeyChange<'_>,
) -> anyhow::Result<()> {
    result.map_err(|error| {
        let trace_id = crate::error_report::trace_id(&error);
        match cloud_code(&error) {
            Some(ErrorCode::NotFound) => {
                unchanged(StoragePlacement::Platform, scope, change, false, trace_id)
            }
            Some(ErrorCode::AlreadyExists) => {
                unchanged(StoragePlacement::Platform, scope, change, true, trace_id)
            }
            _ => error.context(change.context()),
        }
    })
}

/// A cloud rename's outcome: the service's not-found or already-exists as
/// [`unchanged`].
pub(crate) fn cloud_renamed(
    result: anyhow::Result<()>,
    scope: SecretScope<'_>,
    key: &str,
    new_key: &str,
) -> anyhow::Result<()> {
    cloud_changed(result, scope, KeyChange::rename(key, new_key))
}

/// A cloud delete's outcome: the service's not-found as [`unchanged`].
pub(crate) fn cloud_deleted(
    result: anyhow::Result<()>,
    scope: SecretScope<'_>,
    key: &str,
) -> anyhow::Result<()> {
    cloud_changed(result, scope, KeyChange::Delete(key))
}

/// A local key change's outcome: the store's not-found or already-exists as
/// [`unchanged`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn local_changed<T>(
    result: Result<T, tonic::Status>,
    scope: SecretScope<'_>,
    change: KeyChange<'_>,
) -> anyhow::Result<T> {
    result.map_err(|status| match status.code() {
        tonic::Code::NotFound => unchanged(StoragePlacement::Local, scope, change, false, None),
        tonic::Code::AlreadyExists => unchanged(StoragePlacement::Local, scope, change, true, None),
        _ => anyhow::Error::new(status).context(change.context()),
    })
}

/// The first service error code in `error`'s chain.
fn cloud_code(error: &anyhow::Error) -> Option<ErrorCode> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ClientError>())
        .map(ClientError::code)
}

/// That no secret project named `name` is at `placement`, and the command
/// that lists them.
pub(crate) fn no_such_project(placement: StoragePlacement, name: &str) -> anyhow::Error {
    let word = word(placement);
    crate::error_report::with_next_step(
        anyhow::anyhow!("there is no {word} secret project {name:?}"),
        format!("cw --{word} secrets projects list"),
    )
}

/// That more than one secret project at `placement` has `name`, so it must
/// be named by its ID.
pub(crate) fn ambiguous_project(placement: StoragePlacement, name: &str) -> anyhow::Error {
    let word = word(placement);
    crate::error_report::with_next_step(
        anyhow::anyhow!(
            "more than one {word} secret project is named {name:?}; name it by its ID as id:ID"
        ),
        format!("cw --{word} secrets projects list"),
    )
}

fn project_taken(placement: StoragePlacement, name: &str, trace_id: Option<&str>) -> anyhow::Error {
    let word = word(placement);
    crate::error_report::with_next_step(
        crate::reworded::reworded(
            format!("a {word} secret project named {name:?} already exists"),
            trace_id,
        ),
        format!("cw --{word} secrets projects list"),
    )
}

/// A cloud project create's outcome: the service's already-exists as one
/// sentence naming the project.
pub(crate) fn cloud_project_created<T>(result: anyhow::Result<T>, name: &str) -> anyhow::Result<T> {
    result.map_err(|error| match cloud_code(&error) {
        Some(ErrorCode::AlreadyExists) => project_taken(
            StoragePlacement::Platform,
            name,
            crate::error_report::trace_id(&error),
        ),
        _ => error.context("create secret project"),
    })
}

/// A local project create's outcome: the store's already-exists as one
/// sentence naming the project.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn local_project_created<T>(
    result: Result<T, tonic::Status>,
    name: &str,
) -> anyhow::Result<T> {
    result.map_err(|status| match status.code() {
        tonic::Code::AlreadyExists => project_taken(StoragePlacement::Local, name, None),
        _ => anyhow::Error::new(status).context("create secret project"),
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
                &local_changed(
                    Err::<(), _>(tonic::Status::not_found(
                        "local credential record was not found"
                    )),
                    SecretScope::Project("web"),
                    KeyChange::Delete("API_KEY")
                )
                .unwrap_err()
            ),
            says(
                "there is no local secret API_KEY in project \"web\", so nothing was deleted",
                "cw --local secrets --project=web list"
            )
        );
        assert_eq!(
            said(&unchanged(
                StoragePlacement::Platform,
                SecretScope::Organization,
                KeyChange::Delete("API_KEY"),
                false,
                None
            )),
            says(
                "there is no cloud organization secret API_KEY, so nothing was deleted",
                "cw --cloud secrets --organization list"
            )
        );
    }

    #[test]
    fn a_rename_names_the_missing_key_or_the_taken_name_in_both_placements() {
        let rename = KeyChange::Rename {
            key: "A",
            new_key: "B",
        };
        let cloud = |code, message| {
            Err(anyhow::Error::new(ClientError::new(code, message)).context("rename user secret"))
        };
        assert_eq!(
            said(
                &cloud_changed(
                    cloud(ErrorCode::NotFound, "secret not found"),
                    SecretScope::User,
                    rename
                )
                .unwrap_err()
            ),
            says(
                "there is no cloud user secret A, so nothing was renamed",
                "cw --cloud secrets --user list"
            )
        );
        assert_eq!(
            said(
                &cloud_changed(
                    cloud(ErrorCode::AlreadyExists, "secret already exists"),
                    SecretScope::Organization,
                    rename
                )
                .unwrap_err()
            ),
            says(
                "cloud organization secret B already exists, so nothing was renamed",
                "cw --cloud secrets --organization list"
            )
        );
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        for (status, message) in [
            (
                tonic::Status::not_found("local credential record was not found"),
                "there is no local user secret A, so nothing was renamed",
            ),
            (
                tonic::Status::already_exists("local credential record already exists"),
                "local user secret B already exists, so nothing was renamed",
            ),
        ] {
            assert_eq!(
                said(&local_changed(Err::<(), _>(status), SecretScope::User, rename).unwrap_err()),
                says(message, "cw --local secrets --user list")
            );
        }
    }

    #[test]
    fn a_project_is_named_when_missing_taken_or_ambiguous() {
        assert_eq!(
            said(&no_such_project(StoragePlacement::Local, "web")),
            says(
                "there is no local secret project \"web\"",
                "cw --local secrets projects list"
            )
        );
        assert_eq!(
            said(&ambiguous_project(StoragePlacement::Platform, "web")),
            says(
                "more than one cloud secret project is named \"web\"; name it by its ID as id:ID",
                "cw --cloud secrets projects list"
            )
        );
        let taken = Err::<(), _>(
            anyhow::Error::new(ClientError::new(
                ErrorCode::AlreadyExists,
                "secret project with this name already exists",
            ))
            .context("create secret project"),
        );
        assert_eq!(
            said(&cloud_project_created(taken, "web").unwrap_err()),
            says(
                "a cloud secret project named \"web\" already exists",
                "cw --cloud secrets projects list"
            )
        );
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert_eq!(
            said(
                &local_project_created(
                    Err::<(), _>(tonic::Status::already_exists(
                        "local credential record already exists"
                    )),
                    "web"
                )
                .unwrap_err()
            ),
            says(
                "a local secret project named \"web\" already exists",
                "cw --local secrets projects list"
            )
        );
    }
    /// A cloud refusal in cw's words keeps the id of the trace its answer
    /// named (docs/CONFIGURATION.md, "Tracing").
    #[test]
    fn a_cloud_refusal_keeps_its_trace_id() {
        use crate::error_report::trace_id;
        use crate::reworded::{TRACE_FOR_TESTS, answered_for_tests};
        let missing = Err(anyhow::Error::new(answered_for_tests(
            connectrpc::ConnectError::not_found("secret not found"),
            "NOT_FOUND",
        )));
        let error = cloud_renamed(missing, SecretScope::User, "A", "B").unwrap_err();
        assert_eq!(
            said(&error).0,
            "there is no cloud user secret A, so nothing was renamed"
        );
        assert_eq!(trace_id(&error), Some(TRACE_FOR_TESTS));
        let taken = Err::<(), _>(anyhow::Error::new(answered_for_tests(
            connectrpc::ConnectError::already_exists("taken"),
            "ALREADY_EXISTS",
        )));
        let error = cloud_project_created(taken, "web").unwrap_err();
        assert_eq!(trace_id(&error), Some(TRACE_FOR_TESTS));
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
