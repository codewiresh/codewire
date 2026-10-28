//! Which placement answers an environment reference when no `--local` or
//! `--cloud` is given (#3560). Both the local VMs and the cloud are asked.
//! A local VM supervisor that cannot be reached, or that refuses this cw,
//! never blocks a cloud environment ID: the cloud answers, and the notice
//! says so. A reference that names an environment on both sides, or that the
//! unchecked local side might also name, is reported, never guessed.

use super::progress::terminal_text;
use super::*;
use crate::output::{Capabilities, OutputMode, Status};

/// What the local VMs answered for a reference.
#[derive(Debug)]
pub(crate) enum LocalAnswer<T> {
    Found(T),
    Absent,
    /// The local VMs could not be asked: their supervisor could not be
    /// reached or refused this cw. Whether they hold the reference is
    /// unknown, not false.
    Unavailable(anyhow::Error),
}

impl LocalAnswer<codewire_local_vmm::control::v1::Environment> {
    /// Asks the local VM supervisor for `target_ref`, keeping a failure as
    /// an answer instead of ending the lookup.
    pub(crate) async fn ask(target_ref: &str) -> Self {
        match native_environment(target_ref).await {
            Ok(Some(environment)) => Self::Found(environment),
            Ok(None) => Self::Absent,
            Err(error) => Self::Unavailable(error),
        }
    }
}

/// Why the local VMs could not be asked, and the steps that recover when a
/// retry alone cannot (#3548).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalUnavailable {
    pub(crate) reason: String,
    pub(crate) recovery: Option<String>,
}

impl LocalUnavailable {
    pub(crate) fn from_error(error: &anyhow::Error) -> Self {
        match error
            .chain()
            .find_map(codewire_local_vmm::supervisor_client::supervisor_refusal)
        {
            Some(refusal) => Self {
                reason: refusal.summary(),
                recovery: refusal.recovery(),
            },
            None => Self {
                reason: format!("{error:#}"),
                recovery: None,
            },
        }
    }

    /// The reason, followed by its recovery when it has one.
    fn explained(&self) -> String {
        match &self.recovery {
            Some(recovery) => format!("{}. {recovery}", self.reason),
            None => self.reason.clone(),
        }
    }
}

/// The side that answers a reference.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PlacementChoice<T> {
    Local(T),
    /// The cloud environment with this ID. `local_unavailable` is set when
    /// the local VMs could not be asked; the cloud answered alone.
    Cloud {
        id: String,
        local_unavailable: Option<LocalUnavailable>,
    },
}

/// Chooses the side that answers `target_ref` from what each side answered,
/// once the cloud was asked. `ambiguous` is the caller's report for a
/// reference both sides hold.
///
/// - Found on one side only: that side answers.
/// - An exact match on both sides: reported, never guessed.
/// - A local VM's exact name and a cloud ID prefix: the exact match answers,
///   as `cw use` decides (`inventory::find_direct`).
/// - Local unavailable and the reference is an exact cloud environment ID:
///   the cloud answers. A local VM is found by an ID-shaped reference only
///   by its own ID, so the local side can never also hold it.
/// - Local unavailable and the reference is a cloud name or ID prefix: a
///   local VM may hold the same name, so it is refused with the `--cloud`
///   spelling that selects the cloud one.
/// - Found nowhere: not found, saying when the local side was not searched.
pub(crate) fn choose_placement<T>(
    target_ref: &str,
    local: LocalAnswer<T>,
    cloud: Option<(String, EnvironmentMatchKind)>,
    ambiguous: impl FnOnce() -> anyhow::Error,
) -> anyhow::Result<PlacementChoice<T>> {
    match (local, cloud) {
        (
            LocalAnswer::Found(_),
            Some((_, EnvironmentMatchKind::ExactId | EnvironmentMatchKind::ExactName)),
        ) => Err(ambiguous()),
        (LocalAnswer::Found(environment), Some((_, EnvironmentMatchKind::IdPrefix)) | None) => {
            Ok(PlacementChoice::Local(environment))
        }
        (LocalAnswer::Absent, Some((id, _))) => Ok(PlacementChoice::Cloud {
            id,
            local_unavailable: None,
        }),
        (LocalAnswer::Absent, None) => anyhow::bail!("environment {target_ref:?} not found"),
        (LocalAnswer::Unavailable(error), Some((id, EnvironmentMatchKind::ExactId))) => {
            Ok(PlacementChoice::Cloud {
                id,
                local_unavailable: Some(LocalUnavailable::from_error(&error)),
            })
        }
        (LocalAnswer::Unavailable(error), Some((id, _))) => {
            let local = LocalUnavailable::from_error(&error);
            anyhow::bail!(
                "local VMs could not be checked ({}), so {target_ref:?} may also name a local VM; add --cloud to use cloud environment {id}, or name it by that ID",
                local.explained()
            )
        }
        (LocalAnswer::Unavailable(error), None) => {
            let local = LocalUnavailable::from_error(&error);
            anyhow::bail!(
                "no cloud environment is named {target_ref:?}, and local VMs could not be checked: {}",
                local.explained()
            )
        }
    }
}

/// Says on stderr that the cloud answered alone because the local VMs could
/// not be asked.
pub(crate) fn report_cloud_answered(target_ref: &str, local: &LocalUnavailable) {
    let style = Capabilities::from_process(OutputMode::Text).stderr_style();
    eprint!("{}", cloud_answered_notice(target_ref, local, style));
}

pub(crate) fn cloud_answered_notice(
    target_ref: &str,
    local: &LocalUnavailable,
    style: crate::output::Style,
) -> String {
    let mut out = format!(
        "{} Local VMs could not be checked: {}\n  {} is a cloud environment; the cloud answered.\n",
        style.status(Status::Attention),
        terminal_text(&local.reason),
        terminal_text(target_ref),
    );
    if let Some(recovery) = &local.recovery {
        out.push_str(&format!(
            "{} {}\n",
            style.status(Status::Next),
            terminal_text(recovery)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_local_vmm::supervisor_client::{SupervisorRefusal, UdsError};

    const CLOUD_ID: &str = "0b7f6a52-3c1e-4d5a-9f0e-2a6c1d8e4b37";

    /// The error a local supervisor that refuses this cw's configuration
    /// gives, wrapped as the CLI wraps it.
    fn refused() -> anyhow::Error {
        anyhow::Error::new(UdsError::SupervisorPeerAdmission(SupervisorRefusal::Check(
            "role or configuration arguments do not match",
        )))
        .context("connect to native local supervisor")
    }

    /// The error a supervisor that runs a cw this one cannot verify gives.
    fn refused_unverified() -> anyhow::Error {
        anyhow::Error::new(UdsError::SupervisorPeerAdmission(
            SupervisorRefusal::Unverified {
                pid: 7,
                executable: "/src/target/debug/cw".into(),
            },
        ))
        .context("connect to native local supervisor")
    }

    /// A supervisor that cannot be reached at all.
    fn unreachable() -> anyhow::Error {
        anyhow::anyhow!("connection refused").context("connect to native local supervisor")
    }

    fn ambiguous() -> anyhow::Error {
        anyhow::anyhow!("ambiguous")
    }

    fn cloud(kind: EnvironmentMatchKind) -> Option<(String, EnvironmentMatchKind)> {
        Some((CLOUD_ID.to_owned(), kind))
    }

    #[test]
    fn a_refused_local_supervisor_never_blocks_a_cloud_id() {
        let choice = choose_placement::<()>(
            CLOUD_ID,
            LocalAnswer::Unavailable(refused()),
            cloud(EnvironmentMatchKind::ExactId),
            ambiguous,
        )
        .unwrap();
        assert_eq!(
            choice,
            PlacementChoice::Cloud {
                id: CLOUD_ID.to_owned(),
                local_unavailable: Some(LocalUnavailable {
                    reason: "native supervisor admission refused: role or configuration arguments do not match".to_owned(),
                    recovery: None,
                }),
            }
        );
    }

    #[test]
    fn an_unreachable_local_supervisor_never_blocks_a_cloud_id() {
        let PlacementChoice::Cloud {
            id,
            local_unavailable: Some(local),
        } = choose_placement::<()>(
            CLOUD_ID,
            LocalAnswer::Unavailable(unreachable()),
            cloud(EnvironmentMatchKind::ExactId),
            ambiguous,
        )
        .unwrap()
        else {
            panic!("the cloud answers a cloud ID");
        };
        assert_eq!(id, CLOUD_ID);
        assert_eq!(
            local.reason,
            "connect to native local supervisor: connection refused"
        );
    }

    #[test]
    fn an_unchecked_local_side_never_makes_a_name_or_prefix_unambiguous() {
        for kind in [
            EnvironmentMatchKind::ExactName,
            EnvironmentMatchKind::IdPrefix,
        ] {
            let error = choose_placement::<()>(
                "app",
                LocalAnswer::Unavailable(refused()),
                cloud(kind),
                ambiguous,
            )
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "local VMs could not be checked (native supervisor admission refused: role or configuration arguments do not match), so \"app\" may also name a local VM; add --cloud to use cloud environment {CLOUD_ID}, or name it by that ID"
                )
            );
        }
    }

    #[test]
    fn a_reference_found_nowhere_says_the_local_side_was_not_searched() {
        assert_eq!(
            choose_placement::<()>(
                "gone",
                LocalAnswer::Unavailable(refused_unverified()),
                None,
                ambiguous,
            )
            .unwrap_err()
            .to_string(),
            "no cloud environment is named \"gone\", and local VMs could not be checked: they are served by a cw this one cannot verify (process 7, /src/target/debug/cw), not an installed cw version. List its VMs with `/src/target/debug/cw --local ls` and stop any with `/src/target/debug/cw --local stop NAME`, then end it with `kill 7`; the next cw command starts this cw's own"
        );
        assert_eq!(
            choose_placement::<()>("gone", LocalAnswer::Absent, None, ambiguous)
                .unwrap_err()
                .to_string(),
            "environment \"gone\" not found"
        );
    }

    #[test]
    fn a_reference_on_both_sides_is_reported_never_guessed() {
        for kind in [
            EnvironmentMatchKind::ExactId,
            EnvironmentMatchKind::ExactName,
        ] {
            assert_eq!(
                choose_placement("app", LocalAnswer::Found("app"), cloud(kind), ambiguous)
                    .unwrap_err()
                    .to_string(),
                "ambiguous"
            );
        }
        // A local VM's exact name is a closer match than a cloud ID prefix.
        assert_eq!(
            choose_placement(
                "db",
                LocalAnswer::Found("db"),
                cloud(EnvironmentMatchKind::IdPrefix),
                ambiguous
            )
            .unwrap(),
            PlacementChoice::Local("db")
        );
    }

    #[test]
    fn one_side_answers_when_only_it_holds_the_reference() {
        assert_eq!(
            choose_placement("app", LocalAnswer::Found("app"), None, ambiguous).unwrap(),
            PlacementChoice::Local("app")
        );
        assert_eq!(
            choose_placement::<()>(
                "app",
                LocalAnswer::Absent,
                cloud(EnvironmentMatchKind::ExactName),
                ambiguous
            )
            .unwrap(),
            PlacementChoice::Cloud {
                id: CLOUD_ID.to_owned(),
                local_unavailable: None,
            }
        );
    }

    #[test]
    fn the_notice_says_the_cloud_answered_and_how_to_recover() {
        let plain = crate::output::Style::new(false, crate::output::Charset::Unicode);
        assert_eq!(
            cloud_answered_notice(CLOUD_ID, &LocalUnavailable::from_error(&refused()), plain),
            format!(
                "! Local VMs could not be checked: native supervisor admission refused: role or configuration arguments do not match\n  {CLOUD_ID} is a cloud environment; the cloud answered.\n"
            )
        );
        assert!(
            cloud_answered_notice(
                CLOUD_ID,
                &LocalUnavailable::from_error(&refused_unverified()),
                plain
            )
            .ends_with("→ List its VMs with `/src/target/debug/cw --local ls` and stop any with `/src/target/debug/cw --local stop NAME`, then end it with `kill 7`; the next cw command starts this cw's own\n")
        );
    }
}
