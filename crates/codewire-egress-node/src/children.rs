//! The child processes cw-egress starts from its own image (#4000): one
//! confined broker and one confined worker for each admitted Pod, and one
//! confined front door for a Pod that intercepts (#4001).
//!
//! The supervisor starts a child with a command word as its first argument.
//! `main` hands its arguments to [`run_child`] before it does anything else:
//! a child must still be single-threaded when it confines itself, so it runs
//! on a current-thread runtime, never the supervisor's.

use std::ffi::OsString;
use std::process::ExitCode;

use codewire_egress_worker::broker::{BrokerIntercepts, run_inherited_egress_broker_intercepting};
use codewire_egress_worker::hosted::{HOSTED_GENERATION, run_hosted_worker};
use uuid::Uuid;

use crate::front_door::run_inherited_front_door;

pub const BROKER_WORD: &str = "__egress-broker";
pub const WORKER_WORD: &str = "__egress-worker";
pub const FRONT_DOOR_WORD: &str = "__egress-front-door";
pub const POD_UID_FLAG: &str = "--pod-uid";
/// After a broker's Pod UID: it hands intercepted dials to the Pod's front
/// door.
pub const INTERCEPT_HANDOFF_FLAG: &str = "--intercept-handoff";
/// After a broker's Pod UID: it refuses intercepted dials, for a Pod whose
/// bindings no front door serves.
pub const INTERCEPT_REFUSE_FLAG: &str = "--intercept-refuse";
/// A broker's last flag: it reports its refusals on its control channel,
/// whose every frame the supervisor reads (SPEC.md "The refusal path").
/// Without it the broker sends nothing there but acknowledgements.
pub const REPORT_REFUSALS_FLAG: &str = "--report-refusals";

/// Exit status of a child whose command line is not one the supervisor
/// writes: the conventional status for a usage error.
const USAGE: u8 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Child {
    Broker {
        pod_uid: Uuid,
        intercepts: BrokerIntercepts,
        report_refusals: bool,
    },
    Worker(Uuid),
    FrontDoor(Uuid),
}

/// The child `arguments` name, `None` when they name none and the caller is
/// the supervisor, or an error for a first argument that looks like a command
/// word but is not a whole, valid one: nothing that was meant to be a child
/// ever becomes a supervisor.
fn child(arguments: impl IntoIterator<Item = OsString>) -> Option<Result<Child, ()>> {
    let mut arguments = arguments.into_iter().skip(1);
    let word = arguments.next()?;
    let word = word.to_str().filter(|word| word.starts_with("__"))?;
    let pod_uid = match (arguments.next(), arguments.next()) {
        (Some(flag), Some(pod_uid)) if flag == POD_UID_FLAG => {
            pod_uid.to_str().and_then(|text| Uuid::parse_str(text).ok())
        }
        _ => None,
    };
    // No child takes more than two flags after its Pod UID.
    let flags: Vec<OsString> = arguments.take(3).collect();
    Some(match (word, pod_uid) {
        (BROKER_WORD, Some(pod_uid)) => broker(pod_uid, &flags),
        (WORKER_WORD, Some(pod_uid)) if flags.is_empty() => Ok(Child::Worker(pod_uid)),
        (FRONT_DOOR_WORD, Some(pod_uid)) if flags.is_empty() => Ok(Child::FrontDoor(pod_uid)),
        _ => Err(()),
    })
}

/// A broker's flags after its Pod UID: what it does with intercepted dials,
/// then whether it reports its refusals, each at most once and in that order.
fn broker(pod_uid: Uuid, flags: &[OsString]) -> Result<Child, ()> {
    let mut flags = flags.iter().peekable();
    let intercepts = if flags
        .next_if(|flag| *flag == INTERCEPT_HANDOFF_FLAG)
        .is_some()
    {
        BrokerIntercepts::HandOff
    } else if flags
        .next_if(|flag| *flag == INTERCEPT_REFUSE_FLAG)
        .is_some()
    {
        BrokerIntercepts::Refuse
    } else {
        BrokerIntercepts::Off
    };
    let report_refusals = flags
        .next_if(|flag| *flag == REPORT_REFUSALS_FLAG)
        .is_some();
    if flags.next().is_some() {
        return Err(());
    }
    Ok(Child::Broker {
        pod_uid,
        intercepts,
        report_refusals,
    })
}

/// Runs the child `arguments` name to its end and returns its exit status,
/// or `None` when they name no child.
pub fn run_child(arguments: impl IntoIterator<Item = OsString>) -> Option<ExitCode> {
    let Ok(child) = child(arguments)? else {
        return Some(ExitCode::from(USAGE));
    };
    // No thread but this one: each child checks that before it confines
    // itself.
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return Some(ExitCode::FAILURE);
    };
    let status = runtime.block_on(async {
        match child {
            Child::Broker {
                pod_uid,
                intercepts,
                report_refusals,
            } => run_inherited_egress_broker_intercepting(
                pod_uid,
                HOSTED_GENERATION,
                intercepts,
                report_refusals,
            )
            .await
            .map_err(|error| error.exit_code()),
            Child::Worker(pod_uid) => run_hosted_worker(pod_uid)
                .await
                .map_err(|error| error.exit_code()),
            Child::FrontDoor(pod_uid) => run_inherited_front_door(pod_uid)
                .await
                .map_err(|error| error.exit_code()),
        }
    });
    Some(match status {
        Ok(()) => ExitCode::SUCCESS,
        // A status outside a byte cannot be reported as itself.
        Err(status) => u8::try_from(status).map_or(ExitCode::FAILURE, ExitCode::from),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const POD: &str = "0b0f7d1e-6c1c-4a55-9a5e-0d6d8c2f1a11";

    fn arguments(arguments: &[&str]) -> Vec<OsString> {
        arguments.iter().map(OsString::from).collect()
    }

    #[test]
    fn arguments_that_name_no_child_are_the_supervisors() {
        for supervisor in [
            &["cw-egress"][..],
            &["cw-egress", "--help"],
            &["cw-egress", "serve", POD_UID_FLAG, POD],
        ] {
            assert_eq!(child(arguments(supervisor)), None, "{supervisor:?}");
        }
    }

    #[test]
    fn each_command_word_names_its_child_for_one_pod() {
        let pod = Uuid::parse_str(POD).unwrap();
        assert_eq!(
            child(arguments(&["cw-egress", BROKER_WORD, POD_UID_FLAG, POD])),
            Some(Ok(Child::Broker {
                pod_uid: pod,
                intercepts: BrokerIntercepts::Off,
                report_refusals: false,
            }))
        );
        assert_eq!(
            child(arguments(&[
                "cw-egress",
                BROKER_WORD,
                POD_UID_FLAG,
                POD,
                INTERCEPT_HANDOFF_FLAG
            ])),
            Some(Ok(Child::Broker {
                pod_uid: pod,
                intercepts: BrokerIntercepts::HandOff,
                report_refusals: false,
            }))
        );
        assert_eq!(
            child(arguments(&[
                "cw-egress",
                BROKER_WORD,
                POD_UID_FLAG,
                POD,
                INTERCEPT_REFUSE_FLAG
            ])),
            Some(Ok(Child::Broker {
                pod_uid: pod,
                intercepts: BrokerIntercepts::Refuse,
                report_refusals: false,
            }))
        );
        assert_eq!(
            child(arguments(&["cw-egress", WORKER_WORD, POD_UID_FLAG, POD])),
            Some(Ok(Child::Worker(pod)))
        );
        assert_eq!(
            child(arguments(&[
                "cw-egress",
                FRONT_DOOR_WORD,
                POD_UID_FLAG,
                POD
            ])),
            Some(Ok(Child::FrontDoor(pod)))
        );
    }

    /// The broker reports its refusals only when the supervisor asks, after
    /// any interception flag; without the flag it reports none.
    #[test]
    fn a_broker_reports_refusals_only_when_its_command_line_asks() {
        let pod = Uuid::parse_str(POD).unwrap();
        for (flags, intercepts) in [
            (&[][..], BrokerIntercepts::Off),
            (&[INTERCEPT_HANDOFF_FLAG][..], BrokerIntercepts::HandOff),
            (&[INTERCEPT_REFUSE_FLAG][..], BrokerIntercepts::Refuse),
        ] {
            let mut line = vec!["cw-egress", BROKER_WORD, POD_UID_FLAG, POD];
            line.extend_from_slice(flags);
            line.push(REPORT_REFUSALS_FLAG);
            assert_eq!(
                child(arguments(&line)),
                Some(Ok(Child::Broker {
                    pod_uid: pod,
                    intercepts,
                    report_refusals: true,
                })),
                "{line:?}"
            );
        }
        for refused in [
            &[
                "cw-egress",
                BROKER_WORD,
                POD_UID_FLAG,
                POD,
                REPORT_REFUSALS_FLAG,
                INTERCEPT_REFUSE_FLAG,
            ][..],
            &[
                "cw-egress",
                BROKER_WORD,
                POD_UID_FLAG,
                POD,
                REPORT_REFUSALS_FLAG,
                REPORT_REFUSALS_FLAG,
            ],
            &[
                "cw-egress",
                WORKER_WORD,
                POD_UID_FLAG,
                POD,
                REPORT_REFUSALS_FLAG,
            ],
            &[
                "cw-egress",
                FRONT_DOOR_WORD,
                POD_UID_FLAG,
                POD,
                REPORT_REFUSALS_FLAG,
            ],
            &[
                "cw-egress",
                BROKER_WORD,
                POD_UID_FLAG,
                POD,
                INTERCEPT_HANDOFF_FLAG,
                REPORT_REFUSALS_FLAG,
                "extra",
            ],
        ] {
            assert_eq!(child(arguments(refused)), Some(Err(())), "{refused:?}");
        }
    }

    #[test]
    fn anything_that_looks_like_a_child_word_never_becomes_a_supervisor() {
        for refused in [
            &["cw-egress", "__egress-brokr", POD_UID_FLAG, POD][..],
            &["cw-egress", "__anything"],
            &["cw-egress", BROKER_WORD],
            &["cw-egress", BROKER_WORD, "--pod", POD],
            &["cw-egress", WORKER_WORD, POD_UID_FLAG, "not-a-uuid"],
            &["cw-egress", WORKER_WORD, POD_UID_FLAG, POD, "extra"],
            // Only a broker intercepts, and only with one flag after its Pod.
            &[
                "cw-egress",
                WORKER_WORD,
                POD_UID_FLAG,
                POD,
                INTERCEPT_REFUSE_FLAG,
            ],
            &[
                "cw-egress",
                BROKER_WORD,
                POD_UID_FLAG,
                POD,
                INTERCEPT_REFUSE_FLAG,
                INTERCEPT_HANDOFF_FLAG,
            ],
            &[
                "cw-egress",
                WORKER_WORD,
                POD_UID_FLAG,
                POD,
                INTERCEPT_HANDOFF_FLAG,
            ],
            &[
                "cw-egress",
                FRONT_DOOR_WORD,
                POD_UID_FLAG,
                POD,
                INTERCEPT_HANDOFF_FLAG,
            ],
            &[
                "cw-egress",
                BROKER_WORD,
                INTERCEPT_HANDOFF_FLAG,
                POD_UID_FLAG,
                POD,
            ],
            &["cw-egress", BROKER_WORD, POD_UID_FLAG, POD, "--intercept"],
            &[
                "cw-egress",
                BROKER_WORD,
                POD_UID_FLAG,
                POD,
                INTERCEPT_HANDOFF_FLAG,
                INTERCEPT_HANDOFF_FLAG,
            ],
            &["cw-egress", FRONT_DOOR_WORD],
        ] {
            assert_eq!(child(arguments(refused)), Some(Err(())), "{refused:?}");
        }
    }
}
