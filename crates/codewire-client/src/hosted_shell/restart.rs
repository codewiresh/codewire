//! Waiting out an environment's restart (#4342). A sandbox coming back, such
//! as one whose runtime is being replaced (#4311), is `starting` toward
//! `started`, and the server answers its sessions `Unavailable` until it runs
//! again. A dropped connection gets the same answer, so a client reads the
//! environment's state to tell the two apart. A restart is waited out for as
//! long as the server says it lasts, up to [`RESTART_LIMIT`]: a slow one, such
//! as a Confidential activation queued for its host, is still a restart and
//! not a lost network, but a script or an agent never waits forever.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

use super::{HostedShellError, SHELL_GRACE};
use crate::{
    ClientError, CodewireClient, DesiredState, Environment, EnvironmentState, ErrorCode,
    GetEnvironmentRequest,
};

/// How often to ask whether a restarting environment runs again, when the
/// server doesn't say.
const RESTART_POLL: Duration = Duration::from_secs(5);

/// The longest a client waits for one restart. Above the server's own bound
/// on a slow one: a Confidential activation waits up to 30 minutes for a slot
/// on its host before its readiness deadline starts.
pub const RESTART_LIMIT: Duration = Duration::from_secs(45 * 60);

/// Whether the environment is coming back from a restart: starting toward
/// started, the state in which the server answers sessions `Unavailable`.
pub fn is_restarting(environment: &Environment) -> bool {
    environment.state.as_known() == Some(EnvironmentState::Starting)
        && environment.desired_state.as_known() == Some(DesiredState::Started)
}

/// A failure that may carry the server's answer.
pub trait ServerAnswer {
    fn server_answer(&self) -> Option<&ClientError>;
}

impl ServerAnswer for HostedShellError {
    fn server_answer(&self) -> Option<&ClientError> {
        match self {
            HostedShellError::Client(error) => Some(error),
            HostedShellError::Other(error) => error.downcast_ref(),
        }
    }
}

impl ServerAnswer for anyhow::Error {
    fn server_answer(&self) -> Option<&ClientError> {
        self.downcast_ref()
    }
}

/// The environment as the server has it now, and how soon to ask again.
pub type EnvironmentAnswer = Result<(Environment, Option<Duration>), ClientError>;

/// Ask the server for the environment.
pub async fn ask_environment(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> EnvironmentAnswer {
    let response = client
        .get_environment(GetEnvironmentRequest {
            org_id: org_id.into(),
            environment_id: environment_id.into(),
            ..Default::default()
        })
        .await?;
    let poll = response.poll_interval.as_option().and_then(|interval| {
        let interval = Duration::new(
            u64::try_from(interval.seconds).ok()?,
            u32::try_from(interval.nanos).ok()?,
        );
        (!interval.is_zero()).then_some(interval)
    });
    let environment = response
        .environment
        .into_option()
        .ok_or_else(|| ClientError::new(ErrorCode::Internal, "the server sent no environment"))?;
    Ok((environment, poll))
}

/// Whether a call failed because the environment is restarting. Only an
/// `Unavailable` answer can mean that, and the environment's state decides.
pub async fn failed_for_restart<Ask, Asked>(ask: &Ask, error: &impl ServerAnswer) -> bool
where
    Ask: Fn() -> Asked,
    Asked: Future<Output = EnvironmentAnswer>,
{
    error
        .server_answer()
        .is_some_and(|error| error.code() == ErrorCode::Unavailable)
        && ask()
            .await
            .is_ok_and(|(environment, _)| is_restarting(&environment))
}

/// Wait until a restarting environment runs again, asking at the server's
/// pace. It ends with the state the environment came back in if that isn't
/// running, when the server can't be reached for [`SHELL_GRACE`], and after
/// [`RESTART_LIMIT`].
pub async fn wait_for_restart<Ask, Asked>(ask: &Ask) -> Result<(), HostedShellError>
where
    Ask: Fn() -> Asked,
    Asked: Future<Output = EnvironmentAnswer>,
{
    let started = Instant::now();
    let mut answered = started;
    let mut poll = RESTART_POLL;
    loop {
        if started.elapsed() >= RESTART_LIMIT {
            return Err(anyhow::anyhow!(
                "the environment was still restarting after {} minutes",
                RESTART_LIMIT.as_secs() / 60
            )
            .into());
        }
        tokio::time::sleep(poll).await;
        match ask().await {
            Ok((environment, interval)) => {
                answered = Instant::now();
                poll = interval.unwrap_or(RESTART_POLL);
                if is_restarting(&environment) {
                    continue;
                }
                if environment.state.as_known() == Some(EnvironmentState::Running) {
                    return Ok(());
                }
                return Err(anyhow::anyhow!(
                    "the environment did not come back from its restart: it is {}{}",
                    state_name(&environment),
                    match environment.error_reason.trim() {
                        "" => String::new(),
                        reason => format!(" ({reason})"),
                    }
                )
                .into());
            }
            Err(error) if is_network_failure(&error) => {
                if answered.elapsed() >= SHELL_GRACE {
                    return Err(anyhow::anyhow!(
                        "the connection to the environment was lost for 10 minutes while it restarted"
                    )
                    .into());
                }
                poll = RESTART_POLL;
            }
            Err(error) => return Err(HostedShellError::Client(error)),
        }
    }
}

/// Make a first call to an environment's sessions through a restart. A call
/// refused because the environment is restarting tells `restarting`, waits
/// until it runs again, and is then retried as a reconnect is, since the
/// environment's daemon starts after it and answers `Unavailable` until it
/// does. Any other failure is the call's own.
pub async fn through_restart<T, E, Ask, Asked, Call, Called>(
    ask: &Ask,
    mut restarting: impl FnMut(),
    mut call: Call,
) -> Result<T, E>
where
    E: ServerAnswer + From<HostedShellError>,
    Ask: Fn() -> Asked,
    Asked: Future<Output = EnvironmentAnswer>,
    Call: FnMut() -> Called,
    Called: Future<Output = Result<T, E>>,
{
    let mut ran_again: Option<Instant> = None;
    let mut attempt = 0_u32;
    loop {
        let error = match call().await {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        if failed_for_restart(ask, &error).await {
            restarting();
            wait_for_restart(ask).await?;
            ran_again = Some(Instant::now());
            attempt = 0;
            continue;
        }
        let daemon_starting = ran_again.is_some_and(|at| at.elapsed() < SHELL_GRACE)
            && error.server_answer().is_some_and(is_network_failure);
        if !daemon_starting {
            return Err(error);
        }
        attempt += 1;
        tokio::time::sleep(Duration::from_millis(250 * u64::from(attempt.min(8)))).await;
    }
}

/// Whether a failure says nothing about the environment: the server wasn't
/// reached or didn't answer in time.
pub fn is_network_failure(error: &ClientError) -> bool {
    error.is_retryable_transport_interruption() || error.code() == ErrorCode::DeadlineExceeded
}

fn state_name(environment: &Environment) -> &'static str {
    match environment.state.as_known() {
        Some(EnvironmentState::Pending) => "pending",
        Some(EnvironmentState::PendingBuild) => "pending a build",
        Some(EnvironmentState::Building) => "building",
        Some(EnvironmentState::BuildFailed) => "build failed",
        Some(EnvironmentState::PullingSnapshot) => "pulling a snapshot",
        Some(EnvironmentState::Creating) => "creating",
        Some(EnvironmentState::Starting) => "starting",
        Some(EnvironmentState::Running) => "running",
        Some(EnvironmentState::Stopping) => "stopping",
        Some(EnvironmentState::Stopped) => "stopped",
        Some(EnvironmentState::Archiving) => "archiving",
        Some(EnvironmentState::Archived) => "archived",
        Some(EnvironmentState::Restoring) => "restoring",
        Some(EnvironmentState::Resizing) => "resizing",
        Some(EnvironmentState::Destroying) => "destroying",
        Some(EnvironmentState::Destroyed) => "destroyed",
        Some(EnvironmentState::Error) => "in error",
        Some(EnvironmentState::Unspecified | EnvironmentState::Unknown) | None => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;

    fn environment(state: EnvironmentState, desired: DesiredState) -> Environment {
        Environment {
            state: state.into(),
            desired_state: desired.into(),
            ..Default::default()
        }
    }

    fn restarting() -> EnvironmentAnswer {
        Ok((
            environment(EnvironmentState::Starting, DesiredState::Started),
            None,
        ))
    }

    fn running() -> EnvironmentAnswer {
        Ok((
            environment(EnvironmentState::Running, DesiredState::Started),
            None,
        ))
    }

    fn unavailable(message: &str) -> ClientError {
        ClientError::new(ErrorCode::Unavailable, message)
    }

    /// The server's answers, in order; the last one repeats.
    fn answers(
        answers: Vec<EnvironmentAnswer>,
    ) -> impl Fn() -> std::future::Ready<EnvironmentAnswer> {
        let answers = RefCell::new(VecDeque::from(answers));
        move || {
            let mut answers = answers.borrow_mut();
            let next = if answers.len() > 1 {
                answers.pop_front().unwrap()
            } else {
                answers.front().unwrap().clone()
            };
            std::future::ready(next)
        }
    }

    #[test]
    fn only_starting_toward_started_is_a_restart() {
        assert!(is_restarting(&environment(
            EnvironmentState::Starting,
            DesiredState::Started
        )));
        for (state, desired) in [
            (EnvironmentState::Starting, DesiredState::Stopped),
            (EnvironmentState::Running, DesiredState::Started),
            (EnvironmentState::Creating, DesiredState::Started),
            (EnvironmentState::Stopped, DesiredState::Stopped),
            (EnvironmentState::Error, DesiredState::Started),
        ] {
            assert!(
                !is_restarting(&environment(state, desired)),
                "{state:?} {desired:?}"
            );
        }
    }

    #[tokio::test]
    async fn only_an_unavailable_answer_from_a_restarting_environment_is_a_restart() {
        let ask = answers(vec![restarting()]);
        assert!(failed_for_restart(&ask, &HostedShellError::Client(unavailable("starting"))).await);
        let refused = ClientError::new(ErrorCode::FailedPrecondition, "must be running");
        assert!(!failed_for_restart(&ask, &HostedShellError::Client(refused)).await);
        let ask = answers(vec![running()]);
        assert!(!failed_for_restart(&ask, &HostedShellError::Client(unavailable("reset"))).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_longer_than_the_network_budget_is_waited_out() {
        let started = Instant::now();
        let mut waits = vec![restarting(); 200];
        waits.push(running());
        // 200 answers 5 s apart: well past the 10 minutes a lost network gets.
        wait_for_restart(&answers(waits)).await.unwrap();
        assert_eq!(started.elapsed(), RESTART_POLL * 201);
        assert!(started.elapsed() > SHELL_GRACE);
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_that_never_ends_is_given_up_after_the_limit() {
        let started = Instant::now();
        let error = wait_for_restart(&answers(vec![restarting()]))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "the environment was still restarting after 45 minutes"
        );
        assert!(started.elapsed() >= RESTART_LIMIT);
        assert!(started.elapsed() < RESTART_LIMIT + RESTART_POLL * 2);
    }

    #[tokio::test(start_paused = true)]
    async fn the_wait_asks_at_the_servers_pace() {
        let started = Instant::now();
        let paced = Ok((
            environment(EnvironmentState::Starting, DesiredState::Started),
            Some(Duration::from_secs(2)),
        ));
        wait_for_restart(&answers(vec![paced, restarting(), running()]))
            .await
            .unwrap();
        assert_eq!(
            started.elapsed(),
            RESTART_POLL + Duration::from_secs(2) + RESTART_POLL
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_that_ends_in_another_state_says_so() {
        let mut failed = environment(EnvironmentState::Error, DesiredState::Started);
        failed.error_reason = "the sandbox did not become ready".into();
        let error = wait_for_restart(&answers(vec![restarting(), Ok((failed, None))]))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "the environment did not come back from its restart: it is in error (the sandbox did not become ready)"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_network_lost_while_waiting_still_ends_after_the_budget() {
        let started = Instant::now();
        let error = wait_for_restart(&answers(vec![restarting(), Err(unavailable("reset"))]))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("lost for 10 minutes while it restarted")
        );
        assert!(started.elapsed() >= SHELL_GRACE);
        assert!(started.elapsed() < SHELL_GRACE + RESTART_POLL * 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_first_call_waits_out_a_restart_and_then_its_daemon() {
        let ask = answers(vec![restarting(), restarting(), running()]);
        let calls = RefCell::new(0);
        let told = RefCell::new(0);
        let value = through_restart(
            &ask,
            || *told.borrow_mut() += 1,
            || {
                *calls.borrow_mut() += 1;
                let answer = match *calls.borrow() {
                    // Refused while the sandbox starts, then while its daemon does.
                    1 => Err(HostedShellError::Client(unavailable(
                        "environment is starting",
                    ))),
                    2 | 3 => Err(HostedShellError::Client(unavailable(
                        "environment daemon is still starting",
                    ))),
                    _ => Ok("attached"),
                };
                std::future::ready(answer)
            },
        )
        .await
        .unwrap();
        assert_eq!(value, "attached");
        assert_eq!(*calls.borrow(), 4);
        assert_eq!(*told.borrow(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_first_call_with_no_restart_fails_at_once_as_before() {
        let started = Instant::now();
        let error = through_restart(
            &answers(vec![running()]),
            || panic!("no restart"),
            || std::future::ready(Err::<(), _>(HostedShellError::Client(unavailable("reset")))),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.server_answer().unwrap().code(),
            ErrorCode::Unavailable
        );
        assert_eq!(started.elapsed(), Duration::ZERO);
    }
}
