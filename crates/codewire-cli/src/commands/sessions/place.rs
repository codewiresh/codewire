//! Where a session runs, as `run` and `attach` say it, and the commands
//! that find it again.

use super::*;

/// Where a session runs, for what `run` and `attach` print: the
/// environment's name, its location, and the placement flag that finds it
/// again.
pub(super) struct SessionPlace {
    pub(super) environment: String,
    pub(super) location: String,
    pub(super) placement: &'static str,
}

impl SessionPlace {
    pub(super) fn of(target: &EnvironmentSessionTarget) -> Self {
        let (location, placement) = match target {
            #[cfg(unix)]
            EnvironmentSessionTarget::Host { .. } => ("host", ""),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            EnvironmentSessionTarget::NativeLocal { .. } => ("local VM", "--local "),
            EnvironmentSessionTarget::Platform { host, .. } => {
                return Self::platform(&target.current_target().name, host.as_deref());
            }
        };
        Self {
            environment: crate::commands::progress::terminal_text(&target.current_target().name),
            location: location.to_owned(),
            placement,
        }
    }

    /// A platform environment: on a host it is the host's VM, and its name
    /// is found again with no placement flag, as `cw` looks in both.
    pub(super) fn platform(environment: &str, host: Option<&str>) -> Self {
        Self {
            environment: crate::commands::progress::terminal_text(environment),
            location: match host {
                Some(_) => crate::commands::lifecycle_output::platform_location_label(host),
                None => "cloud".to_owned(),
            },
            placement: if host.is_some() { "" } else { "--cloud " },
        }
    }

    /// `cw --local attach app --session coding`.
    pub(super) fn reconnect(&self, session: &EnvironmentSessionView) -> String {
        format!(
            "cw {}attach {} --session {}",
            self.placement,
            self.environment,
            session_reference(session)
        )
    }

    /// `Started Claude Code in app/coding · local VM`.
    pub(super) fn started(
        &self,
        session: &EnvironmentSessionView,
        agent: Option<NativeAgent>,
        style: crate::output::Style,
    ) -> String {
        let what = match agent {
            Some(agent) => format!("{} in", agent.title()),
            None => "session".to_owned(),
        };
        let sep = style.separator();
        format!(
            "Started {what} {}/{}{sep}{}",
            self.environment,
            session_reference(session),
            self.location
        )
    }

    /// `Restarted session app/coding · local VM`.
    pub(super) fn restarted(
        &self,
        session: &EnvironmentSessionView,
        style: crate::output::Style,
    ) -> String {
        let sep = style.separator();
        format!(
            "Restarted session {}/{}{sep}{}",
            self.environment,
            session_reference(session),
            self.location
        )
    }

    /// What a foreground run says once its command ended: `Exited with
    /// status 3 · Output: cw --local logs app --session test · Restart: cw
    /// --local restart app --session test`.
    pub(super) fn ended_hint(
        &self,
        session: &EnvironmentSessionView,
        style: crate::output::Style,
    ) -> String {
        let ended = match session.exit_code {
            Some(0) => "Exited".to_owned(),
            Some(code) => format!("Exited with status {code}"),
            None => session.state.clone(),
        };
        let (placement, environment) = (self.placement, &self.environment);
        let reference = session_reference(session);
        let sep = style.separator();
        style.paint(
            crate::output::Role::Dim,
            &format!(
                "{ended}{sep}Output: cw {placement}logs {environment} --session {reference}{sep}Restart: cw {placement}restart {environment} --session {reference}"
            ),
        )
    }

    /// The key named here is the one [`AttachNavigationDecoder`] detaches
    /// on: a lowercase `d`, like the other prefix keys (#3185).
    pub(super) fn detach_hint(
        &self,
        session: &EnvironmentSessionView,
        style: crate::output::Style,
    ) -> String {
        let sep = style.separator();
        style.paint(
            crate::output::Role::Dim,
            &format!(
                "Detach: Ctrl-B, then d{sep}Reconnect: {}",
                self.reconnect(session)
            ),
        )
    }
}

/// A session's name when it has one, else its canonical ID.
pub(super) fn session_reference(session: &EnvironmentSessionView) -> String {
    crate::commands::progress::terminal_text(if session.name.is_empty() {
        &session.session_id
    } else {
        &session.name
    })
}

/// The refusal of a `--name` an existing session holds. It starts with its
/// own words, not the environment's name, which the error report would
/// capitalize ("U5471a", #5471).
pub(super) fn duplicate_session_name(
    place: &SessionPlace,
    existing: &EnvironmentSessionView,
) -> anyhow::Error {
    let name = &existing.name;
    let environment = &place.environment;
    let placement = place.placement;
    let state = existing.state.to_lowercase();
    if existing.cleanup_unknown {
        anyhow::anyhow!("{}", cleanup_unknown_refusal(place, name))
    } else if session_is_terminal(existing) {
        anyhow::anyhow!(
            "a session named {name} already exists in {environment} ({state}); `--name` never reuses one: restart it with `cw {placement}restart {environment} --session {name}`, or choose another --name"
        )
    } else {
        anyhow::anyhow!(
            "a session named {name} already exists in {environment} ({state}); `--name` never reuses one: attach with `cw {placement}attach {environment} --session {name}`, or choose another --name"
        )
    }
}

/// Why a session whose cleanup is unknown cannot be restarted, and what ends
/// its processes so it can be (#5471).
pub(super) fn cleanup_unknown_refusal(place: &SessionPlace, name: &str) -> String {
    let environment = &place.environment;
    let placement = place.placement;
    if place.location == "host" {
        format!(
            "session {name}'s processes may still be running on this host, so it is not restarted; end them, then run `cw restart {environment} --session {name}`"
        )
    } else {
        format!(
            "session {name}'s processes may still be running, because their end could not be confirmed, so it is not restarted; `cw {placement}stop {environment}` then `cw {placement}start {environment}` ends them, and then `cw {placement}restart {environment} --session {name}` starts it again"
        )
    }
}

/// The name of the host `environment_id` runs on, when it runs on one. A
/// lookup that fails names none; the command's own call reports the failure.
pub(super) async fn environment_host(
    client: &codewire_client::CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> Option<String> {
    let response = client
        .get_environment(codewire_client::GetEnvironmentRequest {
            org_id: org_id.to_owned(),
            environment_id: environment_id.to_owned(),
            ..Default::default()
        })
        .await
        .ok()?;
    let host = response.environment.into_option()?.host.into_option()?;
    Some(host.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(name: &str) -> EnvironmentSessionView {
        EnvironmentSessionView {
            session_id: "session-1".into(),
            name: name.into(),
            parent_session_id: String::new(),
            cleanup_unknown: false,
            started_at: String::new(),
            launch_generation: 1,
            state: "running".into(),
            command: vec!["sh".into()],
            working_dir: String::new(),
            pty: true,
            exit_code: None,
            output_end_offset: 0,
            output_start_offset: 0,
            status_message: String::new(),
        }
    }

    /// An environment on a host is its host's VM, never `cloud`, and its
    /// commands carry no `--cloud`: `cw` finds the name in either placement
    /// (#6397).
    #[test]
    fn an_environment_on_a_host_is_its_hosts_vm_with_no_placement_flag() {
        let unicode = crate::output::Style::new(false, crate::output::Charset::Unicode);
        let place = SessionPlace::platform("h4-env", Some("cw-hosts-h4"));
        assert_eq!(
            place.started(&session("sh"), None, unicode),
            "Started session h4-env/sh · VM on host cw-hosts-h4"
        );
        assert_eq!(
            place.reconnect(&session("sh")),
            "cw attach h4-env --session sh"
        );
        assert_eq!(
            cleanup_unknown_refusal(&place, "sh"),
            "session sh's processes may still be running, because their end could not be confirmed, so it is not restarted; `cw stop h4-env` then `cw start h4-env` ends them, and then `cw restart h4-env --session sh` starts it again"
        );
        let cloud = SessionPlace::platform("app", None);
        assert_eq!(
            cloud.started(&session("sh"), None, unicode),
            "Started session app/sh · cloud"
        );
        assert_eq!(
            cloud.reconnect(&session("sh")),
            "cw --cloud attach app --session sh"
        );
    }

    #[test]
    fn ascii_charset_emits_only_ascii_separators_for_session_messages() {
        let ascii = crate::output::Style::new(false, crate::output::Charset::Ascii);
        let cloud = SessionPlace::platform("app", None);
        let mut s = session("sh");
        s.exit_code = Some(1);
        let lines = [
            cloud.started(&s, None, ascii),
            cloud.restarted(&s, ascii),
            cloud.ended_hint(&s, ascii),
            cloud.detach_hint(&s, ascii),
        ];
        assert_eq!(lines[0], "Started session app/sh - cloud");
        assert_eq!(lines[1], "Restarted session app/sh - cloud");
        assert_eq!(
            lines[2],
            "Exited with status 1 - Output: cw --cloud logs app --session sh - Restart: cw --cloud restart app --session sh"
        );
        assert_eq!(
            lines[3],
            "Detach: Ctrl-B, then d - Reconnect: cw --cloud attach app --session sh"
        );
        for line in &lines {
            assert!(line.is_ascii(), "expected pure ASCII line, got: {line}");
        }
    }
}
