//! The configure-environment exec's defaults and Git author.

use super::*;

impl WorkerSetupOps<'_> {
    /// Publish the complete ordinary defaults before clone/install, including an
    /// empty map after clearing values, then set the creator's Git author, in
    /// one workspace exec: each exec costs about 0.2 s of attachment on the
    /// create critical path. Resolved application secrets never enter the
    /// defaults file; the first write gets canonical defaults as explicit
    /// overrides. A failed publication fails the phase; a failed author is a
    /// warning, as when it was its own exec.
    pub(super) async fn publish_defaults_and_git_identity(
        &self,
        namespace: &str,
    ) -> anyhow::Result<()> {
        let identity = self.resolve_git_identity().await;
        let cmd = build_configure_environment_command(
            &self.env.project_spec.environment,
            identity
                .as_ref()
                .map(|(email, name)| (email.as_str(), name.as_str())),
        );
        let result = self
            .workspace_exec(
                namespace,
                &self.env.id,
                &cmd,
                "",
                &self.env.project_spec.environment,
            )
            .await;
        match configure_environment_outcome(result, identity.is_some())? {
            GitIdentityOutcome::Unresolved => {}
            GitIdentityOutcome::Configured => {
                if let Some((email, name)) = &identity {
                    log_git_identity_configured(&self.env.id, email, name);
                }
            }
            GitIdentityOutcome::Failed(error) => log_git_identity_failed(&self.env.id, &error),
        }
        Ok(())
    }

    /// The creator's Git author as (email, name), or `None` with a warning
    /// when the creator or their user row cannot be read.
    async fn resolve_git_identity(&self) -> Option<(String, String)> {
        let env_id = &self.env.id;
        let created_by: Option<(String,)> =
            sqlx::query_as("SELECT created_by FROM environments WHERE id = $1")
                .bind(env_id)
                .fetch_optional(&self.ctx.pool)
                .await
                .unwrap_or(None);
        let Some((created_by,)) = created_by else {
            tracing::warn!(
                environment_id = env_id,
                "git-identity: could not resolve creator"
            );
            return None;
        };

        let user_row: Option<GitIdentityRow> =
            sqlx::query_as("SELECT git_name, git_email, name, email FROM users WHERE id = $1")
                .bind(&created_by)
                .fetch_optional(&self.ctx.pool)
                .await
                .unwrap_or(None);
        let Some((git_name, git_email, name, email)) = user_row else {
            tracing::warn!(user_id = created_by, "git-identity: could not load user");
            return None;
        };

        let resolved_name = resolve_git_field(git_name.as_deref(), name.as_deref(), &email);
        let resolved_email = match git_email.as_deref() {
            Some(email) if !email.is_empty() => email.to_string(),
            _ => email,
        };
        Some((resolved_email, resolved_name))
    }

    /// Applies non-secret Git author metadata through the fenced setup
    /// executor: restart's post-start configuration, after a Pod replacement.
    pub(super) async fn configure_git_identity(&self, namespace: &str) -> anyhow::Result<()> {
        let env_id = &self.env.id;
        let Some((resolved_email, resolved_name)) = self.resolve_git_identity().await else {
            return Ok(());
        };
        // One workspace exec sets both fields: each exec costs about 0.2 s of
        // attachment on the create and restart critical paths.
        let git_config_result = self
            .workspace_exec(
                namespace,
                env_id,
                &build_git_identity_command(&resolved_email, &resolved_name),
                "",
                &BTreeMap::new(),
            )
            .await;
        match git_config_result {
            Err(error) if is_setup_control_flow(&error) => {
                return Err(error);
            }
            Err(error) => log_git_identity_failed(env_id, &error),
            Ok(()) => log_git_identity_configured(env_id, &resolved_email, &resolved_name),
        }

        Ok(())
    }
}

/// What the configure-environment exec did with the Git author.
#[derive(Debug)]
pub(super) enum GitIdentityOutcome {
    /// No author was resolved, so the exec only published the defaults.
    Unresolved,
    Configured,
    /// The defaults were published; only the author failed.
    Failed(anyhow::Error),
}

/// Attribute the configure-environment exec's result: any failure but the
/// author's own status is the defaults publication's (or control flow) and
/// fails the phase; the author's status is a warning.
pub(super) fn configure_environment_outcome(
    result: anyhow::Result<()>,
    identity_resolved: bool,
) -> anyhow::Result<GitIdentityOutcome> {
    match result {
        Ok(()) if identity_resolved => Ok(GitIdentityOutcome::Configured),
        Ok(()) => Ok(GitIdentityOutcome::Unresolved),
        Err(error)
            if identity_resolved
                && !is_setup_control_flow(&error)
                && exited_with(&error, GIT_IDENTITY_FAILED_EXIT) =>
        {
            Ok(GitIdentityOutcome::Failed(error))
        }
        Err(error) => Err(error),
    }
}

fn log_git_identity_failed(environment_id: &str, error: &anyhow::Error) {
    tracing::warn!(
        environment_id,
        error = %error,
        "git-identity: failed to set Git identity"
    );
}

fn log_git_identity_configured(environment_id: &str, email: &str, name: &str) {
    tracing::info!(environment_id, name, email, "git-identity: configured");
}

/// Row shape for the git-identity lookup: (git_name, git_email, name, email).
type GitIdentityRow = (Option<String>, Option<String>, Option<String>, String);
