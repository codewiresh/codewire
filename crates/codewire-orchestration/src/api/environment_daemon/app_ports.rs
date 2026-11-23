//! Pushing an environment's exposed application ports to its bound daemon.

use super::*;

/// Push the environment's exposed application ports to its bound daemon,
/// which serves exactly these on its tailnet address (#2460). Called after a
/// change commits; best effort: a failed push is logged, and the daemon's
/// next access renewal restates the set.
pub(crate) async fn push_environment_app_ports(
    pool: &PgPool,
    runtime: Option<&dyn RuntimeDriver>,
    session_secret: &str,
    endpoints: Option<&EnvironmentDaemonEndpointOverrides>,
    environment_id: &str,
) {
    let result: AppResult<Option<usize>> = async {
        let namespace: Option<String> = sqlx::query_scalar(
            "SELECT namespace FROM sandbox_environment_backend WHERE environment_id = $1",
        )
        .bind(environment_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| AppError::InternalMsg("load environment backend".into()))?;
        let Some(namespace) = namespace.filter(|namespace| !namespace.is_empty()) else {
            return Ok(None);
        };
        let ports = crate::workspace_binding::exposed_app_ports(pool, environment_id)
            .await
            .map_err(|_| AppError::InternalMsg("load environment app ports".into()))?;
        let endpoint = match endpoints {
            Some(endpoints) => endpoints.endpoint(&namespace, environment_id),
            None => cluster_daemon_endpoint(&namespace, environment_id),
        };
        let (channel, token) = daemon_channel_for_endpoint(
            pool,
            runtime,
            session_secret,
            environment_id,
            endpoint,
            DaemonRequestBudget::Control,
        )
        .await?;
        let count = ports.len();
        send_app_ports(channel, &token, ports).await?;
        Ok(Some(count))
    }
    .await;
    match result {
        Ok(Some(app_port_count)) => {
            tracing::info!(
                environment_id,
                app_port_count,
                "application ports pushed to the environment daemon"
            );
        }
        Ok(None) => {}
        Err(error) => tracing::warn!(
            environment_id,
            error = %error,
            "push application ports to the environment daemon failed; its next access renewal restates them"
        ),
    }
}

pub(super) async fn send_app_ports(
    channel: Channel,
    token: &str,
    ports: Vec<i32>,
) -> AppResult<()> {
    v1::daemon_service_client::DaemonServiceClient::new(channel)
        .set_app_ports(authorize(v1::SetAppPortsRequest { ports }, token)?)
        .await
        .map_err(|status| {
            AppError::Upstream(
                format!(
                    "environment daemon refused application ports: {:?}",
                    status.code()
                )
                .into(),
            )
        })?;
    Ok(())
}
