//! Starting a stopped environment.

use super::*;

pub(crate) async fn start_environment_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<StartEnvironmentResult> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(
        &state.pool,
        user,
        env_id,
        org_id,
        "operator",
        "access denied",
    )
    .await?;
    let env = fetch_env_summary(&state.pool, org_id, env_id).await?;
    require_bring_up_access(state, user, org_id, &env).await?;

    let dispatch_ambiguous = AtomicBool::new(false);
    // The admitted operation outlives a dropped request, so it owns its inputs.
    let owned_state = state.clone();
    let owned_user = user.clone();
    let owned_org_id = org_id.to_owned();
    run_environment_runtime_mutation(&state.pool, org_id, env_id, async move {
        let (state, user, org_id) = (&owned_state, &owned_user, owned_org_id.as_str());
        let result: AppResult<StartEnvironmentResult> = async {
            let lifecycle = crate::lifecycle::Service::for_pool(state.pool.clone());
            match env.state.as_str() {
                "stopped" => {} // normal start flow below
                "error" | "pending" => {
                    // Reset for immediate re-creation.
                    let retry = if env.state == "error" && env.isolation_tier == "confidential" {
                        lifecycle.retry_confidential_start(&env.id, org_id).await
                    } else {
                        lifecycle.reset_for_retry(&env.id).await
                    };
                    if retry.is_err() {
                        return Err(coded(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            "failed to reset environment",
                        ));
                    }
                    if trigger_environment(state, &env.id, "create").await.is_err() {
                        dispatch_ambiguous.store(true, Ordering::Release);
                        return Err(coded(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            "failed to retry environment create",
                        ));
                    }
                    return Ok(StartEnvironmentResult {
                        status: "retry requested",
                        outcome: StartOutcomeCore::Retried,
                    });
                }
                _ => {
                    return Err(coded(
                        StatusCode::BAD_REQUEST,
                        "invalid_state",
                        "environment must be stopped, pending, or errored to start",
                    ));
                }
            }

            take_user_rate_limit(
                &state.pool,
                &rate_limit::SANDBOX_START,
                &user.user_id,
                "sandbox starts",
            )
            .await?;

            // Starting resumes compute allocation: the quota is checked and
            // the start intent recorded under the organization row lock.
            let quota = admission_quota(&state.pool, org_id).await?;
            if let Err(error) = lifecycle
                .admit_start(
                    &env.id,
                    org_id,
                    &env.isolation_tier,
                    crate::lifecycle::StartQuota {
                        credit_enforcement: state.credit_enforcement,
                        quota,
                        env_type: &env.env_type,
                        cpu_millicores: env.cpu_millicores,
                        memory_mb: env.memory_mb,
                    },
                )
                .await
            {
                let error = match error.downcast::<AppError>() {
                    Ok(refused) => return Err(refused),
                    Err(error) => error,
                };
                tracing::error!(%error, environment_id = env.id, "start environment admission failed");
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to start environment",
                ));
            }
            if trigger_environment(state, &env.id, "start").await.is_err() {
                dispatch_ambiguous.store(true, Ordering::Release);
                return Err(coded(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "failed to request environment start",
                ));
            }
            Ok(StartEnvironmentResult {
                status: "start requested",
                outcome: StartOutcomeCore::Started,
            })
        }
        .await;
        match result {
            Ok(response) => Ok(response),
            Err(error) if dispatch_ambiguous.load(Ordering::Acquire) => {
                Err(OrganizationRuntimeMutationError::ambiguous(error))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await
}
