//! Connect-RPC adapter for global administrator reads.
//!
//! This module maps [`crate::api::admin`] core functions to protobuf and
//! renders Connect errors.

use std::sync::Arc;

use buffa_types::{Duration, Struct, Timestamp, Value};
use codewire_proto::codewire::admin::v1::{
    AdminService, AuditLogEntry as ProtoAuditLogEntry, EnvironmentLifecycleJournalEntry,
    EnvironmentStartupTiming, GetEnvironmentStartupSummaryRequest,
    GetEnvironmentStartupSummaryResponse, GetEnvironmentStartupTimingsRequest,
    GetEnvironmentStartupTimingsResponse, GetStatsRequest, GetStatsResponse, ListAuditLogsRequest,
    ListAuditLogsResponse, ListEnvironmentLifecycleJournalRequest,
    ListEnvironmentLifecycleJournalResponse, ListOrganizationsRequest, ListOrganizationsResponse,
    Organization as ProtoOrganization, StartupPhaseSummary,
};
use codewire_server_core::connect::rpc_app_error;
use codewire_server_core::{AppError, AppResult};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::api::ApiState;
use crate::api::admin::{
    self, AdminEnvironmentLifecycleJournalEntry, AdminEnvironmentStartupPhaseSummary,
    AdminEnvironmentStartupTiming, AdminEnvironmentStartupTimings, AdminOrg, AuditLogEntry,
    ListAuditLogsParams,
};

/// Registers the six AdminService reads on their generated Connect routes.
pub fn router(state: ApiState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(AdminConnectService { state }))
}

struct AdminConnectService {
    state: ApiState,
}

#[allow(refining_impl_trait)]
impl AdminService for AdminConnectService {
    async fn get_stats(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetStatsRequest>,
    ) -> ServiceResult<GetStatsResponse> {
        let stats = admin::get_admin_stats_core(&self.state)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetStatsResponse {
            total_environments: stats.total_environments,
            active_environments: stats.active_environments,
            monthly_cpu_hours: stats.monthly_cpu_hours,
            monthly_memory_gb_hours: stats.monthly_memory_gb_hours,
            monthly_cost_cents: stats.monthly_cost,
            ..Default::default()
        })
    }

    async fn list_organizations(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListOrganizationsRequest>,
    ) -> ServiceResult<ListOrganizationsResponse> {
        let organizations = admin::list_admin_organizations_core(&self.state)
            .await
            .and_then(|organizations| {
                organizations
                    .into_iter()
                    .map(proto_organization)
                    .collect::<AppResult<Vec<_>>>()
            })
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListOrganizationsResponse {
            organizations,
            ..Default::default()
        })
    }

    async fn list_audit_logs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListAuditLogsRequest>,
    ) -> ServiceResult<ListAuditLogsResponse> {
        let request = request.view();
        let entries = admin::list_audit_logs_core(
            &self.state,
            ListAuditLogsParams {
                limit: if request.limit == 0 {
                    admin::default_limit()
                } else {
                    i64::from(request.limit)
                },
                offset: i64::from(request.offset),
                action: (!request.action.is_empty()).then(|| request.action.to_owned()),
                severity: (!request.severity.is_empty()).then(|| request.severity.to_owned()),
            },
        )
        .await
        .and_then(|entries| {
            entries
                .into_iter()
                .map(proto_audit_log)
                .collect::<AppResult<Vec<_>>>()
        })
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListAuditLogsResponse {
            audit_logs: entries,
            ..Default::default()
        })
    }

    async fn list_environment_lifecycle_journal(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListEnvironmentLifecycleJournalRequest>,
    ) -> ServiceResult<ListEnvironmentLifecycleJournalResponse> {
        let request = request.view();
        let limit = if request.limit == 0 {
            admin::default_journal_limit()
        } else {
            i64::from(request.limit)
        };
        let entries = admin::list_admin_environment_lifecycle_journal_core(
            &self.state,
            request.environment_id,
            limit,
        )
        .await
        .and_then(|entries| {
            entries
                .into_iter()
                .map(proto_lifecycle_entry)
                .collect::<AppResult<Vec<_>>>()
        })
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListEnvironmentLifecycleJournalResponse {
            entries,
            ..Default::default()
        })
    }

    async fn get_environment_startup_summary(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetEnvironmentStartupSummaryRequest>,
    ) -> ServiceResult<GetEnvironmentStartupSummaryResponse> {
        let window = request
            .view()
            .window
            .as_option()
            .map(|window| (window.seconds, window.nanos));
        let window_minutes =
            request_window_minutes(window).map_err(|error| rpc_app_error(&error, &ctx))?;
        let summary =
            admin::get_admin_environment_startup_summary_core(&self.state, window_minutes)
                .await
                .and_then(proto_startup_summary)
                .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(summary)
    }

    async fn get_environment_startup_timings(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetEnvironmentStartupTimingsRequest>,
    ) -> ServiceResult<GetEnvironmentStartupTimingsResponse> {
        let timings = admin::get_admin_environment_startup_timings_core(
            &self.state,
            request.view().environment_id,
        )
        .await
        .and_then(proto_startup_timings)
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(timings)
    }
}

fn proto_organization(value: AdminOrg) -> AppResult<ProtoOrganization> {
    Ok(ProtoOrganization {
        id: value.id,
        name: value.name,
        slug: value.slug,
        created_at: Some(proto_timestamp(&value.created_at)?).into(),
        ..Default::default()
    })
}

fn proto_audit_log(value: AuditLogEntry) -> AppResult<ProtoAuditLogEntry> {
    Ok(ProtoAuditLogEntry {
        id: value.id,
        timestamp: Some(proto_timestamp(&value.timestamp)?).into(),
        action: value.action,
        user_id: value.user_id,
        user_email: value.user_email,
        ip_address: value.ip_address,
        user_agent: value.user_agent,
        metadata: value
            .metadata
            .filter(|metadata| !metadata.is_null())
            .map(proto_struct)
            .transpose()?
            .into(),
        severity: value.severity,
        ..Default::default()
    })
}

fn proto_lifecycle_entry(
    value: AdminEnvironmentLifecycleJournalEntry,
) -> AppResult<EnvironmentLifecycleJournalEntry> {
    Ok(EnvironmentLifecycleJournalEntry {
        id: value.id,
        environment_id: value.environment_id,
        kind: value.kind,
        actor: value.actor,
        phase: value.phase,
        status: value.status,
        from_state: value.from_state,
        to_state: value.to_state,
        checkpoint: value.checkpoint,
        reason: value.reason,
        metadata: Some(proto_value(value.metadata)?).into(),
        created_at: Some(proto_timestamp(&value.created_at)?).into(),
        ..Default::default()
    })
}

fn proto_startup_summary(
    value: admin::AdminEnvironmentStartupSummary,
) -> AppResult<GetEnvironmentStartupSummaryResponse> {
    let phase_durations = value
        .phase_durations
        .into_iter()
        .map(proto_phase_summary)
        .collect();
    Ok(GetEnvironmentStartupSummaryResponse {
        generated_at: Some(proto_timestamp(&value.generated_at)?).into(),
        window: Some(Duration::from_secs(i64::from(value.window_minutes) * 60)).into(),
        starting_backlog_count: value.starting_backlog_count,
        starting_backlog_over_5m_count: value.starting_backlog_over_5m_count,
        starting_backlog_over_10m_count: value.starting_backlog_over_10m_count,
        running_without_gateway_ready_count: value.running_without_gateway_ready_count,
        phase_durations,
        ..Default::default()
    })
}

fn proto_phase_summary(value: AdminEnvironmentStartupPhaseSummary) -> StartupPhaseSummary {
    StartupPhaseSummary {
        phase: value.phase,
        sample_count: value.sample_count,
        p50: value.p50_ms.map(Duration::from_millis).into(),
        p95: value.p95_ms.map(Duration::from_millis).into(),
        ..Default::default()
    }
}

fn proto_startup_timings(
    value: AdminEnvironmentStartupTimings,
) -> AppResult<GetEnvironmentStartupTimingsResponse> {
    let timings = value
        .timings
        .into_iter()
        .map(proto_startup_timing)
        .collect::<AppResult<Vec<_>>>()?;
    Ok(GetEnvironmentStartupTimingsResponse {
        environment_id: value.environment_id,
        created_at: Some(proto_timestamp(&value.created_at)?).into(),
        timings,
        ..Default::default()
    })
}

fn proto_startup_timing(
    value: AdminEnvironmentStartupTiming,
) -> AppResult<EnvironmentStartupTiming> {
    Ok(EnvironmentStartupTiming {
        phase: value.phase,
        status: value.status,
        message: value.message,
        duration: value.duration_ms.map(Duration::from_millis).into(),
        metadata: Some(proto_value(value.metadata)?).into(),
        created_at: Some(proto_timestamp(&value.created_at)?).into(),
        ..Default::default()
    })
}

fn request_window_minutes(window: Option<(i64, i32)>) -> AppResult<i32> {
    let Some((seconds, nanos)) = window else {
        return Ok(admin::default_startup_window_minutes());
    };
    if nanos != 0 || seconds % 60 != 0 {
        return Err(AppError::BadRequest(
            "window must be a whole number of minutes".into(),
        ));
    }
    i32::try_from(seconds / 60)
        .map_err(|_| AppError::BadRequest("window is outside the supported range".into()))
}

fn proto_timestamp(value: &str) -> AppResult<Timestamp> {
    let value = chrono::DateTime::parse_from_rfc3339(value).map_err(|error| {
        tracing::error!(%error, value, "admin: map timestamp into protobuf");
        AppError::InternalMsg("failed to map admin timestamp".into())
    })?;
    Ok(Timestamp::from_unix(
        value.timestamp(),
        value.timestamp_subsec_nanos() as i32,
    ))
}

fn proto_struct(value: serde_json::Value) -> AppResult<Struct> {
    serde_json::from_value(value).map_err(|error| {
        tracing::error!(%error, "admin: map JSON object into protobuf Struct");
        AppError::InternalMsg("failed to map admin metadata".into())
    })
}

fn proto_value(value: serde_json::Value) -> AppResult<Value> {
    serde_json::from_value(value).map_err(|error| {
        tracing::error!(%error, "admin: map JSON value into protobuf Value");
        AppError::InternalMsg("failed to map admin metadata".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_window_defaults_and_requires_whole_minutes() {
        assert_eq!(request_window_minutes(None).unwrap(), 240);
        assert_eq!(request_window_minutes(Some((300, 0))).unwrap(), 5);

        for invalid in [(61, 0), (60, 1)] {
            assert!(matches!(
                request_window_minutes(Some(invalid)),
                Err(AppError::BadRequest(_))
            ));
        }
    }

    #[test]
    fn metadata_mappings_preserve_objects_arrays_and_null() {
        let object = proto_struct(serde_json::json!({"attempt": 1})).unwrap();
        assert_eq!(
            serde_json::to_value(object).unwrap(),
            serde_json::json!({"attempt": 1.0})
        );

        for (value, expected) in [
            (serde_json::Value::Null, serde_json::Value::Null),
            (
                serde_json::json!([1, "two"]),
                serde_json::json!([1.0, "two"]),
            ),
        ] {
            let mapped = proto_value(value).unwrap();
            assert_eq!(serde_json::to_value(mapped).unwrap(), expected);
        }
    }

    #[test]
    fn audit_log_json_null_metadata_is_unset() {
        let audit_log = proto_audit_log(AuditLogEntry {
            id: "audit_null_metadata".into(),
            timestamp: "2026-07-23T10:00:00Z".into(),
            action: "contract.admin.null-metadata".into(),
            user_id: None,
            user_email: None,
            ip_address: None,
            user_agent: None,
            metadata: Some(serde_json::Value::Null),
            severity: "info".into(),
        })
        .unwrap();

        assert!(audit_log.metadata.as_option().is_none());
    }
}
