//! Connect-RPC adapter for administrator billing-catalog operations.
//!
//! This module owns protobuf mapping and Connect error rendering for the
//! catalog and catalog-admin core operations.

use std::borrow::Cow;
use std::sync::Arc;

use buffa_types::{Struct, Timestamp};
use codewire_admin_proto::codewire::admin::v1::{
    BillingCatalogService, CatalogPlan as ProtoCatalogPlan, CatalogPrice as ProtoCatalogPrice,
    CatalogSetting as ProtoCatalogSetting, CreatePlanRequest, CreatePlanResponse,
    CreatePriceRequest, CreatePriceResponse, GetCatalogRequest, GetCatalogResponse,
    ListSubscriptionMigrationsRequest, ListSubscriptionMigrationsResponse,
    MigrationRun as ProtoMigrationRun, MigrationSample as ProtoMigrationSample,
    PlanSpec as ProtoPlanSpec, PreviewSubscriptionMigrationRequest,
    PreviewSubscriptionMigrationResponse, RunSubscriptionMigrationRequest,
    RunSubscriptionMigrationResponse, SetOrganizationBillingExemptionRequest,
    SetOrganizationBillingExemptionResponse, SetPlanArchivedRequest, SetPlanArchivedResponse,
    SetPriceArchivedRequest, SetPriceArchivedResponse, UpdatePlanRequest, UpdatePlanResponse,
    UpdatePriceRequest, UpdatePriceResponse, UpdateSettingRequest, UpdateSettingResponse,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::catalog;
use crate::catalog_admin::{
    self, MigrationRunResponse, MigrationSample, PlanWriteBody, PreviewMigrationBody,
    RunMigrationBody,
};
use crate::routes::BillingState;

/// Registers all eleven BillingCatalogService RPCs on their generated Connect
/// routes. The billing binary mounts this router behind the global-admin auth
/// layer.
pub fn router(state: BillingState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(BillingCatalogConnectService { state }))
}

struct BillingCatalogConnectService {
    state: BillingState,
}

#[allow(refining_impl_trait)]
impl BillingCatalogService for BillingCatalogConnectService {
    async fn get_catalog(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetCatalogRequest>,
    ) -> ServiceResult<GetCatalogResponse> {
        let catalog = catalog::get_catalog_core(&self.state.pool)
            .await
            .and_then(proto_catalog)
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(catalog)
    }

    async fn create_plan(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreatePlanRequest>,
    ) -> ServiceResult<CreatePlanResponse> {
        let request = request.to_owned_message();
        validate_required(&[
            (&request.resource_type, "/resource_type"),
            (&request.plan_key, "/plan_key"),
        ])
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        let plan =
            plan_spec(request.plan.as_option()).map_err(|error| rpc_app_error(&error, &ctx))?;
        catalog_admin::create_plan_core(
            &self.state.pool,
            &request.resource_type,
            &request.plan_key,
            &plan,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(CreatePlanResponse::default())
    }

    async fn update_plan(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdatePlanRequest>,
    ) -> ServiceResult<UpdatePlanResponse> {
        let request = request.to_owned_message();
        validate_required(&[
            (&request.resource_type, "/resource_type"),
            (&request.plan_key, "/plan_key"),
        ])
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        let plan =
            plan_spec(request.plan.as_option()).map_err(|error| rpc_app_error(&error, &ctx))?;
        catalog_admin::update_plan_core(
            &self.state.pool,
            &request.resource_type,
            &request.plan_key,
            &plan,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(UpdatePlanResponse::default())
    }

    async fn set_plan_archived(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetPlanArchivedRequest>,
    ) -> ServiceResult<SetPlanArchivedResponse> {
        let request = request.view();
        validate_required(&[
            (request.resource_type, "/resource_type"),
            (request.plan_key, "/plan_key"),
        ])
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        catalog_admin::set_plan_archived_core(
            &self.state.pool,
            request.resource_type,
            request.plan_key,
            request.archived,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(SetPlanArchivedResponse::default())
    }

    async fn create_price(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreatePriceRequest>,
    ) -> ServiceResult<CreatePriceResponse> {
        let request = request.view();
        validate_required(&[
            (request.resource_type, "/resource_type"),
            (request.plan_key, "/plan_key"),
            (request.stripe_mode, "/stripe_mode"),
            (request.price_kind, "/price_kind"),
            (request.stripe_price_id, "/stripe_price_id"),
        ])
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        catalog_admin::create_price_core(
            &self.state.pool,
            request.resource_type,
            request.plan_key,
            request.stripe_mode,
            request.price_kind,
            request.stripe_price_id,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(CreatePriceResponse::default())
    }

    async fn update_price(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdatePriceRequest>,
    ) -> ServiceResult<UpdatePriceResponse> {
        let request = request.view();
        validate_required(&[
            (request.resource_type, "/resource_type"),
            (request.plan_key, "/plan_key"),
            (request.stripe_mode, "/stripe_mode"),
            (request.price_kind, "/price_kind"),
            (request.stripe_price_id, "/stripe_price_id"),
        ])
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        catalog_admin::update_price_core(
            &self.state.pool,
            request.resource_type,
            request.plan_key,
            request.stripe_mode,
            request.price_kind,
            request.stripe_price_id,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(UpdatePriceResponse::default())
    }

    async fn set_price_archived(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetPriceArchivedRequest>,
    ) -> ServiceResult<SetPriceArchivedResponse> {
        let request = request.view();
        validate_required(&[
            (request.resource_type, "/resource_type"),
            (request.plan_key, "/plan_key"),
            (request.stripe_mode, "/stripe_mode"),
            (request.price_kind, "/price_kind"),
        ])
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        catalog_admin::set_price_archived_core(
            &self.state.pool,
            request.resource_type,
            request.plan_key,
            request.stripe_mode,
            request.price_kind,
            request.archived,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(SetPriceArchivedResponse::default())
    }

    async fn update_setting(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateSettingRequest>,
    ) -> ServiceResult<UpdateSettingResponse> {
        let request = request.view();
        validate_required(&[(request.setting_key, "/setting_key")])
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        catalog_admin::update_setting_core(
            &self.state.pool,
            request.setting_key,
            request.int_value,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(UpdateSettingResponse::default())
    }

    async fn preview_subscription_migration(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, PreviewSubscriptionMigrationRequest>,
    ) -> ServiceResult<PreviewSubscriptionMigrationResponse> {
        let request = request.view();
        validate_required(&[
            (request.resource_type, "/resource_type"),
            (request.source_plan_key, "/source_plan_key"),
            (request.target_plan_key, "/target_plan_key"),
        ])
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        let preview = catalog_admin::preview_migration_core(
            &self.state,
            &PreviewMigrationBody {
                resource_type: request.resource_type.to_owned(),
                source_plan_key: request.source_plan_key.to_owned(),
                target_plan_key: request.target_plan_key.to_owned(),
                sample_limit: request.sample_limit,
            },
        )
        .await
        .and_then(proto_migration_preview)
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(preview)
    }

    async fn run_subscription_migration(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RunSubscriptionMigrationRequest>,
    ) -> ServiceResult<RunSubscriptionMigrationResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_required(&[
            (request.resource_type, "/resource_type"),
            (request.source_plan_key, "/source_plan_key"),
            (request.target_plan_key, "/target_plan_key"),
        ])
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        let run = catalog_admin::run_migration_core(
            &self.state,
            &RunMigrationBody {
                resource_type: request.resource_type.to_owned(),
                source_plan_key: request.source_plan_key.to_owned(),
                target_plan_key: request.target_plan_key.to_owned(),
                proration_behavior: request.proration_behavior.to_owned(),
            },
            &user.user_id,
        )
        .await
        .and_then(proto_migration_run)
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(RunSubscriptionMigrationResponse {
            migration: Some(run).into(),
            ..Default::default()
        })
    }

    async fn list_subscription_migrations(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListSubscriptionMigrationsRequest>,
    ) -> ServiceResult<ListSubscriptionMigrationsResponse> {
        let request = request.view();
        let limit = if request.limit == 0 {
            25
        } else {
            i64::from(request.limit)
        };
        let limit = catalog_admin::validate_connect_migration_limit(limit)
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        let migrations = catalog_admin::list_migrations_core(&self.state.pool, limit)
            .await
            .and_then(|migrations| {
                migrations
                    .into_iter()
                    .map(proto_migration_run)
                    .collect::<AppResult<Vec<_>>>()
            })
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListSubscriptionMigrationsResponse {
            migrations,
            ..Default::default()
        })
    }

    async fn set_organization_billing_exemption(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetOrganizationBillingExemptionRequest>,
    ) -> ServiceResult<SetOrganizationBillingExemptionResponse> {
        let actor = auth_user(&ctx)?.clone();
        let request = request.view();
        validate_required(&[(request.organization_id, "/organization_id")])
            .map_err(|error| rpc_app_error(&error, &ctx))?;

        let mut tx = self.state.pool.begin().await.map_err(|_| {
            rpc_app_error(
                &AppError::InternalMsg("failed to start billing exemption update".into()),
                &ctx,
            )
        })?;
        let updated: Option<String> = sqlx::query_scalar(
            r#"UPDATE organizations
                  SET billing_exempt = $2, updated_at = NOW()
                WHERE id = $1
              RETURNING id"#,
        )
        .bind(request.organization_id)
        .bind(request.billing_exempt)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| {
            rpc_app_error(
                &AppError::InternalMsg("failed to update billing exemption".into()),
                &ctx,
            )
        })?;
        let organization_id = updated.ok_or_else(|| {
            rpc_app_error(&AppError::NotFound("organization not found".into()), &ctx)
        })?;
        sqlx::query(
            r#"INSERT INTO audit_logs
                   (id, timestamp, action, user_id, metadata, severity)
               VALUES
                   (gen_random_uuid()::text, NOW(), 'admin.billing.organization_exemption', $1,
                    jsonb_build_object('organization_id', $2, 'billing_exempt', $3), 'warn')"#,
        )
        .bind(&actor.user_id)
        .bind(&organization_id)
        .bind(request.billing_exempt)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            rpc_app_error(
                &AppError::InternalMsg("failed to audit billing exemption update".into()),
                &ctx,
            )
        })?;
        tx.commit().await.map_err(|_| {
            rpc_app_error(
                &AppError::InternalMsg("failed to commit billing exemption update".into()),
                &ctx,
            )
        })?;

        connectrpc::Response::ok(SetOrganizationBillingExemptionResponse {
            organization_id,
            billing_exempt: request.billing_exempt,
            ..Default::default()
        })
    }
}

fn plan_spec(plan: Option<&ProtoPlanSpec>) -> AppResult<PlanWriteBody> {
    let plan = plan.ok_or_else(|| AppError::Validation {
        errors: vec![ValidationIssue {
            path: Cow::Borrowed("/plan"),
            message: Cow::Borrowed("must be provided"),
        }],
    })?;
    validate_required(&[(&plan.display_name, "/plan/display_name")])?;
    Ok(PlanWriteBody {
        display_name: plan.display_name.to_owned(),
        price_cents: plan.price_cents,
        included_devs: plan.included_devs,
        max_concurrent_ws: plan.max_concurrent_ws,
        max_team_members: plan.max_team_members,
        storage_gb: plan.storage_gb,
        is_contact_us: plan.is_contact_us,
        is_admin_only: plan.is_admin_only,
        included_cpu_hours: plan.included_cpu_hours,
        included_mem_gb_hours: plan.included_mem_gb_hours,
        included_disk_gb_hours: plan.included_disk_gb_hours,
        cpu_overage_cents: plan.cpu_overage_cents,
        mem_overage_cents: plan.mem_overage_cents,
        disk_overage_cents: plan.disk_overage_cents,
    })
}

fn validate_required(fields: &[(&str, &'static str)]) -> AppResult<()> {
    let errors: Vec<_> = fields
        .iter()
        .filter(|(value, _)| value.trim().is_empty())
        .map(|(_, path)| ValidationIssue {
            path: Cow::Borrowed(*path),
            message: Cow::Borrowed("must not be empty"),
        })
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::Validation { errors })
    }
}

fn proto_catalog(value: catalog::CatalogResponse) -> AppResult<GetCatalogResponse> {
    Ok(GetCatalogResponse {
        plans: value.plans.into_iter().map(proto_catalog_plan).collect(),
        prices: value.prices.into_iter().map(proto_catalog_price).collect(),
        settings: value
            .settings
            .into_iter()
            .map(proto_catalog_setting)
            .collect(),
        ..Default::default()
    })
}

fn proto_catalog_plan(value: catalog::CatalogPlan) -> ProtoCatalogPlan {
    ProtoCatalogPlan {
        resource_type: value.resource_type,
        plan_key: value.plan_key,
        plan: Some(ProtoPlanSpec {
            display_name: value.display_name,
            price_cents: value.price_cents,
            included_devs: value.included_devs,
            max_concurrent_ws: value.max_concurrent_ws,
            max_team_members: value.max_team_members,
            storage_gb: value.storage_gb,
            is_contact_us: value.is_contact_us,
            is_admin_only: value.is_admin_only,
            included_cpu_hours: value.included_cpu_hours,
            included_mem_gb_hours: value.included_mem_gb_hours,
            included_disk_gb_hours: value.included_disk_gb_hours,
            cpu_overage_cents: value.cpu_overage_cents,
            mem_overage_cents: value.mem_overage_cents,
            disk_overage_cents: value.disk_overage_cents,
            ..Default::default()
        })
        .into(),
        archived: value.archived,
        ..Default::default()
    }
}

fn proto_catalog_price(value: catalog::CatalogPrice) -> ProtoCatalogPrice {
    ProtoCatalogPrice {
        resource_type: value.resource_type,
        plan_key: value.plan_key,
        stripe_mode: value.stripe_mode,
        price_kind: value.price_kind,
        stripe_price_id: value.stripe_price_id,
        archived: value.archived,
        ..Default::default()
    }
}

fn proto_catalog_setting(value: catalog::CatalogSetting) -> ProtoCatalogSetting {
    ProtoCatalogSetting {
        setting_key: value.setting_key,
        int_value: value.int_value,
        ..Default::default()
    }
}

fn proto_migration_preview(
    value: catalog_admin::MigrationPreviewResponse,
) -> AppResult<PreviewSubscriptionMigrationResponse> {
    Ok(PreviewSubscriptionMigrationResponse {
        resource_type: value.resource_type,
        source_plan_key: value.source_plan_key,
        target_plan_key: value.target_plan_key,
        target_stripe_price_id: value.target_stripe_price_id,
        matching_count: value.matching_count,
        candidate_count: value.candidate_count,
        already_on_target: value.already_on_target,
        samples: value
            .samples
            .into_iter()
            .map(proto_migration_sample)
            .collect(),
        ..Default::default()
    })
}

fn proto_migration_sample(value: MigrationSample) -> ProtoMigrationSample {
    ProtoMigrationSample {
        scope: value.scope,
        org_id: value.org_id,
        org_slug: value.org_slug,
        stripe_subscription_id: value.stripe_subscription_id,
        status: value.status,
        current_plan_key: value.current_plan_key,
        current_stripe_price_id: (!value.current_stripe_price_id.is_empty())
            .then_some(value.current_stripe_price_id),
        ..Default::default()
    }
}

fn proto_migration_run(value: MigrationRunResponse) -> AppResult<ProtoMigrationRun> {
    let metadata = value
        .metadata
        .map(serde_json::from_value::<Struct>)
        .transpose()
        .map_err(|error| AppError::Internal(anyhow::Error::new(error)))?;
    Ok(ProtoMigrationRun {
        id: value.id,
        resource_type: value.resource_type,
        source_plan_key: value.source_plan_key,
        target_plan_key: value.target_plan_key,
        target_stripe_price_id: value.target_stripe_price_id,
        proration_behavior: value.proration_behavior,
        migrated_count: value.migrated_count,
        skipped_count: value.skipped_count,
        failed_count: value.failed_count,
        created_by: (!value.created_by.is_empty()).then_some(value.created_by),
        created_at: Some(timestamp(&value.created_at)?).into(),
        metadata: metadata.into(),
        ..Default::default()
    })
}

fn timestamp(value: &str) -> AppResult<Timestamp> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|error| AppError::Internal(anyhow::Error::new(error)))?;
    Ok(Timestamp::from_unix(
        parsed.timestamp(),
        parsed.timestamp_subsec_nanos() as i32,
    ))
}

#[cfg(test)]
mod tests {
    use codewire_server_core::connect_error::{ConnectCode, ConnectError, ConnectErrorDetail};

    use super::*;

    #[test]
    fn missing_plan_and_large_limit_render_canonical_field_violations() {
        for (error, field) in [
            (plan_spec(None).expect_err("plan is required"), "plan"),
            (
                validate_required(&[("", "/resource_type")])
                    .expect_err("resource type is required"),
                "resource_type",
            ),
            (
                catalog_admin::validate_connect_migration_limit(101)
                    .expect_err("limit must be capped"),
                "limit",
            ),
        ] {
            let rendered = ConnectError::from_app_error(&error, None);
            assert_eq!(rendered.code, ConnectCode::InvalidArgument);
            let ConnectErrorDetail::BadRequest(detail) = &rendered.details[0] else {
                panic!("missing BadRequest detail");
            };
            assert_eq!(detail.field_violations[0].field, field);
        }
    }

    #[test]
    fn fractional_catalog_rates_remain_doubles() {
        let plan = ProtoPlanSpec {
            display_name: "Fractional rate fixture".into(),
            cpu_overage_cents: 0.5,
            mem_overage_cents: 0.25,
            disk_overage_cents: 0.125,
            ..Default::default()
        };
        let body = plan_spec(Some(&plan)).expect("proto plan maps to shared body");
        assert_eq!(body.cpu_overage_cents, 0.5);
        assert_eq!(body.mem_overage_cents, 0.25);
        assert_eq!(body.disk_overage_cents, 0.125);
    }
}
