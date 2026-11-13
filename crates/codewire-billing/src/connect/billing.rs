//! Connect-RPC adapter for the first-party billing surface.
//!
//! This module owns protobuf mapping, Connect error rendering, and the public
//! transport for the shared billing operations.

use std::sync::Arc;

use buffa_types::Timestamp;
use codewire_proto::codewire::console::v1::{
    AddCreditOutcome as ProtoAddCreditOutcome, AddCreditRefusal, AddCreditRequest,
    AddCreditResponse, BillingEvent as ProtoBillingEvent,
    BillingLimitUsage as ProtoBillingLimitUsage, BillingLimits as ProtoBillingLimits,
    BillingService, CreateCheckoutSessionRequest, CreateCheckoutSessionResponse,
    CreatePortalSessionRequest, CreatePortalSessionResponse, CreateSetupSessionRequest,
    CreateSetupSessionResponse, CreditRates as ProtoCreditRates,
    EnvironmentUsageEntry as ProtoEnvironmentUsageEntry,
    EnvironmentUsageHour as ProtoEnvironmentUsageHour,
    EnvironmentUsageMonth as ProtoEnvironmentUsageMonth, GetBillingOverviewRequest,
    GetBillingOverviewResponse, GetEnvironmentUsageRequest, GetEnvironmentUsageResponse,
    GetSignupCreditRequest, GetSignupCreditResponse, Invoice as ProtoInvoice,
    ListBillingEventsRequest, ListBillingEventsResponse, ListInvoicesRequest, ListInvoicesResponse,
    ListOrgPlansRequest, ListOrgPlansResponse, ListResourcePlansRequest, ListResourcePlansResponse,
    OrgPlan as ProtoOrgPlan, PaymentCard as ProtoPaymentCard, ResourcePlan as ProtoResourcePlan,
    UpdateAutoTopUpRequest, UpdateAutoTopUpResponse, UsageSummary as ProtoUsageSummary,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};

use crate::checkout_sessions::{
    CheckoutRequest, PortalRequest, SetupRequest, create_checkout_session, create_portal_session,
    create_setup_session,
};
use crate::credit_purchase::{AddCreditOutcome, add_credit};
use crate::org_billing::{
    BillingEventResponse, InvoiceResponse, list_events_core, list_invoices_core,
};
use crate::overview::{
    BillingOverviewResponse, EnvironmentUsageEntry, EnvironmentUsageHour, EnvironmentUsageResponse,
    billing_overview, environment_usage, update_auto_top_up,
};
use crate::plans::{self, OrgPlan, ResourcePlan};
use crate::routes::BillingState;

/// Registers every BillingService RPC on its generated Connect route.
pub fn router(state: BillingState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(BillingConnectService { state }))
}

struct BillingConnectService {
    state: BillingState,
}

#[allow(refining_impl_trait)]
impl BillingService for BillingConnectService {
    async fn list_org_plans(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListOrgPlansRequest>,
    ) -> ServiceResult<ListOrgPlansResponse> {
        auth_user(&ctx)?;
        let plans = plans::list_org_plans(&self.state.pool)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListOrgPlansResponse {
            plans: plans
                .into_iter()
                .map(|(key, plan)| (key, proto_org_plan(plan)))
                .collect(),
            ..Default::default()
        })
    }

    async fn list_resource_plans(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListResourcePlansRequest>,
    ) -> ServiceResult<ListResourcePlansResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let plans = plans::list_resource_plans(&self.state.pool, &user, request.resource_type)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        let plans = plans
            .into_iter()
            .map(|(key, plan)| proto_resource_plan(plan).map(|plan| (key, plan)))
            .collect::<AppResult<_>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListResourcePlansResponse {
            plans,
            ..Default::default()
        })
    }

    async fn get_signup_credit(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, GetSignupCreditRequest>,
    ) -> ServiceResult<GetSignupCreditResponse> {
        let amount_nano_eur = crate::catalog::signup_credit_nano_eur(&self.state.pool)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetSignupCreditResponse {
            amount_nano_eur,
            ..Default::default()
        })
    }

    async fn get_billing_overview(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetBillingOverviewRequest>,
    ) -> ServiceResult<GetBillingOverviewResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let overview = billing_overview(&self.state, &user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        let response =
            proto_billing_overview(overview).map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(response)
    }

    async fn list_invoices(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListInvoicesRequest>,
    ) -> ServiceResult<ListInvoicesResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let invoices = list_invoices_core(&self.state.pool, &user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?
            .into_iter()
            .map(proto_invoice)
            .collect::<AppResult<_>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListInvoicesResponse {
            invoices,
            ..Default::default()
        })
    }

    async fn list_billing_events(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListBillingEventsRequest>,
    ) -> ServiceResult<ListBillingEventsResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let events = list_events_core(&self.state.pool, &user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?
            .into_iter()
            .map(proto_billing_event)
            .collect::<AppResult<_>>()
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(ListBillingEventsResponse {
            events,
            ..Default::default()
        })
    }

    async fn get_environment_usage(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetEnvironmentUsageRequest>,
    ) -> ServiceResult<GetEnvironmentUsageResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let usage = environment_usage(&self.state, &user, request.org_id)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        let response =
            proto_environment_usage(usage).map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(response)
    }

    async fn create_checkout_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateCheckoutSessionRequest>,
    ) -> ServiceResult<CreateCheckoutSessionResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let checkout_url = create_checkout_session(
            &self.state,
            &user,
            request.org_id,
            CheckoutRequest {
                plan: request.plan.to_owned(),
                success_url: request.success_url.to_owned(),
                cancel_url: request.cancel_url.to_owned(),
            },
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(CreateCheckoutSessionResponse {
            checkout_url,
            ..Default::default()
        })
    }

    async fn create_portal_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreatePortalSessionRequest>,
    ) -> ServiceResult<CreatePortalSessionResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let portal_url = create_portal_session(
            &self.state,
            &user,
            request.org_id,
            PortalRequest {
                return_url: request.return_url.to_owned(),
            },
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(CreatePortalSessionResponse {
            portal_url,
            ..Default::default()
        })
    }

    async fn create_setup_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateSetupSessionRequest>,
    ) -> ServiceResult<CreateSetupSessionResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let checkout_url = create_setup_session(
            &self.state,
            &user,
            request.org_id,
            SetupRequest {
                success_url: request.success_url.to_owned(),
                cancel_url: request.cancel_url.to_owned(),
            },
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(CreateSetupSessionResponse {
            checkout_url,
            ..Default::default()
        })
    }

    async fn update_auto_top_up(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateAutoTopUpRequest>,
    ) -> ServiceResult<UpdateAutoTopUpResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let (enabled, amount_cents) = update_auto_top_up(
            &self.state.pool,
            &user,
            request.org_id,
            request.enabled,
            request.amount_cents,
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        // Turning top-up on charges a balance that already ran out now,
        // rather than at the next metering pass. The setting is saved either
        // way; a failed charge is recorded by the settlement.
        if enabled
            && let Err(error) = crate::credit::settle_organization(
                &self.state.pool,
                &self.state.stripe,
                self.state.credit_enforcement,
                request.org_id,
                true,
            )
            .await
        {
            tracing::warn!(org_id = request.org_id, %error, "billing: settle after enabling top-up failed");
        }
        connectrpc::Response::ok(UpdateAutoTopUpResponse {
            enabled,
            amount_cents,
            ..Default::default()
        })
    }

    async fn add_credit(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AddCreditRequest>,
    ) -> ServiceResult<AddCreditResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.view();
        let amount_cents = request.amount_cents;
        let outcome = add_credit(
            &self.state,
            &user,
            request.org_id,
            crate::credit_purchase::AddCreditRequest {
                amount_cents,
                request_id: request.request_id.to_owned(),
                success_url: request.success_url.to_owned(),
                cancel_url: request.cancel_url.to_owned(),
            },
        )
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(proto_add_credit(outcome, amount_cents))
    }
}

fn proto_add_credit(outcome: AddCreditOutcome, amount_cents: i32) -> AddCreditResponse {
    let mut response = AddCreditResponse {
        amount_cents,
        ..Default::default()
    };
    match outcome {
        AddCreditOutcome::Paid => response.outcome = ProtoAddCreditOutcome::Paid.into(),
        AddCreditOutcome::ActionRequired { payment_url } => {
            response.outcome = ProtoAddCreditOutcome::ActionRequired.into();
            response.payment_url = payment_url;
        }
        AddCreditOutcome::Declined { code } => {
            response.outcome = ProtoAddCreditOutcome::Refused.into();
            response.refusal = AddCreditRefusal::Declined.into();
            response.decline_code = code;
        }
        AddCreditOutcome::InProgress => {
            response.outcome = ProtoAddCreditOutcome::Refused.into();
            response.refusal = AddCreditRefusal::InProgress.into();
        }
    }
    response
}

fn proto_org_plan(plan: OrgPlan) -> ProtoOrgPlan {
    ProtoOrgPlan {
        display_name: plan.display_name,
        price_cents: plan.price_cents,
        included_devs: plan.included_devs,
        max_concurrent_ws: plan.max_concurrent_ws,
        max_team_members: plan.max_team_members,
        storage_gb: plan.storage_gb,
        is_contact_us: plan.is_contact_us,
        archived: plan.archived,
        ..Default::default()
    }
}

fn proto_resource_plan(plan: ResourcePlan) -> AppResult<ProtoResourcePlan> {
    Ok(ProtoResourcePlan {
        display_name: plan.display_name,
        price_cents: plan.price_cents,
        included_devs: plan.included_devs,
        max_concurrent_ws: plan.max_concurrent_ws,
        max_team_members: plan.max_team_members,
        storage_gb: plan.storage_gb,
        is_contact_us: plan.is_contact_us,
        is_admin_only: plan.is_admin_only,
        archived: plan.archived,
        included_cpu_hours: plan.included_cpu_hours,
        included_mem_gb_hours: plan.included_mem_gb_hours,
        included_disk_gb_hours: plan.included_disk_gb_hours,
        cpu_overage_millicents: millicents(plan.cpu_overage_cents)?,
        mem_overage_millicents: millicents(plan.mem_overage_cents)?,
        disk_overage_millicents: millicents(plan.disk_overage_cents)?,
        ..Default::default()
    })
}

fn millicents(cents: f64) -> AppResult<i64> {
    let scaled = cents * 1_000.0;
    if !scaled.is_finite() || scaled < i64::MIN as f64 || scaled > i64::MAX as f64 {
        return Err(AppError::Internal(anyhow::anyhow!(
            "billing overage rate cannot be represented in millicents"
        )));
    }
    Ok(scaled.round() as i64)
}

fn proto_billing_overview(value: BillingOverviewResponse) -> AppResult<GetBillingOverviewResponse> {
    Ok(GetBillingOverviewResponse {
        billing_enabled: value.billing_enabled,
        has_payment_method: value.has_payment_method,
        plan: value.plan,
        plan_display_name: value.plan_display_name,
        status: value.status,
        trial_end: optional_timestamp(value.trial_end.as_deref())?.into(),
        trial_days: value.trial_days,
        seat_count: value.seat_count,
        included_devs: value.included_devs,
        extra_seat_price_cents: value.extra_seat_price_cents,
        limits: Some(ProtoBillingLimits {
            team_members: Some(ProtoBillingLimitUsage {
                used: value.limits.team_members.used,
                max: value.limits.team_members.max,
                ..Default::default()
            })
            .into(),
            concurrent_workspaces: value.limits.concurrent_workspaces,
            storage_gb: value.limits.storage_gb,
            ..Default::default()
        })
        .into(),
        current_period_end: optional_timestamp(value.current_period_end.as_deref())?.into(),
        active_subscriptions: value.active_subscriptions,
        total_monthly_cost_cents: value.total_monthly_cost_cents,
        current_month_usage: Some(ProtoUsageSummary {
            cpu_hours: value.current_month_usage.cpu_hours,
            memory_gb_hours: value.current_month_usage.memory_gb_hours,
            storage_gb_hours: value.current_month_usage.storage_gb_hours,
            ..Default::default()
        })
        .into(),
        credit_balance_nano_eur: value.credit.balance_nano_eur,
        rates: Some(ProtoCreditRates {
            cpu_nano_eur_per_vcpu_hour: value.credit.rates.cpu_per_vcpu_hour,
            memory_nano_eur_per_gib_hour: value.credit.rates.memory_per_gib_hour,
            disk_nano_eur_per_gib_hour: value.credit.rates.disk_per_gib_hour,
            ..Default::default()
        })
        .into(),
        unmetered: value.credit.unmetered,
        auto_top_up_enabled: value.credit.auto_top_up_enabled,
        auto_top_up_cents: value.credit.auto_top_up_cents,
        credit_exhausted_at: optional_timestamp(value.credit.exhausted_at.as_deref())?.into(),
        month_usage_nano_eur: value.credit.month_usage_nano_eur,
        default_card: value
            .default_card
            .map(|card| ProtoPaymentCard {
                brand: card.brand,
                last4: card.last4,
                exp_month: card.exp_month,
                exp_year: card.exp_year,
                ..Default::default()
            })
            .into(),
        ..Default::default()
    })
}

fn proto_invoice(value: InvoiceResponse) -> AppResult<ProtoInvoice> {
    Ok(ProtoInvoice {
        id: value.id,
        stripe_invoice_id: value.stripe_invoice_id,
        status: value.status,
        amount_due: value.amount_due,
        amount_paid: value.amount_paid,
        currency: value.currency,
        hosted_invoice_url: value.hosted_invoice_url,
        invoice_pdf: value.invoice_pdf,
        period_start: optional_timestamp(value.period_start.as_deref())?.into(),
        period_end: optional_timestamp(value.period_end.as_deref())?.into(),
        created_at: Some(timestamp(&value.created_at)?).into(),
        ..Default::default()
    })
}

fn proto_billing_event(value: BillingEventResponse) -> AppResult<ProtoBillingEvent> {
    let metadata = value
        .metadata
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| AppError::Internal(anyhow::Error::new(error)))?;
    Ok(ProtoBillingEvent {
        id: value.id,
        event_type: value.event_type,
        org_id: value.org_id,
        amount_cents: value.amount_cents,
        currency: value.currency,
        stripe_item_id: value.stripe_item_id,
        metadata: metadata.into(),
        created_at: Some(timestamp(&value.created_at)?).into(),
        ..Default::default()
    })
}

fn proto_environment_usage(
    value: EnvironmentUsageResponse,
) -> AppResult<GetEnvironmentUsageResponse> {
    let hourly_breakdown = value
        .hourly_breakdown
        .unwrap_or_default()
        .into_iter()
        .map(proto_environment_usage_hour)
        .collect::<AppResult<_>>()?;
    let current_month = value.current_month;
    Ok(GetEnvironmentUsageResponse {
        current_month: Some(ProtoEnvironmentUsageMonth {
            cpu_hours: current_month.cpu_hours,
            mem_gb_hours: current_month.mem_gb_hours,
            disk_gb_hours: current_month.disk_gb_hours,
            cost_cents: whole_cents(current_month.cost_nano_eur),
            cost_nano_eur: current_month.cost_nano_eur,
            included_cpu_hours: current_month.included_cpu_hours,
            included_mem_gb_hours: current_month.included_mem_gb_hours,
            ..Default::default()
        })
        .into(),
        hourly_breakdown,
        per_environment: value
            .per_environment
            .unwrap_or_default()
            .into_iter()
            .map(proto_environment_usage_entry)
            .collect(),
        ..Default::default()
    })
}

fn proto_environment_usage_hour(
    value: EnvironmentUsageHour,
) -> AppResult<ProtoEnvironmentUsageHour> {
    Ok(ProtoEnvironmentUsageHour {
        hour: Some(timestamp(&value.hour)?).into(),
        cpu_hours: value.cpu_hours,
        mem_gb_hours: value.mem_gb_hours,
        cost_cents: whole_cents(value.cost_nano_eur),
        cost_nano_eur: value.cost_nano_eur,
        ..Default::default()
    })
}

fn proto_environment_usage_entry(value: EnvironmentUsageEntry) -> ProtoEnvironmentUsageEntry {
    ProtoEnvironmentUsageEntry {
        id: value.id,
        name: value.name,
        running_seconds: value.running_seconds,
        cost_cents: whole_cents(value.cost_nano_eur),
        cpu_millicores: value.cpu_millicores,
        memory_mb: value.memory_mb,
        hourly_cents: whole_cents(value.hourly_nano_eur),
        cost_nano_eur: value.cost_nano_eur,
        hourly_nano_eur: value.hourly_nano_eur,
        ..Default::default()
    }
}

/// A nano-euro amount in whole cents, rounded down, for the superseded
/// `*_cents` fields.
fn whole_cents(nano_eur: i64) -> i32 {
    i32::try_from(nano_eur / crate::credit::NANO_EUR_PER_CENT).unwrap_or(i32::MAX)
}

fn optional_timestamp(value: Option<&str>) -> AppResult<Option<Timestamp>> {
    value.map(timestamp).transpose()
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
    use codewire_server_core::{ConnectCode, ConnectError};

    use super::*;

    #[test]
    fn billing_error_classes_use_canonical_connect_codes() {
        for (error, expected) in [
            (
                AppError::NotFound("billing is not enabled".into()),
                ConnectCode::NotFound,
            ),
            (AppError::Forbidden, ConnectCode::PermissionDenied),
            (
                AppError::Conflict("organization already has a subscription".into()),
                ConnectCode::AlreadyExists,
            ),
            (
                AppError::BadRequest("success_url must use the configured frontend origin".into()),
                ConnectCode::InvalidArgument,
            ),
        ] {
            assert_eq!(ConnectError::from_app_error(&error, None).code, expected);
        }
    }

    #[test]
    fn fractional_cents_convert_to_exact_integer_millicents() {
        assert_eq!(millicents(0.5).unwrap(), 500);
        assert_eq!(millicents(0.25).unwrap(), 250);
        assert_eq!(millicents(0.125).unwrap(), 125);
        assert_eq!(millicents(5.04).unwrap(), 5_040);
    }

    #[test]
    fn usage_none_slices_become_empty_repeated_fields() {
        let response = proto_environment_usage(EnvironmentUsageResponse {
            current_month: crate::overview::EnvironmentUsageMonth {
                cpu_hours: 0.0,
                mem_gb_hours: 0.0,
                disk_gb_hours: 0.0,
                cost_nano_eur: 0,
                included_cpu_hours: 0,
                included_mem_gb_hours: 0,
            },
            hourly_breakdown: None,
            per_environment: None,
        })
        .unwrap();
        assert!(response.hourly_breakdown.is_empty());
        assert!(response.per_environment.is_empty());
    }

    #[test]
    fn stripe_session_response_fields_are_transport_specific() {
        let checkout = CreateCheckoutSessionResponse {
            checkout_url: "https://checkout.stripe.test/checkout".into(),
            ..Default::default()
        };
        let portal = CreatePortalSessionResponse {
            portal_url: "https://billing.stripe.test/portal".into(),
            ..Default::default()
        };
        let setup = CreateSetupSessionResponse {
            checkout_url: "https://checkout.stripe.test/setup".into(),
            ..Default::default()
        };
        assert!(!checkout.checkout_url.is_empty());
        assert!(!portal.portal_url.is_empty());
        assert!(!setup.checkout_url.is_empty());
    }
}
