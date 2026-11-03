use chrono::{DateTime, SecondsFormat, Utc};
use codewire_client::{self as rpc, ClientConfig, CodewireClient};
use serde::{Deserialize, Serialize};

use crate::CLI_VERSION;
use crate::config::ResolvedPlatformConfig;
use crate::environment_client::display_client_error;

/// CLI presentation shape retained across the BillingService flip.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct BillingOverview {
    pub billing_enabled: bool,
    pub has_payment_method: bool,
    pub plan: String,
    pub plan_display_name: String,
    pub status: String,
    pub trial_end: Option<String>,
    pub trial_days: i32,
    pub seat_count: i32,
    pub included_devs: i32,
    pub extra_seat_price_cents: i32,
    pub limits: BillingLimits,
    pub current_period_end: Option<String>,
    pub active_subscriptions: i32,
    pub total_monthly_cost_cents: i32,
    /// The former REST handler faithfully emitted this as JSON null.
    pub subscriptions: Option<Vec<SubscriptionSummary>>,
    pub current_month_usage: UsageSummary,
    /// Prepaid compute credit (#3381), in nano-euros (1e-9 EUR).
    pub credit_balance_nano_eur: i64,
    pub month_usage_nano_eur: i64,
    pub rates: CreditRates,
    /// No charge and no quota.
    pub unmetered: bool,
    pub auto_top_up_enabled: bool,
    pub auto_top_up_cents: i32,
    /// When credit ran out with no way to get more; creates and starts are
    /// refused while it is set.
    pub credit_exhausted_at: Option<String>,
}

/// What a running sandbox costs per unit-hour, in nano-euros.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct CreditRates {
    pub cpu_per_vcpu_hour: i64,
    pub memory_per_gib_hour: i64,
    pub disk_per_gib_hour: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct SubscriptionSummary {
    pub resource_type: String,
    pub plan: String,
    pub plan_display_name: String,
    pub status: String,
    pub monthly_cost_cents: i32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct BillingLimits {
    pub team_members: LimitUsage,
    pub concurrent_workspaces: i32,
    pub storage_gb: i32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct LimitUsage {
    pub used: i32,
    pub max: i32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct UsageSummary {
    pub cpu_hours: f64,
    pub memory_gb_hours: f64,
    pub storage_gb_hours: f64,
}

/// Typed console-service facade while the CLI retains its established billing
/// output DTOs.
#[derive(Clone)]
pub struct ConsoleClient {
    inner: CodewireClient,
}

impl ConsoleClient {
    pub fn new(config: &ResolvedPlatformConfig) -> anyhow::Result<Self> {
        let client_config = ClientConfig::new(&config.server_url)?
            .with_user_agent(format!("codewire-cli/{CLI_VERSION}"))?;
        Ok(Self {
            inner: CodewireClient::with_token_provider(client_config, config.token_provider()?)?,
        })
    }

    pub async fn get_billing_overview(&self, org_id: &str) -> anyhow::Result<BillingOverview> {
        self.inner
            .get_billing_overview(rpc::GetBillingOverviewRequest {
                org_id: org_id.to_string(),
                ..Default::default()
            })
            .await
            .map(legacy_billing_overview)
            .map_err(display_client_error)
    }
}

fn legacy_billing_overview(value: rpc::GetBillingOverviewResponse) -> BillingOverview {
    let rates = value.rates.into_option().unwrap_or_default();
    BillingOverview {
        credit_balance_nano_eur: value.credit_balance_nano_eur,
        month_usage_nano_eur: value.month_usage_nano_eur,
        rates: CreditRates {
            cpu_per_vcpu_hour: rates.cpu_nano_eur_per_vcpu_hour,
            memory_per_gib_hour: rates.memory_nano_eur_per_gib_hour,
            disk_per_gib_hour: rates.disk_nano_eur_per_gib_hour,
        },
        unmetered: value.unmetered,
        auto_top_up_enabled: value.auto_top_up_enabled,
        auto_top_up_cents: value.auto_top_up_cents,
        credit_exhausted_at: value
            .credit_exhausted_at
            .into_option()
            .map(timestamp_to_rfc3339),
        billing_enabled: value.billing_enabled,
        has_payment_method: value.has_payment_method,
        plan: value.plan,
        plan_display_name: value.plan_display_name,
        status: value.status,
        trial_end: value.trial_end.into_option().map(timestamp_to_rfc3339),
        trial_days: value.trial_days,
        seat_count: value.seat_count,
        included_devs: value.included_devs,
        extra_seat_price_cents: value.extra_seat_price_cents,
        limits: value
            .limits
            .into_option()
            .map(legacy_billing_limits)
            .unwrap_or_default(),
        current_period_end: value
            .current_period_end
            .into_option()
            .map(timestamp_to_rfc3339),
        active_subscriptions: value.active_subscriptions,
        total_monthly_cost_cents: value.total_monthly_cost_cents,
        subscriptions: None,
        current_month_usage: value
            .current_month_usage
            .into_option()
            .map(legacy_usage_summary)
            .unwrap_or_default(),
    }
}

fn legacy_billing_limits(value: rpc::BillingLimits) -> BillingLimits {
    BillingLimits {
        team_members: value
            .team_members
            .into_option()
            .map(|value| LimitUsage {
                used: value.used,
                max: value.max,
            })
            .unwrap_or_default(),
        concurrent_workspaces: value.concurrent_workspaces,
        storage_gb: value.storage_gb,
    }
}

fn legacy_usage_summary(value: rpc::UsageSummary) -> UsageSummary {
    UsageSummary {
        cpu_hours: value.cpu_hours,
        memory_gb_hours: value.memory_gb_hours,
        storage_gb_hours: value.storage_gb_hours,
    }
}

fn timestamp_to_rfc3339(timestamp: rpc::Timestamp) -> String {
    DateTime::<Utc>::from_timestamp(timestamp.seconds, timestamp.nanos as u32)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn billing_overview_conversion_preserves_cli_json_shape() {
        let overview = legacy_billing_overview(rpc::GetBillingOverviewResponse {
            billing_enabled: true,
            plan: "team".into(),
            plan_display_name: "Team".into(),
            trial_end: Some(rpc::Timestamp::from_unix_secs(1_785_801_600)).into(),
            limits: Some(rpc::BillingLimits {
                team_members: Some(rpc::BillingLimitUsage {
                    used: 3,
                    max: 10,
                    ..Default::default()
                })
                .into(),
                concurrent_workspaces: 4,
                storage_gb: 100,
                ..Default::default()
            })
            .into(),
            current_month_usage: Some(rpc::UsageSummary {
                cpu_hours: 12.5,
                memory_gb_hours: 32.25,
                storage_gb_hours: 90.0,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        });

        let value = serde_json::to_value(overview).expect("serialize billing overview");
        assert_eq!(value["trial_end"], "2026-08-04T00:00:00Z");
        assert_eq!(value["limits"]["team_members"]["max"], 10);
        assert_eq!(value["subscriptions"], serde_json::Value::Null);
        assert_eq!(value["current_month_usage"]["memory_gb_hours"], 32.25);
    }
}
