//! Connect-RPC adapter for platform network policies (#4000, item 1). Every
//! method answers UNAVAILABLE while the deployment switch is off.

use std::sync::Arc;

use buffa_types::Timestamp;
use chrono::{DateTime, Utc};
use codewire_egress_policy::HOSTED_DEFAULT_NAME;
use codewire_proto::codewire::v1::__buffa::oneof::{network_policy_selector, network_policy_usage};
use codewire_proto::codewire::v1::{
    CreateNetworkPolicyRequest, CreateNetworkPolicyResponse, DeleteNetworkPolicyRequest,
    DeleteNetworkPolicyResponse, EnvironmentNetworkPolicy, GetNetworkPolicyRequest,
    GetNetworkPolicyResponse, ListNetworkPoliciesRequest, ListNetworkPoliciesResponse,
    NetworkPolicy, NetworkPolicyEnforcement, NetworkPolicyRule, NetworkPolicySelector,
    NetworkPolicyService, NetworkPolicyUsage, UpdateEnvironmentNetworkPolicyRequest,
    UpdateEnvironmentNetworkPolicyResponse, UpdateNetworkPolicyRequest,
    UpdateNetworkPolicyResponse,
};
use codewire_server_core::connect::{auth_user, rpc_app_error};
use codewire_server_core::{AppError, AppResult};
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use sqlx::PgPool;

use crate::api::network_policies::{
    EnvironmentPolicyView, NetworkPolicyFlags, PolicyUsage, PolicyView, RuleInput, Selector,
    UsageSelection, create_policy, delete_policy, get_policy, list_policies, policy_usage,
    select_for_environment, update_policy,
};

pub fn router(pool: PgPool, flags: NetworkPolicyFlags) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(NetworkPolicyConnectService { pool, flags }))
}

struct NetworkPolicyConnectService {
    pool: PgPool,
    flags: NetworkPolicyFlags,
}

#[allow(refining_impl_trait)]
impl NetworkPolicyService for NetworkPolicyConnectService {
    async fn create_network_policy(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateNetworkPolicyRequest>,
    ) -> ServiceResult<CreateNetworkPolicyResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let result = async {
            self.flags.require()?;
            let from = request.from.into_option();
            let from = from.as_ref().map(selector).transpose()?;
            let allow = rules(&request.allow);
            create_policy(
                &self.pool,
                &user,
                &request.org_id,
                &request.name,
                from,
                &allow,
            )
            .await
        }
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(CreateNetworkPolicyResponse {
            policy: Some(proto_policy(result)).into(),
            ..Default::default()
        })
    }

    async fn list_network_policies(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListNetworkPoliciesRequest>,
    ) -> ServiceResult<ListNetworkPoliciesResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let result = async {
            self.flags.require()?;
            let policies = list_policies(&self.pool, &user, &request.org_id).await?;
            let usage = policy_usage(&self.pool, &user, &request.org_id).await?;
            Ok::<_, AppError>((policies, usage))
        }
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        let (policies, usage) = result;
        connectrpc::Response::ok(ListNetworkPoliciesResponse {
            policies: policies.into_iter().map(proto_policy).collect(),
            usage: usage.into_iter().map(proto_usage).collect(),
            ..Default::default()
        })
    }

    async fn get_network_policy(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetNetworkPolicyRequest>,
    ) -> ServiceResult<GetNetworkPolicyResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let result = async {
            self.flags.require()?;
            let policy = request.policy.into_option();
            let policy = required_selector(policy.as_ref())?;
            let revision = (request.revision != 0).then_some(request.revision);
            get_policy(&self.pool, &user, &request.org_id, policy, revision).await
        }
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(GetNetworkPolicyResponse {
            policy: Some(proto_policy(result)).into(),
            ..Default::default()
        })
    }

    async fn update_network_policy(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateNetworkPolicyRequest>,
    ) -> ServiceResult<UpdateNetworkPolicyResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let result = async {
            self.flags.require()?;
            let policy = request.policy.into_option();
            let policy = required_selector(policy.as_ref())?;
            let allow = rules(&request.allow);
            let remove: Vec<&str> = request.remove.iter().map(String::as_str).collect();
            let expected = (request.expected_revision != 0).then_some(request.expected_revision);
            update_policy(
                &self.pool,
                &user,
                &request.org_id,
                policy,
                &allow,
                &remove,
                expected,
            )
            .await
        }
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(UpdateNetworkPolicyResponse {
            policy: Some(proto_policy(result)).into(),
            ..Default::default()
        })
    }

    async fn delete_network_policy(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteNetworkPolicyRequest>,
    ) -> ServiceResult<DeleteNetworkPolicyResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let result = async {
            self.flags.require()?;
            let policy = request.policy.into_option();
            let policy = required_selector(policy.as_ref())?;
            delete_policy(&self.pool, &user, &request.org_id, policy).await
        }
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(DeleteNetworkPolicyResponse {
            policy: Some(proto_policy(result)).into(),
            ..Default::default()
        })
    }

    async fn update_environment_network_policy(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateEnvironmentNetworkPolicyRequest>,
    ) -> ServiceResult<UpdateEnvironmentNetworkPolicyResponse> {
        let user = auth_user(&ctx)?.clone();
        let request = request.to_owned_message();
        let result = async {
            self.flags.require()?;
            select_for_environment(
                &self.pool,
                &user,
                &request.org_id,
                &request.environment_id,
                &request.network_policy,
            )
            .await
        }
        .await
        .map_err(|error| rpc_app_error(&error, &ctx))?;
        connectrpc::Response::ok(UpdateEnvironmentNetworkPolicyResponse {
            network_policy: Some(proto_environment_policy(result)).into(),
            ..Default::default()
        })
    }
}

fn selector(value: &NetworkPolicySelector) -> AppResult<Selector<'_>> {
    match &value.selector {
        Some(network_policy_selector::Selector::Name(name)) => Ok(Selector::Name(name)),
        Some(network_policy_selector::Selector::Id(id)) => Ok(Selector::Id(id)),
        None => Err(no_selector()),
    }
}

fn required_selector(value: Option<&NetworkPolicySelector>) -> AppResult<Selector<'_>> {
    selector(value.ok_or_else(no_selector)?)
}

fn no_selector() -> AppError {
    AppError::Validation {
        errors: vec![codewire_server_core::ValidationIssue {
            path: "/policy".into(),
            message: "must name a policy by name or id".into(),
        }],
    }
}

fn rules(values: &[NetworkPolicyRule]) -> Vec<RuleInput<'_>> {
    values
        .iter()
        .map(|rule| RuleInput {
            target: &rule.target,
            ports: &rule.ports,
        })
        .collect()
}

fn proto_timestamp(value: DateTime<Utc>) -> Timestamp {
    Timestamp::from_unix(value.timestamp(), value.timestamp_subsec_nanos() as i32)
}

fn proto_policy(view: PolicyView) -> NetworkPolicy {
    NetworkPolicy {
        id: view.id,
        org_id: view.org_id,
        name: view.name,
        revision: view.revision,
        current_revision: view.current_revision,
        rules: view
            .policy
            .rules()
            .iter()
            .map(|rule| NetworkPolicyRule {
                target: rule.target().to_string(),
                ports: rule.ports().iter().copied().map(u32::from).collect(),
                ..Default::default()
            })
            .collect(),
        digest: view.digest,
        created_at: Some(proto_timestamp(view.created_at)).into(),
        created_by: view.created_by.unwrap_or_default(),
        ..Default::default()
    }
}

fn proto_usage(usage: PolicyUsage) -> NetworkPolicyUsage {
    NetworkPolicyUsage {
        selection: Some(match usage.selection {
            UsageSelection::Policy(id) => network_policy_usage::Selection::PolicyId(id),
            UsageSelection::Builtin(builtin) => {
                network_policy_usage::Selection::Builtin(builtin.name().to_owned())
            }
            UsageSelection::HostedDefault => {
                network_policy_usage::Selection::Builtin(HOSTED_DEFAULT_NAME.to_owned())
            }
        }),
        environments: usage.environments,
        names: usage.names,
        ..Default::default()
    }
}

/// The environment read's form: the selection, and what cw-egress reports
/// the environment's current Pod enforces (#4000).
pub(crate) fn proto_environment_policy(view: EnvironmentPolicyView) -> EnvironmentNetworkPolicy {
    use crate::api::network_policies::EnforcementView;
    let failure_code = match view.enforcement {
        EnforcementView::FailedClosed(reason) => reason.code(),
        _ => "",
    };
    let (enforcement, enforced) = match view.enforcement {
        EnforcementView::NotEnforced => (
            NetworkPolicyEnforcement::NETWORK_POLICY_ENFORCEMENT_NOT_ENFORCED,
            None,
        ),
        EnforcementView::Enforced(at) => (
            NetworkPolicyEnforcement::NETWORK_POLICY_ENFORCEMENT_ENFORCED,
            Some(at),
        ),
        EnforcementView::Enforcing(at) => (
            NetworkPolicyEnforcement::NETWORK_POLICY_ENFORCEMENT_ENFORCING,
            Some(at),
        ),
        EnforcementView::FailedClosed(_) => (
            NetworkPolicyEnforcement::NETWORK_POLICY_ENFORCEMENT_FAILED_CLOSED,
            None,
        ),
    };
    let (enforced_revision, enforced_digest, enforced_at) = match enforced {
        Some(enforced) => (
            enforced.revision,
            enforced.digest,
            Some(proto_timestamp(enforced.at)).into(),
        ),
        None => (0, String::new(), None.into()),
    };
    EnvironmentNetworkPolicy {
        reference: view.reference,
        name: view.name,
        revision: view.revision,
        digest: view.digest,
        enforcement: enforcement.into(),
        enforced_revision,
        enforced_digest,
        enforced_at,
        failure_code: failure_code.to_owned(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use codewire_server_core::auth::AuthUser;
    use codewire_server_core::connect::connect_router;
    use tower::ServiceExt as _;

    /// With the deployment switch off, every method answers UNAVAILABLE before
    /// it reads the request's organization or touches the database: the pool
    /// here is lazy and points at a documentation address that answers nothing.
    #[tokio::test]
    async fn every_method_is_unavailable_while_the_switch_is_off() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://fixture:fixture@192.0.2.1:1/fixture")
            .unwrap();
        let app = connect_router(router(pool, NetworkPolicyFlags::default()));
        for method in [
            "CreateNetworkPolicy",
            "ListNetworkPolicies",
            "GetNetworkPolicy",
            "UpdateNetworkPolicy",
            "DeleteNetworkPolicy",
            "UpdateEnvironmentNetworkPolicy",
        ] {
            let mut request = Request::post(format!("/codewire.v1.NetworkPolicyService/{method}"))
                .header("content-type", "application/json")
                .header("connect-protocol-version", "1")
                .body(Body::from(r#"{"orgId":"org-one"}"#))
                .unwrap();
            request.extensions_mut().insert(AuthUser {
                user_id: "synthetic-member".into(),
                org_id: None,
                is_admin: false,
                via_api_key: false,
            });
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                app.clone().oneshot(request),
            )
            .await
            .expect("the switch answers before any database access")
            .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{method}"
            );
            let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            let body = String::from_utf8_lossy(&body);
            assert!(body.contains("unavailable"), "{method}: {body}");
            assert!(body.contains("not enabled"), "{method}: {body}");
        }
    }

    #[test]
    fn every_selection_reports_not_enforced_until_cw_egress_exists() {
        let wire = proto_environment_policy(EnvironmentPolicyView {
            reference: "platform:id:6b1f7c55-2a4f-4b8e-9d4b-1f2e3d4c5b6a".into(),
            name: "web".into(),
            revision: 2,
            digest: "aa".into(),
            enforcement: crate::api::network_policies::EnforcementView::NotEnforced,
        });
        assert_eq!(
            wire.enforcement.as_known(),
            Some(NetworkPolicyEnforcement::NETWORK_POLICY_ENFORCEMENT_NOT_ENFORCED)
        );
        assert_eq!(
            (wire.enforced_revision, wire.enforced_digest.as_str()),
            (0, "")
        );
        assert!(wire.enforced_at.as_option().is_none());
        assert_eq!((wire.revision, wire.digest.as_str()), (2, "aa"));
    }
}
