//! A one-time credit purchase: "Add credit" on the Billing page (#3381;
//! owner, 2026-11-11: "Saved card, Stripe if needed").
//!
//! - **Saved card.** The purchase is a `billing_top_ups` row charged exactly
//!   as an automatic top-up is ([`StripeHandle::charge_top_up`]: its own EUR
//!   invoice, paid off-session, every step keyed on the top-up id). The row
//!   takes the organization's one pending slot, so it never races the
//!   automatic sweep, and the sweep resumes it if this request dies mid-way.
//!   - Paid: [`complete_top_up`] credits it.
//!   - The bank wants the customer to approve it (SCA): the top-up is
//!     recorded as failed with `authentication_required`, which frees the
//!     slot, and the customer is sent to the invoice's Stripe page. Paying
//!     there sends `invoice.paid`, whose handler completes the top-up and
//!     credits it once, failed or not.
//!   - Declined: [`fail_top_up`] records it; nothing is credited.
//! - **No card.** A payment-mode Checkout session takes the card and the
//!   payment together and saves the card. Its `checkout.session.completed`
//!   delivery credits the purchase and makes the card the default
//!   ([`crate::webhook`]). Nothing is pending meanwhile: an abandoned page
//!   holds nothing up.
//!
//! The top-up id is derived from the organization, the client's request id
//! and the amount, so a retry of the same request finds the same purchase and
//! never charges twice.
//!
//! [`StripeHandle::charge_top_up`]: crate::stripe_client::StripeHandle
//! [`complete_top_up`]: crate::credit::complete_top_up
//! [`fail_top_up`]: crate::credit::fail_top_up

use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    OrganizationBillingMutationError, run_organization_billing_mutation,
};
use codewire_server_core::{AppError, AppResult, ValidationIssue};
use sha2::{Digest, Sha256};

use crate::checkout_sessions::{billing_idempotency_key, org_identity, require_billing_admin};
use crate::credit::{complete_top_up, fail_top_up, top_up_ledger_key};
use crate::overview::AUTO_TOP_UP_CENTS;
use crate::routes::BillingState;
use crate::stripe_client::{AUTHENTICATION_REQUIRED, CreditCheckout, TopUpCharge, failure_code};

/// One purchase as the caller asked for it.
#[derive(Debug, Clone)]
pub struct AddCreditRequest {
    pub amount_cents: i32,
    pub request_id: String,
    pub success_url: String,
    pub cancel_url: String,
}

/// How a purchase ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddCreditOutcome {
    /// The card was charged and the credit added.
    Paid,
    /// The customer approves the charge, or pays, on this Stripe page.
    ActionRequired { payment_url: String },
    /// The card was declined; nothing was charged. Stripe's code, made safe.
    Declined { code: String },
    /// Another top-up of the organization is being charged.
    InProgress,
}

/// The purchase a request names: the same organization, request id and
/// amount always give the same id.
pub(crate) fn purchase_top_up_id(
    organization_id: &str,
    request_id: &str,
    amount_cents: i32,
) -> String {
    let mut hasher = Sha256::new();
    for part in [organization_id, request_id, &amount_cents.to_string()] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    let mut id = String::from("credit-");
    for byte in &digest[..16] {
        id.push_str(&format!("{byte:02x}"));
    }
    id
}

fn valid_request_id(request_id: &str) -> bool {
    (16..=64).contains(&request_id.len())
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn invalid(path: &'static str, message: &'static str) -> AppError {
    AppError::Validation {
        errors: vec![ValidationIssue {
            path: path.into(),
            message: message.into(),
        }],
    }
}

/// Buys `request.amount_cents` of credit for an organization, for one of its
/// owners or admins.
pub async fn add_credit(
    state: &BillingState,
    user: &AuthUser,
    organization_id: &str,
    request: AddCreditRequest,
) -> AppResult<AddCreditOutcome> {
    require_billing_admin(state, user, organization_id).await?;
    if !AUTO_TOP_UP_CENTS.contains(&request.amount_cents) {
        return Err(invalid("/amount_cents", "must be between 500 and 100000"));
    }
    if !valid_request_id(&request.request_id) {
        return Err(invalid(
            "/request_id",
            "must be 16 to 64 letters, digits, '-' or '_'",
        ));
    }
    if request.success_url.is_empty() || request.cancel_url.is_empty() {
        return Err(AppError::BadRequest(
            "success_url and cancel_url are required".into(),
        ));
    }
    state
        .frontend_origin
        .validate_redirect("success_url", &request.success_url)?;
    state
        .frontend_origin
        .validate_redirect("cancel_url", &request.cancel_url)?;

    let top_up_id = purchase_top_up_id(organization_id, &request.request_id, request.amount_cents);
    if let Some(outcome) = earlier_attempt(state, organization_id, &top_up_id).await? {
        return Ok(outcome);
    }
    if !state
        .stripe
        .org_has_payment_method(&state.pool, organization_id)
        .await
    {
        return checkout(state, organization_id, &top_up_id, &request).await;
    }
    let created: Option<String> = sqlx::query_scalar(
        r#"INSERT INTO billing_top_ups (id, organization_id, amount_cents)
           VALUES ($1, $2, $3)
           ON CONFLICT DO NOTHING
           RETURNING id"#,
    )
    .bind(&top_up_id)
    .bind(organization_id)
    .bind(request.amount_cents)
    .fetch_optional(&state.pool)
    .await?;
    if created.is_none() {
        // Either a retry of this request got here first, or another top-up
        // holds the organization's pending slot.
        return Ok(earlier_attempt(state, organization_id, &top_up_id)
            .await?
            .unwrap_or(AddCreditOutcome::InProgress));
    }
    charge(state, organization_id, &top_up_id, request.amount_cents).await
}

/// What an earlier attempt of the same purchase came to, resuming one that
/// is still pending. `None` when there was none.
async fn earlier_attempt(
    state: &BillingState,
    organization_id: &str,
    top_up_id: &str,
) -> AppResult<Option<AddCreditOutcome>> {
    let pool = &state.pool;
    let credited: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM billing_credit_ledger \
         WHERE organization_id = $1 AND idempotency_key = $2)",
    )
    .bind(organization_id)
    .bind(top_up_ledger_key(top_up_id))
    .fetch_one(pool)
    .await?;
    if credited {
        return Ok(Some(AddCreditOutcome::Paid));
    }
    type Row = (String, i32, Option<String>, Option<String>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT state, amount_cents, stripe_invoice_id, failure_code FROM billing_top_ups \
         WHERE id = $1 AND organization_id = $2",
    )
    .bind(top_up_id)
    .bind(organization_id)
    .fetch_optional(pool)
    .await?;
    let Some((top_up_state, amount_cents, invoice_id, code)) = row else {
        return Ok(None);
    };
    match (top_up_state.as_str(), invoice_id, code) {
        ("paid", _, _) => Ok(Some(AddCreditOutcome::Paid)),
        ("pending", _, _) => Ok(Some(
            charge(state, organization_id, top_up_id, amount_cents).await?,
        )),
        ("failed", Some(invoice_id), Some(code)) if code == AUTHENTICATION_REQUIRED => {
            let payment = state
                .stripe
                .invoice_payment(&invoice_id)
                .await
                .inspect_err(|error| {
                    tracing::warn!(
                        organization_id,
                        top_up_id,
                        ?error,
                        "add credit: invoice lookup failed"
                    );
                })?;
            if payment.paid {
                complete_top_up(pool, top_up_id, &invoice_id)
                    .await
                    .map_err(AppError::Internal)?;
                return Ok(Some(AddCreditOutcome::Paid));
            }
            Ok(Some(match payment.payment_url {
                Some(payment_url) if payment.open => {
                    AddCreditOutcome::ActionRequired { payment_url }
                }
                _ => AddCreditOutcome::Declined { code },
            }))
        }
        (_, _, code) => Ok(Some(AddCreditOutcome::Declined {
            code: failure_code(code.as_deref()),
        })),
    }
}

/// Charges a pending purchase to the saved card and records how it ended.
async fn charge(
    state: &BillingState,
    organization_id: &str,
    top_up_id: &str,
    amount_cents: i32,
) -> AppResult<AddCreditOutcome> {
    let pool = &state.pool;
    let customer: Option<String> =
        sqlx::query_scalar("SELECT stripe_customer_id FROM organizations WHERE id = $1")
            .bind(organization_id)
            .fetch_optional(pool)
            .await?
            .flatten()
            .filter(|customer: &String| !customer.is_empty());
    let Some(customer) = customer else {
        fail_top_up(pool, top_up_id, None, "no_customer")
            .await
            .map_err(AppError::Internal)?;
        return Ok(AddCreditOutcome::Declined {
            code: "no_customer".to_owned(),
        });
    };
    let charged = run_organization_billing_mutation(pool, organization_id, async {
        state
            .stripe
            .charge_top_up(
                &customer,
                organization_id,
                top_up_id,
                i64::from(amount_cents),
            )
            .await
            .map_err(OrganizationBillingMutationError::ambiguous)
    })
    .await;
    match charged {
        Ok(TopUpCharge::Paid { invoice_id }) => {
            complete_top_up(pool, top_up_id, &invoice_id)
                .await
                .map_err(AppError::Internal)?;
            Ok(AddCreditOutcome::Paid)
        }
        Ok(TopUpCharge::Declined { invoice_id, code }) => {
            fail_top_up(pool, top_up_id, invoice_id.as_deref(), &code)
                .await
                .map_err(AppError::Internal)?;
            Ok(AddCreditOutcome::Declined {
                code: failure_code(Some(&code)),
            })
        }
        Ok(TopUpCharge::ActionRequired {
            invoice_id,
            payment_url,
        }) => {
            // Released, so the organization's pending slot is not held while
            // the customer decides; paying the invoice still credits it.
            fail_top_up(pool, top_up_id, Some(&invoice_id), AUTHENTICATION_REQUIRED)
                .await
                .map_err(AppError::Internal)?;
            Ok(AddCreditOutcome::ActionRequired { payment_url })
        }
        Err(error) => {
            // The top-up stays pending; the credit sweep resumes the same
            // charge within a minute.
            tracing::warn!(
                organization_id,
                top_up_id,
                ?error,
                "add credit: charge unconfirmed"
            );
            Err(AppError::ServiceUnavailable(
                "the payment could not be confirmed yet; it is retried automatically".into(),
            ))
        }
    }
}

/// Opens Stripe's payment page for an organization with no saved card.
async fn checkout(
    state: &BillingState,
    organization_id: &str,
    top_up_id: &str,
    request: &AddCreditRequest,
) -> AppResult<AddCreditOutcome> {
    let pool = &state.pool;
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM billing_top_ups WHERE organization_id = $1 AND state = 'pending')",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await?;
    if pending {
        return Ok(AddCreditOutcome::InProgress);
    }
    let result = async {
        let (name, owner_email) = org_identity(pool, organization_id).await?;
        let customer_key = billing_idempotency_key("customer", &[organization_id]);
        let customer_id = run_organization_billing_mutation(pool, organization_id, async {
            state
                .stripe
                .ensure_customer(pool, organization_id, &name, &owner_email, &customer_key)
                .await
                .map_err(OrganizationBillingMutationError::ambiguous)
        })
        .await?;
        run_organization_billing_mutation(pool, organization_id, async {
            state
                .stripe
                .create_credit_checkout_session(&CreditCheckout {
                    customer_id: &customer_id,
                    organization_id,
                    top_up_id,
                    amount_cents: i64::from(request.amount_cents),
                    success_url: &request.success_url,
                    cancel_url: &request.cancel_url,
                })
                .await
                .map_err(OrganizationBillingMutationError::ambiguous)
        })
        .await
    }
    .await;
    match result {
        Ok(payment_url) => Ok(AddCreditOutcome::ActionRequired { payment_url }),
        Err(error) => {
            tracing::error!(?error, "billing: credit checkout session failed");
            Err(AppError::InternalMsg(
                "failed to create checkout session".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests;
