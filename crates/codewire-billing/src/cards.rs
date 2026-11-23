//! Saved cards (#4750): the console adds a card in the page, through Stripe's
//! card form on a SetupIntent, instead of sending the customer to a Stripe
//! page; it lists the organization's cards, makes one the default and
//! removes one.
//!
//! Adding a card is two calls around the form, which mounts without a
//! SetupIntent. When the customer saves, [`begin_card_setup`] makes the
//! SetupIntent with the [`CardChoices`] made beside the form written into its
//! metadata, and returns the secret the form confirms with. Once the card is
//! confirmed, [`finish_card_setup`] checks the SetupIntent is this
//! organization's, succeeded, and can still be finished, makes its card the
//! default, buys any credit chosen with it (Add credit with no card yet),
//! saves the automatic top-up setting chosen, and settles the organization at
//! once. With top-up on and still no credit, that charges the stated amount,
//! through the same invoice path as every top-up, so it has a receipt. The
//! credit is bought before the setting is saved, so top-up never charges on
//! top of it.
//!
//! Finish takes nothing but the SetupIntent: every choice is read from the
//! metadata Begin wrote with the secret key, so a request or a crafted link
//! can't choose what a finish buys or sets (#4750).
//!
//! Every charge stays where it was: automatic top-up and Add credit. Saving a
//! card charges nothing by itself.
//!
//! Begin is limited per organization, per user and per client address
//! (docs/CONFIGURATION.md, "Card setup limits"). The address is the last
//! `X-Forwarded-For` hop: the dashboard's own, which replaces the browser's,
//! or the edge's on the public API. Billing's NetworkPolicy admits only those
//! two, so nothing else can write it (#4901).

use std::net::IpAddr;

use codewire_server_core::auth::AuthUser;
use codewire_server_core::client_address::unit_hash;
use codewire_server_core::internal_hmac::derive_internal_hmac_secret;
use codewire_server_core::org::require_org_member;
use codewire_server_core::org_deletion::{
    OrganizationBillingMutationError, run_organization_billing_mutation,
};
use codewire_server_core::rate_limit::{
    CARD_SETUP_ADDRESS, CARD_SETUP_ORGANIZATION, CARD_SETUP_USER, Limit, take, take_fixed,
};
use codewire_server_core::{AppError, AppResult, ValidationIssue};

use crate::checkout_sessions::{billing_idempotency_key, org_identity, require_billing_admin};
use crate::credit::Settlement;
use crate::credit_purchase::AddCreditOutcome;
use crate::overview::AUTO_TOP_UP_CENTS;
use crate::routes::BillingState;
use crate::stripe_client::SavedCard;

/// The label the card-setup address key is derived under from billing's
/// session secret, so the key is never the secret itself nor another
/// service's. Changing it restarts every address's count.
const CLIENT_ADDRESS_KEY_LABEL: &str = "codewire/billing-card-setup-client-address/v1";

/// The key of the client-address hash [`CARD_SETUP_ADDRESS`] counts under.
#[derive(Clone)]
pub struct CardSetupAddressKey(String);

impl std::fmt::Debug for CardSetupAddressKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CardSetupAddressKey([redacted])")
    }
}

impl CardSetupAddressKey {
    pub fn derive(session_secret: &str) -> anyhow::Result<Self> {
        derive_internal_hmac_secret(session_secret, CLIENT_ADDRESS_KEY_LABEL)
            .map(Self)
            .map_err(|_| anyhow::anyhow!("the session secret for card-setup limits is not set"))
    }

    /// A key of its own per `seed`, so tests sharing a database count apart.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(seed: &str) -> Self {
        Self(format!("synthetic-card-setup-address-key-{seed}"))
    }
}

/// An organization's saved cards, which is the default, and the publishable
/// key Stripe's card form mounts with: `None` when the form is not
/// configured.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CardList {
    pub cards: Vec<SavedCard>,
    pub default_id: Option<String>,
    pub publishable_key: Option<String>,
}

/// What the card form confirms the new card with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardSetup {
    pub client_secret: String,
}

/// What adding a card is for, chosen beside the form before saving: the
/// automatic top-up setting, and any credit to buy with the card.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardChoices {
    pub auto_top_up_enabled: bool,
    /// EUR 5 to EUR 1,000, in cents.
    pub auto_top_up_cents: i32,
    /// Credit to buy with the new card, as Add credit does with a saved
    /// one: EUR 5 to EUR 1,000 in cents.
    pub credit_cents: Option<i32>,
}

const ORG_ID: &str = "org_id";
const AUTO_TOP_UP: &str = "auto_top_up";
const AUTO_TOP_UP_CENTS_KEY: &str = "auto_top_up_cents";
const CREDIT_CENTS: &str = "credit_cents";
const FINISHED_AT: &str = "finished_at";

/// How long after Begin a card setup can be finished. A bank's check takes
/// minutes; an hour also stays well inside the 24 hours Stripe keeps the
/// idempotency keys a repeated finish relies on.
pub const CARD_SETUP_FINISH_WINDOW: std::time::Duration = std::time::Duration::from_secs(60 * 60);

impl CardChoices {
    fn check(&self) -> AppResult<()> {
        if !AUTO_TOP_UP_CENTS.contains(&self.auto_top_up_cents) {
            return Err(out_of_range("/auto_top_up_cents"));
        }
        if let Some(cents) = self.credit_cents
            && !AUTO_TOP_UP_CENTS.contains(&cents)
        {
            return Err(out_of_range("/credit_cents"));
        }
        Ok(())
    }

    fn metadata(&self, org_id: &str) -> std::collections::HashMap<String, String> {
        let mut metadata = std::collections::HashMap::from([
            (ORG_ID.to_owned(), org_id.to_owned()),
            (AUTO_TOP_UP.to_owned(), self.auto_top_up_enabled.to_string()),
            (
                AUTO_TOP_UP_CENTS_KEY.to_owned(),
                self.auto_top_up_cents.to_string(),
            ),
        ]);
        if let Some(cents) = self.credit_cents {
            metadata.insert(CREDIT_CENTS.to_owned(), cents.to_string());
        }
        metadata
    }

    /// The choices Begin wrote, when every field is there and passes Begin's
    /// checks.
    fn from_metadata(metadata: &std::collections::HashMap<String, String>) -> Option<Self> {
        let choices = Self {
            auto_top_up_enabled: metadata.get(AUTO_TOP_UP)?.parse().ok()?,
            auto_top_up_cents: metadata.get(AUTO_TOP_UP_CENTS_KEY)?.parse().ok()?,
            credit_cents: match metadata.get(CREDIT_CENTS) {
                Some(cents) => Some(cents.parse().ok()?),
                None => None,
            },
        };
        choices.check().ok().map(|()| choices)
    }
}

fn out_of_range(path: &'static str) -> AppError {
    AppError::Validation {
        errors: vec![ValidationIssue {
            path: path.into(),
            message: "must be between 500 and 100000".into(),
        }],
    }
}

/// The organization's saved cards. Any member may see them; an organization
/// with no Stripe customer, or where billing is off, has none.
pub async fn list_cards(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<CardList> {
    require_org_member(&state.pool, user, org_id).await?;
    if !state.stripe.is_configured() {
        return Ok(CardList::default());
    }
    let publishable_key = state.stripe.publishable_key().map(str::to_owned);
    let Some(customer_id) = customer_id(state, org_id).await? else {
        return Ok(CardList {
            publishable_key,
            ..CardList::default()
        });
    };
    let (cards, default_id) = state.stripe.list_cards(&customer_id).await?;
    Ok(CardList {
        cards,
        default_id,
        publishable_key,
    })
}

/// Starts adding a card once the customer saves it: the organization's
/// Stripe customer (made if it has none) and a SetupIntent for one card,
/// with `choices` in its metadata. Owners and admins only. `address` is the
/// request's client address, which the per-address cap counts.
pub async fn begin_card_setup(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
    choices: CardChoices,
    address: Option<IpAddr>,
) -> AppResult<CardSetup> {
    require_billing_admin(state, user, org_id).await?;
    // Checked first: a request Finish would refuse takes no try from the caps.
    choices.check()?;
    limit_card_setups(state, user, org_id, address).await?;
    if state.stripe.publishable_key().is_none() {
        return Err(AppError::NotFound("the card form is not configured".into()));
    }
    let (org_name, owner_email) = org_identity(&state.pool, org_id).await?;
    let customer_idempotency_key = billing_idempotency_key("customer", &[org_id]);
    let customer_id = run_organization_billing_mutation(&state.pool, org_id, async {
        state
            .stripe
            .ensure_customer(
                &state.pool,
                org_id,
                &org_name,
                &owner_email,
                &customer_idempotency_key,
            )
            .await
            .map_err(OrganizationBillingMutationError::ambiguous)
    })
    .await?;
    let intent = run_organization_billing_mutation(&state.pool, org_id, async {
        state
            .stripe
            .create_card_setup_intent(&customer_id, choices.metadata(org_id))
            .await
            .map_err(OrganizationBillingMutationError::ambiguous)
    })
    .await?;
    let client_secret = intent.client_secret.ok_or_else(|| {
        AppError::InternalMsg("Stripe returned a SetupIntent without its secret".into())
    })?;
    Ok(CardSetup { client_secret })
}

/// Credit bought with a new card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCardCredit {
    pub amount_cents: i32,
    pub outcome: AddCreditOutcome,
}

/// What finishing a card setup did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardSetupResult {
    pub settlement: Settlement,
    /// The credit bought with the card; `None` when none was chosen.
    pub credit: Option<NewCardCredit>,
    /// The automatic top-up setting saved, as chosen at Begin.
    pub auto_top_up_enabled: bool,
}

/// Bounds how many SetupIntents an organization, a user and a client address
/// can start, so the card form can't be used to test stolen cards (#4750,
/// #4901): every start counts, confirmed or not, organization first, as the
/// shared counter asks. A start with no address is refused before anything
/// counts, never let through. A refusal is counted in
/// `codewire_rate_limit_refusals_total`.
async fn limit_card_setups(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
    address: Option<IpAddr>,
) -> AppResult<()> {
    let Some(address) = unit_hash(&state.card_setup_address_key.0, address) else {
        tracing::error!(
            organization_id = org_id,
            "card setup refused: the request named no client address"
        );
        return Err(AppError::Coded {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: "client_address_required",
            detail: "Codewire can't tell where this card setup came from, so it can't start it"
                .into(),
        });
    };
    let mut connection = state.pool.acquire().await?;
    let limits: [(&'static Limit, &str); 3] = [
        (&CARD_SETUP_ORGANIZATION, org_id),
        (&CARD_SETUP_USER, user.user_id.as_str()),
        (&CARD_SETUP_ADDRESS, &address),
    ];
    for (limit, subject) in limits {
        // The organization and user caps are fixed; the address cap is the
        // operator's count, else its default, so a larger group behind one
        // address can be let through.
        let decision = if limit.name == CARD_SETUP_ADDRESS.name {
            take(&mut connection, limit, subject).await?
        } else {
            take_fixed(&mut connection, limit, subject).await?
        };
        if !decision.allowed {
            // The refusal metric carries only the limit's name; this names
            // who reached it, for the card-testing alert that is #4750's
            // Production enablement condition.
            tracing::warn!(
                organization_id = org_id,
                user_id = %user.user_id,
                limit = limit.name,
                "card setup refused by its rate limit"
            );
            return Err(AppError::Coded {
                status: axum::http::StatusCode::TOO_MANY_REQUESTS,
                code: "rate_limited",
                detail: decision.refusal("card setups", limit).into(),
            });
        }
    }
    Ok(())
}

/// Finishes adding a card once the form confirmed it: the SetupIntent must
/// be this organization's, have succeeded, and still be finishable (see
/// [`finishable_choices`]). Its card becomes the default, the credit chosen
/// at Begin is bought with it, the top-up setting chosen at Begin is saved
/// (audited), and the organization is settled at once; the settlement says
/// whether that charged the card.
///
/// Finishing twice charges once. The purchase is keyed by the SetupIntent,
/// and `billing_top_ups.id`'s primary key, a database constraint, admits one
/// purchase per key, while `billing_top_ups_one_pending_idx` admits one
/// pending top-up per organization; the default change and the top-up's
/// Stripe calls are idempotent on their keys. A second finish is also refused
/// once the first has marked the SetupIntent, though two at the same moment
/// can both pass that read.
pub async fn finish_card_setup(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
    setup_intent_id: &str,
) -> AppResult<CardSetupResult> {
    require_billing_admin(state, user, org_id).await?;
    let customer_id = customer_id(state, org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("this organization has no card setup".into()))?;
    let intent = state.stripe.retrieve_setup_intent(setup_intent_id).await?;
    let payment_method = setup_intent_card(&intent, &customer_id, org_id)?;
    // Everything is checked before any change: a refused finish must not
    // surface after the card is the default and charged.
    let now = chrono::Utc::now();
    let choices = finishable_choices(intent.metadata.as_ref(), intent.created, now.timestamp())?;
    if let Some(amount_cents) = choices.credit_cents {
        crate::credit_purchase::check_purchase(
            amount_cents,
            setup_intent_id,
            "/credit_cents",
            "/setup_intent_id",
        )?;
    }
    // Keyed by the SetupIntent, so a retried finish replays the same change.
    let key = billing_idempotency_key("default-card", &[org_id, setup_intent_id]);
    run_organization_billing_mutation(&state.pool, org_id, async {
        state
            .stripe
            .set_default_payment_method(&customer_id, &payment_method, &key)
            .await
            .map_err(OrganizationBillingMutationError::ambiguous)
    })
    .await?;
    let credit = match choices.credit_cents {
        Some(amount_cents) => Some(NewCardCredit {
            amount_cents,
            outcome: crate::credit_purchase::buy_with_new_card(
                state,
                org_id,
                amount_cents,
                setup_intent_id,
            )
            .await?,
        }),
        None => None,
    };
    crate::overview::update_auto_top_up(
        &state.pool,
        user,
        org_id,
        choices.auto_top_up_enabled,
        choices.auto_top_up_cents,
    )
    .await?;
    let settlement = crate::credit::settle_organization(
        &state.pool,
        &state.stripe,
        state.credit_enforcement,
        org_id,
        true,
    )
    .await
    .map_err(|error| AppError::InternalMsg(format!("settle after a new card: {error:#}").into()))?;
    // Marked last, so a finish that failed part-way can be retried.
    if let Err(error) = state
        .stripe
        .add_setup_intent_metadata(setup_intent_id, FINISHED_AT, &now.to_rfc3339())
        .await
    {
        tracing::warn!(
            organization_id = org_id,
            setup_intent_id,
            ?error,
            "card setup finished but not marked finished"
        );
    }
    Ok(CardSetupResult {
        settlement,
        credit,
        auto_top_up_enabled: choices.auto_top_up_enabled,
    })
}

/// The choices Begin wrote into a SetupIntent's `metadata`, when it can be
/// finished: not finished before, within [`CARD_SETUP_FINISH_WINDOW`] of its
/// `created` time, and with all of Begin's fields passing Begin's checks.
/// Times are Unix seconds.
fn finishable_choices(
    metadata: Option<&std::collections::HashMap<String, String>>,
    created: i64,
    now: i64,
) -> AppResult<CardChoices> {
    let empty = std::collections::HashMap::new();
    let metadata = metadata.unwrap_or(&empty);
    if metadata.contains_key(FINISHED_AT) {
        return Err(AppError::Conflict("this card was already added".into()));
    }
    let window = i64::try_from(CARD_SETUP_FINISH_WINDOW.as_secs()).unwrap_or(i64::MAX);
    if now.saturating_sub(created) > window {
        return Err(AppError::Conflict(
            "this card setup expired; nothing was charged or changed".into(),
        ));
    }
    CardChoices::from_metadata(metadata)
        .ok_or_else(|| AppError::Conflict("this card setup has no choices from its start".into()))
}

/// The card a finished SetupIntent saved, when it is this organization's.
fn setup_intent_card(
    intent: &stripe_shared::SetupIntent,
    customer_id: &str,
    org_id: &str,
) -> AppResult<String> {
    let customer = intent.customer.as_ref().map(expandable_id);
    let ours = customer.as_deref() == Some(customer_id)
        && intent
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get(ORG_ID))
            .map(String::as_str)
            == Some(org_id);
    if !ours {
        return Err(AppError::NotFound("card setup not found".into()));
    }
    if intent.status != stripe_shared::SetupIntentStatus::Succeeded {
        return Err(AppError::Conflict(
            "the card was not confirmed; nothing was saved".into(),
        ));
    }
    intent
        .payment_method
        .as_ref()
        .map(expandable_id)
        .ok_or_else(|| AppError::Conflict("the card setup saved no card".into()))
}

/// Makes one of the organization's cards its default: top-ups charge it
/// from now on. Owners and admins only.
pub async fn set_default_card(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
    payment_method_id: &str,
) -> AppResult<()> {
    require_billing_admin(state, user, org_id).await?;
    let customer_id = owned_card(state, org_id, payment_method_id).await?.0;
    make_default(state, org_id, &customer_id, payment_method_id).await
}

/// Removes one of the organization's cards. A removed default is replaced by
/// the newest card left; with none left, top-up has nothing to charge.
/// Owners and admins only.
pub async fn remove_card(
    state: &BillingState,
    user: &AuthUser,
    org_id: &str,
    payment_method_id: &str,
) -> AppResult<()> {
    require_billing_admin(state, user, org_id).await?;
    let (customer_id, list) = owned_card(state, org_id, payment_method_id).await?;
    run_organization_billing_mutation(&state.pool, org_id, async {
        state
            .stripe
            .detach_card(payment_method_id)
            .await
            .map_err(OrganizationBillingMutationError::ambiguous)
    })
    .await?;
    if list.default_id.as_deref() == Some(payment_method_id)
        && let Some(next) = list.cards.iter().find(|card| card.id != payment_method_id)
    {
        make_default(state, org_id, &customer_id, &next.id).await?;
    }
    Ok(())
}

/// The organization's customer and cards, when `payment_method_id` is one of
/// them; any other card is not found, so no organization can act on
/// another's.
async fn owned_card(
    state: &BillingState,
    org_id: &str,
    payment_method_id: &str,
) -> AppResult<(String, CardList)> {
    let not_found = || AppError::NotFound("card not found".into());
    let customer_id = customer_id(state, org_id).await?.ok_or_else(not_found)?;
    let (cards, default_id) = state.stripe.list_cards(&customer_id).await?;
    if !cards.iter().any(|card| card.id == payment_method_id) {
        return Err(not_found());
    }
    Ok((
        customer_id,
        CardList {
            cards,
            default_id,
            publishable_key: None,
        },
    ))
}

/// Sets the default with a key of its own: Stripe replays a key's first
/// result for a day, so a fixed key would turn a later switch back into a
/// no-op.
async fn make_default(
    state: &BillingState,
    org_id: &str,
    customer_id: &str,
    payment_method_id: &str,
) -> AppResult<()> {
    let attempt = uuid::Uuid::new_v4().to_string();
    let key = billing_idempotency_key("default-card", &[org_id, payment_method_id, &attempt]);
    run_organization_billing_mutation(&state.pool, org_id, async {
        state
            .stripe
            .set_default_payment_method(customer_id, payment_method_id, &key)
            .await
            .map_err(OrganizationBillingMutationError::ambiguous)
    })
    .await
}

fn expandable_id<T: stripe_types::Object>(expandable: &stripe_types::Expandable<T>) -> String
where
    T::Id: ToString,
{
    match expandable {
        stripe_types::Expandable::Id(id) => id.to_string(),
        stripe_types::Expandable::Object(object) => object.id().to_string(),
    }
}

async fn customer_id(state: &BillingState, org_id: &str) -> AppResult<Option<String>> {
    let customer: Option<Option<String>> =
        sqlx::query_scalar("SELECT stripe_customer_id FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&state.pool)
            .await?;
    Ok(customer.flatten().filter(|id| !id.is_empty()))
}

#[cfg(test)]
mod tests;
