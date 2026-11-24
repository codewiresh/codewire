//! `/admin/pricing/`: each rate card's prices, which a platform admin
//! reviews before saving (docs/dev/BILLING.md "Prices", journey
//! `billing-admin-prices`, #5782).

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use connectrpc::{ConnectError, ErrorCode};
use serde::Deserialize;

use super::{admin_action_page_context_for, admin_context, admin_error, mutation_error};
use crate::{
    admin_connect::pricing::{
        self, CardVersion, PriceReviewView, PricingPageView, RateCardView, Rates,
        has_large_increase, rate_nano,
    },
    response::{login_redirect, redirect, render_template},
    security::{csrf_cookie, page_csrf_token, with_csrf_cookie},
    state::AppState,
    templates::AdminPricingTemplate,
    view::DashboardView,
};

const PRICING_PATH: &str = "/admin/pricing/";
const UNAVAILABLE: &str = "Prices can't be loaded right now.";
const STALE: &str = "These prices changed since you opened them. Review them again.";
/// The confirmation a large increase needs, as the review's checkbox sends it.
const CONFIRMED: &str = "yes";

#[derive(Debug, Default, Deserialize)]
pub(in crate::routes) struct PricingQuery {
    #[serde(default)]
    org: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
    /// After a save, the card whose prices were saved.
    #[serde(default)]
    card: String,
}

/// The edit form: the euro amounts as typed, and the card as the page showed
/// it, so the review compares with what the admin saw without reading again.
#[derive(Debug, Deserialize)]
pub(in crate::routes) struct ReviewSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    rate_card: String,
    display_name: String,
    expected_updated_at: String,
    now_cpu: i64,
    now_memory: i64,
    now_disk: i64,
    now_storage: i64,
    cpu: String,
    memory: String,
    disk: String,
    storage: String,
}

/// The review's form: the new rates in nano-euros.
#[derive(Debug, Deserialize)]
pub(in crate::routes) struct UpdateSubmission {
    #[serde(rename = "_csrf")]
    csrf: String,
    rate_card: String,
    expected_updated_at: String,
    cpu_nano: i64,
    memory_nano: i64,
    disk_nano: i64,
    storage_nano: i64,
    #[serde(default)]
    confirm_increase: String,
}

pub(in crate::routes) async fn page(
    State(state): State<AppState>,
    Query(query): Query<PricingQuery>,
    headers: HeaderMap,
) -> Response {
    let (dashboard, cookie) = match admin_context(&state, &headers, PRICING_PATH, &query.org).await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let token = page_csrf_token(&headers);
    let mut page = PricingPageView {
        csrf_token: token.clone(),
        ..Default::default()
    };
    match pricing::rate_cards(&state, cookie).await {
        Ok(cards) => page.cards = cards,
        Err(error) if error.code == ErrorCode::Unauthenticated => {
            return login_redirect(PRICING_PATH, &headers);
        }
        Err(_) => page.unavailable = true,
    }
    page.message = message_text(&query.message, &query.card, &page.cards);
    page.error = if page.unavailable {
        UNAVAILABLE.to_owned()
    } else {
        error_text(&query.error).to_owned()
    };
    with_csrf_cookie(
        render(&dashboard, &page, StatusCode::OK),
        csrf_cookie(&state.public_origin, &token),
    )
}

/// Show the changed rates beside the current ones. It reads and saves
/// nothing: the current rates are the ones the page showed.
pub(in crate::routes) async fn review(
    State(state): State<AppState>,
    Query(query): Query<PricingQuery>,
    headers: HeaderMap,
    Form(submission): Form<ReviewSubmission>,
) -> Response {
    let (dashboard, _) = match admin_action_page_context_for(
        &state,
        &headers,
        &submission.csrf,
        &query.org,
        PRICING_PATH,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(mut card) = submitted_card(&submission) else {
        return pricing_redirect(&[("error", "invalid")], &headers);
    };
    let typed = [
        &submission.cpu,
        &submission.memory,
        &submission.disk,
        &submission.storage,
    ];
    let amounts = typed.map(|text| rate_nano(text));
    let [Some(cpu), Some(memory), Some(disk), Some(storage)] = amounts else {
        // The edit form again, as typed, with each refused amount marked.
        for ((field, text), amount) in card.fields.iter_mut().zip(typed).zip(amounts) {
            field.value = text.chars().take(64).collect();
            field.invalid = amount.is_none();
        }
        let page = PricingPageView {
            csrf_token: submission.csrf,
            cards: vec![card],
            ..Default::default()
        };
        return render(&dashboard, &page, StatusCode::UNPROCESSABLE_ENTITY);
    };
    let new = Rates {
        cpu,
        memory,
        disk,
        storage,
    };
    let Some(review) = PriceReviewView::new(&card, new) else {
        return pricing_redirect(&[("message", "unchanged")], &headers);
    };
    let page = PricingPageView {
        csrf_token: submission.csrf,
        review: Some(review),
        ..Default::default()
    };
    render(&dashboard, &page, StatusCode::OK)
}

/// Save the reviewed rates. A large increase is checked again against the
/// card as it is now, never the browser's copy; the server's stale-read
/// check decides whether the write happens.
pub(in crate::routes) async fn update(
    State(state): State<AppState>,
    Query(query): Query<PricingQuery>,
    headers: HeaderMap,
    Form(submission): Form<UpdateSubmission>,
) -> Response {
    let (dashboard, cookie) = match admin_action_page_context_for(
        &state,
        &headers,
        &submission.csrf,
        &query.org,
        PRICING_PATH,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    let new = Rates {
        cpu: submission.cpu_nano,
        memory: submission.memory_nano,
        disk: submission.disk_nano,
        storage: submission.storage_nano,
    };
    let version = CardVersion::parse(&submission.expected_updated_at)
        .filter(|_| valid_rate_card(&submission.rate_card) && new.valid());
    let Some(version) = version else {
        return pricing_redirect(&[("error", "invalid")], &headers);
    };
    let cards = match pricing::rate_cards(&state, cookie.clone()).await {
        Ok(cards) => cards,
        Err(error) => return save_error(&error, &headers),
    };
    let Some(current) = cards
        .iter()
        .find(|card| card.rate_card == submission.rate_card)
    else {
        return pricing_redirect(&[("error", "not-found")], &headers);
    };
    if !current.charged() {
        return pricing_redirect(&[("error", "invalid")], &headers);
    }
    if has_large_increase(current.rates, new) && submission.confirm_increase != CONFIRMED {
        // Refused: the review again, against the card as it is now.
        let page = PricingPageView {
            csrf_token: submission.csrf,
            review: PriceReviewView::new(current, new),
            ..Default::default()
        };
        return render(&dashboard, &page, StatusCode::UNPROCESSABLE_ENTITY);
    }
    match pricing::update_rate_card(&state, cookie, submission.rate_card.clone(), new, version)
        .await
    {
        Ok(()) => pricing_redirect(
            &[("message", "saved"), ("card", &submission.rate_card)],
            &headers,
        ),
        Err(error) if error.code == ErrorCode::FailedPrecondition => {
            pricing_redirect(&[("error", "stale")], &headers)
        }
        Err(error) if error.code == ErrorCode::InvalidArgument => {
            let page = PricingPageView {
                csrf_token: submission.csrf,
                error: error
                    .message
                    .filter(|message| !message.trim().is_empty())
                    .map(|message| message.chars().take(512).collect())
                    .unwrap_or_else(|| admin_error("invalid").to_owned()),
                cards,
                ..Default::default()
            };
            render(&dashboard, &page, StatusCode::UNPROCESSABLE_ENTITY)
        }
        Err(error) => save_error(&error, &headers),
    }
}

fn render(dashboard: &DashboardView, page: &PricingPageView, status: StatusCode) -> Response {
    render_template(
        status,
        AdminPricingTemplate {
            view: dashboard,
            page,
        },
    )
}

/// The card the edit form showed, or `None` when a field is not one the page
/// writes.
fn submitted_card(submission: &ReviewSubmission) -> Option<RateCardView> {
    let version = CardVersion::parse(&submission.expected_updated_at)?;
    let rates = Rates {
        cpu: submission.now_cpu,
        memory: submission.now_memory,
        disk: submission.now_disk,
        storage: submission.now_storage,
    };
    let display_name = submission.display_name.trim();
    if !valid_rate_card(&submission.rate_card)
        || display_name.is_empty()
        || display_name.chars().count() > 128
        || display_name.chars().any(char::is_control)
        || !rates.valid()
    {
        return None;
    }
    let card = RateCardView::new(
        submission.rate_card.clone(),
        display_name.to_owned(),
        version,
        rates,
    );
    card.charged().then_some(card)
}

/// Rate card keys are short lowercase words, such as "regular".
fn valid_rate_card(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn save_error(error: &ConnectError, headers: &HeaderMap) -> Response {
    if error.code == ErrorCode::Unauthenticated {
        return login_redirect(PRICING_PATH, headers);
    }
    pricing_redirect(&[("error", mutation_error(error))], headers)
}

fn pricing_redirect(pairs: &[(&str, &str)], headers: &HeaderMap) -> Response {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    redirect(format!("{PRICING_PATH}?{query}"), headers)
}

/// The message a redirect asks for. A saved card is named from the cards
/// just read, so nothing from the URL is shown.
fn message_text(message: &str, card: &str, cards: &[RateCardView]) -> String {
    match message {
        "unchanged" => "Nothing changed.".to_owned(),
        "saved" => cards
            .iter()
            .find(|candidate| candidate.rate_card == card)
            .map(|card| format!("{}'s prices are saved.", card.display_name))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn error_text(error: &str) -> &'static str {
    match error {
        "stale" => STALE,
        other => admin_error(other),
    }
}

#[cfg(test)]
mod tests;
