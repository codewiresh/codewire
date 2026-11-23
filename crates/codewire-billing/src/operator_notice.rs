//! The operator's credit purchase notice (#5358). docs/CONFIGURATION.md,
//! "Operator notices", has the rules: `CODEWIRE_OPERATOR_EMAIL` gets one short
//! email per paid credit purchase, naming the organization, the amount, how it
//! was bought and when, with a link to the organization's admin page. It is a
//! notice, not a receipt: no card, payment method, invoice, Stripe ID or buyer.
//!
//! The notices share [`rate_limit::OPERATOR_PURCHASE_NOTICE`], ten an hour
//! across every replica. The eleventh sends one "more credit purchases" notice
//! instead, and the rest of the hour sends nothing. A notice is sent in its own
//! task after the `invoice.paid` delivery has been handled, so a failed send,
//! a full limit or a database error is only logged, never retried, and never
//! fails the delivery.

use chrono::{DateTime, Utc};
use codewire_email::Email;
use codewire_server_core::rate_limit;
use sqlx::PgPool;

use crate::checkout_sessions::FrontendOrigin;
use crate::email::EmailClient;
use crate::stripe_client::{CREDIT_CHECKOUT_INVOICE_KIND, CREDIT_TOP_UP_KIND};

/// The one subject the site-wide notice limit counts under.
const SITE: &str = "all";

/// The prefix every Add credit top-up id has (`purchase_top_up_id`); an
/// automatic top-up's id is a generated one.
const PURCHASE_TOP_UP_PREFIX: &str = "credit-";

const REASON: &str =
    "You got this email because this address is the operator address of a Codewire server.";

/// How the organization bought the credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PurchaseKind {
    AddCredit,
    AutomaticTopUp,
}

impl PurchaseKind {
    fn label(self) -> &'static str {
        match self {
            PurchaseKind::AddCredit => "Add credit",
            PurchaseKind::AutomaticTopUp => "Automatic top-up",
        }
    }
}

/// A paid credit purchase, as the operator's notice describes it.
#[derive(Clone, Debug)]
pub(crate) struct CreditPurchase {
    pub organization_id: String,
    pub amount_cents: i64,
    pub currency: String,
    pub kind: PurchaseKind,
    pub at: DateTime<Utc>,
}

/// How a paid invoice bought credit, from its metadata, or `None` for an
/// invoice that bought none.
pub(crate) fn purchase_kind(
    metadata: Option<&std::collections::HashMap<String, String>>,
) -> Option<PurchaseKind> {
    let metadata = metadata?;
    match metadata.get("kind").map(String::as_str) {
        Some(CREDIT_CHECKOUT_INVOICE_KIND) => Some(PurchaseKind::AddCredit),
        Some(CREDIT_TOP_UP_KIND) => Some(
            if metadata
                .get("top_up_id")
                .is_some_and(|id| id.starts_with(PURCHASE_TOP_UP_PREFIX))
            {
                PurchaseKind::AddCredit
            } else {
                PurchaseKind::AutomaticTopUp
            },
        ),
        _ => None,
    }
}

/// Sends the operator's notice of `purchase` in its own task, when the server
/// has an operator address and mail. It never waits for the send and never
/// fails the caller.
pub(crate) fn notify(
    pool: &PgPool,
    email: &EmailClient,
    origin: &FrontendOrigin,
    operator: Option<&str>,
    purchase: CreditPurchase,
) {
    let Some(operator) = operator else {
        return;
    };
    if !email.is_configured() {
        return;
    }
    let pool = pool.clone();
    let email = email.clone();
    let origin = origin.clone();
    let operator = operator.to_owned();
    tokio::spawn(async move {
        if let Err(error) = send(&pool, &email, &origin, &operator, &purchase).await {
            tracing::warn!(
                %error,
                organization_id = %purchase.organization_id,
                "operator credit purchase notice not sent"
            );
        }
    });
}

/// Counts the notice, then sends it, the one "more credit purchases" notice,
/// or nothing.
async fn send(
    pool: &PgPool,
    email: &EmailClient,
    origin: &FrontendOrigin,
    operator: &str,
    purchase: &CreditPurchase,
) -> anyhow::Result<()> {
    let mut connection = pool.acquire().await?;
    let decision =
        rate_limit::take_fixed(&mut connection, &rate_limit::OPERATOR_PURCHASE_NOTICE, SITE)
            .await?;
    let notice = if decision.allowed {
        let organization: Option<(String, String)> =
            sqlx::query_as("SELECT name, slug FROM organizations WHERE id = $1")
                .bind(&purchase.organization_id)
                .fetch_optional(&mut *connection)
                .await?;
        let (name, slug) = organization.unwrap_or_default();
        purchase_notice(
            purchase,
            &name,
            &slug,
            &origin.admin_organization_url(&purchase.organization_id),
        )
    } else if decision.count == decision.max + 1 {
        more_purchases_notice(
            decision.count,
            decision.resets_at,
            &origin.admin_organizations_url(),
        )
    } else {
        return Ok(());
    };
    drop(connection);
    email.send_to_operator(operator, &notice).await
}

/// "€5.00" for 500 euro cents; another currency is named by its code.
fn amount(cents: i64, currency: &str) -> String {
    let value = format!("{}.{:02}", cents / 100, (cents % 100).abs());
    if currency.eq_ignore_ascii_case("eur") {
        format!("€{value}")
    } else {
        format!("{value} {}", currency.to_ascii_uppercase())
    }
}

/// The notice of one paid purchase. The organization's name and slug go only
/// in the body, which the layout escapes.
pub(crate) fn purchase_notice(
    purchase: &CreditPurchase,
    name: &str,
    slug: &str,
    organization_url: &str,
) -> Email {
    let amount = amount(purchase.amount_cents, &purchase.currency);
    let organization = match (name.is_empty(), slug.is_empty()) {
        (false, false) => format!("{name} ({slug})"),
        (false, true) => name.to_owned(),
        (true, false) => slug.to_owned(),
        (true, true) => purchase.organization_id.clone(),
    };
    Email::new(
        format!("Codewire: credit bought, {amount}"),
        "An organization bought credit",
    )
    .details([
        ("Organization".to_owned(), organization),
        ("Amount".to_owned(), amount),
        ("How".to_owned(), purchase.kind.label().to_owned()),
        (
            "When".to_owned(),
            format!("{} UTC", purchase.at.format("%Y-%m-%d %H:%M:%S")),
        ),
    ])
    .button("Open the organization", organization_url)
    .reason(REASON)
}

/// The one notice past the hour's count.
pub(crate) fn more_purchases_notice(
    paid: i32,
    resumes_at: DateTime<Utc>,
    organizations_url: &str,
) -> Email {
    Email::new(
        "Codewire: more credit purchases",
        "More credit purchases this hour",
    )
    .paragraph(format!(
        "{paid} credit purchases were paid this hour. Notices stop until {} UTC; Admin → Organizations lists every organization.",
        resumes_at.format("%H:%M")
    ))
    .button("Open Organizations", organizations_url)
    .reason(REASON)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-21T16:47:55Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn purchase(kind: PurchaseKind) -> CreditPurchase {
        CreditPurchase {
            organization_id: "org_1".into(),
            amount_cents: 500,
            currency: "eur".into(),
            kind,
            at: at(),
        }
    }

    fn kind_of(metadata: &[(&str, &str)]) -> Option<PurchaseKind> {
        let metadata: HashMap<String, String> = metadata
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        purchase_kind(Some(&metadata))
    }

    #[test]
    fn each_credit_invoice_says_how_it_was_bought_and_others_buy_none() {
        assert_eq!(
            kind_of(&[("kind", "credit_checkout"), ("top_up_id", "credit-ab")]),
            Some(PurchaseKind::AddCredit)
        );
        assert_eq!(
            kind_of(&[("kind", "credit_top_up"), ("top_up_id", "credit-ab")]),
            Some(PurchaseKind::AddCredit)
        );
        assert_eq!(
            kind_of(&[("kind", "credit_top_up"), ("top_up_id", "9f8d18d0")]),
            Some(PurchaseKind::AutomaticTopUp)
        );
        assert_eq!(kind_of(&[]), None);
        assert_eq!(purchase_kind(None), None);
        assert_eq!(kind_of(&[("kind", "plan")]), None);
    }

    #[test]
    fn a_purchase_names_the_organization_amount_how_and_when_and_nothing_to_pay_with() {
        let notice = purchase_notice(
            &purchase(PurchaseKind::AutomaticTopUp),
            "Ada's lab",
            "adas-lab",
            "https://codewire.sh/admin/organizations/org_1/",
        );
        assert_eq!(notice.subject, "Codewire: credit bought, €5.00");
        let text = notice.text();
        for expected in [
            "Organization: Ada's lab (adas-lab)",
            "Amount: €5.00",
            "How: Automatic top-up",
            "When: 2026-11-21 16:47:55 UTC",
            "https://codewire.sh/admin/organizations/org_1/",
        ] {
            assert!(text.contains(expected), "{expected:?} in {text}");
        }
        for absent in ["card", "Card", "invoice", "Invoice", "in_1", "cus_", "pm_"] {
            assert!(!text.contains(absent), "{absent:?} in {text}");
        }
    }

    #[test]
    fn markup_and_line_breaks_in_a_name_stay_in_the_escaped_body() {
        let notice = purchase_notice(
            &purchase(PurchaseKind::AddCredit),
            "<b>Acme</b>\r\nBcc: mallory@example.com",
            "acme",
            "https://codewire.sh/admin/organizations/org_1/",
        );
        assert_eq!(notice.subject, "Codewire: credit bought, €5.00");
        let html = notice.html();
        assert!(!html.contains("<b>Acme</b>"), "{html}");
        assert!(html.contains("&lt;b&gt;Acme&lt;/b&gt;"), "{html}");
        assert!(notice.text().contains("How: Add credit"));
    }

    #[test]
    fn another_currency_is_named_by_its_code() {
        assert_eq!(amount(12_345, "usd"), "123.45 USD");
        assert_eq!(amount(5, "eur"), "€0.05");
    }

    #[test]
    fn past_the_count_one_notice_says_how_many_and_when_notices_resume() {
        let notice = more_purchases_notice(11, at(), "https://codewire.sh/admin/organizations/");
        assert_eq!(notice.subject, "Codewire: more credit purchases");
        let text = notice.text();
        assert!(
            text.contains("11 credit purchases were paid this hour."),
            "{text}"
        );
        assert!(text.contains("Notices stop until 16:47 UTC"), "{text}");
        assert!(text.contains("https://codewire.sh/admin/organizations/"));
    }
}
