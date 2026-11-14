//! Billing emails via the shared transactional-email provider.
//!
//! Owns payment receipt, payment-failed, credit, trial and account-deleted
//! messages. Every email that asks the owner to pay or add credit links to
//! the organization's Billing page on the configured frontend origin (#4553).

use codewire_email::{Email, EmailClient as DeliveryEmailClient};

use crate::checkout_sessions::FrontendOrigin;

/// The frontend origin a client without real configuration links to.
const TEST_ORIGIN: &str = "https://app.codewire.test";

#[derive(Clone)]
pub struct EmailClient {
    delivery: DeliveryEmailClient,
    /// The dashboard's origin, `FRONTEND_URL`, which the Billing page links
    /// use.
    frontend_origin: FrontendOrigin,
}

/// Receipt email payload — mirrors `email.ReceiptData`.
#[derive(Debug, Default)]
pub struct ReceiptData {
    pub invoice_number: String,
    pub date: String,
    pub period_start: String,
    pub period_end: String,
    pub amount_paid: i64,
    pub subtotal: i64,
    pub net_amount_due: i64,
    pub currency: String,
    pub hosted_invoice_url: String,
    pub invoice_pdf: String,
    pub charge_reasons: Vec<String>,
    pub credit_reasons: Vec<String>,
}

impl EmailClient {
    /// Builds the billing sender from the selected delivery configuration.
    /// Its links go to `frontend_origin`, the same validated `FRONTEND_URL`
    /// that checkout uses.
    pub async fn from_env(frontend_origin: FrontendOrigin) -> anyhow::Result<Self> {
        Ok(Self {
            delivery: DeliveryEmailClient::from_env().await?,
            frontend_origin,
        })
    }

    /// A client that sends nothing, for tests; its links use a test origin.
    pub fn disabled() -> Self {
        Self {
            delivery: DeliveryEmailClient::disabled(),
            frontend_origin: FrontendOrigin::parse(TEST_ORIGIN)
                .expect("the test frontend origin is valid"),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.delivery.is_configured()
    }

    async fn send(&self, to: &str, email: &Email) -> anyhow::Result<()> {
        self.delivery.send(to, email).await
    }

    /// The organization's Billing page.
    fn billing_url(&self, org_slug: Option<&str>) -> String {
        self.frontend_origin.billing_url(org_slug)
    }

    /// Mirrors `email.SendPaymentReceipt`.
    pub async fn send_payment_receipt(&self, to: &str, data: &ReceiptData) -> anyhow::Result<()> {
        self.send(to, &payment_receipt_email(data)).await
    }

    /// Mirrors `email.SendPaymentFailed`.
    pub async fn send_payment_failed(
        &self,
        to: &str,
        org_slug: Option<&str>,
        amount_due: i64,
        currency: &str,
    ) -> anyhow::Result<()> {
        let billing_url = self.billing_url(org_slug);
        self.send(
            to,
            &payment_failed_email(amount_due, currency, &billing_url),
        )
        .await
    }

    /// Compute credit is below the low-balance mark and nothing will top it up.
    pub async fn send_credit_low(
        &self,
        to: &str,
        org_slug: Option<&str>,
        balance_cents: i64,
    ) -> anyhow::Result<()> {
        let billing_url = self.billing_url(org_slug);
        self.send(to, &credit_low_email(balance_cents, &billing_url))
            .await
    }

    /// Compute credit ran out with no way to get more.
    pub async fn send_credit_exhausted(
        &self,
        to: &str,
        org_slug: Option<&str>,
    ) -> anyhow::Result<()> {
        let billing_url = self.billing_url(org_slug);
        self.send(to, &credit_exhausted_email(&billing_url)).await
    }

    /// Mirrors `email.SendTrialExpired`.
    pub async fn send_trial_expired(&self, to: &str, org_slug: Option<&str>) -> anyhow::Result<()> {
        let billing_url = self.billing_url(org_slug);
        self.send(to, &trial_expired_email(&billing_url)).await
    }

    /// Mirrors `email.SendTrialEnding`.
    pub async fn send_trial_ending(
        &self,
        to: &str,
        org_slug: Option<&str>,
        days_left: i32,
    ) -> anyhow::Result<()> {
        let billing_url = self.billing_url(org_slug);
        self.send(to, &trial_ending_email(days_left, &billing_url))
            .await
    }

    /// The confirmation that an account was deleted (#3679).
    pub async fn send_account_deleted(&self, to: &str) -> anyhow::Result<()> {
        self.send(to, &account_deleted_email()).await
    }
}

/// The receipt for a paid or credited invoice. Every value is raw; the
/// layout escapes it.
fn payment_receipt_email(data: &ReceiptData) -> Email {
    let amount_str = format_cents(data.amount_paid, &data.currency);
    let subtotal_str = format_cents(data.subtotal, &data.currency);
    let net_due_str = format_cents(data.net_amount_due, &data.currency);

    let mut details = vec![
        ("Invoice".to_owned(), data.invoice_number.clone()),
        ("Amount".to_owned(), amount_str),
        ("Date".to_owned(), data.date.clone()),
    ];
    if !data.period_start.is_empty() && !data.period_end.is_empty() {
        details.push((
            "Billing period".to_owned(),
            format!("{} – {}", data.period_start, data.period_end),
        ));
    }
    details.push(("Subtotal before credits".to_owned(), subtotal_str));
    details.push(("Net due after credits".to_owned(), net_due_str));

    let mut email = Email::new("Payment Receipt — Codewire", "Payment Receipt")
        .paragraph(receipt_intro(data))
        .details(details);
    if !data.charge_reasons.is_empty() {
        email = email
            .subheading("You were billed for:")
            .list(data.charge_reasons.clone());
    }
    if !data.credit_reasons.is_empty() {
        email = email
            .subheading("Credits applied:")
            .list(data.credit_reasons.clone());
    }
    if !data.hosted_invoice_url.is_empty() {
        email = email.button("View Invoice", &data.hosted_invoice_url);
    }
    if !data.invoice_pdf.is_empty() {
        email = email.link("Download PDF", &data.invoice_pdf);
    }
    email
        .note("This is an automated receipt from Codewire.")
        .reason(OWNER_BILLING_REASON)
}

/// Why an organization's owner gets its billing emails.
const OWNER_BILLING_REASON: &str = "You got this email because you own an organization on Codewire and receive its billing emails.";

fn payment_failed_email(amount_due: i64, currency: &str, billing_url: &str) -> Email {
    let amount_str = format_cents(amount_due, currency);
    Email::new("Payment Failed — Codewire", "Payment Failed")
        .paragraph(format!(
            "We were unable to process your payment of {amount_str}."
        ))
        .paragraph("Please update your payment method to avoid service interruption.")
        .button("Update payment method", billing_url)
        .note("If you believe this is an error, please contact support.")
        .reason(OWNER_BILLING_REASON)
}

fn credit_low_email(balance_cents: i64, billing_url: &str) -> Email {
    let balance = format_cents(balance_cents, "eur");
    Email::new(
        "Your compute credit is running low — Codewire",
        "Your compute credit is running low",
    )
    .paragraph(format!(
        "This organization has {balance} of compute credit left, and automatic top-up won't add more."
    ))
    .paragraph(
        "When it runs out, new Sandboxes and starts are refused, and running Sandboxes stop 24 hours later. Their storage is kept.",
    )
    .paragraph(
        "Add a payment method or turn on automatic top-up on the organization's Billing page to keep running.",
    )
    .button("Add credit", billing_url)
    .reason(OWNER_BILLING_REASON)
}

fn credit_exhausted_email(billing_url: &str) -> Email {
    Email::new(
        "Your compute credit has run out — Codewire",
        "Your compute credit has run out",
    )
    .paragraph(
        "New Sandboxes and starts are refused from now on, and running Sandboxes stop in 24 hours. Their storage is kept.",
    )
    .paragraph(
        "Add a payment method or update your card on the organization's Billing page to continue.",
    )
    .button("Add credit", billing_url)
    .reason(OWNER_BILLING_REASON)
}

fn trial_expired_email(billing_url: &str) -> Email {
    Email::new("Your Codewire trial has ended", "Your trial has ended")
        .paragraph("Your Codewire free trial has expired. Your organization has been suspended.")
        .paragraph("Upgrade to a paid plan to restore access and continue using your resources.")
        .button("Choose a plan", billing_url)
        .note("If you have any questions, please contact support.")
        .reason(OWNER_BILLING_REASON)
}

fn trial_ending_email(days_left: i32, billing_url: &str) -> Email {
    let days_str = if days_left == 1 {
        "1 day".to_string()
    } else {
        format!("{days_left} days")
    };
    Email::new("Your Codewire trial ends soon", "Your trial is ending soon")
        .paragraph(format!("Your Codewire free trial ends in {days_str}."))
        .paragraph("Upgrade now to keep your resources running and avoid any disruption.")
        .button("Choose a plan", billing_url)
        .note("If you have any questions, please contact support.")
        .reason(OWNER_BILLING_REASON)
}

fn account_deleted_email() -> Email {
    Email::new("Your Codewire account was deleted", "Your account was deleted")
        .paragraph(
            "Your Codewire account has been deleted, together with the organizations only you belonged to and their environments, secrets and credentials. Your memberships in other organizations were removed.",
        )
        .paragraph("You can sign up again with this address at any time.")
        .note("If you did not ask for this, please contact support.")
        .reason("You got this email because the Codewire account for this address was deleted.")
}

fn receipt_intro(data: &ReceiptData) -> String {
    if data.net_amount_due == 0 && has_admin_credits(&data.credit_reasons) {
        return format!(
            "This invoice shows billing activity for your organization. Charges were recorded for the items below, then offset by admin credits so the balance due was {}.",
            format_cents(data.net_amount_due, &data.currency)
        );
    }
    if data.net_amount_due == 0 && !data.credit_reasons.is_empty() {
        return "This invoice was generated successfully. Credits were applied to offset the charges, so no payment was due.".to_string();
    }
    "Thank you for your payment.".to_string()
}

fn has_admin_credits(reasons: &[String]) -> bool {
    reasons
        .iter()
        .any(|r| r.to_lowercase().contains("admin credit"))
}

/// Mirrors `email.formatCents`: `$%.2f` with €/£ for eur/gbp.
fn format_cents(cents: i64, currency: &str) -> String {
    let dollars = cents as f64 / 100.0;
    let sym = match currency {
        "eur" => "€",
        "gbp" => "£",
        _ => "$",
    };
    format!("{sym}{dollars:.2}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_cents_matches_go() {
        assert_eq!(format_cents(4900, "usd"), "$49.00");
        assert_eq!(format_cents(0, "usd"), "$0.00");
        assert_eq!(format_cents(105, "eur"), "€1.05");
        assert_eq!(format_cents(33, "gbp"), "£0.33");
        assert_eq!(format_cents(-1800, "usd"), "$-18.00");
    }

    #[test]
    fn receipt_intro_branches_match_go() {
        let mut d = ReceiptData {
            net_amount_due: 0,
            credit_reasons: vec![
                "Admin credit for billing visibility: subscription renewal".into(),
            ],
            currency: "usd".into(),
            ..Default::default()
        };
        assert!(receipt_intro(&d).contains("offset by admin credits"));
        d.credit_reasons = vec!["Promo credit".into()];
        assert!(receipt_intro(&d).contains("no payment was due"));
        d.net_amount_due = 4900;
        assert_eq!(receipt_intro(&d), "Thank you for your payment.");
    }

    fn sample_receipt() -> ReceiptData {
        ReceiptData {
            invoice_number: "INV-0042".into(),
            date: "November 13, 2026".into(),
            period_start: "Oct 13, 2026".into(),
            period_end: "Nov 13, 2026".into(),
            amount_paid: 1250,
            subtotal: 1750,
            net_amount_due: 1250,
            currency: "eur".into(),
            hosted_invoice_url: "https://invoice.stripe.com/i/EXAMPLE".into(),
            invoice_pdf: "https://pay.stripe.com/invoice/EXAMPLE/pdf".into(),
            charge_reasons: vec![
                "Pro plan (Nov 13, 2026 – Dec 13, 2026)".into(),
                "Compute usage: 12.5 vCPU-hours".into(),
            ],
            credit_reasons: vec!["Promo credit: welcome".into()],
        }
    }

    #[test]
    fn the_receipt_shows_amounts_period_items_and_links() {
        let email = payment_receipt_email(&sample_receipt());
        assert_eq!(email.subject, "Payment Receipt — Codewire");
        let text = email.text();
        for expected in [
            "Thank you for your payment.",
            "Invoice: INV-0042",
            "Amount: €12.50",
            "Date: November 13, 2026",
            "Billing period: Oct 13, 2026 – Nov 13, 2026",
            "Subtotal before credits: €17.50",
            "Net due after credits: €12.50",
            "You were billed for:\n\n- Pro plan (Nov 13, 2026 – Dec 13, 2026)\n- Compute usage: 12.5 vCPU-hours\n",
            "Credits applied:\n\n- Promo credit: welcome\n",
            "View Invoice: https://invoice.stripe.com/i/EXAMPLE",
            "Download PDF: https://pay.stripe.com/invoice/EXAMPLE/pdf",
            "This is an automated receipt from Codewire.",
        ] {
            assert!(text.contains(expected), "{expected:?} missing from {text}");
        }
        let html = email.html();
        assert!(html.contains(r#"href="https://invoice.stripe.com/i/EXAMPLE""#));
        assert!(html.contains(r#"href="https://pay.stripe.com/invoice/EXAMPLE/pdf""#));
    }

    #[test]
    fn the_receipt_leaves_out_what_the_invoice_lacks() {
        let email = payment_receipt_email(&ReceiptData {
            period_end: String::new(),
            credit_reasons: Vec::new(),
            hosted_invoice_url: String::new(),
            invoice_pdf: String::new(),
            ..sample_receipt()
        });
        let text = email.text();
        for absent in [
            "Billing period",
            "Credits applied:",
            "View Invoice",
            "Download PDF",
        ] {
            assert!(!text.contains(absent), "{absent:?} in {text}");
        }
        assert!(text.contains("You were billed for:"));
    }

    #[test]
    fn receipt_line_items_are_escaped() {
        let html = payment_receipt_email(&ReceiptData {
            charge_reasons: vec!["<b>Pro</b> & more".into()],
            ..sample_receipt()
        })
        .html();
        assert!(html.contains("&lt;b&gt;Pro&lt;/b&gt; &amp; more"));
        assert!(!html.contains("<b>Pro"));
    }

    /// An organization whose slug can't be found still gets every email:
    /// a missed "payment failed" is worse than a missing link. The button
    /// goes to the dashboard, which lists the person's organizations.
    #[test]
    fn an_unknown_organization_still_gets_each_email_linking_to_the_dashboard() {
        let client = EmailClient::disabled();
        let dashboard = client.billing_url(None);
        assert_eq!(dashboard, format!("{TEST_ORIGIN}/dashboard/"));
        for email in [
            payment_failed_email(1250, "eur", &dashboard),
            credit_low_email(250, &dashboard),
            credit_exhausted_email(&dashboard),
            trial_expired_email(&dashboard),
            trial_ending_email(3, &dashboard),
        ] {
            let urls: Vec<_> = email
                .blocks
                .iter()
                .filter_map(|block| match block {
                    codewire_email::Block::Button { url, .. } => Some(url.as_str()),
                    _ => None,
                })
                .collect();
            assert_eq!(urls, [dashboard.as_str()], "{}", email.subject);
        }
    }

    /// Every email that asks the owner to pay or add credit has one button,
    /// to the organization's Billing page on the configured origin.
    #[test]
    fn payment_and_credit_emails_link_to_the_billing_page() {
        let client = EmailClient::disabled();
        let billing_url = client.billing_url(Some("acme"));
        assert_eq!(billing_url, format!("{TEST_ORIGIN}/acme/billing/"));
        for (email, label) in [
            (
                payment_failed_email(1250, "eur", &billing_url),
                "Update payment method",
            ),
            (credit_low_email(250, &billing_url), "Add credit"),
            (credit_exhausted_email(&billing_url), "Add credit"),
            (trial_expired_email(&billing_url), "Choose a plan"),
            (trial_ending_email(3, &billing_url), "Choose a plan"),
        ] {
            let buttons: Vec<_> = email
                .blocks
                .iter()
                .filter_map(|block| match block {
                    codewire_email::Block::Button { label, url } => Some((label, url)),
                    _ => None,
                })
                .collect();
            assert_eq!(
                buttons,
                [(&label.to_owned(), &billing_url)],
                "{}",
                email.subject
            );
            assert!(email.text().contains(&format!(
                "{label}: https://app.codewire.test/acme/billing/\n"
            )));
            assert!(
                email
                    .html()
                    .contains(r#"<a href="https://app.codewire.test/acme/billing/""#)
            );
            assert!(!email.html().contains("codewire.sh"), "{}", email.subject);
        }
    }

    /// Writes every billing email, with synthetic values, as `<name>.html`
    /// and `<name>.txt` into `EMAIL_PREVIEW_DIR`, for review. Without the
    /// variable it does nothing.
    #[test]
    #[ignore = "writes email previews"]
    fn write_email_previews() {
        let Some(dir) = std::env::var_os("EMAIL_PREVIEW_DIR") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        let billing = FrontendOrigin::parse("https://codewire.sh")
            .unwrap()
            .billing_url(Some("acme"));
        for (name, email) in [
            ("billing-receipt", payment_receipt_email(&sample_receipt())),
            (
                "billing-payment-failed",
                payment_failed_email(1250, "eur", &billing),
            ),
            ("billing-credit-low", credit_low_email(250, &billing)),
            ("billing-credit-exhausted", credit_exhausted_email(&billing)),
            ("billing-trial-expired", trial_expired_email(&billing)),
            ("billing-trial-ending", trial_ending_email(3, &billing)),
            ("billing-account-deleted", account_deleted_email()),
        ] {
            std::fs::write(dir.join(format!("{name}.html")), email.html()).unwrap();
            std::fs::write(dir.join(format!("{name}.txt")), email.text()).unwrap();
        }
    }

    #[tokio::test]
    async fn unconfigured_client_reports_disabled() {
        let c = EmailClient::disabled();
        assert!(!c.is_configured());
    }

    #[tokio::test]
    async fn unconfigured_client_reports_unavailable_delivery() {
        let c = EmailClient::disabled();
        let error = c
            .send_trial_expired("owner@example.com", Some("acme"))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "transactional email delivery is not configured"
        );
    }
}
