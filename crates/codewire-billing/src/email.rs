//! Billing emails via the Resend API.
//!
//! Owns payment receipt, payment-failed, and trial-ending messages.

use serde::Serialize;

const DEFAULT_BASE_URL: &str = "https://api.resend.com";
const FROM: &str = "Codewire <ops@example.invalid>";

#[derive(Clone)]
pub struct EmailClient {
    api_key: String,
    base_url: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct ResendRequest<'a> {
    from: &'a str,
    to: [&'a str; 1],
    subject: &'a str,
    html: &'a str,
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
    /// `api_key` empty -> emails disabled. Callers usually check
    /// [`Self::is_configured`] like the Go `resendAPIKey != ""` guards, and
    /// [`Self::send`] also no-ops so a missed guard cannot perform external
    /// network I/O in CI or local test runs.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Test seam: point at a wiremock server.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub fn is_configured(&self) -> bool {
        !self.api_key.is_empty()
    }

    async fn send(&self, to: &str, subject: &str, html: &str) -> anyhow::Result<()> {
        if !self.is_configured() {
            tracing::debug!("billing email disabled; skipping send");
            return Ok(());
        }

        let resp = self
            .http
            .post(format!("{}/emails", self.base_url))
            .bearer_auth(&self.api_key)
            .json(&ResendRequest {
                from: FROM,
                to: [to],
                subject,
                html,
            })
            .send()
            .await?;
        if resp.status().as_u16() >= 400 {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("resend API error {status}: {body}");
        }
        Ok(())
    }

    /// Mirrors `email.SendPaymentReceipt`.
    pub async fn send_payment_receipt(&self, to: &str, data: &ReceiptData) -> anyhow::Result<()> {
        let amount_str = format_cents(data.amount_paid, &data.currency);
        let subtotal_str = format_cents(data.subtotal, &data.currency);
        let net_due_str = format_cents(data.net_amount_due, &data.currency);

        let period_str = if !data.period_start.is_empty() && !data.period_end.is_empty() {
            format!(
                r#"<p style="color: #666; font-size: 14px;">Billing period: {} – {}</p>"#,
                data.period_start, data.period_end
            )
        } else {
            String::new()
        };

        let mut reason_section = String::new();
        if !data.charge_reasons.is_empty() {
            reason_section.push_str(r#"<div style="margin: 16px 0;"><p style="margin: 0 0 8px; font-weight: 600;">You were billed for:</p><ul style="margin: 0; padding-left: 20px;">"#);
            for reason in &data.charge_reasons {
                reason_section.push_str(&format!(r#"<li style="margin: 0 0 6px;">{reason}</li>"#));
            }
            reason_section.push_str("</ul></div>");
        }
        if !data.credit_reasons.is_empty() {
            reason_section.push_str(r#"<div style="margin: 16px 0;"><p style="margin: 0 0 8px; font-weight: 600;">Credits applied:</p><ul style="margin: 0; padding-left: 20px;">"#);
            for reason in &data.credit_reasons {
                reason_section.push_str(&format!(r#"<li style="margin: 0 0 6px;">{reason}</li>"#));
            }
            reason_section.push_str("</ul></div>");
        }

        let summary_section = format!(
            "<div style=\"background: #fafafa; padding: 16px; border-radius: 8px; margin: 16px 0;\">\n\t\t<p style=\"margin: 0 0 6px; font-size: 14px; color: #666;\">Subtotal before credits: {subtotal_str}</p>\n\t\t<p style=\"margin: 0; font-size: 14px; color: #666;\">Net due after credits: {net_due_str}</p>\n\t</div>"
        );
        let intro = receipt_intro(data);

        let mut links = String::new();
        if !data.hosted_invoice_url.is_empty() {
            links.push_str(&format!(
                r#"<a href="{}" style="display: inline-block; padding: 10px 20px; background: #171717; color: #fff; text-decoration: none; border-radius: 6px; margin-right: 8px;">View Invoice</a>"#,
                data.hosted_invoice_url
            ));
        }
        if !data.invoice_pdf.is_empty() {
            links.push_str(&format!(
                r#"<a href="{}" style="display: inline-block; padding: 10px 20px; background: #fff; color: #171717; text-decoration: none; border-radius: 6px; border: 1px solid #ddd;">Download PDF</a>"#,
                data.invoice_pdf
            ));
        }

        let html = format!(
            "<div style=\"font-family: sans-serif; max-width: 480px; margin: 0 auto;\">\n\t<h2>Payment Receipt</h2>\n\t{intro}\n\t<div style=\"background: #f5f5f5; padding: 16px; border-radius: 8px; margin: 16px 0;\">\n\t\t<p style=\"margin: 0; font-size: 14px; color: #666;\">Invoice {invoice}</p>\n\t\t<p style=\"margin: 4px 0 0; font-size: 24px; font-weight: bold; color: #171717;\">{amount_str}</p>\n\t\t<p style=\"margin: 4px 0 0; font-size: 14px; color: #666;\">{date}</p>\n\t</div>{period_str}{summary_section}{reason_section}\n\t<p>{links}</p>\n\t<p style=\"color: #999; font-size: 12px; margin-top: 24px;\">This is an automated receipt from Codewire.</p>\n</div>",
            invoice = data.invoice_number,
            date = data.date,
        );
        self.send(to, "Payment Receipt — Codewire", &html).await
    }

    /// Mirrors `email.SendPaymentFailed`.
    pub async fn send_payment_failed(
        &self,
        to: &str,
        amount_due: i64,
        currency: &str,
    ) -> anyhow::Result<()> {
        let amount_str = format_cents(amount_due, currency);
        let html = format!(
            "<div style=\"font-family: sans-serif; max-width: 480px; margin: 0 auto;\">\n\t<h2>Payment Failed</h2>\n\t<p>We were unable to process your payment of <strong>{amount_str}</strong>.</p>\n\t<p>Please update your payment method to avoid service interruption.</p>\n\t<p style=\"color: #666; font-size: 14px;\">If you believe this is an error, please contact support.</p>\n</div>"
        );
        self.send(to, "Payment Failed — Codewire", &html).await
    }

    /// Mirrors `email.SendTrialEnding`.
    /// Mirrors `email.SendTrialExpired` byte-for-byte.
    pub async fn send_trial_expired(&self, to: &str) -> anyhow::Result<()> {
        let html = "<div style=\"font-family: sans-serif; max-width: 480px; margin: 0 auto;\">\n\t<h2>Your trial has ended</h2>\n\t<p>Your Codewire free trial has expired. Your organization has been suspended.</p>\n\t<p>Upgrade to a paid plan to restore access and continue using your resources.</p>\n\t<p><a href=\"https://codewire.sh/dashboard\" style=\"display: inline-block; padding: 12px 24px; background: #171717; color: #fff; text-decoration: none; border-radius: 6px;\">Upgrade Now</a></p>\n\t<p style=\"color: #666; font-size: 14px;\">If you have any questions, please contact support.</p>\n</div>";
        self.send(to, "Your Codewire trial has ended", html).await
    }

    pub async fn send_trial_ending(&self, to: &str, days_left: i32) -> anyhow::Result<()> {
        let days_str = if days_left == 1 {
            "1 day".to_string()
        } else {
            format!("{days_left} days")
        };
        let html = format!(
            "<div style=\"font-family: sans-serif; max-width: 480px; margin: 0 auto;\">\n\t<h2>Your trial is ending soon</h2>\n\t<p>Your Codewire free trial ends in <strong>{days_str}</strong>.</p>\n\t<p>Upgrade now to keep your resources running and avoid any disruption.</p>\n\t<p><a href=\"https://codewire.sh/dashboard\" style=\"display: inline-block; padding: 12px 24px; background: #171717; color: #fff; text-decoration: none; border-radius: 6px;\">Upgrade Now</a></p>\n\t<p style=\"color: #666; font-size: 14px;\">If you have any questions, please contact support.</p>\n</div>"
        );
        self.send(to, "Your Codewire trial ends soon", &html).await
    }
}

fn receipt_intro(data: &ReceiptData) -> String {
    if data.net_amount_due == 0 && has_admin_credits(&data.credit_reasons) {
        return format!(
            "<p>This invoice shows billing activity for your organization. Charges were recorded for the items below, then offset by admin credits so the balance due was {}.</p>",
            format_cents(data.net_amount_due, &data.currency)
        );
    }
    if data.net_amount_due == 0 && !data.credit_reasons.is_empty() {
        return "<p>This invoice was generated successfully. Credits were applied to offset the charges, so no payment was due.</p>".to_string();
    }
    "<p>Thank you for your payment.</p>".to_string()
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
        assert_eq!(receipt_intro(&d), "<p>Thank you for your payment.</p>");
    }

    #[tokio::test]
    async fn unconfigured_client_reports_disabled() {
        let c = EmailClient::new("");
        assert!(!c.is_configured());
    }

    #[tokio::test]
    async fn unconfigured_client_skips_sends() {
        let c = EmailClient::new("").with_base_url("http://127.0.0.1:9");
        c.send_trial_expired("owner@example.com")
            .await
            .expect("disabled email sends should no-op");
    }
}
