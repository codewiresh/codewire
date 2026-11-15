//! Who sends the receipt for a paid invoice (#4816).
//!
//! Every purchase is a Stripe invoice paid on the organization's customer:
//! automatic top-ups, Add credit with a saved or a new card, and the hosted
//! credit Checkout. Stripe can email that customer its own receipt, with the
//! invoice and receipt PDFs attached, once the account's "Successful
//! payments" email is on. A deployment then switches to `stripe` so nobody
//! gets two receipts. Only the receipt moves: the low-credit, payment-failed
//! and every other billing email stay Codewire's.

/// `codewire` or `stripe`. Unset or empty is `codewire`.
pub const BILLING_RECEIPTS_ENV: &str = "CODEWIRE_BILLING_RECEIPTS";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReceiptSender {
    /// Billing emails its own receipt for each paid invoice.
    #[default]
    Codewire,
    /// Stripe emails the receipt; billing sends none.
    Stripe,
}

impl ReceiptSender {
    /// Anything else than `codewire` or `stripe` is refused, so a typo stops
    /// the service instead of quietly sending two receipts or none.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim) {
            None | Some("" | "codewire") => Ok(Self::Codewire),
            Some("stripe") => Ok(Self::Stripe),
            Some(value) => Err(format!(
                "{BILLING_RECEIPTS_ENV} must be \"codewire\" or \"stripe\"; got {value:?}"
            )),
        }
    }

    /// [`Self::parse`] of [`BILLING_RECEIPTS_ENV`].
    pub fn from_env() -> anyhow::Result<Self> {
        Self::parse(std::env::var(BILLING_RECEIPTS_ENV).ok().as_deref()).map_err(anyhow::Error::msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codewire_sends_unless_stripe_is_named_and_a_typo_is_refused() {
        for value in [None, Some(""), Some(" "), Some("codewire")] {
            assert_eq!(
                ReceiptSender::parse(value),
                Ok(ReceiptSender::Codewire),
                "{value:?}"
            );
        }
        assert_eq!(
            ReceiptSender::parse(Some(" stripe ")),
            Ok(ReceiptSender::Stripe)
        );
        assert_eq!(ReceiptSender::default(), ReceiptSender::Codewire);
        for value in ["Stripe", "ses", "off", "both"] {
            let error = ReceiptSender::parse(Some(value)).unwrap_err();
            assert!(error.contains(BILLING_RECEIPTS_ENV), "{error}");
        }
    }
}
