//! Whether a deployment enforces prepaid compute credit (#3381).
//!
//! Metering always draws credit. Everything that costs or stops anything
//! acts only with this setting on: the card grant, charging a card, marking
//! an organization out of credit, refusing creates and starts, and stopping
//! running sandboxes. It is off unless a deployment turns it on, so a release
//! never starts enforcing by itself.

/// `on` or `off`. Unset or empty is off.
pub const CREDIT_ENFORCEMENT_ENV: &str = "CODEWIRE_CREDIT_ENFORCEMENT";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CreditEnforcement {
    #[default]
    Off,
    On,
}

impl CreditEnforcement {
    /// Anything else than `on` or `off` is refused, so a typo stops the
    /// service instead of quietly choosing whether cards are charged.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim) {
            None | Some("" | "off") => Ok(Self::Off),
            Some("on") => Ok(Self::On),
            Some(value) => Err(format!(
                "{CREDIT_ENFORCEMENT_ENV} must be \"on\" or \"off\"; got {value:?}"
            )),
        }
    }

    /// [`Self::parse`] of [`CREDIT_ENFORCEMENT_ENV`].
    pub fn from_env() -> anyhow::Result<Self> {
        Self::parse(std::env::var(CREDIT_ENFORCEMENT_ENV).ok().as_deref())
            .map_err(anyhow::Error::msg)
    }

    pub fn is_on(self) -> bool {
        self == Self::On
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforcement_is_off_unless_turned_on_and_a_typo_is_refused() {
        for value in [None, Some(""), Some(" "), Some("off")] {
            assert_eq!(
                CreditEnforcement::parse(value),
                Ok(CreditEnforcement::Off),
                "{value:?}"
            );
        }
        assert_eq!(
            CreditEnforcement::parse(Some(" on ")),
            Ok(CreditEnforcement::On)
        );
        assert_eq!(CreditEnforcement::default(), CreditEnforcement::Off);
        for value in ["ON", "true", "1", "enforce"] {
            let error = CreditEnforcement::parse(Some(value)).unwrap_err();
            assert!(error.contains(CREDIT_ENFORCEMENT_ENV), "{error}");
        }
    }
}
