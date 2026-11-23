//! The operator's address, `CODEWIRE_OPERATOR_EMAIL`, shared by every service
//! that emails the operator: the IdP's sign-up and feedback notices and
//! billing's credit purchase notices (docs/CONFIGURATION.md, "Operator
//! notices").

pub const OPERATOR_EMAIL_ENV: &str = "CODEWIRE_OPERATOR_EMAIL";

/// `CODEWIRE_OPERATOR_EMAIL`: one email address, or `None` for an unset or
/// empty value. Anything else stops the service that reads it, by the rule
/// the dashboard applies to `CODEWIRE_SUPPORT_EMAIL`.
pub fn parse_operator_email(value: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let valid = value.len() <= 254
        && value
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
        && value.matches('@').count() == 1
        && value.chars().all(|c| c.is_ascii_graphic());
    if !valid {
        anyhow::bail!(
            "{OPERATOR_EMAIL_ENV} must be one email address, such as operator@example.com"
        );
    }
    Ok(Some(value.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_is_one_email_address_or_nothing() {
        for unset in [None, Some(""), Some("  ")] {
            assert_eq!(parse_operator_email(unset).ok(), Some(None));
        }
        assert_eq!(
            parse_operator_email(Some(" hello@codewire.sh ")).ok(),
            Some(Some("hello@codewire.sh".to_owned()))
        );
        for invalid in [
            "hello",
            "@codewire.sh",
            "hello@localhost",
            "a@b.sh, c@d.sh",
            "a@b@c.sh",
            "hello@codewire.sh\nBcc: x@y.sh",
        ] {
            let error = parse_operator_email(Some(invalid))
                .err()
                .map(|e| e.to_string());
            assert!(
                error
                    .as_deref()
                    .is_some_and(|e| e.contains(OPERATOR_EMAIL_ENV)),
                "{invalid:?}: {error:?}"
            );
        }
    }
}
