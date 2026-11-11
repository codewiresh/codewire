//! The platform's refusal of a cloud create or start when the organization
//! has no compute credit (#3381), said the way the dashboard's Create drawer
//! says it: who, why, where to fix it, and that local sandboxes stay free.
//!
//! The shared client maps the refusal to [`CreditExhausted`] in one place
//! (`environment_client::display_client_error`); a create or start then names
//! the organization; [`report`] prints it once, for every command.

use std::fmt;

use crate::commands::progress::terminal_text;

/// `google.rpc.ErrorInfo.reason` of the refusal on the wire.
pub(crate) const REASON: &str = "CREDIT_EXHAUSTED";
/// The stable code `--output json` reports.
pub(crate) const CODE: &str = "credit_exhausted";
/// What still runs without credit.
const LOCAL_CREATE: &str = "cw create --local";

/// The organization the refusal is about.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct RefusedOrganization {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
}

/// A cloud create or start refused because the organization has no compute
/// credit. Without an organization (it could not be looked up), the text
/// says "This organization" and gives no billing link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CreditExhausted {
    organization: Option<RefusedOrganization>,
    billing_url: Option<String>,
}

impl CreditExhausted {
    /// `server_url` is the platform the CLI talks to; the dashboard is served
    /// from its origin, as invitation links are.
    pub(crate) fn new(organization: Option<RefusedOrganization>, server_url: &url::Url) -> Self {
        let billing_url = organization
            .as_ref()
            .and_then(|organization| billing_url(server_url, &organization.slug));
        Self {
            organization,
            billing_url,
        }
    }

    /// A refusal from a call that does not know its organization.
    pub(crate) fn unnamed() -> Self {
        Self {
            organization: None,
            billing_url: None,
        }
    }

    fn headline(&self) -> String {
        let name = self
            .organization
            .as_ref()
            .map(|organization| terminal_text(&organization.name))
            .filter(|name| !name.is_empty())
            .or_else(|| {
                self.organization
                    .as_ref()
                    .map(|organization| terminal_text(&organization.slug))
                    .filter(|slug| !slug.is_empty())
            })
            .unwrap_or_else(|| "This organization".to_owned());
        format!("{name} has no compute credit, so it can't run cloud sandboxes.")
    }

    /// The `--output json` form: the stable code, the organization and its billing
    /// page, and the local alternative.
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "error": {
                "code": CODE,
                "message": self.headline(),
                "organization": self.organization,
                "billing_url": self.billing_url,
                "local_create": LOCAL_CREATE,
            }
        })
    }
}

impl fmt::Display for CreditExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.headline())?;
        match &self.billing_url {
            Some(url) => writeln!(f, "Add a card or credit on its billing page: {url}")?,
            None => writeln!(f, "Add a card or credit on its billing page.")?,
        }
        write!(f, "Local sandboxes stay free: {LOCAL_CREATE}")
    }
}

impl std::error::Error for CreditExhausted {}

/// `{origin}/{slug}/billing/`, the dashboard's Billing page.
fn billing_url(server_url: &url::Url, slug: &str) -> Option<String> {
    let slug = slug.trim();
    if slug.is_empty() || slug.contains('/') {
        return None;
    }
    let mut url = server_url.clone();
    url.set_path(&format!("/{slug}/billing/"));
    url.set_query(None);
    url.set_fragment(None);
    Some(url.into())
}

/// Ends a command that failed on a credit refusal with the refusal alone,
/// without the operation context around it, and with `--output json` also prints
/// its structured form on stdout. Every other result passes through.
pub(crate) fn report(result: anyhow::Result<()>, json: bool) -> anyhow::Result<()> {
    let Err(error) = result else {
        return Ok(());
    };
    let Some(refusal) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<CreditExhausted>())
        .cloned()
    else {
        return Err(error);
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&refusal.json())?);
    }
    Err(refusal.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acme() -> RefusedOrganization {
        RefusedOrganization {
            id: "org-1".into(),
            name: "Acme".into(),
            slug: "acme".into(),
        }
    }

    #[test]
    fn names_the_organization_and_its_billing_page_on_the_server_origin() {
        let refusal = CreditExhausted::new(
            Some(acme()),
            &url::Url::parse("https://codewire.test/api/?x=1").unwrap(),
        );
        assert_eq!(
            refusal.to_string(),
            "Acme has no compute credit, so it can't run cloud sandboxes.\n\
             Add a card or credit on its billing page: https://codewire.test/acme/billing/\n\
             Local sandboxes stay free: cw create --local"
        );
        assert_eq!(
            refusal.json(),
            serde_json::json!({"error": {
                "code": "credit_exhausted",
                "message": "Acme has no compute credit, so it can't run cloud sandboxes.",
                "organization": {"id": "org-1", "name": "Acme", "slug": "acme"},
                "billing_url": "https://codewire.test/acme/billing/",
                "local_create": "cw create --local",
            }})
        );
    }

    #[test]
    fn an_unknown_organization_still_says_what_to_do() {
        let refusal = CreditExhausted::unnamed();
        assert_eq!(
            refusal.to_string(),
            "This organization has no compute credit, so it can't run cloud sandboxes.\n\
             Add a card or credit on its billing page.\n\
             Local sandboxes stay free: cw create --local"
        );
        assert_eq!(
            refusal.json()["error"]["billing_url"],
            serde_json::Value::Null
        );
        // A blank name gives way to the slug; terminal controls never print.
        let server = url::Url::parse("https://codewire.test").unwrap();
        let named = |name: &str| {
            CreditExhausted::new(
                Some(RefusedOrganization {
                    name: name.into(),
                    ..acme()
                }),
                &server,
            )
            .to_string()
        };
        assert!(named(" \n\t").starts_with("acme has no compute credit"));
        assert!(named("Acme\u{1b}[2J").starts_with("Acme [2J has no compute credit"));
    }

    #[test]
    fn report_drops_the_operation_context_and_passes_other_failures_through() {
        let refusal =
            CreditExhausted::new(Some(acme()), &url::Url::parse("https://c.test").unwrap());
        let wrapped = Err(anyhow::Error::new(refusal.clone()).context("create environment"));
        let reported = report(wrapped, false).unwrap_err();
        assert_eq!(format!("{reported:#}"), refusal.to_string());

        let other = report(
            Err(anyhow::anyhow!("boom").context("start environment")),
            true,
        );
        assert_eq!(
            format!("{:#}", other.unwrap_err()),
            "start environment: boom"
        );
        assert!(report(Ok(()), true).is_ok());
    }
}
