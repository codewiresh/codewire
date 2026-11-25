//! The public pages' analytics tag (infra#2677): Umami's tracker, served from
//! the dashboard's own assets, counting page views without cookies. A
//! deployment turns it on with `CODEWIRE_ANALYTICS_ORIGIN` and
//! `CODEWIRE_ANALYTICS_WEBSITE_ID`; with neither, no page carries it, so a
//! self-hosted deployment reports to no one.

use anyhow::{Context as _, bail};
use axum::http::HeaderMap;
use url::Url;

/// What the tag needs: where it sends, the website it counts for, and the
/// one host it may send from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Analytics {
    pub(crate) origin: String,
    pub(crate) website_id: String,
    pub(crate) domain: String,
}

impl Analytics {
    /// The tag for a page that a cache never shares: none for a request that
    /// may carry a session.
    pub(crate) fn for_visitor(this: Option<&Self>, headers: &HeaderMap) -> Option<Self> {
        this.filter(|_| !crate::security::carries_session(headers))
            .cloned()
    }
}

/// Both values or neither, like the Updates page's: one without the other
/// is a half-configured deployment, which refuses to start. The tag sends
/// only from the public origin's host, so a copy of the configuration on
/// another deployment counts nothing.
pub(crate) fn parse(
    origin: Option<String>,
    website_id: Option<String>,
    public_origin: &str,
) -> anyhow::Result<Option<Analytics>> {
    let (origin, website_id) = match (origin, website_id) {
        (None, None) => return Ok(None),
        (Some(origin), Some(website_id)) => (origin, website_id),
        _ => bail!(
            "CODEWIRE_ANALYTICS_ORIGIN and CODEWIRE_ANALYTICS_WEBSITE_ID are set together or not at all"
        ),
    };
    let (_, origin) = crate::config::parse_origin("CODEWIRE_ANALYTICS_ORIGIN", origin)?;
    if !origin.starts_with("https://") {
        bail!("CODEWIRE_ANALYTICS_ORIGIN must be an https:// origin");
    }
    let website_id = website_id.trim().to_ascii_lowercase();
    if !is_uuid(&website_id) {
        bail!("CODEWIRE_ANALYTICS_WEBSITE_ID must be an Umami website ID, a UUID");
    }
    let domain = Url::parse(public_origin)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .context("CODEWIRE_PUBLIC_ORIGIN has no host for the analytics tag")?;
    Ok(Some(Analytics {
        origin,
        website_id,
        domain,
    }))
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.char_indices().all(|(index, c)| match index {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "00000000-0000-4000-8000-0000000000aa";

    #[test]
    fn both_values_or_neither() {
        assert_eq!(parse(None, None, "https://codewire.test").unwrap(), None);
        assert!(
            parse(
                Some("https://umami.test".into()),
                None,
                "https://codewire.test"
            )
            .is_err()
        );
        assert!(parse(None, Some(ID.into()), "https://codewire.test").is_err());
        assert_eq!(
            parse(
                Some("https://umami.test/".into()),
                Some(ID.to_ascii_uppercase()),
                "https://codewire.test"
            )
            .unwrap(),
            Some(Analytics {
                origin: "https://umami.test".into(),
                website_id: ID.into(),
                domain: "codewire.test".into(),
            })
        );
    }

    #[test]
    fn only_an_https_origin_and_a_uuid() {
        for origin in ["http://umami.test", "https://umami.test/path", "umami.test"] {
            assert!(
                parse(
                    Some(origin.into()),
                    Some(ID.into()),
                    "https://codewire.test"
                )
                .is_err(),
                "{origin}"
            );
        }
        for id in [
            "",
            "00000000",
            "00000000-0000-4000-8000-0000000000ag",
            "\"><script>",
        ] {
            assert!(
                parse(
                    Some("https://umami.test".into()),
                    Some(id.into()),
                    "https://codewire.test"
                )
                .is_err(),
                "{id}"
            );
        }
    }
}
