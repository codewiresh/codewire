//! Whether SES will deliver to an address (#4548). SES keeps an
//! account-level suppression list, on for bounces and complaints on
//! Codewire's servers, and drops every send to an address on it. The IdP asks
//! about one address it holds before it would send nothing useful; the rules
//! are in docs/dev/AUTH-POLICY.md, "An address SES won't deliver to".
//!
//! Only the outcome is read from SES's record: never its time, feedback id or
//! message. The address is never logged.

use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

use crate::{Delivery, EmailClient, SesDelivery, sign_ses_request, validate_mailbox};

/// How long one lookup may take, connecting and reading the answer included,
/// before it counts as [`Suppression::Unknown`].
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
/// The most of an answer's body read, well above SES's record.
const ANSWER_LIMIT: usize = 8 * 1024;

/// What SES's account-level suppression list says about one address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Suppression {
    /// Suppressed after a hard bounce.
    Bounced,
    /// Suppressed after its owner marked our mail as spam.
    Complained,
    /// Not on the list: SES delivers to it.
    NotSuppressed,
    /// No answer to act on: no SES, a refused, throttled or late call, or an
    /// answer it couldn't read. Never blocks a send and is never shown.
    Unknown,
}

impl Suppression {
    /// The label of a skip's count: `bounce` or `complaint`, else `None`.
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Self::Bounced => Some("bounce"),
            Self::Complained => Some("complaint"),
            Self::NotSuppressed | Self::Unknown => None,
        }
    }
}

impl EmailClient {
    /// Asks SES whether `address` is on the account-level suppression list,
    /// within [`LOOKUP_TIMEOUT`]. Anything but a clear answer is
    /// [`Suppression::Unknown`].
    pub async fn suppression(&self, address: &str) -> Suppression {
        match self.delivery.as_ref() {
            Delivery::Disabled => Suppression::Unknown,
            // The request's own timeout bounds the whole lookup, the answer
            // read included; a failure says nothing the caller acts on.
            Delivery::Ses(delivery) => ask_ses(delivery, address)
                .await
                .unwrap_or(Suppression::Unknown),
            #[cfg(feature = "test-support")]
            Delivery::Recording(outbox) => outbox
                .suppressed
                .lock()
                .expect("outbox lock")
                .get(address)
                .copied()
                .unwrap_or(Suppression::NotSuppressed),
        }
    }
}

async fn ask_ses(delivery: &SesDelivery, address: &str) -> Result<Suppression> {
    validate_mailbox(address, "suppression lookup")?;
    let mut url = reqwest::Url::parse(&format!(
        "https://email.{}.amazonaws.com/v2/email/suppression/addresses/",
        delivery.region
    ))
    .context("build SES suppression URL")?;
    url.path_segments_mut()
        .map_err(|()| anyhow::anyhow!("SES suppression URL has no path"))?
        .pop_if_empty()
        .push(address);
    let request = delivery
        .client
        .get(url)
        .build()
        .context("build SES suppression request")?;
    let mut request = sign_ses_request(
        request,
        &delivery.credentials,
        &delivery.region,
        Vec::new(),
        SystemTime::now(),
    )?;
    *request.timeout_mut() = Some(LOOKUP_TIMEOUT);
    let mut response = delivery
        .client
        .execute(request)
        .await
        .context("ask SES about an address")?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(Suppression::NotSuppressed);
    }
    if !status.is_success() {
        // 429 is SES throttling the call; like any refusal it is unknown.
        anyhow::bail!("SES suppression lookup answered {}", status.as_u16());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read SES suppression answer")?
    {
        if body.len() + chunk.len() > ANSWER_LIMIT {
            anyhow::bail!("SES suppression answer is too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(read_answer(&body))
}

/// The outcome of a 200 answer, from its `Reason` alone.
fn read_answer(body: &[u8]) -> Suppression {
    let reason = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|answer| {
            answer
                .get("SuppressedDestination")?
                .get("Reason")?
                .as_str()
                .map(str::to_owned)
        });
    match reason.as_deref() {
        Some("BOUNCE") => Suppression::Bounced,
        Some("COMPLAINT") => Suppression::Complained,
        _ => Suppression::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_reason_is_read_and_anything_else_is_unknown() {
        let answer = |reason: &str| {
            format!(
                r#"{{"SuppressedDestination":{{"EmailAddress":"a@example.test","Reason":"{reason}","LastUpdateTime":1.7e9,"Attributes":{{"MessageId":"m","FeedbackId":"f"}}}}}}"#
            )
        };
        assert_eq!(
            read_answer(answer("BOUNCE").as_bytes()),
            Suppression::Bounced
        );
        assert_eq!(
            read_answer(answer("COMPLAINT").as_bytes()),
            Suppression::Complained
        );
        assert_eq!(
            read_answer(answer("OTHER").as_bytes()),
            Suppression::Unknown
        );
        assert_eq!(read_answer(b"{}"), Suppression::Unknown);
        assert_eq!(read_answer(b"not json"), Suppression::Unknown);
        assert_eq!(Suppression::Bounced.reason(), Some("bounce"));
        assert_eq!(Suppression::Complained.reason(), Some("complaint"));
        assert_eq!(Suppression::Unknown.reason(), None);
    }

    #[tokio::test]
    async fn without_ses_every_answer_is_unknown() {
        assert_eq!(
            EmailClient::disabled().suppression("a@example.test").await,
            Suppression::Unknown
        );
    }

    #[test]
    fn the_address_is_one_encoded_path_segment() {
        let mut url = reqwest::Url::parse(
            "https://email.eu-west-1.amazonaws.com/v2/email/suppression/addresses/",
        )
        .unwrap();
        url.path_segments_mut()
            .unwrap()
            .pop_if_empty()
            .push("a+b/c@example.test");
        assert_eq!(
            url.path(),
            "/v2/email/suppression/addresses/a+b%2Fc@example.test"
        );
    }
}
