//! Cloudflare DNS client, mirroring `worker/cloudflare.go` — same
//! endpoints, same record shapes (proxied CNAME, TTL 1).

use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct CloudflareClient {
    api_token: String,
    zone_id: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct DnsRecord<'a> {
    #[serde(rename = "type")]
    type_: &'a str,
    name: &'a str,
    content: &'a str,
    proxied: bool,
    ttl: i64,
}

#[derive(Deserialize)]
struct CreateResponse {
    result: CreateResult,
}

#[derive(Deserialize)]
struct CreateResult {
    id: String,
}

impl CloudflareClient {
    pub fn new(api_token: impl Into<String>, zone_id: impl Into<String>) -> Self {
        Self {
            api_token: api_token.into(),
            zone_id: zone_id.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Builds from env like the Go config: prefers the preview zone
    /// when configured, falls back to the main zone; None when no
    /// Cloudflare credentials are set (handlers then no-op, like Go).
    pub fn from_env() -> Option<Self> {
        let token = std::env::var("CLOUDFLARE_API_TOKEN").unwrap_or_default();
        if token.is_empty() {
            return None;
        }
        let zone = std::env::var("PREVIEW_CLOUDFLARE_ZONE_ID")
            .ok()
            .filter(|z| !z.is_empty())
            .or_else(|| std::env::var("CLOUDFLARE_ZONE_ID").ok())
            .filter(|z| !z.is_empty())?;
        Some(Self::new(token, zone))
    }

    /// Mirrors `CreateCNAMEReturningID`: proxied CNAME, TTL 1.
    pub async fn create_cname_returning_id(
        &self,
        domain: &str,
        target: &str,
    ) -> anyhow::Result<String> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        );
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.api_token)
            .json(&DnsRecord {
                type_: "CNAME",
                name: domain,
                content: target,
                proxied: true,
                ttl: 1,
            })
            .send()
            .await?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        if status >= 400 {
            anyhow::bail!("cloudflare create CNAME failed (status {status}): {body}");
        }
        let parsed: CreateResponse = serde_json::from_str(&body)?;
        tracing::info!(
            domain,
            target,
            record_id = parsed.result.id,
            "cloudflare: created CNAME record"
        );
        Ok(parsed.result.id)
    }

    /// Mirrors `DeleteDNSRecordByID`.
    pub async fn delete_dns_record_by_id(&self, record_id: &str) -> anyhow::Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{record_id}",
            self.zone_id
        );
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        if resp.status().as_u16() == 404 {
            tracing::info!(record_id, "cloudflare: DNS record already absent");
            return Ok(());
        }
        if resp.status().as_u16() >= 400 {
            anyhow::bail!(
                "cloudflare delete record {record_id} failed (status {})",
                resp.status().as_u16()
            );
        }
        tracing::info!(record_id, "cloudflare: deleted DNS record");
        Ok(())
    }
}
