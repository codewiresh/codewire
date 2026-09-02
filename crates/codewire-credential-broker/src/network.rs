use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _};
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt as _;
use http::HeaderMap;
use reqwest::redirect::Policy;

use crate::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
};

const OPENAI_HOST: &str = "api.openai.com";
const OPENAI_PORT: u16 = 443;
const OPENAI_PATH: &str = "/v1/responses";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_RESOLVED_ADDRESSES: usize = 16;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;

/// Broker-local OpenAI transport. DNS is resolved once per broker process, every
/// result is classified before dialing, and the admitted addresses are pinned
/// into the TLS client so a second resolver lookup cannot rebind the request.
#[derive(Clone)]
pub struct OpenAiHttpsTransport {
    client: reqwest::Client,
    resolved_address_count: usize,
}

impl std::fmt::Debug for OpenAiHttpsTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenAiHttpsTransport")
            .field("destination", &OPENAI_HOST)
            .field("resolved_address_count", &self.resolved_address_count)
            .finish_non_exhaustive()
    }
}

impl OpenAiHttpsTransport {
    /// Resolve and classify the fixed provider destination before any
    /// credential lease is requested. The admitted addresses remain pinned for
    /// this broker process, so post-confinement requests perform no DNS I/O.
    pub async fn resolve() -> Result<Self, BrokerUpstreamError> {
        // This deliberately uses the calling thread instead of Tokio's
        // blocking resolver pool. Broker launch is bounded by the authority's
        // readiness timeout, and retaining a resolver worker here would leave
        // an already-running thread outside older Landlock thread domains.
        let addresses = (OPENAI_HOST, OPENAI_PORT)
            .to_socket_addrs()
            .map_err(|_| BrokerUpstreamError::Connect)?;
        let addresses = admit_resolved_addresses(addresses)?;
        let resolved_address_count = addresses.len();
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .referer(false)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .http2_max_header_list_size(MAX_RESPONSE_HEADER_BYTES as u32)
            .pool_max_idle_per_host(0)
            .resolve_to_addrs(OPENAI_HOST, &addresses)
            .build()
            .map_err(|_| BrokerUpstreamError::Protocol)?;
        Ok(Self {
            client,
            resolved_address_count,
        })
    }
}

#[async_trait]
impl BrokerUpstreamTransport for OpenAiHttpsTransport {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        validate_target(&target)?;
        let response = self
            .client
            .request(method, target.as_str())
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        if response.url().scheme() != "https"
            || response.url().host_str() != Some(OPENAI_HOST)
            || response.url().port_or_known_default() != Some(OPENAI_PORT)
            || response.url().path() != OPENAI_PATH
            || response.url().query().is_some()
        {
            return Err(BrokerUpstreamError::DestinationDenied);
        }
        let status = response.status();
        let headers = response.headers().clone();
        validate_response_headers(&headers)?;
        let body = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(map_reqwest_error));
        Ok(BrokerUpstreamResponse::new(status, headers, Box::pin(body)))
    }
}

fn validate_target(target: &url::Url) -> Result<(), BrokerUpstreamError> {
    if target.scheme() != "https"
        || target.host_str() != Some(OPENAI_HOST)
        || target.port_or_known_default() != Some(OPENAI_PORT)
        || target.path() != OPENAI_PATH
        || target.query().is_some()
        || target.fragment().is_some()
        || !target.username().is_empty()
        || target.password().is_some()
    {
        return Err(BrokerUpstreamError::DestinationDenied);
    }
    Ok(())
}

fn admit_resolved_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, BrokerUpstreamError> {
    let mut admitted = BTreeSet::new();
    for address in addresses {
        if address.port() != OPENAI_PORT || !public_provider_ip(address.ip()) {
            return Err(BrokerUpstreamError::DestinationDenied);
        }
        admitted.insert(address);
        if admitted.len() > MAX_RESOLVED_ADDRESSES {
            return Err(BrokerUpstreamError::ResourceLimit);
        }
    }
    if admitted.is_empty() {
        return Err(BrokerUpstreamError::Connect);
    }
    Ok(admitted.into_iter().collect())
}

fn public_provider_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => public_ipv4(address),
        IpAddr::V6(address) => match address.to_ipv4() {
            Some(address) => public_ipv4(address),
            None => public_ipv6(address),
        },
    }
}

fn public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
        || (a == 255 && b == 255 && c == 255 && d == 255))
}

fn public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    let first = segments[0];
    let nat64_well_known =
        first == 0x0064 && segments[1] == 0xff9b && segments[2..6].iter().all(|value| *value == 0);
    if nat64_well_known {
        return public_ipv4(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        ));
    }
    !(address.is_unspecified()
        || address.is_loopback()
        || first & 0xfe00 == 0xfc00
        || first & 0xffc0 == 0xfe80
        || first & 0xffc0 == 0xfec0
        || first & 0xff00 == 0xff00
        || (first == 0x0100 && segments[1..4].iter().all(|value| *value == 0))
        || (first == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001)
        || (first == 0x2001 && segments[1] == 0x0000)
        || (first == 0x2001 && segments[1] == 0x0002)
        || (first == 0x2001 && segments[1] == 0x0db8)
        || (first == 0x2001 && (segments[1] & 0xfff0 == 0x0010))
        || (first == 0x2001 && (segments[1] & 0xfff0 == 0x0020))
        || first == 0x2002)
}

fn validate_response_headers(headers: &HeaderMap) -> Result<(), BrokerUpstreamError> {
    let bytes = headers.iter().try_fold(0_usize, |total, (name, value)| {
        total
            .checked_add(name.as_str().len())
            .and_then(|total| total.checked_add(value.as_bytes().len()))
    });
    if !bytes.is_some_and(|bytes| bytes <= MAX_RESPONSE_HEADER_BYTES) {
        return Err(BrokerUpstreamError::ResourceLimit);
    }
    Ok(())
}

fn map_reqwest_error(error: reqwest::Error) -> BrokerUpstreamError {
    if error.is_timeout() || error.is_connect() {
        BrokerUpstreamError::Connect
    } else if error.is_builder() {
        BrokerUpstreamError::DestinationDenied
    } else {
        BrokerUpstreamError::Protocol
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_is_exact_and_never_redirectable() {
        assert!(
            validate_target(&url::Url::parse("https://api.openai.com/v1/responses").unwrap())
                .is_ok()
        );
        for denied in [
            "http://api.openai.com/v1/responses",
            "https://api.openai.com.evil.test/v1/responses",
            "https://api.openai.com/v1/responses?next=evil",
            "https://api.openai.com/v1/other",
            "https://user@api.openai.com/v1/responses",
            "https://api.openai.com:444/v1/responses",
        ] {
            assert_eq!(
                validate_target(&url::Url::parse(denied).unwrap()),
                Err(BrokerUpstreamError::DestinationDenied),
                "{denied}"
            );
        }
    }

    #[test]
    fn resolver_fails_closed_on_any_non_public_or_oversized_answer_set() {
        for denied in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::192.168.0.1",
            "::ffff:127.0.0.1",
            "100::1",
            "64:ff9b::127.0.0.1",
            "64:ff9b:1::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2002:0808:0808::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ] {
            let address = denied.parse::<IpAddr>().unwrap();
            assert!(!public_provider_ip(address), "{denied}");
            assert_eq!(
                admit_resolved_addresses([SocketAddr::new(address, OPENAI_PORT)]),
                Err(BrokerUpstreamError::DestinationDenied),
                "{denied}"
            );
        }
        for admitted in [
            "1.1.1.1",
            "8.8.8.8",
            "64:ff9b::8.8.8.8",
            "2606:4700:4700::1111",
        ] {
            assert!(public_provider_ip(admitted.parse().unwrap()), "{admitted}");
        }
        let too_many = (1..=17)
            .map(|last| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, last)), OPENAI_PORT));
        assert_eq!(
            admit_resolved_addresses(too_many),
            Err(BrokerUpstreamError::ResourceLimit)
        );
    }

    #[test]
    fn response_headers_are_bounded_before_the_bridge() {
        let mut headers = HeaderMap::new();
        headers.insert("x-test", http::HeaderValue::from_static("small"));
        assert!(validate_response_headers(&headers).is_ok());
        headers.insert(
            "x-large",
            http::HeaderValue::from_bytes(&vec![b'a'; MAX_RESPONSE_HEADER_BYTES]).unwrap(),
        );
        assert_eq!(
            validate_response_headers(&headers),
            Err(BrokerUpstreamError::ResourceLimit)
        );
    }
}
