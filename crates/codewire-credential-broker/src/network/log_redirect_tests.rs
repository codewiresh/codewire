use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::{HeaderMap, HeaderValue, Method, StatusCode, header};

use super::super::{ConnectionReuse, ProviderHttpsTransport, client_builder};
use super::{Refused, admit_location, fetch_log, follows};
use crate::{BrokerUpstreamError, BrokerUpstreamTransport as _};
use codewire_access::HttpProvider;

const SIGNED: &str = "sig=signed-url-secret-never-logged";

fn url(text: &str) -> url::Url {
    url::Url::parse(text).unwrap()
}

fn location(values: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for value in values {
        headers.append(header::LOCATION, HeaderValue::from_str(value).unwrap());
    }
    headers
}

fn public(last: u8) -> SocketAddr {
    SocketAddr::from(([8, 8, 8, last], 443))
}

/// Only a 3xx to GET on the two log downloads at the API host is followed.
#[test]
fn only_the_two_log_downloads_redirect_is_followed() {
    for path in [
        "/repos/owner/repo/actions/jobs/7/logs",
        "/repos/owner/repo/actions/runs/7/logs",
    ] {
        let target = url(&format!("https://api.github.com{path}"));
        assert!(follows(&target, &Method::GET, StatusCode::FOUND), "{path}");
        assert!(!follows(&target, &Method::GET, StatusCode::OK), "{path}");
        assert!(
            !follows(&target, &Method::HEAD, StatusCode::FOUND),
            "{path}"
        );
        let git_host = url(&format!("https://github.com{path}"));
        assert!(
            !follows(&git_host, &Method::GET, StatusCode::FOUND),
            "{path}"
        );
    }
    for path in [
        "/repos/owner/repo/actions/jobs/7",
        "/repos/owner/repo/actions/runs/7",
        "/repos/owner/repo/actions/runs/7/jobs",
        "/repos/owner/repo/actions/runs/07/logs",
        "/repos/owner/repo/actions/artifacts/7/zip",
        "/repos/owner/repo/readme",
        "/repos/owner/repo/tarball/main",
    ] {
        let target = url(&format!("https://api.github.com{path}"));
        assert!(!follows(&target, &Method::GET, StatusCode::FOUND), "{path}");
    }
}

/// The host is compared exactly, as the URL parser gives it. Every refusal
/// happens before anything is dialled.
#[test]
fn a_location_is_admitted_only_to_an_exact_listed_host_by_https_on_443() {
    for (location_text, host) in [
        (
            "https://productionresultssa0.blob.core.windows.net/actions-results/a/b.txt",
            "productionresultssa0.blob.core.windows.net",
        ),
        (
            "https://productionresultssa199.blob.core.windows.net:443/x",
            "productionresultssa199.blob.core.windows.net",
        ),
        // The parser lowercases a host, so this is the same name.
        (
            "https://PRODUCTIONRESULTSSA7.Blob.Core.Windows.Net/x",
            "productionresultssa7.blob.core.windows.net",
        ),
        (
            "https://pipelinesghubeus1.actions.githubusercontent.com/x/_apis/signedlogcontent/1",
            "pipelinesghubeus1.actions.githubusercontent.com",
        ),
    ] {
        let signed = format!("{location_text}?{SIGNED}");
        let (target, listed) = admit_location(&location(&[&signed])).unwrap();
        assert_eq!(listed, host);
        assert_eq!(target.host_str(), Some(host));
        assert_eq!(target.query(), Some(SIGNED));
    }
    for (location_text, reason) in [
        // Same-shape accounts outside the list, and look-alikes.
        (
            "https://productionresultssa20.blob.core.windows.net/x",
            Refused::Unlisted,
        ),
        (
            "https://productionresultssa200.blob.core.windows.net/x",
            Refused::Unlisted,
        ),
        (
            "https://productionresultssa1x.blob.core.windows.net/x",
            Refused::Unlisted,
        ),
        (
            "https://xproductionresultssa1.blob.core.windows.net/x",
            Refused::Unlisted,
        ),
        ("https://anyone.blob.core.windows.net/x", Refused::Unlisted),
        (
            "https://productionresultssa1.blob.core.windows.net.evil.example/x",
            Refused::Unlisted,
        ),
        (
            "https://productionresultssa1.blob.core.windows.net./x",
            Refused::Unlisted,
        ),
        // GitHub's zone too is matched by name, never by suffix.
        (
            "https://anything.actions.githubusercontent.com/x",
            Refused::Unlisted,
        ),
        ("https://api.github.com/x", Refused::Unlisted),
        ("https://192.0.2.7/x", Refused::Unlisted),
        ("https://[2001:db8::1]/x", Refused::Unlisted),
        (
            "http://productionresultssa0.blob.core.windows.net/x",
            Refused::Scheme,
        ),
        (
            "https://productionresultssa0.blob.core.windows.net:8443/x",
            Refused::Port,
        ),
        (
            "https://user@productionresultssa0.blob.core.windows.net/x",
            Refused::Userinfo,
        ),
        (
            "https://user:pass@productionresultssa0.blob.core.windows.net/x",
            Refused::Userinfo,
        ),
        (
            "https://productionresultssa0.blob.core.windows.net/x#part",
            Refused::Fragment,
        ),
        ("/repos/owner/repo/actions/jobs/7/logs", Refused::Location),
        ("not a url", Refused::Location),
    ] {
        assert_eq!(
            admit_location(&location(&[location_text]))
                .map(|(_, host)| host)
                .map_err(|(reason, _)| reason),
            Err(reason),
            "{location_text}"
        );
    }
    assert_eq!(
        admit_location(&HeaderMap::new()).map(|(_, host)| host),
        Err((Refused::Location, None))
    );
    let listed = "https://productionresultssa0.blob.core.windows.net/x";
    assert_eq!(
        admit_location(&location(&[listed, listed])).map(|(_, host)| host),
        Err((Refused::Location, None))
    );
}

/// The log hosts are looked up at a GitHub broker's start with its other
/// hosts. One that fails, or answers only addresses the broker never dials,
/// is dropped by name: it is no provider's, so GitHub stays served.
#[test]
fn a_start_pins_the_log_hosts_that_resolve_and_drops_the_rest_by_name() {
    let dropped = "productionresultssa3.blob.core.windows.net";
    let private = "pipelinesghubeus2.actions.githubusercontent.com";
    let github = BTreeSet::from([HttpProvider::GitHubOAuth]);
    let looked_up = ProviderHttpsTransport::look_up_with(&[&github], |host, _| match host {
        _ if host == dropped => Err(std::io::ErrorKind::TimedOut.into()),
        _ if host == private => Ok(vec![SocketAddr::from(([10, 0, 0, 1], 443))]),
        _ => Ok(vec![public(1)]),
    })
    .unwrap();
    let transport = ProviderHttpsTransport::available(&github, &looked_up).unwrap();
    assert_eq!(transport.unresolved_hosts().count(), 0);
    assert!(!transport.slot_unserved("github"));
    assert_eq!(transport.resolved_address_count, 2);
    let listed = crate::github::log_hosts::log_hosts().collect::<BTreeSet<_>>();
    assert_eq!(listed.len(), 171);
    assert_eq!(
        listed
            .difference(&transport.log_hosts)
            .copied()
            .collect::<Vec<_>>(),
        [private, dropped]
    );

    // A broker that doesn't serve GitHub looks none up.
    let asked = Mutex::new(Vec::new());
    let openai = BTreeSet::from([HttpProvider::OpenAiApiKey]);
    ProviderHttpsTransport::look_up_with(&[&openai], |host, _| {
        asked.lock().unwrap().push(host.to_owned());
        Ok(vec![public(1)])
    })
    .unwrap();
    assert_eq!(asked.into_inner().unwrap(), ["api.openai.com"]);

    // The hosted service's pooled transport looks them up too, and a log host
    // never fails it; a sign-in command's per-request one looks none up.
    let pooled =
        ProviderHttpsTransport::resolve_with(&github, ConnectionReuse::Pooled, |host, _| {
            if crate::github::log_hosts::log_host(host).is_some() {
                Err(std::io::ErrorKind::TimedOut.into())
            } else {
                Ok(vec![public(1)])
            }
        })
        .unwrap();
    assert!(pooled.log_hosts.is_empty());
    let asked = Mutex::new(0_usize);
    let per_request =
        ProviderHttpsTransport::resolve_with(&github, ConnectionReuse::PerRequest, |_, _| {
            *asked.lock().unwrap() += 1;
            Ok(vec![public(1)])
        })
        .unwrap();
    assert!(per_request.log_hosts.is_empty());
    assert_eq!(asked.into_inner().unwrap(), 2);
}

fn redirect(status: StatusCode, location_text: &str) -> reqwest::Response {
    reqwest::Response::from(
        http::Response::builder()
            .status(status)
            .header(header::LOCATION, location_text)
            .body(Vec::<u8>::new())
            .unwrap(),
    )
}

/// A redirect to a listed host this broker dropped is refused at once, with
/// no lookup: the client would otherwise look the name up itself.
#[tokio::test]
async fn a_redirect_to_a_dropped_or_off_list_host_is_refused_without_a_dial() {
    let dropped = "productionresultssa3.blob.core.windows.net";
    let github = BTreeSet::from([HttpProvider::GitHubOAuth]);
    let looked_up = ProviderHttpsTransport::look_up_with(&[&github], |host, _| {
        if host == dropped {
            Err(std::io::ErrorKind::TimedOut.into())
        } else {
            Ok(vec![public(1)])
        }
    })
    .unwrap();
    let transport = ProviderHttpsTransport::available(&github, &looked_up).unwrap();
    for (status, location_text) in [
        (StatusCode::FOUND, format!("https://{dropped}/x?{SIGNED}")),
        (
            StatusCode::FOUND,
            format!("https://productionresultssa20.blob.core.windows.net/x?{SIGNED}"),
        ),
        (
            StatusCode::MOVED_PERMANENTLY,
            format!("https://productionresultssa0.blob.core.windows.net/x?{SIGNED}"),
        ),
    ] {
        let refused = tokio::time::timeout(
            Duration::from_secs(1),
            transport.follow_log_redirect(redirect(status, &location_text)),
        )
        .await
        .expect("refused without a dial");
        assert_eq!(refused.err(), Some(BrokerUpstreamError::Protocol));
    }
}

/// A loopback log host that records each request head and answers one canned
/// response.
struct LogHostStandIn {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl LogHostStandIn {
    async fn start(response: &'static [u8]) -> Self {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let record = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = tokio::io::BufReader::new(stream);
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if stream.read_line(&mut line).await.unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    head.push_str(&line);
                }
                record.lock().unwrap().push(head);
                let _ = stream.get_mut().write_all(response).await;
                let _ = stream.get_mut().shutdown().await;
            }
        });
        Self {
            address,
            requests,
            task,
        }
    }

    /// The production client settings, except plain http to the stand-in.
    fn client(&self) -> reqwest::Client {
        client_builder(ConnectionReuse::PerRequest)
            .https_only(false)
            .build()
            .unwrap()
    }

    fn url(&self) -> url::Url {
        url(&format!(
            "http://{}/actions-results/job-logs.txt?{SIGNED}",
            self.address
        ))
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for LogHostStandIn {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The second request carries only what the broker writes, never a
/// credential or cookie, and the guest gets the body with `Content-Type` and
/// `Content-Length` alone.
#[tokio::test]
async fn the_second_request_carries_no_credential_and_returns_only_the_body() {
    let host = LogHostStandIn::start(
        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 9\r\n\
          etag: \"x\"\r\nset-cookie: a=b\r\nx-ms-request-id: r\r\n\
          location: https://elsewhere.example/\r\n\r\nlog line\n",
    )
    .await;
    let response = fetch_log(
        &host.client(),
        host.url(),
        "productionresultssa0.blob.core.windows.net",
    )
    .await
    .unwrap();
    let (status, headers, body) = response.into_parts();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.keys().map(|name| name.as_str()).collect::<Vec<_>>(),
        ["content-type", "content-length"]
    );
    let body = futures::StreamExt::collect::<Vec<_>>(body).await;
    let body = body
        .into_iter()
        .map(Result::unwrap)
        .collect::<Vec<_>>()
        .concat();
    assert_eq!(body, b"log line\n");
    let requests = host.requests();
    assert_eq!(requests.len(), 1);
    let head = requests[0].to_ascii_lowercase();
    assert!(
        head.starts_with(&format!(
            "get /actions-results/job-logs.txt?{SIGNED} http/1.1\r\n"
        )),
        "{head}"
    );
    let names = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.to_owned()))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from(["accept", "accept-encoding", "host", "user-agent"].map(str::to_owned))
    );
}

/// The log host's own 3xx is never followed, and any answer but 200 fails the
/// request without its body or headers.
#[tokio::test]
async fn a_second_redirect_or_another_status_is_refused_and_never_followed() {
    for response in [
        &b"HTTP/1.1 302 Found\r\nlocation: https://productionresultssa1.blob.core.windows.net/x\r\ncontent-length: 0\r\n\r\n"[..],
        &b"HTTP/1.1 307 Temporary Redirect\r\nlocation: /again\r\ncontent-length: 0\r\n\r\n"[..],
        &b"HTTP/1.1 403 Forbidden\r\ncontent-type: application/xml\r\ncontent-length: 2\r\n\r\nno"[..],
    ] {
        let host = LogHostStandIn::start(response).await;
        let refused = fetch_log(
            &host.client(),
            host.url(),
            "productionresultssa0.blob.core.windows.net",
        )
        .await;
        assert_eq!(refused.err(), Some(BrokerUpstreamError::Protocol));
        assert_eq!(host.requests().len(), 1, "followed a second hop");
    }
}

/// A refusal's log line names the host and the reason and carries the running
/// count, never the signed URL, its path or its query.
#[tokio::test(flavor = "current_thread")]
async fn a_refusal_is_logged_by_host_and_reason_never_by_url() {
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    crate::timing::tests::keep_interest_peer();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

    let github = BTreeSet::from([HttpProvider::GitHubOAuth]);
    let transport = ProviderHttpsTransport::available(
        &github,
        &ProviderHttpsTransport::look_up_with(&[&github], |_, _| Ok(vec![public(1)])).unwrap(),
    )
    .unwrap();
    let off_list =
        format!("https://productionresultssa200.blob.core.windows.net/secret-path/x?{SIGNED}");
    assert!(
        transport
            .follow_log_redirect(redirect(StatusCode::FOUND, &off_list))
            .await
            .is_err()
    );
    let host = LogHostStandIn::start(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n").await;
    assert!(
        fetch_log(
            &host.client(),
            host.url(),
            "productionresultssa0.blob.core.windows.net"
        )
        .await
        .is_err()
    );

    let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.contains("host=productionresultssa200.blob.core.windows.net reason=\"unlisted\"")
            || text.contains("host=productionresultssa200.blob.core.windows.net reason=unlisted"),
        "{text}"
    );
    assert!(
        text.contains("reason=") && text.contains("status"),
        "{text}"
    );
    assert!(text.contains("refused_total="), "{text}");
    for secret in [SIGNED, "secret-path", "job-logs.txt", "actions-results"] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
}
