//! The user-facing text of a request that failed before any response.
//!
//! reqwest's own display is only "error sending request for url (...)": the
//! cause that tells a DNS failure from a refused connection, a TLS failure or a
//! timeout sits in its source chain. The message keeps that stable first part
//! and appends the chain on the same line after `; caused by: `, so scripts
//! can still match the first part and read the cause. rustls names a TLS
//! failure only by its own text, so its cause is labelled `tls error:` the way
//! the connector already labels `dns error:` and `tcp connect error:`.

use std::fmt::Write as _;

use connectrpc::ConnectError;

/// Separates the stable first part of a send failure from its cause chain.
pub(crate) const CAUSE_SEPARATOR: &str = "; caused by: ";

/// The canonical `unavailable` error for a request that got no response.
pub(crate) fn send_failure(error: reqwest::Error) -> ConnectError {
    ConnectError::unavailable(send_failure_message(error))
}

fn send_failure_message(error: reqwest::Error) -> String {
    let url = error.url().map(redacted_url);
    let error = error.without_url();
    let mut message = format!("send request: {error}");
    if let Some(url) = url {
        let _ = write!(message, " for url ({url})");
    }
    let causes = cause_chain(&error);
    if !causes.is_empty() {
        message.push_str(CAUSE_SEPARATOR);
        message.push_str(&causes.join(": "));
    }
    message
}

/// Each source's own text, outermost first. A source whose text an outer one
/// already shows is skipped, so wrappers that repeat their inner error do not
/// print it twice. Control characters become spaces to keep one line.
fn cause_chain(error: &(dyn std::error::Error + 'static)) -> Vec<String> {
    let mut causes: Vec<String> = Vec::new();
    let mut source = error.source();
    while let Some(cause) = source {
        let text = if is_tls_failure(cause) {
            format!("tls error: {cause}")
        } else {
            cause.to_string()
        };
        let text: String = text
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect();
        let text = text.trim();
        if !text.is_empty() && !causes.iter().any(|outer| outer.contains(text)) {
            causes.push(text.to_owned());
        }
        source = cause.source();
    }
    causes
}

/// rustls reaches the connector inside nested `io::Error`s, whose `source`
/// skips the wrapped error itself, so each wrapper is opened in turn.
fn is_tls_failure(cause: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = cause;
    loop {
        if current.is::<rustls::Error>() {
            return true;
        }
        match current
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
        {
            Some(inner) => current = inner,
            None => return false,
        }
    }
}

/// The request URL without user information, query or fragment, which can
/// carry credentials or request contents.
fn redacted_url(url: &reqwest::Url) -> String {
    let mut url = url.clone();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use connectrpc::ErrorCode;
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpListener;

    use super::*;
    use crate::{ClientConfig, CodewireClient, ListApiKeysRequest, StaticTokenProvider};

    const PATH: &str = "codewire.v1.ApiKeyService/ListApiKeys";

    /// The rendered message of one failed `ListApiKeys` call through the
    /// client's own transport, with the canonical code checked.
    async fn failed_call(server_url: &str, http: reqwest::Client) -> String {
        let config = ClientConfig::new(server_url)
            .expect("server URL")
            .with_unary_timeout(Duration::from_secs(20));
        let client = CodewireClient::with_http(
            config,
            StaticTokenProvider::new("synthetic-token").expect("token"),
            http,
        )
        .expect("client");
        let error = client
            .list_api_keys(ListApiKeysRequest::default())
            .await
            .expect_err("the request has no server to answer it");
        assert_eq!(error.code(), ErrorCode::Unavailable, "{error}");
        assert!(error.is_retryable_transport_interruption(), "{error}");
        let message = error.to_string();
        assert!(
            !message.contains("synthetic-token"),
            "the message carries the token: {message}"
        );
        assert!(
            !message.contains('\n'),
            "the message spans lines: {message}"
        );
        message
    }

    fn cause(message: &str) -> &str {
        message
            .split_once(CAUSE_SEPARATOR)
            .unwrap_or_else(|| panic!("no cause in {message}"))
            .1
    }

    fn assert_stable_first_part(message: &str, url: &str) {
        let expected = format!("send request: error sending request for url ({url}/{PATH})");
        assert!(
            message.starts_with(&format!("{expected}{CAUSE_SEPARATOR}")),
            "{message}"
        );
    }

    #[tokio::test]
    async fn a_name_that_does_not_resolve_names_the_dns_failure() {
        let url = "https://codewire-transport-test.invalid";
        let message = failed_call(url, reqwest::Client::new()).await;
        assert_stable_first_part(&message, url);
        assert!(cause(&message).contains("dns error"), "{message}");
    }

    #[tokio::test]
    async fn a_closed_local_port_names_the_refused_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        drop(listener);
        let url = format!("http://{address}");
        let message = failed_call(&url, reqwest::Client::new()).await;
        assert_stable_first_part(&message, &url);
        assert!(
            cause(&message)
                .to_ascii_lowercase()
                .contains("connection refused"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn a_server_that_does_not_speak_tls_names_the_tls_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
        });
        let url = format!("https://{address}");
        let message = failed_call(&url, reqwest::Client::new()).await;
        server.abort();
        assert_stable_first_part(&message, &url);
        assert!(
            cause(&message).contains("tls error: received corrupt message"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn a_server_that_never_answers_names_the_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            std::future::pending::<()>().await;
        });
        let url = format!("http://{address}");
        let http = reqwest::Client::builder()
            .http2_prior_knowledge()
            .timeout(Duration::from_millis(200))
            .build()
            .expect("client");
        let message = failed_call(&url, http).await;
        server.abort();
        assert_stable_first_part(&message, &url);
        assert!(cause(&message).contains("timed out"), "{message}");
    }

    #[tokio::test]
    async fn the_whole_call_deadline_is_its_own_canonical_code() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            std::future::pending::<()>().await;
        });
        let config = ClientConfig::new(format!("http://{address}"))
            .expect("server URL")
            .with_unary_timeout(Duration::from_millis(200));
        let client = CodewireClient::with_http(
            config,
            StaticTokenProvider::new("synthetic-token").expect("token"),
            reqwest::Client::builder()
                .http2_prior_knowledge()
                .build()
                .expect("client"),
        )
        .expect("client");
        let error = client
            .list_api_keys(ListApiKeysRequest::default())
            .await
            .expect_err("the server never answers");
        server.abort();
        assert_eq!(error.code(), ErrorCode::DeadlineExceeded, "{error}");
        assert_eq!(error.to_string(), "client-side deadline exceeded");
    }

    /// The classifier matches connectrpc's wording, so this takes the error
    /// from connectrpc itself: a rewording on an upgrade must fail here rather
    /// than end every attachment whose connection drops (#3895).
    #[tokio::test]
    async fn a_response_cut_off_part_way_is_a_retryable_interruption() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = Vec::new();
            while !request.windows(4).any(|end| end == b"\r\n\r\n") {
                let mut chunk = [0; 1024];
                let read = tokio::io::AsyncReadExt::read(&mut stream, &mut chunk)
                    .await
                    .expect("read the request");
                assert_ne!(read, 0, "the request ended early");
                request.extend_from_slice(&chunk[..read]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/connect+proto\r\ncontent-length: 1000\r\n\r\n\0\0\0\0\x10partial",
                )
                .await
                .expect("write the start of a response");
            // Dropping the stream ends the response short of its length.
        });
        let client = CodewireClient::with_http(
            ClientConfig::new(format!("http://{address}")).expect("server URL"),
            StaticTokenProvider::new("synthetic-token").expect("token"),
            reqwest::Client::new(),
        )
        .expect("client");
        let mut attachment = client
            .attach_session(crate::AttachSessionOpen::default())
            .await
            .expect("the stream opens");
        let error = attachment
            .next_output()
            .await
            .expect_err("the response is cut off");
        server.await.expect("server");
        assert!(error.is_retryable_transport_interruption(), "{error:?}");
    }

    #[tokio::test]
    async fn an_attachment_nobody_answers_opens_but_is_not_answered() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listen");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            std::future::pending::<()>().await;
        });
        let client = CodewireClient::with_http(
            ClientConfig::new(format!("http://{address}")).expect("server URL"),
            StaticTokenProvider::new("synthetic-token").expect("token"),
            reqwest::Client::builder()
                .http2_prior_knowledge()
                .build()
                .expect("client"),
        )
        .expect("client");
        let mut attachment = client
            .attach_session(crate::AttachSessionOpen::default())
            .await
            .expect("a stream opens with nobody there");
        let error = attachment
            .wait_for_answer(Duration::from_millis(200))
            .await
            .expect_err("nobody answers");
        server.abort();
        assert_eq!(error.code(), ErrorCode::DeadlineExceeded, "{error}");
    }

    #[test]
    fn the_url_drops_credentials_query_and_fragment() {
        let url = reqwest::Url::parse("https://user:secret@example.test:8443/a/b?token=t#f")
            .expect("url");
        assert_eq!(redacted_url(&url), "https://example.test:8443/a/b");
    }

    #[test]
    fn the_cause_chain_skips_repeated_text_and_stays_on_one_line() {
        #[derive(Debug)]
        struct Layer(&'static str, Option<Box<Layer>>);
        impl std::fmt::Display for Layer {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.0)
            }
        }
        impl std::error::Error for Layer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.1.as_deref().map(|layer| layer as _)
            }
        }
        let error = Layer(
            "top",
            Some(Box::new(Layer(
                "dns error: no such\nname",
                Some(Box::new(Layer("no such\nname", None))),
            ))),
        );
        assert_eq!(cause_chain(&error), vec!["dns error: no such name"]);
    }
}
