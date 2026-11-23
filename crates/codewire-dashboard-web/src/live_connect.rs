//! Orchestration's `LiveService.Watch` (#4762), the source the browser's live
//! stream relays. Events carry ids only; the page re-fetches through the
//! routes that re-authorize (private-docs `designs/live-updates.md`).

use axum::http::HeaderValue;
use codewire_proto::codewire::console::v1::{LiveServiceClient, WatchRequest, WatchResponse};
use connectrpc::{ConnectError, client::ClientConfig};

use crate::{state::AppState, transport::BrowserTransport};

/// Opens a watch for the signed-in viewer and forwards its events until the
/// reader goes away, the watch ends, or it fails; a failure is sent last.
pub(crate) fn watch_events(
    state: &AppState,
    cookie: HeaderValue,
) -> tokio::sync::mpsc::Receiver<Result<WatchResponse, ConnectError>> {
    let (events, receiver) = tokio::sync::mpsc::channel(16);
    let client = LiveServiceClient::new(
        BrowserTransport {
            http: state.stream_http.clone(),
            cookie: Some(cookie),
            origin: None,
        },
        ClientConfig::new(state.api_origin.clone()),
    );
    tokio::spawn(async move {
        let mut stream = match client.watch(WatchRequest::default()).await {
            Ok(stream) => stream,
            Err(error) => {
                let _ = events.send(Err(error)).await;
                return;
            }
        };
        loop {
            // Stop as soon as the reader goes away, so orchestration releases
            // this account's watch slot without waiting for a heartbeat.
            let message = tokio::select! {
                () = events.closed() => return,
                message = stream.message::<WatchResponse>() => message,
            };
            let message = match message {
                Ok(Some(message)) => Ok(message.to_owned_message()),
                Ok(None) => return,
                Err(error) => Err(error),
            };
            let failed = message.is_err();
            if events.send(message).await.is_err() || failed {
                return;
            }
        }
    });
    receiver
}
