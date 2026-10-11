//! A scripted synthetic provider: it answers each request with the next
//! queued response and records what Codewire sent and when.

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};

use crate::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
};

pub(crate) struct Sent {
    pub method: Method,
    pub target: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub at: tokio::time::Instant,
}

impl Sent {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    pub fn form(&self) -> Vec<(String, String)> {
        url::form_urlencoded::parse(&self.body)
            .into_owned()
            .collect()
    }
}

#[derive(Default)]
pub(crate) struct ScriptedProvider {
    answers: Mutex<VecDeque<(StatusCode, Vec<u8>)>>,
    /// Answered once the script runs out, for flows that poll until expiry.
    repeat: Mutex<Option<(StatusCode, Vec<u8>)>>,
    sent: Mutex<Vec<Sent>>,
}

impl ScriptedProvider {
    pub fn answer(&self, status: StatusCode, body: serde_json::Value) -> &Self {
        self.answer_bytes(status, serde_json::to_vec(&body).unwrap())
    }

    pub fn answer_bytes(&self, status: StatusCode, body: Vec<u8>) -> &Self {
        self.answers.lock().unwrap().push_back((status, body));
        self
    }

    pub fn then_always(&self, status: StatusCode, body: serde_json::Value) {
        *self.repeat.lock().unwrap() = Some((status, serde_json::to_vec(&body).unwrap()));
    }

    pub fn sent(&self) -> std::sync::MutexGuard<'_, Vec<Sent>> {
        self.sent.lock().unwrap()
    }
}

#[async_trait]
impl BrokerUpstreamTransport for ScriptedProvider {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        self.sent.lock().unwrap().push(Sent {
            method,
            target: target.as_str().to_owned(),
            headers,
            body,
            at: tokio::time::Instant::now(),
        });
        let next = self.answers.lock().unwrap().pop_front();
        let (status, body) = next
            .or_else(|| self.repeat.lock().unwrap().clone())
            .ok_or(BrokerUpstreamError::Protocol)?;
        Ok(BrokerUpstreamResponse::new(
            status,
            HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json; charset=utf-8"),
            )]),
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(body)) })),
        ))
    }
}
