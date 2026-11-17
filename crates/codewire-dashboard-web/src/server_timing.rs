//! A `Server-Timing` header for pages whose upstream reads are worth seeing in
//! the browser's network panel. Each mark records the time since the previous
//! one in milliseconds under a fixed name; no request data enters the header.

use std::time::{Duration, Instant};

use axum::{
    extract::Request,
    http::{HeaderMap, HeaderName, HeaderValue, Method},
    middleware::Next,
    response::Response,
};

use crate::security::canonical_cookie;

const HEADER: HeaderName = HeaderName::from_static("server-timing");

/// Every signed-in page carries `Server-Timing: total;dur=MS`: the time this
/// server took from the request to its response, so the browser's network
/// panel can tell the server's share from the rest (#5206). A page that marks
/// its own phases keeps them beside it. Pages and requests with no session
/// carry nothing, so a sign-in form never shows how long a lookup took.
pub(crate) async fn total_for_signed_in_pages(request: Request, next: Next) -> Response {
    let timed = signed_in_page(request.method(), request.headers());
    let started = Instant::now();
    let mut response = next.run(request).await;
    if timed {
        add_total(&mut response, started.elapsed());
    }
    response
}

fn signed_in_page(method: &Method, headers: &HeaderMap) -> bool {
    method == Method::GET && canonical_cookie(headers).is_ok()
}

fn add_total(response: &mut Response, elapsed: Duration) {
    let value = format!("total;dur={:.1}", elapsed.as_secs_f64() * 1000.0);
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().append(HEADER, value);
    }
}

pub(crate) struct ServerTiming {
    last: Instant,
    marks: Vec<(&'static str, f64)>,
}

impl ServerTiming {
    pub(crate) fn start() -> Self {
        Self {
            last: Instant::now(),
            marks: Vec::new(),
        }
    }

    /// Close the phase that ended now.
    pub(crate) fn mark(&mut self, name: &'static str) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64() * 1000.0;
        self.marks.push((name, elapsed));
        self.last = now;
    }

    fn value(&self) -> Option<HeaderValue> {
        if self.marks.is_empty() {
            return None;
        }
        let value = self
            .marks
            .iter()
            .map(|(name, milliseconds)| format!("{name};dur={milliseconds:.1}"))
            .collect::<Vec<_>>()
            .join(", ");
        HeaderValue::from_str(&value).ok()
    }

    pub(crate) fn apply(&self, response: &mut Response) {
        if let Some(value) = self.value() {
            response.headers_mut().insert(HEADER, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, Method, header};

    use super::{HEADER, ServerTiming, add_total, signed_in_page};

    #[test]
    fn marks_name_each_phase_with_its_own_duration() {
        let mut timing = ServerTiming::start();
        timing.mark("shell");
        timing.mark("reads");
        let value = timing.value().unwrap();
        let value = value.to_str().unwrap();
        let phases: Vec<&str> = value
            .split(", ")
            .map(|phase| phase.split(";dur=").next().unwrap())
            .collect();
        assert_eq!(phases, ["shell", "reads"]);
        assert!(value.split(", ").all(|phase| {
            phase
                .split(";dur=")
                .nth(1)
                .is_some_and(|duration| duration.parse::<f64>().is_ok())
        }));
    }

    #[test]
    fn no_marks_sends_no_header() {
        assert!(ServerTiming::start().value().is_none());
    }

    fn cookie(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn only_a_signed_in_get_is_timed() {
        let signed_in = cookie("codewire.session_token=abc");
        assert!(signed_in_page(&Method::GET, &signed_in));
        assert!(!signed_in_page(&Method::POST, &signed_in));
        assert!(!signed_in_page(&Method::GET, &HeaderMap::new()));
        assert!(!signed_in_page(&Method::GET, &cookie("theme=dark")));
    }

    #[test]
    fn the_total_sits_beside_a_pages_own_phases() {
        let mut response = axum::response::Response::new(axum::body::Body::empty());
        let mut phases = ServerTiming::start();
        phases.mark("reads");
        phases.apply(&mut response);
        add_total(&mut response, std::time::Duration::from_millis(59));
        let values: Vec<&str> = response
            .headers()
            .get_all(HEADER)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(values.len(), 2, "{values:?}");
        assert!(values[0].starts_with("reads;dur="), "{values:?}");
        assert_eq!(values[1], "total;dur=59.0");
    }
}
