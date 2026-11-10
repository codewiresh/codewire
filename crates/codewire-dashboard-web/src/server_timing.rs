//! A `Server-Timing` header for pages whose upstream reads are worth seeing in
//! the browser's network panel. Each mark records the time since the previous
//! one in milliseconds under a fixed name; no request data enters the header.

use std::time::Instant;

use axum::{
    http::{HeaderName, HeaderValue},
    response::Response,
};

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
            response
                .headers_mut()
                .insert(HeaderName::from_static("server-timing"), value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ServerTiming;

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
}
