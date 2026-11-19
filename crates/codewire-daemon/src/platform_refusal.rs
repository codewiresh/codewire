//! A broker-mode daemon's refusal of a platform input that arrives after it
//! serves, such as a direct UDP endpoint that is a name rather than an
//! address (#4000). The tailnet refuses it and keeps retrying; GetHealth
//! shows the refusal, by its fixed class, for as long as it lasts, so it is
//! never only a log line.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use codewire_daemon_proto::daemon::v1;

/// The current refusal, shared by the tailnet that sets it and the health
/// that reports it.
#[derive(Clone, Default)]
pub struct PlatformRefusal(Arc<Mutex<Option<Refused>>>);

struct Refused {
    class: &'static str,
    message: String,
}

impl PlatformRefusal {
    /// Report `class`, a fixed name, with `message` until [`Self::clear`].
    pub fn refuse(&self, class: &'static str, message: impl Into<String>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(Refused {
            class,
            message: message.into(),
        });
    }

    /// The fixed class of the refusal reported now, if any.
    pub fn class(&self) -> Option<&'static str> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|refused| refused.class)
    }

    pub fn clear(&self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    pub(crate) fn diagnostic(&self) -> Option<v1::HealthDiagnostic> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|refused| v1::HealthDiagnostic {
                name: "platform".into(),
                healthy: false,
                message: format!("{}: {}", refused.class, refused.message),
            })
    }
}

impl fmt::Debug for PlatformRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PlatformRefusal")
            .field(&self.diagnostic())
            .finish()
    }
}

/// Two handles are equal when they report the same refusal now, so a
/// runtime state compares by what its health would say: two daemons with no
/// refusal are equal, whichever handle each holds.
impl PartialEq for PlatformRefusal {
    fn eq(&self, other: &Self) -> bool {
        // One lock at a time: the two may be the same handle.
        let ours = self.diagnostic();
        ours == other.diagnostic()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_reported_by_its_class_until_cleared() {
        let refusal = PlatformRefusal::default();
        assert_eq!(refusal.diagnostic(), None);
        let tailnet = refusal.clone();
        tailnet.refuse("broker_endpoint_not_literal", "endpoint \"udp.example\"");
        let diagnostic = refusal.diagnostic().unwrap();
        assert_eq!(diagnostic.name, "platform");
        assert!(!diagnostic.healthy);
        assert_eq!(
            diagnostic.message,
            "broker_endpoint_not_literal: endpoint \"udp.example\""
        );
        tailnet.clear();
        assert_eq!(refusal.diagnostic(), None);
    }

    /// The daemon's runtime state holds a handle and is compared whole (the
    /// test harness checks a state is the plain ready one), so equality is
    /// by what is reported, not by which handle it is.
    #[test]
    fn handles_are_equal_when_they_report_the_same_refusal() {
        let one = PlatformRefusal::default();
        let other = PlatformRefusal::default();
        assert_eq!(one, other);
        assert_eq!(
            crate::service::DaemonRuntimeState::ready(),
            crate::service::DaemonRuntimeState::ready()
        );
        one.refuse("broker_no_deployment_relay", "no relay");
        assert_ne!(one, other);
        assert_eq!(one, one.clone());
        other.refuse("broker_no_deployment_relay", "no relay");
        assert_eq!(one, other);
    }
}
