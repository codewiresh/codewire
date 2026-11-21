//! A broker-mode daemon's refusal of a platform input that arrives after it
//! serves, such as a direct UDP endpoint that is a name rather than an
//! address (#4000). The tailnet refuses it and keeps retrying; GetHealth
//! shows the refusal, by its fixed class, for as long as it lasts, so it is
//! never only a log line.
//!
//! The egress loop reports its own the same way: cw-egress refusing the
//! daemon's session version. Each source holds its own refusal, so the
//! tailnet coming up never clears the egress loop's, nor the reverse.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use codewire_daemon_proto::daemon::v1;

/// The current refusals, shared by the sources that set them and the health
/// that reports them. A handle sets and clears its own source's only.
#[derive(Clone, Default)]
pub struct PlatformRefusal {
    refused: Arc<Mutex<[Option<Refused>; 2]>>,
    source: Source,
}

/// Who refuses, which is also the health diagnostic's name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Source {
    #[default]
    Tailnet,
    Egress,
}

impl Source {
    const ALL: [Self; 2] = [Self::Tailnet, Self::Egress];

    fn slot(self) -> usize {
        match self {
            Self::Tailnet => 0,
            Self::Egress => 1,
        }
    }

    fn diagnostic_name(self) -> &'static str {
        match self {
            Self::Tailnet => "platform",
            Self::Egress => "egress",
        }
    }
}

struct Refused {
    class: &'static str,
    message: String,
}

impl PlatformRefusal {
    /// The egress loop's handle on the same refusals.
    pub fn egress(&self) -> Self {
        Self {
            refused: Arc::clone(&self.refused),
            source: Source::Egress,
        }
    }

    /// Report `class`, a fixed name, with `message` until [`Self::clear`].
    pub fn refuse(&self, class: &'static str, message: impl Into<String>) {
        self.refused.lock().unwrap_or_else(PoisonError::into_inner)[self.source.slot()] =
            Some(Refused {
                class,
                message: message.into(),
            });
    }

    /// The fixed class of the refusal this source reports now, if any.
    pub fn class(&self) -> Option<&'static str> {
        self.refused.lock().unwrap_or_else(PoisonError::into_inner)[self.source.slot()]
            .as_ref()
            .map(|refused| refused.class)
    }

    /// Clear this source's refusal.
    pub fn clear(&self) {
        self.refused.lock().unwrap_or_else(PoisonError::into_inner)[self.source.slot()] = None;
    }

    /// Every source's refusal, each under its own diagnostic name.
    pub(crate) fn diagnostics(&self) -> Vec<v1::HealthDiagnostic> {
        let refused = self.refused.lock().unwrap_or_else(PoisonError::into_inner);
        Source::ALL
            .into_iter()
            .filter_map(|source| {
                refused[source.slot()]
                    .as_ref()
                    .map(|refused| v1::HealthDiagnostic {
                        name: source.diagnostic_name().into(),
                        healthy: false,
                        message: format!("{}: {}", refused.class, refused.message),
                    })
            })
            .collect()
    }
}

impl fmt::Debug for PlatformRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlatformRefusal")
            .field("source", &self.source)
            .field("refused", &self.diagnostics())
            .finish()
    }
}

/// Two handles are equal when they report the same refusals now, so a
/// runtime state compares by what its health would say: two daemons with no
/// refusal are equal, whichever handle each holds.
impl PartialEq for PlatformRefusal {
    fn eq(&self, other: &Self) -> bool {
        // One lock at a time: the two may share their refusals.
        let ours = self.diagnostics();
        ours == other.diagnostics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_reported_by_its_class_until_cleared() {
        let refusal = PlatformRefusal::default();
        assert_eq!(refusal.diagnostics(), []);
        let tailnet = refusal.clone();
        tailnet.refuse("broker_endpoint_not_literal", "endpoint \"udp.example\"");
        let [diagnostic] = &refusal.diagnostics()[..] else {
            panic!("one refusal is one diagnostic");
        };
        assert_eq!(diagnostic.name, "platform");
        assert!(!diagnostic.healthy);
        assert_eq!(
            diagnostic.message,
            "broker_endpoint_not_literal: endpoint \"udp.example\""
        );
        tailnet.clear();
        assert_eq!(refusal.diagnostics(), []);
    }

    /// The tailnet clears its refusal each time it comes up; that must not
    /// hide an egress refusal that still lasts, nor the reverse.
    #[test]
    fn the_tailnet_and_the_egress_loop_each_report_and_clear_their_own() {
        let tailnet = PlatformRefusal::default();
        let egress = tailnet.egress();
        egress.refuse("egress_version_unsupported", "versions 3 to 4");
        tailnet.refuse("broker_no_deployment_relay", "no relay");
        let names = |refusal: &PlatformRefusal| {
            refusal
                .diagnostics()
                .into_iter()
                .map(|diagnostic| (diagnostic.name, diagnostic.message))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(&tailnet),
            [
                (
                    "platform".to_owned(),
                    "broker_no_deployment_relay: no relay".to_owned()
                ),
                (
                    "egress".to_owned(),
                    "egress_version_unsupported: versions 3 to 4".to_owned()
                ),
            ]
        );
        assert_eq!(tailnet.class(), Some("broker_no_deployment_relay"));
        assert_eq!(egress.class(), Some("egress_version_unsupported"));

        tailnet.clear();
        assert_eq!(tailnet.class(), None);
        assert_eq!(
            names(&egress),
            [(
                "egress".to_owned(),
                "egress_version_unsupported: versions 3 to 4".to_owned()
            )]
        );
        egress.clear();
        assert_eq!(names(&tailnet), []);
    }

    /// The daemon's runtime state holds a handle and is compared whole (the
    /// test harness checks a state is the plain ready one), so equality is
    /// by what is reported, not by which handle it is.
    #[test]
    fn handles_are_equal_when_they_report_the_same_refusals() {
        let one = PlatformRefusal::default();
        let other = PlatformRefusal::default();
        assert_eq!(one, other);
        assert_eq!(
            crate::service::DaemonRuntimeState::ready(),
            crate::service::DaemonRuntimeState::ready()
        );
        one.egress()
            .refuse("egress_version_unsupported", "versions 3 to 4");
        assert_ne!(one, other);
        assert_eq!(one, one.egress());
        other.refuse("egress_version_unsupported", "versions 3 to 4");
        assert_ne!(one, other, "the same class from another source");
        other.clear();
        other
            .egress()
            .refuse("egress_version_unsupported", "versions 3 to 4");
        assert_eq!(one, other);
    }
}
