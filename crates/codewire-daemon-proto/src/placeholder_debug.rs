//! `Debug` for a projected placeholder, whose `placeholder` is marked
//! `debug_redact`, which prost's derived `Debug` ignores. build.rs names it in
//! `skip_debug`.

use std::fmt;

use crate::codewire::bridge::v1::CredentialBridgePlaceholder;

impl fmt::Debug for CredentialBridgePlaceholder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialBridgePlaceholder")
            .field("capability_slot", &self.capability_slot)
            .field("placeholder", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::codewire::bridge::v1::CredentialBridgeOpen;

    use super::*;

    const MARKER: &str = "cwp1_synthetic-projected-placeholder";

    #[test]
    fn an_open_never_prints_its_placeholders() {
        let open = CredentialBridgeOpen {
            placeholders: vec![CredentialBridgePlaceholder {
                capability_slot: "anthropic".to_owned(),
                placeholder: MARKER.to_owned(),
            }],
            ..Default::default()
        };
        let printed = format!("{open:?}");
        assert!(!printed.contains(MARKER), "prints a placeholder: {printed}");
        assert!(printed.contains("[REDACTED]"), "{printed}");
        assert!(printed.contains("anthropic"), "{printed}");
    }
}
