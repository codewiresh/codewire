//! The closed table behind `cw secrets set --preset NAME`
//! (docs/dev/SECRETS-AND-CREDENTIALS.md, "Presets"): the hosts and the
//! presentation a vendor's API takes its key in. Each row is checked against
//! the vendor's own documentation when it is added. There is no row for a
//! provider Codewire connects as a credential.

use crate::{StoredBinding, StoredPresentation};

/// One vendor's API: where its key is sent and how.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingPreset {
    pub name: &'static str,
    pub hosts: &'static [&'static str],
    pub header: &'static str,
    /// `None` sends the key alone in the header.
    pub scheme: Option<&'static str>,
    /// What the vendor's keys start with, put before the placeholder for a
    /// client that checks a key's shape.
    pub prefix: Option<&'static str>,
}

impl BindingPreset {
    /// The binding this preset fills, naming the preset.
    pub fn binding(&self) -> StoredBinding {
        StoredBinding {
            hosts: self.hosts.iter().map(|host| (*host).to_owned()).collect(),
            presentation: StoredPresentation::Header {
                headers: vec![self.header.to_owned()],
                scheme: self.scheme.map(str::to_owned),
            },
            prefix: self.prefix.map(str::to_owned),
            preset: Some(self.name.to_owned()),
        }
    }
}

/// Every preset, by name.
pub const BINDING_PRESETS: [BindingPreset; 3] = [
    BindingPreset {
        name: "huggingface",
        hosts: &["huggingface.co"],
        header: "Authorization",
        scheme: Some("Bearer"),
        prefix: Some("hf_"),
    },
    // A personal API key is the whole `Authorization` header; an OAuth
    // token, which a preset doesn't cover, takes `Bearer`.
    BindingPreset {
        name: "linear",
        hosts: &["api.linear.app"],
        header: "Authorization",
        scheme: None,
        prefix: None,
    },
    // `Authorization: Bearer` is accepted beside Basic, which Stripe's
    // documentation shows first.
    BindingPreset {
        name: "stripe",
        hosts: &["api.stripe.com"],
        header: "Authorization",
        scheme: Some("Bearer"),
        prefix: None,
    },
];

/// The preset named `name`, exactly.
pub fn binding_preset(name: &str) -> Option<&'static BindingPreset> {
    BINDING_PRESETS.iter().find(|preset| preset.name == name)
}

/// The preset a mistyped `name` most likely meant: the closest within two
/// edits, ignoring case.
pub fn nearest_binding_preset(name: &str) -> Option<&'static BindingPreset> {
    let name = name.to_ascii_lowercase();
    BINDING_PRESETS
        .iter()
        .map(|preset| (edit_distance(&name, preset.name), preset))
        .filter(|(distance, _)| *distance <= 2)
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, preset)| preset)
}

/// Levenshtein distance over bytes; preset names are ASCII.
fn edit_distance(a: &str, b: &str) -> usize {
    let b = b.as_bytes();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for (i, a_byte) in a.bytes().enumerate() {
        let mut current = vec![i + 1];
        for (j, b_byte) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(a_byte != *b_byte);
            current.push(substitution.min(previous[j + 1] + 1).min(current[j] + 1));
        }
        previous = current;
    }
    previous[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReservedHosts;

    /// The table as the design and each vendor's documentation give it.
    #[test]
    fn the_preset_table_is_pinned() {
        let rows: Vec<_> = BINDING_PRESETS
            .iter()
            .map(|preset| {
                (
                    preset.name,
                    preset.hosts,
                    preset.header,
                    preset.scheme,
                    preset.prefix,
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                (
                    "huggingface",
                    &["huggingface.co"][..],
                    "Authorization",
                    Some("Bearer"),
                    Some("hf_"),
                ),
                (
                    "linear",
                    &["api.linear.app"][..],
                    "Authorization",
                    None,
                    None
                ),
                (
                    "stripe",
                    &["api.stripe.com"][..],
                    "Authorization",
                    Some("Bearer"),
                    None,
                ),
            ]
        );
    }

    #[test]
    fn every_preset_fills_a_binding_the_rules_accept_and_names_itself() {
        for preset in &BINDING_PRESETS {
            let stored = preset.binding();
            assert_eq!(stored.preset.as_deref(), Some(preset.name));
            stored
                .parse(&ReservedHosts::default())
                .unwrap_or_else(|error| panic!("{}: {error}", preset.name));
        }
    }

    #[test]
    fn a_preset_is_found_by_its_exact_name_and_a_near_miss_is_suggested() {
        assert_eq!(binding_preset("stripe").map(|p| p.name), Some("stripe"));
        assert_eq!(binding_preset("Stripe"), None);
        assert_eq!(binding_preset("strpe"), None);
        assert_eq!(
            nearest_binding_preset("strpe").map(|p| p.name),
            Some("stripe")
        );
        assert_eq!(
            nearest_binding_preset("Linaer").map(|p| p.name),
            Some("linear")
        );
        assert_eq!(nearest_binding_preset("openai"), None);
    }
}
