//! Syntax only for storage-origin selections. Resolution belongs to an
//! authenticated placement adapter; a bare name never chooses a default store.

use serde::{Deserialize, Serialize};

use crate::{AccessProfileReference, ProjectError};

/// Storage origin, independent of the environment's execution placement.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StoragePlacement {
    Local,
    Platform,
}

/// A bounded, value-free request to resolve one selection. An absent placement
/// means the caller must prove uniqueness, not silently choose a backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageReference<'a> {
    pub placement: Option<StoragePlacement>,
    pub selector: &'a str,
}

impl<'a> StorageReference<'a> {
    pub fn project(value: &'a str) -> Result<Self, ProjectError> {
        let reference = Self::split(value, "secrets.project")?;
        if !valid_exact_id(reference.selector)
            && (reference.selector.len() > 64
                || reference.selector.contains(['/', ':'])
                || reference.selector == "."
                || reference.selector == "..")
        {
            return Err(invalid("secrets.project"));
        }
        Ok(reference)
    }

    pub fn profile(value: &'a str) -> Result<Self, ProjectError> {
        let reference = Self::split(value, "credentials.profile")?;
        if valid_exact_id(reference.selector) {
            return Ok(reference);
        }
        if reference.selector.contains('/') {
            reference
                .selector
                .parse::<AccessProfileReference>()
                .map_err(|_| invalid("credentials.profile"))?;
        } else {
            codewire_access::AccessProfileName::parse(reference.selector)
                .map_err(|_| invalid("credentials.profile"))?;
        }
        Ok(reference)
    }

    fn split(value: &'a str, field: &'static str) -> Result<Self, ProjectError> {
        if value.is_empty()
            || value.len() > 1024
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(invalid(field));
        }
        let (placement, selector) = if let Some(selector) = value.strip_prefix("local:") {
            (Some(StoragePlacement::Local), selector)
        } else if let Some(selector) = value.strip_prefix("platform:") {
            (Some(StoragePlacement::Platform), selector)
        } else {
            (None, value)
        };
        if selector.is_empty() || selector.trim() != selector {
            return Err(invalid(field));
        }
        Ok(Self {
            placement,
            selector,
        })
    }
}

fn valid_exact_id(selector: &str) -> bool {
    let Some(id) = selector.strip_prefix("id:") else {
        return false;
    };
    id.len() == 36
        && id != "00000000-0000-0000-0000-000000000000"
        && id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
}

fn invalid(field: &'static str) -> ProjectError {
    ProjectError::InvalidField {
        field,
        detail: "expected a name or exact id, optionally qualified with local: or platform:"
            .to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_never_infers_an_execution_placement_or_default_owner() {
        for value in ["work", "user/work", "organization/work"] {
            assert_eq!(StorageReference::profile(value).unwrap().placement, None);
        }
        for (prefix, placement) in [
            ("local", StoragePlacement::Local),
            ("platform", StoragePlacement::Platform),
        ] {
            let value = format!("{prefix}:work");
            let profile = StorageReference::profile(&value).unwrap();
            assert_eq!(profile.placement, Some(placement));
            assert_eq!(profile.selector, "work");
            let project = StorageReference::project(&value).unwrap();
            assert_eq!(project, profile);
        }
    }

    #[test]
    fn exact_ids_are_origin_qualified_without_a_name_fallback() {
        let reference = "platform:id:6bf8d155-e84c-4fc5-b479-b17022fe41dd";
        for parsed in [
            StorageReference::profile(reference),
            StorageReference::project(reference),
        ] {
            let parsed = parsed.unwrap();
            assert_eq!(parsed.placement, Some(StoragePlacement::Platform));
            assert_eq!(parsed.selector, "id:6bf8d155-e84c-4fc5-b479-b17022fe41dd");
        }
    }

    #[test]
    fn invalid_selectors_fail_without_reflecting_input() {
        for value in [
            "",
            "local:",
            "platform:",
            "local: work",
            "platform:work ",
            "unknown:work",
            "platform:local:work",
            "id:not-a-uuid",
            "work\n",
            "id:00000000-0000-0000-0000-000000000000",
            "https://credential-canary.example/",
            "user/../work",
        ] {
            for result in [
                StorageReference::profile(value),
                StorageReference::project(value),
            ] {
                let error = result.unwrap_err().to_string();
                assert!(!error.contains("credential-canary"));
            }
        }
    }
}
