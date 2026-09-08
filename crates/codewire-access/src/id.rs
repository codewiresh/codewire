use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::AccessError;

const MAX_IDENTIFIER_BYTES: usize = 128;

fn validate_identifier(value: &str, field: &'static str) -> Result<(), AccessError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(AccessError::InvalidIdentifier { field });
    }
    Ok(())
}

macro_rules! identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, AccessError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = AccessError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

identifier!(CredentialId, "credential ID");
identifier!(AccessProfileId, "access profile ID");
identifier!(AccessProfileName, "access profile name");
identifier!(EnvironmentId, "environment ID");
identifier!(OwnerId, "owner ID");
identifier!(ProviderId, "provider ID");
identifier!(CapabilitySlot, "capability slot");
identifier!(BrokerOperationId, "broker operation ID");
identifier!(BrokerRouteId, "broker route ID");

impl CapabilitySlot {
    pub fn codex() -> Self {
        Self::parse("codex").expect("canonical Codex capability slot")
    }

    pub fn github() -> Self {
        Self::parse("github").expect("canonical GitHub capability slot")
    }

    pub fn openai() -> Self {
        Self::parse("openai").expect("canonical OpenAI capability slot")
    }

    pub fn anthropic() -> Self {
        Self::parse("anthropic").expect("canonical Anthropic capability slot")
    }

    pub fn git_ssh() -> Self {
        Self::parse("git_ssh").expect("canonical Git SSH capability slot")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AccessProfileScope {
    User,
    Organization,
}

/// Scope-qualified logical profile selector used by `codewire.yaml` and CLI
/// adapters. It contains no placement record ID.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccessProfileReference {
    scope: AccessProfileScope,
    name: AccessProfileName,
}

impl AccessProfileReference {
    pub fn new(scope: AccessProfileScope, name: AccessProfileName) -> Self {
        Self { scope, name }
    }

    pub fn scope(&self) -> AccessProfileScope {
        self.scope
    }

    pub fn name(&self) -> &AccessProfileName {
        &self.name
    }
}

impl fmt::Display for AccessProfileReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scope = match self.scope {
            AccessProfileScope::User => "user",
            AccessProfileScope::Organization => "organization",
        };
        write!(formatter, "{scope}/{}", self.name)
    }
}

impl FromStr for AccessProfileReference {
    type Err = AccessError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (scope, name) = value
            .split_once('/')
            .ok_or(AccessError::InvalidProfileReference)?;
        if name.contains('/') {
            return Err(AccessError::InvalidProfileReference);
        }
        let scope = match scope {
            "user" => AccessProfileScope::User,
            "organization" => AccessProfileScope::Organization,
            _ => return Err(AccessError::InvalidProfileReference),
        };
        let name =
            AccessProfileName::parse(name).map_err(|_| AccessError::InvalidProfileReference)?;
        Ok(Self { scope, name })
    }
}

impl Serialize for AccessProfileReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AccessProfileReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}
