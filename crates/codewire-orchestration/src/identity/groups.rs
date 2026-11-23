//! Identity groups and the other names a registration holds
//! (docs/dev/SANDBOX-IDENTITY.md, "Groups" and "Audiences").
//!
//! Groups are stored bare. A token names `<org id>:all`, then
//! `<org id>:<group>` for each group the audience may see, so `all` is no
//! group's name.

use std::time::Duration;

/// The most groups one Sandbox holds.
pub const MAX_GROUPS: usize = 32;
/// The longest group or file name.
pub const MAX_NAME_LENGTH: usize = 63;
/// Every token's group; no group may take its name.
pub const RESERVED_GROUP: &str = "all";
/// A registration's lifetime when it names none, and the longest it may name.
pub const MAX_LIFETIME: Duration = Duration::from_secs(600);
/// The shortest lifetime a registration may name.
pub const MIN_LIFETIME: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GroupError {
    #[error("group name {0:?} is not 1 to {MAX_NAME_LENGTH} lowercase letters, digits and hyphens")]
    InvalidName(String),
    #[error("group name `all` is reserved: every token carries it")]
    Reserved,
    #[error("a Sandbox has at most {MAX_GROUPS} groups")]
    TooMany,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistrationError {
    #[error("a lifetime is whole seconds from 1 to 10 minutes")]
    InvalidLifetime,
    #[error("file name {0:?} is not 1 to {MAX_NAME_LENGTH} lowercase letters, digits and hyphens")]
    InvalidFileName(String),
}

/// 1 to 63 of `[a-z0-9-]`.
fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME_LENGTH).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// A group's bare name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupName(String);

impl GroupName {
    pub fn parse(name: &str) -> Result<Self, GroupError> {
        if !valid_name(name) {
            return Err(GroupError::InvalidName(name.to_owned()));
        }
        if name == RESERVED_GROUP {
            return Err(GroupError::Reserved);
        }
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A set of groups: sorted, each once, and at most [`MAX_GROUPS`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupSet(Vec<GroupName>);

impl GroupSet {
    pub fn parse<S: AsRef<str>>(names: &[S]) -> Result<Self, GroupError> {
        let mut groups = names
            .iter()
            .map(|name| GroupName::parse(name.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        groups.sort();
        groups.dedup();
        if groups.len() > MAX_GROUPS {
            return Err(GroupError::TooMany);
        }
        Ok(Self(groups))
    }

    pub fn names(&self) -> Vec<String> {
        self.0.iter().map(|name| name.0.clone()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The groups an audience may see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VisibleGroups {
    All,
    /// Only these; empty sees none but `all`.
    Only(GroupSet),
}

/// A registration's token lifetime: whole seconds from one to ten minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudienceLifetime(u16);

impl AudienceLifetime {
    pub const DEFAULT: Self = Self(600);

    pub fn parse(lifetime: Duration) -> Result<Self, RegistrationError> {
        if lifetime.subsec_nanos() != 0 || !(MIN_LIFETIME..=MAX_LIFETIME).contains(&lifetime) {
            return Err(RegistrationError::InvalidLifetime);
        }
        u16::try_from(lifetime.as_secs())
            .map(Self)
            .map_err(|_| RegistrationError::InvalidLifetime)
    }

    pub fn seconds(self) -> u16 {
        self.0
    }
}

/// The name of an audience's projected file, `<name>.jwt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedFileName(String);

impl ProjectedFileName {
    pub fn parse(name: &str) -> Result<Self, RegistrationError> {
        if !valid_name(name) {
            return Err(RegistrationError::InvalidFileName(name.to_owned()));
        }
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_names_are_lowercase_letters_digits_and_hyphens_up_to_63() {
        for name in ["a", "data-readers", "x9", "-", &"a".repeat(63)] {
            assert_eq!(GroupName::parse(name).unwrap().as_str(), name);
        }
        for name in [
            "",
            "Data",
            "data_readers",
            "data.readers",
            "dätä",
            "a b",
            &"a".repeat(64),
        ] {
            assert_eq!(
                GroupName::parse(name),
                Err(GroupError::InvalidName(name.to_owned())),
                "{name:?}"
            );
        }
        assert_eq!(GroupName::parse("all"), Err(GroupError::Reserved));
    }

    #[test]
    fn a_set_is_sorted_once_each_and_at_most_32() {
        let set = GroupSet::parse(&["b", "a", "b"]).unwrap();
        assert_eq!(set.names(), ["a", "b"]);
        assert!(GroupSet::parse::<&str>(&[]).unwrap().is_empty());

        let most: Vec<String> = (0..32).map(|index| format!("g{index}")).collect();
        assert_eq!(GroupSet::parse(&most).unwrap().names().len(), 32);
        let mut too_many = most.clone();
        too_many.push("g32".to_owned());
        assert_eq!(GroupSet::parse(&too_many), Err(GroupError::TooMany));
        // A repeat isn't a 33rd group.
        let mut repeated = most;
        repeated.push("g0".to_owned());
        assert_eq!(GroupSet::parse(&repeated).unwrap().names().len(), 32);
        assert_eq!(GroupSet::parse(&["ok", "all"]), Err(GroupError::Reserved));
    }

    #[test]
    fn a_lifetime_is_whole_seconds_from_one_to_ten_minutes() {
        assert_eq!(AudienceLifetime::DEFAULT.seconds(), 600);
        for seconds in [60, 61, 300, 600] {
            assert_eq!(
                AudienceLifetime::parse(Duration::from_secs(seconds))
                    .unwrap()
                    .seconds(),
                u16::try_from(seconds).unwrap()
            );
        }
        for lifetime in [
            Duration::ZERO,
            Duration::from_secs(59),
            Duration::from_secs(601),
            Duration::from_secs(3600),
            Duration::from_millis(60_500),
        ] {
            assert_eq!(
                AudienceLifetime::parse(lifetime),
                Err(RegistrationError::InvalidLifetime),
                "{lifetime:?}"
            );
        }
    }

    #[test]
    fn a_file_name_is_a_name_and_never_a_path() {
        assert_eq!(ProjectedFileName::parse("k8s").unwrap().as_str(), "k8s");
        for name in ["", "../x", "a/b", ".", "K8S", "a.jwt", &"a".repeat(64)] {
            assert_eq!(
                ProjectedFileName::parse(name),
                Err(RegistrationError::InvalidFileName(name.to_owned())),
                "{name:?}"
            );
        }
    }
}
