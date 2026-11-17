//! An intercepting boot's secrets as the authority carries them (#3999).
//!
//! The runner mints them and the supervisor hands them to the authority in
//! `EnsureEnvironmentBroker`. The authority keeps them in the generation's
//! broker launch, in memory only, and gives them to each broker it starts on
//! an inherited descriptor. They are never stored, logged or echoed in any
//! answer.

use std::fmt;

use tonic::Status;
use zeroize::Zeroizing;

use crate::control::v1;

/// The length of each secret.
pub const BOOT_SECRET_BYTES: usize = 32;
/// The most secrets one boot carries.
const MAX_BOOT_SECRETS: usize = 4;
/// One record on the broker's descriptor: the purpose, then the secret.
const RECORD_BYTES: usize = 1 + BOOT_SECRET_BYTES;
/// The most bytes the broker reads from its descriptor.
pub const MAX_BOOT_SECRET_RECORDS_BYTES: usize = MAX_BOOT_SECRETS * RECORD_BYTES;

/// What a boot secret is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BootSecretPurpose {
    /// Presented on the runner's pairing socket by each of the generation's
    /// credential brokers.
    FrontDoorPairing,
}

impl BootSecretPurpose {
    fn code(self) -> u8 {
        match self {
            Self::FrontDoorPairing => 1,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::FrontDoorPairing),
            _ => None,
        }
    }
}

/// A boot's secrets, each once, by purpose. Empty for a boot that doesn't
/// intercept. `Debug` never prints a value.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BrokerBootSecrets(Vec<(BootSecretPurpose, Zeroizing<[u8; BOOT_SECRET_BYTES]>)>);

impl fmt::Debug for BrokerBootSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_list()
            .entries(self.0.iter().map(|(purpose, _)| purpose))
            .finish()
    }
}

impl BrokerBootSecrets {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The secret for `purpose`, if the boot carries one.
    pub fn get(&self, purpose: BootSecretPurpose) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|(held, _)| *held == purpose)
            .map(|(_, value)| value.as_slice())
    }

    /// Each known purpose at most once, each value exactly
    /// [`BOOT_SECRET_BYTES`]. The error names no value.
    pub fn new(
        secrets: impl IntoIterator<Item = (BootSecretPurpose, Vec<u8>)>,
    ) -> Result<Self, InvalidBootSecrets> {
        let mut held: Vec<(BootSecretPurpose, Zeroizing<[u8; BOOT_SECRET_BYTES]>)> = Vec::new();
        for (purpose, value) in secrets {
            let value = Zeroizing::new(value);
            let Ok(bytes) = <[u8; BOOT_SECRET_BYTES]>::try_from(value.as_slice()) else {
                return Err(InvalidBootSecrets);
            };
            if held.len() == MAX_BOOT_SECRETS || held.iter().any(|(seen, _)| *seen == purpose) {
                return Err(InvalidBootSecrets);
            }
            held.push((purpose, Zeroizing::new(bytes)));
        }
        Ok(Self(held))
    }

    pub(crate) fn from_proto(secrets: Vec<v1::BrokerBootSecret>) -> Result<Self, Status> {
        let secrets = secrets
            .into_iter()
            .map(|secret| {
                let purpose = match v1::BrokerBootSecretPurpose::try_from(secret.purpose) {
                    Ok(v1::BrokerBootSecretPurpose::FrontDoorPairing) => {
                        BootSecretPurpose::FrontDoorPairing
                    }
                    _ => return Err(InvalidBootSecrets),
                };
                Ok((purpose, secret.value))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        Self::new(secrets).map_err(|_| invalid())
    }

    pub(crate) fn to_proto(&self) -> Vec<v1::BrokerBootSecret> {
        self.0
            .iter()
            .map(|(purpose, value)| v1::BrokerBootSecret {
                purpose: match purpose {
                    BootSecretPurpose::FrontDoorPairing => {
                        v1::BrokerBootSecretPurpose::FrontDoorPairing as i32
                    }
                },
                value: value.to_vec(),
            })
            .collect()
    }

    /// The records written to a broker's descriptor.
    pub fn records(&self) -> Zeroizing<Vec<u8>> {
        let mut records = Zeroizing::new(Vec::with_capacity(self.0.len() * RECORD_BYTES));
        for (purpose, value) in &self.0 {
            records.push(purpose.code());
            records.extend_from_slice(value.as_slice());
        }
        records
    }

    /// The secrets a broker read from its descriptor: whole records only, each
    /// a known purpose once.
    pub fn from_records(records: &[u8]) -> Result<Self, InvalidBootSecrets> {
        if !records.len().is_multiple_of(RECORD_BYTES)
            || records.len() > MAX_BOOT_SECRET_RECORDS_BYTES
        {
            return Err(InvalidBootSecrets);
        }
        Self::new(
            records
                .as_chunks::<RECORD_BYTES>()
                .0
                .iter()
                .map(|record| {
                    let purpose =
                        BootSecretPurpose::from_code(record[0]).ok_or(InvalidBootSecrets)?;
                    Ok((purpose, record[1..].to_vec()))
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
}

/// Boot secrets that were malformed. Names nothing about their values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid boot secrets")]
pub struct InvalidBootSecrets;

fn invalid() -> Status {
    Status::invalid_argument("invalid boot secrets")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairing(byte: u8) -> (BootSecretPurpose, Vec<u8>) {
        (
            BootSecretPurpose::FrontDoorPairing,
            vec![byte; BOOT_SECRET_BYTES],
        )
    }

    #[test]
    fn records_round_trip_and_debug_names_no_value() {
        let secrets = BrokerBootSecrets::new([pairing(0xab)]).unwrap();
        let read = BrokerBootSecrets::from_records(&secrets.records()).unwrap();
        assert_eq!(read, secrets);
        assert_eq!(
            read.get(BootSecretPurpose::FrontDoorPairing),
            Some(&[0xab; BOOT_SECRET_BYTES][..])
        );
        let debug = format!("{secrets:?}");
        assert_eq!(debug, "[FrontDoorPairing]");
        assert!(BrokerBootSecrets::default().records().is_empty());
    }

    #[test]
    fn malformed_secrets_are_refused_without_naming_them() {
        for secrets in [
            vec![(BootSecretPurpose::FrontDoorPairing, vec![1; 31])],
            vec![pairing(1), pairing(2)],
        ] {
            assert_eq!(BrokerBootSecrets::new(secrets), Err(InvalidBootSecrets));
        }
        let good = BrokerBootSecrets::new([pairing(7)]).unwrap().records();
        for records in [&good[..good.len() - 1], &[9_u8; RECORD_BYTES][..]] {
            assert_eq!(
                BrokerBootSecrets::from_records(records),
                Err(InvalidBootSecrets)
            );
        }
        let status = BrokerBootSecrets::from_proto(vec![v1::BrokerBootSecret {
            purpose: v1::BrokerBootSecretPurpose::FrontDoorPairing as i32,
            value: vec![7; 5],
        }])
        .unwrap_err();
        assert!(!status.message().contains('\u{7}'));
    }
}
