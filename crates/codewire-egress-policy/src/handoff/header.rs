//! The fixed-layout header of one hand-off (see the module table).

use std::net::Ipv4Addr;

use super::{
    HANDOFF_ENVIRONMENT_ID_LEN, HANDOFF_FIXED_LEN, HANDOFF_MAX_ALIASES, HANDOFF_MAX_HOSTNAME_LEN,
    HANDOFF_VERSION, HandoffError,
};

/// One intercepted connection's header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterceptedStreamHeader {
    pub version: u16,
    pub hostname: String,
    pub port: u16,
    pub destination_ip: Ipv4Addr,
    pub stream_id: u64,
    pub environment_id: String,
    /// The other bound names an active lease holds at `destination_ip`,
    /// which the client may equally have asked for.
    pub aliases: Vec<String>,
}

impl InterceptedStreamHeader {
    pub fn encode(&self) -> Result<Vec<u8>, HandoffError> {
        let hostname = self.hostname.as_bytes();
        let environment = self.environment_id.as_bytes();
        if self.version != HANDOFF_VERSION {
            return Err(HandoffError::Version);
        }
        if !valid_hostname(&self.hostname)
            || self.port == 0
            || !valid_environment_id(&self.environment_id)
            || self.aliases.len() > HANDOFF_MAX_ALIASES
            || !self.aliases.iter().all(|alias| valid_hostname(alias))
        {
            return Err(HandoffError::Malformed);
        }
        let mut bytes = Vec::with_capacity(HANDOFF_FIXED_LEN + hostname.len() + environment.len());
        bytes.extend_from_slice(&self.version.to_le_bytes());
        let hostname_len = u16::try_from(hostname.len()).map_err(|_| HandoffError::Malformed)?;
        let environment_len =
            u16::try_from(environment.len()).map_err(|_| HandoffError::Malformed)?;
        bytes.extend_from_slice(&hostname_len.to_le_bytes());
        bytes.extend_from_slice(&self.port.to_le_bytes());
        bytes.extend_from_slice(&self.destination_ip.octets());
        bytes.extend_from_slice(&self.stream_id.to_le_bytes());
        bytes.extend_from_slice(&environment_len.to_le_bytes());
        bytes.extend_from_slice(hostname);
        bytes.extend_from_slice(environment);
        bytes.push(u8::try_from(self.aliases.len()).map_err(|_| HandoffError::Malformed)?);
        for alias in &self.aliases {
            bytes.push(u8::try_from(alias.len()).map_err(|_| HandoffError::Malformed)?);
            bytes.extend_from_slice(alias.as_bytes());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HandoffError> {
        if bytes.len() < HANDOFF_FIXED_LEN {
            return Err(HandoffError::Malformed);
        }
        let u16_at = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        if u16_at(0) != HANDOFF_VERSION {
            return Err(HandoffError::Version);
        }
        let hostname_len = usize::from(u16_at(2));
        let port = u16_at(4);
        let destination = Ipv4Addr::new(bytes[6], bytes[7], bytes[8], bytes[9]);
        let mut stream_id = [0_u8; 8];
        stream_id.copy_from_slice(&bytes[10..18]);
        let environment_len = usize::from(u16_at(18));
        let names_at = HANDOFF_FIXED_LEN + hostname_len + environment_len;
        if hostname_len == 0
            || hostname_len > HANDOFF_MAX_HOSTNAME_LEN
            || environment_len != HANDOFF_ENVIRONMENT_ID_LEN
            || bytes.len() <= names_at
            || port == 0
        {
            return Err(HandoffError::Malformed);
        }
        let hostname = std::str::from_utf8(&bytes[HANDOFF_FIXED_LEN..][..hostname_len])
            .map_err(|_| HandoffError::Malformed)?;
        if !valid_hostname(hostname) {
            return Err(HandoffError::Malformed);
        }
        let environment_id =
            std::str::from_utf8(&bytes[HANDOFF_FIXED_LEN + hostname_len..names_at])
                .map_err(|_| HandoffError::Malformed)?;
        if !valid_environment_id(environment_id) {
            return Err(HandoffError::Malformed);
        }
        let aliases = decode_aliases(&bytes[names_at..])?;
        Ok(Self {
            version: HANDOFF_VERSION,
            hostname: hostname.to_string(),
            port,
            destination_ip: destination,
            stream_id: u64::from_le_bytes(stream_id),
            environment_id: environment_id.to_string(),
            aliases,
        })
    }
}

/// The alias count and the aliases, exactly filling `bytes`.
fn decode_aliases(bytes: &[u8]) -> Result<Vec<String>, HandoffError> {
    let (&count, mut rest) = bytes.split_first().ok_or(HandoffError::Malformed)?;
    if usize::from(count) > HANDOFF_MAX_ALIASES {
        return Err(HandoffError::Malformed);
    }
    let mut aliases = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (&length, after) = rest.split_first().ok_or(HandoffError::Malformed)?;
        let length = usize::from(length);
        if length == 0 || after.len() < length {
            return Err(HandoffError::Malformed);
        }
        let alias = std::str::from_utf8(&after[..length]).map_err(|_| HandoffError::Malformed)?;
        if !valid_hostname(alias) {
            return Err(HandoffError::Malformed);
        }
        aliases.push(alias.to_owned());
        rest = &after[length..];
    }
    if !rest.is_empty() {
        return Err(HandoffError::Malformed);
    }
    Ok(aliases)
}

/// An environment id is a canonical UUID: 36 characters, lowercase hex in
/// 8-4-4-4-12 groups. It reaches logs, so nothing else is accepted.
pub fn valid_environment_id(id: &str) -> bool {
    id.len() == HANDOFF_ENVIRONMENT_ID_LEN
        && id.bytes().enumerate().all(|(at, byte)| match at {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn valid_hostname(hostname: &str) -> bool {
    !hostname.is_empty()
        && hostname.len() <= HANDOFF_MAX_HOSTNAME_LEN
        && hostname
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-.".contains(&byte))
}
