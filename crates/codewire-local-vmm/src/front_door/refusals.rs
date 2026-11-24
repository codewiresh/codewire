//! The front door's refusal reports to its runner (#5058), on the control
//! channel it already has: one word, at most once a second, carrying the
//! rows its fold changed since the last. A row is a host of the front door's
//! own route table, a port, a [`RefusalCode`] and a count, and nothing else:
//! no method, path, query, header, body, credential, placeholder or text of
//! the answer can travel in it.
//!
//! The front door terminates the guest's traffic, so the runner reads the
//! word as untrusted ([`decode_report`]): every length is bounded, every
//! field is checked, and anything else rejects the whole word.
//!
//! Word: [`FRONT_DOOR_REFUSALS_PREFIX`], then the rows the front door's fold
//! dropped (big-endian `u16`, saturated), the row count (`u8`, at most
//! [`MAX_FRONT_DOOR_REPORT_ROWS`]) and each row: the host's length (`u8`, 1
//! to 253) and its bytes, the port (`u16`, never 0), the code's index in
//! [`RefusalCode::ALL`] (`u8`) and the count (`u64`, never 0).

use std::sync::Arc;

use codewire_access::RefusalCode;
use codewire_egress_broker::refusals::{Fold, FoldBatch};
use codewire_egress_front_door_bridge::RefusalSink;
use codewire_egress_policy::record::{Destination, MAX_RECORDED_NAME_BYTES};

use crate::broker_control::InterceptedRow;

/// The word's first bytes.
pub const FRONT_DOOR_REFUSALS_PREFIX: &[u8] = b"CWFD1 refusals\n";
/// The most rows one word carries, and the most the front door's fold holds.
pub const MAX_FRONT_DOOR_REPORT_ROWS: usize = 128;
/// The longest word: its prefix, counts, and as many of the longest row.
pub const MAX_FRONT_DOOR_REPORT_BYTES: usize =
    FRONT_DOOR_REFUSALS_PREFIX.len() + 3 + MAX_FRONT_DOOR_REPORT_ROWS * (1 + 253 + 2 + 1 + 8);

/// A report as the runner admitted its shape. Its hosts are checked names;
/// whether each is one the runner bound is the runner's own check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontDoorReport {
    pub rows: Vec<InterceptedRow>,
    pub dropped: u64,
}

/// Why the runner rejected a whole word. Carries nothing from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MalformedReport {
    #[error("front door refusal report is truncated or has trailing bytes")]
    Length,
    #[error("front door refusal report has too many rows")]
    Rows,
    #[error("front door refusal report names a host that is not a checked name")]
    Host,
    #[error("front door refusal report has an invalid port, code or count")]
    Field,
}

/// Whether `message` is a refusal report, by its prefix alone.
pub fn is_refusal_report(message: &[u8]) -> bool {
    message.starts_with(FRONT_DOOR_REFUSALS_PREFIX)
}

/// The word for `batch`. A row whose host could not be decoded is left out,
/// which no host of a route table is.
pub fn encode_report(batch: &FoldBatch<RowKey, ()>) -> Vec<u8> {
    let rows: Vec<_> = batch
        .rows
        .iter()
        .filter(|row| (1..=MAX_RECORDED_NAME_BYTES).contains(&row.key.host.len()))
        .take(MAX_FRONT_DOOR_REPORT_ROWS)
        .collect();
    let mut word = FRONT_DOOR_REFUSALS_PREFIX.to_vec();
    word.extend_from_slice(
        &u16::try_from(batch.dropped)
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    word.push(u8::try_from(rows.len()).expect("at most MAX_FRONT_DOOR_REPORT_ROWS rows"));
    for row in rows {
        word.push(u8::try_from(row.key.host.len()).expect("a host of at most 253 bytes"));
        word.extend_from_slice(row.key.host.as_bytes());
        word.extend_from_slice(&row.key.port.to_be_bytes());
        word.push(row.key.code.index());
        word.extend_from_slice(&row.count.to_be_bytes());
    }
    word
}

/// Reads a word strictly: the prefix, every bound and every field, or
/// nothing at all.
pub fn decode_report(message: &[u8]) -> Result<FrontDoorReport, MalformedReport> {
    if message.len() > MAX_FRONT_DOOR_REPORT_BYTES {
        return Err(MalformedReport::Length);
    }
    let mut body = Body(
        message
            .strip_prefix(FRONT_DOOR_REFUSALS_PREFIX)
            .ok_or(MalformedReport::Length)?,
    );
    let dropped = u64::from(u16::from_be_bytes(body.array()?));
    let count = usize::from(body.byte()?);
    if count > MAX_FRONT_DOOR_REPORT_ROWS {
        return Err(MalformedReport::Rows);
    }
    let mut rows = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::from(body.byte()?);
        let host = std::str::from_utf8(body.take(length)?).map_err(|_| MalformedReport::Host)?;
        if Destination::checked_name(host) != Destination::Name(host.to_owned()) {
            return Err(MalformedReport::Host);
        }
        let port = u16::from_be_bytes(body.array()?);
        let code = RefusalCode::at(body.byte()?).ok_or(MalformedReport::Field)?;
        let count = u64::from_be_bytes(body.array()?);
        if port == 0 || count == 0 {
            return Err(MalformedReport::Field);
        }
        rows.push(InterceptedRow {
            host: host.to_owned(),
            port,
            code,
            count,
        });
    }
    if !body.0.is_empty() {
        return Err(MalformedReport::Length);
    }
    Ok(FrontDoorReport { rows, dropped })
}

struct Body<'a>(&'a [u8]);

impl<'a> Body<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], MalformedReport> {
        if self.0.len() < length {
            return Err(MalformedReport::Length);
        }
        let (taken, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(taken)
    }

    fn byte(&mut self) -> Result<u8, MalformedReport> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], MalformedReport> {
        Ok(self
            .take(N)?
            .try_into()
            .expect("take returns exactly the requested length"))
    }
}

/// A front door refusal's key in its fold.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RowKey {
    host: String,
    port: u16,
    code: RefusalCode,
}

/// The front door's refusals, folded until its reporter sends them.
pub struct FrontDoorRefusals(Fold<RowKey, ()>);

impl FrontDoorRefusals {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Fold::new(MAX_FRONT_DOOR_REPORT_ROWS)))
    }

    pub fn fold(&self) -> &Fold<RowKey, ()> {
        &self.0
    }
}

impl RefusalSink for FrontDoorRefusals {
    fn refused(&self, host: &str, port: u16, code: RefusalCode) {
        let key = RowKey {
            host: host.to_owned(),
            port,
            code,
        };
        self.0.add(key, (), |(), ()| {});
    }
}

#[cfg(test)]
mod tests;
