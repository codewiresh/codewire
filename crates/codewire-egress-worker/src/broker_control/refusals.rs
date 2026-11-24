//! The broker's refusal reports to its runner (#5058), the one frame that
//! goes up the control channel besides the policy acknowledgement.
//!
//! A report (`CWRL`) carries the rows that changed since the last one, each
//! with a count delta, and how many rows the broker dropped to stay within
//! its bound. The broker sends at most one a second. A report carries no
//! environment: the runner files every report under the environment it
//! serves, the only one whose broker holds this channel.
//!
//! Frame: magic, version, the body's length (big-endian `u32`, at most
//! [`MAX_REFUSAL_FRAME_BYTES`]), then the body: the dropped count (`u64`),
//! the row count (`u16`, at most [`MAX_REFUSAL_FRAME_ROWS`]) and each row:
//! the destination (0 and a length-prefixed name, 1 and an address, or 2
//! for a withheld name), the address (0 for none, or an address), the
//! transport (0 DNS, 1 TCP, 2 UDP) and its port (0 for DNS only), the
//! reason's index in [`RefusalReason::ALL`], the policy digest and the
//! count (`u64`, never 0). An address is 4 and four bytes or 6 and sixteen.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use codewire_access::RefusalCode;
use codewire_egress_broker::refusals::{RefusalBatch, RefusalFold, RefusedRow};
use codewire_egress_policy::PolicyDigest;
use codewire_egress_policy::lease::RefusalReason;
use codewire_egress_policy::record::{
    Destination, EGRESS_RECORD_LIMIT, EgressObservation, EgressRecord, EgressRecordLog,
    PolicyLabel, RecordOutcome, Transport,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::invalid;

pub(super) const REFUSAL_FRAME_MAGIC: [u8; 4] = *b"CWRL";
const REFUSAL_FRAME_VERSION: u8 = 1;
/// The most rows one report carries: every row the broker's fold holds.
pub const MAX_REFUSAL_FRAME_ROWS: usize = EGRESS_RECORD_LIMIT;
/// The longest body a report has: its counts and as many of the longest
/// row (a 253-byte name and an IPv6 address, 316 bytes) as it may carry.
pub const MAX_REFUSAL_FRAME_BYTES: usize = 320 * 1024;
pub use codewire_egress_broker::refusals::REFUSAL_REPORT_INTERVAL;

pub fn encode_refusal_frame(batch: &RefusalBatch) -> io::Result<Vec<u8>> {
    if batch.rows.len() > MAX_REFUSAL_FRAME_ROWS {
        return Err(invalid("refusal report exceeds its row bound"));
    }
    let mut body = Vec::with_capacity(10 + batch.rows.len() * 64);
    body.extend_from_slice(&batch.dropped.to_be_bytes());
    body.extend_from_slice(
        &u16::try_from(batch.rows.len())
            .map_err(|_| invalid("refusal report exceeds its row bound"))?
            .to_be_bytes(),
    );
    for row in &batch.rows {
        encode_row(row, &mut body)?;
    }
    if body.len() > MAX_REFUSAL_FRAME_BYTES {
        return Err(invalid("refusal report exceeds its byte bound"));
    }
    let mut frame = Vec::with_capacity(9 + body.len());
    frame.extend_from_slice(&REFUSAL_FRAME_MAGIC);
    frame.push(REFUSAL_FRAME_VERSION);
    frame.extend_from_slice(
        &u32::try_from(body.len())
            .map_err(|_| invalid("refusal report exceeds its byte bound"))?
            .to_be_bytes(),
    );
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn encode_row(row: &RefusedRow, body: &mut Vec<u8>) -> io::Result<()> {
    match &row.destination {
        Destination::Name(name) => {
            if Destination::checked_name(name) != row.destination {
                return Err(invalid("refusal report names an unchecked host"));
            }
            body.push(0);
            body.push(u8::try_from(name.len()).map_err(|_| invalid("refused name too long"))?);
            body.extend_from_slice(name.as_bytes());
        }
        Destination::Address(address) => {
            body.push(1);
            encode_address(*address, body);
        }
        Destination::Withheld => body.push(2),
    }
    match row.address {
        None => body.push(0),
        Some(address) => encode_address(address, body),
    }
    let (transport, port) = match row.transport {
        Transport::Dns => (0, 0),
        Transport::Tcp { port } => (1, port),
        Transport::Udp { port } => (2, port),
    };
    body.push(transport);
    body.extend_from_slice(&port.to_be_bytes());
    body.push(reason_index(row.reason));
    body.extend_from_slice(row.policy_digest.as_bytes());
    body.extend_from_slice(&row.count.to_be_bytes());
    Ok(())
}

fn encode_address(address: IpAddr, body: &mut Vec<u8>) {
    match address {
        IpAddr::V4(address) => {
            body.push(4);
            body.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            body.push(6);
            body.extend_from_slice(&address.octets());
        }
    }
}

fn reason_index(reason: RefusalReason) -> u8 {
    RefusalReason::ALL
        .iter()
        .position(|candidate| *candidate == reason)
        .and_then(|index| u8::try_from(index).ok())
        .expect("every reason is in RefusalReason::ALL, which has fewer than 256")
}

/// Reads a report after its magic. A body past its bound is refused before
/// it is read.
pub(super) async fn read_refusal_frame_after_magic<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<RefusalBatch> {
    if reader.read_u8().await? != REFUSAL_FRAME_VERSION {
        return Err(invalid("refusal report has an unknown version"));
    }
    let length = usize::try_from(reader.read_u32().await?)
        .map_err(|_| invalid("refusal report exceeds its byte bound"))?;
    if length > MAX_REFUSAL_FRAME_BYTES {
        return Err(invalid("refusal report exceeds its byte bound"));
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).await?;
    decode_refusal_body(&body)
}

pub fn decode_refusal_body(body: &[u8]) -> io::Result<RefusalBatch> {
    let mut reader = Body(body);
    let dropped = reader.u64()?;
    let rows = usize::from(reader.u16()?);
    if rows > MAX_REFUSAL_FRAME_ROWS {
        return Err(invalid("refusal report exceeds its row bound"));
    }
    let mut batch = RefusalBatch {
        rows: Vec::with_capacity(rows),
        dropped,
    };
    for _ in 0..rows {
        batch.rows.push(decode_row(&mut reader)?);
    }
    if !reader.0.is_empty() {
        return Err(invalid("refusal report has trailing bytes"));
    }
    Ok(batch)
}

fn decode_row(reader: &mut Body<'_>) -> io::Result<RefusedRow> {
    let destination = match reader.byte()? {
        0 => {
            let length = usize::from(reader.byte()?);
            let name = std::str::from_utf8(reader.take(length)?)
                .map_err(|_| invalid("refused name is not text"))?;
            let checked = Destination::checked_name(name);
            // Only checked, canonical names travel; anything else was not
            // the broker's.
            if checked != Destination::Name(name.to_owned()) {
                return Err(invalid("refused name is not a checked host"));
            }
            checked
        }
        1 => Destination::Address(decode_address(reader)?),
        2 => Destination::Withheld,
        _ => return Err(invalid("refused destination has an unknown kind")),
    };
    let address = match reader.0.first().copied() {
        Some(0) => {
            reader.byte()?;
            None
        }
        _ => Some(decode_address(reader)?),
    };
    let transport = match (reader.byte()?, reader.u16()?) {
        (0, 0) => Transport::Dns,
        (1, port) if port != 0 => Transport::Tcp { port },
        (2, port) if port != 0 => Transport::Udp { port },
        _ => return Err(invalid("refused transport is invalid")),
    };
    let reason = *RefusalReason::ALL
        .get(usize::from(reader.byte()?))
        .ok_or_else(|| invalid("refusal reason is unknown"))?;
    let policy_digest = PolicyDigest::from_bytes(
        reader
            .take(32)?
            .try_into()
            .expect("take returns exactly the requested length"),
    );
    let count = reader.u64()?;
    if count == 0 {
        return Err(invalid("refused row has no refusals"));
    }
    Ok(RefusedRow {
        destination,
        address,
        transport,
        reason,
        policy_digest,
        count,
    })
}

fn decode_address(reader: &mut Body<'_>) -> io::Result<IpAddr> {
    match reader.byte()? {
        4 => {
            let octets: [u8; 4] = reader
                .take(4)?
                .try_into()
                .expect("take returns exactly the requested length");
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        6 => {
            let octets: [u8; 16] = reader
                .take(16)?
                .try_into()
                .expect("take returns exactly the requested length");
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(invalid("refused address has an unknown family")),
    }
}

struct Body<'a>(&'a [u8]);

impl<'a> Body<'a> {
    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        if self.0.len() < length {
            return Err(invalid("refusal report is truncated"));
        }
        let (taken, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(taken)
    }

    fn byte(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .expect("take returns exactly the requested length"),
        ))
    }

    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .expect("take returns exactly the requested length"),
        ))
    }
}

/// The broker's reporter: each time a refusal is folded, send everything
/// folded since the last report, at most once a second
/// ([`codewire_egress_broker::refusals::report_folded`]). It ends when the
/// channel fails.
pub async fn report_refusals<W: AsyncWrite + Unpin>(
    fold: &RefusalFold,
    writer: &tokio::sync::Mutex<W>,
) -> io::Result<()> {
    codewire_egress_broker::refusals::report_folded(fold.fold(), |batch| async move {
        let frame = encode_refusal_frame(&RefusalBatch::from(batch))?;
        let mut writer = writer.lock().await;
        writer.write_all(&frame).await?;
        writer.flush().await
    })
    .await
}

/// The most rows an intercepted host's front door may hold in the log
/// (#5058): its rows never grow past this, and never evict the egress
/// broker's.
pub const INTERCEPTED_ROW_LIMIT: usize = 128;

/// Why a row of the merged log was refused, by its source: the egress
/// broker's raw reason, or the code an intercepted host's front door
/// answered with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LoggedRefusal {
    Network(RefusalReason),
    Intercepted(RefusalCode),
}

impl RecordOutcome for LoggedRefusal {
    fn is_pass(self) -> bool {
        false
    }
}

/// One row of a front door's report, as the runner admitted it: a host on
/// the routes it bound for this boot, its port, a code and a count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterceptedRow {
    pub host: String,
    pub port: u16,
    pub code: RefusalCode,
    pub count: u64,
}

/// One environment's refusals for this run of its VM, as its runner keeps
/// them from its egress broker's and its front door's reports: in memory
/// only, bounded at [`EGRESS_RECORD_LIMIT`] rows with the least recently
/// seen dropped.
#[derive(Debug)]
pub struct RunnerRefusalLog {
    inner: Mutex<LogInner>,
}

#[derive(Debug)]
struct LogInner {
    log: EgressRecordLog<LoggedRefusal>,
    /// The policies the runner sent the broker, by digest.
    labels: HashMap<PolicyDigest, (String, u64)>,
    /// The policy of the allowed hosts the supervisor last sent the
    /// credential authority, as it told the runner: the only label an
    /// intercepted host's `name_not_allowed` row takes.
    intercepted_label: Option<(String, u64)>,
    started_unix_ms: u64,
    dropped_by_reporters: u64,
    rejected: u64,
    refused: u64,
    last_unix_ms: Option<u64>,
}

/// What the log holds when it is read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusalLogSnapshot {
    /// The most recently seen first. The egress broker's are labelled with
    /// the policy the runner sent for their digest, a digest it sent none
    /// for with an empty name; an intercepted host's `name_not_allowed`
    /// with the supervisor's label, and every other one with none.
    pub records: Vec<EgressRecord<LoggedRefusal>>,
    /// Rows dropped, by a reporter's fold or by this log, to stay within
    /// their bounds.
    pub dropped: u64,
    /// The front door's reports and rows the runner rejected.
    pub rejected: u64,
    pub started_unix_ms: u64,
    /// Every refusal reported since the VM started, dropped rows included.
    pub refused: u64,
    pub last_unix_ms: Option<u64>,
}

impl RunnerRefusalLog {
    pub fn new(started_unix_ms: u64) -> Self {
        Self {
            inner: Mutex::new(LogInner {
                log: EgressRecordLog::with_policy(unlabelled(PolicyDigest::from_bytes([0; 32]))),
                labels: HashMap::new(),
                intercepted_label: None,
                started_unix_ms,
                dropped_by_reporters: 0,
                rejected: 0,
                refused: 0,
                last_unix_ms: None,
            }),
        }
    }

    /// Names the policy the runner sent the broker as `digest`. Rows show it
    /// from now on, those already filed under the digest included.
    pub fn label(&self, digest: PolicyDigest, name: String, revision: u64) {
        self.lock().labels.insert(digest, (name, revision));
    }

    /// Names the policy of the allowed hosts the supervisor sent the
    /// credential authority: an intercepted host's `name_not_allowed` filed
    /// from now on carries it.
    pub fn label_intercepted(&self, name: String, revision: u64) {
        self.lock().intercepted_label = Some((name, revision));
    }

    /// Files one report at `now_unix_ms`, the runner's clock when it
    /// arrived: every row's first and last seen.
    pub fn file(&self, batch: RefusalBatch, now_unix_ms: u64) {
        let mut inner = self.lock();
        inner.dropped_by_reporters = inner.dropped_by_reporters.saturating_add(batch.dropped);
        for row in batch.rows {
            inner.refused = inner.refused.saturating_add(row.count);
            inner.last_unix_ms = Some(now_unix_ms);
            inner.log.fold(
                EgressObservation {
                    destination: row.destination,
                    address: row.address,
                    transport: row.transport,
                    outcome: LoggedRefusal::Network(row.reason),
                },
                unlabelled(row.policy_digest),
                row.count,
                now_unix_ms,
            );
        }
    }

    /// Files a front door's admitted rows at `now_unix_ms`. A row that would
    /// take the front door past [`INTERCEPTED_ROW_LIMIT`] rows, or need a
    /// row dropped from a full log, is rejected and counted instead: the
    /// front door's rows never evict the egress broker's.
    pub fn file_intercepted(&self, rows: Vec<InterceptedRow>, dropped: u64, now_unix_ms: u64) {
        let mut inner = self.lock();
        inner.dropped_by_reporters = inner.dropped_by_reporters.saturating_add(dropped);
        for row in rows {
            let destination = Destination::Name(row.host);
            let transport = Transport::Tcp { port: row.port };
            let outcome = LoggedRefusal::Intercepted(row.code);
            if !inner.log.holds(&destination, transport, outcome)
                && (inner.log.len() >= EGRESS_RECORD_LIMIT
                    || inner
                        .log
                        .count_where(|held| matches!(held, LoggedRefusal::Intercepted(_)))
                        >= INTERCEPTED_ROW_LIMIT)
            {
                inner.rejected = inner.rejected.saturating_add(1);
                continue;
            }
            let label = match (row.code, &inner.intercepted_label) {
                (RefusalCode::NameNotAllowed, Some((name, revision))) => PolicyLabel {
                    name: name.clone(),
                    revision: *revision,
                    digest: PolicyDigest::from_bytes([0; 32]),
                },
                _ => unlabelled(PolicyDigest::from_bytes([0; 32])),
            };
            inner.refused = inner.refused.saturating_add(row.count);
            inner.last_unix_ms = Some(now_unix_ms);
            inner.log.fold(
                EgressObservation {
                    destination,
                    address: None,
                    transport,
                    outcome,
                },
                label,
                row.count,
                now_unix_ms,
            );
        }
    }

    /// Counts `count` of the front door's reports or rows as rejected.
    pub fn reject(&self, count: u64) {
        let mut inner = self.lock();
        inner.rejected = inner.rejected.saturating_add(count);
    }

    pub fn snapshot(&self) -> RefusalLogSnapshot {
        let inner = self.lock();
        let records = inner
            .log
            .list(EGRESS_RECORD_LIMIT)
            .into_iter()
            .map(|mut record| {
                if let (LoggedRefusal::Network(_), Some((name, revision))) =
                    (record.outcome, inner.labels.get(&record.policy.digest))
                {
                    record.policy.name.clone_from(name);
                    record.policy.revision = *revision;
                }
                record
            })
            .collect();
        RefusalLogSnapshot {
            records,
            dropped: inner
                .log
                .dropped()
                .saturating_add(inner.dropped_by_reporters),
            rejected: inner.rejected,
            started_unix_ms: inner.started_unix_ms,
            refused: inner.refused,
            last_unix_ms: inner.last_unix_ms,
        }
    }

    /// The log stays consistent if a holder panicked: every change is one
    /// fold plus counters.
    fn lock(&self) -> MutexGuard<'_, LogInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn unlabelled(digest: PolicyDigest) -> PolicyLabel {
    PolicyLabel {
        name: String::new(),
        revision: 0,
        digest,
    }
}

/// The runner's wall clock, in milliseconds since the epoch.
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
