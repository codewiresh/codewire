//! Where a request on a bound secret's host carries this environment's
//! bound-secret placeholders, and whether that is exactly the binding's
//! shape (#4003; docs/dev/SECRETS-AND-CREDENTIALS.md, "The swap" steps 3 and
//! 4). Nothing here leases, decrypts or sends: the swap asks it twice, once
//! with the grants alone, to know which secret's row to read, and once with
//! that row's binding, to know whether to swap or refuse.
//!
//! A placeholder is not a secret, so finding one anywhere is a plain search;
//! the bound header's exact shape is compared in constant time.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use codewire_access::{HostBinding, OutsideBinding, Presentation, Scheme};
use http::{HeaderMap, HeaderName, header};

use super::super::swap::CREDENTIAL_HEADERS;
use crate::bound_secret::EpochBoundSecret;

/// How much of a body is searched for a placeholder.
pub(super) const SCANNED_BODY_BYTES: usize = 64 * 1024;

/// One place a request carried a grant's placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Found {
    /// The grant's index in the epoch's grants.
    pub(super) secret: usize,
    pub(super) place: Place,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Place {
    Header(HeaderName),
    Query,
    Body,
}

/// The request's parts that are searched.
pub(super) struct Carried<'a> {
    pub(super) headers: &'a HeaderMap,
    pub(super) query: Option<&'a str>,
    pub(super) body: &'a [u8],
}

/// Every place `carried` holds one of `grants`' placeholders, once per
/// header name, query and body: in a header's value, or in what an
/// `Authorization: Basic` value decodes to; in the query string as sent or
/// percent-decoded; and in the first [`SCANNED_BODY_BYTES`] of the body.
pub(super) fn find(carried: &Carried<'_>, grants: &[EpochBoundSecret]) -> Vec<Found> {
    let mut found = Vec::new();
    for (index, grant) in grants.iter().enumerate() {
        let needle = grant.placeholder.as_str().as_bytes();
        let mut names: Vec<&HeaderName> = Vec::new();
        for (name, value) in carried.headers {
            if !names.contains(&name) && header_holds(name, value.as_bytes(), needle) {
                names.push(name);
                found.push(Found {
                    secret: index,
                    place: Place::Header(name.clone()),
                });
            }
        }
        if carried
            .query
            .is_some_and(|query| query_holds(query, needle))
        {
            found.push(Found {
                secret: index,
                place: Place::Query,
            });
        }
        let scanned = &carried.body[..carried.body.len().min(SCANNED_BODY_BYTES)];
        if contains(scanned, needle) {
            found.push(Found {
                secret: index,
                place: Place::Body,
            });
        }
    }
    found
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn header_holds(name: &HeaderName, value: &[u8], needle: &[u8]) -> bool {
    contains(value, needle)
        || (*name == header::AUTHORIZATION
            && basic_credentials(value).is_some_and(|decoded| contains(&decoded, needle)))
}

fn query_holds(query: &str, needle: &[u8]) -> bool {
    contains(query.as_bytes(), needle)
        || url::form_urlencoded::parse(query.as_bytes()).any(|(name, value)| {
            contains(name.as_bytes(), needle) || contains(value.as_bytes(), needle)
        })
}

/// What an `Authorization: Basic` value decodes to.
fn basic_credentials(value: &[u8]) -> Option<Vec<u8>> {
    let (scheme, encoded) = std::str::from_utf8(value).ok()?.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    STANDARD.decode(encoded).ok()
}

/// What the request's placeholders allow before any row is read.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Candidate {
    /// None of this environment's bound-secret placeholders.
    None,
    /// More than one secret's placeholder: `credential_conflict`.
    Conflict,
    /// One secret's, the grant at this index.
    Secret(usize),
}

pub(super) fn candidate(found: &[Found]) -> Candidate {
    let Some(first) = found.first() else {
        return Candidate::None;
    };
    if found.iter().any(|other| other.secret != first.secret) {
        Candidate::Conflict
    } else {
        Candidate::Secret(first.secret)
    }
}

/// What the request gets once its secret's binding is read.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Decision {
    /// Swap the value into each of these headers, each sent exactly once in
    /// the binding's shape.
    Swap(Vec<HeaderName>),
    /// `placeholder_outside_binding`.
    Outside(OutsideBinding),
    /// `credential_conflict`: the bound header twice, as two lines or one
    /// combined list, the placeholder twice in it, or another credential
    /// header beside it.
    Conflict,
}

/// The binding's headers, lowercase.
pub(super) fn bound_headers(binding: &HostBinding) -> Vec<HeaderName> {
    match binding.presentation() {
        Presentation::Header { headers, .. } => headers
            .iter()
            .filter_map(|bound| HeaderName::from_bytes(bound.as_str().as_bytes()).ok())
            .collect(),
        Presentation::Basic { .. } | Presentation::BasicUser => vec![header::AUTHORIZATION],
    }
}

/// Whether `carried`, whose only placeholder is `grant`'s at `found`, holds
/// it exactly as `binding` presents it.
pub(super) fn decide(
    carried: &Carried<'_>,
    found: &[Found],
    grant: &EpochBoundSecret,
    binding: &HostBinding,
) -> Decision {
    let bound = bound_headers(binding);
    for place in found.iter().map(|found| &found.place) {
        match place {
            Place::Query => return Decision::Outside(OutsideBinding::Query),
            Place::Body => return Decision::Outside(OutsideBinding::Body),
            Place::Header(name) if !bound.contains(name) => {
                return Decision::Outside(outside_header(carried.headers, name, grant));
            }
            Place::Header(_) => {}
        }
    }
    let needle = grant.placeholder.as_str().as_bytes();
    let mut swapped = Vec::new();
    for name in &bound {
        let mut lines = carried.headers.get_all(name).iter();
        let Some(line) = lines.next() else {
            continue;
        };
        let value = line.as_bytes();
        if lines.next().is_some()
            || value.contains(&b',')
            || value
                .windows(needle.len())
                .filter(|window| *window == needle)
                .count()
                > 1
        {
            return Decision::Conflict;
        }
        // A bound header without the placeholder holds another credential.
        if !header_holds(name, value, needle) {
            return Decision::Conflict;
        }
        if !exact_shape(value, binding.presentation(), grant) {
            return Decision::Outside(outside_header(carried.headers, name, grant));
        }
        swapped.push(name.clone());
    }
    if CREDENTIAL_HEADERS
        .iter()
        .any(|name| !bound.contains(name) && carried.headers.contains_key(name))
    {
        return Decision::Conflict;
    }
    Decision::Swap(swapped)
}

/// Whether `value` is exactly the presentation's form around the
/// placeholder: `<scheme> <placeholder>` (the scheme's case aside, as RFC
/// 9110 compares it) or the placeholder alone; for `basic`, Basic of any
/// user and the placeholder as the password; for `basic-user`, Basic of the
/// placeholder and an empty password.
fn exact_shape(value: &[u8], presentation: &Presentation, grant: &EpochBoundSecret) -> bool {
    match presentation {
        Presentation::Header {
            scheme: Scheme::None,
            ..
        } => grant.placeholder.ct_eq(value),
        Presentation::Header {
            scheme: Scheme::Word(word),
            ..
        } => value
            .split_at_checked(word.len() + 1)
            .is_some_and(|(prefix, rest)| {
                prefix[..word.len()].eq_ignore_ascii_case(word.as_bytes())
                    && prefix[word.len()] == b' '
                    && grant.placeholder.ct_eq(rest)
            }),
        Presentation::Basic { .. } => basic_credentials(value).is_some_and(|decoded| {
            decoded
                .iter()
                .position(|byte| *byte == b':')
                .is_some_and(|colon| grant.placeholder.ct_eq(&decoded[colon + 1..]))
        }),
        Presentation::BasicUser => basic_credentials(value).is_some_and(|decoded| {
            decoded
                .strip_suffix(b":")
                .is_some_and(|user| grant.placeholder.ct_eq(user))
        }),
    }
}

/// `name` as the place a placeholder was sent outside its binding: with the
/// scheme the request used before it, when the header holds exactly a
/// scheme and the placeholder or the placeholder alone, so the hint can
/// name the command that binds it there.
fn outside_header(
    headers: &HeaderMap,
    name: &HeaderName,
    grant: &EpochBoundSecret,
) -> OutsideBinding {
    let display = display_name(name);
    let mut lines = headers.get_all(name).iter();
    let shape = match (lines.next(), lines.next()) {
        (Some(line), None) => sent_scheme(line.as_bytes(), grant),
        _ => None,
    };
    match shape {
        Some(scheme) if refusable_by_binding(name) => OutsideBinding::Header {
            name: display,
            scheme,
            exact: true,
        },
        _ => OutsideBinding::Header {
            name: display,
            scheme: None,
            exact: false,
        },
    }
}

/// `Some(None)` for the placeholder alone, `Some(Some(word))` for one token
/// and a space before it, `None` for any other shape.
fn sent_scheme(value: &[u8], grant: &EpochBoundSecret) -> Option<Option<String>> {
    if grant.placeholder.ct_eq(value) {
        return Some(None);
    }
    let text = std::str::from_utf8(value).ok()?;
    let (word, rest) = text.split_once(' ')?;
    let token = !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte));
    (token && grant.placeholder.ct_eq(rest.as_bytes())).then(|| Some(word.to_owned()))
}

/// Whether a binding could name `name`: the hint never offers a command the
/// binding's own rules refuse.
fn refusable_by_binding(name: &HeaderName) -> bool {
    codewire_access::BoundHeader::parse(name.as_str()).is_ok()
}

/// A header's name as people write it: each `-`-separated word capitalised.
fn display_name(name: &HeaderName) -> String {
    name.as_str()
        .split('-')
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_ascii_uppercase().to_string() + chars.as_str()
            })
        })
        .collect::<Vec<_>>()
        .join("-")
}
