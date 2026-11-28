//! Antigravity Google sign-in pasted code normalization.

use zeroize::Zeroizing;

use super::percent_decode;

const MAX_ANTIGRAVITY_CODE_BYTES: usize = 1024;
const MAX_ANTIGRAVITY_PASTE_BYTES: usize = 4096;

/// Google's raw authorization code or `code#state` from what was pasted, or
/// `None` for any other shape. Accepts a raw code, `code#state`, or an
/// `http(s)` callback URL carrying `code` (and optional `state`).
pub(in crate::commands) fn normalize_antigravity_code(pasted: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(pasted).ok()?.trim();
    if text.is_empty() || text.len() > MAX_ANTIGRAVITY_PASTE_BYTES {
        return None;
    }
    let (code, state) = if is_http_url(text) {
        let query = text
            .split_once('?')?
            .1
            .split('#')
            .next()
            .unwrap_or_default();
        let (mut code, mut state) = (None, None);
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("code", value)) => {
                    if code.is_some() {
                        return None;
                    }
                    code = Some(percent_decode(value)?);
                }
                Some(("state", value)) => {
                    if state.is_some() {
                        return None;
                    }
                    state = Some(percent_decode(value)?);
                }
                _ => {}
            }
        }
        (code?, state)
    } else if let Some((code, state)) = text.split_once('#') {
        (
            Zeroizing::new(code.as_bytes().to_vec()),
            Some(Zeroizing::new(state.as_bytes().to_vec())),
        )
    } else {
        if looks_like_malformed_url(text) {
            return None;
        }
        (Zeroizing::new(text.as_bytes().to_vec()), None)
    };
    if !valid_part(&code) {
        return None;
    }
    match state {
        Some(state) => {
            if !valid_part(&state) {
                return None;
            }
            let mut normalized = Zeroizing::new(Vec::with_capacity(code.len() + 1 + state.len()));
            normalized.extend_from_slice(&code);
            normalized.push(b'#');
            normalized.extend_from_slice(&state);
            Some(normalized)
        }
        None => Some(code),
    }
}

fn valid_part(part: &[u8]) -> bool {
    !part.is_empty()
        && part.len() <= MAX_ANTIGRAVITY_CODE_BYTES
        && part
            .iter()
            .all(|byte| byte.is_ascii_graphic() && *byte != b'#')
}

fn is_http_url(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https://"))
        || bytes
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http://"))
}

fn looks_like_malformed_url(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.contains("://")
        || value.contains('?')
        || bytes
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http:"))
        || bytes
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https:"))
}
