//! The keys `cw attach` reads for itself: Ctrl-B, then a key that moves
//! between sessions or environments, restarts or detaches. Every other key
//! goes to the session.
//!
//! A program that turns on the kitty keyboard protocol (Codex, neovim, helix,
//! fish 4) makes the terminal send Ctrl-B as `CSI 98;5u` and its release as
//! `CSI 98;5:3u`, not as 0x02 (#5102). Both forms start the prefix; a
//! release is dropped.

use super::AttachExit;

/// Ctrl-B as a terminal sends it without the kitty keyboard protocol.
const CTRL_B: u8 = 0x02;

/// The longest kitty key sequence read as one, ESC to `u`.
const MAX_KEY_SEQUENCE: usize = 32;

#[derive(Default)]
pub(crate) struct AttachNavigationDecoder {
    /// The Ctrl-B waiting for its key, as it arrived (0x02 or a kitty
    /// sequence), so a prefix that isn't used reaches the session unchanged.
    pending_prefix: Option<Vec<u8>>,
    /// Every key goes to the session, Ctrl-B included: a plain `cw shell`.
    plain: bool,
}

impl AttachNavigationDecoder {
    pub(crate) fn new(plain: bool) -> Self {
        Self {
            plain,
            ..Self::default()
        }
    }

    pub(crate) fn feed(&mut self, input: &[u8]) -> (Option<AttachExit>, Vec<u8>) {
        if self.plain {
            return (None, input.to_vec());
        }
        let mut forward = Vec::with_capacity(input.len());
        let mut at = 0;
        while at < input.len() {
            // A terminal writes one key event in one write, so a kitty
            // sequence split across reads isn't put back together; its bytes
            // pass through as they are.
            if let Some((length, key)) = kitty_key(&input[at..]) {
                let sequence = &input[at..at + length];
                at += length;
                match key {
                    // Usually between Ctrl-B and its key; it never ends one.
                    KittyKey::CtrlBRelease => {}
                    KittyKey::CtrlBPress if self.pending_prefix.is_none() => {
                        self.pending_prefix = Some(sequence.to_vec());
                    }
                    KittyKey::CtrlBPress | KittyKey::Other => {
                        if let Some(prefix) = self.pending_prefix.take() {
                            forward.extend_from_slice(&prefix);
                        }
                        forward.extend_from_slice(sequence);
                    }
                }
                continue;
            }
            let byte = input[at];
            at += 1;
            if let Some(prefix) = self.pending_prefix.take() {
                let action = match byte {
                    b'h' => Some(AttachExit::PreviousSession),
                    b'l' => Some(AttachExit::NextSession),
                    b'k' => Some(AttachExit::PreviousEnvironment),
                    b'j' => Some(AttachExit::NextEnvironment),
                    b'w' => Some(AttachExit::OpenWorkspaces),
                    b'r' => Some(AttachExit::Restart),
                    b'd' => Some(AttachExit::Detached),
                    b'b' => {
                        forward.extend_from_slice(&prefix);
                        None
                    }
                    _ => {
                        forward.extend_from_slice(&prefix);
                        forward.push(byte);
                        None
                    }
                };
                if action.is_some() {
                    return (action, forward);
                }
            } else if byte == CTRL_B {
                self.pending_prefix = Some(vec![CTRL_B]);
            } else {
                forward.push(byte);
            }
        }
        (None, forward)
    }

    pub(crate) fn finish(&mut self) -> Vec<u8> {
        self.pending_prefix.take().unwrap_or_default()
    }
}

/// A key in the kitty keyboard protocol's form, as far as attach cares.
#[derive(Debug, PartialEq, Eq)]
enum KittyKey {
    CtrlBPress,
    CtrlBRelease,
    Other,
}

/// The kitty key sequence `CSI key[:alternates] ; modifiers[:event] [; text] u`
/// at the start of `input`, with its length. Anything else, including every
/// other CSI sequence, a mouse report and bracketed paste's markers, is not
/// one.
fn kitty_key(input: &[u8]) -> Option<(usize, KittyKey)> {
    if !input.starts_with(b"\x1b[") {
        return None;
    }
    let end = input
        .iter()
        .take(MAX_KEY_SEQUENCE)
        .skip(2)
        .position(|byte| !matches!(byte, b'0'..=b'9' | b':' | b';'))?
        + 2;
    if input[end] != b'u' || end == 2 {
        return None;
    }
    let parameters = std::str::from_utf8(&input[2..end]).ok()?;
    let mut fields = parameters.split(';');
    let key: u32 = fields.next()?.split(':').next()?.parse().ok()?;
    let (modifiers, event) = match fields.next() {
        Some(field) => {
            let mut parts = field.split(':');
            let modifiers: u32 = parts.next()?.parse().ok()?;
            let event: u32 = match parts.next() {
                Some(event) => event.parse().ok()?,
                None => 1,
            };
            (modifiers, event)
        }
        None => (1, 1),
    };
    Some((end + 1, classify(key, modifiers, event)))
}

/// Ctrl alone, with Caps Lock and Num Lock ignored: shift, alt, super, hyper
/// and meta make it another key.
fn classify(key: u32, modifiers: u32, event: u32) -> KittyKey {
    const SHIFT: u32 = 1;
    const ALT: u32 = 2;
    const CTRL: u32 = 4;
    const SUPER: u32 = 8;
    const HYPER: u32 = 16;
    const META: u32 = 32;
    let held = modifiers.saturating_sub(1);
    let ctrl_alone = held & CTRL != 0 && held & (SHIFT | ALT | SUPER | HYPER | META) == 0;
    match (key == u32::from(b'b') && ctrl_alone, event) {
        (true, 1 | 2) => KittyKey::CtrlBPress,
        (true, 3) => KittyKey::CtrlBRelease,
        _ => KittyKey::Other,
    }
}

#[cfg(test)]
mod tests;
