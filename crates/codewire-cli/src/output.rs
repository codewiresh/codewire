//! Shared terminal presentation for ordinary `cw` commands.
//!
//! One renderer decides what a command may draw from the terminal it runs
//! on ([`Capabilities`]), names each status with a glyph that keeps its
//! meaning without colour ([`Style`]), animates only the row doing active
//! work ([`StatusLine`] with [`Spinner`]), writes the durable lifecycle
//! result ([`LifecycleSummary`]) and offers a searchable choice
//! ([`Picker`], [`run_picker`]) or a multi-select checklist ([`Checklist`],
//! [`run_checklist`]) on an interactive terminal.
//!
//! Streams: progress and the interactive widgets draw on stderr; a
//! summary's `render` is the durable result for stdout. Nothing here emits a
//! redraw sequence unless [`Capabilities::live`] is set, and machine (JSON)
//! output receives no progress, escapes or decoration. Every
//! server-provided string passes through the shared control-character
//! sanitizer before it is drawn.

// Phase 2 of the v0.4.0 CLI UX Program wires these primitives into the
// lifecycle, `use`, `upgrade` and inventory commands; until then only tests
// use them.
#![allow(dead_code)]

mod caps;
mod checklist;
mod interactive;
mod keys;
mod picker;
mod spinner;
mod status_line;
mod style;
mod summary;

#[cfg(all(test, unix))]
mod pty_tests;

// The module's API for Phase 2; unused until then, like the items above.
#[allow(unused_imports)]
pub(crate) use self::{
    caps::{Capabilities, Charset, Motion, OutputMode, TerminalFacts},
    checklist::{Checklist, ChecklistItem, ChecklistOutcome, ChecklistStep, run_checklist},
    keys::{Key, decode_keys, needs_more_input},
    picker::{Picker, PickerOutcome, PickerRow, PickerStep, run_picker},
    spinner::{FRAME_INTERVAL, Spinner},
    status_line::StatusLine,
    style::{Role, Status, Style},
    summary::{
        Allocation, LifecycleSummary, MeshPlacement, NetworkRef, Outcome, SourcePlacement,
        SourceRef, VmLocation,
    },
};
