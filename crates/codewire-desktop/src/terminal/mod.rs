//! Terminal integration using alacritty_terminal
//!
//! This module provides:
//! - Terminal rendering using alacritty_terminal
//! - SSH shell spawn with session attachment
//! - Full keyboard passthrough

pub mod backend;
mod view;

pub use view::TerminalView;
