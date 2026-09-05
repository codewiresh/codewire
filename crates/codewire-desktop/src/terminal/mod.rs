//! Terminal integration using alacritty_terminal
//!
//! This module provides:
//! - Terminal rendering using alacritty_terminal
//! - Local and Codewire environment sessions
//! - Full keyboard passthrough

pub mod backend;
mod view;

pub use view::TerminalView;
