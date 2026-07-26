//! Storage and persistence for Codewire
//!
//! This module handles:
//! - App settings persistence (generic over PersistentStorage trait)

mod config;

pub use config::ConfigStorage;
