//! Shared seed codec, canonical initramfs writer, and Linux guest helpers for
//! the Codewire-owned microVM spike.

mod newc;
mod seed;

#[cfg(target_os = "linux")]
pub mod guest;

pub use newc::{
    NewcError, canonical_guest_root_newc, canonical_newc, write_canonical_guest_root_initramfs,
    write_canonical_initramfs,
};
pub use seed::{ROOT_DISK_SERIAL, SEED_DISK_SERIAL, SEED_LEN, STATE_DISK_SERIAL, Seed, SeedError};
