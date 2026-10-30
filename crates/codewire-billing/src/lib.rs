//! Codewire billing service.
//!
//! This crate owns the billing Connect surface, Stripe webhook and checkout
//! behavior, catalog, metering, email, and Temporal billing work.
//! Rust-owned listener contracts and service integration are its correctness
//! authority.

pub mod billing_teardown;
pub mod catalog;
pub mod catalog_admin;
pub mod checkout_sessions;
pub mod connect;
pub mod credit;
pub mod email;
pub mod metering;
pub mod overview;
pub mod stripe_client;
pub mod stripe_endpoint_check;
pub mod subscription_migration;
pub mod temporal;
pub mod webhook;

pub mod org_billing;
pub mod plans;
pub mod routes;

pub use routes::router;
