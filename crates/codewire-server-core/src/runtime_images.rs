//! The published runtime images every component agrees on.
//!
//! The workspace digest is the published pin in `codewire-workspace-image`,
//! which support-images.yaml proposes after each publication. A deployment
//! pulls it from the repository it configures, and runs the support (daemon)
//! image it configures; orchestration reads both (docs/CONFIGURATION.md).

pub use codewire_workspace_image as workspace_image;

/// The workspace image at its public mirror: what cw and the dashboard send
/// as their default and what local environments pull. Orchestration resolves
/// it to the same digest at the deployment's configured repository.
pub const PUBLIC_WORKSPACE_IMAGE: &str = codewire_workspace_image::PUBLIC_IMAGE;
