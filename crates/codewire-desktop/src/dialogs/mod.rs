//! Native desktop dialogs.

mod login;
mod unavailable;

pub use login::LoginDialog;
pub use unavailable::{UnavailableDialog, UnavailableDialogDismissed};
