//! How a text result names an environment. Moved out of `environment.rs`
//! unchanged.

use super::*;

/// The environment as a text result names it, read once.
#[derive(Clone, Debug, Default)]
pub(super) struct Shown {
    pub(super) name: String,
    /// The host it runs on, when it runs on one (#3609).
    pub(super) host: Option<String>,
}

/// The environment's name and host for a text result, read once; scripts
/// (machine output) and a failed read keep the reference they gave.
pub(super) async fn display_name_for(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
    environment_ref: &str,
    caps: &crate::output::Capabilities,
) -> Shown {
    let given = || Shown {
        name: environment_ref.to_owned(),
        host: None,
    };
    if caps.is_machine() {
        return given();
    }
    client
        .get_environment(org_id, environment_id)
        .await
        .map(|environment| Shown {
            name: lifecycle::display_name(&environment),
            host: environment.host.map(|host| host.name),
        })
        .unwrap_or_else(|_| given())
}
