//! What `connect github` says the Codewire GitHub App can reach for this
//! login (#5443).

/// What the Codewire GitHub App can reach for this login, and where to change
/// it. GitHub decides access per installation, not per Codewire credential,
/// and gives a user token only what both the user and the installation can
/// reach. So only the user's own account is named with its installation's
/// selection; any other account's selection is its owner's choice, not this
/// sign-in's reach, and is never shown (#5443). GitHub logins ignore case.
pub(super) fn github_reach_summary(
    verified_login: Option<&str>,
    reach: &[codewire_credential_broker::GitHubAppInstallationReach],
) -> String {
    let (own, others): (Vec<_>, Vec<_>) = reach.iter().partition(|installation| {
        verified_login.is_some_and(|login| installation.account.eq_ignore_ascii_case(login))
    });
    let own = own
        .iter()
        .map(|installation| {
            let scope = if installation.all_repositories {
                "all repositories"
            } else {
                "selected repositories"
            };
            format!("{} ({scope})", installation.account)
        })
        .collect::<Vec<_>>();
    let others = others
        .iter()
        .map(|installation| installation.account.as_str())
        .collect::<Vec<_>>();
    let own = (!own.is_empty()).then(|| format!("repositories of: {}", own.join(", ")));
    let others = (!others.is_empty())
        .then(|| format!("repositories you can access in {}", others.join(", ")));
    let places = [own, others].into_iter().flatten().collect::<Vec<_>>();
    let reach = if places.is_empty() {
        "Codewire can read, push to and open pull requests in repositories where the Codewire GitHub App is installed.".to_owned()
    } else {
        format!(
            "Codewire can read, push to and open pull requests in {}.",
            places.join(", and in ")
        )
    };
    format!(
        "{reach}\nTo add an account or organization, or choose repositories, open {} and choose \"Only select repositories\".",
        codewire_credential_broker::provider_oauth::github::codewire_github_app_install_url()
    )
}

#[cfg(test)]
mod tests {
    use super::github_reach_summary;

    fn reach(
        account: &str,
        all_repositories: bool,
    ) -> codewire_credential_broker::GitHubAppInstallationReach {
        codewire_credential_broker::GitHubAppInstallationReach {
            account: account.into(),
            all_repositories,
            pending_permissions: None,
        }
    }

    const REACH_INSTALL_LINE: &str = "\nTo add an account or organization, or choose repositories, open \
         https://github.com/apps/codewire-sh/installations/new and choose \"Only select repositories\".";

    /// A collaborator on one repository of another user's account, where
    /// that user installed the App on all repositories, reaches only what
    /// the collaborator can already reach there (#5443).
    #[test]
    fn github_reach_never_shows_another_users_selection() {
        let summary = github_reach_summary(Some("octo-user"), &[reach("other-user", true)]);
        assert_eq!(
            summary,
            format!(
                "Codewire can read, push to and open pull requests in repositories you can access in other-user.{REACH_INSTALL_LINE}"
            )
        );
        assert!(!summary.contains("(all repositories)"));
        assert!(!summary.contains("(selected repositories)"));
    }

    #[test]
    fn github_reach_never_shows_an_organizations_selection() {
        let summary = github_reach_summary(Some("octo-user"), &[reach("acme-org", true)]);
        assert_eq!(
            summary,
            format!(
                "Codewire can read, push to and open pull requests in repositories you can access in acme-org.{REACH_INSTALL_LINE}"
            )
        );
        assert!(!summary.contains("(all repositories)"));
    }

    /// The user's own account keeps its installation's selection, whatever
    /// the letter case GitHub reports the login in.
    #[test]
    fn github_reach_names_the_users_own_selection() {
        for (login, account) in [
            ("octo-user", "octo-user"),
            ("Octo-User", "octo-user"),
            ("octo-user", "OCTO-USER"),
        ] {
            assert_eq!(
                github_reach_summary(Some(login), &[reach(account, true)]),
                format!(
                    "Codewire can read, push to and open pull requests in repositories of: {account} (all repositories).{REACH_INSTALL_LINE}"
                )
            );
            assert_eq!(
                github_reach_summary(Some(login), &[reach(account, false)]),
                format!(
                    "Codewire can read, push to and open pull requests in repositories of: {account} (selected repositories).{REACH_INSTALL_LINE}"
                )
            );
        }
    }

    #[test]
    fn github_reach_mixes_the_users_own_account_and_others() {
        assert_eq!(
            github_reach_summary(
                Some("octo-user"),
                &[
                    reach("acme-org", true),
                    reach("octo-user", false),
                    reach("other-user", true)
                ]
            ),
            format!(
                "Codewire can read, push to and open pull requests in repositories of: octo-user (selected repositories), \
                 and in repositories you can access in acme-org, other-user.{REACH_INSTALL_LINE}"
            )
        );
    }

    #[test]
    fn github_reach_without_installations_or_a_login_claims_no_selection() {
        assert_eq!(
            github_reach_summary(Some("octo-user"), &[]),
            format!(
                "Codewire can read, push to and open pull requests in repositories where the Codewire GitHub App is installed.{REACH_INSTALL_LINE}"
            )
        );
        // Without a verified login no account is the user's own.
        assert_eq!(
            github_reach_summary(None, &[reach("octo-user", true)]),
            format!(
                "Codewire can read, push to and open pull requests in repositories you can access in octo-user.{REACH_INSTALL_LINE}"
            )
        );
    }
}
