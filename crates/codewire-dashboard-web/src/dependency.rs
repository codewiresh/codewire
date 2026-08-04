use connectrpc::{ConnectError, ErrorCode};

use crate::error::WebError;

/// A composed-page dependency whose failure policy is declared at the call
/// site instead of inferred from a catch-all error branch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum PageDependency {
    DashboardOrganizations,
    DashboardGithubStatus,
    SettingsGithubStatus,
    SettingsCredentials,
    SettingsGitIdentity,
    SettingsSshKey,
    BillingOverview,
    BillingUsage,
    BillingInvoices,
    BillingEvents,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Criticality {
    Required,
    Optional,
}

impl PageDependency {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 10] = [
        Self::DashboardOrganizations,
        Self::DashboardGithubStatus,
        Self::SettingsGithubStatus,
        Self::SettingsCredentials,
        Self::SettingsGitIdentity,
        Self::SettingsSshKey,
        Self::BillingOverview,
        Self::BillingUsage,
        Self::BillingInvoices,
        Self::BillingEvents,
    ];

    fn criticality(self) -> Criticality {
        match self {
            Self::DashboardOrganizations | Self::BillingOverview => Criticality::Required,
            Self::DashboardGithubStatus
            | Self::SettingsGithubStatus
            | Self::SettingsCredentials
            | Self::SettingsGitIdentity
            | Self::SettingsSshKey
            | Self::BillingUsage
            | Self::BillingInvoices
            | Self::BillingEvents => Criticality::Optional,
        }
    }
}

/// The explicit result of resolving a page dependency.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DependencyResult<T> {
    Available(T),
    Unavailable,
}

impl<T> DependencyResult<T> {
    pub(crate) fn into_option(self) -> Option<T> {
        match self {
            Self::Available(value) => Some(value),
            Self::Unavailable => None,
        }
    }
}

/// Resolve a Connect dependency without ever degrading authentication or
/// authorization failures into a partially authorized page.
pub(crate) fn resolve_connect<T>(
    dependency: PageDependency,
    result: Result<T, ConnectError>,
) -> Result<DependencyResult<T>, ConnectError> {
    match result {
        Ok(value) => Ok(DependencyResult::Available(value)),
        Err(error)
            if dependency.criticality() == Criticality::Optional
                && !is_auth_boundary(error.code) =>
        {
            Ok(DependencyResult::Unavailable)
        }
        Err(error) => Err(error),
    }
}

/// Resolve a dashboard adapter dependency that has already been mapped to
/// [`WebError`]. Non-Connect adapter failures remain hard failures.
pub(crate) fn resolve_web<T>(
    dependency: PageDependency,
    result: Result<T, WebError>,
) -> Result<DependencyResult<T>, WebError> {
    match result {
        Ok(value) => Ok(DependencyResult::Available(value)),
        Err(WebError::Connect(error)) if error.code == ErrorCode::Unauthenticated => {
            Err(WebError::Unauthorized)
        }
        Err(WebError::Connect(error))
            if dependency.criticality() == Criticality::Optional
                && !is_auth_boundary(error.code) =>
        {
            Ok(DependencyResult::Unavailable)
        }
        Err(error) => Err(error),
    }
}

fn is_auth_boundary(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::Unauthenticated | ErrorCode::PermissionDenied
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn dependency_inventory_is_unique_and_has_both_criticalities() {
        let unique = PageDependency::ALL.into_iter().collect::<HashSet<_>>();
        assert_eq!(unique.len(), PageDependency::ALL.len());
        assert!(
            PageDependency::ALL
                .iter()
                .any(|dependency| dependency.criticality() == Criticality::Required)
        );
        assert!(
            PageDependency::ALL
                .iter()
                .any(|dependency| dependency.criticality() == Criticality::Optional)
        );
    }

    #[test]
    fn every_optional_dependency_degrades_only_operational_failures() {
        for dependency in PageDependency::ALL
            .into_iter()
            .filter(|dependency| dependency.criticality() == Criticality::Optional)
        {
            let degraded = resolve_connect::<()>(
                dependency,
                Err(ConnectError::unavailable("upstream-sensitive-detail")),
            )
            .expect("optional operational failure degrades");
            assert_eq!(degraded, DependencyResult::Unavailable, "{dependency:?}");

            for error in [
                ConnectError::unauthenticated("expired session"),
                ConnectError::permission_denied("forbidden"),
            ] {
                let returned = resolve_connect::<()>(dependency, Err(error))
                    .expect_err("auth boundaries stay hard failures");
                assert!(is_auth_boundary(returned.code), "{dependency:?}");
            }
        }
    }

    #[test]
    fn every_required_dependency_keeps_operational_failures_hard() {
        for dependency in PageDependency::ALL
            .into_iter()
            .filter(|dependency| dependency.criticality() == Criticality::Required)
        {
            let error = resolve_connect::<()>(
                dependency,
                Err(ConnectError::unavailable("required upstream failed")),
            )
            .expect_err("required dependency must fail the page");
            assert_eq!(error.code, ErrorCode::Unavailable, "{dependency:?}");
        }
    }

    #[test]
    fn web_dependencies_preserve_login_and_authorization_boundaries() {
        let login = resolve_web::<()>(
            PageDependency::DashboardGithubStatus,
            Err(WebError::Connect(ConnectError::unauthenticated(
                "expired session",
            ))),
        )
        .expect_err("unauthenticated dependency must redirect through the route");
        assert!(matches!(login, WebError::Unauthorized));

        let forbidden = resolve_web::<()>(
            PageDependency::DashboardGithubStatus,
            Err(WebError::Connect(ConnectError::permission_denied(
                "forbidden",
            ))),
        )
        .expect_err("permission denied must remain a hard page failure");
        assert!(matches!(
            forbidden,
            WebError::Connect(error) if error.code == ErrorCode::PermissionDenied
        ));
    }
}
