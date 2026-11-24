//! Admin → Organizations' Sandbox counts (#6086), defined on `SandboxCounts`
//! in `proto/codewire/admin/v1/admin.proto`. One AdminService call reads
//! every organization's counts; an organization it doesn't list has none.

use std::collections::HashMap;

use codewire_admin_proto::codewire::admin::v1::{
    ListOrganizationSandboxCountsResponse, SandboxCounts,
};

use crate::time_display::calendar_datetime;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SandboxCountsView {
    pub(crate) created: i64,
    pub(crate) running: i64,
    pub(crate) stopped: i64,
    pub(crate) failed: i64,
    pub(crate) deleted: i64,
}

impl From<&SandboxCounts> for SandboxCountsView {
    fn from(counts: &SandboxCounts) -> Self {
        Self {
            created: counts.created,
            running: counts.running,
            stopped: counts.stopped,
            failed: counts.failed,
            deleted: counts.deleted,
        }
    }
}

/// One organization's row: its counts and when it last created a Sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrganizationSandboxes {
    pub(crate) counts: SandboxCountsView,
    pub(crate) last_created: String,
}

#[derive(Debug, Default)]
pub(crate) struct SandboxCountsByOrganization {
    pub(crate) totals: SandboxCountsView,
    organizations: HashMap<String, OrganizationSandboxes>,
}

impl SandboxCountsByOrganization {
    pub(crate) fn new(response: ListOrganizationSandboxCountsResponse) -> Self {
        let organizations = response
            .organizations
            .into_iter()
            .map(|organization| {
                let sandboxes = OrganizationSandboxes {
                    counts: organization
                        .counts
                        .as_option()
                        .map(SandboxCountsView::from)
                        .unwrap_or_default(),
                    last_created: organization
                        .last_created_at
                        .as_option()
                        .map(|at| calendar_datetime(at.seconds))
                        .unwrap_or_else(|| "Never".to_owned()),
                };
                (organization.organization_id, sandboxes)
            })
            .collect();
        Self {
            totals: response
                .totals
                .as_option()
                .map(SandboxCountsView::from)
                .unwrap_or_default(),
            organizations,
        }
    }

    /// An organization absent from the counts has never created a Sandbox.
    pub(crate) fn organization(&self, organization_id: &str) -> OrganizationSandboxes {
        self.organizations
            .get(organization_id)
            .cloned()
            .unwrap_or_else(|| OrganizationSandboxes {
                counts: SandboxCountsView::default(),
                last_created: "Never".to_owned(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_admin_proto::codewire::admin::v1::OrganizationSandboxCounts;

    fn counts(
        created: i64,
        running: i64,
        stopped: i64,
        failed: i64,
        deleted: i64,
    ) -> SandboxCounts {
        SandboxCounts {
            created,
            running,
            stopped,
            failed,
            deleted,
            ..Default::default()
        }
    }

    #[test]
    fn an_organization_left_out_of_the_counts_has_none() {
        let mut busy = OrganizationSandboxCounts {
            organization_id: "org_busy".into(),
            counts: Some(counts(5, 2, 1, 1, 1)).into(),
            ..Default::default()
        };
        busy.last_created_at.get_or_insert_default().seconds = 1_795_000_000;
        let by_organization =
            SandboxCountsByOrganization::new(ListOrganizationSandboxCountsResponse {
                organizations: vec![busy],
                totals: Some(counts(5, 2, 1, 1, 1)).into(),
                ..Default::default()
            });
        let busy = by_organization.organization("org_busy");
        assert_eq!(
            busy.counts,
            SandboxCountsView {
                created: 5,
                running: 2,
                stopped: 1,
                failed: 1,
                deleted: 1
            }
        );
        assert_eq!(busy.last_created, calendar_datetime(1_795_000_000));
        assert_eq!(
            by_organization.organization("org_new"),
            OrganizationSandboxes {
                counts: SandboxCountsView::default(),
                last_created: "Never".into(),
            }
        );
        assert_eq!(by_organization.totals.failed, 1);
    }
}
