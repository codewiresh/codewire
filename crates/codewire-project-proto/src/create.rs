//! The `CreateEnvironment` request for a create form's accepted draft, so the
//! dashboard and the iOS app send the same request, `project_spec` included.

use codewire_project::create_input::{CreateDraft, Isolation};
use codewire_proto::codewire::v1 as proto;

use crate::to_proto;

pub fn create_request(org_id: &str, draft: CreateDraft) -> proto::CreateEnvironmentRequest {
    proto::CreateEnvironmentRequest {
        org_id: org_id.to_owned(),
        preset_id: draft.preset_id,
        name: draft.name,
        ttl_seconds: draft.ttl_seconds,
        isolation_tier: match draft.isolation {
            Isolation::Standard => proto::IsolationTier::Standard,
            Isolation::Confidential => proto::IsolationTier::Confidential,
        }
        .into(),
        omit_application_previews: draft.omit_application_previews,
        project_spec: Some(to_proto(draft.project_spec)).into(),
        ..Default::default()
    }
}
