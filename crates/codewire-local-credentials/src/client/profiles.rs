//! Access profiles through the authority: create, change, read and delete.

use super::*;

impl LocalCredentialClient {
    pub async fn create_profile(
        &mut self,
        name: &AccessProfileName,
        entries: &BTreeMap<CapabilitySlot, CredentialId>,
    ) -> Result<AccessProfileRecord, Status> {
        profile_record_from_proto(
            self.inner
                .create_access_profile(v1::CreateAccessProfileRequest {
                    name: name.to_string(),
                    entries: profile_entries_to_proto(entries),
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn update_profile(
        &mut self,
        id: &AccessProfileId,
        expected_revision: u64,
        entries: &BTreeMap<CapabilitySlot, CredentialId>,
    ) -> Result<AccessProfileRecord, Status> {
        profile_record_from_proto(
            self.inner
                .update_access_profile(v1::UpdateAccessProfileRequest {
                    profile_id: id.to_string(),
                    expected_revision,
                    entries: profile_entries_to_proto(entries),
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn list_profiles(&mut self) -> Result<Vec<AccessProfileRecord>, Status> {
        self.inner
            .list_access_profiles(v1::ListAccessProfilesRequest {})
            .await?
            .into_inner()
            .profiles
            .into_iter()
            .map(profile_record_from_proto)
            .collect()
    }

    pub async fn get_profile(
        &mut self,
        id: &AccessProfileId,
    ) -> Result<AccessProfileRecord, Status> {
        profile_record_from_proto(
            self.inner
                .get_access_profile(profile_selector(id))
                .await?
                .into_inner(),
        )
    }

    pub async fn get_profile_revision(
        &mut self,
        id: &AccessProfileId,
        revision: u64,
    ) -> Result<AccessProfileRevisionRecord, Status> {
        profile_revision_from_proto(
            self.inner
                .get_access_profile_revision(v1::GetAccessProfileRevisionRequest {
                    profile_id: id.to_string(),
                    revision,
                })
                .await?
                .into_inner(),
        )
    }

    pub async fn list_profile_revisions(
        &mut self,
        id: &AccessProfileId,
    ) -> Result<Vec<AccessProfileRevisionRecord>, Status> {
        self.inner
            .list_access_profile_revisions(v1::ListAccessProfileRevisionsRequest {
                profile_id: id.to_string(),
            })
            .await?
            .into_inner()
            .revisions
            .into_iter()
            .map(profile_revision_from_proto)
            .collect()
    }

    pub async fn resolve_profile(
        &mut self,
        reference: &AccessProfileReference,
    ) -> Result<AccessProfileRecord, Status> {
        profile_record_from_proto(
            self.inner
                .resolve_access_profile(v1::ResolveAccessProfileRequest {
                    reference: reference.to_string(),
                })
                .await?
                .into_inner(),
        )
    }

    /// Make `id` the store's default profile. Needs
    /// [`crate::AuthorityFeature::DefaultProfile`].
    pub async fn set_default_profile(
        &mut self,
        id: &AccessProfileId,
    ) -> Result<AccessProfileRecord, Status> {
        profile_record_from_proto(
            self.inner
                .set_default_access_profile(profile_selector(id))
                .await?
                .into_inner(),
        )
    }

    pub async fn delete_profile(&mut self, id: &AccessProfileId) -> Result<(), Status> {
        self.inner
            .delete_access_profile(profile_selector(id))
            .await?;
        Ok(())
    }
}
