//! Personal access-profile metadata through the canonical generated client.

use crate::*;

impl CodewireClient {
    pub async fn list_access_profiles(
        &self,
        request: ListAccessProfilesRequest,
    ) -> Result<ListAccessProfilesResponse, ClientError> {
        self.access_profiles
            .list_access_profiles_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_access_profile(
        &self,
        request: GetAccessProfileRequest,
    ) -> Result<GetAccessProfileResponse, ClientError> {
        self.access_profiles
            .get_access_profile_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn create_access_profile(
        &self,
        request: CreateAccessProfileRequest,
    ) -> Result<CreateAccessProfileResponse, ClientError> {
        self.access_profiles
            .create_access_profile_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn update_access_profile(
        &self,
        request: UpdateAccessProfileRequest,
    ) -> Result<UpdateAccessProfileResponse, ClientError> {
        self.access_profiles
            .update_access_profile_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    /// Relabel the exact current revision; no revision is published and
    /// environment bindings are unchanged.
    pub async fn rename_access_profile(
        &self,
        request: RenameAccessProfileRequest,
    ) -> Result<RenameAccessProfileResponse, ClientError> {
        self.access_profiles
            .rename_access_profile_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn delete_access_profile(
        &self,
        request: DeleteAccessProfileRequest,
    ) -> Result<DeleteAccessProfileResponse, ClientError> {
        self.access_profiles
            .delete_access_profile_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }

    pub async fn get_environment_access_profile(
        &self,
        request: GetEnvironmentAccessProfileRequest,
    ) -> Result<GetEnvironmentAccessProfileResponse, ClientError> {
        self.access_profiles
            .get_environment_access_profile_with_options(request, self.auth_options().await?)
            .await
            .map(|response| response.into_owned())
            .map_err(ClientError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message as _;
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn profile_facade_preserves_exact_requests_and_uses_shared_bearer_transport() {
        let server = MockServer::start().await;
        let client = CodewireClient::with_http(
            ClientConfig::new(server.uri()).unwrap(),
            StaticTokenProvider::new("synthetic-profile-token").unwrap(),
            reqwest::Client::new(),
        )
        .unwrap();
        let entry = AccessProfileEntry {
            capability_slot: "codex".into(),
            credential_id: "credential".into(),
            ..Default::default()
        };
        let request = ListAccessProfilesRequest {
            page_size: 1,
            page_token: "cursor".into(),
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path("/codewire.v1.AccessProfileService/ListAccessProfiles"))
            .and(header("authorization", "Bearer synthetic-profile-token"))
            .and(body_bytes(request.encode_to_vec()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(ListAccessProfilesResponse::default().encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;
        client.list_access_profiles(request).await.unwrap();
        let request = GetAccessProfileRequest {
            selector: Some(get_access_profile_request::Selector::Name("work".into())),
            revision: Some(9_007_199_254_740_993),
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path("/codewire.v1.AccessProfileService/GetAccessProfile"))
            .and(header("authorization", "Bearer synthetic-profile-token"))
            .and(body_bytes(request.encode_to_vec()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(GetAccessProfileResponse::default().encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;
        client.get_access_profile(request).await.unwrap();
        let request = CreateAccessProfileRequest {
            name: "work".into(),
            entries: vec![entry.clone()],
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.AccessProfileService/CreateAccessProfile",
            ))
            .and(header("authorization", "Bearer synthetic-profile-token"))
            .and(body_bytes(request.encode_to_vec()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(CreateAccessProfileResponse::default().encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;
        client.create_access_profile(request).await.unwrap();
        let request = UpdateAccessProfileRequest {
            access_profile_id: "profile".into(),
            expected_revision: 9_007_199_254_740_993,
            entries: vec![entry],
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.AccessProfileService/UpdateAccessProfile",
            ))
            .and(header("authorization", "Bearer synthetic-profile-token"))
            .and(body_bytes(request.encode_to_vec()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(UpdateAccessProfileResponse::default().encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;
        client.update_access_profile(request).await.unwrap();
        let request = RenameAccessProfileRequest {
            access_profile_id: "profile".into(),
            expected_revision: 9_007_199_254_740_993,
            name: "renamed".into(),
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.AccessProfileService/RenameAccessProfile",
            ))
            .and(header("authorization", "Bearer synthetic-profile-token"))
            .and(body_bytes(request.encode_to_vec()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(RenameAccessProfileResponse::default().encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;
        client.rename_access_profile(request).await.unwrap();
        let request = DeleteAccessProfileRequest {
            access_profile_id: "profile".into(),
            expected_revision: 9_007_199_254_740_993,
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.AccessProfileService/DeleteAccessProfile",
            ))
            .and(header("authorization", "Bearer synthetic-profile-token"))
            .and(body_bytes(request.encode_to_vec()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(DeleteAccessProfileResponse::default().encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;
        client.delete_access_profile(request).await.unwrap();
        let request = GetEnvironmentAccessProfileRequest {
            environment_id: "environment".into(),
            ..Default::default()
        };
        Mock::given(method("POST"))
            .and(path(
                "/codewire.v1.AccessProfileService/GetEnvironmentAccessProfile",
            ))
            .and(header("authorization", "Bearer synthetic-profile-token"))
            .and(body_bytes(request.encode_to_vec()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/proto")
                    .set_body_bytes(GetEnvironmentAccessProfileResponse::default().encode_to_vec()),
            )
            .expect(1)
            .mount(&server)
            .await;
        client
            .get_environment_access_profile(request)
            .await
            .unwrap();
    }
}
