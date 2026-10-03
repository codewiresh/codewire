use codewire_gateway_proto::DAEMON_AUTH_TOKEN_HEADER;
use codewire_gateway_proto::daemon::v1;
use codewire_gateway_proto::daemon::v1::host_control_service_server::HostControlService as Rpc;
use prost::Message;
use subtle::ConstantTimeEq;
use tonic::{Request, Response, Status};

use super::{Error, HostControlBinding, Mutation, Owner, Scope};

const SESSION_PAGE_BYTES: usize = 256 * 1024;

pub(super) fn session_page(
    records: Vec<v1::SessionRecord>,
    after: &str,
    limit: usize,
) -> Result<v1::HostControlListSessionsResponse, Error> {
    let records = records
        .into_iter()
        .filter(|record| record.session_id.as_str() > after)
        .collect::<Vec<_>>();
    let mut response = v1::HostControlListSessionsResponse::default();
    for (index, record) in records.iter().take(limit).enumerate() {
        response.sessions.push(record.clone());
        // Reserve the actual cursor before accepting the item. The lookahead
        // stays unconsumed until it fits; the next request resumes after the
        // last returned item, never after a discarded oversized candidate.
        response.next_session_id = if index + 1 < records.len() {
            record.session_id.clone()
        } else {
            String::new()
        };
        if response.encoded_len() > SESSION_PAGE_BYTES {
            response.sessions.pop();
            if response.sessions.is_empty() {
                return Err(Error::Capacity);
            }
            break;
        }
    }
    response.next_session_id = if response.sessions.len() < records.len() {
        response
            .sessions
            .last()
            .map(|record| record.session_id.clone())
            .unwrap_or_default()
    } else {
        String::new()
    };
    if response.encoded_len() > SESSION_PAGE_BYTES {
        return Err(Error::Capacity);
    }
    Ok(response)
}

#[derive(Clone)]
pub(crate) struct HostControlService {
    owner: Owner,
    config: crate::Config,
}

impl HostControlService {
    pub(crate) async fn new(
        config: &crate::Config,
        binding: HostControlBinding,
        engine: crate::durable_session::SessionEngine,
    ) -> Result<Self, Error> {
        Ok(Self {
            owner: Owner::new(config, binding, engine).await?,
            config: config.clone(),
        })
    }

    pub(crate) fn owner(&self) -> Owner {
        self.owner.clone()
    }

    fn authorize<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let actual = request
            .metadata()
            .get(DAEMON_AUTH_TOKEN_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("missing daemon auth token"))?;
        if !bool::from(
            actual
                .as_bytes()
                .ct_eq(self.config.auth_token.expose_secret().as_bytes()),
        ) {
            return Err(Status::unauthenticated("invalid daemon auth token"));
        }
        self.config
            .validate_host()
            .map_err(|_| Error::Denied.status())?;
        if self.config.host.is_none() {
            return Err(Error::Denied.status());
        }
        Ok(())
    }

    fn read_scope(request: &v1::HostControlReadRequest) -> Result<Scope, Status> {
        Scope::from_wire(
            request
                .scope
                .clone()
                .ok_or(Error::Invalid)
                .map_err(Error::status)?,
        )
        .map_err(Error::status)
    }
}

#[tonic::async_trait]
impl Rpc for HostControlService {
    async fn get_host_control_info(
        &self,
        request: Request<v1::HostControlInfoRequest>,
    ) -> Result<Response<v1::HostControlInfoResponse>, Status> {
        self.authorize(&request)?;
        Ok(Response::new(v1::HostControlInfoResponse {
            protocol_version: super::HOST_CONTROL_PROTOCOL,
            environment_id: self.owner.environment_id().into(),
            verbs: vec![
                v1::HostControlVerb::Read as i32,
                v1::HostControlVerb::Launch as i32,
                v1::HostControlVerb::Input as i32,
                v1::HostControlVerb::Stop as i32,
            ],
        }))
    }

    async fn put_host_control_grant(
        &self,
        request: Request<v1::HostControlPutGrantRequest>,
    ) -> Result<Response<v1::HostControlGrantsResponse>, Status> {
        self.authorize(&request)?;
        self.owner
            .put_grant(request.into_inner())
            .await
            .map(Response::new)
            .map_err(Error::status)
    }

    async fn revoke_host_control_grant(
        &self,
        request: Request<v1::HostControlRevokeGrantRequest>,
    ) -> Result<Response<v1::HostControlGrantsResponse>, Status> {
        self.authorize(&request)?;
        self.owner
            .revoke_grant(request.into_inner())
            .await
            .map(Response::new)
            .map_err(Error::status)
    }

    async fn list_host_control_grants(
        &self,
        request: Request<v1::HostControlInfoRequest>,
    ) -> Result<Response<v1::HostControlGrantsResponse>, Status> {
        self.authorize(&request)?;
        self.owner
            .grants()
            .await
            .map(Response::new)
            .map_err(Error::status)
    }

    async fn mutate_host_session(
        &self,
        request: Request<v1::HostControlMutationRequest>,
    ) -> Result<Response<v1::HostControlReceipt>, Status> {
        self.authorize(&request)?;
        let mutation = Mutation::from_wire(request.into_inner()).map_err(Error::status)?;
        self.owner
            .mutate(mutation)
            .await
            .map(|receipt| Response::new(receipt.to_wire()))
            .map_err(Error::status)
    }

    async fn observe_host_request(
        &self,
        request: Request<v1::HostControlObserveRequest>,
    ) -> Result<Response<v1::HostControlReceipt>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        let scope = Scope::from_wire(request.scope.ok_or(Error::Invalid).map_err(Error::status)?)
            .map_err(Error::status)?;
        self.owner
            .observe(&request.request_id, &scope)
            .await
            .map(|receipt| Response::new(receipt.to_wire()))
            .map_err(Error::status)
    }

    async fn list_host_sessions(
        &self,
        request: Request<v1::HostControlReadRequest>,
    ) -> Result<Response<v1::HostControlListSessionsResponse>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        let scope = Self::read_scope(&request)?;
        if !request.session_id.is_empty()
            || request.offset != 0
            || request.limit != 0
            || request.allow_history_gap
            || request.page_limit > 8
        {
            return Err(Error::Invalid.status());
        }
        if !request.after_session_id.is_empty() {
            super::session_id(&request.after_session_id).map_err(Error::status)?;
        }
        let page_limit = if request.page_limit == 0 {
            8
        } else {
            request.page_limit as usize
        };
        session_page(
            self.owner.list(&scope).await.map_err(Error::status)?,
            &request.after_session_id,
            page_limit,
        )
        .map(Response::new)
        .map_err(Error::status)
    }

    async fn get_host_session(
        &self,
        request: Request<v1::HostControlReadRequest>,
    ) -> Result<Response<v1::GetSessionResponse>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        let scope = Self::read_scope(&request)?;
        if request.offset != 0
            || request.limit != 0
            || request.allow_history_gap
            || !request.after_session_id.is_empty()
            || request.page_limit != 0
        {
            return Err(Error::Invalid.status());
        }
        self.owner
            .get(&scope, &request.session_id)
            .await
            .map(|session| {
                Response::new(v1::GetSessionResponse {
                    session: Some(session),
                })
            })
            .map_err(Error::status)
    }

    async fn read_host_session_output(
        &self,
        request: Request<v1::HostControlReadRequest>,
    ) -> Result<Response<v1::ReadSessionOutputResponse>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        let scope = Self::read_scope(&request)?;
        if request.limit > super::HOST_CONTROL_MAX_OUTPUT_BYTES
            || !request.after_session_id.is_empty()
            || request.page_limit != 0
        {
            return Err(Error::Invalid.status());
        }
        let output = v1::ReadSessionOutputRequest {
            session_id: request.session_id,
            offset: request.offset,
            limit: if request.limit == 0 {
                super::HOST_CONTROL_MAX_OUTPUT_BYTES
            } else {
                request.limit
            },
            allow_history_gap: request.allow_history_gap,
        };
        self.owner
            .output(&scope, output)
            .await
            .map(Response::new)
            .map_err(Error::status)
    }
}
