use codewire_gateway_proto::DAEMON_AUTH_TOKEN_HEADER;
use codewire_gateway_proto::daemon::v1;
use codewire_gateway_proto::daemon::v1::host_control_service_server::HostControlService as Rpc;
use prost::Message;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tonic::{Request, Response, Status};

use super::{Error, HostControlBinding, Mutation, Owner, Scope};

const SESSION_PAGE_BYTES: usize = 256 * 1024;

pub(super) fn managed_chunks(
    request: &v1::HostControlManagedReadRequest,
    bytes: &[u8],
) -> Result<Vec<v1::HostControlManagedRecordChunk>, Error> {
    if bytes.is_empty() || bytes.len() > super::managed::MAX_RECORD_REPLY {
        return Err(Error::Capacity);
    }
    let digest = format!("{:x}", Sha256::digest(bytes));
    bytes
        .chunks(super::managed::CHUNK_DATA)
        .enumerate()
        .map(|(index, data)| {
            let chunk = v1::HostControlManagedRecordChunk {
                session_id: request.session_id.clone(),
                driver_id: request.driver_id.clone(),
                launch_generation: request.expected_launch_generation,
                message_id: request.message_id.clone(),
                offset: (index * super::managed::CHUNK_DATA) as u64,
                total_bytes: bytes.len() as u64,
                payload_sha256: digest.clone(),
                data: data.to_vec(),
            };
            // Reserve the member response success byte as well as protobuf framing.
            if chunk.encoded_len() + 1 > super::managed::MAX_CHUNK {
                Err(Error::Capacity)
            } else {
                Ok(chunk)
            }
        })
        .collect()
}

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
    type ReadHostManagedSessionStream = std::pin::Pin<
        Box<
            dyn tokio_stream::Stream<Item = Result<v1::HostControlManagedRecordChunk, Status>>
                + Send
                + 'static,
        >,
    >;

    async fn read_host_managed_session(
        &self,
        request: Request<v1::HostControlManagedReadRequest>,
    ) -> Result<Response<Self::ReadHostManagedSessionStream>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        let scope = Scope::from_wire(
            request
                .scope
                .clone()
                .ok_or(Error::Invalid)
                .map_err(Error::status)?,
        )
        .map_err(Error::status)?;
        super::session_id(&request.session_id).map_err(Error::status)?;
        super::canonical_uuid(&request.driver_id).map_err(Error::status)?;
        if request.session_id != format!("session-{}", request.driver_id)
            || request.expected_launch_generation == 0
            || request.limit > 100
        {
            return Err(Error::Invalid.status());
        }
        if !request.message_id.is_empty() {
            super::canonical_uuid(&request.message_id).map_err(Error::status)?;
        }
        let bytes = self
            .owner
            .read_managed(&request, &scope)
            .await
            .map_err(Error::status)?;
        let chunks = managed_chunks(&request, &bytes).map_err(Error::status)?;
        Ok(Response::new(Box::pin(tokio_stream::iter(
            chunks.into_iter().map(Ok),
        ))))
    }
    async fn get_host_control_info(
        &self,
        request: Request<v1::HostControlInfoRequest>,
    ) -> Result<Response<v1::HostControlInfoResponse>, Status> {
        self.authorize(&request)?;
        Ok(Response::new(v1::HostControlInfoResponse {
            protocol_version: super::HOST_CONTROL_PROTOCOL,
            environment_id: self.owner.environment_id().into(),
            verbs: super::managed::verbs(self.owner.managed_agents()),
            managed_agent_protocol_version: if self.owner.managed_agents() {
                super::managed::PROTOCOL
            } else {
                0
            },
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

#[cfg(test)]
mod managed_tests {
    use super::*;
    fn request() -> v1::HostControlManagedReadRequest {
        let driver = uuid::Uuid::new_v4().to_string();
        v1::HostControlManagedReadRequest {
            scope: Some(crate::host_control::tests::scope().to_wire()),
            session_id: format!("session-{driver}"),
            driver_id: driver,
            expected_launch_generation: 7,
            message_id: uuid::Uuid::new_v4().to_string(),
            limit: 20,
        }
    }
    #[test]
    fn managed_record_chunks_preserve_four_mib_outcome_and_bound_every_encoded_frame() {
        let request = request();
        let bytes = vec![b'x'; 4 * 1024 * 1024];
        let chunks = managed_chunks(&request, &bytes).unwrap();
        assert!(chunks.len() > 16);
        assert!(chunks.iter().all(|c| c.encoded_len() < 256 * 1024));
        assert_eq!(
            crate::client::validate_host_managed_chunks(&request, &chunks).unwrap(),
            bytes
        );
        assert!(managed_chunks(&request, &[]).is_err());
        assert!(
            managed_chunks(
                &request,
                &vec![0; super::super::managed::MAX_RECORD_REPLY + 1]
            )
            .is_err()
        );
    }
    #[test]
    fn managed_record_chunks_refuse_missing_reordered_truncated_tampered_or_rebound_frames() {
        let request = request();
        let bytes = vec![b'x'; 300 * 1024];
        let valid = managed_chunks(&request, &bytes).unwrap();
        for field in [
            "missing",
            "reorder",
            "duplicate",
            "offset",
            "total",
            "hash",
            "bytes",
            "scope",
            "message",
            "generation",
            "oversize",
        ] {
            let mut chunks = valid.clone();
            match field {
                "missing" => {
                    chunks.pop();
                }
                "reorder" => chunks.swap(0, 1),
                "duplicate" => {
                    chunks.insert(1, chunks[0].clone());
                }
                "offset" => chunks[1].offset += 1,
                "total" => chunks[0].total_bytes += 1,
                "hash" => chunks[0].payload_sha256 = "00".repeat(32),
                "bytes" => chunks[0].data[0] ^= 1,
                "scope" => chunks[0].driver_id = uuid::Uuid::new_v4().to_string(),
                "message" => chunks[0].message_id = uuid::Uuid::new_v4().to_string(),
                "generation" => chunks[0].launch_generation += 1,
                "oversize" => chunks[0].data = vec![0; 256 * 1024],
                _ => unreachable!(),
            }
            assert!(
                crate::client::validate_host_managed_chunks(&request, &chunks).is_err(),
                "{field}"
            );
        }
    }
}
