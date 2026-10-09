//! Typed original-channel private platform client. No discovery or latest-token
//! fallback, mutation retry, command or credential projection is available here.
use super::*;
use codewire_daemon_proto::platform_managed as wire;
use sha2::{Digest, Sha256};

pub fn platform_managed_request_fingerprint(
    request: &v1::PlatformManagedMutationRequest,
) -> Result<String, DaemonClientError> {
    wire::platform_managed_request_fingerprint(request).map_err(DaemonClientError::InvalidFrame)
}
fn refused() -> DaemonClientError {
    DaemonClientError::InvalidFrame("platform managed")
}
fn deadline() -> DaemonClientError {
    tonic::Status::deadline_exceeded("original platform managed operation deadline").into()
}
fn verify_receipt(
    r: &v1::PlatformManagedReceipt,
    id: &str,
    scope: &v1::PlatformManagedScope,
) -> Result<(), DaemonClientError> {
    wire::validate_receipt(r).map_err(DaemonClientError::InvalidFrame)?;
    if r.request_id != id || r.scope.as_ref() != Some(scope) {
        Err(refused())
    } else {
        Ok(())
    }
}
impl DaemonClient {
    pub async fn platform_managed_info(
        &self,
        request: v1::PlatformManagedInfoRequest,
    ) -> Result<v1::PlatformManagedInfoResponse, DaemonClientError> {
        wire::validate_info(&request).map_err(DaemonClientError::InvalidFrame)?;
        let expected = request.clone();
        let mut client = self.platform.clone();
        let r = tokio::time::timeout(
            Duration::from_secs(30),
            client.get_platform_managed_info(self.authorized(request)),
        )
        .await
        .map_err(|_| deadline())??
        .into_inner();
        if r.protocol_version != wire::PROTOCOL
            || r.environment_id != expected.environment_id
            || r.binding_generation != expected.binding_generation
            || r.projection_selection_sha256 != expected.projection_selection_sha256
            || r.support_image_sha256.len() != 32
            || !r.support_image_sha256.iter().any(|b| *b != 0)
            || !(4..=wire::SUPPORT_BYTES).contains(&r.support_image_size)
            || r.support_image_version.is_empty()
            || r.support_image_version.len() > 128
            || r.agents.len() > 2
        {
            return Err(refused());
        }
        let mut agents = std::collections::BTreeSet::new();
        for a in &r.agents {
            let kind = v1::PlatformManagedAgent::try_from(a.agent).map_err(|_| refused())?;
            if !agents.insert(a.agent)
                || wire::provider_version(kind) != Some(a.provider_version.as_str())
                || !a.proxy_only_qualified
                || a.provider_sha256.len() != 32
                || !a.provider_sha256.iter().any(|b| *b != 0)
                || !(4..=wire::PROVIDER_BYTES).contains(&a.provider_size)
            {
                return Err(refused());
            }
        }
        Ok(r)
    }
    pub async fn mutate_platform_managed_session(
        &self,
        request: v1::PlatformManagedMutationRequest,
    ) -> Result<v1::PlatformManagedReceipt, DaemonClientError> {
        let fingerprint = platform_managed_request_fingerprint(&request)?;
        let expected = request.clone();
        let mut client = self.platform.clone();
        // A timeout is uncertain; the caller must Observe this UUID on THIS
        // channel. Neither this method nor cancellation sends another mutation.
        let r = tokio::time::timeout(
            Duration::from_secs(180),
            client.mutate_platform_managed_session(self.authorized(request)),
        )
        .await
        .map_err(|_| deadline())??
        .into_inner();
        verify_receipt(
            &r,
            &expected.request_id,
            expected.scope.as_ref().ok_or_else(refused)?,
        )?;
        if r.fingerprint_sha256 != fingerprint {
            return Err(refused());
        }
        let expected_cleanup = match &expected.operation {
            Some(v1::platform_managed_mutation_request::Operation::Control(c)) => {
                c.cleanup_of_request_id.as_ref()
            }
            _ => None,
        };
        if r.cleanup_of_request_id.as_ref() != expected_cleanup {
            return Err(refused());
        }
        Ok(r)
    }
    pub async fn observe_platform_managed_request(
        &self,
        request: v1::PlatformManagedObserveRequest,
    ) -> Result<v1::PlatformManagedReceipt, DaemonClientError> {
        wire::validate_scope(request.scope.as_ref().ok_or_else(refused)?)
            .map_err(DaemonClientError::InvalidFrame)?;
        if !wire::valid_uuid(&request.request_id) {
            return Err(refused());
        }
        let expected = request.clone();
        let mut client = self.platform.clone();
        let r = tokio::time::timeout(
            Duration::from_secs(30),
            client.observe_platform_managed_request(self.authorized(request)),
        )
        .await
        .map_err(|_| deadline())??
        .into_inner();
        verify_receipt(
            &r,
            &expected.request_id,
            expected.scope.as_ref().ok_or_else(refused)?,
        )?;
        Ok(r)
    }
    pub async fn list_platform_managed_sessions(
        &self,
        request: v1::PlatformManagedListRequest,
    ) -> Result<v1::PlatformManagedListResponse, DaemonClientError> {
        wire::validate_scope(request.scope.as_ref().ok_or_else(refused)?)
            .map_err(DaemonClientError::InvalidFrame)?;
        if request.page_limit > 8
            || (!request.after_session_id.is_empty()
                && !wire::valid_session(&request.after_session_id))
        {
            return Err(refused());
        }
        let mut client = self.platform.clone();
        let r = tokio::time::timeout(
            Duration::from_secs(30),
            client.list_platform_managed_sessions(self.authorized(request)),
        )
        .await
        .map_err(|_| deadline())??
        .into_inner();
        let mut previous = "";
        if r.sessions.len() > 8 {
            return Err(refused());
        }
        for s in &r.sessions {
            if !wire::valid_session(&s.session_id)
                || s.session_id.as_str() <= previous
                || s.launch_generation == 0
            {
                return Err(refused());
            }
            previous = &s.session_id;
        }
        if !r.next_session_id.is_empty() && r.next_session_id != previous {
            return Err(refused());
        }
        Ok(r)
    }
    pub async fn read_platform_managed_session(
        &self,
        request: v1::PlatformManagedReadRequest,
    ) -> Result<PlatformManagedRecordStream, DaemonClientError> {
        wire::validate_read(&request).map_err(DaemonClientError::InvalidFrame)?;
        let expected = request.clone();
        let mut client = self.platform.clone();
        let stream = tokio::time::timeout(
            Duration::from_secs(30),
            client.read_platform_managed_session(self.authorized(request)),
        )
        .await
        .map_err(|_| deadline())??
        .into_inner();
        Ok(PlatformManagedRecordStream {
            stream,
            decoder: RecordDecoder {
                expected,
                offset: 0,
                total: None,
                hash: None,
                digest: Sha256::new(),
                finished: false,
                refused: false,
            },
            deadline: tokio::time::Instant::now() + Duration::from_secs(30),
        })
    }
}
/// One bounded stream; dropping it cancels observation, never the target owner.
pub struct PlatformManagedRecordStream {
    stream: Streaming<v1::PlatformManagedRecordChunk>,
    decoder: RecordDecoder,
    deadline: tokio::time::Instant,
}
struct RecordDecoder {
    expected: v1::PlatformManagedReadRequest,
    offset: u64,
    total: Option<u64>,
    hash: Option<String>,
    digest: Sha256,
    finished: bool,
    refused: bool,
}
impl PlatformManagedRecordStream {
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, DaemonClientError> {
        if self.decoder.refused {
            return Err(refused());
        }
        if self.decoder.finished {
            return Ok(None);
        }
        let r = match tokio::time::timeout_at(self.deadline, self.stream.message()).await {
            Ok(Ok(row)) => row,
            other => {
                self.decoder.refused = true;
                return Err(match other {
                    Ok(Err(error)) => error.into(),
                    _ => deadline(),
                });
            }
        };
        self.decoder.accept(r)
    }
    pub async fn read_complete(mut self) -> Result<Vec<u8>, DaemonClientError> {
        let mut bytes = Vec::new();
        while let Some(part) = self.next_chunk().await? {
            bytes.extend_from_slice(&part);
        }
        Ok(bytes)
    }
}
impl RecordDecoder {
    fn accept(
        &mut self,
        r: Option<v1::PlatformManagedRecordChunk>,
    ) -> Result<Option<Vec<u8>>, DaemonClientError> {
        if self.refused {
            return Err(refused());
        }
        if self.finished {
            return if r.is_none() {
                Ok(None)
            } else {
                self.refused = true;
                Err(refused())
            };
        }
        let Some(r) = r else {
            if self.total != Some(self.offset)
                || self.hash.as_deref()
                    != Some(format!("{:x}", self.digest.clone().finalize()).as_str())
            {
                self.refused = true;
                return Err(refused());
            }
            self.finished = true;
            return Ok(None);
        };
        // Each allowed header is bounded; preserve a conservative encoded-frame
        // allowance without reserializing or trusting an unbounded unknown field.
        if r.scope != self.expected.scope
            || r.session_id != self.expected.session_id
            || r.driver_id != self.expected.driver_id
            || r.launch_generation != self.expected.expected_launch_generation
            || r.message_id != self.expected.message_id
            || r.offset != self.offset
            || r.data.is_empty()
            || r.data.len() > wire::FRAME_BYTES - 4096
            || r.total_bytes == 0
            || r.total_bytes > wire::RECORD_BYTES as u64
            || !wire::valid_hash(&r.payload_sha256)
            || self.total.is_some_and(|t| t != r.total_bytes)
            || self.hash.as_ref().is_some_and(|h| h != &r.payload_sha256)
            || r.data.len() as u64 > r.total_bytes.saturating_sub(self.offset)
        {
            self.refused = true;
            return Err(refused());
        }
        self.total = Some(r.total_bytes);
        self.hash = Some(r.payload_sha256);
        self.offset += r.data.len() as u64;
        self.digest.update(&r.data);
        Ok(Some(r.data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn request() -> v1::PlatformManagedReadRequest {
        v1::PlatformManagedReadRequest {
            scope: Some(v1::PlatformManagedScope {
                environment_id: "00000000-0000-4000-8000-000000000001".into(),
                org_id: "synthetic".into(),
                pod_uid: "00000000-0000-4000-8000-000000000002".into(),
                binding_generation: u64::MAX,
                projection_selection_sha256: vec![1; 32],
                support_image_sha256: vec![2; 32],
                support_image_size: 1024,
            }),
            session_id: "session-00000000-0000-4000-8000-000000000003".into(),
            driver_id: "00000000-0000-4000-8000-000000000003".into(),
            expected_launch_generation: u64::MAX,
            message_id: "00000000-0000-4000-8000-000000000004".into(),
            limit: 1,
        }
    }
    fn decoder() -> RecordDecoder {
        RecordDecoder {
            expected: request(),
            offset: 0,
            total: None,
            hash: None,
            digest: Sha256::new(),
            finished: false,
            refused: false,
        }
    }
    fn frame(payload: &[u8], offset: usize, data: &[u8]) -> v1::PlatformManagedRecordChunk {
        let r = request();
        let row = v1::PlatformManagedRecordChunk {
            scope: r.scope,
            session_id: r.session_id,
            driver_id: r.driver_id,
            launch_generation: r.expected_launch_generation,
            message_id: r.message_id,
            offset: offset as u64,
            total_bytes: payload.len() as u64,
            payload_sha256: format!("{:x}", Sha256::digest(payload)),
            data: data.to_vec(),
        };
        v1::PlatformManagedRecordChunk::decode(row.encode_to_vec().as_slice()).unwrap()
    }
    #[test]
    fn platform_bridge_owned_decoder_reassembles_original_full_u64_identity_and_requires_eof() {
        let payload = vec![7; wire::FRAME_BYTES + 3];
        let split = wire::FRAME_BYTES - 4096;
        let mut d = decoder();
        let mut actual = d
            .accept(Some(frame(&payload, 0, &payload[..split])))
            .unwrap()
            .unwrap();
        actual.extend(
            d.accept(Some(frame(&payload, split, &payload[split..])))
                .unwrap()
                .unwrap(),
        );
        assert_eq!(actual, payload);
        assert!(!d.finished);
        assert!(d.accept(None).unwrap().is_none());
        assert!(d.finished);
        assert!(d.accept(Some(frame(&payload, 0, &payload[..1]))).is_err());
    }
    #[test]
    fn platform_bridge_decoder_poison_refuses_foreign_scope_generation_offsets_and_bounds() {
        let base = frame(b"body", 0, b"body");
        for field in 0..7 {
            let mut row = base.clone();
            match field {
                0 => row.scope.as_mut().unwrap().binding_generation -= 1,
                1 => row.launch_generation -= 1,
                2 => row.message_id = request().driver_id,
                3 => row.offset = 1,
                4 => row.total_bytes = wire::RECORD_BYTES as u64 + 1,
                5 => row.data.clear(),
                _ => row.data = vec![1; wire::FRAME_BYTES],
            }
            let mut d = decoder();
            assert!(d.accept(Some(row)).is_err());
            assert!(d.accept(Some(base.clone())).is_err());
            assert!(d.accept(None).is_err());
        }
    }
    #[test]
    fn platform_bridge_decoder_refuses_truncated_changed_digest_and_extra_stream_data() {
        let mut empty = decoder();
        assert!(empty.accept(None).is_err());
        let mut short = decoder();
        short.accept(Some(frame(b"body", 0, b"bo"))).unwrap();
        assert!(short.accept(None).is_err());
        let mut corrupt = decoder();
        let mut row = frame(b"body", 0, b"body");
        row.data[0] = b'x';
        corrupt.accept(Some(row)).unwrap();
        assert!(corrupt.accept(None).is_err());
        let mut extra = decoder();
        extra.accept(Some(frame(b"body", 0, b"body"))).unwrap();
        assert!(extra.accept(Some(frame(b"body", 4, b"x"))).is_err());
    }
    #[test]
    fn platform_bridge_receipt_keeps_original_request_and_reason_closed() {
        let r = request();
        let mut row = v1::PlatformManagedReceipt {
            request_id: r.message_id.clone(),
            scope: r.scope.clone(),
            fingerprint_sha256: "1".repeat(64),
            phase: 5,
            session_id: r.session_id,
            driver_id: r.driver_id,
            launch_generation: u64::MAX,
            cleanup_unknown: true,
            reason: "target-owner-lost".into(),
            ..Default::default()
        };
        assert!(verify_receipt(&row, &r.message_id, r.scope.as_ref().unwrap()).is_ok());
        row.reason = "provider-error".into();
        assert!(verify_receipt(&row, &r.message_id, r.scope.as_ref().unwrap()).is_err());
        row.reason = "target-owner-lost".into();
        row.scope.as_mut().unwrap().binding_generation -= 1;
        assert!(verify_receipt(&row, &r.message_id, r.scope.as_ref().unwrap()).is_err());
    }
}
