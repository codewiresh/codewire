//! Nonsecret target ownership and Restart advancement provenance. The original
//! outcome is never rewritten by cleanup: one linked clean Stop receipt is the
//! atomic, durable proof that releases exactly its old barrier.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeerIdentity {
    environment_id: String,
    driver_id: String,
    session_id: String,
    instance_id: String,
    driver_started_at: String,
    boot_id: String,
    driver_pid: u32,
    driver_start_ticks: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestartAdvance {
    request_id: String,
    fingerprint: String,
    scope: Vec<u8>,
    driver: String,
    session: String,
    from: u64,
    to: u64,
    peer: PeerIdentity,
    guardian_pid: u32,
    guardian_start_ticks: u64,
    finished_at: String,
    old_cleanup_known: bool,
    old_monitor_closed: bool,
}
impl RestartAdvance {
    pub(crate) fn from_shutdown(
        request: &v1::PlatformManagedMutationRequest,
        state: &Value,
        old_monitor_closed: bool,
    ) -> Result<Self, Error> {
        let Some(v1::platform_managed_mutation_request::Operation::Control(c)) = &request.operation
        else {
            return Err(Error::Refused);
        };
        if c.action != v1::PlatformManagedAction::Restart as i32
            || c.cleanup_of_request_id.is_some()
        {
            return Err(Error::Refused);
        }
        let peer = &state["peer"];
        if peer["cleanup_unknown"].as_bool() != Some(false) {
            return Err(Error::Unknown);
        }
        let witness = Self {
            request_id: request.request_id.clone(),
            fingerprint: wire::platform_managed_request_fingerprint(request)
                .map_err(|_| Error::Refused)?,
            scope: request
                .scope
                .as_ref()
                .ok_or(Error::Refused)?
                .encode_to_vec(),
            driver: c.driver_id.clone(),
            session: c.session_id.clone(),
            from: c.expected_launch_generation,
            to: c
                .expected_launch_generation
                .checked_add(1)
                .ok_or(Error::Refused)?,
            peer: serde_json::from_value(peer["identity"].clone()).map_err(|_| Error::Unknown)?,
            guardian_pid: peer["guardian_pid"]
                .as_u64()
                .and_then(|p| p.try_into().ok())
                .ok_or(Error::Unknown)?,
            guardian_start_ticks: peer["guardian_start_ticks"]
                .as_u64()
                .ok_or(Error::Unknown)?,
            finished_at: peer["finished_at"].as_str().ok_or(Error::Unknown)?.into(),
            old_cleanup_known: true,
            old_monitor_closed,
        };
        witness.validate(request)?;
        Ok(witness)
    }
    fn validate(&self, request: &v1::PlatformManagedMutationRequest) -> Result<(), Error> {
        let Some(v1::platform_managed_mutation_request::Operation::Control(c)) = &request.operation
        else {
            return Err(Error::Refused);
        };
        let scope = request.scope.as_ref().ok_or(Error::Refused)?;
        if c.action != v1::PlatformManagedAction::Restart as i32
            || c.cleanup_of_request_id.is_some()
            || self.request_id != request.request_id
            || self.fingerprint
                != wire::platform_managed_request_fingerprint(request)
                    .map_err(|_| Error::Refused)?
            || self.scope != scope.encode_to_vec()
            || self.driver != c.driver_id
            || self.session != c.session_id
            || self.from != c.expected_launch_generation
            || self.from.checked_add(1) != Some(self.to)
            || !self.old_cleanup_known
            || !self.old_monitor_closed
            || self.peer.environment_id != scope.environment_id
            || self.peer.driver_id != self.driver
            || self.peer.session_id != self.session
            || !wire::valid_uuid(&self.peer.instance_id)
            || !wire::valid_uuid(&self.peer.boot_id)
            || self.peer.driver_pid < 2
            || self.peer.driver_start_ticks == 0
            || self.guardian_pid < 2
            || self.guardian_start_ticks == 0
            || !bounded_timestamp(&self.peer.driver_started_at)
            || !bounded_timestamp(&self.finished_at)
        {
            return Err(Error::Refused);
        }
        Ok(())
    }
    pub(crate) fn peer(&self) -> Result<Value, Error> {
        serde_json::to_value(&self.peer).map_err(|_| Error::Refused)
    }
    pub(crate) fn generations(&self) -> (u64, u64) {
        (self.from, self.to)
    }
    pub(crate) fn check_state(&self, state: &Value) -> Result<(), Error> {
        let peer = &state["peer"];
        if peer["identity"] != self.peer()?
            || peer["cleanup_unknown"].as_bool() != Some(false)
            || peer["guardian_pid"].as_u64() != Some(u64::from(self.guardian_pid))
            || peer["guardian_start_ticks"].as_u64() != Some(self.guardian_start_ticks)
            || peer["finished_at"].as_str() != Some(self.finished_at.as_str())
        {
            return Err(Error::Unknown);
        }
        Ok(())
    }
    pub(crate) fn current_boot(&self) -> Result<(), Error> {
        let file =
            std::fs::File::open("/proc/sys/kernel/random/boot_id").map_err(|_| Error::Refused)?;
        let mut boot = String::new();
        file.take(65)
            .read_to_string(&mut boot)
            .map_err(|_| Error::Refused)?;
        if boot.len() > 64 || boot.trim_end() != self.peer.boot_id {
            return Err(Error::Refused);
        }
        Ok(())
    }
}
fn bounded_timestamp(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.trim() == s && !s.chars().any(char::is_control)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Stored {
    version: u32,
    receipt: Vec<u8>,
    // 0 is Launch; no original prompt, text or launch projection. 1-6 are
    // the private control actions, 6 being Resume (#2705).
    action: i32,
    restart: Option<RestartAdvance>,
}
impl Stored {
    pub(super) fn new(
        request: &v1::PlatformManagedMutationRequest,
        receipt: &v1::PlatformManagedReceipt,
    ) -> Result<Self, Error> {
        let action = match request.operation.as_ref().ok_or(Error::Refused)? {
            v1::platform_managed_mutation_request::Operation::Launch(_) => 0,
            v1::platform_managed_mutation_request::Operation::Control(c) => c.action,
        };
        Ok(Self {
            version: 1,
            receipt: receipt.encode_to_vec(),
            action,
            restart: None,
        })
    }
    /// A Resume (#2705). Its open or unknown outcome ends its conversation,
    /// and no cleanup Stop can resolve it.
    pub(super) fn is_resume(&self) -> bool {
        self.action == v1::PlatformManagedAction::Resume as i32
    }
    pub(super) fn row(&self) -> Result<v1::PlatformManagedReceipt, Error> {
        let row = v1::PlatformManagedReceipt::decode(self.receipt.as_slice())
            .map_err(|_| Error::Refused)?;
        wire::validate_receipt(&row).map_err(|_| Error::Refused)?;
        if self.version != 1
            || !(0..=6).contains(&self.action)
            || (self.action == 0 && (row.driver_id != row.request_id || row.launch_generation != 1))
            || (matches!(self.action, 1..=3) && row.message_id != row.request_id)
            || (matches!(self.action, 4..=6) && !row.message_id.is_empty())
            || (row.cleanup_of_request_id.is_some() && self.action != 4)
        {
            return Err(Error::Refused);
        }
        if let Some(w) = &self.restart {
            w.validate(&self.restart_request(&row, w.from)?)?;
            if row.fingerprint_sha256 != w.fingerprint
                || row.launch_generation != if row.phase == 3 { w.to } else { w.from }
            {
                return Err(Error::Refused);
            }
        }
        Ok(row)
    }
    fn restart_request(
        &self,
        row: &v1::PlatformManagedReceipt,
        from: u64,
    ) -> Result<v1::PlatformManagedMutationRequest, Error> {
        if self.action != 5 || row.cleanup_of_request_id.is_some() {
            return Err(Error::Refused);
        }
        Ok(v1::PlatformManagedMutationRequest {
            request_id: row.request_id.clone(),
            scope: row.scope.clone(),
            operation: Some(v1::platform_managed_mutation_request::Operation::Control(
                v1::PlatformManagedControl {
                    action: 5,
                    session_id: row.session_id.clone(),
                    driver_id: row.driver_id.clone(),
                    expected_launch_generation: from,
                    ..Default::default()
                },
            )),
        })
    }
    pub(super) fn set_row(&mut self, row: &v1::PlatformManagedReceipt) {
        self.receipt = row.encode_to_vec();
    }
    pub(super) fn stop_request(&self) -> Result<v1::PlatformManagedMutationRequest, Error> {
        let row = self.row()?;
        if self.action != 4 {
            return Err(Error::Refused);
        }
        let request = v1::PlatformManagedMutationRequest {
            request_id: row.request_id,
            scope: row.scope,
            operation: Some(v1::platform_managed_mutation_request::Operation::Control(
                v1::PlatformManagedControl {
                    action: 4,
                    session_id: row.session_id,
                    driver_id: row.driver_id,
                    expected_launch_generation: row.launch_generation,
                    cleanup_of_request_id: row.cleanup_of_request_id,
                    ..Default::default()
                },
            )),
        };
        if wire::platform_managed_request_fingerprint(&request).map_err(|_| Error::Refused)?
            != row.fingerprint_sha256
        {
            return Err(Error::Refused);
        }
        Ok(request)
    }
    pub(super) fn write(&self, tree: &files::Tree, replace: bool) -> Result<(), Error> {
        let row = self.row()?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Unknown)?;
        tree.write(&format!("{}.bin", row.request_id), &bytes, replace)
    }
    pub(super) fn read(tree: &files::Tree, id: &str) -> Result<Option<Self>, Error> {
        if !wire::valid_uuid(id) {
            return Err(Error::Refused);
        }
        let Some(bytes) = tree.read(&format!("{id}.bin"), 128 * 1024)? else {
            return Ok(None);
        };
        let saved: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Refused)?;
        if saved.row()?.request_id != id {
            return Err(Error::Refused);
        }
        Ok(Some(saved))
    }
    pub(super) fn record_advance(
        &mut self,
        request: &v1::PlatformManagedMutationRequest,
        witness: RestartAdvance,
    ) -> Result<(), Error> {
        let row = self.row()?;
        if row.phase != 2
            || row.request_id != request.request_id
            || row.fingerprint_sha256 != witness.fingerprint
            || row.scope != request.scope
            || self.action != 5
            || self.restart.is_some()
        {
            return Err(Error::Unknown);
        }
        witness.validate(request)?;
        self.restart = Some(witness);
        Ok(())
    }
    /// The validated receipt records the selected generation; a successful
    /// Restart's immutable witness records the original request generation.
    fn original_generation(&self, row: &v1::PlatformManagedReceipt) -> Result<u64, Error> {
        match &self.restart {
            Some(witness) => Ok(witness.from), // self.row() already validated the full lineage.
            None if self.action == 5 && row.phase == 3 => Err(Error::Refused),
            None => Ok(row.launch_generation),
        }
    }
    /// Project only the fields used by the existing settlement predicate. This
    /// is neither a reconstructed mutation nor permission to repeat its effect.
    fn valid_completed_result(
        &self,
        row: &v1::PlatformManagedReceipt,
        original_generation: u64,
    ) -> bool {
        let operation = if self.action == 0 {
            v1::platform_managed_mutation_request::Operation::Launch(Default::default())
        } else {
            v1::platform_managed_mutation_request::Operation::Control(v1::PlatformManagedControl {
                action: self.action,
                expected_launch_generation: original_generation,
                ..Default::default()
            })
        };
        let request = v1::PlatformManagedMutationRequest {
            operation: Some(operation),
            ..Default::default()
        };
        let record = v1::SessionRecord {
            session_id: row.session_id.clone(),
            launch_generation: row.launch_generation,
            state: row.session_state,
            exit_code: row.exit_code,
            cleanup_unknown: row.cleanup_unknown,
            ..Default::default()
        };
        valid_settlement(
            &request,
            row,
            &record,
            row.pipe_acknowledged,
            row.native_acknowledged,
        )
    }
    pub(super) fn cleanup_for(
        &self,
        request: &v1::PlatformManagedMutationRequest,
    ) -> Result<CleanupLink, Error> {
        let row = self.row()?;
        let Some(v1::platform_managed_mutation_request::Operation::Control(c)) = &request.operation
        else {
            return Err(Error::Refused);
        };
        if !matches!(row.phase, 1 | 2 | 3 | 5)
            || c.action != 4
            || c.cleanup_of_request_id.as_deref() != Some(row.request_id.as_str())
            || row.request_id == request.request_id
            || row.scope != request.scope
            || row.session_id != c.session_id
            || row.driver_id != c.driver_id
        {
            return Err(Error::Refused);
        }
        let previous_generation = self.original_generation(&row)?;
        if row.phase == 3
            && (c.expected_launch_generation != row.launch_generation
                || !self.valid_completed_result(&row, previous_generation))
        {
            return Err(Error::Refused);
        }
        let advanced = c.expected_launch_generation != previous_generation;
        let witness = if advanced {
            let w = self.restart.as_ref().ok_or(Error::Refused)?;
            if self.action != 5
                || previous_generation.checked_add(1) != Some(c.expected_launch_generation)
                || w.from != previous_generation
                || w.to != c.expected_launch_generation
            {
                return Err(Error::Refused);
            }
            w.validate(&self.restart_request(&row, previous_generation)?)?;
            Some(w.clone())
        } else {
            None
        };
        Ok(CleanupLink {
            original: row.request_id,
            previous_generation,
            advance: witness,
        })
    }
    /// The clean Stop's own atomic record resolves the old barrier. Never
    /// terminalize, delete or edit the original Unknown/owner-lost receipt.
    pub(super) fn resolved_by(&self, stop: &Stored) -> Result<bool, Error> {
        let row = self.row()?;
        let clean = stop.row()?;
        if stop.action != 4
            || clean.phase != 3
            || clean.cleanup_unknown
            || clean.cleanup_of_request_id.as_deref() != Some(row.request_id.as_str())
            || !clean.cleanup_previous_cleanup_known
            || clean.cleanup_previous_generation != self.original_generation(&row)?
        {
            return Ok(false);
        }
        let request = v1::PlatformManagedMutationRequest {
            request_id: clean.request_id.clone(),
            scope: clean.scope.clone(),
            operation: Some(v1::platform_managed_mutation_request::Operation::Control(
                v1::PlatformManagedControl {
                    action: 4,
                    session_id: clean.session_id.clone(),
                    driver_id: clean.driver_id.clone(),
                    expected_launch_generation: clean.launch_generation,
                    cleanup_of_request_id: clean.cleanup_of_request_id.clone(),
                    ..Default::default()
                },
            )),
        };
        if wire::platform_managed_request_fingerprint(&request).map_err(|_| Error::Refused)?
            != clean.fingerprint_sha256
        {
            return Err(Error::Refused);
        }
        self.cleanup_for(&request)?;
        Ok(
            (clean.session_state == v1::SessionLifecycleState::Stopped as i32
                && clean.exit_code.is_none())
                || (clean.session_state == v1::SessionLifecycleState::Exited as i32
                    && clean.exit_code == Some(0)),
        )
    }
}
#[derive(Clone)]
pub(crate) struct CleanupLink {
    pub(crate) original: String,
    pub(crate) previous_generation: u64,
    pub(crate) advance: Option<RestartAdvance>,
}

#[cfg(test)]
mod tests {
    // Real held-file durability and private protobuf intake, with synthetic
    // custody records. This does not attest an actual provider/guardian/Pod.
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn request(
        action: i32,
        generation: u64,
        link: Option<String>,
    ) -> v1::PlatformManagedMutationRequest {
        v1::PlatformManagedMutationRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            scope: Some(v1::PlatformManagedScope {
                environment_id: uuid::Uuid::new_v4().to_string(),
                org_id: "synthetic".into(),
                pod_uid: uuid::Uuid::new_v4().to_string(),
                binding_generation: u64::MAX,
                projection_selection_sha256: vec![1; 32],
                support_image_sha256: vec![2; 32],
                support_image_size: 1024,
            }),
            operation: Some(v1::platform_managed_mutation_request::Operation::Control(
                v1::PlatformManagedControl {
                    action,
                    session_id: "session-00000000-0000-4000-8000-000000000003".into(),
                    driver_id: "00000000-0000-4000-8000-000000000003".into(),
                    expected_launch_generation: generation,
                    cleanup_of_request_id: link,
                    ..Default::default()
                },
            )),
        }
    }
    fn original() -> (v1::PlatformManagedMutationRequest, Stored, Value) {
        let r = request(5, 1, None);
        let c = match r.operation.as_ref().unwrap() {
            v1::platform_managed_mutation_request::Operation::Control(c) => c,
            _ => panic!(),
        };
        let row = v1::PlatformManagedReceipt {
            request_id: r.request_id.clone(),
            scope: r.scope.clone(),
            fingerprint_sha256: wire::platform_managed_request_fingerprint(&r).unwrap(),
            phase: 2,
            session_id: c.session_id.clone(),
            driver_id: c.driver_id.clone(),
            launch_generation: 1,
            cleanup_unknown: true,
            reason: "issued".into(),
            ..Default::default()
        };
        let state = json!({"peer":{"identity":{"environment_id":r.scope.as_ref().unwrap().environment_id,
            "driver_id":c.driver_id,"session_id":c.session_id,"instance_id":uuid::Uuid::new_v4().to_string(),
            "driver_started_at":"2026-10-05T00:00:00Z","boot_id":std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap().trim(),
            "driver_pid":42,"driver_start_ticks":100}, "guardian_pid":43,"guardian_start_ticks":101,
            "cleanup_unknown":false,"finished_at":"2026-10-05T00:00:01Z"}});
        let stored = Stored::new(&r, &row).unwrap();
        (r, stored, state)
    }
    fn stop_for(
        original: &v1::PlatformManagedMutationRequest,
        generation: u64,
    ) -> v1::PlatformManagedMutationRequest {
        let mut r = request(4, generation, Some(original.request_id.clone()));
        r.scope = original.scope.clone();
        r
    }
    fn clean_stop(original: &v1::PlatformManagedMutationRequest, generation: u64) -> Stored {
        let r = stop_for(original, generation);
        let c = match r.operation.as_ref().unwrap() {
            v1::platform_managed_mutation_request::Operation::Control(c) => c,
            _ => panic!(),
        };
        let row = v1::PlatformManagedReceipt {
            request_id: r.request_id.clone(),
            scope: r.scope.clone(),
            fingerprint_sha256: wire::platform_managed_request_fingerprint(&r).unwrap(),
            phase: 3,
            session_id: c.session_id.clone(),
            driver_id: c.driver_id.clone(),
            launch_generation: generation,
            session_state: v1::SessionLifecycleState::Stopped as i32,
            cleanup_unknown: false,
            reason: "settled".into(),
            cleanup_of_request_id: c.cleanup_of_request_id.clone(),
            cleanup_previous_generation: 1,
            cleanup_previous_cleanup_known: true,
            ..Default::default()
        };
        Stored::new(&r, &row).unwrap()
    }
    fn completed_control(action: i32) -> (v1::PlatformManagedMutationRequest, Stored) {
        let mut r = request(action, 1, None);
        if let Some(v1::platform_managed_mutation_request::Operation::Control(c)) = &mut r.operation
            && action == 1
        {
            c.text = "synthetic original text; never persisted".into();
        }
        let row = v1::PlatformManagedReceipt {
            request_id: r.request_id.clone(),
            scope: r.scope.clone(),
            fingerprint_sha256: wire::platform_managed_request_fingerprint(&r).unwrap(),
            phase: 3,
            reason: "settled".into(),
            session_id: "session-00000000-0000-4000-8000-000000000003".into(),
            driver_id: "00000000-0000-4000-8000-000000000003".into(),
            message_id: if action == 1 {
                r.request_id.clone()
            } else {
                String::new()
            },
            launch_generation: 1,
            session_state: if action == 1 {
                v1::SessionLifecycleState::Running as i32
            } else {
                v1::SessionLifecycleState::Stopped as i32
            },
            cleanup_unknown: false,
            pipe_acknowledged: action == 1,
            ..Default::default()
        };
        let stored = Stored::new(&r, &row).unwrap();
        (r, stored)
    }
    fn mark_unknown(saved: &mut Stored) {
        let mut row = saved.row().unwrap();
        row.phase = 5;
        row.reason = "issued-outcome-unknown".into();
        saved.set_row(&row);
    }
    #[test]
    fn platform_book_reads_back_a_resume_in_every_phase() {
        // #2705: a stored Resume is read back by issue, finish, observe and
        // every later request's barrier check, so it must be a valid row.
        let r = request(v1::PlatformManagedAction::Resume as i32, 4, None);
        let mut row = v1::PlatformManagedReceipt {
            request_id: r.request_id.clone(),
            scope: r.scope.clone(),
            fingerprint_sha256: "7".repeat(64),
            phase: 1,
            reason: "pending".into(),
            session_id: "session-00000000-0000-4000-8000-000000000003".into(),
            driver_id: "00000000-0000-4000-8000-000000000003".into(),
            launch_generation: 4,
            cleanup_unknown: true,
            ..Default::default()
        };
        let mut stored = Stored::new(&r, &row).unwrap();
        assert_eq!(stored.row().unwrap(), row);
        for (phase, reason, generation, cleanup_unknown) in [
            (2, "issued", 4, true),
            (3, "settled", 5, false),
            (4, "refused-before-issue", 4, false),
            (4, "resume-driver-alive", 4, false),
            (5, "issued-outcome-unknown", 4, true),
        ] {
            row.phase = phase;
            row.reason = reason.into();
            row.launch_generation = generation;
            row.cleanup_unknown = cleanup_unknown;
            stored.set_row(&row);
            assert_eq!(stored.row().unwrap(), row, "{phase} {reason}");
        }
        // A Resume names no message, and no action past Resume is stored.
        row.message_id = r.request_id.clone();
        stored.set_row(&row);
        assert!(stored.row().is_err());
        row.message_id.clear();
        let mut unknown = request(7, 4, None);
        unknown.request_id = r.request_id.clone();
        let stored = Stored::new(&unknown, &row).unwrap();
        assert!(stored.row().is_err());
    }
    #[test]
    fn platform_book_completed_message_or_stop_lost_ack_cleanup_preserves_original_bytes() {
        for action in [1, 4] {
            let (original, saved) = completed_control(action);
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let tree = files::Tree::open(root.path(), false).unwrap();
            saved.write(&tree, false).unwrap();
            let path = root.path().join(format!("{}.bin", original.request_id));
            let before = std::fs::read(&path).unwrap();
            let read = Stored::read(&tree, &original.request_id).unwrap().unwrap();
            let stop = stop_for(&original, 1);
            let link = read.cleanup_for(&stop).unwrap();
            assert_eq!(link.previous_generation, 1);
            assert!(link.advance.is_none());
            let mut prior = clean_stop(&original, 1);
            let mut row = prior.row().unwrap();
            row.phase = 5;
            row.reason = "issued-outcome-unknown".into();
            row.cleanup_unknown = true;
            row.cleanup_previous_cleanup_known = false;
            prior.set_row(&row);
            let books = vec![read.clone(), prior.clone()];
            assert!(Service::enforce_barriers(&books, &stop, Some(&link)).is_ok());
            assert!(Service::enforce_barriers(&books, &stop, None).is_err());
            let clean = clean_stop(&original, 1);
            clean.write(&tree, false).unwrap();
            let clean = Stored::read(&tree, &clean.row().unwrap().request_id)
                .unwrap()
                .unwrap();
            assert!(read.resolved_by(&clean).unwrap());
            assert_eq!(before, std::fs::read(&path).unwrap());
            assert_eq!(read.row().unwrap().phase, 3);
            assert_eq!(prior.row().unwrap().phase, 5);
            assert!(read.cleanup_for(&stop_for(&original, 2)).is_err());
        }
    }
    #[test]
    fn platform_book_completed_restart_lost_ack_uses_original_witness_generation_only() {
        let (original, mut saved, state) = original();
        saved
            .record_advance(
                &original,
                RestartAdvance::from_shutdown(&original, &state, true).unwrap(),
            )
            .unwrap();
        let mut row = saved.row().unwrap();
        row.phase = 3;
        row.reason = "settled".into();
        row.launch_generation = 2;
        row.session_state = v1::SessionLifecycleState::Running as i32;
        row.cleanup_unknown = false;
        saved.set_row(&row);
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let tree = files::Tree::open(root.path(), false).unwrap();
        saved.write(&tree, false).unwrap();
        let path = root.path().join(format!("{}.bin", original.request_id));
        let before = std::fs::read(&path).unwrap();
        let observed = Stored::read(&tree, &original.request_id).unwrap().unwrap();
        let link = observed.cleanup_for(&stop_for(&original, 2)).unwrap();
        assert_eq!(link.previous_generation, 1);
        assert_eq!(link.advance.unwrap().generations(), (1, 2));
        let clean = clean_stop(&original, 2);
        clean.write(&tree, false).unwrap();
        assert!(
            observed
                .resolved_by(
                    &Stored::read(&tree, &clean.row().unwrap().request_id)
                        .unwrap()
                        .unwrap()
                )
                .unwrap()
        );
        assert_eq!(before, std::fs::read(&path).unwrap());
        assert!(observed.cleanup_for(&stop_for(&original, 1)).is_err());
        assert!(observed.cleanup_for(&stop_for(&original, 3)).is_err());
        let mut missing = observed.clone();
        missing.restart = None;
        assert!(missing.cleanup_for(&stop_for(&original, 2)).is_err());
        let mut corrupt = observed.clone();
        corrupt.restart.as_mut().unwrap().old_cleanup_known = false;
        assert!(corrupt.cleanup_for(&stop_for(&original, 2)).is_err());
    }
    #[test]
    fn platform_book_completed_cleanup_refuses_invalid_result_scope_and_active_owner() {
        let (original, saved) = completed_control(1);
        let stop = stop_for(&original, 1);
        for field in 0..4 {
            let mut invalid = saved.clone();
            let mut row = invalid.row().unwrap();
            match field {
                0 => row.pipe_acknowledged = false,
                1 => row.cleanup_unknown = true,
                2 => row.session_state = v1::SessionLifecycleState::Starting as i32,
                _ => {
                    row.phase = 4;
                    row.reason = "refused-before-issue".into();
                    row.pipe_acknowledged = false;
                }
            }
            invalid.set_row(&row);
            assert!(invalid.cleanup_for(&stop).is_err());
        }
        let (stopped, mut invalid) = completed_control(4);
        let mut row = invalid.row().unwrap();
        row.session_state = v1::SessionLifecycleState::Exited as i32;
        row.exit_code = Some(1);
        invalid.set_row(&row);
        assert!(invalid.cleanup_for(&stop_for(&stopped, 1)).is_err());
        let mut foreign = stop.clone();
        foreign.scope.as_mut().unwrap().binding_generation -= 1;
        assert!(saved.cleanup_for(&foreign).is_err());
        let mut wrong = stop.clone();
        wrong.request_id = original.request_id.clone();
        assert!(saved.cleanup_for(&wrong).is_err());
        let root = tempfile::tempdir().unwrap();
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: root.path().into(),
            home_root: root.path().into(),
            mount_roots: Vec::new(),
            auth_token: crate::DaemonAuthToken::new("synthetic-owner").unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
        };
        let service = Service {
            inner: Arc::new(Inner {
                engine: SessionEngine::new(
                    &config,
                    crate::credential_bridge::CredentialBridge::new(None),
                ),
                config,
                pod_uid: uuid::Uuid::new_v4().to_string(),
                gate: Mutex::new(()),
                active: std::sync::Mutex::new(BTreeSet::from([original.request_id.clone()])),
            }),
        };
        assert!(
            service
                .cleanup_link(std::slice::from_ref(&saved), &stop)
                .is_err()
        );
        service.inner.active.lock().unwrap().clear();
        assert!(service.cleanup_link(&[saved], &stop).unwrap().is_some());
    }
    #[test]
    fn platform_book_restart_advance_requires_issued_exact_request_and_clean_peer_before_generation()
     {
        let (r, mut saved, state) = original();
        let witness = RestartAdvance::from_shutdown(&r, &state, true).unwrap();
        assert!(RestartAdvance::from_shutdown(&r, &state, false).is_err());
        saved.record_advance(&r, witness.clone()).unwrap();
        assert!(saved.record_advance(&r, witness).is_err());
        assert!(saved.cleanup_for(&stop_for(&r, 2)).is_ok());
        let (_, without, _) = original();
        let mut missing = saved.clone();
        missing.restart = None;
        assert!(missing.cleanup_for(&stop_for(&r, 2)).is_err());
        assert!(without.cleanup_for(&stop_for(&r, 2)).is_err());
        let mut dirty = state.clone();
        dirty["peer"]["cleanup_unknown"] = json!(true);
        assert!(RestartAdvance::from_shutdown(&r, &dirty, true).is_err());
        let mut wrong = r.clone();
        wrong.scope.as_mut().unwrap().binding_generation -= 1;
        assert!(saved.restart.as_ref().unwrap().validate(&wrong).is_err());
        let mut jumped = stop_for(&r, 3);
        assert!(saved.cleanup_for(&jumped).is_err());
        jumped.scope.as_mut().unwrap().pod_uid = uuid::Uuid::new_v4().to_string();
        assert!(saved.cleanup_for(&jumped).is_err());
    }
    #[test]
    fn platform_book_lost_ack_clean_link_resolves_only_exact_barrier_without_rewriting_unknown() {
        let (r, mut saved, state) = original();
        saved
            .record_advance(&r, RestartAdvance::from_shutdown(&r, &state, true).unwrap())
            .unwrap();
        mark_unknown(&mut saved);
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let tree = files::Tree::open(root.path(), false).unwrap();
        saved.write(&tree, false).unwrap();
        let original_path = root.path().join(format!("{}.bin", r.request_id));
        let before = std::fs::read(&original_path).unwrap();
        let cleanup = clean_stop(&r, 2);
        cleanup.write(&tree, false).unwrap();
        let observed = Stored::read(&tree, &cleanup.row().unwrap().request_id)
            .unwrap()
            .unwrap();
        assert!(saved.resolved_by(&observed).unwrap());
        assert_eq!(before, std::fs::read(&original_path).unwrap());
        assert_eq!(
            Stored::read(&tree, &r.request_id)
                .unwrap()
                .unwrap()
                .row()
                .unwrap()
                .phase,
            5
        );
        let books = Service::books(&tree, root.path()).unwrap();
        let mut next = request(5, 2, None);
        next.scope = r.scope.clone();
        assert!(Service::enforce_barriers(&books, &next, None).is_ok());
        let mut corrupt = observed.clone();
        let mut row = corrupt.row().unwrap();
        row.cleanup_previous_cleanup_known = false;
        corrupt.set_row(&row);
        assert!(saved.resolved_by(&corrupt).is_err());
    }
    #[test]
    fn platform_book_same_generation_cleanup_and_prior_linked_unknown_preserve_original_outcomes() {
        let (r, mut saved, _) = original();
        mark_unknown(&mut saved);
        let mut prior = clean_stop(&r, 1);
        let mut row = prior.row().unwrap();
        row.phase = 5;
        row.reason = "issued-outcome-unknown".into();
        row.cleanup_unknown = true;
        row.cleanup_previous_cleanup_known = false;
        prior.set_row(&row);
        let before = saved.receipt.clone();
        let prior_before = prior.receipt.clone();
        let books = vec![saved.clone(), prior.clone()];
        let fresh = stop_for(&r, 1);
        let link = saved.cleanup_for(&fresh).unwrap();
        assert!(Service::enforce_barriers(&books, &fresh, Some(&link)).is_ok());
        let clean = clean_stop(&r, 1);
        assert!(
            Service::enforce_barriers(&[saved.clone(), prior.clone(), clean], &r, None).is_ok()
        );
        assert_eq!(saved.receipt, before);
        assert_eq!(prior.receipt, prior_before);
        assert!(Service::enforce_barriers(&books, &r, None).is_err());
    }
    #[test]
    fn platform_book_advance_witness_refuses_peer_birth_boot_cleanup_and_fingerprint_drift() {
        let (r, mut saved, state) = original();
        saved
            .record_advance(&r, RestartAdvance::from_shutdown(&r, &state, true).unwrap())
            .unwrap();
        for field in 0..5 {
            let mut corrupt = saved.clone();
            let w = corrupt.restart.as_mut().unwrap();
            match field {
                0 => w.old_cleanup_known = false,
                1 => w.to = 3,
                2 => w.peer.driver_start_ticks = 0,
                3 => w.fingerprint = "f".repeat(64),
                _ => w.scope[0] ^= 1,
            };
            assert!(corrupt.row().is_err());
        }
        let witness = saved.restart.as_ref().unwrap();
        witness.current_boot().unwrap();
        let mut changed = state.clone();
        changed["peer"]["guardian_start_ticks"] = json!(102);
        assert!(witness.check_state(&changed).is_err());
        let mut changed = witness.clone();
        changed.peer.boot_id = uuid::Uuid::new_v4().to_string();
        assert!(changed.current_boot().is_err());
        let (mut overflow, _, state) = original();
        let Some(v1::platform_managed_mutation_request::Operation::Control(c)) =
            &mut overflow.operation
        else {
            panic!()
        };
        c.expected_launch_generation = u64::MAX;
        assert!(RestartAdvance::from_shutdown(&overflow, &state, true).is_err());
    }
    #[test]
    fn platform_book_active_original_or_prior_cleanup_owner_cannot_be_taken_over() {
        let (r, mut saved, _) = original();
        mark_unknown(&mut saved);
        let root = tempfile::tempdir().unwrap();
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: root.path().into(),
            home_root: root.path().into(),
            mount_roots: Vec::new(),
            auth_token: crate::DaemonAuthToken::new("synthetic-owner").unwrap(),
            process_execution: ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
        };
        // Only the in-memory admission predicate, not availability, Info,
        // original channel or actual provider launch, is under test here.
        let service = Service {
            inner: Arc::new(Inner {
                engine: SessionEngine::new(
                    &config,
                    crate::credential_bridge::CredentialBridge::new(None),
                ),
                config,
                pod_uid: uuid::Uuid::new_v4().to_string(),
                gate: Mutex::new(()),
                active: std::sync::Mutex::new(BTreeSet::from([r.request_id.clone()])),
            }),
        };
        let stop = stop_for(&r, 1);
        assert!(service.cleanup_link(&[saved.clone()], &stop).is_err());
        service.inner.active.lock().unwrap().clear();
        assert!(
            service
                .cleanup_link(&[saved.clone()], &stop)
                .unwrap()
                .is_some()
        );
        let mut prior = clean_stop(&r, 1);
        let mut row = prior.row().unwrap();
        row.phase = 2;
        row.reason = "issued".into();
        row.cleanup_unknown = true;
        row.cleanup_previous_cleanup_known = false;
        prior.set_row(&row);
        service.inner.active.lock().unwrap().insert(row.request_id);
        assert!(service.cleanup_link(&[saved, prior], &stop).is_err());
    }
}
