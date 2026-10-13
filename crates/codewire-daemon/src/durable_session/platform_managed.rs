//! Exact generation/origin fence around fixed platform Guest record helpers.
//! Next Start must publish Origin together with generation before effects;
//! ordinary Launch continues to write None and cannot adopt a managed record.
use super::*;
use crate::platform_managed::{CleanupLink, Owner, ProviderPin, RestartAdvance};
use crate::platform_managed::{Error, ImagePin, Origin, peer_packet};
use codewire_daemon_proto::platform_managed as wire;
use serde_json::{Value, json};

pub(super) fn refuse_platform_managed_bypass(
    metadata: &PersistedSession,
) -> Result<(), SessionError> {
    if metadata.platform_managed_origin.is_some() {
        return Err(SessionError::FailedPrecondition(
            "platform managed control requires its original incarnation and guardian".into(),
        ));
    }
    Ok(())
}

struct Captured {
    handle: Arc<SessionHandle>,
    control: Option<mpsc::Sender<SessionControl>>,
    token: Option<Uuid>,
}

impl SessionEngine {
    async fn ensure_platform_records(&self, create: bool) -> Result<bool, Error> {
        match std::fs::symlink_metadata(&self.inner.root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => {
                return Ok(false);
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(Error::Refused);
            }
            _ => {}
        }
        let tree = crate::platform_managed::Tree::open(&self.inner.root, create)?;
        self.ensure_initialized()
            .await
            .map_err(|_| Error::Refused)?;
        tree.check()?;
        Ok(true)
    }
    pub(crate) async fn platform_origin(
        &self,
        scope: &v1::PlatformManagedScope,
        session: &str,
        generation: u64,
        historical: bool,
    ) -> Result<Origin, Error> {
        if !self.ensure_platform_records(false).await? {
            return Err(Error::Refused);
        }
        let handle = self.handle(session).map_err(|_| Error::Refused)?;
        let _guard = handle.operation.lock().await;
        let metadata = handle.metadata.lock().await;
        checked_origin(&metadata, scope, generation, historical)
    }
    /// Restart runs the record's provider again, so it needs the provider this
    /// release runs. A record an earlier provider wrote refuses with that
    /// reason before any scope check or effect; launch admits its own origin.
    pub(crate) async fn platform_restartable(&self, session: &str) -> Result<(), Error> {
        if !self.ensure_platform_records(false).await? {
            return Err(Error::Refused);
        }
        let handle = self.handle(session).map_err(|_| Error::Refused)?;
        let metadata = handle.metadata.lock().await;
        let origin = metadata
            .platform_managed_origin
            .as_ref()
            .ok_or(Error::Refused)?;
        origin.validate_shape(&metadata.session_id)?;
        if !origin.current_provider() {
            return Err(Error::EarlierProvider(origin.agent));
        }
        Ok(())
    }
    pub(crate) async fn platform_list(
        &self,
        scope: &v1::PlatformManagedScope,
        after: &str,
        limit: usize,
    ) -> Result<v1::PlatformManagedListResponse, Error> {
        wire::validate_scope(scope).map_err(|_| Error::Refused)?;
        if !(1..=8).contains(&limit) {
            return Err(Error::Refused);
        }
        if !self.ensure_platform_records(false).await? {
            return Ok(v1::PlatformManagedListResponse::default());
        }
        let handles = lock(&self.inner.sessions)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut rows = Vec::new();
        for handle in handles {
            let metadata = handle.metadata.lock().await;
            if metadata.session_id.as_str() > after
                && metadata
                    .platform_managed_origin
                    .as_ref()
                    .is_some_and(|o| o.same_scope(scope))
            {
                checked_origin(&metadata, scope, metadata.launch_generation, false)?;
                rows.push(metadata.to_record());
            }
        }
        rows.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        let more = rows.len() > limit;
        rows.truncate(limit);
        Ok(v1::PlatformManagedListResponse {
            next_session_id: if more {
                rows.last().ok_or(Error::Refused)?.session_id.clone()
            } else {
                String::new()
            },
            sessions: rows,
        })
    }
    pub(crate) async fn platform_read(
        &self,
        r: &v1::PlatformManagedReadRequest,
    ) -> Result<Vec<u8>, Error> {
        wire::validate_read(r).map_err(|_| Error::Refused)?;
        if !self.ensure_platform_records(false).await? {
            return Err(Error::Refused);
        }
        let scope = r.scope.as_ref().ok_or(Error::Refused)?;
        let handle = self.handle(&r.session_id).map_err(|_| Error::Refused)?;
        let _operation = handle.operation.lock().await;
        let metadata = handle.metadata.lock().await;
        let origin = checked_origin(&metadata, scope, r.expected_launch_generation, true)?;
        if origin.driver_id != r.driver_id {
            return Err(Error::Refused);
        }
        let session = session_value(&metadata);
        drop(metadata);
        let image = ImagePin::admit(&self.inner.config, &origin)?;
        let packet = if r.message_id.is_empty() {
            json!({"op":"status","driver_id":r.driver_id,"session_id":r.session_id,"limit":r.limit})
        } else {
            json!({"op":"get_message","driver_id":r.driver_id,"message_id":r.message_id})
        };
        let mut value = image
            .helper(&origin, &r.session_id, r.expected_launch_generation, packet)
            .await?;
        value["session"] = session;
        let bytes = serde_json::to_vec(&value).map_err(|_| Error::Unknown)?;
        if bytes.len() > wire::RECORD_BYTES {
            return Err(Error::Unknown);
        }
        Ok(bytes)
    }
    async fn own_platform_effect<F, T>(&self, effect: F) -> Result<T, Error>
    where
        F: Future<Output = Result<T, Error>> + Send + 'static,
        T: Send + 'static,
    {
        let task = {
            let _admission = lock(&self.inner.launch_admission);
            if self.inner.shutdown.is_cancelled() {
                return Err(Error::Refused);
            }
            self.inner.launches.spawn(effect)
        };
        task.await.map_err(|_| Error::Unknown)?
    }

    pub(crate) async fn platform_mutation(
        &self,
        owner: Owner,
    ) -> Result<v1::PlatformManagedReceipt, Error> {
        let engine = self.clone();
        struct Release(Owner);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0.release();
            }
        }
        let release = Release(owner.clone());
        self.own_platform_effect(async move {
            let _release = release;
            let request = owner.request().clone();
            let result = match request.operation.as_ref().ok_or(Error::Refused)? {
                v1::platform_managed_mutation_request::Operation::Launch(l) => {
                    engine.platform_start(&owner, l.clone()).await
                }
                v1::platform_managed_mutation_request::Operation::Control(c) => {
                    engine.platform_control(&owner, c.clone()).await
                }
            };
            owner.finish(result).await
        })
        .await
    }
    async fn platform_start(
        &self,
        owner: &Owner,
        mut launch: v1::PlatformManagedLaunch,
    ) -> Result<(v1::SessionRecord, bool, bool), Error> {
        let origin = owner.launch_origin()?;
        let image = ImagePin::admit(&self.inner.config, &origin)?;
        let provider = ProviderPin::admit(origin.agent, &origin.provider)?;
        // The binding's selection is fixed for its generation, so the route
        // the private home records now stays the selected one.
        let route = origin
            .agent
            .route(self.inner.config.managed_credential_clients)
            .ok_or(Error::Refused)?;
        self.ensure_platform_records(false).await?;
        let admission = self.inner.retention_admission.lock().await;
        let session = format!("session-{}", origin.driver_id);
        if lock(&self.inner.sessions).contains_key(&session) {
            return Err(Error::Refused);
        }
        let handles = lock(&self.inner.sessions)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for h in handles {
            if !launch.name.is_empty() && h.metadata.lock().await.name == launch.name {
                return Err(Error::Refused);
            }
        }
        if launch.working_dir.is_empty() {
            launch.working_dir = match hosted_default_working_dir(&self.inner.config).await {
                Some(directory) => directory,
                None => self
                    .inner
                    .config
                    .workspace_root
                    .to_string_lossy()
                    .into_owned(),
            };
        }
        if !path_is_directory(&launch.working_dir).await {
            return Err(Error::Refused);
        }
        let parent = if launch.parent_session_id.is_empty() {
            None
        } else {
            Some(
                self.handle(&launch.parent_session_id)
                    .map_err(|_| Error::Refused)?,
            )
        };
        let _parent_operation = match &parent {
            Some(h) => Some(h.operation.lock().await),
            None => None,
        };
        if let Some(parent) = &parent {
            let metadata = parent.metadata.lock().await;
            checked_origin(
                &metadata,
                owner.request().scope.as_ref().ok_or(Error::Refused)?,
                launch.expected_parent_launch_generation,
                false,
            )?;
            if metadata.cleanup_unknown
                || metadata.state != v1::SessionLifecycleState::Running as i32
            {
                return Err(Error::Refused);
            }
        }
        let handle = Arc::new(SessionHandle {
            metadata: AsyncMutex::new(PersistedSession {
                session_id: session.clone(),
                control_origin: None,
                platform_managed_origin: Some(origin.clone()),
                launch_generation: 1,
                name: launch.name.clone(),
                parent_session_id: (!launch.parent_session_id.is_empty())
                    .then(|| launch.parent_session_id.clone()),
                state: v1::SessionLifecycleState::Starting as i32,
                command: origin.command(),
                working_dir: launch.working_dir.clone(),
                env: Vec::new(),
                environment_projection_required: false,
                pty: false,
                term: String::new(),
                width: 0,
                height: 0,
                created_at: PersistedTimestamp::now(),
                started_at: None,
                finished_at: None,
                exit_code: None,
                output_start_offset: 0,
                output_end_offset: 0,
                cleanup_confirmed: false,
                cleanup_unknown: true,
                status_message: "platform managed session starting".into(),
            }),
            output_index: Mutex::new(Vec::new()),
            operation: AsyncMutex::new(()),
            launch_cancellation: watch::channel(false).0,
        });
        let _operation = handle.operation.lock().await;
        owner.issue().await?;
        self.ensure_platform_records(true).await?;
        self.make_record_room_preserving(None)
            .await
            .map_err(|_| Error::Unknown)?;
        provider.check()?;
        image.check()?;
        let message = launch
            .prompt
            .as_ref()
            .map(|_| wire::platform_managed_initial_prompt_id(&owner.request().request_id))
            .transpose()
            .map_err(|_| Error::Refused)?;
        let value=image.helper(&origin,&session,1,json!({"op":"prepare","model":launch.model,"effort":launch.effort,"working_dir":launch.working_dir,
            "name":launch.name,"prompt":launch.prompt,"parent_session_id":launch.parent_session_id,"initial_message_id":message,"route":route})).await?;
        if value["driver_id"].as_str() != Some(origin.driver_id.as_str())
            || value["message_id"].as_str() != Some(message.as_deref().unwrap_or_default())
        {
            return Err(Error::Unknown);
        }
        let bytes =
            serde_json::to_vec(&*handle.metadata.lock().await).map_err(|_| Error::Unknown)?;
        crate::platform_managed::publish_session(&self.inner.root, &session, &bytes)?;
        lock(&self.inner.sessions).insert(session, handle.clone());
        drop(_parent_operation);
        drop(admission);
        let record = self
            .start_process(handle.clone(), &self.inner.shutdown)
            .await
            .map_err(|_| Error::Unknown)?;
        // A refused projection ends the launch before the launcher executes the
        // driver. With that cleanup confirmed nothing ran and nothing remains,
        // so it is a definite refusal (#2705), never an unknown outcome.
        if denied_before_run(&record) {
            return Err(Error::DeniedBeforeRun);
        }
        Ok((record, false, false))
    }
    async fn platform_control(
        &self,
        owner: &Owner,
        c: v1::PlatformManagedControl,
    ) -> Result<(v1::SessionRecord, bool, bool), Error> {
        if !self.ensure_platform_records(false).await? {
            return Err(Error::Refused);
        }
        let admission = self.inner.retention_admission.lock().await;
        let origin = self
            .platform_origin(
                owner.request().scope.as_ref().ok_or(Error::Refused)?,
                &c.session_id,
                c.expected_launch_generation,
                false,
            )
            .await?;
        let image = ImagePin::admit(&self.inner.config, &origin)?;
        ProviderPin::admit(origin.agent, &origin.provider)?;
        let cleanup = owner.cleanup_link().await?;
        let allow_missing = cleanup.as_ref().is_some_and(|l| l.advance.is_some());
        let engine = self.clone();
        let control = c.clone();
        let owner = owner.clone();
        self.with_platform_incarnation_inner(&origin,&c.session_id,c.expected_launch_generation,allow_missing,move |captured| async move {
            use v1::PlatformManagedAction as A;
            let action=A::try_from(control.action).map_err(|_|Error::Refused)?;
            if !matches!(action,A::Stop|A::Restart) {
                let record=captured.handle.metadata.lock().await.to_record();
                if record.state!=v1::SessionLifecycleState::Running as i32||record.cleanup_unknown||captured.control.is_none(){return Err(Error::Refused);}
            }
            if action==A::Restart {control.expected_launch_generation.checked_add(1).ok_or(Error::Refused)?;}
            let origin=captured.handle.metadata.lock().await.platform_managed_origin.clone().ok_or(Error::Refused)?;
            owner.issue().await?;
            if matches!(action,A::Stop|A::Restart) {
                if let Some(link) = &cleanup {
                    engine.platform_reconcile_cleanup(&origin, &control.session_id,
                        control.expected_launch_generation, link, &captured, &image).await?;
                }
                let shutdown = engine.platform_shutdown(&origin,&control.session_id,control.expected_launch_generation,&owner.request().request_id,&captured,&image).await?;
                if action==A::Stop {return Ok((captured.handle.metadata.lock().await.to_record(),false,false));}
                let advance = RestartAdvance::from_shutdown(owner.request(), &shutdown,
                    !lock(&engine.inner.active).contains_key(&control.session_id))?;
                let expected_peer = advance.peer()?;
                // Durable old-guardian closure BEFORE either generation changes.
                owner.record_advance(advance).await?;
                captured.handle.launch_cancellation.send_replace(false);
                {let mut metadata=captured.handle.metadata.lock().await;
                    if metadata.launch_generation!=control.expected_launch_generation||metadata.cleanup_unknown||is_live_state(metadata.state){return Err(Error::Unknown);}
                    metadata.launch_generation=metadata.launch_generation.checked_add(1).ok_or(Error::Refused)?;
                    metadata.state=v1::SessionLifecycleState::Starting as i32;metadata.started_at=None;metadata.finished_at=None;metadata.exit_code=None;
                    metadata.cleanup_unknown=true;metadata.cleanup_confirmed=false;metadata.status_message="platform managed session restarting".into();
                    persist_metadata(&engine.inner.root,&metadata).await.map_err(|_|Error::Unknown)?;
                }
                let advanced=image.helper(&origin,&control.session_id,control.expected_launch_generation,json!({"op":"advance_generation","expected_generation":control.expected_launch_generation,
                    "expected_peer":expected_peer})).await?;
                if advanced["launch_generation"].as_u64()!=control.expected_launch_generation.checked_add(1){return Err(Error::Unknown);}
                drop(admission);
                let record=engine.start_process(captured.handle.clone(),&engine.inner.shutdown).await.map_err(|_|Error::Unknown)?;
                return Ok((record,false,false));
            }
            let id=&owner.request().request_id;
            let queued=image.helper(&origin,&control.session_id,control.expected_launch_generation,json!({"op":"queue","driver_id":control.driver_id,"session_id":control.session_id,
                "message_id":id,"action":match action{A::Message=>"message",A::Steer=>"steer",A::Interrupt=>"interrupt",_=>return Err(Error::Refused)},
                "text":control.text,"reply_to":control.reply_to,"expected_turn_id":control.expected_turn_id,"expected_active_message_id":control.expected_active_message_id})).await?;
            if queued["record"]["id"].as_str()!=Some(id)||queued["record"]["platform_launch_generation"].as_u64()!=Some(control.expected_launch_generation){return Err(Error::Unknown);}
            let delivered=engine.host_managed_input(captured.control.ok_or(Error::Refused)?,crate::host_control::managed::line(&control.driver_id,id,false).map_err(|_|Error::Refused)?).await;
            image.helper(&origin,&control.session_id,control.expected_launch_generation,json!({"op":"mark_delivery","driver_id":control.driver_id,"session_id":control.session_id,
                "message_id":id,"outcome":if delivered.is_ok(){"written"}else{"ambiguous_failure"}})).await?;
            if delivered.is_err(){return Err(Error::Unknown);}
            let deadline=tokio::time::Instant::now()+Duration::from_secs(30);
            let native=loop {
                let value=image.helper(&origin,&control.session_id,control.expected_launch_generation,json!({"op":"get_message","driver_id":control.driver_id,"message_id":id})).await?;
                if value["record"]["id"].as_str()!=Some(id){return Err(Error::Unknown);}
                if value["record"]["native_acknowledged"].as_bool()==Some(true){break true;}
                if action!=A::Interrupt {break false;}
                if tokio::time::Instant::now()>=deadline {return Err(Error::Unknown);}
                tokio::time::sleep(Duration::from_millis(100)).await;
            };
            Ok((captured.handle.metadata.lock().await.to_record(),true,native))
        }).await
    }
    /// Private closure seam, not a helper/program override. Production calls
    /// it for controls; fixtures place real-child barriers around this lock.
    #[cfg(test)]
    async fn with_platform_incarnation<F, Fut, T>(
        &self,
        origin: &Origin,
        session_id: &str,
        generation: u64,
        operation: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(Captured) -> Fut,
        Fut: Future<Output = Result<T, Error>>,
    {
        self.with_platform_incarnation_inner(origin, session_id, generation, false, operation)
            .await
    }
    async fn with_platform_incarnation_inner<F, Fut, T>(
        &self,
        origin: &Origin,
        session_id: &str,
        generation: u64,
        linked_advance_cleanup: bool,
        operation: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(Captured) -> Fut,
        Fut: Future<Output = Result<T, Error>>,
    {
        origin.validate_shape(session_id)?;
        if generation == 0 {
            return Err(Error::Refused);
        }
        if !self.ensure_platform_records(false).await? {
            return Err(Error::Refused);
        }
        let handle = self.handle(session_id).map_err(|_| Error::Refused)?;
        let _operation = handle.operation.lock().await;
        let metadata = handle.metadata.lock().await;
        if metadata.platform_managed_origin.as_ref() != Some(origin)
            || metadata.control_origin.is_some()
            || metadata.launch_generation != generation
            || metadata.command != origin.command()
            || metadata.pty
            || metadata.environment_projection_required
            || !metadata.env.is_empty()
        {
            return Err(Error::Refused);
        }
        let captured = lock(&self.inner.active)
            .get(session_id)
            .map(|active| (active.token, active.control.clone()));
        if captured.is_none()
            && is_live_state(metadata.state)
            && !(linked_advance_cleanup
                && metadata.state == v1::SessionLifecycleState::Starting as i32)
        {
            return Err(Error::Refused);
        }
        drop(metadata);
        operation(Captured {
            handle: Arc::clone(&handle),
            token: captured.as_ref().map(|(token, _)| *token),
            control: captured.map(|(_, sender)| sender),
        })
        .await
    }

    async fn platform_reconcile_cleanup(
        &self,
        origin: &Origin,
        session: &str,
        generation: u64,
        link: &CleanupLink,
        captured: &Captured,
        image: &ImagePin,
    ) -> Result<(), Error> {
        let Some(witness) = &link.advance else {
            return Ok(());
        };
        let (from, to) = witness.generations();
        if from != link.previous_generation || to != generation {
            return Err(Error::Refused);
        }
        witness.current_boot()?;
        let state = image
            .helper(
                origin,
                session,
                from,
                json!({"op":"generation_status","driver_id":origin.driver_id,"session_id":session}),
            )
            .await?;
        let helper_generation = state["launch_generation"].as_u64().ok_or(Error::Unknown)?;
        if ![from, to].contains(&helper_generation) {
            return Err(Error::Unknown);
        }
        // Already-to with a new owned peer follows normal Stop. It does not
        // qualify for the old-peer, no-new-process split reconciliation.
        if helper_generation == to && state["peer"]["identity"] != witness.peer()? {
            return Ok(());
        }
        if captured.token.is_some() || lock(&self.inner.active).contains_key(session) {
            return Err(Error::Unknown);
        }
        witness.check_state(&state)?;
        if helper_generation == from {
            let advanced = image.helper(origin, session, from,
                json!({"op":"advance_generation","expected_generation":from,"expected_peer":witness.peer()?})).await?;
            if advanced["launch_generation"].as_u64() != Some(to) {
                return Err(Error::Unknown);
            }
            witness.check_state(&advanced)?;
        }
        let confirmed = image
            .helper(
                origin,
                session,
                to,
                json!({"op":"confirm_clean_generation","expected_peer":witness.peer()?}),
            )
            .await?;
        if confirmed["launch_generation"].as_u64() != Some(to) {
            return Err(Error::Unknown);
        }
        witness.check_state(&confirmed)?;
        let mut metadata = captured.handle.metadata.lock().await;
        if metadata.launch_generation != to
            || metadata.platform_managed_origin.as_ref() != Some(origin)
            || lock(&self.inner.active).contains_key(session)
            || !matches!(
                v1::SessionLifecycleState::try_from(metadata.state),
                Ok(v1::SessionLifecycleState::Starting
                    | v1::SessionLifecycleState::Interrupted
                    | v1::SessionLifecycleState::Stopped
                    | v1::SessionLifecycleState::Exited)
            )
        {
            return Err(Error::Unknown);
        }
        metadata.state = v1::SessionLifecycleState::Stopped as i32;
        metadata.exit_code = None;
        metadata.finished_at = Some(PersistedTimestamp::now());
        metadata.cleanup_unknown = false;
        metadata.cleanup_confirmed = true;
        metadata.status_message = "platform linked cleanup confirmed".into();
        persist_metadata(&self.inner.root, &metadata)
            .await
            .map_err(|_| Error::Unknown)
    }

    async fn platform_shutdown(
        &self,
        origin: &Origin,
        session: &str,
        generation: u64,
        request_id: &str,
        captured: &Captured,
        image: &ImagePin,
    ) -> Result<Value, Error> {
        let initial = image
            .helper(origin, session, generation, peer_packet(origin, session))
            .await?;
        let peer = &initial["peer"];
        let identity = peer["identity"].clone();
        let instance = identity["instance_id"].as_str().ok_or(Error::Unknown)?;
        let instance_id = uuid::Uuid::parse_str(instance).map_err(|_| Error::Unknown)?;
        if instance_id.is_nil()
            || instance_id.to_string() != instance
            || identity["environment_id"].as_str() != Some(origin.environment_id.as_str())
            || identity["driver_id"].as_str() != Some(origin.driver_id.as_str())
            || identity["session_id"].as_str() != Some(session)
            || peer["cleanup_unknown"].as_bool().is_none()
        {
            return Err(Error::Unknown);
        }
        let clean = peer["cleanup_unknown"].as_bool() == Some(false)
            && peer["finished_at"].as_str().is_some();
        // Existing intent is observe-only, even if the original RPC lost ACK.
        // Another UUID cannot take over that peer or turn uncertainty into replay.
        let has_intent = !initial["shutdown"].is_null();
        let intent_id = if has_intent {
            let id = initial["shutdown"]["operation_id"]
                .as_str()
                .ok_or(Error::Unknown)?;
            if !wire::valid_uuid(id) {
                return Err(Error::Unknown);
            }
            id.to_owned()
        } else {
            request_id.to_owned()
        };
        if !clean && !has_intent {
            image
                .helper(
                    origin,
                    session,
                    generation,
                    json!({"op":"shutdown", "driver_id":origin.driver_id,
                "session_id":session, "operation_id":request_id, "peer":identity}),
                )
                .await?;
            if let Some(control) = &captured.control {
                // Only the originally captured monitor pipe is addressed. This
                // hint does not confer native ACK or substitute for durable intent.
                let bytes = crate::host_control::managed::line(&origin.driver_id, request_id, true)
                    .map_err(|_| Error::Refused)?;
                let (reply, ack) = oneshot::channel();
                let _ = tokio::time::timeout(SESSION_INPUT_TIMEOUT, async {
                    control
                        .send(SessionControl::Input { data: bytes, reply })
                        .await
                        .map_err(|_| Error::Unknown)?;
                    ack.await
                        .map_err(|_| Error::Unknown)?
                        .map_err(|_| Error::Unknown)
                })
                .await;
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let state = image
                .helper(origin, session, generation, peer_packet(origin, session))
                .await?;
            if state["peer"]["identity"] != identity {
                return Err(Error::Unknown);
            }
            let record = captured.handle.metadata.lock().await.to_record();
            if record.launch_generation != generation {
                return Err(Error::Unknown);
            }
            let native_clean = state["peer"]["cleanup_unknown"].as_bool() == Some(false)
                && state["peer"]["finished_at"].as_str().is_some();
            let intent_clean = clean
                || (state["shutdown"]["operation_id"].as_str() == Some(intent_id.as_str())
                    && state["shutdown"]["peer"] == identity
                    && state["shutdown"]["cleanup_unknown"].as_bool() == Some(false)
                    && state["shutdown"]["finished_at"].as_str().is_some());
            let same_control = lock(&self.inner.active)
                .get(session)
                .map(|active| active.token)
                == captured.token;
            if !same_control && lock(&self.inner.active).contains_key(session) {
                return Err(Error::Unknown);
            }
            if native_clean
                && intent_clean
                && !record.cleanup_unknown
                && (record.state == v1::SessionLifecycleState::Stopped as i32
                    || (record.state == v1::SessionLifecycleState::Exited as i32
                        && record.exit_code == Some(0)))
                && !lock(&self.inner.active).contains_key(session)
            {
                return Ok(state);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Unknown);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
fn checked_origin(
    metadata: &PersistedSession,
    scope: &v1::PlatformManagedScope,
    generation: u64,
    historical: bool,
) -> Result<Origin, Error> {
    let origin = metadata
        .platform_managed_origin
        .as_ref()
        .ok_or(Error::Refused)?;
    origin.validate_shape(&metadata.session_id)?;
    if !origin.same_scope(scope)
        || metadata.control_origin.is_some()
        || generation == 0
        || metadata.launch_generation < generation
        || (!historical && metadata.launch_generation != generation)
        || metadata.command != origin.command()
        || metadata.pty
        || metadata.environment_projection_required
        || !metadata.env.is_empty()
    {
        return Err(Error::Refused);
    }
    Ok(origin.clone())
}
/// The first check a retained platform record fails on load, named without
/// its environment, command arguments or other values. Load checks shape only:
/// the provider pin of the release that wrote it is not this release's to judge.
pub(super) fn retained_record_fault(
    metadata: &PersistedSession,
    host_store: bool,
) -> Option<&'static str> {
    let origin = metadata.platform_managed_origin.as_ref()?;
    origin.shape_fault(&metadata.session_id).or_else(|| {
        [
            (host_store, "a host session store cannot hold it"),
            (
                metadata.control_origin.is_some(),
                "it also carries a host control origin",
            ),
            (
                metadata.command != origin.command(),
                "its command is not its fixed driver command",
            ),
            (
                metadata.launch_generation == 0,
                "its launch generation is zero",
            ),
            (
                !metadata.env.is_empty() || metadata.environment_projection_required,
                "it carries an environment",
            ),
            (metadata.pty, "it is a terminal session"),
        ]
        .into_iter()
        .find_map(|(failed, check)| failed.then_some(check))
    })
}
fn session_value(m: &PersistedSession) -> Value {
    let state = v1::SessionLifecycleState::try_from(m.state)
        .unwrap_or(v1::SessionLifecycleState::Unspecified);
    json!({"session_id":m.session_id,"name":m.name,"parent_session_id":m.parent_session_id.clone().unwrap_or_default(),"launch_generation":m.launch_generation,
        "state":match state{v1::SessionLifecycleState::Starting=>"starting",v1::SessionLifecycleState::Running=>"running",v1::SessionLifecycleState::Stopping=>"stopping",v1::SessionLifecycleState::Stopped=>"stopped",v1::SessionLifecycleState::Exited=>"exited",v1::SessionLifecycleState::Failed=>"failed",v1::SessionLifecycleState::Interrupted=>"interrupted",_=>"unspecified"},
        "command":m.command,"working_dir":m.working_dir,"pty":m.pty,"exit_code":m.exit_code,"cleanup_unknown":m.cleanup_unknown,"output_end_offset":m.output_end_offset,"output_start_offset":m.output_start_offset,"status_message":m.status_message})
}

/// A launch whose projection was refused, expired or cancelled before the
/// launcher executed the driver, with the launcher's cleanup confirmed.
pub(crate) fn denied_before_run(record: &v1::SessionRecord) -> bool {
    record.state == v1::SessionLifecycleState::Failed as i32
        && !record.cleanup_unknown
        && record.started_at.is_none()
        && record.exit_code.is_none()
        && record.status_message == crate::durable_session::LAUNCH_PROJECTION_DENIED
}

#[cfg(test)]
#[path = "platform_managed_tests.rs"]
mod tests;
