//! Starting a boot's isolated host network worker process: its confined
//! spawn, its bootstrap over the control socket, the guest network's
//! descriptor and the worker's readiness. Moved out of `runner.rs` unchanged.

use super::*;

pub(super) async fn spawn_network_worker_process(
    context: &NetworkStackLaunch<'_>,
    key: NetworkKey,
    attachment: WorkerBrokerAttachment,
) -> Result<NetworkWorkerProcess, RunnerError> {
    PrivateRoot::open(context.working_directory)?;
    let (bootstrap_parent, bootstrap_child) =
        StdUnixStream::pair().map_err(|_| RunnerError::NetworkWorkerSpawn)?;
    bootstrap_parent
        .set_nonblocking(true)
        .map_err(|_| RunnerError::NetworkWorkerSpawn)?;
    let mut bootstrap = tokio::net::UnixStream::from_std(bootstrap_parent)
        .map_err(|_| RunnerError::NetworkWorkerSpawn)?;
    let product_worker = matches!(&attachment, WorkerBrokerAttachment::Product { .. });
    let mesh_ingress_key = product_worker.then(fresh_mesh_ingress_control_key);
    let (bytes, broker_endpoints) = match attachment {
        WorkerBrokerAttachment::Product {
            endpoints,
            key: broker_key,
        } => (
            encode_product_worker_bootstrap(
                context.vm_id,
                context.generation,
                &key,
                &broker_key,
                mesh_ingress_key
                    .as_deref()
                    .expect("product worker has a Mesh ingress control key"),
                context
                    .mesh
                    .map(|attachment| attachment.guest_ports.as_slice())
                    .unwrap_or_default(),
                context.policy.digest(),
            )
            .map(|bytes| Zeroizing::new(bytes.to_vec())),
            Some(endpoints),
        ),
        WorkerBrokerAttachment::InjectedVerification => (
            encode_worker_bootstrap(context.vm_id, context.generation, &key)
                .map(|bytes| Zeroizing::new(bytes.to_vec())),
            None,
        ),
    };
    let bytes = bytes.map_err(|_| RunnerError::NetworkWorkerBootstrap)?;
    let inherited_bootstrap = duplicate_inherited_descriptor(bootstrap_child.as_raw_fd())
        .map_err(|_| RunnerError::NetworkWorkerSpawn)?;
    let bootstrap_fd = inherited_bootstrap.as_raw_fd();
    let expected_parent = unsafe { libc::getpid() };
    let mut command = crate::swept_tokio_command(context.executable, &[]);
    command
        .args(worker_arguments(context, product_worker))
        .env_clear()
        .current_dir(context.working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            raise_open_file_limit()?;
            prepare_isolated_child(expected_parent, &[(bootstrap_fd, NETWORK_BOOTSTRAP_FD)])
        });
    }
    let child = command
        .spawn()
        .map_err(|_| RunnerError::NetworkWorkerSpawn)?;
    drop(inherited_bootstrap);
    drop(bootstrap_child);
    let mut startup = NetworkWorkerStartup::new(child);
    let Some(pid) = startup.child_mut().id() else {
        reap_failed_network_worker_startup(&mut startup).await?;
        return Err(RunnerError::NetworkWorkerSpawn);
    };

    let bootstrap_write = tokio::time::timeout_at(context.deadline, async {
        bootstrap.write_all(bytes.as_ref()).await?;
        bootstrap.flush().await
    })
    .await;
    match bootstrap_write {
        Ok(Ok(())) => {}
        Err(_) => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerStartTimeout);
        }
        Ok(Err(_)) => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerBootstrap);
        }
    }
    drop(bytes);

    let prepared_deadline = std::cmp::min(
        context.deadline,
        tokio::time::Instant::now() + NETWORK_WORKER_READY_TIMEOUT,
    );
    let prepared = match read_worker_status_frame(&mut bootstrap, prepared_deadline).await {
        Ok(prepared) => prepared,
        Err(error) => {
            let error = classify_network_worker_startup_error(&mut startup, error).await?;
            return Err(error);
        }
    };
    if prepared.as_slice() != WORKER_PREPARED_MESSAGE {
        if let Some(NetworkWorkerStartupStatus::Failed(failure)) =
            decode_worker_startup_status(&prepared)
        {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerStartup(failure));
        }
        reap_failed_network_worker_startup(&mut startup).await?;
        return Err(RunnerError::NetworkWorkerBootstrap);
    }

    let process = match LiveProcess::capture_child(pid, context.executable) {
        Ok(process) => process,
        Err(error) => {
            let fallback = RunnerError::Recovery(error);
            let error = classify_network_worker_startup_error(&mut startup, fallback).await?;
            return Err(error);
        }
    };
    startup.admit(process);

    if let Some(endpoints) = broker_endpoints {
        // One message per session, in session order, answered together.
        let status = pass_to_worker(
            &mut startup,
            &mut bootstrap,
            endpoints,
            context.deadline,
            send_worker_broker_descriptor,
        )
        .await?;
        if status.as_slice() != WORKER_BROKER_READY_MESSAGE {
            if let Some(NetworkWorkerStartupStatus::Failed(failure)) =
                decode_worker_startup_status(&status)
            {
                reap_failed_network_worker_startup(&mut startup).await?;
                return Err(RunnerError::NetworkWorkerStartup(failure));
            }
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerBootstrap);
        }
    }

    let network = loop {
        match startup.child_mut().try_wait() {
            Ok(Some(status)) => return Err(network_worker_exit_error(status)),
            Ok(None) => {}
            Err(_) => {
                reap_failed_network_worker_startup(&mut startup).await?;
                return Err(RunnerError::NetworkWorkerWait);
            }
        }
        let connection = tokio::time::timeout_at(
            context.deadline,
            context.hybrid.connect_guest_port(GUEST_NETWORK_VSOCK_PORT),
        )
        .await;
        match connection {
            Ok(Ok(network)) => break network,
            Ok(Err(
                HybridVsockError::InvalidSocketPath
                | HybridVsockError::InvalidGuestPort
                | HybridVsockError::SocketIdentity(_),
            )) => {
                reap_failed_network_worker_startup(&mut startup).await?;
                return Err(RunnerError::NetworkWorkerBootstrap);
            }
            Ok(Err(_)) if tokio::time::Instant::now() < context.deadline => {
                tokio::time::sleep(NETWORK_WORKER_RETRY_DELAY).await;
            }
            Ok(Err(_)) | Err(_) => {
                reap_failed_network_worker_startup(&mut startup).await?;
                return Err(RunnerError::NetworkWorkerStartTimeout);
            }
        }
    };
    let network = match network.into_std() {
        Ok(network) => network,
        Err(_) => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerBootstrap);
        }
    };
    let status = pass_to_worker(
        &mut startup,
        &mut bootstrap,
        vec![network],
        context.deadline,
        send_worker_network_descriptor,
    )
    .await?;
    match decode_worker_startup_status(&status) {
        Some(NetworkWorkerStartupStatus::Ready) => {}
        Some(NetworkWorkerStartupStatus::Failed(failure)) => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerStartup(failure));
        }
        None => {
            reap_failed_network_worker_startup(&mut startup).await?;
            return Err(RunnerError::NetworkWorkerBootstrap);
        }
    }
    let ingress_control = product_worker.then_some(bootstrap);
    Ok(startup.disarm(ingress_control, mesh_ingress_key))
}

/// The worker's command and identity, and in broker mode the flag that gives
/// its session the broker /30: the guest network's addresses are the
/// runner's to choose, never the guest's (#5602).
fn worker_arguments(context: &NetworkStackLaunch<'_>, product_worker: bool) -> Vec<String> {
    let command = if product_worker {
        "__native-network-worker"
    } else {
        "__native-network-worker-fixture"
    };
    let mut arguments = vec![
        command.to_owned(),
        "--environment-id".to_owned(),
        context.vm_id.to_string(),
        "--generation".to_owned(),
        context.generation.to_string(),
    ];
    if context.hosted_broker_network {
        arguments.push("--hosted-broker-network".to_owned());
    }
    arguments
}
