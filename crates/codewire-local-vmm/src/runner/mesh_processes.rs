//! Starting an environment's Mesh transport and Mesh enrollment broker
//! processes, each confined and bootstrapped over its own control socket.

use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use std::process::Stdio;

use crate::host::process::LiveProcess;

use super::{
    MESH_ENROLLMENT_BOOTSTRAP_FD, MESH_ENROLLMENT_PREPARED_MESSAGE,
    MESH_ENROLLMENT_STATUS_MAX_BYTES, MESH_ENROLLMENT_TRANSFER_FD, MESH_TRANSPORT_BOOTSTRAP_FD,
    MESH_TRANSPORT_ENROLLMENT_FD, MESH_TRANSPORT_PREPARED_MESSAGE, MESH_TRANSPORT_STATUS_MAX_BYTES,
    MeshAttachment, MeshEnrollmentStartupStatus, MeshProcessStartup, MeshStatusReadError,
    MeshTransportStartupStatus, NetworkStackLaunch, PreparedMeshEnrollment, PreparedMeshTransport,
    RunnerError, decode_mesh_enrollment_startup_status, decode_mesh_transport_startup_status,
    duplicate_inherited_descriptor, encode_mesh_enrollment_bootstrap,
    encode_mesh_transport_bootstrap, fresh_mesh_ingress_control_key, mesh_enrollment_exit_or,
    mesh_transport_exit_or, prepare_isolated_child_pair, read_mesh_status_frame,
    reap_failed_mesh_process_startup, write_mesh_control_frame,
};

pub(super) async fn spawn_mesh_transport_process(
    context: &NetworkStackLaunch<'_>,
    attachment: &MeshAttachment,
    enrollment: StdUnixStream,
    deadline: tokio::time::Instant,
) -> Result<PreparedMeshTransport, RunnerError> {
    let submission_key = fresh_mesh_ingress_control_key();
    let bootstrap = encode_mesh_transport_bootstrap(
        context.vm_id,
        context.generation,
        attachment,
        &submission_key,
    )
    .map_err(|_| RunnerError::MeshTransportBootstrap)?;
    let (control_parent, control_child) =
        StdUnixStream::pair().map_err(|_| RunnerError::MeshTransportSpawn)?;
    control_parent
        .set_nonblocking(true)
        .map_err(|_| RunnerError::MeshTransportSpawn)?;
    let mut control = tokio::net::UnixStream::from_std(control_parent)
        .map_err(|_| RunnerError::MeshTransportSpawn)?;
    let inherited_control = duplicate_inherited_descriptor(control_child.as_raw_fd())
        .map_err(|_| RunnerError::MeshTransportSpawn)?;
    let inherited_enrollment = duplicate_inherited_descriptor(enrollment.as_raw_fd())
        .map_err(|_| RunnerError::MeshTransportSpawn)?;
    let expected_parent = unsafe { libc::getpid() };
    let mut command = crate::swept_tokio_command(context.executable, &[]);
    command
        .arg("__native-mesh-transport")
        .arg("--environment-id")
        .arg(context.vm_id.to_string())
        .arg("--generation")
        .arg(context.generation.to_string())
        .env_clear()
        .current_dir(context.working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let control_fd = inherited_control.as_raw_fd();
    let enrollment_fd = inherited_enrollment.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            prepare_isolated_child_pair(
                expected_parent,
                control_fd,
                MESH_TRANSPORT_BOOTSTRAP_FD,
                enrollment_fd,
                MESH_TRANSPORT_ENROLLMENT_FD,
            )
        });
    }
    let child = command
        .spawn()
        .map_err(|_| RunnerError::MeshTransportSpawn)?;
    drop(inherited_control);
    drop(inherited_enrollment);
    drop(control_child);
    drop(enrollment);
    let mut startup = MeshProcessStartup::new(child);
    let Some(pid) = startup.child_mut().id() else {
        reap_failed_mesh_process_startup(&mut startup).await?;
        return Err(RunnerError::MeshTransportSpawn);
    };
    if let Err(error) = write_mesh_control_frame(&mut control, bootstrap.as_ref(), deadline).await {
        return match error {
            MeshStatusReadError::Timeout => {
                reap_failed_mesh_process_startup(&mut startup).await?;
                Err(RunnerError::MeshTransportStartTimeout)
            }
            MeshStatusReadError::Protocol => Err(mesh_transport_exit_or(
                &mut startup,
                RunnerError::MeshTransportBootstrap,
            )
            .await?),
        };
    }
    let prepared =
        match read_mesh_status_frame(&mut control, MESH_TRANSPORT_STATUS_MAX_BYTES, deadline).await
        {
            Ok(prepared) => prepared,
            Err(MeshStatusReadError::Timeout) => {
                reap_failed_mesh_process_startup(&mut startup).await?;
                return Err(RunnerError::MeshTransportStartTimeout);
            }
            Err(MeshStatusReadError::Protocol) => {
                return Err(mesh_transport_exit_or(
                    &mut startup,
                    RunnerError::MeshTransportBootstrap,
                )
                .await?);
            }
        };
    if prepared.as_slice() != MESH_TRANSPORT_PREPARED_MESSAGE {
        let error = decode_mesh_transport_startup_status(&prepared).map_or(
            RunnerError::MeshTransportBootstrap,
            |status| match status {
                MeshTransportStartupStatus::Confined | MeshTransportStartupStatus::Ready => {
                    RunnerError::MeshTransportBootstrap
                }
                MeshTransportStartupStatus::Failed(failure) => {
                    RunnerError::MeshTransportStartup(failure)
                }
            },
        );
        reap_failed_mesh_process_startup(&mut startup).await?;
        return Err(error);
    }
    let process = match LiveProcess::capture_child(pid, context.executable) {
        Ok(process) => process,
        Err(error) => {
            let fallback = RunnerError::Recovery(error);
            return Err(mesh_transport_exit_or(&mut startup, fallback).await?);
        }
    };
    startup.admit(process);
    Ok(PreparedMeshTransport {
        startup,
        control,
        submission_key,
    })
}

pub(super) async fn spawn_mesh_enrollment_process(
    context: &NetworkStackLaunch<'_>,
    attachment: &MeshAttachment,
    mesh_data_dir: &Path,
    platform_config_dir: &Path,
    transfer: StdUnixStream,
    deadline: tokio::time::Instant,
) -> Result<PreparedMeshEnrollment, RunnerError> {
    let bootstrap = encode_mesh_enrollment_bootstrap(context.vm_id, context.generation, attachment)
        .map_err(|_| RunnerError::MeshEnrollmentBrokerBootstrap)?;
    let (control_parent, control_child) =
        StdUnixStream::pair().map_err(|_| RunnerError::MeshEnrollmentBrokerSpawn)?;
    control_parent
        .set_nonblocking(true)
        .map_err(|_| RunnerError::MeshEnrollmentBrokerSpawn)?;
    let mut control = tokio::net::UnixStream::from_std(control_parent)
        .map_err(|_| RunnerError::MeshEnrollmentBrokerSpawn)?;
    let inherited_control = duplicate_inherited_descriptor(control_child.as_raw_fd())
        .map_err(|_| RunnerError::MeshEnrollmentBrokerSpawn)?;
    let inherited_transfer = duplicate_inherited_descriptor(transfer.as_raw_fd())
        .map_err(|_| RunnerError::MeshEnrollmentBrokerSpawn)?;
    let expected_parent = unsafe { libc::getpid() };
    let mut command = crate::swept_tokio_command(context.executable, &[]);
    command
        .arg("__native-mesh-enrollment-broker")
        .arg("--environment-id")
        .arg(context.vm_id.to_string())
        .arg("--generation")
        .arg(context.generation.to_string())
        .arg("--mesh-data-dir")
        .arg(mesh_data_dir)
        .arg("--platform-config-dir")
        .arg(platform_config_dir)
        .env_clear()
        .current_dir(context.working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let control_fd = inherited_control.as_raw_fd();
    let transfer_fd = inherited_transfer.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            prepare_isolated_child_pair(
                expected_parent,
                control_fd,
                MESH_ENROLLMENT_BOOTSTRAP_FD,
                transfer_fd,
                MESH_ENROLLMENT_TRANSFER_FD,
            )
        });
    }
    let child = command
        .spawn()
        .map_err(|_| RunnerError::MeshEnrollmentBrokerSpawn)?;
    drop(inherited_control);
    drop(inherited_transfer);
    drop(control_child);
    drop(transfer);
    let mut startup = MeshProcessStartup::new(child);
    let Some(pid) = startup.child_mut().id() else {
        reap_failed_mesh_process_startup(&mut startup).await?;
        return Err(RunnerError::MeshEnrollmentBrokerSpawn);
    };
    if let Err(error) = write_mesh_control_frame(&mut control, &bootstrap, deadline).await {
        return match error {
            MeshStatusReadError::Timeout => {
                reap_failed_mesh_process_startup(&mut startup).await?;
                Err(RunnerError::MeshEnrollmentBrokerStartTimeout)
            }
            MeshStatusReadError::Protocol => Err(mesh_enrollment_exit_or(
                &mut startup,
                RunnerError::MeshEnrollmentBrokerBootstrap,
            )
            .await?),
        };
    }
    let prepared = match read_mesh_status_frame(
        &mut control,
        MESH_ENROLLMENT_STATUS_MAX_BYTES,
        deadline,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(MeshStatusReadError::Timeout) => {
            reap_failed_mesh_process_startup(&mut startup).await?;
            return Err(RunnerError::MeshEnrollmentBrokerStartTimeout);
        }
        Err(MeshStatusReadError::Protocol) => {
            return Err(mesh_enrollment_exit_or(
                &mut startup,
                RunnerError::MeshEnrollmentBrokerBootstrap,
            )
            .await?);
        }
    };
    if prepared.as_slice() != MESH_ENROLLMENT_PREPARED_MESSAGE {
        let error = decode_mesh_enrollment_startup_status(&prepared).map_or(
            RunnerError::MeshEnrollmentBrokerBootstrap,
            |status| match status {
                MeshEnrollmentStartupStatus::Ready => RunnerError::MeshEnrollmentBrokerBootstrap,
                MeshEnrollmentStartupStatus::Failed(failure) => {
                    RunnerError::MeshEnrollmentBrokerStartup(failure)
                }
            },
        );
        reap_failed_mesh_process_startup(&mut startup).await?;
        return Err(error);
    }
    let process = match LiveProcess::capture_child(pid, context.executable) {
        Ok(process) => process,
        Err(error) => {
            let fallback = RunnerError::Recovery(error);
            return Err(mesh_enrollment_exit_or(&mut startup, fallback).await?);
        }
    };
    startup.admit(process);
    Ok(PreparedMeshEnrollment { startup, control })
}
