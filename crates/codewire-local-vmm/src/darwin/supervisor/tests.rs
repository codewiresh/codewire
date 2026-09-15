use super::*;

use std::fs;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::PathBuf;

use crate::control::v1::local_supervisor_service_client::LocalSupervisorServiceClient;
use crate::darwin::store::tests::{Fixture, environment, protected_rows};
use crate::supervisor_client::{NativeSupervisorClient, SupervisorClientError};
use crate::supervisor_config::NATIVE_SUPERVISOR_PROTOCOL_VERSION;
use crate::uds::connect_owner_only;

fn config(fixture: &Fixture) -> NativeRuntimeConfig {
    let parent = fixture.path.parent().unwrap();
    NativeRuntimeConfig {
        root: fixture.path.clone(),
        artifact_root: parent.join("synthetic-artifacts"),
        artifact_lock: parent.join("synthetic-artifacts.lock"),
        mesh_data_dir: parent.join("synthetic-mesh"),
        platform_config_dir: parent.join("synthetic-platform"),
        credential_authority_root: parent.join("synthetic-credentials-never-opened"),
        executable: fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
    }
}

struct Running {
    config: NativeRuntimeConfig,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), SupervisorError>>,
    retain: Arc<AtomicBool>,
}

impl Running {
    async fn start(fixture: &Fixture) -> Self {
        let config = config(fixture);
        let (stop, stopped) = oneshot::channel();
        let service_config = config.clone();
        let task = tokio::spawn(serve_until(service_config, async {
            let _ = stopped.await;
        }));
        let running = Self {
            config,
            stop: Some(stop),
            task,
            retain: fixture.retain.clone(),
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while !running.config.supervisor_socket().exists() {
                assert!(
                    !running.task.is_finished(),
                    "native service exited before binding its socket"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("native service did not bind within its startup bound");
        running
    }

    async fn client(&self) -> NativeSupervisorClient {
        NativeSupervisorClient::connect_admitted(
            &self.config.supervisor_socket(),
            Some(self.config.configuration_digest()),
        )
        .await
        .unwrap()
    }

    async fn raw_client(&self) -> LocalSupervisorServiceClient<tonic::transport::Channel> {
        LocalSupervisorServiceClient::new(
            connect_owner_only(&self.config.supervisor_socket())
                .await
                .unwrap(),
        )
    }

    async fn shutdown(mut self) -> Result<(), SupervisorError> {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(8), &mut self.task)
            .await
            .expect("native service exceeded its bounded shutdown")
            .unwrap()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        // Only this test's task is aborted on assertion failure. Successful
        // tests always use and assert the actual graceful shutdown path.
        if !self.task.is_finished() {
            self.retain.store(true, Ordering::SeqCst);
            self.task.abort();
        }
    }
}

macro_rules! bounded_test {
    ($name:ident, $body:block) => {
        #[tokio::test]
        async fn $name() {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            tokio::time::timeout_at(deadline, async $body)
                .await.expect("native RPC test exceeded its complete lifecycle bound");
            assert!(tokio::time::Instant::now() < deadline,
                "native RPC test completed beyond its complete lifecycle bound");
        }
    };
}

bounded_test!(
    shared_client_reads_selects_and_reopens_complete_metadata_over_private_socket,
    {
        let fixture = Fixture::new();
        let alpha = environment("alpha");
        let beta = environment("beta");
        fixture.seed(&[alpha.clone(), beta.clone()]);
        let mut protected = Vec::new();
        fixture.edit(|connection| protected = protected_rows(connection));
        let running = Running::start(&fixture).await;
        let metadata = fs::symlink_metadata(running.config.supervisor_socket()).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let mut raw = running.raw_client().await;
        let info = raw
            .get_supervisor_info(v1::GetSupervisorInfoRequest {})
            .await
            .unwrap()
            .into_inner();
        assert_eq!(info.protocol_version, NATIVE_SUPERVISOR_PROTOCOL_VERSION);
        assert_eq!(
            info.configuration_sha256,
            running.config.configuration_digest()
        );
        drop(raw);
        let mut client = running.client().await;
        let listed = client.list().await.unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|record| record.name.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
        assert!(
            listed
                .iter()
                .all(|record| !record.selected
                    && record.state == v1::EnvironmentState::Stopped as i32)
        );
        let read = client.get("beta").await.unwrap();
        assert_eq!(read.id, beta.id.to_string());
        assert_eq!(
            read.project_spec_json,
            beta.project_spec_json.clone().unwrap()
        );
        assert_eq!(
            read.project_spec_sha256,
            beta.project_spec_sha256.clone().unwrap()
        );
        assert_eq!(
            read.workspace_plan_sha256,
            beta.workspace_plan.sha256().unwrap()
        );
        assert_eq!(read.workspace_input_count, 1);
        assert_eq!(read.generation, beta.generation);
        let selected = client.select("beta", &beta.id.to_string()).await.unwrap();
        assert!(selected.selected);
        assert_eq!(selected.id, beta.id.to_string());
        assert!(!client.get("alpha").await.unwrap().selected);
        assert!(client.get("beta").await.unwrap().selected);
        drop(client);
        let socket = running.config.supervisor_socket();
        running.shutdown().await.unwrap();
        assert!(
            !socket.exists(),
            "successful shutdown removes only its admitted socket"
        );
        fixture.edit(|connection| assert_eq!(protected_rows(connection), protected));
        let reopened = Running::start(&fixture).await;
        let mut client = reopened.client().await;
        assert!(client.get("beta").await.unwrap().selected);
        drop(client);
        reopened.shutdown().await.unwrap();
        for untouched in [
            "synthetic-artifacts",
            "synthetic-artifacts.lock",
            "synthetic-mesh",
            "synthetic-platform",
            "synthetic-credentials-never-opened",
        ] {
            assert!(
                !fixture.path.parent().unwrap().join(untouched).exists(),
                "{untouched}"
            );
        }
    }
);

bounded_test!(
    malformed_nil_stale_and_recreated_expected_ids_never_select_another_record,
    {
        let fixture = Fixture::new();
        let record = environment("dev");
        fixture.seed(std::slice::from_ref(&record));
        let running = Running::start(&fixture).await;
        let mut client = running.client().await;
        for invalid in ["not-a-uuid", "00000000-0000-0000-0000-000000000000"] {
            assert_eq!(
                client.select("dev", invalid).await.unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
        }
        assert_eq!(
            client
                .select("dev", &Uuid::new_v4().to_string())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            client.get("missing").await.unwrap_err().code(),
            tonic::Code::NotFound
        );
        for invalid in ["", "../dev", "dev/other"] {
            assert_eq!(
                client.get(invalid).await.unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
            assert_eq!(
                client.select(invalid, "").await.unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
        }
        let mut raw = running.raw_client().await;
        for request_id in ["", "bad", "00000000-0000-0000-0000-000000000000"] {
            let error = raw
                .select_environment(v1::EnvironmentSelector {
                    name: "dev".to_owned(),
                    environment_id: record.id.to_string(),
                    request_id: request_id.to_owned(),
                })
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
        assert!(!client.get("dev").await.unwrap().selected);
        assert!(
            client.select("dev", "").await.unwrap().selected,
            "empty expected ID retains the existing unspecified contract"
        );
        drop(raw);
        drop(client);
        running.shutdown().await.unwrap();

        // Recreate only test-owned metadata while no service is running. The
        // original exact identity must not select the new same-named record.
        let replacement = Uuid::new_v4();
        fixture.edit(|connection| {
            connection
                .execute_batch("UPDATE supervisor_settings SET current_environment_id = NULL")
                .unwrap();
            connection
                .execute(
                    "UPDATE environments SET id = ?1 WHERE name = 'dev'",
                    [replacement.to_string()],
                )
                .unwrap();
        });
        let running = Running::start(&fixture).await;
        let mut client = running.client().await;
        assert_eq!(
            client
                .select("dev", &record.id.to_string())
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
        assert!(!client.get("dev").await.unwrap().selected);
        assert_eq!(
            client
                .select("dev", &replacement.to_string())
                .await
                .unwrap()
                .id,
            replacement.to_string()
        );
        drop(client);
        running.shutdown().await.unwrap();
    }
);

bounded_test!(
    all_thirteen_unsupported_methods_reject_over_real_rpc_without_effects,
    {
        let fixture = Fixture::new();
        fixture.seed(&[environment("dev")]);
        let mut protected = Vec::new();
        fixture.edit(|connection| protected = protected_rows(connection));
        let running = Running::start(&fixture).await;
        let mut raw = running.raw_client().await;
        macro_rules! rejects {
            ($method:ident, $request:expr) => {
                assert_eq!(
                    raw.$method($request)
                        .await
                        .err()
                        .expect(stringify!($method))
                        .code(),
                    tonic::Code::Unimplemented,
                    stringify!($method)
                );
            };
        }
        // Deliberately malformed/default inputs prove these methods reject before
        // admission can interpret requests as lifecycle or credential authority.
        rejects!(create_environment, v1::CreateEnvironmentRequest::default());
        rejects!(list_orphans, v1::ListOrphansRequest::default());
        rejects!(start_environment, v1::EnvironmentSelector::default());
        rejects!(stop_environment, v1::EnvironmentSelector::default());
        rejects!(restart_environment, v1::EnvironmentSelector::default());
        rejects!(
            refresh_environment_skills,
            v1::EnvironmentSelector::default()
        );
        rejects!(resize_environment, v1::ResizeEnvironmentRequest::default());
        rejects!(
            update_environment_sources,
            v1::UpdateEnvironmentSourcesRequest::default()
        );
        rejects!(delete_environment, v1::EnvironmentSelector::default());
        rejects!(get_operation, v1::GetOperationRequest::default());
        rejects!(ensure_credential_broker, v1::EnvironmentSelector::default());
        rejects!(get_daemon_access, v1::EnvironmentSelector::default());
        rejects!(watch_operation, v1::WatchOperationRequest::default());
        drop(raw);
        running.shutdown().await.unwrap();
        fixture.edit(|connection| assert_eq!(protected_rows(connection), protected));
        let names = fs::read_dir(&fixture.path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert!(names.iter().all(|name| {
            [
                "supervisor.db",
                "supervisor.db-wal",
                "supervisor.db-shm",
                "supervisor.lock",
            ]
            .iter()
            .any(|allowed| name == *allowed)
        }));
    }
);

bounded_test!(
    configuration_mismatch_is_rejected_by_the_shared_client_before_requests,
    {
        let fixture = Fixture::new();
        let running = Running::start(&fixture).await;
        let result = NativeSupervisorClient::connect_admitted(
            &running.config.supervisor_socket(),
            Some([0x7f; 32]),
        )
        .await;
        assert!(matches!(
            result,
            Err(SupervisorClientError::Configuration(
                SupervisorConfigError::SupervisorConfigurationMismatch
            ))
        ));
        running.shutdown().await.unwrap();
    }
);

bounded_test!(
    second_service_cannot_replace_live_singleton_or_socket_and_shutdown_releases_lock,
    {
        let fixture = Fixture::new();
        let running = Running::start(&fixture).await;
        let socket = running.config.supervisor_socket();
        let identity = super::super::path::SocketIdentity::capture(&socket).unwrap();
        let second = serve_until(running.config.clone(), std::future::pending()).await;
        assert!(matches!(second, Err(SupervisorError::AlreadyRunning)));
        identity.revalidate(&socket).unwrap();
        let mut client = running.client().await;
        assert!(client.list().await.unwrap().is_empty());
        drop(client);
        running.shutdown().await.unwrap();
        let replacement = Running::start(&fixture).await;
        replacement.shutdown().await.unwrap();
    }
);

bounded_test!(retained_unsupported_store_never_binds_a_socket, {
    let fixture = Fixture::new();
    fixture.seed(&[environment("dev")]);
    fixture.edit(|connection| {
        connection
            .execute_batch("PRAGMA user_version = 11")
            .unwrap()
    });
    let config = config(&fixture);
    let result = serve_until(config.clone(), std::future::pending()).await;
    assert!(matches!(
        result,
        Err(SupervisorError::Store(StoreError::UnsupportedFormat))
    ));
    assert!(!config.supervisor_socket().exists());
    fixture.edit(|connection| {
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            11
        )
    });
});

bounded_test!(
    changed_singleton_identity_rejects_requests_without_removing_replacement,
    {
        let fixture = Fixture::new();
        let running = Running::start(&fixture).await;
        let mut client = running.client().await;
        let original = fixture.path.parent().unwrap().join("retained-lock");
        fs::rename(fixture.path.join("supervisor.lock"), &original).unwrap();
        let replacement = PrivateRoot::open(&fixture.path)
            .unwrap()
            .create_regular(Path::new("supervisor.lock"), 0o600, true)
            .unwrap();
        let error = client.list().await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        drop(client);
        running.shutdown().await.unwrap();
        assert!(original.exists());
        assert_eq!(
            fs::metadata(fixture.path.join("supervisor.lock"))
                .unwrap()
                .len(),
            0
        );
        drop(replacement);
    }
);

bounded_test!(
    uncertain_socket_cleanup_reports_error_and_preserves_replacement,
    {
        let fixture = Fixture::new();
        let running = Running::start(&fixture).await;
        let socket = running.config.supervisor_socket();
        let retained = fixture.path.parent().unwrap().join("retained-socket");
        fs::rename(&socket, &retained).unwrap();
        let replacement = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            running.shutdown().await,
            Err(SupervisorError::Socket(_))
        ));
        assert!(socket.exists());
        assert!(retained.exists());
        drop(replacement);
    }
);

bounded_test!(
    invalid_explicit_configuration_is_rejected_before_root_creation,
    {
        let fixture = Fixture::new();
        let mut config = config(&fixture);
        config.root = fixture.path.parent().unwrap().join("not-created");
        config.artifact_lock = PathBuf::from("relative-disallowed");
        assert!(matches!(
            serve_until(config.clone(), std::future::pending()).await,
            Err(SupervisorError::Configuration(
                SupervisorConfigError::InvalidConfiguration
            ))
        ));
        assert!(!config.root.exists());
    }
);

bounded_test!(
    graceful_shutdown_completes_with_a_still_connected_shared_client,
    {
        let fixture = Fixture::new();
        let running = Running::start(&fixture).await;
        let mut client = running.client().await;
        assert!(client.list().await.unwrap().is_empty());
        let socket = running.config.supervisor_socket();
        // Retain the real HTTP/2 client while shutdown drains the service. Closing
        // the client first would conceal a detached connection-task lifetime bug.
        running.shutdown().await.unwrap();
        assert!(!socket.exists());
        assert!(
            tokio::time::timeout(Duration::from_secs(3), client.list())
                .await
                .expect("closed native service must promptly reject its retained client")
                .is_err()
        );
        drop(client);
        let next = Running::start(&fixture).await;
        next.shutdown().await.unwrap();
    }
);

bounded_test!(
    shutdown_rejects_selection_queued_behind_core_mutex_before_commit,
    {
        let fixture = Fixture::new();
        let record = environment("dev");
        fixture.seed(std::slice::from_ref(&record));
        let root = PrivateRoot::open(&fixture.path).unwrap();
        let singleton = Singleton::acquire(&root).unwrap();
        let core = Arc::new(Mutex::new(Core {
            store: fixture.open().unwrap(),
            singleton,
        }));
        let closed = Arc::new(AtomicBool::new(false));
        let rpc = SupervisorRpc {
            core: core.clone(),
            info: supervisor_info(&config(&fixture)),
            closed: closed.clone(),
        };
        let held = core.lock().await;
        let request = v1::EnvironmentSelector {
            name: "dev".to_owned(),
            environment_id: record.id.to_string(),
            request_id: Uuid::new_v4().to_string(),
        };
        let queued =
            tokio::spawn(async move { rpc.select_environment(Request::new(request)).await });
        // This current-thread runtime polls the spawned request until the held
        // mutex makes it Pending. Closing before release tests the second check.
        tokio::task::yield_now().await;
        assert!(!queued.is_finished());
        closed.store(true, Ordering::Release);
        assert!(
            matches!(
                Singleton::acquire(&root),
                Err(SupervisorError::AlreadyRunning)
            ),
            "the live core retains singleton ownership while the request is queued"
        );
        drop(held);
        assert_eq!(
            queued.await.unwrap().unwrap_err().code(),
            tonic::Code::Unavailable
        );
        assert!(core.lock().await.store.state().unwrap().current.is_none());
        drop(core);
        drop(Singleton::acquire(&root).unwrap());
        assert!(fixture.open().unwrap().state().unwrap().current.is_none());
    }
);

bounded_test!(
    kernel_peer_uid_rejection_happens_before_any_http_stream_is_admitted,
    {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio_stream::StreamExt as _;

        let fixture = Fixture::new();
        let socket = fixture.path.join("peer.sock");
        let current_uid = super::super::path::current_uid();
        let (incoming, identity) =
            crate::uds::bind_owner_only_with_uid(&socket, current_uid.wrapping_add(1)).unwrap();
        let mut incoming = Box::pin(incoming);
        let mut peer = tokio::net::UnixStream::connect(&socket).await.unwrap();
        assert_eq!(peer.peer_cred().unwrap().uid(), current_uid);
        // Bytes are queued before acceptance. Only the expected UID is synthetic;
        // no credential result or Unix transport is mocked. The actual kernel UID
        // mismatch must close the connection without yielding an HTTP input stream.
        peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        let mut byte = [0_u8; 1];
        tokio::select! {
            accepted = incoming.next() => panic!("wrong UID reached HTTP admission: {}", accepted.is_some()),
            closed = peer.read(&mut byte) => {
                assert!(matches!(closed, Ok(0)) || closed.as_ref().is_err_and(|error| error.kind() == io::ErrorKind::ConnectionReset));
            }
        }
        drop(peer);
        drop(incoming);
        remove_bound_socket(&socket, &identity).unwrap();
        assert!(!socket.exists());
    }
);
