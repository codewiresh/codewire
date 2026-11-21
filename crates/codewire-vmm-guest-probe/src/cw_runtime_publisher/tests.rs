use super::*;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

/// The trusted launcher the cache seals and copies into its view. Only its
/// bytes, mode and size matter: the publisher never runs it, and the view's
/// permission probe checks only that it is executable. It is small and fixed,
/// so these fixtures never depend on the size of the test build, which a
/// full-debug build makes larger than `CW_RUNTIME_MAX_BYTES` (#5676).
const LAUNCHER_FIXTURE: &[u8] = b"#!/bin/false\n# trusted runtime launcher fixture\n";

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    bootstrap_root: PathBuf,
    launcher: PathBuf,
    binding: RuntimeBinding,
    bootstrap: CwRuntimeCatalog,
    a: CwRuntimeProvenance,
    b: CwRuntimeProvenance,
    b_bytes: Vec<u8>,
    cache: Option<RuntimeCache>,
}
impl Fixture {
    fn new() -> Self {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "kernel fixture requires isolated root identity"
        );
        // Keep executable-mode assertions on the same executable
        // filesystem as this admitted ci-profile test ELF. /tmp may be
        // deliberately noexec on the owner workstation.
        let executable = std::env::current_exe().unwrap();
        let directory = tempfile::Builder::new()
            .prefix("cw-runtime-kernel-")
            .tempdir_in(executable.parent().unwrap())
            .unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let (a_bytes, a_json) = crate::cw_runtime::fixture();
        let a = CwRuntimeProvenance::decode(&a_json).unwrap();
        let mut b_bytes = a_bytes.clone();
        b_bytes[135] = 1;
        let mut b = a.clone();
        b.payload.sha256 = digest_bytes(&b_bytes);
        b.payload.package_version = "0.1.1".into();
        b.image_index_sha256 = "e".repeat(64);
        let bootstrap = CwRuntimeCatalog {
            schema_version: 1,
            active_sha256: a.payload.sha256.clone(),
            runtimes: vec![a.clone()],
        };
        let binding = RuntimeBinding {
            environment_id: Uuid::new_v4(),
            generation: 1,
            bootstrap_catalog_sha256: digest_bytes(&bootstrap.encode().unwrap()),
        };
        let bootstrap_root = directory.path().join("bootstrap");
        create_directory(&bootstrap_root, 0, 0o700).unwrap();
        let member = bootstrap_root.join(&a.payload.sha256);
        create_directory(&member, 0, 0o700).unwrap();
        write_new(&member.join("cw"), &a_bytes, 0o555).unwrap();
        write_new(&member.join("provenance.json"), &a_json, 0o444).unwrap();
        fs::set_permissions(&member, fs::Permissions::from_mode(0o555)).unwrap();
        let launcher = directory.path().join("trusted-init-fixture");
        write_new(&launcher, LAUNCHER_FIXTURE, 0o755).unwrap();
        let root = directory.path().join("cache");
        let cache = RuntimeCache::initialize_at(
            &root,
            binding.clone(),
            &bootstrap,
            &bootstrap_root,
            &launcher,
            None,
            0,
        )
        .unwrap();
        Self {
            _directory: directory,
            root,
            bootstrap_root,
            launcher,
            binding,
            bootstrap,
            a,
            b,
            b_bytes,
            cache: Some(cache),
        }
    }
    fn cache(&self) -> &RuntimeCache {
        self.cache.as_ref().unwrap()
    }
    fn request(&self, action: RuntimeAction) -> RuntimeRequest {
        RuntimeRequest {
            protocol_version: LIVE_RUNTIME_PROTOCOL,
            binding: self.binding.clone(),
            action,
        }
    }
    fn pack(&self) -> Vec<u8> {
        pack(&self.b, &self.b_bytes)
    }
    fn publish(&self, id: Uuid) -> RuntimeReply {
        let pack = self.pack();
        let request = self.request(RuntimeAction::Publish {
            operation_id: id,
            pack_size: pack.len() as u64,
            pack_sha256: digest_bytes(&pack),
            provenance: Box::new(self.b.clone()),
        });
        self.cache().publish(&request, &pack).unwrap()
    }
    fn select(&self, id: Uuid) -> RuntimeRequest {
        self.request(RuntimeAction::Select {
            operation_id: id,
            expected_revision: 1,
            target_sha256: self.b.payload.sha256.clone(),
        })
    }
    fn reopen(&mut self, generation: u64) {
        drop(self.cache.take());
        self.binding.generation = generation;
        self.cache = Some(
            RuntimeCache::initialize_at(
                &self.root,
                self.binding.clone(),
                &self.bootstrap,
                &self.bootstrap_root,
                &self.launcher,
                None,
                0,
            )
            .unwrap(),
        );
    }
}
fn pack(member: &CwRuntimeProvenance, bytes: &[u8]) -> Vec<u8> {
    let provenance = serde_json::to_vec(member).unwrap();
    let mut pack = b"CWRPACK1".to_vec();
    pack.extend_from_slice(&(provenance.len() as u64).to_le_bytes());
    pack.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    pack.extend(provenance);
    pack.extend(bytes);
    pack
}

fn scenario(name: &str) {
    let mut fixture = Fixture::new();
    let id = Uuid::new_v4();
    match name {
        "receipt_capacity" => {
            let mut last = None;
            for _ in 0..LIVE_RUNTIME_MAX_OPERATIONS {
                let request = fixture.request(RuntimeAction::Cancel {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 1,
                    target_sha256: fixture.b.payload.sha256.clone(),
                });
                fixture.cache().control(&request).unwrap();
                last = Some(request);
            }
            let before = fixture.cache().selection().unwrap();
            assert_eq!(before.operations.len(), LIVE_RUNTIME_MAX_OPERATIONS);
            let pack = fixture.pack();
            let publication = fixture.request(RuntimeAction::Publish {
                operation_id: id,
                pack_size: pack.len() as u64,
                pack_sha256: digest_bytes(&pack),
                provenance: Box::new(fixture.b.clone()),
            });
            assert_eq!(
                fixture.cache().publish(&publication, &pack),
                Err(RuntimeRefusal::Capacity)
            );
            assert_eq!(
                fixture.cache().control(&fixture.select(id)),
                Err(RuntimeRefusal::Capacity)
            );
            assert_eq!(fixture.cache().selection().unwrap(), before);
            assert!(
                !fixture
                    .root
                    .join("view")
                    .join(&fixture.b.payload.sha256)
                    .exists()
            );
            // Retention pressure cannot erase/reclassify an existing
            // receipt, even after the publisher itself is re-created.
            fixture.reopen(1);
            assert_eq!(
                fixture
                    .cache()
                    .control(last.as_ref().unwrap())
                    .unwrap()
                    .selection,
                before
            );
        }
        "member_capacity" => {
            for index in 2..=CW_RUNTIME_MAX_VERSIONS as u8 {
                let mut bytes = fixture.b_bytes.clone();
                bytes[135] = index;
                let mut member = fixture.b.clone();
                member.payload.sha256 = digest_bytes(&bytes);
                let pack = pack(&member, &bytes);
                let request = fixture.request(RuntimeAction::Publish {
                    operation_id: Uuid::new_v4(),
                    pack_size: pack.len() as u64,
                    pack_sha256: digest_bytes(&pack),
                    provenance: Box::new(member),
                });
                fixture.cache().publish(&request, &pack).unwrap();
            }
            let before = fixture.cache().selection().unwrap();
            assert_eq!(before.catalog.runtimes.len(), CW_RUNTIME_MAX_VERSIONS);
            let pack = fixture.pack();
            let request = fixture.request(RuntimeAction::Publish {
                operation_id: id,
                pack_size: pack.len() as u64,
                pack_sha256: digest_bytes(&pack),
                provenance: Box::new(fixture.b.clone()),
            });
            assert_eq!(
                fixture.cache().publish(&request, &pack),
                Err(RuntimeRefusal::Capacity)
            );
            assert_eq!(fixture.cache().selection().unwrap(), before);
            assert!(
                !fixture
                    .root
                    .join("view")
                    .join(&fixture.b.payload.sha256)
                    .exists()
            );
            fixture.reopen(1);
            assert_eq!(fixture.cache().selection().unwrap(), before);
        }
        "retention" => {
            let publication = fixture.publish(id);
            assert_eq!(publication.selection.revision, 1);
            assert_eq!(
                publication.selection.catalog.active_sha256,
                fixture.a.payload.sha256
            );
            assert!(
                publication
                    .selection
                    .catalog
                    .runtime(&fixture.b.payload.sha256)
                    .is_some()
            );
            let selected = fixture.cache().control(&fixture.select(id)).unwrap();
            assert_eq!(selected.selection.revision, 2);
            assert_eq!(
                selected.selection.previous_sha256,
                Some(fixture.a.payload.sha256.clone())
            );
            assert_eq!(
                fixture.cache().control(&fixture.select(id)).unwrap(),
                selected
            );
            fixture.reopen(1);
            assert_eq!(fixture.cache().selection().unwrap(), selected.selection);
            for member in [&fixture.a, &fixture.b] {
                let path = fixture
                    .root
                    .join("view")
                    .join(&member.payload.sha256)
                    .join("cw");
                let metadata = fs::symlink_metadata(path).unwrap();
                assert_eq!(metadata.uid(), 0);
                assert_eq!(metadata.gid(), 0);
                assert_eq!(metadata.nlink(), 1);
                assert_eq!(metadata.mode() & 0o7777, 0o555);
            }
        }
        "stale" => {
            fixture.publish(id);
            let mut request = fixture.select(id);
            if let RuntimeAction::Select {
                expected_revision, ..
            } = &mut request.action
            {
                *expected_revision = 2;
            }
            assert_eq!(
                fixture.cache().control(&request),
                Err(RuntimeRefusal::StaleRevision)
            );
            assert_eq!(fixture.cache().selection().unwrap().revision, 1);
            assert_eq!(
                fixture.cache().selection().unwrap().catalog.active_sha256,
                fixture.a.payload.sha256
            );
        }
        "corrupt" => {
            let mut bytes = fixture.pack();
            let request = fixture.request(RuntimeAction::Publish {
                operation_id: id,
                pack_size: bytes.len() as u64,
                pack_sha256: digest_bytes(&bytes),
                provenance: Box::new(fixture.b.clone()),
            });
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            assert_eq!(
                fixture.cache().publish(&request, &bytes),
                Err(RuntimeRefusal::Invalid)
            );
            assert!(
                !fixture
                    .root
                    .join("view")
                    .join(&fixture.b.payload.sha256)
                    .exists()
            );
            assert_eq!(fixture.cache().selection().unwrap().revision, 1);
        }
        "conflict" => {
            let (a_bytes, _) = crate::cw_runtime::fixture();
            let mut candidate = fixture.a.clone();
            candidate.image_index_sha256 = "e".repeat(64);
            let bytes = pack(&candidate, &a_bytes);
            let request = fixture.request(RuntimeAction::Publish {
                operation_id: id,
                pack_size: bytes.len() as u64,
                pack_sha256: digest_bytes(&bytes),
                provenance: Box::new(candidate),
            });
            assert_eq!(
                fixture.cache().publish(&request, &bytes),
                Err(RuntimeRefusal::Collision)
            );
            assert_eq!(
                fixture.cache().selection().unwrap().catalog.runtimes,
                vec![fixture.a.clone()]
            );
        }
        "cancel_before" => {
            let cancel = fixture.request(RuntimeAction::Cancel {
                operation_id: id,
                expected_revision: 1,
                target_sha256: fixture.b.payload.sha256.clone(),
            });
            let receipt = fixture.cache().control(&cancel).unwrap();
            assert_eq!(
                receipt.observed.unwrap().outcome,
                SelectionOutcome::Cancelled
            );
            let bytes = fixture.pack();
            let publication = fixture.request(RuntimeAction::Publish {
                operation_id: id,
                pack_size: bytes.len() as u64,
                pack_sha256: digest_bytes(&bytes),
                provenance: Box::new(fixture.b.clone()),
            });
            assert_eq!(
                fixture.cache().publish(&publication, &bytes),
                Err(RuntimeRefusal::Cancelled)
            );
            assert_eq!(
                fixture
                    .cache()
                    .control(&fixture.select(id))
                    .unwrap()
                    .observed
                    .unwrap()
                    .outcome,
                SelectionOutcome::Cancelled
            );
            assert_eq!(
                fixture.cache().selection().unwrap().catalog.active_sha256,
                fixture.a.payload.sha256
            );
        }
        "cancel_after" => {
            fixture.publish(id);
            let selected = fixture.cache().control(&fixture.select(id)).unwrap();
            let cancel = fixture.request(RuntimeAction::Cancel {
                operation_id: id,
                expected_revision: 1,
                target_sha256: fixture.b.payload.sha256.clone(),
            });
            assert_eq!(fixture.cache().control(&cancel).unwrap(), selected);
            assert_eq!(
                selected.observed.unwrap().outcome,
                SelectionOutcome::Committed
            );
        }
        "rollback" => {
            fixture.publish(id);
            fixture.cache().control(&fixture.select(id)).unwrap();
            let request = fixture.request(RuntimeAction::RetainedSelect {
                operation_id: Uuid::new_v4(),
                expected_revision: 2,
                target_sha256: fixture.a.payload.sha256.clone(),
            });
            let restored = fixture.cache().control(&request).unwrap();
            assert_eq!(restored.selection.revision, 3);
            assert_eq!(
                restored.selection.catalog.active_sha256,
                fixture.a.payload.sha256
            );
            assert_eq!(
                restored.selection.previous_sha256,
                Some(fixture.b.payload.sha256.clone())
            );
            assert_eq!(restored.selection.catalog.runtimes.len(), 2);
        }
        "birth" => {
            fixture.publish(id);
            let old = fixture.select(id);
            fixture.cache().control(&old).unwrap();
            fixture.reopen(2);
            assert_eq!(fixture.cache().control(&old), Err(RuntimeRefusal::Identity));
            let observed = fixture
                .cache()
                .control(&fixture.request(RuntimeAction::Observe { operation_id: id }))
                .unwrap();
            assert_eq!(observed.binding.generation, 2);
            assert_eq!(observed.observed.unwrap().generation, 1);
            assert_eq!(observed.selection.revision, 2);
            let mut foreign = fixture.request(RuntimeAction::Info);
            foreign.binding.environment_id = Uuid::new_v4();
            assert_eq!(
                fixture.cache().control(&foreign),
                Err(RuntimeRefusal::Identity)
            );
        }
        "rebind" => {
            fixture.publish(id);
            let source = fixture.select(id);
            let selected = fixture.cache().control(&source).unwrap().selection;
            assert_eq!(selected.operations.len(), 1);
            // A restored boot of the same environment: only the binding
            // moves, and the old generation's requests are refused.
            fixture
                .cache
                .as_mut()
                .unwrap()
                .rebind(fixture.binding.environment_id, 2)
                .unwrap();
            assert_eq!(fixture.cache().selection().unwrap(), selected);
            assert_eq!(
                fixture.cache().control(&source),
                Err(RuntimeRefusal::Identity)
            );
            fixture.binding.generation = 2;
            fixture
                .cache()
                .control(&fixture.request(RuntimeAction::Info))
                .unwrap();
            // A fork: the fork's identity, the same runtimes and revision,
            // and none of the source's receipts.
            let source_binding = fixture.binding.clone();
            let fork = Uuid::new_v4();
            fixture.cache.as_mut().unwrap().rebind(fork, 1).unwrap();
            let forked = fixture.cache().selection().unwrap();
            assert_eq!(forked.environment_id, fork);
            assert_eq!(forked.catalog, selected.catalog);
            assert_eq!(forked.revision, selected.revision);
            assert!(forked.operations.is_empty());
            assert_eq!(
                fixture.cache().control(&RuntimeRequest {
                    protocol_version: LIVE_RUNTIME_PROTOCOL,
                    binding: source_binding,
                    action: RuntimeAction::Info,
                }),
                Err(RuntimeRefusal::Identity)
            );
            // The fork's next boot admits the rebound selection.
            fixture.binding.environment_id = fork;
            fixture.reopen(2);
            assert_eq!(fixture.cache().selection().unwrap(), forked);
            assert!(
                fixture
                    .cache
                    .as_mut()
                    .unwrap()
                    .rebind(Uuid::nil(), 3)
                    .is_err()
            );
            assert_eq!(fixture.cache().selection().unwrap(), forked);
        }
        "staging" => {
            let stage = fixture.root.join(format!("stage-{}", Uuid::new_v4()));
            create_directory(&stage, 0, 0o700).unwrap();
            write_new(&stage.join("cw"), b"incomplete", 0o600).unwrap();
            let selector = fixture.root.join(format!("selector-{}", Uuid::new_v4()));
            write_new(&selector, b"incomplete", 0o600).unwrap();
            fixture.reopen(1);
            assert!(!stage.exists());
            assert!(!selector.exists());
            assert_eq!(fixture.cache().selection().unwrap().revision, 1);
            let unowned = fixture.root.join("unexpected");
            write_new(&unowned, b"preserve", 0o600).unwrap();
            drop(fixture.cache.take());
            assert!(
                RuntimeCache::initialize_at(
                    &fixture.root,
                    fixture.binding.clone(),
                    &fixture.bootstrap,
                    &fixture.bootstrap_root,
                    &fixture.launcher,
                    None,
                    0
                )
                .is_err()
            );
            assert_eq!(fs::read(&unowned).unwrap(), b"preserve");
        }
        "verity" => {
            let path = fixture
                .root
                .join("view")
                .join(&fixture.a.payload.sha256)
                .join("cw");
            let file = File::open(&path).unwrap();
            let Some(measured) = measure_verity(&file).unwrap() else {
                // This fixture's filesystem cannot seal: the full read.
                assert_eq!(recorded_verity(&file).unwrap(), None);
                assert!(!verity_sealed(&path, 0).unwrap());
                assert!(fixture.cache().selection().is_ok());
                return;
            };
            assert_eq!(recorded_verity(&file).unwrap(), Some(measured));
            assert!(verity_sealed(&path, 0).unwrap());
            assert!(fixture.cache().selection().is_ok());
            assert_eq!(
                fs::read(&path).unwrap(),
                fixture_binary(&fixture.bootstrap_root, &fixture.a)
            );
            // A live publication is sealed the same way.
            let id = Uuid::new_v4();
            fixture.publish(id);
            let published = fixture
                .root
                .join("view")
                .join(&fixture.b.payload.sha256)
                .join("cw");
            assert!(verity_sealed(&published, 0).unwrap());
            // A digest that is not the file's refuses the member.
            let mut other = measured;
            other[0] ^= 1;
            record_verity(&file, &other).unwrap();
            assert!(fixture.cache().selection().is_err());
            // Without a record the member is read in full, and still passes.
            assert_eq!(
                unsafe { libc::fremovexattr(file.as_raw_fd(), VERITY_RECORD.as_ptr()) },
                0
            );
            assert!(!verity_sealed(&path, 0).unwrap());
            assert!(fixture.cache().selection().is_ok());
            record_verity(&file, &measured).unwrap();
            assert!(fixture.cache().selection().is_ok());
            // A record on an unsealed file refuses it, even with the
            // right bytes: the kernel no longer checks its pages.
            drop(file);
            let bytes = fs::read(&path).unwrap();
            fs::remove_file(&path).unwrap();
            write_new(&path, &bytes, 0o555).unwrap();
            let file = File::open(&path).unwrap();
            record_verity(&file, &measured).unwrap();
            assert!(fixture.cache().selection().is_err());
        }
        "links" => {
            let path = fixture
                .root
                .join("view")
                .join(&fixture.a.payload.sha256)
                .join("cw");
            let alias = fixture.root.join("external-link");
            fs::hard_link(&path, &alias).unwrap();
            assert!(fixture.cache().selection().is_err());
            fs::remove_file(&alias).unwrap();
            assert!(fixture.cache().selection().is_ok());
            fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&fixture.launcher, &path).unwrap();
            assert!(fixture.cache().selection().is_err());
        }
        "readonly" => {
            let view = File::open(fixture.root.join("view")).unwrap();
            let fd = view.as_raw_fd();
            let mut child = Command::new("/bin/sh");
            child.env_clear().env("PATH","/usr/bin:/bin").args(["-c","test -r selection.json && test -x cw && ! touch forbidden && ! rm selection.json && ! mkdir forbidden-dir"])
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).uid(65534).gid(65534);
            unsafe {
                child.pre_exec(move || {
                    if libc::fchdir(fd) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let status = child.status().unwrap();
            assert!(
                status.success(),
                "readonly workload permission probe exited {status}"
            );
            assert!(!fixture.root.join("view/forbidden").exists());
            fixture.publish(id);
            fixture.cache().control(&fixture.select(id)).unwrap();
            assert!(
                fixture
                    .root
                    .join("view")
                    .join(&fixture.a.payload.sha256)
                    .join("cw")
                    .is_file()
            );
        }
        "readonly_mount" => {
            // This scenario always runs in a separate source-bound test
            // process. Isolate propagation before touching its own mount.
            assert_eq!(
                unsafe { libc::unshare(libc::CLONE_NEWNS) },
                0,
                "private mount namespace unavailable: {}",
                std::io::Error::last_os_error()
            );
            let slash = std::ffi::CString::new("/").unwrap();
            assert_eq!(
                unsafe {
                    libc::mount(
                        std::ptr::null(),
                        slash.as_ptr(),
                        std::ptr::null(),
                        libc::MS_REC | libc::MS_PRIVATE,
                        std::ptr::null(),
                    )
                },
                0
            );
            let source = fixture.root.join("view");
            let target = fixture.root.parent().unwrap().join("readonly-view");
            create_directory(&target, 0, 0o555).unwrap();
            let source_c = std::ffi::CString::new(source.as_os_str().as_encoded_bytes()).unwrap();
            let target_c = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(
                unsafe {
                    libc::mount(
                        source_c.as_ptr(),
                        target_c.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    )
                },
                0
            );
            struct OwnedMount(std::ffi::CString);
            impl Drop for OwnedMount {
                fn drop(&mut self) {
                    assert_eq!(
                        unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) },
                        0
                    );
                }
            }
            let _mount = OwnedMount(target_c.clone());
            assert_eq!(
                unsafe {
                    libc::mount(
                        std::ptr::null(),
                        target_c.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND
                            | libc::MS_REMOUNT
                            | libc::MS_RDONLY
                            | libc::MS_NOSUID
                            | libc::MS_NODEV,
                        std::ptr::null(),
                    )
                },
                0
            );
            // Even root's DAC override cannot alter the workload mount.
            assert_eq!(
                fs::write(target.join("forbidden"), b"no")
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EROFS)
            );
            assert_eq!(
                fs::remove_file(target.join(SELECTOR))
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EROFS)
            );
            let before = fs::read(target.join(&fixture.a.payload.sha256).join("cw")).unwrap();
            fixture.publish(id);
            fixture.cache().control(&fixture.select(id)).unwrap();
            let selected: RuntimeSelection =
                serde_json::from_slice(&fs::read(target.join(SELECTOR)).unwrap()).unwrap();
            assert_eq!(selected.catalog.active_sha256, fixture.b.payload.sha256);
            assert_eq!(
                fs::read(target.join(&fixture.a.payload.sha256).join("cw")).unwrap(),
                before
            );
            assert!(target.join(&fixture.b.payload.sha256).join("cw").is_file());
        }
        "lost_reply" => {
            fixture.publish(id);
            let cache = Arc::new(Mutex::new(fixture.cache.take().unwrap()));
            let request = fixture.select(id);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let (mut client, server) = tokio::io::duplex(1024 * 1024);
                client
                    .write_all(&encode_frame(&request).unwrap())
                    .await
                    .unwrap();
                client.shutdown().await.unwrap();
                drop(client);
                // Commit still occurs even though the response receiver
                // disappears. The error is an uncertain reply, not rollback.
                assert!(
                    handle(
                        server,
                        cache.clone(),
                        Arc::new(tokio::sync::Semaphore::new(1)),
                        None
                    )
                    .await
                    .is_err()
                );
            });
            let observed = cache
                .lock()
                .unwrap()
                .control(&fixture.request(RuntimeAction::Observe { operation_id: id }))
                .unwrap();
            assert_eq!(
                observed.observed.unwrap().outcome,
                SelectionOutcome::Committed
            );
            assert_eq!(observed.selection.revision, 2);
        }
        "truncated" => {
            let bytes = fixture.pack();
            let request = fixture.request(RuntimeAction::Publish {
                operation_id: id,
                pack_size: bytes.len() as u64,
                pack_sha256: digest_bytes(&bytes),
                provenance: Box::new(fixture.b.clone()),
            });
            let cache = Arc::new(Mutex::new(fixture.cache.take().unwrap()));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let (mut client, server) = tokio::io::duplex(1024 * 1024);
                client
                    .write_all(&encode_frame(&request).unwrap())
                    .await
                    .unwrap();
                client.write_all(&bytes[..bytes.len() - 1]).await.unwrap();
                client.shutdown().await.unwrap();
                assert!(
                    handle(
                        server,
                        cache.clone(),
                        Arc::new(tokio::sync::Semaphore::new(1)),
                        None
                    )
                    .await
                    .is_err()
                );
            });
            assert_eq!(cache.lock().unwrap().selection().unwrap().revision, 1);
            assert!(
                !fixture
                    .root
                    .join("view")
                    .join(&fixture.b.payload.sha256)
                    .exists()
            );
        }
        "move" => {
            // The installed runtime this environment moves onto: another
            // bootstrap catalog and another init as its trusted launcher.
            let installed = CwRuntimeCatalog {
                schema_version: 1,
                active_sha256: fixture.b.payload.sha256.clone(),
                runtimes: vec![fixture.b.clone()],
            };
            let installed_sha256 = digest_bytes(&installed.encode().unwrap());
            let member = fixture.bootstrap_root.join(&fixture.b.payload.sha256);
            create_directory(&member, 0, 0o700).unwrap();
            write_new(&member.join("cw"), &fixture.b_bytes, 0o555).unwrap();
            write_new(
                &member.join("provenance.json"),
                &serde_json::to_vec(&fixture.b).unwrap(),
                0o444,
            )
            .unwrap();
            fs::set_permissions(&member, fs::Permissions::from_mode(0o555)).unwrap();
            let installed_launcher = fixture.root.with_file_name("installed-init-fixture");
            let mut launcher_bytes = fs::read(&fixture.launcher).unwrap();
            launcher_bytes.push(0);
            write_new(&installed_launcher, &launcher_bytes, 0o755).unwrap();
            let earlier_sha256 = fixture.binding.bootstrap_catalog_sha256.clone();
            let earlier = fixture.cache().selection().unwrap();
            drop(fixture.cache.take());
            let environment = fixture.binding.environment_id;
            let open = |environment: Uuid,
                        bootstrap: &CwRuntimeCatalog,
                        bootstrap_sha256: &str,
                        launcher: &Path,
                        moved_from: Option<&str>| {
                RuntimeCache::initialize_at(
                    &fixture.root,
                    RuntimeBinding {
                        environment_id: environment,
                        generation: 2,
                        bootstrap_catalog_sha256: bootstrap_sha256.to_owned(),
                    },
                    bootstrap,
                    &fixture.bootstrap_root,
                    launcher,
                    moved_from,
                    0,
                )
            };
            let refused = |result: Result<RuntimeCache>, message: &str| {
                let error = result.err().expect("a mismatch is refused");
                assert!(error.to_string().contains(message), "{error:#}");
            };
            // Every mismatch but the declared move is refused as before,
            // and leaves the cache as it was.
            refused(
                open(
                    environment,
                    &fixture.bootstrap,
                    &earlier_sha256,
                    &installed_launcher,
                    None,
                ),
                "trusted runtime launcher changed",
            );
            refused(
                open(
                    environment,
                    &installed,
                    &installed_sha256,
                    &installed_launcher,
                    None,
                ),
                "native runtime bootstrap identity changed",
            );
            refused(
                open(
                    environment,
                    &installed,
                    &installed_sha256,
                    &installed_launcher,
                    Some(&installed_sha256),
                ),
                "native runtime bootstrap identity changed",
            );
            refused(
                open(
                    environment,
                    &installed,
                    &installed_sha256,
                    &installed_launcher,
                    Some(&"f".repeat(64)),
                ),
                "native runtime bootstrap identity changed",
            );
            refused(
                open(
                    Uuid::new_v4(),
                    &installed,
                    &installed_sha256,
                    &installed_launcher,
                    Some(&earlier_sha256),
                ),
                "native runtime bootstrap identity changed",
            );
            assert_eq!(
                open(
                    environment,
                    &fixture.bootstrap,
                    &earlier_sha256,
                    &fixture.launcher,
                    None
                )
                .unwrap()
                .selection()
                .unwrap(),
                earlier
            );
            let view = fixture.root.join("view");
            // An entry the rebuild does not expect stops the boot, before
            // the earlier selector goes, so the next move boot tries again.
            let fifo =
                std::ffi::CString::new(view.join("fifo").into_os_string().into_vec()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
            refused(
                open(
                    environment,
                    &installed,
                    &installed_sha256,
                    &installed_launcher,
                    Some(&earlier_sha256),
                ),
                "unexpected runtime cache entry",
            );
            assert!(view.join(SELECTOR).exists());
            fs::remove_file(view.join("fifo")).unwrap();
            // A link out of the cache is removed where it is, never followed.
            let outside = fixture.root.with_file_name("outside");
            fs::write(&outside, b"untouched").unwrap();
            std::os::unix::fs::symlink(&outside, view.join("link")).unwrap();
            // The declared move rebuilds the cache from the installed
            // bootstrap and launcher.
            let moved = open(
                environment,
                &installed,
                &installed_sha256,
                &installed_launcher,
                Some(&earlier_sha256),
            )
            .unwrap();
            assert_eq!(fs::read(&outside).unwrap(), b"untouched");
            assert!(!exists_nofollow(&view.join("link")).unwrap());
            assert!(!exists_nofollow(&view.join(&fixture.a.payload.sha256)).unwrap());
            let rebuilt = moved.selection().unwrap();
            assert_eq!(rebuilt.environment_id, environment);
            assert_eq!(rebuilt.bootstrap_catalog_sha256, installed_sha256);
            assert_eq!(rebuilt.catalog, installed);
            assert_eq!(rebuilt.revision, 1);
            assert!(rebuilt.operations.is_empty());
            assert_eq!(fs::read(view.join("cw")).unwrap(), launcher_bytes);
            drop(moved);
            // A move boot that runs again, after one that stopped once the
            // cache was rebuilt, proceeds with the cache unchanged.
            let again = open(
                environment,
                &installed,
                &installed_sha256,
                &installed_launcher,
                Some(&earlier_sha256),
            )
            .unwrap();
            assert_eq!(again.selection().unwrap(), rebuilt);
            drop(again);
            assert_eq!(
                open(
                    environment,
                    &installed,
                    &installed_sha256,
                    &installed_launcher,
                    None
                )
                .unwrap()
                .selection()
                .unwrap(),
                rebuilt
            );
        }
        _ => panic!("closed kernel fixture scenario refused"),
    }
}
fn fixture_binary(bootstrap_root: &Path, member: &CwRuntimeProvenance) -> Vec<u8> {
    fs::read(bootstrap_root.join(&member.payload.sha256).join("cw")).unwrap()
}

fn kernel(name: &str) {
    let executable = std::env::current_exe().unwrap();
    let mut child = if unsafe { libc::geteuid() } == 0 {
        let mut child = Command::new(&executable);
        child
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("CW_RUNTIME_KERNEL_SCENARIO", name);
        child
    } else {
        let mut child = Command::new("/usr/bin/sudo");
        child
            .args(["-n", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C"])
            .arg(format!("CW_RUNTIME_KERNEL_SCENARIO={name}"))
            .arg(&executable);
        child
    };
    let output = child
        .args([
            "--ignored",
            "--exact",
            "cw_runtime_publisher::tests::root_kernel_child",
            "--test-threads=1",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("isolated kernel fixture invocation");
    assert!(
        output.status.success(),
        "actual root kernel fixture {name} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed; 0 ignored"));
}
#[test]
fn live_runtime_measures_a_sealed_member_by_its_verity_digest() {
    kernel("verity");
}
#[test]
fn live_runtime_rebinds_to_a_restored_boot_and_a_fork() {
    kernel("rebind");
}
#[test]
fn live_runtime_rebuilds_its_cache_only_for_the_declared_move() {
    kernel("move");
}
#[test]
fn live_runtime_receipt_capacity_preserves_selection_and_observation() {
    kernel("receipt_capacity");
}
#[test]
fn live_runtime_member_capacity_refuses_before_publication() {
    kernel("member_capacity");
}
#[test]
fn live_runtime_retains_versions_and_exact_receipts() {
    kernel("retention");
}
#[test]
fn live_runtime_stale_revision_cannot_change_default() {
    kernel("stale");
}
#[test]
fn live_runtime_corrupt_candidate_never_publishes() {
    kernel("corrupt");
}
#[test]
fn live_runtime_conflicting_provenance_preserves_old_bytes() {
    kernel("conflict");
}
#[test]
fn live_runtime_cancel_before_commit_never_replays() {
    kernel("cancel_before");
}
#[test]
fn live_runtime_cancel_after_commit_reports_effect() {
    kernel("cancel_after");
}
#[test]
fn live_runtime_rollback_retains_both_versions() {
    kernel("rollback");
}
#[test]
fn live_runtime_new_birth_observes_without_old_request_replay() {
    kernel("birth");
}
#[test]
fn live_runtime_recovers_only_exact_owned_staging() {
    kernel("staging");
}
#[test]
fn live_runtime_refuses_hardlinks_and_symlinks() {
    kernel("links");
}
#[test]
fn live_runtime_workload_cannot_mutate_root_owned_view() {
    kernel("readonly");
}
#[test]
#[ignore = "privileged kernel fixture: needs a private mount namespace (CAP_SYS_ADMIN); the transport local-vmm shard runs it where root or sudo can grant one"]
fn live_runtime_readonly_mount_exposes_new_members_without_replacing_old_bytes() {
    kernel("readonly_mount");
}
#[test]
fn live_runtime_lost_reply_keeps_observable_commit() {
    kernel("lost_reply");
}
#[test]
fn live_runtime_partial_transfer_has_no_selection_effect() {
    kernel("truncated");
}
#[test]
#[ignore = "invoked exactly by the source-bound isolated kernel fixture; not optional proof"]
fn root_kernel_child() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let name = std::env::var("CW_RUNTIME_KERNEL_SCENARIO").expect("closed fixture selector");
    scenario(&name);
}
