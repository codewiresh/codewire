use super::*;

const CLEARED: CheckpointDisk = CheckpointDisk {
    intercepted: true,
    cleared: true,
};

#[test]
fn a_boot_without_interception_always_loses_the_marker() {
    for marker in [false, true] {
        for origin in [Origin::Existing, Origin::New, Origin::Checkpoint(CLEARED)] {
            assert_eq!(plan(false, marker, origin), Plan::Uncleared);
        }
    }
}

#[test]
fn an_intercepting_boot_clears_an_existing_disk_only_without_the_marker() {
    assert_eq!(plan(true, true, Origin::Existing), Plan::Cleared);
    assert_eq!(plan(true, false, Origin::Existing), Plan::Clear);
    // A new disk, or one placed from a disk snapshot, holds no sign-in.
    assert_eq!(plan(true, false, Origin::New), Plan::Mark);
}

#[test]
fn a_restore_takes_its_marker_from_the_checkpoint_never_from_the_vm() {
    for marker in [false, true] {
        assert_eq!(plan(true, marker, Origin::Checkpoint(CLEARED)), Plan::Mark);
        // Absent or false: the checkpoint may hold an earlier sign-in.
        let uncleared = CheckpointDisk {
            intercepted: true,
            cleared: false,
        };
        assert_eq!(
            plan(true, marker, Origin::Checkpoint(uncleared)),
            Plan::Refuse
        );
        // Taken without interception: the runner refuses the restore itself.
        let off = CheckpointDisk {
            intercepted: false,
            cleared: true,
        };
        assert_eq!(plan(true, marker, Origin::Checkpoint(off)), Plan::Uncleared);
    }
}

#[test]
fn a_checkpoint_is_flagged_unless_it_intercepted_and_recorded_a_cleared_disk() {
    assert!(!CLEARED.may_hold_sign_in());
    for (intercepted, cleared) in [(false, true), (true, false), (false, false)] {
        assert!(
            CheckpointDisk {
                intercepted,
                cleared
            }
            .may_hold_sign_in()
        );
    }
}

#[test]
fn only_a_vm_off_the_platform_is_offered_the_override() {
    let step = ClearStep::Scrub(ScrubStep::Check);
    let local = UnclearedDisk::ClearFailed {
        step,
        platform: false,
    }
    .to_string();
    assert!(local.contains("--start-with-uncleared-disk"), "{local}");
    assert!(local.contains("e2fsck"), "{local}");
    let platform = UnclearedDisk::ClearFailed {
        step,
        platform: true,
    }
    .to_string();
    assert!(
        !platform.contains("--start-with-uncleared-disk"),
        "{platform}"
    );
    assert!(platform.contains("platform profile"), "{platform}");
    let checkpoint = UnclearedDisk::Checkpoint { platform: true }.to_string();
    assert!(
        !checkpoint.contains("--start-with-uncleared-disk"),
        "{checkpoint}"
    );
    assert!(checkpoint.contains("cw checkpoint rm"), "{checkpoint}");
}

#[test]
fn every_refusal_code_is_a_valid_journal_code() {
    for refusal in [
        UnclearedDisk::ClearFailed {
            step: ClearStep::Marker,
            platform: false,
        },
        UnclearedDisk::Checkpoint { platform: false },
    ] {
        assert!(crate::supervisor_metadata::runner_event_error_code_valid(
            refusal.create_code()
        ));
        assert_eq!(refusal.create_code(), format!("create_{}", refusal.code()));
    }
}

/// A VM's layout under a private state root, as the supervisor makes it.
fn vm_paths() -> (tempfile::TempDir, VmPaths) {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = PrivateRoot::open(&state).unwrap();
    let paths = VmPaths::create(&root, Uuid::new_v4()).unwrap();
    (directory, paths)
}

#[test]
fn the_marker_is_written_and_removed_in_the_vm_directory() {
    let (_directory, paths) = vm_paths();
    assert!(!marker_present(&paths));
    write_marker(&paths).unwrap();
    assert!(marker_present(&paths));
    // Writing it again keeps it.
    write_marker(&paths).unwrap();
    assert!(marker_present(&paths));
    remove_marker(&paths).unwrap();
    assert!(!marker_present(&paths));
    // Removing an absent marker is not an error.
    remove_marker(&paths).unwrap();
}

#[test]
fn a_marker_that_is_not_a_private_empty_file_is_not_a_marker() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_directory, paths) = vm_paths();
    let marker = paths.vm_dir.join(MARKER);
    std::fs::write(&marker, b"x").unwrap();
    std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!marker_present(&paths));
    std::fs::remove_file(&marker).unwrap();
    std::os::unix::fs::symlink("/dev/null", &marker).unwrap();
    assert!(!marker_present(&paths));
}

/// A supervisor with one stopped environment, and that VM's paths.
fn stopped_vm() -> (tempfile::TempDir, Arc<Supervisor>, VmPaths, Uuid) {
    let environment = crate::supervisor::tests::project_environment();
    let environment_id = environment.id;
    let (directory, core) = crate::supervisor::tests::test_supervisor_core(environment);
    let supervisor = crate::supervisor::tests::test_supervisor(core);
    let paths = VmPaths::create(
        &PrivateRoot::open(&supervisor.config.engine_root()).unwrap(),
        environment_id,
    )
    .unwrap();
    (directory, supervisor, paths, environment_id)
}

fn boot(environment_id: Uuid, intercept: bool, origin: Origin) -> BootDisk {
    BootDisk {
        environment_id,
        intercept,
        platform: false,
        override_uncleared: false,
        origin,
    }
}

/// A state disk no e2fsck can settle, so its clearing fails at the first
/// step.
fn unsettleable_disk(paths: &VmPaths) {
    std::fs::write(&paths.state_disk, vec![0xa5; 1 << 20]).unwrap();
}

#[tokio::test]
async fn a_boot_without_interception_removes_the_marker_before_its_runner_starts() {
    let (_directory, supervisor, paths, id) = stopped_vm();
    write_marker(&paths).unwrap();
    supervisor
        .settle_state_disk(boot(id, false, Origin::Existing))
        .await
        .unwrap();
    assert!(!marker_present(&paths));
}

#[tokio::test]
async fn an_intercepting_boot_with_the_marker_touches_nothing() {
    let (_directory, supervisor, paths, id) = stopped_vm();
    write_marker(&paths).unwrap();
    // A disk that a clearing would fail on: it is never cleared.
    unsettleable_disk(&paths);
    supervisor
        .settle_state_disk(boot(id, true, Origin::Existing))
        .await
        .unwrap();
    assert!(marker_present(&paths));
}

#[tokio::test]
async fn a_failed_clearing_refuses_the_boot_and_leaves_no_marker() {
    let (_directory, supervisor, paths, id) = stopped_vm();
    unsettleable_disk(&paths);
    let error = supervisor
        .settle_state_disk(boot(id, true, Origin::Existing))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            SupervisorError::UnclearedDisk(UnclearedDisk::ClearFailed {
                step: ClearStep::Scrub(ScrubStep::Check),
                platform: false,
            })
        ),
        "{error:?}"
    );
    assert!(!marker_present(&paths));
}

#[tokio::test]
async fn the_override_starts_one_boot_off_the_platform_and_never_on_it() {
    let (_directory, supervisor, paths, id) = stopped_vm();
    unsettleable_disk(&paths);
    let overridden = BootDisk {
        override_uncleared: true,
        ..boot(id, true, Origin::Existing)
    };
    supervisor.settle_state_disk(overridden).await.unwrap();
    // The marker stays missing, so the next start clears again.
    assert!(!marker_present(&paths));
    let platform = BootDisk {
        platform: true,
        ..overridden
    };
    let error = supervisor.settle_state_disk(platform).await.unwrap_err();
    assert!(
        matches!(
            error,
            SupervisorError::UnclearedDisk(UnclearedDisk::ClearFailed { platform: true, .. })
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn an_uncleared_checkpoint_is_refused_unless_overridden_off_the_platform() {
    let (_directory, supervisor, paths, id) = stopped_vm();
    write_marker(&paths).unwrap();
    let uncleared = Origin::Checkpoint(CheckpointDisk {
        intercepted: true,
        cleared: false,
    });
    let error = supervisor
        .settle_state_disk(boot(id, true, uncleared))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            SupervisorError::UnclearedDisk(UnclearedDisk::Checkpoint { platform: false })
        ),
        "{error:?}"
    );
    let overridden = BootDisk {
        override_uncleared: true,
        ..boot(id, true, uncleared)
    };
    supervisor.settle_state_disk(overridden).await.unwrap();
    // The restored VM never takes its source's marker.
    assert!(!marker_present(&paths));
    let error = supervisor
        .settle_state_disk(BootDisk {
            platform: true,
            ..overridden
        })
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            SupervisorError::UnclearedDisk(UnclearedDisk::Checkpoint { platform: true })
        ),
        "{error:?}"
    );
    // A checkpoint recorded as cleared gives the restored VM the marker.
    supervisor
        .settle_state_disk(boot(id, true, Origin::Checkpoint(CLEARED)))
        .await
        .unwrap();
    assert!(marker_present(&paths));
}
