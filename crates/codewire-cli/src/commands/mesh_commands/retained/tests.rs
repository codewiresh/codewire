use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
#[test]
fn read_only_state_lookup_creates_neither_directory_nor_lock() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    assert!(load_local_mesh_runtime(&missing).unwrap().is_none());
    assert!(!missing.exists());
    let directory = StateDir::open(&root.path().join("owned"), true)
        .unwrap()
        .unwrap();
    assert!(directory.read(LOCAL_MESH_RUNTIME_FILE).unwrap().is_none());
    assert!(!directory.path.join(LOCK).exists());
    fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(directory.read(LOCAL_MESH_RUNTIME_FILE).unwrap().is_none());
    assert!(directory.write(LOCAL_MESH_RUNTIME_FILE, b"{}").is_err());
    assert!(!directory.path.join(LOCAL_MESH_RUNTIME_FILE).exists());
    fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn state_symlink_hardlink_fifo_and_oversize_refuse_without_changing_sentinels() {
    let root = tempfile::tempdir().unwrap();
    let directory = StateDir::open(&root.path().join("owned"), true)
        .unwrap()
        .unwrap();
    let sentinel = root.path().join("sentinel");
    fs::write(&sentinel, b"preserve").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    let record = directory.path.join(LOCAL_MESH_RUNTIME_FILE);
    for kind in ["symlink", "hardlink", "fifo", "oversize"] {
        match kind {
            "symlink" => symlink(&sentinel, &record).unwrap(),
            "hardlink" => fs::hard_link(&sentinel, &record).unwrap(),
            "fifo" => {
                let path = std::ffi::CString::new(record.to_str().unwrap()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            "oversize" => {
                fs::write(&record, vec![0; MAX_STATE + 1]).unwrap();
                fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
            }
            _ => unreachable!(),
        }
        let start = Instant::now();
        assert!(directory.read(LOCAL_MESH_RUNTIME_FILE).is_err(), "{kind}");
        assert!(
            directory
                .write(LOCAL_MESH_RUNTIME_FILE, b"replacement")
                .is_err(),
            "{kind}"
        );
        assert!(
            directory.remove(LOCAL_MESH_RUNTIME_FILE, None).is_err(),
            "{kind}"
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve");
        fs::remove_file(&record).unwrap();
    }
}

#[test]
fn symlink_or_public_directory_is_never_chmodded_or_adopted() {
    let root = tempfile::tempdir().unwrap();
    let foreign = root.path().join("foreign");
    fs::create_dir(&foreign).unwrap();
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o755)).unwrap();
    let link = root.path().join("link");
    symlink(&foreign, &link).unwrap();
    assert!(StateDir::open(&link, true).is_err());
    assert!(StateDir::open(&foreign, true).is_err());
    assert_eq!(fs::metadata(&foreign).unwrap().mode() & 0o777, 0o755);
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn shared_mesh_configuration_read_refuses_link_without_following_target() {
    let root = tempfile::tempdir().unwrap();
    let directory = StateDir::open(&root.path().join("mesh"), true)
        .unwrap()
        .unwrap();
    let sentinel = root.path().join("sentinel");
    fs::write(&sentinel, b"mesh_url = 'http://127.0.0.1:18090'\n").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.path.join("config.toml");
    symlink(&sentinel, &link).unwrap();
    assert!(config::load_mesh_config(&directory.path).is_err());
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"mesh_url = 'http://127.0.0.1:18090'\n"
    );
}

#[test]
fn shared_mesh_configuration_write_preserves_link_target_on_refusal() {
    let root = tempfile::tempdir().unwrap();
    let directory = StateDir::open(&root.path().join("mesh"), true)
        .unwrap()
        .unwrap();
    let sentinel = root.path().join("sentinel");
    let original = b"mesh_url = 'http://127.0.0.1:18090'\n";
    fs::write(&sentinel, original).unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.path.join("config.toml");
    symlink(&sentinel, &link).unwrap();
    assert!(
        config::save_mesh_connection(&directory.path, "http://127.0.0.1:18091", "cw_attempt")
            .is_err()
    );
    assert_eq!(fs::read(&sentinel).unwrap(), original);
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn shared_mesh_configuration_defaults_only_for_absent_private_state() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    assert!(
        config::load_mesh_config(&missing)
            .unwrap()
            .mesh_url
            .is_none()
    );
    assert!(!missing.exists());
    let directory = StateDir::open(&root.path().join("mesh"), true)
        .unwrap()
        .unwrap();
    assert!(
        config::load_mesh_config(&directory.path)
            .unwrap()
            .mesh_url
            .is_none()
    );
    assert!(fs::read_dir(&directory.path).unwrap().next().is_none());
    for bytes in [b"\xff".as_slice(), b"mesh_url = [".as_slice()] {
        directory.write("config.toml", bytes).unwrap();
        assert!(config::load_mesh_config(&directory.path).is_err());
        assert_eq!(directory.read("config.toml").unwrap().unwrap(), bytes);
    }
    assert!(!directory.path.join(LOCK).exists());
}

#[test]
fn shared_mesh_configuration_refuses_hardlink_fifo_and_overbound_entries() {
    let root = tempfile::tempdir().unwrap();
    let directory = StateDir::open(&root.path().join("mesh"), true)
        .unwrap()
        .unwrap();
    let sentinel = root.path().join("sentinel");
    let original = b"mesh_url = 'http://127.0.0.1:18090'\n";
    fs::write(&sentinel, original).unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    let path = directory.path.join("config.toml");
    for kind in ["hardlink", "fifo", "overbound"] {
        match kind {
            "hardlink" => fs::hard_link(&sentinel, &path).unwrap(),
            "fifo" => {
                let name = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            "overbound" => {
                fs::write(&path, vec![b' '; MAX_STATE + 1]).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            _ => unreachable!(),
        }
        let identity = stamp(&fs::symlink_metadata(&path).unwrap());
        let start = Instant::now();
        assert!(config::load_mesh_config(&directory.path).is_err(), "{kind}");
        assert!(
            config::save_mesh_connection(&directory.path, "http://127.0.0.1:18091", "cw_attempt")
                .is_err(),
            "{kind}"
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(identity == stamp(&fs::symlink_metadata(&path).unwrap()));
        assert_eq!(fs::read(&sentinel).unwrap(), original);
        fs::remove_file(&path).unwrap();
    }
}

#[test]
fn shared_mesh_configuration_never_repairs_public_or_read_only_directories() {
    let root = tempfile::tempdir().unwrap();
    let directory = StateDir::open(&root.path().join("mesh"), true)
        .unwrap()
        .unwrap();
    let original = b"mesh_url = 'http://127.0.0.1:18090'\n";
    directory.write("config.toml", original).unwrap();
    for mode in [0o755, 0o500] {
        fs::set_permissions(&directory.path, fs::Permissions::from_mode(mode)).unwrap();
        let read = config::load_mesh_config(&directory.path);
        assert_eq!(read.is_ok(), mode == 0o500);
        assert!(
            config::save_mesh_connection(&directory.path, "http://127.0.0.1:18091", "cw_attempt")
                .is_err()
        );
        assert_eq!(fs::metadata(&directory.path).unwrap().mode() & 0o777, mode);
        assert_eq!(
            fs::read(directory.path.join("config.toml")).unwrap(),
            original
        );
        assert!(!directory.path.join(LOCK).exists());
    }
    fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn shared_mesh_configuration_atomically_replaces_and_preserves_bytes_on_refusal() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("mesh");
    config::save_mesh_connection(&path, "http://127.0.0.1:18090", "cw_original").unwrap();
    let before = fs::metadata(path.join("config.toml")).unwrap();
    config::save_mesh_connection(&path, "http://127.0.0.1:18091", "cw_selected").unwrap();
    let metadata = fs::metadata(path.join("config.toml")).unwrap();
    assert_ne!(before.ino(), metadata.ino());
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(
        config::load_mesh_config(&path).unwrap().mesh_url.as_deref(),
        Some("http://127.0.0.1:18091")
    );
    let original = fs::read(path.join("config.toml")).unwrap();
    let too_large = "x".repeat(MAX_STATE + 1);
    assert!(config::save_mesh_connection(&path, "http://127.0.0.1:18090", &too_large).is_err());
    assert_eq!(fs::read(path.join("config.toml")).unwrap(), original);
    assert_eq!(
        fs::metadata(path.join("config.toml")).unwrap().ino(),
        metadata.ino()
    );
    assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
}

#[tokio::test]
async fn startup_and_down_share_one_exact_control_lock() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("owned");
    let first = StateDir::open(&path, true).unwrap().unwrap();
    let lock = first.lock().await.unwrap();
    let second = StateDir::open(&path, false).unwrap().unwrap();
    let task = tokio::spawn(async move { second.lock().await });
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(!task.is_finished());
    drop(lock);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn replaced_control_lock_is_not_repaired_or_used_for_effects() {
    let root = tempfile::tempdir().unwrap();
    let directory = StateDir::open(&root.path().join("owned"), true)
        .unwrap()
        .unwrap();
    let lock = directory.lock().await.unwrap();
    fs::rename(
        directory.path.join(LOCK),
        directory.path.join("retained-lock"),
    )
    .unwrap();
    let replacement = directory.path.join(LOCK);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&replacement)
        .unwrap();
    let inode = fs::symlink_metadata(&replacement).unwrap().ino();
    assert!(lock.check(&directory).is_err());
    assert_eq!(fs::symlink_metadata(&replacement).unwrap().ino(), inode);
    assert!(directory.path.join("retained-lock").exists());
}
