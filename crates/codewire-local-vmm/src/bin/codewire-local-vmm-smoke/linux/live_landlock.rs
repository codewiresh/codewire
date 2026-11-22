//! Cloud Hypervisor's native Landlock, as the running VMM reports it.

use super::*;

/// The VMM runs under its native Landlock, and the runner gives it one
/// broadening: it may write into this VM's own checkpoint directory
/// (`--landlock-rules path=…,access=rw`, #3046 R4), the rule the restore
/// path reads back. The live configuration must hold exactly that rule and
/// nothing else (#5748). [`require_resolved_checkpoints_dir`] makes the
/// byte comparison mean the directory itself.
pub(super) fn require_live_landlock(
    config: &serde_json::Map<String, Value>,
    paths: &VmPaths,
) -> SmokeResult<()> {
    if config.get("landlock_enable") != Some(&Value::Bool(true)) {
        return Err(failure(
            "Cloud Hypervisor live configuration does not enable native Landlock",
        ));
    }
    let path = paths
        .checkpoints_dir
        .to_str()
        .ok_or_else(|| failure("this VM's checkpoint directory is not UTF-8"))?;
    if config.get("landlock_rules") != Some(&serde_json::json!([{ "path": path, "access": "rw" }]))
    {
        return Err(failure(
            "Cloud Hypervisor live Landlock rules are not exactly this VM's checkpoint directory",
        ));
    }
    Ok(())
}

/// Refuses a checkpoint directory whose path does not resolve, byte for
/// byte, to itself on the host: a symlink, `.` or `..` anywhere in it would
/// let the rule's path name another directory.
pub(super) fn require_resolved_checkpoints_dir(paths: &VmPaths) -> SmokeResult<()> {
    let resolved = fs::canonicalize(&paths.checkpoints_dir)?;
    if resolved.as_os_str() != paths.checkpoints_dir.as_os_str() {
        return Err(failure(
            "this VM's checkpoint directory is not a resolved host path",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_paths;
    use super::*;

    fn config(rules: Value) -> serde_json::Map<String, Value> {
        let Value::Object(config) = serde_json::json!({
            "landlock_enable": true,
            "landlock_rules": rules,
        }) else {
            unreachable!()
        };
        config
    }

    #[test]
    fn only_this_vms_checkpoint_directory_may_be_written() {
        let paths = test_paths();
        let own = paths.checkpoints_dir.to_str().unwrap();
        let other = "/state/vms/00000000-0000-4000-8000-000000000002/checkpoints";
        require_live_landlock(
            &config(serde_json::json!([{ "path": own, "access": "rw" }])),
            &paths,
        )
        .unwrap();
        for refused in [
            serde_json::json!(null),
            serde_json::json!([]),
            serde_json::json!({ "path": own, "access": "rw" }),
            serde_json::json!([{ "path": other, "access": "rw" }]),
            serde_json::json!([{ "path": paths.vm_dir.to_str().unwrap(), "access": "rw" }]),
            serde_json::json!([{ "path": own, "access": "ro" }]),
            serde_json::json!([{ "path": own }]),
            serde_json::json!([{ "path": own, "access": "rw", "extra": true }]),
            serde_json::json!([
                { "path": own, "access": "rw" },
                { "path": other, "access": "rw" }
            ]),
        ] {
            assert!(
                require_live_landlock(&config(refused.clone()), &paths).is_err(),
                "{refused}"
            );
        }
        let mut missing = config(serde_json::json!([{ "path": own, "access": "rw" }]));
        missing.remove("landlock_rules");
        assert!(require_live_landlock(&missing, &paths).is_err());
        missing.insert(
            "landlock_rules".to_owned(),
            serde_json::json!([{ "path": own, "access": "rw" }]),
        );
        missing.insert("landlock_enable".to_owned(), Value::Bool(false));
        assert!(require_live_landlock(&missing, &paths).is_err());
    }

    #[test]
    fn a_checkpoint_directory_must_resolve_to_itself() {
        let root = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(root.path()).unwrap();
        let real = root.join("vm").join("checkpoints");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(root.join("vm"), root.join("link")).unwrap();
        let mut paths = test_paths();
        paths.checkpoints_dir = real.clone();
        require_resolved_checkpoints_dir(&paths).unwrap();
        for given in [
            root.join("link").join("checkpoints"),
            root.join("vm").join("..").join("vm").join("checkpoints"),
            PathBuf::from(format!("{}/vm/./checkpoints", root.display())),
            root.join("absent"),
        ] {
            paths.checkpoints_dir = given.clone();
            assert!(
                require_resolved_checkpoints_dir(&paths).is_err(),
                "{}",
                given.display()
            );
        }
    }
}
