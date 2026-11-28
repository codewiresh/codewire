//! The options only a cloud sandbox takes, which a local VM refuses.

use super::*;

pub(super) fn reject_unsupported_native_update_options(args: &EnvUpdateArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.idle_stop.is_none(),
        "--idle-stop applies to cloud sandboxes; a local VM is never stopped for being idle"
    );
    Ok(())
}

pub(super) fn reject_unsupported_native_create_options(args: &EnvCreateArgs) -> anyhow::Result<()> {
    let mut unsupported = Vec::new();
    if args.preset_slug.is_some() || args.preset_id.is_some() {
        unsupported.push("presets");
    }
    if args.spec.is_some() {
        unsupported.push("--spec");
    }
    if args.ttl.is_some() {
        unsupported.push("--ttl");
    }
    if args.idle_stop.is_some() {
        unsupported.push("--idle-stop");
    }
    if args.isolation.is_some() {
        unsupported.push("--isolation");
    }
    if args.coding_agent.is_some() {
        unsupported.push("--coding-agent");
    }
    if !args.follow || args.no_wait {
        unsupported.push("asynchronous creation");
    }
    if args.write_preset || args.save_preset.is_some() {
        unsupported.push("preset publication");
    }
    if !unsupported.is_empty() {
        anyhow::bail!(
            "native local preview does not yet support: {}",
            unsupported.join(", ")
        );
    }
    parse_env_settings(&args.env, "cw create").map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(argv: &[&str]) -> EnvCommand {
        let (_, _, command) = crate::commands::env_operation(Cli::try_parse_from(argv).unwrap());
        command
    }

    /// Idle stop is a cloud setting; a local VM refuses it while admitting
    /// `--idle-suspend` and `--idle-hibernate` (#5529).
    #[test]
    fn a_local_vm_refuses_idle_stop_and_admits_idle_sleep() {
        let EnvCommand::Update(update) = command(&["cw", "update", "app", "--idle-stop", "15m"])
        else {
            panic!("expected an update");
        };
        assert_eq!(
            reject_unsupported_native_update_options(&update)
                .unwrap_err()
                .to_string(),
            "--idle-stop applies to cloud sandboxes; a local VM is never stopped for being idle"
        );
        let EnvCommand::Update(update) = command(&["cw", "update", "app", "--idle-suspend", "15m"])
        else {
            panic!("expected an update");
        };
        reject_unsupported_native_update_options(&update).unwrap();
        let EnvCommand::Create(create) =
            command(&["cw", "create", "--local", "--idle-suspend", "15m"])
        else {
            panic!("expected a create");
        };
        reject_unsupported_native_create_options(&create).unwrap();
        let EnvCommand::Update(update) =
            command(&["cw", "update", "app", "--idle-hibernate", "6h"])
        else {
            panic!("expected an update");
        };
        reject_unsupported_native_update_options(&update).unwrap();
        let EnvCommand::Create(create) =
            command(&["cw", "create", "--local", "--idle-hibernate", "6h"])
        else {
            panic!("expected a create");
        };
        reject_unsupported_native_create_options(&create).unwrap();
    }
}
