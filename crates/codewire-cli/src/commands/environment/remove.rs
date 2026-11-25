//! `cw rm ENV` in the cloud. Moved out of `environment.rs` unchanged.

use super::*;

/// `cw rm ENV` in the cloud: the confirmation, the removal and its result.
pub(super) async fn remove(
    environment_client: &EnvironmentClient,
    org_id: &str,
    args: EnvDeleteArgs,
) -> anyhow::Result<()> {
    let environment_id =
        resolve_environment_id(environment_client, org_id, &args.environment).await?;
    let caps = super::lifecycle_output::capabilities(args.output);
    let shown = display_name_for(
        environment_client,
        org_id,
        &environment_id,
        &args.environment,
        &caps,
    )
    .await;
    let name = shown.name.clone();
    // Machine output names the environment by its ID; a refusal names
    // it as people do.
    let asked = if caps.is_machine() && !args.yes {
        display_name_for(
            environment_client,
            org_id,
            &environment_id,
            &args.environment,
            &super::lifecycle_output::capabilities(OutputFormat::Text),
        )
        .await
    } else {
        shown.clone()
    };
    let place = super::lifecycle_output::platform_location_label(asked.host.as_deref());
    if !crate::commands::confirm_removal(&asked.name, &place, args.yes, args.output)? {
        return Ok(());
    }
    let mut line = StatusLine::new(std::io::stderr(), &caps);
    line.begin(REMOVING_LABEL)?;
    let Some(removal) = Box::pin(lifecycle::tick_while(
        &mut line,
        !caps.is_machine(),
        lifecycle::remove_cloud_environment(environment_client, org_id, &environment_id, &name),
    ))
    .await
    else {
        line.clear()?;
        return Err(InterruptNotice::new(VmLocation::Cloud, "removal", &name).error(false));
    };
    let removal = match removal {
        Ok(removal) => {
            line.clear()?;
            removal
        }
        Err(error) => {
            line.fail(REMOVING_LABEL)?;
            return Err(error);
        }
    };
    match args.output {
        OutputFormat::Json => print_env_delete_result(
            &args.environment,
            &environment_id,
            !matches!(removal, lifecycle::CloudRemoval::Scheduled { .. }),
        )?,
        OutputFormat::Text => removal.result(&name, shown.host.as_deref()).print(&caps),
    }
    Ok(())
}
