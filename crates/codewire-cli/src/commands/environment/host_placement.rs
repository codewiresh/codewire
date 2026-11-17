//! `cw create --on host:NAME` (#3609): the host a create names, the request
//! ID that makes a retry of it safe, and the preview notice.

use super::*;

/// The host an `--on` value names: `host:NAME`, where NAME is a host's name
/// or ID.
fn named_host(on: &str) -> anyhow::Result<String> {
    match on.strip_prefix("host:") {
        Some(host) if !host.is_empty() => Ok(host.to_owned()),
        _ => anyhow::bail!("--on takes host:NAME, for example --on host:build-box"),
    }
}

/// Places `request` on the host `--on` names, when it names one.
pub(super) fn apply(
    args: &EnvCreateArgs,
    request: &mut CreateEnvironmentRequest,
) -> anyhow::Result<()> {
    let Some(on) = args.on.as_deref() else {
        return Ok(());
    };
    request.placement_host = Some(named_host(on)?);
    // One ID per command: a retry of this create returns its environment
    // instead of making a second.
    request.request_id = Some(uuid::Uuid::new_v4().simple().to_string());
    // The same line `cw host` and `cw hosts` print, with every create on a
    // host (owner, 2026-11-13, #3609). Text output only; the notice itself
    // shows only at a terminal.
    if matches!(args.output, OutputFormat::Text) {
        super::super::hosts::preview_notice();
    }
    Ok(())
}

/// `--on` goes through the platform, so a local placement can't take it.
pub(super) fn refuse_local(args: &EnvCreateArgs, local: bool) -> anyhow::Result<()> {
    if args.on.is_some() && local {
        anyhow::bail!(
            "--on runs the environment on a host through the platform; it can't be combined with --local"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::named_host;

    #[test]
    fn on_takes_host_and_a_name() {
        assert_eq!(named_host("host:build-box").unwrap(), "build-box");
        assert_eq!(
            named_host("host:00000000-0000-4000-8000-000000000001").unwrap(),
            "00000000-0000-4000-8000-000000000001"
        );
        for bad in ["host:", "build-box", "cloud:build-box", ""] {
            let error = named_host(bad).unwrap_err();
            assert!(format!("{error}").contains("--on takes host:NAME"), "{bad}");
        }
    }
}
