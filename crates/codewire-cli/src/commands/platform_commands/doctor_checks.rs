//! `cw doctor` checks that stand on their own: this executable's build, and
//! the egress of running local VMs (#4965).

use super::*;

/// The doctor row for local VMs' egress.
const LOCAL_EGRESS: &str = "local VM egress";

/// This executable's version, source revision and target, which tell apart
/// builds that share a package version.
pub(crate) fn doctor_build_check(
    record: anyhow::Result<codewire_cw_release::build_record::BuildRecord>,
) -> DoctorCheck {
    match record {
        Ok(record) => match record.source_revision {
            Some(revision) => doctor_check(
                "cw",
                DoctorStatus::Ok,
                format!(
                    "{} {} {}",
                    record.package_version,
                    &revision[..revision.len().min(12)],
                    record.target
                ),
            ),
            None => doctor_check(
                "cw",
                DoctorStatus::Warn,
                format!(
                    "{} {}; built without source provenance",
                    record.package_version, record.target
                ),
            ),
        },
        Err(error) => doctor_check(
            "cw",
            DoctorStatus::Warn,
            format!("build record unreadable: {error:#}"),
        ),
    }
}

/// Each running local VM whose egress broker is past its deadline (#4965). The
/// local VM supervisor is asked only when it is already running; doctor never
/// starts one.
pub(super) async fn doctor_local_egress_check() -> DoctorCheck {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use codewire_local_vmm::control::v1;
        use codewire_local_vmm::supervisor::NativeSupervisorClient;

        let config = match crate::commands::native_runtime_config() {
            Ok(config) => config,
            Err(error) => {
                return doctor_check(
                    LOCAL_EGRESS,
                    DoctorStatus::Ok,
                    format!("not checked: this cw can't open the local VM state ({error})"),
                );
            }
        };
        let Ok(mut client) = NativeSupervisorClient::connect_runtime(&config).await else {
            return doctor_check(
                LOCAL_EGRESS,
                DoctorStatus::Ok,
                "no local VM supervisor is running",
            );
        };
        let Ok(environments) = client.list().await else {
            return doctor_check(
                LOCAL_EGRESS,
                DoctorStatus::Warn,
                "the local VM supervisor did not list its VMs",
            );
        };
        let mut unavailable = Vec::new();
        for environment in environments
            .iter()
            .filter(|environment| environment.state == v1::EnvironmentState::Running as i32)
        {
            if let Ok(shown) = client.get(&environment.name).await
                && let Some(egress) = shown.egress_unavailable
            {
                unavailable.push((environment.name.clone(), egress.since_unix_ms));
            }
        }
        local_egress_row(&unavailable, std::time::SystemTime::now())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    doctor_check(LOCAL_EGRESS, DoctorStatus::Ok, "no local VMs on this host")
}

/// The row for the running VMs whose egress is unavailable, each with when its
/// refusing began.
fn local_egress_row(unavailable: &[(String, i64)], now: std::time::SystemTime) -> DoctorCheck {
    if unavailable.is_empty() {
        return doctor_check(
            LOCAL_EGRESS,
            DoctorStatus::Ok,
            "every running local VM's egress broker answers in time",
        );
    }
    let names = unavailable
        .iter()
        .map(|(name, since_unix_ms)| {
            let since = std::time::UNIX_EPOCH
                + std::time::Duration::from_millis(since_unix_ms.max(&0).unsigned_abs());
            let refusing = now.duration_since(since).unwrap_or_default();
            format!(
                "{name} for {}",
                crate::commands::environment::progress::format_duration(refusing, false)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    doctor_check(
        LOCAL_EGRESS,
        DoctorStatus::Warn,
        format!(
            "egress unavailable in {names}: the egress broker is past its deadline and requests are refused; `cw --local info NAME` shows it"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Doctor names each running VM whose egress is unavailable, with how
    /// long; none means every broker answers in time (#4965).
    #[test]
    fn doctor_names_each_vm_whose_egress_is_unavailable() {
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_130);
        let none = local_egress_row(&[], now);
        assert_eq!(none.status, DoctorStatus::Ok);
        let row = local_egress_row(&[("dev".to_owned(), 1_700_000_000_000)], now);
        assert_eq!(row.status, DoctorStatus::Warn);
        assert!(
            row.detail.contains("egress unavailable in dev for 2m 10s"),
            "{}",
            row.detail
        );
    }
}
