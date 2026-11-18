//! `cw doctor` checks that stand on their own: this executable's build, the
//! egress of running local VMs (#4965), and the local credential store
//! (#5271).

use super::*;

/// The doctor row for local VMs' egress.
const LOCAL_EGRESS: &str = "local VM egress";
/// The doctor row for the local credential store.
const LOCAL_STORE: &str = "local credential store";
/// How long doctor waits for the store's test write: long enough for a
/// keyring that answers, short of the store's own 2-minute bound.
const LOCAL_STORE_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

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

/// Whether the local credential store accepts a test write (#5271), as a
/// connect checks before its sign-in. The authority is asked only when it is
/// already running; doctor never starts one. A store that is missing, locked
/// or doesn't answer is a warning with the step that fixes it.
pub(super) async fn doctor_local_store_check() -> DoctorCheck {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let Some(mut client) = crate::commands::running_local_credential_authority().await else {
            return doctor_check(
                LOCAL_STORE,
                DoctorStatus::Ok,
                "no local credential authority is running",
            );
        };
        if !codewire_local_credentials::AuthorityFeature::StoreProbe
            .served_by(client.info().protocol_version)
        {
            return doctor_check(
                LOCAL_STORE,
                DoctorStatus::Ok,
                "not checked: the running local credential authority is from an older cw",
            );
        }
        let backend = client
            .info()
            .protected_store
            .map(|store| store.backend.as_str())
            .unwrap_or("the platform default");
        let answer = tokio::time::timeout(LOCAL_STORE_BOUND, client.probe_protected_store()).await;
        local_store_row(
            backend,
            answer.map(|answer| {
                answer.map_err(|status| {
                    codewire_local_credentials::store_refusal_reason(&status).map(str::to_owned)
                })
            }),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    doctor_check(
        LOCAL_STORE,
        DoctorStatus::Ok,
        "no local credential store on this host",
    )
}

/// The store's row for its answer to the test write: `Err(_)` for no answer
/// within doctor's bound, and a refusal by its closed reason, if any.
fn local_store_row(
    backend: &str,
    answer: Result<Result<(), Option<String>>, tokio::time::error::Elapsed>,
) -> DoctorCheck {
    let unlock = if cfg!(target_os = "macos") {
        "unlock it with `security unlock-keychain`"
    } else {
        "unlock it, or restart it with `systemctl --user restart gnome-keyring-daemon`"
    };
    let store = if cfg!(target_os = "macos") {
        "your login keychain"
    } else {
        "your keyring (Secret Service)"
    };
    match answer {
        Ok(Ok(())) => doctor_check(
            LOCAL_STORE,
            DoctorStatus::Ok,
            format!("accepts a test write ({backend})"),
        ),
        Ok(Err(reason)) => {
            use codewire_local_credentials::StoreRefusal;
            let is = |refusal: StoreRefusal| reason.as_deref() == Some(refusal.reason());
            let detail = if is(StoreRefusal::KeychainLocked) {
                format!("{store} is locked: {unlock}")
            } else if is(StoreRefusal::KeychainMissing) {
                format!(
                    "{store} doesn't exist: create it, or unset CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN if it names a missing file"
                )
            } else if is(StoreRefusal::KeyringTimedOut) {
                format!("{store} didn't answer within 2 minutes: {unlock}")
            } else {
                "refused a test write; run `cw credentials --local list` to see what it holds"
                    .to_owned()
            };
            doctor_check(LOCAL_STORE, DoctorStatus::Warn, detail)
        }
        Err(_) => doctor_check(
            LOCAL_STORE,
            DoctorStatus::Warn,
            format!(
                "{store} didn't answer within {} s, perhaps behind an unlock prompt: {unlock}",
                LOCAL_STORE_BOUND.as_secs()
            ),
        ),
    }
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
    /// #5271: doctor names a missing, locked or unanswering local store with
    /// the step that fixes it, and an answering one by its backend.
    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn doctor_names_a_local_store_that_does_not_accept_a_write() {
        use codewire_local_credentials::StoreRefusal;
        let ok = local_store_row("secret-service", Ok(Ok(())));
        assert_eq!(ok.status, DoctorStatus::Ok);
        assert_eq!(ok.detail, "accepts a test write (secret-service)");
        let refused = |refusal: StoreRefusal| {
            local_store_row("secret-service", Ok(Err(Some(refusal.reason().to_owned()))))
        };
        let locked = refused(StoreRefusal::KeychainLocked);
        assert_eq!(locked.status, DoctorStatus::Warn);
        assert_eq!(
            locked.detail,
            "your keyring (Secret Service) is locked: unlock it, or restart it with `systemctl --user restart gnome-keyring-daemon`"
        );
        assert!(
            refused(StoreRefusal::KeyringTimedOut)
                .detail
                .contains("didn't answer within 2 minutes")
        );
        assert!(
            refused(StoreRefusal::KeychainMissing)
                .detail
                .contains("doesn't exist")
        );
        let elapsed = tokio::time::timeout(std::time::Duration::ZERO, std::future::pending::<()>())
            .await
            .unwrap_err();
        let silent = local_store_row("secret-service", Err(elapsed));
        assert_eq!(silent.status, DoctorStatus::Warn);
        assert!(
            silent.detail.contains("didn't answer within 10 s"),
            "{}",
            silent.detail
        );
    }

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
