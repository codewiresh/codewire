//! The smoke's proof of the VMM process's confinement, read from procfs.

use super::*;
use codewire_local_vmm::artifact::{
    ArtifactError, CLOUD_HYPERVISOR_RELEASE, verify_cloud_hypervisor_version,
};

/// The Cloud Hypervisor release whose thread layout [`check_worker_layout`]
/// encodes (#5748). Another release needs that layout derived again from
/// its source before this proof means anything.
const SECCOMP_LAYOUT_RELEASE: &str = "v54.0";

/// The threads Cloud Hypervisor's main thread spawns before it applies its
/// own filter, so that they do not inherit it (`cloud-hypervisor/src/main.rs`
/// at v54.0, "Spawn workers first"): the VMM thread, and the HTTP API thread
/// that `--api-socket` starts. The runner passes no event monitor, D-Bus or
/// gdb option, so no other thread starts that way.
const PRE_MAIN_FILTER_THREADS: [&str; 2] = ["vmm", "http-server"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProcessConfinement {
    pub(super) seccomp: u32,
    pub(super) seccomp_filters: u32,
    pub(super) no_new_privs: u32,
    pub(super) cap_inh: u128,
    pub(super) cap_prm: u128,
    pub(super) cap_eff: u128,
    pub(super) cap_amb: u128,
}

#[derive(Debug, PartialEq, Eq)]
struct WorkerLayout {
    workers: u32,
    minimum_filters: u32,
    maximum_filters: u32,
}

pub(super) async fn require_vmm_process_confinement(identity: &ProcessIdentity) -> SmokeResult<()> {
    if ProcessIdentity::capture(identity.pid)? != *identity {
        return Err(failure(
            "VMM process identity changed before confinement inspection",
        ));
    }
    require_seccomp_layout_release(identity).await?;
    check_seccomp_argument(&fs::read(format!("/proc/{}/cmdline", identity.pid))?)
        .map_err(failure)?;
    let leader_status = fs::read_to_string(format!("/proc/{0}/task/{0}/status", identity.pid))?;
    let leader = parse_process_confinement(&leader_status)?;
    if leader.no_new_privs != 1 || !capability_sets_empty(&leader) {
        return Err(failure(
            "VMM leader lacks its required no-new-privileges/capability boundary",
        ));
    }
    let mut workers = Vec::new();
    for entry in fs::read_dir(format!("/proc/{}/task", identity.pid))? {
        let entry = entry?;
        let tid = entry
            .file_name()
            .to_string_lossy()
            .parse::<u32>()
            .map_err(|_| failure("VMM task identifier is malformed"))?;
        let status = fs::read_to_string(entry.path().join("status"))?;
        let confinement = parse_process_confinement(&status)?;
        if tid == identity.pid {
            if confinement != leader {
                return Err(failure("VMM leader status changed during task inspection"));
            }
            continue;
        }
        if confinement.no_new_privs != 1 || !capability_sets_empty(&confinement) {
            return Err(failure(
                "VMM task lacks no-new-privileges or retains capabilities",
            ));
        }
        let name = fs::read_to_string(entry.path().join("comm"))?;
        workers.push((name.trim_end_matches('\n').to_owned(), confinement));
    }
    let layout = match check_worker_layout(&leader, &workers) {
        Ok(layout) => layout,
        Err(failed) => {
            observation("vmm.leader_seccomp", leader.seccomp);
            observation("vmm.leader_seccomp_filters", leader.seccomp_filters);
            observation("vmm.worker_count", workers.len());
            if let Some(name) = failed.worker {
                observation("vmm.failed_worker", name);
            }
            return Err(failure(failed.reason));
        }
    };
    if ProcessIdentity::capture(identity.pid)? != *identity {
        return Err(failure(
            "VMM process identity changed during confinement inspection",
        ));
    }
    observation("vmm.seccomp_layout_release", SECCOMP_LAYOUT_RELEASE);
    observation("vmm.seccomp_argument_verified", true);
    observation("vmm.leader_seccomp", leader.seccomp);
    observation("vmm.leader_seccomp_filters", leader.seccomp_filters);
    observation("vmm.worker_count", layout.workers);
    observation("vmm.minimum_worker_seccomp_filters", layout.minimum_filters);
    observation("vmm.maximum_worker_seccomp_filters", layout.maximum_filters);
    observation("vmm.worker_seccomp_verified", true);
    observation("vmm.all_tasks_no_new_privs_verified", true);
    observation("vmm.all_tasks_capability_sets_empty_verified", true);
    Ok(())
}

/// Refuses a VMM other than the release [`check_worker_layout`] was derived
/// for, asking the running executable itself, as admission asks the staged
/// one.
async fn require_seccomp_layout_release(identity: &ProcessIdentity) -> SmokeResult<()> {
    const REDERIVE: &str = "VMM release is not the one its seccomp layout was derived for: re-derive the seccomp layout for this version";
    if CLOUD_HYPERVISOR_RELEASE != SECCOMP_LAYOUT_RELEASE {
        return Err(failure(REDERIVE));
    }
    let running = PathBuf::from(format!("/proc/{}/exe", identity.pid));
    match verify_cloud_hypervisor_version(&running).await {
        Ok(()) => Ok(()),
        Err(ArtifactError::VersionMismatch) => Err(failure(REDERIVE)),
        Err(_) => Err(failure("VMM version probe failed")),
    }
}

/// Cloud Hypervisor's `--seccomp` takes `true`, `false`, `log` or `errno`.
/// Only `true` makes a syscall outside a thread's filter trap: `log` installs
/// filters that count as present but block nothing, and `errno` lets the
/// thread carry on.
fn check_seccomp_argument(cmdline: &[u8]) -> Result<(), &'static str> {
    let arguments = cmdline.split(|byte| *byte == 0).collect::<Vec<_>>();
    let mut values = arguments
        .windows(2)
        .filter(|pair| pair[0] == b"--seccomp")
        .map(|pair| pair[1]);
    let value = values.next();
    if value != Some(b"true".as_slice())
        || values.next().is_some()
        || arguments
            .iter()
            .any(|argument| argument.starts_with(b"--seccomp="))
    {
        return Err("VMM does not run with enforcing seccomp filters");
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct LayoutFailure<'a> {
    reason: &'static str,
    worker: Option<&'a str>,
}

/// Cloud Hypervisor v54 filters every one of its threads itself. The leader
/// applies its own filter after spawning [`PRE_MAIN_FILTER_THREADS`], so the
/// leader and each of those holds exactly one. Every other worker starts
/// under the VMM thread, so it holds the VMM thread's filter and at least one
/// of its own. The kernel's workers in the process (`iou-wrk-*`,
/// `kvm-nx-lpage-re`) pass by inheriting their parent's. A count cannot
/// show which filter a thread holds; it shows that no worker runs on its
/// parent's filter alone.
fn check_worker_layout<'a>(
    leader: &ProcessConfinement,
    workers: &'a [(String, ProcessConfinement)],
) -> Result<WorkerLayout, LayoutFailure<'a>> {
    if leader.seccomp != 2 || leader.seccomp_filters != 1 {
        return Err(LayoutFailure {
            reason: "VMM leader does not hold exactly its own seccomp filter",
            worker: None,
        });
    }
    let mut layout = WorkerLayout {
        workers: 0,
        minimum_filters: u32::MAX,
        maximum_filters: 0,
    };
    let mut pre_main_filter_seen = [0_u32; PRE_MAIN_FILTER_THREADS.len()];
    for (name, worker) in workers {
        let own_filter = match PRE_MAIN_FILTER_THREADS
            .iter()
            .position(|thread| thread == name)
        {
            Some(index) => {
                pre_main_filter_seen[index] += 1;
                worker.seccomp_filters == 1
            }
            None => worker.seccomp_filters >= 2,
        };
        if worker.seccomp != 2 || !own_filter {
            return Err(LayoutFailure {
                reason: "VMM worker does not hold a seccomp filter of its own",
                worker: Some(name),
            });
        }
        layout.workers += 1;
        layout.minimum_filters = layout.minimum_filters.min(worker.seccomp_filters);
        layout.maximum_filters = layout.maximum_filters.max(worker.seccomp_filters);
    }
    if pre_main_filter_seen != [1; PRE_MAIN_FILTER_THREADS.len()] {
        return Err(LayoutFailure {
            reason: "VMM threads differ from Cloud Hypervisor v54's layout",
            worker: None,
        });
    }
    Ok(layout)
}

pub(super) fn parse_process_confinement(status: &str) -> SmokeResult<ProcessConfinement> {
    let seccomp = parse_status_decimal(unique_status_value(status, "Seccomp")?)?;
    let seccomp_filters = parse_status_decimal(unique_status_value(status, "Seccomp_filters")?)?;
    let no_new_privs = parse_status_decimal(unique_status_value(status, "NoNewPrivs")?)?;
    let cap_inh = parse_status_hex(unique_status_value(status, "CapInh")?)?;
    let cap_prm = parse_status_hex(unique_status_value(status, "CapPrm")?)?;
    let cap_eff = parse_status_hex(unique_status_value(status, "CapEff")?)?;
    let cap_amb = parse_status_hex(unique_status_value(status, "CapAmb")?)?;
    Ok(ProcessConfinement {
        seccomp,
        seccomp_filters,
        no_new_privs,
        cap_inh,
        cap_prm,
        cap_eff,
        cap_amb,
    })
}

pub(super) fn capability_sets_empty(confinement: &ProcessConfinement) -> bool {
    confinement.cap_inh == 0
        && confinement.cap_prm == 0
        && confinement.cap_eff == 0
        && confinement.cap_amb == 0
}

fn unique_status_value<'a>(status: &'a str, field: &str) -> SmokeResult<&'a str> {
    let mut values = status.lines().filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name == field).then_some(value.trim())
    });
    let value = values
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| failure("VMM process status is missing a confinement field"))?;
    if values.next().is_some() {
        return Err(failure("VMM process status repeats a confinement field"));
    }
    Ok(value)
}

fn parse_status_decimal(value: &str) -> SmokeResult<u32> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(failure(
            "VMM process status has a malformed confinement field",
        ));
    }
    value
        .parse()
        .map_err(|_| failure("VMM process status has an out-of-range confinement field"))
}

fn parse_status_hex(value: &str) -> SmokeResult<u128> {
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(failure(
            "VMM process status has a malformed confinement field",
        ));
    }
    u128::from_str_radix(value, 16)
        .map_err(|_| failure("VMM process status has an out-of-range confinement field"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILTERED: ProcessConfinement = ProcessConfinement {
        seccomp: 2,
        seccomp_filters: 2,
        no_new_privs: 1,
        cap_inh: 0,
        cap_prm: 0,
        cap_eff: 0,
        cap_amb: 0,
    };

    fn with_filters(seccomp_filters: u32) -> ProcessConfinement {
        ProcessConfinement {
            seccomp_filters,
            ..FILTERED
        }
    }

    /// The layout observed on Cloud Hypervisor v54.0 at daemon readiness
    /// (#5748), less the repeated virtio queue threads.
    fn observed_v54_workers() -> Vec<(String, ProcessConfinement)> {
        [
            ("vmm", 1),
            ("http-server", 1),
            ("vmm_signal_hand", 2),
            ("vcpu0", 2),
            ("kvm-nx-lpage-re", 2),
            ("__rng", 2),
            ("cw-state_q0", 2),
            ("cw-vsock", 2),
            ("iou-wrk-2084494", 2),
        ]
        .into_iter()
        .map(|(name, filters)| (name.to_owned(), with_filters(filters)))
        .collect()
    }

    #[test]
    fn seccomp_layout_is_derived_for_the_pinned_release() {
        assert_eq!(SECCOMP_LAYOUT_RELEASE, CLOUD_HYPERVISOR_RELEASE);
    }

    #[test]
    fn worker_layout_accepts_the_observed_v54_layout() {
        assert_eq!(
            check_worker_layout(&with_filters(1), &observed_v54_workers()),
            Ok(WorkerLayout {
                workers: 9,
                minimum_filters: 1,
                maximum_filters: 2,
            })
        );
    }

    #[test]
    fn worker_layout_refuses_a_worker_on_its_parent_filter_alone() {
        let mut workers = observed_v54_workers();
        workers[3].1 = with_filters(1);
        assert_eq!(
            check_worker_layout(&with_filters(1), &workers),
            Err(LayoutFailure {
                reason: "VMM worker does not hold a seccomp filter of its own",
                worker: Some("vcpu0"),
            })
        );
        let mut workers = observed_v54_workers();
        workers[0].1 = with_filters(2);
        assert_eq!(
            check_worker_layout(&with_filters(1), &workers)
                .unwrap_err()
                .worker,
            Some("vmm")
        );
        let mut workers = observed_v54_workers();
        workers[4].1 = ProcessConfinement {
            seccomp: 0,
            seccomp_filters: 0,
            ..FILTERED
        };
        assert_eq!(
            check_worker_layout(&with_filters(1), &workers)
                .unwrap_err()
                .worker,
            Some("kvm-nx-lpage-re")
        );
    }

    #[test]
    fn worker_layout_refuses_a_leader_without_exactly_its_own_filter() {
        let unfiltered = ProcessConfinement {
            seccomp: 0,
            seccomp_filters: 0,
            ..FILTERED
        };
        for leader in [unfiltered, with_filters(2)] {
            assert_eq!(
                check_worker_layout(&leader, &observed_v54_workers())
                    .unwrap_err()
                    .reason,
                "VMM leader does not hold exactly its own seccomp filter"
            );
        }
    }

    #[test]
    fn worker_layout_requires_one_vmm_and_one_api_thread() {
        let mut missing = observed_v54_workers();
        missing.remove(1);
        let mut repeated = observed_v54_workers();
        repeated.push(("vmm".to_owned(), with_filters(1)));
        for workers in [missing, repeated] {
            assert_eq!(
                check_worker_layout(&with_filters(1), &workers)
                    .unwrap_err()
                    .reason,
                "VMM threads differ from Cloud Hypervisor v54's layout"
            );
        }
    }

    #[test]
    fn seccomp_argument_must_be_exactly_one_enforcing_true() {
        let cmdline = |arguments: &[&str]| {
            let mut bytes = Vec::new();
            for argument in arguments {
                bytes.extend_from_slice(argument.as_bytes());
                bytes.push(0);
            }
            bytes
        };
        assert_eq!(
            check_seccomp_argument(&cmdline(&[
                "cloud-hypervisor",
                "--api-socket",
                "path=api.sock",
                "--seccomp",
                "true",
                "--landlock",
            ])),
            Ok(())
        );
        for refused in [
            &["cloud-hypervisor", "--seccomp", "log"][..],
            &["cloud-hypervisor", "--seccomp", "errno"],
            &["cloud-hypervisor", "--seccomp", "false"],
            &["cloud-hypervisor"],
            &["cloud-hypervisor", "--seccomp"],
            &["cloud-hypervisor", "--seccomp", "true", "--seccomp", "log"],
            &["cloud-hypervisor", "--seccomp", "true", "--seccomp=log"],
            &["cloud-hypervisor", "--seccomp=true"],
        ] {
            assert!(
                check_seccomp_argument(&cmdline(refused)).is_err(),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn process_confinement_parser_requires_unique_exact_fields() {
        let status = "Name:\tcloud-hypervisor\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n";
        assert_eq!(
            parse_process_confinement(status).unwrap(),
            ProcessConfinement {
                seccomp: 2,
                seccomp_filters: 1,
                no_new_privs: 1,
                cap_inh: 0,
                cap_prm: 0,
                cap_eff: 0,
                cap_amb: 0,
            }
        );
        assert!(
            parse_process_confinement("CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp:\t2\nSeccomp_filters:\t1\n")
                .is_err()
        );
        assert!(
            parse_process_confinement("CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\nSeccomp:\tfilter\nSeccomp_filters:\t1\n")
                .is_err()
        );
    }
}
