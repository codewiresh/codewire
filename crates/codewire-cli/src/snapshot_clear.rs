//! `cw __snapshot-clear`, the clearing Sandbox's only process.

/// A snapshot's clearing Sandbox runs this as its only process: `__snapshot-clear
/// ROOT` for a restore the node mounted at ROOT, `--standard-vm ROOT [--report
/// PATH]` for a `standard` VM restore whose home lives inside `state.raw`, or
/// `__snapshot-clear --block DEVICE [--report PATH]` for a Block restore, which
/// it clears and wipes without mounting it, writing its report line to PATH too.
/// It runs before any CLI setup, and prints only counts and an error,
/// never a path or a file's contents. Any failure exits non-zero, so the capture
/// keeps nothing.
pub fn run_snapshot_clear_from(arguments: impl Iterator<Item = std::ffi::OsString>) -> i32 {
    use codewire_daemon::snapshot_clearing::{block, clear_workspace_volume, standard_vm};
    use std::path::Path;

    let arguments = arguments.collect::<Vec<_>>();
    match arguments.as_slice() {
        [root] => match clear_workspace_volume(Path::new(root)) {
            Ok(report) => {
                println!(
                    "cleared logins={} trees={}",
                    report.logins_removed, report.trees_removed
                );
                0
            }
            Err(error) => {
                eprintln!("clearing failed: {error}");
                1
            }
        },
        [flag, root, rest @ ..]
            if flag == "--standard-vm"
                && matches!(rest, [] | [_, _])
                && rest.first().is_none_or(|flag| flag == "--report") =>
        {
            let report_path = rest.get(1).map(Path::new);
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("clearing failed: {error}");
                    return 1;
                }
            };
            let started = std::time::Instant::now();
            match runtime.block_on(standard_vm::clear_standard_vm_volume(Path::new(root))) {
                Ok(report) => {
                    let ms = started.elapsed().as_millis();
                    let line = format!(
                        "cleared logins={} trees={} ms={ms}",
                        report.logins_removed, report.trees_removed,
                    );
                    println!("{line}");
                    if let Some(path) = report_path
                        && let Err(error) = std::fs::write(path, format!("{line}\n"))
                    {
                        eprintln!("warning: the clearing report could not be written: {error}");
                    }
                    0
                }
                Err(error) => {
                    eprintln!("clearing failed: {error}");
                    1
                }
            }
        }
        [flag, device, rest @ ..]
            if flag == "--block"
                && matches!(rest, [] | [_, _])
                && rest.first().is_none_or(|flag| flag == "--report") =>
        {
            let report_path = rest.get(1).map(Path::new);
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("clearing failed: {error}");
                    return 1;
                }
            };
            let started = std::time::Instant::now();
            match runtime.block_on(block::clear_block_volume(Path::new(device))) {
                Ok(report) => {
                    let ms = started.elapsed().as_millis();
                    let wipe = report.wipe;
                    let line = format!(
                        "cleared logins={} trees={} wiped ranges={} bytes={} discard={} discarded={} fallback={} written={} ms={ms}",
                        report.files.logins_removed,
                        report.files.trees_removed,
                        wipe.ranges,
                        wipe.bytes,
                        wipe.discard_supported,
                        wipe.discarded_ranges,
                        wipe.fallback_ranges,
                        wipe.written_bytes,
                    );
                    println!("{line}");
                    if !wipe.discard_supported || wipe.fallback_ranges > 0 {
                        eprintln!(
                            "warning: discards didn't clear {} of {} ranges (discard supported: {}), so {} bytes were overwritten; clearing took {ms} ms",
                            if wipe.discard_supported {
                                wipe.fallback_ranges
                            } else {
                                wipe.ranges
                            },
                            wipe.ranges,
                            wipe.discard_supported,
                            wipe.written_bytes,
                        );
                    }
                    // The report is information for the capture's log; the
                    // volume is cleared whether or not it can be written.
                    if let Some(path) = report_path
                        && let Err(error) = std::fs::write(path, format!("{line}\n"))
                    {
                        eprintln!("warning: the clearing report could not be written: {error}");
                    }
                    0
                }
                Err(error) => {
                    eprintln!("clearing failed: {error}");
                    1
                }
            }
        }
        _ => {
            eprintln!(
                "usage: cw __snapshot-clear ROOT | --standard-vm ROOT [--report PATH] | --block DEVICE [--report PATH]"
            );
            2
        }
    }
}
