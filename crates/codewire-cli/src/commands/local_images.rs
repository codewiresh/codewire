//! `cw prune --local`: delete the workspace images local VMs keep after their
//! last VM is removed (#4262).
//!
//! The supervisor keeps the newest pulled image of each of at most two
//! repositories so the next create pulls nothing; this gives the disk back.
//! An image a VM, a pending create or a disk snapshot still uses stays.

use anyhow::Context as _;
use codewire_local_vmm::control::v1;

use super::EnvPruneArgs;
use super::collaboration::prompt_confirm_default_no;
use super::native_client;
use super::snapshot::gib;

pub(super) async fn prune(args: EnvPruneArgs) -> anyhow::Result<()> {
    let client = native_client().await?;
    let report = client
        .prune_images(true)
        .await
        .context("list retained images")?;
    if report.images.is_empty() {
        println!("No retained images to delete.");
        return Ok(());
    }
    print!("{}", report_text(&report));
    if args.dry_run {
        println!("Would free {} (dry run).", gib(report.reclaimable_bytes));
        return Ok(());
    }
    if !args.yes && !prompt_confirm_default_no("Delete the retained images?")? {
        println!("Aborted.");
        return Ok(());
    }
    let pruned = client
        .prune_images(false)
        .await
        .context("delete retained images")?;
    if pruned.collection_pending {
        println!(
            "Forgot the retained images; their {} is freed once the local VM work in progress ends.",
            gib(pruned.reclaimable_bytes)
        );
    } else {
        println!("Freed {}.", gib(pruned.reclaimable_bytes));
    }
    Ok(())
}

/// One line per image: its repository, its size and how much of it only the
/// record keeps.
fn report_text(report: &v1::PruneImagesResponse) -> String {
    let mut text = String::from("Images kept for the next local VM:\n");
    for image in &report.images {
        let shared = image.bytes.saturating_sub(image.reclaimable_bytes);
        let note = if shared == 0 {
            String::new()
        } else {
            format!(" ({} still used by a VM or snapshot, kept)", gib(shared))
        };
        text.push_str(&format!(
            "  {}  {}{note}\n",
            image.repository,
            gib(image.bytes)
        ));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_names_each_image_and_what_stays() {
        let gib = 1024 * 1024 * 1024;
        let report = v1::PruneImagesResponse {
            images: vec![
                v1::RetainedImage {
                    repository: "ghcr.io/acme/workspace".to_owned(),
                    bytes: 2 * gib,
                    reclaimable_bytes: 2 * gib,
                },
                v1::RetainedImage {
                    repository: "ghcr.io/acme/tools".to_owned(),
                    bytes: gib,
                    reclaimable_bytes: gib / 2,
                },
            ],
            reclaimable_bytes: 2 * gib + gib / 2,
            collection_pending: false,
        };
        assert_eq!(
            report_text(&report),
            "Images kept for the next local VM:\n  \
             ghcr.io/acme/workspace  2.0 GiB\n  \
             ghcr.io/acme/tools  1.0 GiB (0.5 GiB still used by a VM or snapshot, kept)\n"
        );
    }
}
