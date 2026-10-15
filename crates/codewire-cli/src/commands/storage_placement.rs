use std::io::{BufRead, IsTerminal as _, Write};

use anyhow::Context as _;

pub(crate) use codewire_project::StoragePlacement;

/// A management command's explicit store constrains a qualified reference; it
/// never permits fallback to another origin or changes execution placement.
pub(crate) fn require_reference_placement<'a>(
    reference: codewire_project::StorageReference<'a>,
    placement: StoragePlacement,
) -> anyhow::Result<&'a str> {
    anyhow::ensure!(
        reference.placement.is_none_or(|origin| origin == placement),
        "source origin conflicts with the explicitly selected storage placement"
    );
    Ok(reference.selector)
}

/// Storage is selected independently of the current execution environment.
/// Resolve it before connecting to an authority or reading protected material.
pub(crate) fn resolve_storage_placement(
    local: bool,
    platform: bool,
    json_output: bool,
) -> anyhow::Result<StoragePlacement> {
    let interactive =
        !json_output && std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    select_storage_placement(local, platform, interactive, || {
        prompt_storage_placement(std::io::stdin().lock(), std::io::stderr().lock())
    })
}

fn select_storage_placement(
    local: bool,
    platform: bool,
    interactive: bool,
    prompt: impl FnOnce() -> anyhow::Result<StoragePlacement>,
) -> anyhow::Result<StoragePlacement> {
    match (local, platform) {
        (true, false) => Ok(StoragePlacement::Local),
        (false, true) => Ok(StoragePlacement::Platform),
        (true, true) => {
            anyhow::bail!("storage placement must be exactly one of --local or --cloud")
        }
        (false, false) if interactive => prompt(),
        (false, false) => anyhow::bail!(
            "storage placement is required: pass --local or --cloud (noninteractive and JSON commands never prompt)"
        ),
    }
}

fn prompt_storage_placement(
    reader: impl BufRead,
    mut writer: impl Write,
) -> anyhow::Result<StoragePlacement> {
    write!(writer, "Storage placement [local/cloud]: ")
        .context("write storage placement prompt")?;
    writer.flush().context("flush storage placement prompt")?;
    let mut input = String::new();
    let count = reader
        .take(65)
        .read_line(&mut input)
        .context("read storage placement")?;
    if count == 0 || input.trim().is_empty() {
        anyhow::bail!("storage placement selection canceled; no storage selected");
    }
    anyhow::ensure!(
        count < 65,
        "invalid storage placement; choose local or cloud"
    );
    match input.trim() {
        "local" => Ok(StoragePlacement::Local),
        "cloud" => Ok(StoragePlacement::Platform),
        _ => anyhow::bail!("invalid storage placement; choose local or cloud"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_placement_never_reads_input_and_conflicts_fail_before_input() {
        for interactive in [false, true] {
            for (local, platform, expected) in [
                (true, false, Some(StoragePlacement::Local)),
                (false, true, Some(StoragePlacement::Platform)),
                (true, true, None),
            ] {
                let result = select_storage_placement(local, platform, interactive, || {
                    panic!("explicit placement must not read input")
                });
                assert_eq!(result.ok(), expected);
            }
        }
    }

    #[test]
    fn missing_noninteractive_placement_never_consumes_sensitive_input() {
        let error = select_storage_placement(false, false, false, || {
            panic!("noninteractive input must remain unread")
        })
        .unwrap_err();
        assert!(error.to_string().contains("--local or --cloud"));
    }

    #[test]
    fn missing_interactive_placement_accepts_only_explicit_answers() {
        for (answer, expected) in [
            ("local\n", Some(StoragePlacement::Local)),
            ("cloud\n", Some(StoragePlacement::Platform)),
            ("platform\n", None),
            ("", None),
            ("\n", None),
            ("yes\n", None),
            ("sensitive-input-canary\n", None),
        ] {
            let mut output = Vec::new();
            let result = select_storage_placement(false, false, true, || {
                prompt_storage_placement(answer.as_bytes(), &mut output)
            });
            if let Err(error) = &result {
                assert!(!error.to_string().contains("sensitive-input-canary"));
            }
            assert_eq!(result.ok(), expected);
            assert_eq!(output, b"Storage placement [local/cloud]: ");
        }
    }

    #[test]
    fn placement_prompt_consumes_only_the_choice_line_and_bounds_invalid_input() {
        let mut input = std::io::Cursor::new(b"local\nvalue-remains-unread\n");
        assert_eq!(
            prompt_storage_placement(&mut input, Vec::new()).unwrap(),
            StoragePlacement::Local
        );
        assert_eq!(input.position(), 6);
        let mut oversized = std::io::Cursor::new(vec![b'x'; 1024]);
        assert!(prompt_storage_placement(&mut oversized, Vec::new()).is_err());
        assert_eq!(oversized.position(), 65);
    }
}
