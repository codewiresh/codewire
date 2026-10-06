use std::time::{Duration, Instant};

use super::*;

fn meter(stage: CloneStage, percent: u8) -> CloneProgress {
    CloneProgress { stage, percent }
}

/// Stderr of a real `git clone --progress` over HTTP, as Git writes it:
/// carriage returns rewrite a meter, a newline ends it.
const CLONE_STDERR: &[u8] = b"Cloning into 'app'...\n\
remote: Enumerating objects: 1234, done.\n\
remote: Counting objects:   1% (13/1234)\rremote: Counting objects:  50% (617/1234)\rremote: Counting objects: 100% (1234/1234), done.\n\
remote: Compressing objects: 100% (500/500), done.\n\
remote: Total 1234 (delta 333), reused 900 (delta 300), pack-reused 0 (from 0)\n\
Receiving objects:   0% (1/1234)\rReceiving objects:  45% (555/1234), 1.20 MiB | 2.40 MiB/s\rReceiving objects: 100% (1234/1234), 2.66 MiB | 2.40 MiB/s, done.\n\
Resolving deltas:   0% (0/333)\rResolving deltas: 100% (333/333), done.\n\
Updating files:  50% (10/20)\rUpdating files: 100% (20/20), done.\n";

fn expected_clone_meters() -> Vec<CloneProgress> {
    vec![
        meter(CloneStage::CountingObjects, 1),
        meter(CloneStage::CountingObjects, 50),
        meter(CloneStage::CountingObjects, 100),
        meter(CloneStage::CompressingObjects, 100),
        meter(CloneStage::ReceivingObjects, 0),
        meter(CloneStage::ReceivingObjects, 45),
        meter(CloneStage::ReceivingObjects, 100),
        meter(CloneStage::ResolvingDeltas, 0),
        meter(CloneStage::ResolvingDeltas, 100),
        meter(CloneStage::UpdatingFiles, 50),
        meter(CloneStage::UpdatingFiles, 100),
    ]
}

#[test]
fn reads_every_stage_meter_of_a_clone() {
    let mut parser = CloneProgressParser::default();
    assert_eq!(parser.feed(CLONE_STDERR), expected_clone_meters());
}

#[test]
fn a_meter_split_across_chunks_is_read_once_it_is_terminated() {
    // Every split point, including inside the stage label and the number.
    for split in 0..=CLONE_STDERR.len() {
        let mut parser = CloneProgressParser::default();
        let mut meters = parser.feed(&CLONE_STDERR[..split]);
        meters.extend(parser.feed(&CLONE_STDERR[split..]));
        assert_eq!(meters, expected_clone_meters(), "split at {split}");
    }
    let mut parser = CloneProgressParser::default();
    let meters: Vec<_> = CLONE_STDERR
        .iter()
        .flat_map(|byte| parser.feed(std::slice::from_ref(byte)))
        .collect();
    assert_eq!(meters, expected_clone_meters());
}

#[test]
fn an_unterminated_tail_is_held_not_guessed() {
    let mut parser = CloneProgressParser::default();
    assert!(parser.feed(b"Receiving objects:  4").is_empty());
    assert_eq!(
        parser.feed(b"5% (1/2)\r"),
        vec![meter(CloneStage::ReceivingObjects, 45)]
    );
}

#[test]
fn only_a_leading_stage_label_and_whole_percentage_count() {
    let mut parser = CloneProgressParser::default();
    let ignored: &[&[u8]] = &[
        b"warning: Receiving objects:  45%\n",
        b"Receiving objects: 101% (1/1)\n",
        b"Receiving objects: 1000% (1/1)\n",
        b"Receiving objects: 45 (1/1)\n",
        b"Receiving objects: -5%\n",
        b"Receiving objects: %\n",
        b"Receiving objects: 4.5%\n",
        b"Receiving: 45%\n",
        b"receiving objects: 45%\n",
        b"Enumerating objects: 1234, done.\n",
        b"\n\r\r\n",
    ];
    for line in ignored {
        assert!(
            parser.feed(line).is_empty(),
            "{:?}",
            String::from_utf8_lossy(line)
        );
    }
    assert_eq!(
        parser.feed(b"  remote:   Resolving deltas:  7% (1/14)\n"),
        vec![meter(CloneStage::ResolvingDeltas, 7)]
    );
}

#[test]
fn hostile_output_never_surfaces_beyond_numbers_and_fixed_tokens() {
    let secret = "synthetic-credential-ghp_0123456789abcdef";
    let url = "https://user:synthetic-password@git.example.test/org/private.git";
    let hostile = format!(
        "Cloning into '/workspace/{secret}'...\n\
         remote: {secret}\n\
         remote: Counting objects: 50% {url}\r\
         fatal: unable to access '{url}': The requested URL returned error: 403\n\
         Receiving objects: 45% ({secret}/{url}) | {secret}\r\
         remote: Receiving objects: {secret} 99%\n\
         error: RPC failed; curl 92 HTTP/2 stream {secret}\n"
    );
    let mut parser = CloneProgressParser::default();
    let meters = parser.feed(hostile.as_bytes());
    assert_eq!(
        meters,
        vec![
            meter(CloneStage::CountingObjects, 50),
            meter(CloneStage::ReceivingObjects, 45),
        ]
    );
    for progress in meters {
        let row = progress_metadata(1, 2, progress).to_string();
        assert!(!row.contains("synthetic"), "{row}");
        assert!(!row.contains("example"), "{row}");
        let object = progress_metadata(1, 2, progress);
        let keys: Vec<_> = object.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["percent", "repo_count", "repo_index", "stage"]);
        assert!(
            ["counting_objects", "receiving_objects"].contains(&object["stage"].as_str().unwrap())
        );
    }
}

#[test]
fn an_overlong_segment_is_discarded_through_its_terminator() {
    let mut parser = CloneProgressParser::default();
    let mut long = b"Receiving objects:  45% ".to_vec();
    long.extend(std::iter::repeat_n(b'x', MAX_SEGMENT_BYTES * 2));
    assert!(parser.feed(&long).is_empty());
    // The terminator ends the discarded segment; the next meter is read.
    assert_eq!(
        parser.feed(b"\rReceiving objects: 50%\r"),
        vec![meter(CloneStage::ReceivingObjects, 50)]
    );
    let mut parser = CloneProgressParser::default();
    let mut long = vec![b'x'; MAX_SEGMENT_BYTES + 1];
    long.extend_from_slice(b"Receiving objects: 45%\n");
    assert!(parser.feed(&long).is_empty());
    assert_eq!(
        parser.feed(b"Receiving objects: 46%\n"),
        vec![meter(CloneStage::ReceivingObjects, 46)]
    );
}

#[test]
fn throttle_writes_each_stage_start_and_end_and_spaces_the_rest() {
    let start = Instant::now();
    let mut throttle = ProgressThrottle::new(Duration::from_secs(1));
    let at = |millis| start + Duration::from_millis(millis);
    assert!(throttle.admit(meter(CloneStage::ReceivingObjects, 1), at(0)));
    assert!(!throttle.admit(meter(CloneStage::ReceivingObjects, 1), at(2_000)));
    assert!(!throttle.admit(meter(CloneStage::ReceivingObjects, 5), at(400)));
    assert!(throttle.admit(meter(CloneStage::ReceivingObjects, 9), at(1_000)));
    // Never backwards within a stage.
    assert!(!throttle.admit(meter(CloneStage::ReceivingObjects, 3), at(5_000)));
    // A stage's first report and its completion are always written.
    assert!(throttle.admit(meter(CloneStage::ResolvingDeltas, 0), at(1_001)));
    assert!(throttle.admit(meter(CloneStage::ReceivingObjects, 100), at(1_002)));
    assert!(!throttle.admit(meter(CloneStage::ReceivingObjects, 100), at(9_000)));
}

#[test]
fn a_remote_cannot_make_one_repository_write_unbounded_rows() {
    let start = Instant::now();
    let mut throttle = ProgressThrottle::new(Duration::ZERO);
    let mut parser = CloneProgressParser::default();
    let mut rows = 0;
    for round in 0..50 {
        for (label, _) in STAGES {
            for percent in (0..=100).rev().chain(0..=100) {
                let mut line = b"remote: ".to_vec();
                line.extend_from_slice(label);
                line.extend_from_slice(format!(" {percent}%\r").as_bytes());
                for progress in parser.feed(&line) {
                    rows +=
                        usize::from(throttle.admit(progress, start + Duration::from_secs(round)));
                }
            }
        }
    }
    assert!(rows <= STAGES.len() * 101, "{rows} rows");
}

#[test]
fn repository_rows_carry_only_their_position() {
    assert_eq!(
        repository_metadata(2, 3),
        serde_json::json!({"repo_index": 2, "repo_count": 3})
    );
    assert_eq!(
        progress_metadata(1, 1, meter(CloneStage::UpdatingFiles, 100)),
        serde_json::json!({"repo_index": 1, "repo_count": 1, "stage": "updating_files", "percent": 100})
    );
}

/// The parser against what the installed Git actually writes, not only the
/// hand-written transcript above.
#[cfg(target_os = "linux")]
#[test]
fn real_git_clone_progress_is_read_as_numbers_only() {
    use std::process::Command;

    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let git = |args: &[&str], dir: &std::path::Path| {
        let output = Command::new("/usr/bin/git")
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("HOME", root.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Synthetic")
            .env("GIT_AUTHOR_EMAIL", "synthetic@example.test")
            .env("GIT_COMMITTER_NAME", "Synthetic")
            .env("GIT_COMMITTER_EMAIL", "synthetic@example.test")
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?} failed");
        output
    };
    std::fs::create_dir(&source).unwrap();
    git(&["init", "-q", "-b", "main"], &source);
    for file in 0..40 {
        std::fs::write(
            source.join(format!("file-{file}.txt")),
            format!("{file}\n").repeat(200),
        )
        .unwrap();
    }
    git(&["add", "."], &source);
    git(&["commit", "-q", "-m", "synthetic"], &source);
    let url = format!("file://{}", source.display());
    let output = git(
        &["clone", "--progress", "--no-local", &url, "destination"],
        root.path(),
    );

    let mut parser = CloneProgressParser::default();
    let meters = parser.feed(&output.stderr);
    assert!(
        meters.contains(&meter(CloneStage::ReceivingObjects, 100)),
        "{meters:?}"
    );
    for progress in meters {
        let row = progress_metadata(1, 1, progress).to_string();
        assert!(!row.contains(&*root.path().to_string_lossy()), "{row}");
    }
}
