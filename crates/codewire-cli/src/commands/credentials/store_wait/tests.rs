use super::*;

#[cfg(target_os = "linux")]
#[test]
fn the_line_names_the_keyring_and_counts_the_wait() {
    assert_eq!(
        waiting_line(Duration::from_secs(75), 0, false),
        "\r  ◐ Waiting for your keyring (Secret Service) to answer · unlock it if it asks 1:15\x1b[K"
    );
    assert_eq!(
        waiting_line(Duration::from_secs(3), 1, true),
        "\r  / Waiting for your keyring (Secret Service) to answer - unlock it if it asks 0:03\x1b[K"
    );
    assert_eq!(
        plain_line(),
        "Waiting for your keyring (Secret Service) to answer; unlock it if it asks."
    );
}

/// An answer within the first second is returned as is, and JSON output never
/// waits on a timer.
#[tokio::test(start_paused = true)]
async fn a_prompt_answer_or_json_shows_nothing_and_returns_the_answer() {
    assert_eq!(waiting_on_store(false, async { 7 }).await, 7);
    let slow = async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        9
    };
    assert_eq!(waiting_on_store(true, slow).await, 9);
}
