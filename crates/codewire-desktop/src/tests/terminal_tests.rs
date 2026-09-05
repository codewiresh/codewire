//! Terminal focus tests using #[gpui::test] headless infrastructure.
//!
//! These tests verify that terminal views receive focus correctly
//! when their containing pane is clicked or activated.

use gpui::{AppContext as _, Modifiers, TestAppContext, VisualTestContext, point, px};

use crate::chat::ChatPanel;
use crate::pane_tree::TerminalConnection;
use crate::split_container::SplitContainer;

/// Helper: create a SplitContainer with a window for testing.
fn setup_split_container(
    cx: &mut TestAppContext,
) -> (gpui::Entity<SplitContainer>, &mut VisualTestContext) {
    let chat = cx.new(|cx| ChatPanel::new(cx));
    cx.add_window_view(|_window, cx| SplitContainer::new(chat, cx))
}

#[gpui::test]
async fn test_terminal_entity_created_on_open(cx: &mut TestAppContext) {
    let (split, _cx) = setup_split_container(cx);

    split.update(cx, |sc, cx| {
        assert_eq!(sc.terminal_count(), 0, "no terminals initially");

        sc.open_terminal(
            "ws-test".to_string(),
            "session-1".to_string(),
            TerminalConnection::Local,
            "zellij".to_string(),
            cx,
        );

        assert_eq!(sc.terminal_count(), 1, "one terminal after opening");
    });
}

#[gpui::test]
async fn test_duplicate_terminal_reuses_tab(cx: &mut TestAppContext) {
    let (split, _cx) = setup_split_container(cx);

    split.update(cx, |sc, cx| {
        sc.open_terminal(
            "ws-test".to_string(),
            "session-1".to_string(),
            TerminalConnection::Local,
            "zellij".to_string(),
            cx,
        );
        let tab_count_after_first = sc.active_pane().unwrap().tabs.len();

        // Opening same workspace_id + session_name should NOT create a new tab
        sc.open_terminal(
            "ws-test".to_string(),
            "session-1".to_string(),
            TerminalConnection::Local,
            "zellij".to_string(),
            cx,
        );
        let tab_count_after_second = sc.active_pane().unwrap().tabs.len();

        assert_eq!(
            tab_count_after_first, tab_count_after_second,
            "duplicate terminal should reuse existing tab"
        );
        assert_eq!(
            sc.terminal_count(),
            1,
            "should still be one terminal entity"
        );
    });
}

#[gpui::test]
async fn test_close_terminal_tab_removes_entity(cx: &mut TestAppContext) {
    let (split, _cx) = setup_split_container(cx);

    split.update(cx, |sc, cx| {
        sc.open_terminal(
            "ws-test".to_string(),
            "session-1".to_string(),
            TerminalConnection::Local,
            "zellij".to_string(),
            cx,
        );
        assert_eq!(sc.terminal_count(), 1);

        // Find the terminal tab and close it
        let pane_id = sc.active_pane().unwrap().id;
        let terminal_tab_id = sc
            .active_pane()
            .unwrap()
            .tabs
            .iter()
            .find(|t| matches!(t.content, crate::pane_tree::TabContent::Terminal { .. }))
            .map(|t| t.id)
            .expect("should find terminal tab");

        sc.close_tab(pane_id, terminal_tab_id, cx);

        assert_eq!(
            sc.terminal_count(),
            0,
            "terminal entity should be cleaned up after closing tab"
        );
    });
}

#[gpui::test]
async fn test_multiple_terminals_independent(cx: &mut TestAppContext) {
    let (split, _cx) = setup_split_container(cx);

    split.update(cx, |sc, cx| {
        sc.open_terminal(
            "ws1".to_string(),
            "session-1".to_string(),
            TerminalConnection::Local,
            "zellij".to_string(),
            cx,
        );
        sc.open_terminal(
            "ws2".to_string(),
            "session-2".to_string(),
            TerminalConnection::Local,
            "tmux".to_string(),
            cx,
        );

        assert_eq!(
            sc.terminal_count(),
            2,
            "should have two independent terminals"
        );
    });
}

#[gpui::test]
async fn test_click_on_pane_with_terminal_doesnt_crash(cx: &mut TestAppContext) {
    let (split, cx) = setup_split_container(cx);

    split.update(cx, |sc, cx| {
        sc.open_terminal(
            "ws-test".to_string(),
            "session-1".to_string(),
            TerminalConnection::Local,
            "zellij".to_string(),
            cx,
        );
    });

    // Left-click on the pane area where the terminal renders
    cx.simulate_click(point(px(400.0), px(400.0)), Modifiers::none());
    cx.run_until_parked();

    // If we get here without panic, the test passes
}

#[gpui::test]
async fn test_local_terminal_opens(cx: &mut TestAppContext) {
    let (split, _cx) = setup_split_container(cx);

    split.update(cx, |sc, cx| {
        sc.open_local_terminal(cx);
        assert_eq!(sc.terminal_count(), 1, "local terminal should be created");
    });
}
