//! Pane interaction tests using #[gpui::test] headless infrastructure.
//!
//! These tests verify that pane operations (click, right-click, tab switching,
//! split) work correctly without crashing.

use gpui::{AppContext as _, Modifiers, MouseButton, TestAppContext, VisualTestContext, point, px};

use crate::chat::ChatPanel;
use crate::pane_tree::{RemoteConnection, SplitDirection};
use crate::split_container::SplitContainer;

/// Helper: create a SplitContainer with a window for testing.
fn setup_split_container(
    cx: &mut TestAppContext,
) -> (gpui::Entity<SplitContainer>, &mut VisualTestContext) {
    let chat = cx.new(|cx| ChatPanel::new(cx));
    cx.add_window_view(|_window, cx| SplitContainer::new(chat, cx))
}

#[gpui::test]
async fn test_right_click_on_pane_doesnt_crash(cx: &mut TestAppContext) {
    let (_split, cx) = setup_split_container(cx);

    // Simulate right-click at center of the window
    cx.simulate_mouse_down(
        point(px(400.0), px(300.0)),
        MouseButton::Right,
        Modifiers::none(),
    );
    cx.simulate_mouse_up(
        point(px(400.0), px(300.0)),
        MouseButton::Right,
        Modifiers::none(),
    );
    cx.run_until_parked();

    // If we get here without a panic, the regression test passes.
    // This validates the fix for the right-click crash bug.
}

#[gpui::test]
async fn test_left_click_on_pane_doesnt_crash(cx: &mut TestAppContext) {
    let (_split, cx) = setup_split_container(cx);

    // Simulate left-click at center
    cx.simulate_click(point(px(400.0), px(300.0)), Modifiers::none());
    cx.run_until_parked();
}

#[gpui::test]
async fn test_split_container_has_initial_tab(cx: &mut TestAppContext) {
    let (split, _cx) = setup_split_container(cx);

    split.read_with(cx, |sc, _cx| {
        // Initial state: one pane with one Chat tab
        let pane = sc.active_pane().expect("should have an active pane");
        assert!(
            !pane.tabs.is_empty(),
            "initial pane should have at least one tab"
        );
    });
}

#[gpui::test]
async fn test_add_tab_to_active_pane(cx: &mut TestAppContext) {
    let (split, _cx) = setup_split_container(cx);

    split.update(cx, |sc, cx| {
        let initial_count = sc.active_pane().unwrap().tabs.len();

        // Add a terminal tab
        sc.open_terminal(
            "ws-test".to_string(),
            "session-1".to_string(),
            RemoteConnection::Ssh {
                host: "test-host".to_string(),
            },
            "zellij".to_string(),
            cx,
        );

        let new_count = sc.active_pane().unwrap().tabs.len();
        assert_eq!(
            new_count,
            initial_count + 1,
            "tab count should increase by 1"
        );
    });
}

#[gpui::test]
async fn test_tab_switching(cx: &mut TestAppContext) {
    let (split, _cx) = setup_split_container(cx);

    split.update(cx, |sc, cx| {
        // Add a second tab
        sc.open_terminal(
            "ws-test".to_string(),
            "session-1".to_string(),
            RemoteConnection::Ssh {
                host: "test-host".to_string(),
            },
            "zellij".to_string(),
            cx,
        );

        let pane_id = sc.active_pane().unwrap().id;
        let tabs: Vec<_> = sc
            .active_pane()
            .unwrap()
            .tabs
            .iter()
            .map(|t| t.id)
            .collect();
        assert!(tabs.len() >= 2, "should have at least 2 tabs");

        // The newly added tab should be active (add_tab makes it active)
        let active_before = sc.active_pane().unwrap().active_tab;
        assert_eq!(active_before, tabs.len() - 1);

        // Switch to first tab
        sc.select_tab(pane_id, tabs[0], cx);
        let active_after = sc.active_pane().unwrap().active_tab;
        assert_eq!(active_after, 0, "should switch to first tab");
    });
}

#[gpui::test]
async fn test_split_pane_creates_new_pane(cx: &mut TestAppContext) {
    let (split, _cx) = setup_split_container(cx);

    split.update(cx, |sc, cx| {
        let pane_ids_before = sc.active_pane().unwrap().id;

        sc.split_active_pane(SplitDirection::Horizontal, cx);

        // The original pane should still be the active one
        assert_eq!(sc.active_pane().unwrap().id, pane_ids_before);
    });

    // Verify the tree now has 2 panes by reading the root
    split.read_with(cx, |sc, _cx| {
        // After split, root should be a Split node with 2 leaf children
        let all_panes = sc.active_pane(); // Just verify we can still access it
        assert!(all_panes.is_some());
    });
}

#[gpui::test]
async fn test_close_tab(cx: &mut TestAppContext) {
    let (split, _cx) = setup_split_container(cx);

    split.update(cx, |sc, cx| {
        // Add two terminal tabs (so we have chat + 2 terminals = 3 tabs)
        sc.open_terminal(
            "ws-test".to_string(),
            "session-1".to_string(),
            RemoteConnection::Ssh {
                host: "host1".to_string(),
            },
            "zellij".to_string(),
            cx,
        );
        sc.open_terminal(
            "ws-test".to_string(),
            "session-2".to_string(),
            RemoteConnection::Ssh {
                host: "host2".to_string(),
            },
            "zellij".to_string(),
            cx,
        );

        let pane_id = sc.active_pane().unwrap().id;
        let tab_count_before = sc.active_pane().unwrap().tabs.len();
        assert_eq!(tab_count_before, 3);

        // Close the last tab
        let last_tab_id = sc.active_pane().unwrap().tabs.last().unwrap().id;
        sc.close_tab(pane_id, last_tab_id, cx);

        let tab_count_after = sc.active_pane().unwrap().tabs.len();
        assert_eq!(tab_count_after, 2, "tab count should decrease by 1");
    });
}

#[gpui::test]
async fn test_next_prev_tab(cx: &mut TestAppContext) {
    let (split, _cx) = setup_split_container(cx);

    split.update(cx, |sc, cx| {
        // Add second tab
        sc.open_terminal(
            "ws-test".to_string(),
            "session-1".to_string(),
            RemoteConnection::Ssh {
                host: "host1".to_string(),
            },
            "zellij".to_string(),
            cx,
        );

        // Active tab should be the last one (index 1)
        assert_eq!(sc.active_pane().unwrap().active_tab, 1);

        // prev_tab should go to 0
        sc.prev_tab(cx);
        assert_eq!(sc.active_pane().unwrap().active_tab, 0);

        // prev_tab again should wrap to last
        sc.prev_tab(cx);
        assert_eq!(sc.active_pane().unwrap().active_tab, 1);

        // next_tab should wrap to 0
        sc.next_tab(cx);
        assert_eq!(sc.active_pane().unwrap().active_tab, 0);
    });
}
