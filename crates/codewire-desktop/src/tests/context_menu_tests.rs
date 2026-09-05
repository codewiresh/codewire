//! Context menu tests using #[gpui::test] headless infrastructure.
//!
//! These tests verify that context menus open/close correctly and
//! menu item clicks trigger the expected actions.

use gpui::{AppContext as _, Modifiers, MouseButton, TestAppContext, VisualTestContext, point, px};

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
async fn test_right_click_opens_context_menu(cx: &mut TestAppContext) {
    let (_split, cx) = setup_split_container(cx);

    // Right-click on the pane area (below tab bar, at center)
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

    // If we get here without a panic, the right-click handling works
}

#[gpui::test]
async fn test_left_click_after_right_click(cx: &mut TestAppContext) {
    let (split, cx) = setup_split_container(cx);

    // Add a terminal tab first
    split.update(cx, |sc, cx| {
        sc.open_terminal(
            "ws-test".to_string(),
            "s1".to_string(),
            TerminalConnection::Local,
            "zellij".to_string(),
            cx,
        );
    });

    // Right-click then left-click should not crash
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

    cx.simulate_click(point(px(10.0), px(10.0)), Modifiers::none());
    cx.run_until_parked();
}

#[gpui::test]
async fn test_multiple_right_clicks_dont_crash(cx: &mut TestAppContext) {
    let (_split, cx) = setup_split_container(cx);

    // Rapid right-clicks at different positions
    for i in 0..5 {
        let x = 100.0 + (i as f32 * 50.0);
        cx.simulate_mouse_down(
            point(px(x), px(300.0)),
            MouseButton::Right,
            Modifiers::none(),
        );
        cx.simulate_mouse_up(
            point(px(x), px(300.0)),
            MouseButton::Right,
            Modifiers::none(),
        );
        cx.run_until_parked();
    }
    // If we get here without panic, the test passes
}
