//! Default landing view for a workspace container.
//!
//! Shows the workspace identity and a hint about opening surfaces from the sidebar.

use crate::theme::Theme;
use crate::workspace::{WorkspaceIdentity, WorkspaceSource};
use gpui::{App, Context, FocusHandle, Focusable, Window, div, prelude::*, px};

/// Home screen shown when a workspace is first opened.
pub struct WorkspaceHome {
    identity: WorkspaceIdentity,
    focus_handle: FocusHandle,
}

impl WorkspaceHome {
    pub fn new(identity: WorkspaceIdentity, cx: &mut Context<Self>) -> Self {
        Self {
            identity,
            focus_handle: cx.focus_handle(),
        }
    }
}

impl Focusable for WorkspaceHome {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for WorkspaceHome {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();

        let source_label = match &self.identity.source {
            WorkspaceSource::Local { path } => format!("Local: {}", path),
            WorkspaceSource::Dashboard => "Codewire Dashboard".to_string(),
            WorkspaceSource::CodewireEnvironment {
                org_slug, env_id, ..
            } => format!("Environment: {}/{}", org_slug, env_id),
        };

        div()
            .size_full()
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap_4()
            .bg(theme.surface)
            .font_family(".AppleSystemUIFont")
            .track_focus(&self.focus_handle)
            .child(
                div()
                    .text_size(px(24.0))
                    .text_color(theme.foreground)
                    .child(self.identity.name.clone()),
            )
            .child(
                div()
                    .text_size(px(13.0))
                    .text_color(theme.muted)
                    .child(source_label),
            )
            .child(
                div()
                    .text_size(px(12.0))
                    .text_color(theme.muted)
                    .mt_4()
                    .child(
                        "Open files, terminals, environments, and dashboard pages from the sidebar",
                    ),
            )
    }
}
