//! Native workspace status and transmission bar.

use crate::sidebar::WorkspaceStatusCounts;
use crate::theme::Theme;
use gpui::{App, Context, FocusHandle, Focusable, Hsla, Window, div, prelude::*, px, svg};

/// Network transmission statistics (stubbed for now).
#[derive(Clone, Debug, Default)]
pub struct TransmissionStats {
    pub bytes_received: Option<u64>,
    pub bytes_sent: Option<u64>,
    pub avg_latency_ms: Option<f64>,
}

pub struct StatusBar {
    workspace_counts: WorkspaceStatusCounts,
    transmission: TransmissionStats,
    focus_handle: FocusHandle,
}

impl StatusBar {
    pub fn new(cx: &mut Context<Self>) -> Self {
        Self {
            workspace_counts: WorkspaceStatusCounts::default(),
            transmission: TransmissionStats::default(),
            focus_handle: cx.focus_handle(),
        }
    }

    pub fn update_workspace_counts(
        &mut self,
        counts: WorkspaceStatusCounts,
        cx: &mut Context<Self>,
    ) {
        self.workspace_counts = counts;
        cx.notify();
    }

    pub fn update_transmission(&mut self, stats: TransmissionStats, cx: &mut Context<Self>) {
        self.transmission = stats;
        cx.notify();
    }
}

impl Focusable for StatusBar {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} kB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn icon_value_pair(
    icon_path: &'static str,
    value: impl ToString,
    icon_color: Hsla,
    text_color: Hsla,
) -> impl IntoElement {
    div()
        .flex()
        .h_full()
        .items_center()
        .gap(px(3.0))
        .child(
            svg()
                .path(icon_path)
                .size(px(12.0))
                .flex_shrink_0()
                .text_color(icon_color),
        )
        .child(
            div()
                .text_color(text_color)
                .line_height(px(24.0))
                .child(value.to_string()),
        )
}

fn separator(muted: Hsla) -> impl IntoElement {
    div()
        .flex()
        .h_full()
        .items_center()
        .text_color(muted)
        .mx(px(4.0))
        .line_height(px(24.0))
        .child("/")
}

impl Render for StatusBar {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();
        let counts = &self.workspace_counts;
        let muted = theme.muted;
        let fg = theme.foreground;

        let rx_text = self
            .transmission
            .bytes_received
            .map(format_bytes)
            .unwrap_or_else(|| "--".to_string());
        let tx_text = self
            .transmission
            .bytes_sent
            .map(format_bytes)
            .unwrap_or_else(|| "--".to_string());
        let latency_text = self
            .transmission
            .avg_latency_ms
            .map(|ms| format!("{:.2} ms", ms))
            .unwrap_or_else(|| "--".to_string());

        div()
            .h(px(24.0))
            .w_full()
            .flex()
            .items_center()
            .justify_between()
            .px_3()
            .bg(theme.surface)
            .border_t_1()
            .border_color(theme.border)
            .text_size(px(11.0))
            .font_family(".AppleSystemUIFont")
            .child(
                div()
                    .h_full()
                    .flex()
                    .items_center()
                    .gap(px(4.0))
                    .child(
                        div()
                            .h_full()
                            .flex()
                            .items_center()
                            .text_color(muted)
                            .mr(px(4.0))
                            .line_height(px(24.0))
                            .child("Workspaces"),
                    )
                    .child(icon_value_pair(
                        "icons/status-pending.svg",
                        counts.pending,
                        theme.status_needs_auth,
                        fg,
                    ))
                    .child(separator(muted))
                    .child(icon_value_pair(
                        "icons/status-building.svg",
                        counts.building,
                        theme.status_needs_auth,
                        fg,
                    ))
                    .child(separator(muted))
                    .child(icon_value_pair(
                        "icons/status-running.svg",
                        counts.running,
                        theme.status_running,
                        fg,
                    ))
                    .child(separator(muted))
                    .child(icon_value_pair(
                        "icons/status-stopped.svg",
                        counts.stopped,
                        theme.status_stopped,
                        fg,
                    ))
                    .child(separator(muted))
                    .child(icon_value_pair(
                        "icons/status-failed.svg",
                        counts.failed,
                        theme.git_deletions,
                        fg,
                    )),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(4.0))
                    .child(
                        div()
                            .h_full()
                            .flex()
                            .items_center()
                            .text_color(muted)
                            .mr(px(4.0))
                            .line_height(px(24.0))
                            .child("Transmission"),
                    )
                    .child(icon_value_pair("icons/arrow-down.svg", &rx_text, muted, fg))
                    .child(separator(muted))
                    .child(icon_value_pair("icons/arrow-up.svg", &tx_text, muted, fg))
                    .child(separator(muted))
                    .child(icon_value_pair(
                        "icons/refresh.svg",
                        &latency_text,
                        muted,
                        fg,
                    )),
            )
    }
}
