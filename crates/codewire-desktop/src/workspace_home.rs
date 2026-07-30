//! Native landing surfaces for local projects and Codewire environments.

use crate::theme::Theme;
use crate::workspace::{EnvironmentSummary, WorkspaceIdentity, WorkspaceSource};
use gpui::{App, Context, FocusHandle, Focusable, Hsla, SharedString, Window, div, prelude::*, px};

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

    fn render_dashboard(&self, theme: &Theme) -> gpui::AnyElement {
        div()
            .id("native-dashboard-scroll")
            .size_full()
            .overflow_y_scroll()
            .bg(theme.surface)
            .font_family(".AppleSystemUIFont")
            .track_focus(&self.focus_handle)
            .child(
                div()
                    .max_w(px(980.0))
                    .mx_auto()
                    .px(px(40.0))
                    .py(px(44.0))
                    .flex()
                    .flex_col()
                    .gap(px(28.0))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(10.0))
                            .child(
                                div()
                                    .text_size(px(12.0))
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .text_color(theme.accent)
                                    .child("CODEWIRE DESKTOP"),
                            )
                            .child(
                                div()
                                    .text_size(px(30.0))
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .text_color(theme.foreground)
                                    .child("Your development workspace"),
                            )
                            .child(
                                div()
                                    .max_w(px(680.0))
                                    .text_size(px(14.0))
                                    .line_height(gpui::relative(1.5))
                                    .text_color(theme.muted)
                                    .child(
                                        "Choose an environment or local project in the sidebar. \
                                         Code, terminals, diffs, and workspace layouts stay in \
                                         this native interface.",
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap(px(12.0))
                            .child(self.render_tool_card(
                                "Editor",
                                "Open files without leaving the workspace.",
                                "Available",
                                theme.status_running,
                                theme,
                            ))
                            .child(self.render_tool_card(
                                "Terminal",
                                "Connect to a Codewire environment or work locally.",
                                "Available",
                                theme.status_running,
                                theme,
                            ))
                            .child(self.render_tool_card(
                                "Diff",
                                "Review changes alongside your editor and terminal.",
                                "Available",
                                theme.status_running,
                                theme,
                            ))
                            .child(self.render_tool_card(
                                "Platform actions",
                                "Creation and billing remain in migration.",
                                "Unavailable here",
                                theme.status_needs_auth,
                                theme,
                            )),
                    )
                    .child(
                        div()
                            .p(px(18.0))
                            .rounded(px(8.0))
                            .border_1()
                            .border_color(theme.border)
                            .bg(theme.background)
                            .flex()
                            .flex_col()
                            .gap(px(6.0))
                            .child(
                                div()
                                    .text_size(px(13.0))
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .text_color(theme.foreground)
                                    .child("Native by default"),
                            )
                            .child(
                                div()
                                    .text_size(px(12.0))
                                    .line_height(gpui::relative(1.45))
                                    .text_color(theme.muted)
                                    .child(
                                        "The desktop uses the shared Connect client and opens \
                                         sign-in in your system browser. It does not embed a \
                                         replacement dashboard or handle your password.",
                                    ),
                            ),
                    ),
            )
            .into_any_element()
    }

    fn render_local(&self, path: &str, theme: &Theme) -> gpui::AnyElement {
        div()
            .size_full()
            .bg(theme.surface)
            .font_family(".AppleSystemUIFont")
            .track_focus(&self.focus_handle)
            .flex()
            .items_center()
            .justify_center()
            .child(
                div()
                    .w(px(620.0))
                    .p(px(28.0))
                    .rounded(px(10.0))
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.background)
                    .flex()
                    .flex_col()
                    .gap(px(14.0))
                    .child(
                        div()
                            .text_size(px(11.0))
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .text_color(theme.accent)
                            .child("LOCAL PROJECT"),
                    )
                    .child(
                        div()
                            .text_size(px(24.0))
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .text_color(theme.foreground)
                            .child(self.identity.name.clone()),
                    )
                    .child(
                        div()
                            .p(px(10.0))
                            .rounded(px(6.0))
                            .bg(theme.surface)
                            .font_family("Menlo")
                            .text_size(px(12.0))
                            .text_color(theme.muted)
                            .child(path.to_string()),
                    )
                    .child(div().text_size(px(13.0)).text_color(theme.muted).child(
                        "Use Browse, Diff, and Terminal in the sidebar to open native tools.",
                    )),
            )
            .into_any_element()
    }

    fn render_environment(
        &self,
        org_slug: &str,
        environment: &EnvironmentSummary,
        theme: &Theme,
    ) -> gpui::AnyElement {
        let status_color = environment_status_color(&environment.state, theme);
        let resource_summary = format!(
            "{} CPU · {} MB memory · {} GB disk",
            format_cpu(environment.cpu_millicores),
            environment.memory_mb,
            environment.disk_gb
        );
        let runtime_summary = format_runtime(environment.total_running_seconds);
        let network = nonempty_or(&environment.network, "default");
        let preset = nonempty_or(&environment.preset_name, "Custom");
        let desired_state = nonempty_or(&environment.desired_state, "unspecified");

        div()
            .id(SharedString::from(format!(
                "environment-home-scroll-{}",
                environment.id
            )))
            .size_full()
            .overflow_y_scroll()
            .bg(theme.surface)
            .font_family(".AppleSystemUIFont")
            .track_focus(&self.focus_handle)
            .child(
                div()
                    .max_w(px(1080.0))
                    .mx_auto()
                    .px(px(32.0))
                    .py(px(28.0))
                    .flex()
                    .flex_col()
                    .gap(px(18.0))
                    .child(
                        div()
                            .p(px(20.0))
                            .rounded(px(10.0))
                            .border_1()
                            .border_color(theme.border)
                            .bg(theme.background)
                            .flex()
                            .flex_col()
                            .gap(px(14.0))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .gap(px(4.0))
                                            .child(
                                                div()
                                                    .text_size(px(11.0))
                                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                                    .text_color(theme.accent)
                                                    .child(format!(
                                                        "{} / ENVIRONMENT",
                                                        org_slug.to_uppercase()
                                                    )),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(24.0))
                                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                                    .text_color(theme.foreground)
                                                    .child(environment.name.clone()),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .px(px(10.0))
                                            .py(px(4.0))
                                            .rounded(px(12.0))
                                            .bg(status_color)
                                            .text_size(px(11.0))
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .text_color(gpui::hsla(0.0, 0.0, 1.0, 1.0))
                                            .child(environment.state.clone()),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .gap(px(8.0))
                                    .child(metadata_chip("Preset", preset, theme))
                                    .child(metadata_chip("Resources", resource_summary, theme))
                                    .child(metadata_chip("Network", network, theme))
                                    .child(metadata_chip("Runtime", runtime_summary, theme))
                                    .child(metadata_chip("Desired", desired_state, theme))
                                    .when(environment.protected, |row| {
                                        row.child(metadata_chip("Protection", "Enabled", theme))
                                    }),
                            ),
                    )
                    .when(
                        !environment.error_reason.is_empty() || !environment.setup_error.is_empty(),
                        |root| {
                            let detail = if environment.setup_error.is_empty() {
                                environment.error_reason.clone()
                            } else {
                                environment.setup_error.clone()
                            };
                            root.child(
                                div()
                                    .p(px(14.0))
                                    .rounded(px(8.0))
                                    .border_1()
                                    .border_color(theme.git_deletions)
                                    .bg(theme.background)
                                    .flex()
                                    .flex_col()
                                    .gap(px(5.0))
                                    .child(
                                        div()
                                            .text_size(px(12.0))
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .text_color(theme.git_deletions)
                                            .child("Environment needs attention"),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(12.0))
                                            .text_color(theme.muted)
                                            .child(detail),
                                    ),
                            )
                        },
                    )
                    .child(
                        div()
                            .flex()
                            .gap(px(12.0))
                            .child(self.render_tool_card(
                                "Terminal",
                                "The environment opens with a native terminal tab.",
                                "Available",
                                theme.status_running,
                                theme,
                            ))
                            .child(self.render_tool_card(
                                "Files & editor",
                                "Browse and edit from the workspace panes.",
                                "Available",
                                theme.status_running,
                                theme,
                            ))
                            .child(self.render_tool_card(
                                "Build logs",
                                "Typed desktop log integration is not in this migration slice.",
                                "Unavailable here",
                                theme.status_needs_auth,
                                theme,
                            )),
                    )
                    .child(
                        div()
                            .p(px(18.0))
                            .rounded(px(8.0))
                            .border_1()
                            .border_color(theme.border)
                            .bg(theme.background)
                            .flex()
                            .flex_col()
                            .gap(px(10.0))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .text_size(px(13.0))
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .text_color(theme.foreground)
                                            .child("Ports"),
                                    )
                                    .child(
                                        div().text_size(px(11.0)).text_color(theme.muted).child(
                                            format!("{} configured", environment.ports.len()),
                                        ),
                                    ),
                            )
                            .when(environment.ports.is_empty(), |panel| {
                                panel.child(
                                    div()
                                        .text_size(px(12.0))
                                        .text_color(theme.muted)
                                        .child("No ports are configured for this environment."),
                                )
                            })
                            .children(environment.ports.iter().map(|port| {
                                let label = if port.label.is_empty() {
                                    format!("Port {}", port.port)
                                } else {
                                    port.label.clone()
                                };
                                let endpoint = port
                                    .preview_url
                                    .as_deref()
                                    .unwrap_or("No preview URL")
                                    .to_string();
                                div()
                                    .py(px(8.0))
                                    .border_t_1()
                                    .border_color(theme.border)
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap(px(10.0))
                                            .child(
                                                div()
                                                    .font_family("Menlo")
                                                    .text_size(px(12.0))
                                                    .text_color(theme.foreground)
                                                    .child(port.port.to_string()),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(12.0))
                                                    .text_color(theme.foreground)
                                                    .child(label),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(theme.muted)
                                                    .child(port.access.clone()),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .max_w(px(380.0))
                                            .text_ellipsis()
                                            .font_family("Menlo")
                                            .text_size(px(10.0))
                                            .text_color(theme.muted)
                                            .child(endpoint),
                                    )
                            })),
                    ),
            )
            .into_any_element()
    }

    fn render_tool_card(
        &self,
        title: impl Into<SharedString>,
        description: impl Into<SharedString>,
        status: impl Into<SharedString>,
        status_color: Hsla,
        theme: &Theme,
    ) -> gpui::AnyElement {
        let title: SharedString = title.into();
        let description: SharedString = description.into();
        let status: SharedString = status.into();
        div()
            .min_w(px(210.0))
            .flex_1()
            .p(px(16.0))
            .rounded(px(8.0))
            .border_1()
            .border_color(theme.border)
            .bg(theme.background)
            .flex()
            .flex_col()
            .gap(px(7.0))
            .child(
                div()
                    .text_size(px(13.0))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(theme.foreground)
                    .child(title),
            )
            .child(
                div()
                    .flex_1()
                    .text_size(px(12.0))
                    .line_height(gpui::relative(1.4))
                    .text_color(theme.muted)
                    .child(description),
            )
            .child(
                div()
                    .text_size(px(10.0))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(status_color)
                    .child(status),
            )
            .into_any_element()
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
        match &self.identity.source {
            WorkspaceSource::Local { path } => self.render_local(path, theme),
            WorkspaceSource::Dashboard => self.render_dashboard(theme),
            WorkspaceSource::CodewireEnvironment {
                org_slug,
                env_id,
                env_name,
                environment,
                ..
            } => {
                let restored = EnvironmentSummary {
                    id: env_id.clone(),
                    name: if env_name.is_empty() {
                        self.identity.name.clone()
                    } else {
                        env_name.clone()
                    },
                    state: "unknown".to_string(),
                    desired_state: "unspecified".to_string(),
                    error_reason: String::new(),
                    setup_error: String::new(),
                    cpu_millicores: 0,
                    memory_mb: 0,
                    disk_gb: 0,
                    total_running_seconds: 0,
                    protected: false,
                    preset_name: String::new(),
                    network: String::new(),
                    ports: Vec::new(),
                };
                self.render_environment(org_slug, environment.as_ref().unwrap_or(&restored), theme)
            }
        }
    }
}

fn metadata_chip(
    label: impl Into<SharedString>,
    value: impl Into<SharedString>,
    theme: &Theme,
) -> gpui::AnyElement {
    let label: SharedString = label.into();
    let value: SharedString = value.into();
    div()
        .px(px(9.0))
        .py(px(5.0))
        .rounded(px(5.0))
        .bg(theme.surface)
        .border_1()
        .border_color(theme.border)
        .flex()
        .items_center()
        .gap(px(5.0))
        .child(
            div()
                .text_size(px(10.0))
                .text_color(theme.muted)
                .child(label),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(theme.foreground)
                .child(value),
        )
        .into_any_element()
}

fn environment_status_color(state: &str, theme: &Theme) -> Hsla {
    match state {
        "running" => theme.status_running,
        "pending" | "pending_build" | "building" | "pulling_snapshot" | "creating" | "starting"
        | "stopping" | "archiving" | "restoring" | "resizing" | "destroying" => {
            theme.status_needs_auth
        }
        "stopped" | "archived" | "destroyed" => theme.status_stopped,
        _ => theme.git_deletions,
    }
}

fn format_cpu(millicores: i32) -> String {
    if millicores > 0 && millicores % 1000 == 0 {
        format!("{} vCPU", millicores / 1000)
    } else {
        format!("{millicores}m")
    }
}

fn format_runtime(seconds: i32) -> String {
    if seconds <= 0 {
        return "Not started".to_string();
    }
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

fn nonempty_or(value: &str, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}
