//! Sidebar for Codewire environments and local projects.

use crate::theme::Theme;
use codewire_types::{GitStatus, PrState, PullRequest};
use codewire_ui::{chevron, selection_bar, status_dot};
use gpui::{
    App, Context, ElementId, EventEmitter, FocusHandle, Focusable, SharedString, Window, div,
    prelude::*, px, svg,
};
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct DashboardRequested;

#[derive(Clone, Debug)]
pub struct SettingsRequested;

#[derive(Clone, Debug)]
pub struct BillingRequested;

#[derive(Clone, Debug)]
pub struct CodewireSignInRequested;

#[derive(Clone, Debug)]
pub struct NewOrganizationRequested;

#[derive(Clone, Debug)]
pub struct OrganizationRequested {
    pub org_slug: String,
}

#[derive(Clone, Debug)]
pub struct OrganizationBillingRequested {
    pub org_slug: String,
}

#[derive(Clone, Debug)]
pub struct OrganizationCreateEnvironmentRequested {
    pub org_slug: String,
}

#[derive(Clone, Debug)]
pub struct EnvironmentTerminalRequested {
    pub org_id: String,
    pub org_slug: String,
    pub env_id: String,
    pub env_name: String,
}

/// Event emitted when the user wants to add a local project.
#[derive(Clone, Debug)]
pub struct AddLocalProjectRequested;

/// Event emitted when a local project is expanded.
#[derive(Clone, Debug)]
pub struct LocalProjectExpanded {
    pub path: String,
}

/// Event emitted when a local project is removed.
#[derive(Clone, Debug)]
pub struct LocalProjectRemoved {
    pub path: String,
}

/// Event emitted when "Browse Files" is clicked for a local project.
#[derive(Clone, Debug)]
pub struct LocalBrowseRequested {
    pub path: String,
}

/// Event emitted when "View Diff" is clicked for a local project.
#[derive(Clone, Debug)]
pub struct LocalDiffRequested {
    pub path: String,
}

/// Event emitted when "New Terminal" is clicked for a local project.
#[derive(Clone, Debug)]
pub struct NewTerminalRequested {
    pub path: String,
}

#[derive(Clone, Debug)]
pub struct SidebarOrganization {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub role: String,
    pub environments: Vec<SidebarEnvironment>,
}

#[derive(Clone, Debug)]
pub struct SidebarEnvironment {
    pub id: String,
    pub name: String,
    pub state: String,
}

/// A local project in the sidebar.
#[derive(Clone, Debug)]
pub struct LocalProject {
    pub path: String,
    pub name: String,
    pub git_status: Option<GitStatus>,
    pub pr: Option<PullRequest>,
}

pub struct Sidebar {
    codewire_orgs: Vec<SidebarOrganization>,
    codewire_authenticated: bool,
    codewire_loading: bool,
    codewire_error: Option<String>,
    expanded_orgs: HashSet<String>,
    local_projects: Vec<LocalProject>,
    expanded_local_projects: HashSet<String>,
    focus_handle: FocusHandle,
}

impl EventEmitter<DashboardRequested> for Sidebar {}
impl EventEmitter<SettingsRequested> for Sidebar {}
impl EventEmitter<BillingRequested> for Sidebar {}
impl EventEmitter<CodewireSignInRequested> for Sidebar {}
impl EventEmitter<NewOrganizationRequested> for Sidebar {}
impl EventEmitter<OrganizationRequested> for Sidebar {}
impl EventEmitter<OrganizationBillingRequested> for Sidebar {}
impl EventEmitter<OrganizationCreateEnvironmentRequested> for Sidebar {}
impl EventEmitter<EnvironmentTerminalRequested> for Sidebar {}
impl EventEmitter<AddLocalProjectRequested> for Sidebar {}
impl EventEmitter<LocalProjectExpanded> for Sidebar {}
impl EventEmitter<LocalProjectRemoved> for Sidebar {}
impl EventEmitter<LocalBrowseRequested> for Sidebar {}
impl EventEmitter<LocalDiffRequested> for Sidebar {}
impl EventEmitter<NewTerminalRequested> for Sidebar {}

impl Sidebar {
    pub fn new(cx: &mut Context<Self>) -> Self {
        Self {
            codewire_orgs: Vec::new(),
            codewire_authenticated: false,
            codewire_loading: true,
            codewire_error: None,
            expanded_orgs: HashSet::new(),
            local_projects: Vec::new(),
            expanded_local_projects: HashSet::new(),
            focus_handle: cx.focus_handle(),
        }
    }

    pub fn set_codewire_state(
        &mut self,
        organizations: Vec<SidebarOrganization>,
        authenticated: bool,
        loading: bool,
        error: Option<String>,
        cx: &mut Context<Self>,
    ) {
        for org in &organizations {
            self.expanded_orgs.insert(org.id.clone());
        }

        self.codewire_orgs = organizations;
        self.codewire_authenticated = authenticated;
        self.codewire_loading = loading;
        self.codewire_error = error;
        cx.notify();
    }

    pub fn add_local_project(&mut self, path: String, cx: &mut Context<Self>) {
        if self
            .local_projects
            .iter()
            .any(|project| project.path == path)
        {
            self.expanded_local_projects.insert(path.clone());
            cx.emit(LocalProjectExpanded { path });
            cx.notify();
            return;
        }

        let name = std::path::Path::new(&path)
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| path.clone());

        self.local_projects.push(LocalProject {
            path: path.clone(),
            name,
            git_status: None,
            pr: None,
        });
        self.expanded_local_projects.insert(path.clone());
        cx.emit(LocalProjectExpanded { path });
        cx.notify();
    }

    pub fn remove_local_project(&mut self, path: &str, cx: &mut Context<Self>) {
        self.local_projects.retain(|project| project.path != path);
        self.expanded_local_projects.remove(path);
        cx.emit(LocalProjectRemoved {
            path: path.to_string(),
        });
        cx.notify();
    }

    pub fn update_local_git_status(
        &mut self,
        path: &str,
        git_status: Option<GitStatus>,
        pr: Option<PullRequest>,
        cx: &mut Context<Self>,
    ) {
        if let Some(project) = self
            .local_projects
            .iter_mut()
            .find(|project| project.path == path)
        {
            project.git_status = git_status;
            project.pr = pr;
            cx.notify();
        }
    }

    pub fn local_project_paths(&self) -> Vec<String> {
        self.local_projects
            .iter()
            .map(|project| project.path.clone())
            .collect()
    }

    pub fn local_project_count(&self) -> usize {
        self.local_projects.len()
    }

    fn icon_box_svg(&self, icon_path: &'static str, theme: &Theme) -> impl IntoElement {
        div()
            .w(px(18.0))
            .h(px(18.0))
            .rounded(px(3.0))
            .bg(theme.surface)
            .flex()
            .items_center()
            .justify_center()
            .flex_shrink_0()
            .child(svg().path(icon_path).size(px(12.0)).text_color(theme.muted))
    }

    fn request_add_local_project(&mut self, cx: &mut Context<Self>) {
        cx.emit(AddLocalProjectRequested);
    }

    fn git_status_indicator(&self, status: &GitStatus, theme: &Theme) -> impl IntoElement {
        div()
            .flex()
            .items_center()
            .gap(px(4.0))
            .text_size(px(11.0))
            .font_family("monospace")
            .flex_shrink_0()
            .when(status.additions > 0, |el| {
                el.child(
                    div()
                        .text_color(theme.git_additions)
                        .child(format!("+{}", status.additions)),
                )
            })
            .when(status.deletions > 0, |el| {
                el.child(
                    div()
                        .text_color(theme.git_deletions)
                        .child(format!("-{}", status.deletions)),
                )
            })
            .when(status.dirty, |el| {
                el.child(div().text_color(theme.git_dirty).child("*"))
            })
    }

    fn render_nav_item(
        &self,
        id: String,
        label: &'static str,
        icon_path: &'static str,
        theme: &Theme,
        cx: &mut Context<Self>,
        on_click: impl Fn(&mut Sidebar, &mut Context<Sidebar>) + 'static,
    ) -> gpui::AnyElement {
        div()
            .id(ElementId::Name(SharedString::from(id)))
            .relative()
            .py(px(6.0))
            .pl(px(12.0))
            .pr_2()
            .mx(px(6.0))
            .rounded(px(6.0))
            .flex()
            .items_center()
            .gap_2()
            .hover({
                let hover_bg = theme.hover;
                move |s| s.bg(hover_bg)
            })
            .cursor_pointer()
            .on_click(cx.listener(move |this, _, _, cx| {
                on_click(this, cx);
            }))
            .child(selection_bar(false))
            .child(self.icon_box_svg(icon_path, theme))
            .child(
                div()
                    .text_size(px(12.5))
                    .text_color(theme.foreground)
                    .child(label),
            )
            .into_any_element()
    }

    fn render_environment(
        &self,
        org: &SidebarOrganization,
        env: &SidebarEnvironment,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let org_id = org.id.clone();
        let org_slug = org.slug.clone();
        let env_id = env.id.clone();
        let env_name = if env.name.is_empty() {
            env.id[..8.min(env.id.len())].to_string()
        } else {
            env.name.clone()
        };
        let env_name_for_click = env_name.clone();
        let env_state = env.state.clone();

        div()
            .id(ElementId::Name(SharedString::from(format!(
                "env-{}-{}",
                org_id, env_id
            ))))
            .relative()
            .py(px(6.0))
            .pl(px(24.0))
            .pr_2()
            .mx(px(6.0))
            .rounded(px(6.0))
            .flex()
            .items_center()
            .gap_2()
            .hover({
                let hover_bg = theme.hover;
                move |s| s.bg(hover_bg)
            })
            .cursor_pointer()
            .on_click(cx.listener(move |_this, _, _, cx| {
                cx.emit(EnvironmentTerminalRequested {
                    org_id: org_id.clone(),
                    org_slug: org_slug.clone(),
                    env_id: env_id.clone(),
                    env_name: env_name_for_click.clone(),
                });
            }))
            .child(selection_bar(false))
            .child(self.icon_box_svg("icons/terminal.svg", theme))
            .child(status_dot(match env_state.as_str() {
                "running" => theme.status_running,
                "starting" | "creating" | "pending" => theme.status_needs_auth,
                "stopped" => theme.status_stopped,
                _ => theme.git_deletions,
            }))
            .child(
                div()
                    .flex_1()
                    .text_size(px(12.0))
                    .text_color(theme.foreground)
                    .child(env_name),
            )
            .child(
                div()
                    .text_size(px(10.0))
                    .text_color(theme.muted)
                    .font_family("monospace")
                    .child(env_state),
            )
            .into_any_element()
    }

    fn render_org(
        &self,
        idx: usize,
        org: &SidebarOrganization,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let org_id = org.id.clone();
        let org_slug = org.slug.clone();
        let org_name = org.name.clone();
        let is_expanded = self.expanded_orgs.contains(&org_id);
        let org_toggle_id = org_id.clone();
        let org_slug_for_dashboard = org_slug.clone();
        let org_slug_for_billing = org_slug.clone();
        let org_slug_for_create = org_slug.clone();

        let mut container = div().flex().flex_col();

        container = container.child(
            div()
                .id(ElementId::Name(SharedString::from(format!("org-{}", idx))))
                .relative()
                .py(px(6.0))
                .pl(px(12.0))
                .pr_2()
                .mx(px(6.0))
                .rounded(px(6.0))
                .flex()
                .items_center()
                .gap_2()
                .hover({
                    let hover_bg = theme.hover;
                    move |s| s.bg(hover_bg)
                })
                .cursor_pointer()
                .on_click(cx.listener(move |this, _, _, cx| {
                    if this.expanded_orgs.contains(&org_toggle_id) {
                        this.expanded_orgs.remove(&org_toggle_id);
                    } else {
                        this.expanded_orgs.insert(org_toggle_id.clone());
                    }
                    cx.emit(OrganizationRequested {
                        org_slug: org_slug_for_dashboard.clone(),
                    });
                    cx.notify();
                }))
                .child(selection_bar(false))
                .child(self.icon_box_svg("icons/folder.svg", theme))
                .child(
                    div()
                        .flex_1()
                        .text_size(px(13.0))
                        .text_color(theme.foreground)
                        .child(org_name),
                )
                .child(
                    div()
                        .text_size(px(10.0))
                        .text_color(theme.muted)
                        .font_family("monospace")
                        .child(org.role.clone()),
                )
                .child(chevron(is_expanded, theme.muted)),
        );

        if is_expanded {
            for env in org
                .environments
                .iter()
                .filter(|env| !matches!(env.state.as_str(), "destroyed" | "destroying"))
            {
                container = container.child(self.render_environment(org, env, theme, cx));
            }

            container = container.child(
                div()
                    .id(ElementId::Name(SharedString::from(format!(
                        "org-billing-{}",
                        org.id
                    ))))
                    .relative()
                    .py(px(6.0))
                    .pl(px(24.0))
                    .pr_2()
                    .mx(px(6.0))
                    .rounded(px(6.0))
                    .flex()
                    .items_center()
                    .gap_2()
                    .hover({
                        let hover_bg = theme.hover;
                        move |s| s.bg(hover_bg)
                    })
                    .cursor_pointer()
                    .on_click(cx.listener(move |_this, _, _, cx| {
                        cx.emit(OrganizationBillingRequested {
                            org_slug: org_slug_for_billing.clone(),
                        });
                    }))
                    .child(selection_bar(false))
                    .child(self.icon_box_svg("icons/folder.svg", theme))
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(theme.accent)
                            .child("Billing"),
                    ),
            );

            container = container.child(
                div()
                    .id(ElementId::Name(SharedString::from(format!(
                        "org-create-env-{}",
                        org.id
                    ))))
                    .relative()
                    .py(px(6.0))
                    .pl(px(24.0))
                    .pr_2()
                    .mx(px(6.0))
                    .rounded(px(6.0))
                    .flex()
                    .items_center()
                    .gap_2()
                    .hover({
                        let hover_bg = theme.hover;
                        move |s| s.bg(hover_bg)
                    })
                    .cursor_pointer()
                    .on_click(cx.listener(move |_this, _, _, cx| {
                        cx.emit(OrganizationCreateEnvironmentRequested {
                            org_slug: org_slug_for_create.clone(),
                        });
                    }))
                    .child(selection_bar(false))
                    .child(self.icon_box_svg("icons/add.svg", theme))
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(theme.accent)
                            .child("Create Env"),
                    ),
            );
        }

        container.into_any_element()
    }

    fn render_local_project(
        &self,
        idx: usize,
        project: &LocalProject,
        theme: &Theme,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let path = project.path.clone();
        let name = project.name.clone();
        let is_expanded = self.expanded_local_projects.contains(&path);
        let path_toggle = path.clone();
        let path_remove = path.clone();
        let git_status = project.git_status.clone();
        let pr = project.pr.clone();
        let hover_bg = theme.hover;

        let mut container = div().flex().flex_col();

        let mut project_row = div()
            .id(ElementId::Name(SharedString::from(format!(
                "local-project-{}",
                idx
            ))))
            .relative()
            .py(px(6.0))
            .pl(px(12.0))
            .pr_2()
            .mx(px(6.0))
            .rounded(px(6.0))
            .flex()
            .items_center()
            .gap_2()
            .hover(move |s| s.bg(hover_bg))
            .cursor_pointer()
            .on_click(cx.listener(move |this, _, _, cx| {
                if this.expanded_local_projects.contains(&path_toggle) {
                    this.expanded_local_projects.remove(&path_toggle);
                } else {
                    this.expanded_local_projects.insert(path_toggle.clone());
                    cx.emit(LocalProjectExpanded {
                        path: path_toggle.clone(),
                    });
                }
                cx.notify();
            }))
            .child(selection_bar(false))
            .child(
                div()
                    .w(px(18.0))
                    .h(px(18.0))
                    .rounded(px(3.0))
                    .bg(theme.surface)
                    .flex()
                    .items_center()
                    .justify_center()
                    .flex_shrink_0()
                    .child(status_dot(theme.status_running)),
            )
            .child(
                div()
                    .flex_1()
                    .text_size(px(13.0))
                    .text_color(theme.foreground)
                    .child(name),
            );

        if let Some(pr) = &pr {
            let pr_color = match pr.state {
                PrState::Open => theme.status_running,
                PrState::Closed => theme.git_deletions,
                PrState::Merged => gpui::hsla(270.0 / 360.0, 0.6, 0.6, 1.0),
            };
            project_row = project_row.child(
                div()
                    .px(px(4.0))
                    .py(px(1.0))
                    .rounded(px(3.0))
                    .bg(pr_color)
                    .text_size(px(9.0))
                    .text_color(gpui::hsla(0.0, 0.0, 1.0, 1.0))
                    .flex_shrink_0()
                    .child(format!("#{}", pr.number)),
            );
        }

        if let Some(status) = &git_status {
            project_row = project_row.child(self.git_status_indicator(status, theme));
        }

        container = container.child(project_row.child(chevron(is_expanded, theme.muted)));

        if is_expanded {
            let browse_path = path.clone();
            container = container.child(
                div()
                    .id(ElementId::Name(SharedString::from(format!(
                        "local-browse-{}",
                        idx
                    ))))
                    .relative()
                    .py(px(6.0))
                    .pl(px(24.0))
                    .pr_2()
                    .mx(px(6.0))
                    .rounded(px(6.0))
                    .flex()
                    .items_center()
                    .gap_2()
                    .hover(move |s| s.bg(hover_bg))
                    .cursor_pointer()
                    .on_click(cx.listener(move |_this, _, _, cx| {
                        cx.emit(LocalBrowseRequested {
                            path: browse_path.clone(),
                        });
                    }))
                    .child(selection_bar(false))
                    .child(self.icon_box_svg("icons/folder.svg", theme))
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(theme.accent)
                            .child("Browse Files"),
                    ),
            );

            if git_status.is_some() || pr.is_some() {
                let diff_path = path.clone();
                container = container.child(
                    div()
                        .id(ElementId::Name(SharedString::from(format!(
                            "local-diff-{}",
                            idx
                        ))))
                        .relative()
                        .py(px(6.0))
                        .pl(px(24.0))
                        .pr_2()
                        .mx(px(6.0))
                        .rounded(px(6.0))
                        .flex()
                        .items_center()
                        .gap_2()
                        .hover(move |s| s.bg(hover_bg))
                        .cursor_pointer()
                        .on_click(cx.listener(move |_this, _, _, cx| {
                            cx.emit(LocalDiffRequested {
                                path: diff_path.clone(),
                            });
                        }))
                        .child(selection_bar(false))
                        .child(self.icon_box_svg("icons/diff-modified.svg", theme))
                        .child(
                            div()
                                .text_size(px(12.0))
                                .text_color(theme.accent)
                                .child("View Diff"),
                        ),
                );
            }

            let terminal_path = path.clone();
            container = container.child(
                div()
                    .id(ElementId::Name(SharedString::from(format!(
                        "local-term-{}",
                        idx
                    ))))
                    .relative()
                    .py(px(6.0))
                    .pl(px(24.0))
                    .pr_2()
                    .mx(px(6.0))
                    .rounded(px(6.0))
                    .flex()
                    .items_center()
                    .gap_2()
                    .hover(move |s| s.bg(hover_bg))
                    .cursor_pointer()
                    .on_click(cx.listener(move |_this, _, _, cx| {
                        cx.emit(NewTerminalRequested {
                            path: terminal_path.clone(),
                        });
                    }))
                    .child(selection_bar(false))
                    .child(self.icon_box_svg("icons/terminal.svg", theme))
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(theme.accent)
                            .child("New Terminal"),
                    ),
            );

            container = container.child(
                div()
                    .id(ElementId::Name(SharedString::from(format!(
                        "local-remove-{}",
                        idx
                    ))))
                    .relative()
                    .py(px(6.0))
                    .pl(px(24.0))
                    .pr_2()
                    .mx(px(6.0))
                    .rounded(px(6.0))
                    .flex()
                    .items_center()
                    .gap_2()
                    .hover(move |s| s.bg(hover_bg))
                    .cursor_pointer()
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.remove_local_project(&path_remove, cx);
                    }))
                    .child(selection_bar(false))
                    .child(self.icon_box_svg("icons/close.svg", theme))
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(theme.git_deletions)
                            .child("Remove"),
                    ),
            );
        }

        container.into_any_element()
    }
}

impl Focusable for Sidebar {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for Sidebar {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();

        div()
            .w(px(280.0))
            .h_full()
            .font_family(".AppleSystemUIFont")
            .flex()
            .flex_col()
            .bg(theme.surface)
            .border_1()
            .border_color(theme.border)
            .rounded(px(12.0))
            .m(px(8.0))
            .overflow_hidden()
            .track_focus(&self.focus_handle(cx))
            .child(
                div()
                    .h(px(52.0))
                    .px_4()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_size(px(13.0))
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .text_color(theme.foreground)
                            .child("Codewire"),
                    )
                    .when(self.codewire_authenticated, |el| {
                        el.child(
                            div()
                                .id("new-org-btn")
                                .text_color(theme.muted)
                                .hover(|s| s.text_color(theme.foreground))
                                .cursor_pointer()
                                .on_click(cx.listener(|_this, _, _, cx| {
                                    cx.emit(NewOrganizationRequested);
                                }))
                                .child(
                                    svg()
                                        .path("icons/add.svg")
                                        .size(px(16.0))
                                        .text_color(theme.muted),
                                ),
                        )
                    }),
            )
            .child(
                div()
                    .flex_1()
                    .overflow_hidden()
                    .child(
                        div()
                            .px_2()
                            .py_3()
                            .flex()
                            .flex_col()
                            .gap(px(14.0))
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap(px(4.0))
                                    .child(
                                        div()
                                            .px(px(10.0))
                                            .text_size(px(10.0))
                                            .text_color(theme.muted)
                                            .child("CODEWIRE"),
                                    )
                                    .child(self.render_nav_item(
                                        "dashboard-link".to_string(),
                                        "Dashboard",
                                        "icons/folder.svg",
                                        &theme,
                                        cx,
                                        |_this, cx| {
                                            cx.emit(DashboardRequested);
                                        },
                                    ))
                                    .child(self.render_nav_item(
                                        "settings-link".to_string(),
                                        "Settings",
                                        "icons/folder.svg",
                                        &theme,
                                        cx,
                                        |_this, cx| {
                                            cx.emit(SettingsRequested);
                                        },
                                    ))
                                    .child(self.render_nav_item(
                                        "billing-link".to_string(),
                                        "Billing",
                                        "icons/folder.svg",
                                        &theme,
                                        cx,
                                        |_this, cx| {
                                            cx.emit(BillingRequested);
                                        },
                                    )),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap(px(4.0))
                                    .child(
                                        div()
                                            .px(px(10.0))
                                            .text_size(px(10.0))
                                            .text_color(theme.muted)
                                            .child("ENVIRONMENTS"),
                                    )
                                    .when(self.codewire_loading, |el| {
                                        el.child(
                                            div()
                                                .px(px(10.0))
                                                .py(px(8.0))
                                                .text_size(px(12.0))
                                                .text_color(theme.muted)
                                                .child("Loading organizations..."),
                                        )
                                    })
                                    .when(!self.codewire_loading && !self.codewire_authenticated, |el| {
                                        el.child(
                                            div()
                                                .px(px(10.0))
                                                .py(px(8.0))
                                                .flex()
                                                .flex_col()
                                                .gap(px(8.0))
                                                .child(
                                                    div()
                                                        .text_size(px(12.0))
                                                        .text_color(theme.muted)
                                                        .child("Sign in to load your Codewire organizations and environments."),
                                                )
                                                .child(
                                                    div()
                                                        .id("codewire-sign-in-btn")
                                                        .relative()
                                                        .py(px(6.0))
                                                        .px(px(10.0))
                                                        .rounded(px(6.0))
                                                        .bg(theme.accent)
                                                        .text_size(px(12.0))
                                                        .text_color(gpui::hsla(0.0, 0.0, 1.0, 1.0))
                                                        .cursor_pointer()
                                                        .on_click(cx.listener(|_this, _, _, cx| {
                                                            cx.emit(CodewireSignInRequested);
                                                        }))
                                                        .child("Sign In"),
                                                ),
                                        )
                                    })
                                    .when(self.codewire_error.is_some(), |el| {
                                        el.child(
                                            div()
                                                .px(px(10.0))
                                                .text_size(px(11.0))
                                                .text_color(theme.git_deletions)
                                                .child(self.codewire_error.clone().unwrap_or_default()),
                                        )
                                    })
                                    .when(
                                        self.codewire_authenticated
                                            && !self.codewire_loading
                                            && self.codewire_orgs.is_empty(),
                                        |el| {
                                            el.child(
                                                div()
                                                    .px(px(10.0))
                                                    .py(px(8.0))
                                                    .text_size(px(12.0))
                                                    .text_color(theme.muted)
                                                    .child("No organizations yet."),
                                            )
                                        },
                                    )
                                    .children(
                                        self.codewire_orgs
                                            .iter()
                                            .enumerate()
                                            .map(|(idx, org)| self.render_org(idx, org, &theme, cx)),
                                    ),
                            )
                            .child(
                                div()
                                    .h(px(1.0))
                                    .mx(px(10.0))
                                    .bg(theme.border),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap(px(4.0))
                                    .child(
                                        div()
                                            .h(px(32.0))
                                            .px_4()
                                            .flex()
                                            .items_center()
                                            .justify_between()
                                            .child(
                                                div()
                                                    .text_size(px(10.0))
                                                    .text_color(theme.muted)
                                                    .child("LOCAL PROJECTS"),
                                            )
                                            .child(
                                                div()
                                                    .id("add-local-project-btn")
                                                    .text_color(theme.muted)
                                                    .hover(|s| s.text_color(theme.foreground))
                                                    .cursor_pointer()
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.request_add_local_project(cx);
                                                    }))
                                                    .child(
                                                        svg()
                                                            .path("icons/add.svg")
                                                            .size(px(16.0))
                                                            .text_color(theme.muted),
                                                    ),
                                            ),
                                    )
                                    .when(self.local_projects.is_empty(), |el| {
                                        el.child(
                                            div()
                                                .px(px(10.0))
                                                .py(px(8.0))
                                                .text_size(px(12.0))
                                                .text_color(theme.muted)
                                                .child("Open a local folder to get started."),
                                        )
                                    })
                                    .children(
                                        self.local_projects
                                            .iter()
                                            .enumerate()
                                            .map(|(idx, project)| {
                                                self.render_local_project(idx, project, &theme, cx)
                                            }),
                                    ),
                            ),
                    ),
            )
    }
}
