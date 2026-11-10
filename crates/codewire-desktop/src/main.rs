//! Codewire Desktop - gpui-based desktop application

mod app_layout;
mod assets;
mod chat;
mod command_palette;
mod desktop_settings;
mod dialogs;
mod diff_view;
mod editor;
mod file_browser;
mod input;
mod layout_storage;
mod local_diff;
mod pane_tree;
mod quick_open;
mod sidebar;
mod split_container;
mod status_bar;
mod terminal;
mod theme;
mod web_browser;
mod workspace;
mod workspace_home;

#[cfg(test)]
mod tests;

use app_layout::AppLayout;
use chat::ChatPanel;
use codewire_client::{
    ClientConfig, CodewireClient, CredentialStore, DesiredState, DesktopOAuthCancellation,
    DesktopOAuthLogin, Environment, EnvironmentState, KeyringCredentialStore,
    ListEnvironmentsRequest, ListOrganizationsRequest, NativeClientFacade, OAuthClient, OrgRole,
    PortAccess, RefreshingTokenProvider,
};
use codewire_types::GitStatus;
use dialogs::{LoginDialog, LoginDialogEvent};
use editor::{
    EditorBackspace, EditorCopy, EditorCut, EditorDelete, EditorEnter, EditorLeft, EditorPaste,
    EditorRight, EditorSelectAll, MoveDown, MoveLineEnd, MoveLineStart, MoveUp, RedoEdit, SaveFile,
    UndoEdit,
};
use file_browser::{NextExplorerItem, PrevExplorerItem, RefreshExplorer, ToggleOrOpen};
use gpui::{
    AnyWindowHandle, App, Bounds, Context, FocusHandle, Focusable, Global, KeyBinding, Menu,
    MenuItem, OsAction, SharedString, Window, WindowBounds, WindowOptions, actions, div,
    prelude::*, px, size, svg,
};
use input::{Backspace, Copy, Cut, Delete, Left, Paste, Right, SelectAll};
use pane_tree::{SplitDirection, TerminalConnection};
use sidebar::{
    AddLocalProjectRequested, CodewireSignInRequested, CodewireSignOutRequested,
    EnvironmentTerminalRequested, LocalBrowseRequested, LocalDiffRequested, LocalProjectExpanded,
    LocalProjectRemoved, NewTerminalRequested, Sidebar, SidebarOrganization,
};
use theme::Theme;
use workspace::{EnvironmentPortSummary, EnvironmentSummary, WorkspaceIdentity};

const DEFAULT_CODEWIRE_URL: &str = "https://codewire.sh";
const CODEWIRE_POLL_INTERVAL_SECS: u64 = 10;
const PRIMARY_QUIT_KEY: &str = "secondary-q";

#[derive(Clone, Debug)]
struct CodewireSidebarState {
    organizations: Vec<SidebarOrganization>,
    authenticated: bool,
    loading: bool,
    error: Option<String>,
}

impl Default for CodewireSidebarState {
    fn default() -> Self {
        Self {
            organizations: Vec::new(),
            authenticated: false,
            loading: true,
            error: None,
        }
    }
}

/// Build the single native Connect client from the desktop's atomic keyring
/// credential. The desktop never reads browser cookies or legacy REST state.
pub(crate) fn connected_client() -> Result<Option<CodewireClient>, String> {
    let store = KeyringCredentialStore::desktop();
    let Some(credentials) = store
        .load()
        .map_err(|_| "Failed to read Codewire credentials from the system keyring".to_string())?
    else {
        return Ok(None);
    };
    let oauth = OAuthClient::for_server_url(codewire_base_url())
        .map_err(|_| "Failed to configure Codewire OAuth".to_string())?;
    let provider = RefreshingTokenProvider::new(oauth, store, credentials)
        .map_err(|_| "Stored Codewire credentials are invalid".to_string())?;
    CodewireClient::new(
        ClientConfig::new(codewire_base_url())
            .map_err(|_| "Invalid Codewire server URL".to_string())?,
        provider,
    )
    .map(Some)
    .map_err(|_| "Failed to configure Codewire Connect client".to_string())
}

pub(crate) fn native_client() -> Result<Option<NativeClientFacade>, String> {
    connected_client().map(|client| client.map(NativeClientFacade::new))
}

fn environment_summary(environment: Environment) -> EnvironmentSummary {
    EnvironmentSummary {
        id: environment.id,
        name: environment.name,
        state: environment_state_label(environment.state.as_known()).to_string(),
        desired_state: desired_state_label(environment.desired_state.as_known()).to_string(),
        error_reason: environment.error_reason,
        setup_error: environment.setup_error,
        cpu_millicores: environment.cpu_millicores,
        memory_mb: environment.memory_mb,
        disk_gb: environment.disk_gb,
        total_running_seconds: environment.total_running_seconds,
        protected: environment.protected,
        preset_name: environment.preset_name,
        network: environment.network,
        ports: environment
            .ports
            .into_iter()
            .map(|port| EnvironmentPortSummary {
                port: port.port,
                label: port.label,
                access: port_access_label(port.access.as_known()).to_string(),
                preview_url: port.preview_url,
            })
            .collect(),
    }
}

fn environment_state_label(state: Option<EnvironmentState>) -> &'static str {
    match state {
        Some(EnvironmentState::Pending) => "pending",
        Some(EnvironmentState::PendingBuild) => "pending_build",
        Some(EnvironmentState::Building) => "building",
        Some(EnvironmentState::BuildFailed) => "build_failed",
        Some(EnvironmentState::PullingSnapshot) => "pulling_snapshot",
        Some(EnvironmentState::Creating) => "creating",
        Some(EnvironmentState::Starting) => "starting",
        Some(EnvironmentState::Running) => "running",
        Some(EnvironmentState::Stopping) => "stopping",
        Some(EnvironmentState::Stopped) => "stopped",
        Some(EnvironmentState::Archiving) => "archiving",
        Some(EnvironmentState::Archived) => "archived",
        Some(EnvironmentState::Restoring) => "restoring",
        Some(EnvironmentState::Resizing) => "resizing",
        Some(EnvironmentState::Destroying) => "destroying",
        Some(EnvironmentState::Destroyed) => "destroyed",
        Some(EnvironmentState::Error) => "error",
        Some(EnvironmentState::Unknown) | Some(EnvironmentState::Unspecified) | None => "unknown",
    }
}

fn desired_state_label(state: Option<DesiredState>) -> &'static str {
    match state {
        Some(DesiredState::Started) => "started",
        Some(DesiredState::Stopped) => "stopped",
        Some(DesiredState::Destroyed) => "destroyed",
        Some(DesiredState::Archived) => "archived",
        Some(DesiredState::Resized) => "resized",
        Some(DesiredState::Unspecified) | None => "unspecified",
    }
}

fn port_access_label(access: Option<PortAccess>) -> &'static str {
    match access {
        Some(PortAccess::Public) => "public",
        Some(PortAccess::OrgMembers) => "organization",
        Some(PortAccess::Creator) => "creator",
        Some(PortAccess::Unspecified) | None => "unspecified",
    }
}

/// Shared application state available to all windows via GPUI's global system.
pub(crate) struct AppState {
    pub(crate) codewire_sidebar: CodewireSidebarState,
    /// All open windows: (WindowId, AnyWindowHandle) pairs
    pub(crate) windows: Vec<(layout_storage::WindowId, AnyWindowHandle)>,
}

impl Global for AppState {}

actions!(
    app,
    [
        Quit,
        CancelLogin,
        DisconnectTerminal,
        // Inner splits (within active workspace)
        SplitRight,
        SplitDown,
        CloseTab,
        // Outer splits (workspace-level)
        SplitWorkspaceRight,
        SplitWorkspaceDown,
        CloseWorkspace,
        // Pane switching (Ctrl+N) — inner panes
        FocusPane1,
        FocusPane2,
        FocusPane3,
        FocusPane4,
        FocusPane5,
        // Tab switching (Cmd+N) — inner tabs
        SelectTab1,
        SelectTab2,
        SelectTab3,
        SelectTab4,
        SelectTab5,
        SelectTab6,
        SelectTab7,
        SelectTab8,
        SelectTab9,
        // Move tab to pane (Ctrl+Shift+N) — inner panes
        MoveTabToPane1,
        MoveTabToPane2,
        MoveTabToPane3,
        MoveTabToPane4,
        MoveTabToPane5,
        // Tab cycling
        NextTab,
        PrevTab,
        // Sidebar
        ToggleSidebar,
        // Quick Open / Command Palette
        QuickOpenAction,
        CommandPaletteAction,
        // Diff view navigation
        NextDiffFile,
        PrevDiffFile,
        ToggleDiffFile,
        RefreshDiff,
        FocusDiffSearch,
        // Local terminal
        OpenLocalTerminal,
        // Window management
        ShowMainWindow,
        NewWindow,
        CloseWindow,
        CloseAllWindows
    ]
);

/// Action to focus a specific window by its index in AppState.windows.
#[derive(Clone, PartialEq, serde::Deserialize, schemars::JsonSchema, gpui::Action)]
#[action(namespace = app)]
struct FocusWindowByIndex {
    index: usize,
}

/// Action to move a workspace tab from the current window to another window.
#[derive(Clone, PartialEq, serde::Deserialize, schemars::JsonSchema, gpui::Action)]
#[action(namespace = app)]
pub(crate) struct MoveWorkspaceToWindow {
    pub target_window_index: usize,
    pub workspace_id: String,
}

/// Rebuild the application menus, including a dynamic Window menu that lists all open windows.
/// Call this after every window open/close.
fn update_window_menu(cx: &App) {
    let windows = &cx.global::<AppState>().windows;

    let mut window_items = vec![
        MenuItem::action("New Window", NewWindow),
        MenuItem::separator(),
    ];

    for (i, (_wid, _)) in windows.iter().enumerate() {
        let label: SharedString = format!("Window {}", i + 1).into();
        window_items.push(MenuItem::action(label, FocusWindowByIndex { index: i }));
    }

    cx.set_menus(vec![
        Menu {
            disabled: false,
            name: "Codewire".into(),
            items: vec![
                MenuItem::action("About Codewire", Quit),
                MenuItem::separator(),
                MenuItem::action("Quit Codewire", Quit),
            ],
        },
        Menu {
            disabled: false,
            name: "File".into(),
            items: vec![
                MenuItem::action("New Window", NewWindow),
                MenuItem::action("New Tab", OpenLocalTerminal),
                MenuItem::separator(),
                MenuItem::action("Split Right", SplitRight),
                MenuItem::action("Split Down", SplitDown),
                MenuItem::separator(),
                MenuItem::action("Close", CloseTab),
                MenuItem::action("Close Workspace", CloseWorkspace),
                MenuItem::action("Close Window", CloseWindow),
                MenuItem::action("Close All Windows", CloseAllWindows),
            ],
        },
        Menu {
            disabled: false,
            name: "Edit".into(),
            items: vec![
                MenuItem::os_action("Cut", Cut, OsAction::Cut),
                MenuItem::os_action("Copy", Copy, OsAction::Copy),
                MenuItem::os_action("Paste", Paste, OsAction::Paste),
                MenuItem::os_action("Select All", SelectAll, OsAction::SelectAll),
                MenuItem::separator(),
                MenuItem::os_action("Undo", UndoEdit, OsAction::Undo),
                MenuItem::os_action("Redo", RedoEdit, OsAction::Redo),
            ],
        },
        Menu {
            disabled: false,
            name: "Window".into(),
            items: window_items,
        },
    ]);
}

fn codewire_base_url() -> String {
    std::env::var("CODEWIRE_URL")
        .unwrap_or_else(|_| DEFAULT_CODEWIRE_URL.to_string())
        .trim_end_matches('/')
        .to_string()
}

fn cancel_window_login(window: &mut Window, cx: &mut App) {
    if let Some(view) = window.root::<AppView>().flatten() {
        view.update(cx, |view, cx| view.cancel_codewire_login(cx));
    }
}

fn prepare_window_close(window_id: &layout_storage::WindowId, window: &mut Window, cx: &mut App) {
    cancel_window_login(window, cx);
    save_window_bounds_to_manifest(window_id, window, cx);
    let closing_window_id = window.window_handle().window_id();
    cx.global_mut::<AppState>()
        .windows
        .retain(|(_, handle)| handle.window_id() != closing_window_id);
    update_window_manifest(cx);
    update_window_menu(cx);
}

fn cancel_all_codewire_logins(cx: &mut App) {
    let windows = cx.windows();
    for handle in windows {
        if let Some(view) = handle.downcast::<AppView>() {
            let _ = view.update(cx, |view, _window, cx| view.cancel_codewire_login(cx));
        }
    }
}

/// Open a new application window. If `restore` is provided, restores that window's layout
/// and bounds. Otherwise creates a fresh window with a new WindowId.
/// Registers the window in AppState.windows.
fn open_new_window(
    restore: Option<(
        layout_storage::WindowId,
        layout_storage::AppLayoutState,
        Option<layout_storage::SerializedBounds>,
    )>,
    cx: &mut App,
) {
    let (window_id, saved_layout, saved_bounds) = match restore {
        Some((id, layout, bounds)) => (id, Some(layout), bounds),
        None => (layout_storage::WindowId::new(), None, None),
    };

    let bounds = if let Some(sb) = saved_bounds {
        Bounds {
            origin: gpui::Point {
                x: px(sb.x as f32),
                y: px(sb.y as f32),
            },
            size: gpui::Size {
                width: px(sb.width as f32),
                height: px(sb.height as f32),
            },
        }
    } else {
        Bounds::centered(None, size(px(1200.0), px(800.0)), cx)
    };

    let wid = window_id.clone();
    let close_wid = window_id.clone();
    let result = cx.open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            ..Default::default()
        },
        |window, cx| {
            window.on_window_should_close(cx, move |window, cx| {
                prepare_window_close(&close_wid, window, cx);
                // GPUI's default quit mode closes the process after the last
                // window on Linux/Windows and keeps the app active on macOS.
                true
            });
            cx.new(|cx| AppView::new(wid, saved_layout, cx))
        },
    );

    if let Ok(handle) = result {
        cx.global_mut::<AppState>()
            .windows
            .push((window_id, handle.into()));
        update_window_manifest(cx);
        update_window_menu(cx);
    }
}

/// Save a window's current bounds into the window manifest.
fn save_window_bounds_to_manifest(
    window_id: &layout_storage::WindowId,
    window: &mut Window,
    _cx: &mut App,
) {
    let storage = match layout_storage::LayoutStorage::new() {
        Ok(s) => s,
        Err(_) => return,
    };

    let bounds = window.bounds();
    let serialized = layout_storage::SerializedBounds {
        x: f32::from(bounds.origin.x) as f64,
        y: f32::from(bounds.origin.y) as f64,
        width: f32::from(bounds.size.width) as f64,
        height: f32::from(bounds.size.height) as f64,
    };

    // Load existing manifest or create new one
    let mut manifest = storage
        .load_window_manifest()
        .unwrap_or(layout_storage::WindowManifest {
            windows: Vec::new(),
            active_window_id: None,
        });

    // Update or remove this window's entry
    if let Some(entry) = manifest
        .windows
        .iter_mut()
        .find(|e| e.window_id == *window_id)
    {
        entry.bounds = Some(serialized);
    }

    // Save updated manifest
    let _ = storage.save_window_manifest(&manifest);
}

/// Rebuild and save the window manifest from current AppState.windows.
fn update_window_manifest(cx: &App) {
    let storage = match layout_storage::LayoutStorage::new() {
        Ok(s) => s,
        Err(_) => return,
    };

    let windows = &cx.global::<AppState>().windows;
    let manifest = layout_storage::WindowManifest {
        windows: windows
            .iter()
            .map(|(wid, _)| layout_storage::WindowManifestEntry {
                window_id: wid.clone(),
                bounds: None, // bounds saved separately on close
            })
            .collect(),
        active_window_id: windows.first().map(|(wid, _)| wid.clone()),
    };

    let _ = storage.save_window_manifest(&manifest);
}

/// Save all windows' bounds and update manifest. Called before quit.
fn save_all_windows(cx: &mut App) {
    let storage = match layout_storage::LayoutStorage::new() {
        Ok(s) => s,
        Err(_) => return,
    };

    let windows = cx.global::<AppState>().windows.clone();
    let mut manifest_entries = Vec::new();

    for (wid, handle) in &windows {
        let bounds = handle.update(cx, |_, window, _cx| {
            let b = window.bounds();
            layout_storage::SerializedBounds {
                x: f32::from(b.origin.x) as f64,
                y: f32::from(b.origin.y) as f64,
                width: f32::from(b.size.width) as f64,
                height: f32::from(b.size.height) as f64,
            }
        });
        manifest_entries.push(layout_storage::WindowManifestEntry {
            window_id: wid.clone(),
            bounds: bounds.ok(),
        });
    }

    let manifest = layout_storage::WindowManifest {
        windows: manifest_entries,
        active_window_id: windows.first().map(|(wid, _)| wid.clone()),
    };

    let _ = storage.save_window_manifest(&manifest);
}

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    tracing::info!("Starting Codewire Desktop");

    let app = gpui_platform::application().with_assets(assets::Assets);
    app.on_reopen(|cx: &mut App| {
        if cx.windows().is_empty() {
            open_new_window(None, cx);
        } else {
            for handle in cx.windows() {
                handle
                    .update(cx, |_, window, _cx| {
                        window.activate();
                    })
                    .ok();
            }
        }
        cx.activate(true);
    });
    app.run(|cx: &mut App| {
        // Register key bindings
        cx.bind_keys([
            // `secondary` is Cmd on macOS and Ctrl on Linux/Windows.
            KeyBinding::new(PRIMARY_QUIT_KEY, Quit, None),
            KeyBinding::new("escape", CancelLogin, None),
            KeyBinding::new("cmd-b", ToggleSidebar, None),
            KeyBinding::new("cmd-p", QuickOpenAction, None),
            KeyBinding::new("cmd-shift-p", CommandPaletteAction, None),
            KeyBinding::new("escape", DisconnectTerminal, Some("TerminalView")),
            KeyBinding::new("cmd-t", OpenLocalTerminal, None),
            // Inner split bindings (within workspace)
            KeyBinding::new("cmd-d", SplitRight, None),
            KeyBinding::new("cmd-shift-d", SplitDown, None),
            KeyBinding::new("cmd-w", CloseTab, None),
            // Outer split bindings (workspace-level)
            KeyBinding::new("cmd-alt-d", SplitWorkspaceRight, None),
            KeyBinding::new("cmd-shift-w", CloseWorkspace, None),
            // Inner pane switching (Ctrl+N)
            KeyBinding::new("ctrl-1", FocusPane1, None),
            KeyBinding::new("ctrl-2", FocusPane2, None),
            KeyBinding::new("ctrl-3", FocusPane3, None),
            KeyBinding::new("ctrl-4", FocusPane4, None),
            KeyBinding::new("ctrl-5", FocusPane5, None),
            // Tab switching within pane (Cmd+N)
            KeyBinding::new("cmd-1", SelectTab1, None),
            KeyBinding::new("cmd-2", SelectTab2, None),
            KeyBinding::new("cmd-3", SelectTab3, None),
            KeyBinding::new("cmd-4", SelectTab4, None),
            KeyBinding::new("cmd-5", SelectTab5, None),
            KeyBinding::new("cmd-6", SelectTab6, None),
            KeyBinding::new("cmd-7", SelectTab7, None),
            KeyBinding::new("cmd-8", SelectTab8, None),
            KeyBinding::new("cmd-9", SelectTab9, None),
            // Move tab to pane (Ctrl+Shift+N)
            KeyBinding::new("ctrl-shift-1", MoveTabToPane1, None),
            KeyBinding::new("ctrl-shift-2", MoveTabToPane2, None),
            KeyBinding::new("ctrl-shift-3", MoveTabToPane3, None),
            KeyBinding::new("ctrl-shift-4", MoveTabToPane4, None),
            KeyBinding::new("ctrl-shift-5", MoveTabToPane5, None),
            // Tab cycling (Cmd+Shift+[ and Cmd+Shift+])
            KeyBinding::new("cmd-shift-[", PrevTab, None),
            KeyBinding::new("cmd-shift-]", NextTab, None),
            // Diff view bindings
            KeyBinding::new("j", NextDiffFile, Some("DiffView")),
            KeyBinding::new("down", NextDiffFile, Some("DiffView")),
            KeyBinding::new("k", PrevDiffFile, Some("DiffView")),
            KeyBinding::new("up", PrevDiffFile, Some("DiffView")),
            KeyBinding::new("enter", ToggleDiffFile, Some("DiffView")),
            KeyBinding::new("space", ToggleDiffFile, Some("DiffView")),
            KeyBinding::new("cmd-r", RefreshDiff, Some("DiffView")),
            KeyBinding::new("/", FocusDiffSearch, Some("DiffView")),
            KeyBinding::new("cmd-f", FocusDiffSearch, Some("DiffView")),
            // Text input bindings
            KeyBinding::new("backspace", Backspace, Some("TextInput")),
            KeyBinding::new("delete", Delete, Some("TextInput")),
            KeyBinding::new("left", Left, Some("TextInput")),
            KeyBinding::new("right", Right, Some("TextInput")),
            KeyBinding::new("cmd-a", SelectAll, Some("TextInput")),
            KeyBinding::new("cmd-v", Paste, Some("TextInput")),
            KeyBinding::new("cmd-c", Copy, Some("TextInput")),
            KeyBinding::new("cmd-x", Cut, Some("TextInput")),
            // Editor bindings
            KeyBinding::new("backspace", EditorBackspace, Some("EditorView")),
            KeyBinding::new("delete", EditorDelete, Some("EditorView")),
            KeyBinding::new("left", EditorLeft, Some("EditorView")),
            KeyBinding::new("right", EditorRight, Some("EditorView")),
            KeyBinding::new("up", MoveUp, Some("EditorView")),
            KeyBinding::new("down", MoveDown, Some("EditorView")),
            KeyBinding::new("cmd-left", MoveLineStart, Some("EditorView")),
            KeyBinding::new("home", MoveLineStart, Some("EditorView")),
            KeyBinding::new("cmd-right", MoveLineEnd, Some("EditorView")),
            KeyBinding::new("end", MoveLineEnd, Some("EditorView")),
            KeyBinding::new("cmd-a", EditorSelectAll, Some("EditorView")),
            KeyBinding::new("cmd-c", EditorCopy, Some("EditorView")),
            KeyBinding::new("cmd-v", EditorPaste, Some("EditorView")),
            KeyBinding::new("cmd-x", EditorCut, Some("EditorView")),
            KeyBinding::new("enter", EditorEnter, Some("EditorView")),
            KeyBinding::new("cmd-s", SaveFile, Some("EditorView")),
            KeyBinding::new("cmd-z", UndoEdit, Some("EditorView")),
            KeyBinding::new("cmd-shift-z", RedoEdit, Some("EditorView")),
            // Explorer bindings
            KeyBinding::new("j", NextExplorerItem, Some("ExplorerView")),
            KeyBinding::new("down", NextExplorerItem, Some("ExplorerView")),
            KeyBinding::new("k", PrevExplorerItem, Some("ExplorerView")),
            KeyBinding::new("up", PrevExplorerItem, Some("ExplorerView")),
            KeyBinding::new("enter", ToggleOrOpen, Some("ExplorerView")),
            KeyBinding::new("space", ToggleOrOpen, Some("ExplorerView")),
            KeyBinding::new("cmd-r", RefreshExplorer, Some("ExplorerView")),
            // Window management
            KeyBinding::new("cmd-0", ShowMainWindow, None),
            KeyBinding::new("cmd-shift-n", NewWindow, None),
        ]);

        cx.on_action(|_: &Quit, cx| {
            cancel_all_codewire_logins(cx);
            save_all_windows(cx);
            cx.quit();
        });

        cx.on_action(|_: &NewWindow, cx| {
            open_new_window(None, cx);
        });

        cx.on_action(|_: &CloseWindow, cx| {
            if let Some(active) = cx.active_window() {
                let wid = cx
                    .global::<AppState>()
                    .windows
                    .iter()
                    .find(|(_, h)| h.window_id() == active.window_id())
                    .map(|(wid, _)| wid.clone());
                active
                    .update(cx, |_, window, cx| {
                        if let Some(ref wid) = wid {
                            prepare_window_close(wid, window, cx);
                        } else {
                            cancel_window_login(window, cx);
                        }
                        window.remove_window();
                    })
                    .ok();
            }
        });

        cx.on_action(|_: &CloseAllWindows, cx| {
            let windows = cx.global::<AppState>().windows.clone();
            for (wid, handle) in windows {
                handle
                    .update(cx, |_, window, cx| {
                        prepare_window_close(&wid, window, cx);
                        window.remove_window();
                    })
                    .ok();
            }
        });

        cx.on_action(|action: &FocusWindowByIndex, cx| {
            let windows = &cx.global::<AppState>().windows;
            if let Some((_, handle)) = windows.get(action.index) {
                handle
                    .update(cx, |_, window, _cx| {
                        window.activate();
                    })
                    .ok();
            }
        });

        cx.on_action(|action: &MoveWorkspaceToWindow, cx| {
            let windows = cx.global::<AppState>().windows.clone();

            // Find source window — the one that currently has this workspace
            let mut source_handle: Option<gpui::WindowHandle<AppView>> = None;
            for (_, handle) in &windows {
                if let Some(typed) = handle.downcast::<AppView>() {
                    let has_ws = typed.read_with(cx, |view, cx| {
                        view.app_layout.read(cx).has_workspace(&action.workspace_id)
                    });
                    if has_ws.unwrap_or(false) {
                        source_handle = Some(typed);
                        break;
                    }
                }
            }

            let target: Option<gpui::WindowHandle<AppView>> = windows
                .get(action.target_window_index)
                .and_then(|(_, h)| h.downcast::<AppView>());

            if let (Some(source), Some(target)) = (source_handle, target) {
                if (*source).window_id() == (*target).window_id() {
                    return; // Same window, nothing to do
                }

                // Detach from source
                let ws_id = action.workspace_id.clone();
                let detached = source.update(cx, |view, _window, cx| {
                    view.app_layout
                        .update(cx, |layout, cx| layout.detach_workspace(&ws_id, cx))
                });

                if let Ok(Some((tab, container, identity))) = detached {
                    // Attach to target
                    target
                        .update(cx, |view, _window, cx| {
                            view.app_layout.update(cx, |layout, cx| {
                                layout.attach_workspace(tab, container, identity, cx);
                            });
                        })
                        .ok();
                }
            }
        });

        cx.on_action(|_: &ShowMainWindow, cx| {
            if cx.windows().is_empty() {
                open_new_window(None, cx);
            } else {
                for handle in cx.windows() {
                    handle
                        .update(cx, |_, window, _cx| {
                            window.activate();
                        })
                        .ok();
                }
            }
            cx.activate(true);
        });

        // Initialize shared AppState global.
        cx.set_global(AppState {
            codewire_sidebar: CodewireSidebarState::default(),
            windows: Vec::new(),
        });

        // Background poll loop: refresh Codewire org/environment sidebar data.
        cx.spawn(async move |cx| {
            let mut first = true;
            loop {
                let is_first = first;
                first = false;

                let (tx, rx) = futures::channel::oneshot::channel();
                std::thread::spawn(move || {
                    if !is_first {
                        std::thread::sleep(std::time::Duration::from_secs(
                            CODEWIRE_POLL_INTERVAL_SECS,
                        ));
                    }
                    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                    let result = rt.block_on(AppView::sync_codewire_sidebar_state());
                    let _ = tx.send(result);
                });

                if let Ok(state) = rx.await {
                    cx.update(|cx| {
                        cx.global_mut::<AppState>().codewire_sidebar = state;
                    });
                }
            }
        })
        .detach();

        // Initial menu (will be rebuilt dynamically by update_window_menu after windows open)
        cx.set_menus(vec![
            Menu {
                disabled: false,
                name: "Codewire".into(),
                items: vec![
                    MenuItem::action("About Codewire", Quit),
                    MenuItem::separator(),
                    MenuItem::action("Quit Codewire", Quit),
                ],
            },
            Menu {
                disabled: false,
                name: "File".into(),
                items: vec![
                    MenuItem::action("New Window", NewWindow),
                    MenuItem::action("New Tab", OpenLocalTerminal),
                    MenuItem::separator(),
                    MenuItem::action("Split Right", SplitRight),
                    MenuItem::action("Split Down", SplitDown),
                    MenuItem::separator(),
                    MenuItem::action("Close", CloseTab),
                    MenuItem::action("Close Workspace", CloseWorkspace),
                    MenuItem::action("Close Window", CloseWindow),
                    MenuItem::action("Close All Windows", CloseAllWindows),
                ],
            },
            Menu {
                disabled: false,
                name: "Edit".into(),
                items: vec![
                    MenuItem::os_action("Cut", Cut, OsAction::Cut),
                    MenuItem::os_action("Copy", Copy, OsAction::Copy),
                    MenuItem::os_action("Paste", Paste, OsAction::Paste),
                    MenuItem::os_action("Select All", SelectAll, OsAction::SelectAll),
                    MenuItem::separator(),
                    MenuItem::os_action("Undo", UndoEdit, OsAction::Undo),
                    MenuItem::os_action("Redo", RedoEdit, OsAction::Redo),
                ],
            },
            Menu {
                disabled: false,
                name: "Window".into(),
                items: vec![MenuItem::action("New Window", NewWindow)],
            },
        ]);

        // Restore current layouts from the manifest, or start fresh.
        let mut opened = false;
        if let Ok(storage) = layout_storage::LayoutStorage::new() {
            if let Some(manifest) = storage.load_window_manifest() {
                // Restore each window from the manifest
                for entry in &manifest.windows {
                    if let Some(layout) = storage.load_window_layout(&entry.window_id) {
                        open_new_window(
                            Some((entry.window_id.clone(), layout, entry.bounds.clone())),
                            cx,
                        );
                        opened = true;
                    }
                }
            }
        }

        // Fallback: open a fresh window
        if !opened {
            open_new_window(None, cx);
        }

        cx.activate(true);
    });
}

/// Main application view
struct AppView {
    window_id: layout_storage::WindowId,
    sidebar: gpui::Entity<Sidebar>,
    app_layout: gpui::Entity<AppLayout>,
    status_bar: gpui::Entity<status_bar::StatusBar>,
    quick_open: gpui::Entity<quick_open::QuickOpen>,
    command_palette: gpui::Entity<command_palette::CommandPalette>,
    login_dialog: Option<gpui::Entity<LoginDialog>>,
    login_cancellation: Option<DesktopOAuthCancellation>,
    login_attempt: u64,
    sidebar_visible: bool,
    focus_handle: FocusHandle,
}

impl AppView {
    /// Create a new AppView.
    fn new(
        window_id: layout_storage::WindowId,
        _restore: Option<layout_storage::AppLayoutState>,
        cx: &mut Context<Self>,
    ) -> Self {
        let sidebar = cx.new(|cx| Sidebar::new(cx));
        let chat_panel = cx.new(|cx| ChatPanel::new(cx));
        let wid = window_id.clone();
        let app_layout = cx.new(|cx| AppLayout::new(wid, chat_panel, None, cx));
        let status_bar = cx.new(|cx| status_bar::StatusBar::new(cx));
        let quick_open = cx.new(|cx| quick_open::QuickOpen::new(cx));
        let command_palette = cx.new(|cx| command_palette::CommandPalette::new(cx));

        // Subscribe to quick open events
        cx.subscribe(&quick_open, Self::on_quick_open_file_selected)
            .detach();
        cx.subscribe(&command_palette, Self::on_palette_action_selected)
            .detach();

        // Subscribe to sidebar events
        cx.subscribe(&sidebar, Self::on_codewire_sign_in_requested)
            .detach();
        cx.subscribe(&sidebar, Self::on_codewire_sign_out_requested)
            .detach();
        cx.subscribe(&sidebar, Self::on_environment_terminal_requested)
            .detach();
        cx.subscribe(&sidebar, Self::on_add_local_project_requested)
            .detach();
        cx.subscribe(&sidebar, Self::on_local_project_expanded)
            .detach();
        cx.subscribe(&sidebar, Self::on_local_project_removed)
            .detach();
        cx.subscribe(&sidebar, Self::on_local_browse_requested)
            .detach();
        cx.subscribe(&sidebar, Self::on_local_diff_requested)
            .detach();
        cx.subscribe(&sidebar, Self::on_new_terminal_requested)
            .detach();

        // Keep the native status bar synchronized with typed environment state.
        {
            let sidebar_for_obs = sidebar.clone();
            cx.observe_global::<AppState>(move |_this: &mut AppView, cx| {
                let state = cx.global::<AppState>().codewire_sidebar.clone();
                sidebar_for_obs.update(cx, |sidebar, cx| {
                    sidebar.set_codewire_state(
                        state.organizations,
                        state.authenticated,
                        state.loading,
                        state.error,
                        cx,
                    );
                });
            })
            .detach();
        }

        {
            let status_bar_for_obs = status_bar.clone();
            cx.observe(&sidebar, move |_this, sidebar_entity, cx| {
                let counts = sidebar_entity.read(cx).workspace_status_counts();
                status_bar_for_obs.update(cx, |bar, cx| {
                    bar.update_workspace_counts(counts, cx);
                });
            })
            .detach();
        }

        // Restore persisted local projects into sidebar
        {
            if let Ok(paths) = desktop_settings::load_local_projects() {
                for path in paths {
                    if std::path::Path::new(&path).exists() {
                        sidebar.update(cx, |sidebar, cx| {
                            sidebar.add_local_project(path, cx);
                        });
                    }
                }
            }
        }

        let codewire_state = cx.global::<AppState>().codewire_sidebar.clone();
        sidebar.update(cx, |sidebar, cx| {
            sidebar.set_codewire_state(
                codewire_state.organizations,
                codewire_state.authenticated,
                codewire_state.loading,
                codewire_state.error,
                cx,
            );
        });
        let workspace_counts = sidebar.read(cx).workspace_status_counts();
        status_bar.update(cx, |bar, cx| {
            bar.update_workspace_counts(workspace_counts, cx);
        });

        Self {
            window_id,
            sidebar,
            app_layout,
            status_bar,
            quick_open,
            command_palette,
            login_dialog: None,
            login_cancellation: None,
            login_attempt: 0,
            sidebar_visible: true,
            focus_handle: cx.focus_handle(),
        }
    }
}

impl AppView {
    fn connected_client() -> Result<Option<CodewireClient>, String> {
        crate::connected_client()
    }

    async fn sync_codewire_sidebar_state() -> CodewireSidebarState {
        let client = match Self::connected_client() {
            Ok(client) => client,
            Err(error) => {
                return CodewireSidebarState {
                    organizations: Vec::new(),
                    authenticated: false,
                    loading: false,
                    error: Some(error),
                };
            }
        };

        let Some(client) = client else {
            return CodewireSidebarState {
                organizations: Vec::new(),
                authenticated: false,
                loading: false,
                error: None,
            };
        };

        let mut organizations = match client
            .list_organizations(ListOrganizationsRequest {
                page_size: 100,
                ..Default::default()
            })
            .await
        {
            Ok(response) => response.organizations,
            Err(e) => {
                return CodewireSidebarState {
                    organizations: Vec::new(),
                    authenticated: true,
                    loading: false,
                    error: Some(format!("Failed to load organizations: {}", e)),
                };
            }
        };

        organizations.sort_by(|left, right| {
            left.organization
                .as_option()
                .map(|organization| organization.name.to_lowercase())
                .cmp(
                    &right
                        .organization
                        .as_option()
                        .map(|organization| organization.name.to_lowercase()),
                )
        });

        let mut sidebar_orgs = Vec::with_capacity(organizations.len());
        for membership in organizations {
            let role = membership.role;
            let Some(org) = membership.organization.into_option() else {
                continue;
            };
            let mut environments = match client
                .list_environments(ListEnvironmentsRequest {
                    org_id: org.id.clone(),
                    page_size: 100,
                    ..Default::default()
                })
                .await
            {
                Ok(response) => response.environments,
                Err(e) => {
                    return CodewireSidebarState {
                        organizations: sidebar_orgs,
                        authenticated: true,
                        loading: false,
                        error: Some(format!(
                            "Failed to load environments for {}: {}",
                            org.name, e
                        )),
                    };
                }
            };

            environments.sort_by(|a, b| {
                let left = a.name.clone().to_lowercase();
                let right = b.name.clone().to_lowercase();
                left.cmp(&right)
            });

            let environments = environments.into_iter().map(environment_summary).collect();
            sidebar_orgs.push(SidebarOrganization {
                id: org.id,
                slug: org.slug,
                name: org.name,
                role: match role.as_known() {
                    Some(OrgRole::Owner) => "owner",
                    Some(OrgRole::Admin) => "admin",
                    Some(OrgRole::Member) => "member",
                    Some(OrgRole::Unspecified) | None => "unknown",
                }
                .to_string(),
                environments,
            });
        }

        CodewireSidebarState {
            organizations: sidebar_orgs,
            authenticated: true,
            loading: false,
            error: None,
        }
    }

    fn authenticate_codewire(
        runtime: &tokio::runtime::Runtime,
        oauth: &OAuthClient,
        login: DesktopOAuthLogin,
        cancellation: &DesktopOAuthCancellation,
    ) -> Result<(), String> {
        let credentials = runtime
            .block_on(oauth.complete_desktop_pkce_login(login))
            .map_err(|error| format!("Codewire authentication did not complete: {error}"))?;
        if cancellation.is_cancelled() {
            return Err("Codewire authentication was cancelled".to_string());
        }
        KeyringCredentialStore::desktop()
            .save(&credentials)
            .map_err(|_| "Failed to save Codewire credentials to the system keyring".to_string())
    }

    fn sign_out_codewire() -> Result<Option<String>, String> {
        let store = KeyringCredentialStore::desktop();
        let credentials = store.load().map_err(|_| {
            "Failed to read Codewire credentials from the system keyring".to_string()
        })?;
        let warning = if let Some(credentials) = credentials {
            match (
                OAuthClient::for_server_url(codewire_base_url()),
                tokio::runtime::Runtime::new(),
            ) {
                (Ok(oauth), Ok(runtime)) => runtime
                    .block_on(oauth.revoke_credentials(&credentials))
                    .err()
                    .map(|_| {
                        "Signed out locally; the remote token could not be revoked.".to_string()
                    }),
                _ => Some("Signed out locally; the remote token could not be revoked.".to_string()),
            }
        } else {
            None
        };
        store.delete().map_err(|_| {
            "Failed to remove Codewire credentials from the system keyring".to_string()
        })?;
        Ok(warning)
    }

    fn ensure_environment_workspace(
        &mut self,
        org_id: &str,
        org_slug: &str,
        environment: EnvironmentSummary,
        cx: &mut Context<Self>,
    ) -> gpui::Entity<split_container::SplitContainer> {
        let identity = WorkspaceIdentity::codewire_environment(
            org_id.to_string(),
            org_slug.to_string(),
            environment,
        );
        let mut container = None;
        self.app_layout.update(cx, |layout, cx| {
            container = Some(layout.open_workspace(identity, cx));
        });
        container.expect("environment workspace should exist")
    }

    fn on_environment_terminal_requested(
        &mut self,
        _sidebar: gpui::Entity<Sidebar>,
        event: &EnvironmentTerminalRequested,
        cx: &mut Context<Self>,
    ) {
        tracing::info!(
            "Open environment terminal: {} ({}/{})",
            event.environment.name,
            event.org_slug,
            event.environment.id
        );

        let workspace_id = format!("codewire:env:{}:{}", event.org_id, event.environment.id);
        let environment = event.environment.clone();
        let container = self.ensure_environment_workspace(
            &event.org_id,
            &event.org_slug,
            environment.clone(),
            cx,
        );
        let env_name = environment.name;
        let env_id = environment.id;
        let org_id = event.org_id.clone();

        container.update(cx, |container, cx| {
            container.open_terminal(
                workspace_id,
                env_name.clone(),
                TerminalConnection::CodewireEnvironment {
                    org_id,
                    env_id,
                    env_name,
                },
                "codewire-env".to_string(),
                cx,
            );
        });

        cx.notify();
    }

    fn on_codewire_sign_in_requested(
        &mut self,
        _sidebar: gpui::Entity<Sidebar>,
        _event: &CodewireSignInRequested,
        cx: &mut Context<Self>,
    ) {
        if self.login_dialog.is_some() {
            return;
        }
        let oauth = match OAuthClient::for_server_url(codewire_base_url()) {
            Ok(oauth) => oauth,
            Err(_) => {
                cx.global_mut::<AppState>().codewire_sidebar = CodewireSidebarState {
                    organizations: Vec::new(),
                    authenticated: false,
                    loading: false,
                    error: Some("Failed to configure Codewire OAuth".to_string()),
                };
                cx.notify();
                return;
            }
        };
        let login = match oauth.begin_desktop_pkce_login() {
            Ok(login) => login,
            Err(error) => {
                cx.global_mut::<AppState>().codewire_sidebar = CodewireSidebarState {
                    organizations: Vec::new(),
                    authenticated: false,
                    loading: false,
                    error: Some(format!("Unable to start Codewire sign-in: {error}")),
                };
                cx.notify();
                return;
            }
        };
        let authorization_url = login.authorization_url().to_string();
        let cancellation = login.cancellation();
        self.login_attempt = self.login_attempt.wrapping_add(1);
        let login_attempt = self.login_attempt;
        self.login_cancellation = Some(cancellation.clone());

        let current_orgs = cx
            .global::<AppState>()
            .codewire_sidebar
            .organizations
            .clone();
        cx.global_mut::<AppState>().codewire_sidebar = CodewireSidebarState {
            organizations: current_orgs,
            authenticated: false,
            loading: true,
            error: None,
        };
        let login_dialog = cx.new(|cx| LoginDialog::new(authorization_url.clone(), cx));
        cx.subscribe(&login_dialog, Self::on_login_dialog_event)
            .detach();
        self.login_dialog = Some(login_dialog);
        cx.notify();
        // Use GPUI's native opener while still handling the initiating click.
        // On Wayland this carries the activation context through the portal.
        cx.open_url(&authorization_url);

        cx.spawn(async move |this, cx| {
            let (tx, rx) = futures::channel::oneshot::channel();
            std::thread::spawn(move || {
                let result = (|| {
                    let rt = tokio::runtime::Runtime::new()
                        .map_err(|e| format!("Runtime error: {}", e))?;
                    Self::authenticate_codewire(&rt, &oauth, login, &cancellation)?;
                    Ok::<CodewireSidebarState, String>(
                        rt.block_on(Self::sync_codewire_sidebar_state()),
                    )
                })();
                let _ = tx.send(result);
            });

            let state = match rx.await {
                Ok(Ok(state)) => state,
                Ok(Err(error)) => CodewireSidebarState {
                    organizations: Vec::new(),
                    authenticated: false,
                    loading: false,
                    error: Some(error),
                },
                Err(_) => CodewireSidebarState {
                    organizations: Vec::new(),
                    authenticated: false,
                    loading: false,
                    error: Some("Codewire sign-in task cancelled".to_string()),
                },
            };
            cx.update(|cx| {
                let _ = this.update(cx, |view, cx| {
                    if view.login_attempt != login_attempt {
                        return;
                    }
                    cx.global_mut::<AppState>().codewire_sidebar = state;
                    view.login_dialog = None;
                    view.login_cancellation = None;
                    cx.notify();
                });
            });
        })
        .detach();
    }

    fn on_login_dialog_event(
        &mut self,
        _dialog: gpui::Entity<LoginDialog>,
        event: &LoginDialogEvent,
        cx: &mut Context<Self>,
    ) {
        match event {
            LoginDialogEvent::Cancelled => self.cancel_codewire_login(cx),
        }
    }

    fn cancel_codewire_login(&mut self, cx: &mut Context<Self>) {
        let was_active = self.login_dialog.take().is_some();
        if let Some(cancellation) = self.login_cancellation.take() {
            cancellation.cancel();
        }
        if !was_active {
            return;
        }
        self.login_attempt = self.login_attempt.wrapping_add(1);
        let current_orgs = cx
            .global::<AppState>()
            .codewire_sidebar
            .organizations
            .clone();
        cx.global_mut::<AppState>().codewire_sidebar = CodewireSidebarState {
            organizations: current_orgs,
            authenticated: false,
            loading: false,
            error: None,
        };
        cx.notify();
    }

    fn cancel_login_action(
        &mut self,
        _: &CancelLogin,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.cancel_codewire_login(cx);
    }

    fn on_codewire_sign_out_requested(
        &mut self,
        _sidebar: gpui::Entity<Sidebar>,
        _event: &CodewireSignOutRequested,
        cx: &mut Context<Self>,
    ) {
        let current_orgs = cx
            .global::<AppState>()
            .codewire_sidebar
            .organizations
            .clone();
        cx.global_mut::<AppState>().codewire_sidebar = CodewireSidebarState {
            organizations: current_orgs,
            authenticated: true,
            loading: true,
            error: None,
        };
        cx.notify();

        cx.spawn(async move |_, cx| {
            let (tx, rx) = futures::channel::oneshot::channel();
            std::thread::spawn(move || {
                let _ = tx.send(Self::sign_out_codewire());
            });

            let (error, authenticated) = match rx.await {
                Ok(Ok(warning)) => (warning, false),
                Ok(Err(error)) => (Some(error), true),
                Err(_) => (Some("Codewire sign-out task cancelled".to_string()), true),
            };
            cx.update(|cx| {
                let organizations = if authenticated {
                    cx.global::<AppState>()
                        .codewire_sidebar
                        .organizations
                        .clone()
                } else {
                    Vec::new()
                };
                cx.global_mut::<AppState>().codewire_sidebar = CodewireSidebarState {
                    organizations,
                    authenticated,
                    loading: false,
                    error,
                };
            });
        })
        .detach();
    }

    fn ensure_local_workspace(
        &mut self,
        path: &str,
        cx: &mut Context<Self>,
    ) -> gpui::Entity<split_container::SplitContainer> {
        let identity = WorkspaceIdentity::local(path.to_string());
        let mut container = None;
        self.app_layout.update(cx, |layout, cx| {
            container = Some(layout.open_workspace(identity, cx));
        });
        container.expect("local workspace should exist")
    }

    fn open_local_folder(&mut self, path: String, cx: &mut Context<Self>) {
        tracing::info!("Open local folder: {}", path);

        self.sidebar.update(cx, |sidebar, cx| {
            sidebar.add_local_project(path.clone(), cx);
        });
        self.persist_local_projects(cx);
        self.ensure_local_workspace(&path, cx);
        cx.notify();
    }

    fn persist_local_projects(&self, cx: &mut Context<Self>) {
        let paths = self.sidebar.read(cx).local_project_paths();
        if let Err(e) = desktop_settings::save_local_projects(&paths) {
            tracing::warn!("Failed to persist local projects: {}", e);
        }
    }

    fn on_add_local_project_requested(
        &mut self,
        _sidebar: gpui::Entity<Sidebar>,
        _event: &AddLocalProjectRequested,
        cx: &mut Context<Self>,
    ) {
        let (tx, rx) = futures::channel::oneshot::channel();
        std::thread::spawn(move || {
            let selected = rfd::FileDialog::new()
                .set_title("Open Local Folder")
                .pick_folder()
                .map(|path| path.to_string_lossy().to_string());
            let _ = tx.send(selected);
        });

        cx.spawn(async move |this, cx| match rx.await {
            Ok(Some(path)) => {
                cx.update(|cx| {
                    let _ = this.update(cx, |view, cx| {
                        view.open_local_folder(path, cx);
                    });
                });
            }
            Ok(None) => {}
            Err(_) => {
                tracing::warn!("Local folder picker task cancelled");
            }
        })
        .detach();
    }

    fn on_new_terminal_requested(
        &mut self,
        _sidebar: gpui::Entity<Sidebar>,
        event: &NewTerminalRequested,
        cx: &mut Context<Self>,
    ) {
        tracing::info!("New local terminal requested: {}", event.path);

        let container = self.ensure_local_workspace(&event.path, cx);
        container.update(cx, |container, cx| {
            container.open_local_terminal(cx);
        });

        cx.notify();
    }

    fn on_local_browse_requested(
        &mut self,
        _sidebar: gpui::Entity<Sidebar>,
        event: &LocalBrowseRequested,
        cx: &mut Context<Self>,
    ) {
        let container = self.ensure_local_workspace(&event.path, cx);
        let source = file_browser::FileSource::Local {
            root_path: event.path.clone(),
        };
        container.update(cx, |container, cx| {
            container.open_explorer(source, cx);
        });

        cx.notify();
    }

    fn on_local_diff_requested(
        &mut self,
        _sidebar: gpui::Entity<Sidebar>,
        event: &LocalDiffRequested,
        cx: &mut Context<Self>,
    ) {
        let container = self.ensure_local_workspace(&event.path, cx);
        let source = local_diff::DiffSource::Local {
            path: event.path.clone(),
        };
        container.update(cx, |container, cx| {
            container.open_diff(source, cx);
        });

        cx.notify();
    }

    fn on_local_project_expanded(
        &mut self,
        _sidebar: gpui::Entity<Sidebar>,
        event: &LocalProjectExpanded,
        cx: &mut Context<Self>,
    ) {
        tracing::info!("Local project expanded: {}", event.path);

        // Spawn background git status discovery
        let sidebar = self.sidebar.clone();
        let path = event.path.clone();

        cx.spawn(async move |_, cx| {
            let (tx, rx) = futures::channel::oneshot::channel();
            let discover_path = path.clone();
            std::thread::spawn(move || {
                let result = discover_local_git_status(&discover_path);
                let _ = tx.send(result);
            });

            if let Ok(Ok(git_status)) = rx.await {
                cx.update(|cx| {
                    sidebar.update(cx, |sidebar, cx| {
                        sidebar.update_local_git_status(&path, git_status, cx);
                    });
                });
            }
        })
        .detach();
    }

    fn on_local_project_removed(
        &mut self,
        _sidebar: gpui::Entity<Sidebar>,
        event: &LocalProjectRemoved,
        cx: &mut Context<Self>,
    ) {
        tracing::info!("Local project removed: {}", event.path);

        // Close the workspace container if open
        let workspace_id = format!("local:{}", event.path);
        self.app_layout.update(cx, |layout, cx| {
            layout.close_workspace(&workspace_id, cx);
        });

        // Persist updated list
        self.persist_local_projects(cx);
    }

    fn quick_open_action(
        &mut self,
        _: &QuickOpenAction,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.quick_open.update(cx, |qo, cx| {
            if qo.is_visible() {
                qo.hide(cx);
            } else {
                qo.show(cx);
            }
        });
    }

    fn on_quick_open_file_selected(
        &mut self,
        _quick_open: gpui::Entity<quick_open::QuickOpen>,
        event: &quick_open::QuickOpenFileSelected,
        cx: &mut Context<Self>,
    ) {
        // Open the file in the active workspace's editor
        self.with_active_workspace(cx, |container, cx| {
            container.open_editor(event.source.clone(), cx);
        });
    }

    fn command_palette_action(
        &mut self,
        _: &CommandPaletteAction,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.command_palette.update(cx, |cp, cx| {
            if cp.is_visible() {
                cp.hide(cx);
            } else {
                cp.show(cx);
            }
        });
    }

    fn on_palette_action_selected(
        &mut self,
        _palette: gpui::Entity<command_palette::CommandPalette>,
        event: &command_palette::PaletteActionSelected,
        cx: &mut Context<Self>,
    ) {
        match event.action_id.as_str() {
            "split_right" => self.with_active_workspace(cx, |c, cx| {
                c.split_active_pane(SplitDirection::Horizontal, cx)
            }),
            "split_down" => self.with_active_workspace(cx, |c, cx| {
                c.split_active_pane(SplitDirection::Vertical, cx)
            }),
            "close_tab" => {
                self.with_active_workspace(cx, |container, cx| {
                    let ids = container
                        .active_pane()
                        .and_then(|pane| pane.active_tab().map(|tab| (pane.id, tab.id)));
                    if let Some((pane_id, tab_id)) = ids {
                        container.close_tab(pane_id, tab_id, cx);
                    }
                });
            }
            "next_tab" => self.with_active_workspace(cx, |c, cx| c.next_tab(cx)),
            "prev_tab" => self.with_active_workspace(cx, |c, cx| c.prev_tab(cx)),
            "toggle_sidebar" => {
                self.sidebar_visible = !self.sidebar_visible;
                cx.notify();
            }
            "quick_open" => {
                self.quick_open.update(cx, |qo, cx| qo.show(cx));
            }
            _ => {
                tracing::debug!("Unhandled palette action: {}", event.action_id);
            }
        }
    }

    fn toggle_sidebar(&mut self, _: &ToggleSidebar, _window: &mut Window, cx: &mut Context<Self>) {
        self.sidebar_visible = !self.sidebar_visible;
        cx.notify();
    }

    fn disconnect_terminal(
        &mut self,
        _: &DisconnectTerminal,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) {
        // TODO: Disconnect the terminal in the active pane
    }

    fn open_local_terminal(
        &mut self,
        _: &OpenLocalTerminal,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.with_active_workspace(cx, |container, cx| {
            container.open_local_terminal(cx);
        });
    }

    // Inner split actions (within active workspace)
    fn split_right(&mut self, _: &SplitRight, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |container, cx| {
            container.split_active_pane(SplitDirection::Horizontal, cx);
        });
    }

    fn split_down(&mut self, _: &SplitDown, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |container, cx| {
            container.split_active_pane(SplitDirection::Vertical, cx);
        });
    }

    fn next_tab(&mut self, _: &NextTab, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |container, cx| {
            container.next_tab(cx);
        });
    }

    fn prev_tab(&mut self, _: &PrevTab, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |container, cx| {
            container.prev_tab(cx);
        });
    }

    fn close_tab(&mut self, _: &CloseTab, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |container, cx| {
            let ids = container
                .active_pane()
                .and_then(|pane| pane.active_tab().map(|tab| (pane.id, tab.id)));

            if let Some((pane_id, tab_id)) = ids {
                container.close_tab(pane_id, tab_id, cx);
            }
        });
    }

    // Outer split actions (workspace-level)
    fn split_workspace_right(
        &mut self,
        _: &SplitWorkspaceRight,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.app_layout.update(cx, |layout, cx| {
            layout.split_outer(SplitDirection::Horizontal, cx);
        });
    }

    fn split_workspace_down(
        &mut self,
        _: &SplitWorkspaceDown,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.app_layout.update(cx, |layout, cx| {
            layout.split_outer(SplitDirection::Vertical, cx);
        });
    }

    fn close_workspace_action(
        &mut self,
        _: &CloseWorkspace,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let ws_id = self
            .app_layout
            .read(cx)
            .active_workspace()
            .and_then(|container| {
                container
                    .read(cx)
                    .workspace_identity()
                    .map(|identity| identity.id.clone())
            });

        if let Some(ws_id) = ws_id {
            self.app_layout.update(cx, |layout, cx| {
                layout.close_workspace(&ws_id, cx);
            });
        }
    }

    /// Helper to run a closure on the active workspace's SplitContainer.
    fn with_active_workspace(
        &self,
        cx: &mut Context<Self>,
        f: impl FnOnce(
            &mut split_container::SplitContainer,
            &mut Context<split_container::SplitContainer>,
        ),
    ) {
        let container = self.app_layout.read(cx).active_workspace();
        if let Some(container) = container {
            container.update(cx, f);
        }
    }

    // Pane focus handlers (Ctrl+N) — within active workspace
    fn focus_pane_1(&mut self, _: &FocusPane1, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.focus_pane_by_index(0, cx));
    }
    fn focus_pane_2(&mut self, _: &FocusPane2, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.focus_pane_by_index(1, cx));
    }
    fn focus_pane_3(&mut self, _: &FocusPane3, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.focus_pane_by_index(2, cx));
    }
    fn focus_pane_4(&mut self, _: &FocusPane4, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.focus_pane_by_index(3, cx));
    }
    fn focus_pane_5(&mut self, _: &FocusPane5, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.focus_pane_by_index(4, cx));
    }

    // Tab selection handlers (Cmd+N) — within active workspace
    fn select_tab_1(&mut self, _: &SelectTab1, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.select_tab_by_index(0, cx));
    }
    fn select_tab_2(&mut self, _: &SelectTab2, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.select_tab_by_index(1, cx));
    }
    fn select_tab_3(&mut self, _: &SelectTab3, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.select_tab_by_index(2, cx));
    }
    fn select_tab_4(&mut self, _: &SelectTab4, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.select_tab_by_index(3, cx));
    }
    fn select_tab_5(&mut self, _: &SelectTab5, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.select_tab_by_index(4, cx));
    }
    fn select_tab_6(&mut self, _: &SelectTab6, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.select_tab_by_index(5, cx));
    }
    fn select_tab_7(&mut self, _: &SelectTab7, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.select_tab_by_index(6, cx));
    }
    fn select_tab_8(&mut self, _: &SelectTab8, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.select_tab_by_index(7, cx));
    }
    fn select_tab_9(&mut self, _: &SelectTab9, _window: &mut Window, cx: &mut Context<Self>) {
        self.with_active_workspace(cx, |c, cx| c.select_tab_by_index(8, cx));
    }

    // Move tab to pane handlers (Ctrl+Shift+N) — within active workspace
    fn move_tab_to_pane_1(
        &mut self,
        _: &MoveTabToPane1,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.with_active_workspace(cx, |c, cx| c.move_active_tab_to_pane(0, cx));
    }
    fn move_tab_to_pane_2(
        &mut self,
        _: &MoveTabToPane2,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.with_active_workspace(cx, |c, cx| c.move_active_tab_to_pane(1, cx));
    }
    fn move_tab_to_pane_3(
        &mut self,
        _: &MoveTabToPane3,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.with_active_workspace(cx, |c, cx| c.move_active_tab_to_pane(2, cx));
    }
    fn move_tab_to_pane_4(
        &mut self,
        _: &MoveTabToPane4,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.with_active_workspace(cx, |c, cx| c.move_active_tab_to_pane(3, cx));
    }
    fn move_tab_to_pane_5(
        &mut self,
        _: &MoveTabToPane5,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.with_active_workspace(cx, |c, cx| c.move_active_tab_to_pane(4, cx));
    }
}

impl Focusable for AppView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for AppView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();

        div()
            .relative()
            .flex()
            .flex_col()
            .size_full()
            .bg(theme.background)
            .text_color(theme.foreground)
            .font_family("Menlo")
            .track_focus(&self.focus_handle(cx))
            .on_action(cx.listener(Self::cancel_login_action))
            .on_action(cx.listener(Self::disconnect_terminal))
            .on_action(cx.listener(Self::open_local_terminal))
            // Inner split actions
            .on_action(cx.listener(Self::split_right))
            .on_action(cx.listener(Self::split_down))
            .on_action(cx.listener(Self::close_tab))
            // Tab cycling
            .on_action(cx.listener(Self::next_tab))
            .on_action(cx.listener(Self::prev_tab))
            // Sidebar
            .on_action(cx.listener(Self::toggle_sidebar))
            // Quick Open / Command Palette
            .on_action(cx.listener(Self::quick_open_action))
            .on_action(cx.listener(Self::command_palette_action))
            // Outer split actions
            .on_action(cx.listener(Self::split_workspace_right))
            .on_action(cx.listener(Self::split_workspace_down))
            .on_action(cx.listener(Self::close_workspace_action))
            // Pane focus actions
            .on_action(cx.listener(Self::focus_pane_1))
            .on_action(cx.listener(Self::focus_pane_2))
            .on_action(cx.listener(Self::focus_pane_3))
            .on_action(cx.listener(Self::focus_pane_4))
            .on_action(cx.listener(Self::focus_pane_5))
            // Tab selection actions
            .on_action(cx.listener(Self::select_tab_1))
            .on_action(cx.listener(Self::select_tab_2))
            .on_action(cx.listener(Self::select_tab_3))
            .on_action(cx.listener(Self::select_tab_4))
            .on_action(cx.listener(Self::select_tab_5))
            .on_action(cx.listener(Self::select_tab_6))
            .on_action(cx.listener(Self::select_tab_7))
            .on_action(cx.listener(Self::select_tab_8))
            .on_action(cx.listener(Self::select_tab_9))
            // Move tab to pane actions
            .on_action(cx.listener(Self::move_tab_to_pane_1))
            .on_action(cx.listener(Self::move_tab_to_pane_2))
            .on_action(cx.listener(Self::move_tab_to_pane_3))
            .on_action(cx.listener(Self::move_tab_to_pane_4))
            .on_action(cx.listener(Self::move_tab_to_pane_5))
            // Main row: activity bar + sidebar + content
            .child(
                div()
                    .flex()
                    .flex_1()
                    .overflow_hidden()
                    // Activity bar (always visible)
                    .child(
                        div()
                            .flex_shrink_0()
                            .w(px(48.0))
                            .flex()
                            .flex_col()
                            .items_center()
                            .pt_2()
                            .bg(theme.background)
                            .child(
                                div()
                                    .id("activity-bar-workspaces")
                                    .relative()
                                    .w(px(40.0))
                                    .h(px(40.0))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .rounded(px(8.0))
                                    .cursor_pointer()
                                    .hover_style(|s| s.bg(theme.hover))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.sidebar_visible = !this.sidebar_visible;
                                        cx.notify();
                                    }))
                                    .when(self.sidebar_visible, |d| {
                                        d.child(
                                            div()
                                                .absolute()
                                                .left_0()
                                                .top(px(8.0))
                                                .bottom(px(8.0))
                                                .w(px(2.0))
                                                .rounded(px(1.0))
                                                .bg(theme.accent),
                                        )
                                    })
                                    .child(
                                        svg()
                                            .path("icons/panel-left.svg")
                                            .size(px(20.0))
                                            .text_color(if self.sidebar_visible {
                                                theme.foreground
                                            } else {
                                                theme.muted
                                            }),
                                    ),
                            ),
                    )
                    .when(self.sidebar_visible, |d| d.child(self.sidebar.clone()))
                    .child(
                        div()
                            .flex_1()
                            .overflow_hidden()
                            .child(self.app_layout.clone()),
                    ),
            )
            // Status bar (full width, below main row)
            .child(self.status_bar.clone())
            // Quick open overlay
            .child(self.quick_open.clone())
            // Command palette overlay
            .child(self.command_palette.clone())
            // Browser-owned OAuth PKCE progress
            .when(self.login_dialog.is_some(), |view| {
                view.child(self.login_dialog.clone().expect("login dialog exists"))
            })
    }
}

/// Discover git status for a local project directory.
/// Runs on a background thread (no tokio needed — uses std::process::Command).
fn discover_local_git_status(path: &str) -> Result<Option<GitStatus>, String> {
    use std::process::Command;

    // Check if this is a git repo
    let is_git = Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(path)
        .output();

    let is_git = match is_git {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim() == "true",
        Err(_) => false,
    };

    if !is_git {
        return Ok(None);
    }

    // Get status --porcelain for dirty flag
    let status_output = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(path)
        .output()
        .map_err(|e| format!("git status failed: {}", e))?;

    let status_text = String::from_utf8_lossy(&status_output.stdout);
    let dirty = !status_text.trim().is_empty();

    // Get line-level additions/deletions via git diff HEAD --numstat
    let diff_output = Command::new("git")
        .args(["diff", "HEAD", "--numstat"])
        .current_dir(path)
        .output();

    let (additions, deletions) = match diff_output {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut adds = 0u32;
            let mut dels = 0u32;
            for line in text.lines() {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() >= 2 {
                    adds += parts[0].parse::<u32>().unwrap_or(0);
                    dels += parts[1].parse::<u32>().unwrap_or(0);
                }
            }
            (adds, dels)
        }
        _ => (0, 0),
    };

    // Get ahead/behind counts
    let rev_list = Command::new("git")
        .args(["rev-list", "--left-right", "--count", "HEAD...@{upstream}"])
        .current_dir(path)
        .output();

    let (ahead, behind) = match rev_list {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = text.trim().split('\t').collect();
            let a = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0u32);
            let b = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0u32);
            (a, b)
        }
        _ => (0, 0),
    };

    Ok(Some(GitStatus {
        ahead,
        behind,
        dirty,
        additions,
        deletions,
    }))
}
