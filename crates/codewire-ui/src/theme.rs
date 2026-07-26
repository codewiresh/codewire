//! Theme colors for the application (Mux-style dark theme)

use gpui::{Hsla, hsla};
use std::sync::LazyLock;

/// Application theme with colors
#[derive(Clone, Copy)]
pub struct Theme {
    pub background: Hsla,
    pub surface: Hsla,
    pub foreground: Hsla,
    pub muted: Hsla,
    pub border: Hsla,
    pub accent: Hsla,
    pub user_message: Hsla,
    pub assistant_message: Hsla,
    // Sidebar-specific colors (Mux-style)
    pub sidebar: Hsla,
    pub hover: Hsla,
    pub accent_selection: Hsla,
    // Status colors
    pub status_running: Hsla,
    pub status_stopped: Hsla,
    pub status_needs_auth: Hsla,
    pub status_attached: Hsla,
    // Git status colors
    pub git_additions: Hsla,
    pub git_deletions: Hsla,
    pub git_dirty: Hsla,
    // Tab colors
    pub tab_active_border: Hsla,
    pub tab_inactive: Hsla,
    // Pane colors
    pub divider_hover: Hsla,
    pub pane_focus_border: Hsla,
    // Diff colors
    pub diff_add_bg: Hsla,
    pub diff_remove_bg: Hsla,
    pub diff_header_bg: Hsla,
    pub diff_gutter_add: Hsla,
    pub diff_gutter_remove: Hsla,
    pub diff_line_number: Hsla,
    // Mux-style diff UI colors
    pub diff_selected_border: Hsla,
    pub diff_controls_bg: Hsla,
    pub diff_badge_added: Hsla,
    pub diff_badge_deleted: Hsla,
    pub diff_badge_modified: Hsla,
    pub diff_badge_renamed: Hsla,
    pub diff_hunk_border: Hsla,
    // File explorer colors
    pub explorer_dir_icon: Hsla,
    pub explorer_file_icon: Hsla,
    pub explorer_selected_bg: Hsla,
    // Editor colors
    pub editor_cursor_line: Hsla,
    pub editor_gutter: Hsla,
    pub editor_line_number: Hsla,
    // Workspace tab bar colors
    pub workspace_tab_bar_bg: Hsla,
    pub workspace_tab_active: Hsla,
    // Terminal ANSI colors (standard 16-color palette)
    pub term_black: Hsla,
    pub term_red: Hsla,
    pub term_green: Hsla,
    pub term_yellow: Hsla,
    pub term_blue: Hsla,
    pub term_magenta: Hsla,
    pub term_cyan: Hsla,
    pub term_white: Hsla,
    pub term_bright_black: Hsla,
    pub term_bright_red: Hsla,
    pub term_bright_green: Hsla,
    pub term_bright_yellow: Hsla,
    pub term_bright_blue: Hsla,
    pub term_bright_magenta: Hsla,
    pub term_bright_cyan: Hsla,
    pub term_bright_white: Hsla,
    pub term_cursor: Hsla,
}

static DARK_THEME: LazyLock<Theme> = LazyLock::new(|| {
    Theme {
        background: hsla(0.0, 0.0, 0.09, 1.0), // #171717 (neutral-900)
        surface: hsla(225.0 / 360.0, 0.074, 0.106, 1.0), // rgb(25,26,29)
        foreground: hsla(0.0, 0.0, 0.83, 1.0), // white at 83%
        muted: hsla(0.0, 0.0, 0.53, 1.0),      // hsl(0 0% 53%)
        border: hsla(225.0 / 360.0, 0.063, 0.125, 1.0), // rgb(30,31,34)
        accent: hsla(207.0 / 360.0, 1.0, 0.40, 1.0), // #007acc (VSCode blue)
        user_message: hsla(189. / 360., 0.71, 0.73, 1.0), // Sky
        assistant_message: hsla(115. / 360., 0.54, 0.76, 1.0), // Green
        // Sidebar-specific colors (Mux-style)
        sidebar: hsla(0.0, 0.0, 0.09, 1.0), // #171717
        hover: hsla(0.0, 0.0, 0.20, 1.0),   // Lighter hover for floating sidebar
        accent_selection: hsla(207.0 / 360.0, 1.0, 0.40, 1.0), // #007acc
        // Status colors
        status_running: hsla(115. / 360., 0.54, 0.45, 1.0), // Green
        status_stopped: hsla(0., 0., 0.3, 1.0),             // Dark gray
        status_needs_auth: hsla(35. / 360., 0.77, 0.60, 1.0), // Yellow/orange
        status_attached: hsla(217. / 360., 0.92, 0.60, 1.0), // Blue
        // Git status colors
        git_additions: hsla(115. / 360., 0.54, 0.60, 1.0), // Green (same as status_running)
        git_deletions: hsla(0. / 360., 0.72, 0.60, 1.0),   // Red
        git_dirty: hsla(45. / 360., 0.93, 0.60, 1.0),      // Yellow
        // Tab colors
        tab_active_border: hsla(207.0 / 360.0, 1.0, 0.40, 1.0), // VSCode blue accent
        tab_inactive: hsla(0.0, 0.0, 0.4, 1.0),                 // Dimmed text
        // Pane colors
        divider_hover: hsla(207.0 / 360.0, 0.6, 0.50, 1.0), // Blue tint on hover
        pane_focus_border: hsla(207.0 / 360.0, 0.6, 0.45, 0.7), // Subtle blue border for active pane
        // Diff colors
        diff_add_bg: hsla(115.0 / 360.0, 0.3, 0.15, 1.0), // Dark green
        diff_remove_bg: hsla(0.0, 0.3, 0.15, 1.0),        // Dark red
        diff_header_bg: hsla(217.0 / 360.0, 0.3, 0.18, 1.0), // Dark blue
        diff_gutter_add: hsla(115.0 / 360.0, 0.4, 0.25, 1.0), // Gutter green
        diff_gutter_remove: hsla(0.0, 0.4, 0.25, 1.0),    // Gutter red
        diff_line_number: hsla(0.0, 0.0, 0.35, 1.0),      // Dimmed line numbers
        // Mux-style diff UI colors
        diff_selected_border: hsla(48.0 / 360.0, 0.70, 0.50, 1.0), // Review accent (amber)
        diff_controls_bg: hsla(0.0, 0.0, 0.12, 1.0),               // Controls bar bg
        diff_badge_added: hsla(120.0 / 360.0, 0.40, 0.50, 1.0),    // Green A badge
        diff_badge_deleted: hsla(0.0, 0.80, 0.50, 1.0),            // Red D badge
        diff_badge_modified: hsla(38.0 / 360.0, 0.92, 0.50, 1.0),  // Yellow/amber M badge
        diff_badge_renamed: hsla(207.0 / 360.0, 0.45, 0.50, 1.0),  // Blue R badge
        diff_hunk_border: hsla(0.0, 0.0, 0.18, 1.0),               // Subtle hunk border
        // File explorer colors
        explorer_dir_icon: hsla(38.0 / 360.0, 0.80, 0.55, 1.0), // Amber folder color
        explorer_file_icon: hsla(0.0, 0.0, 0.45, 1.0),          // Muted file icon
        explorer_selected_bg: hsla(207.0 / 360.0, 0.50, 0.20, 1.0), // Subtle blue highlight
        // Editor colors
        editor_cursor_line: hsla(0.0, 0.0, 0.12, 1.0), // Subtle cursor line highlight
        editor_gutter: hsla(0.0, 0.0, 0.11, 1.0),      // Line number gutter bg
        editor_line_number: hsla(0.0, 0.0, 0.35, 1.0), // Line number text color
        // Workspace tab bar colors
        workspace_tab_bar_bg: hsla(0.0, 0.0, 0.12, 1.0), // Slightly lighter than bg
        workspace_tab_active: hsla(207.0 / 360.0, 1.0, 0.40, 1.0), // Accent for active ws tab
        // Terminal ANSI colors
        term_black: hsla(0.0, 0.0, 0.12, 1.0),
        term_red: hsla(0.0, 0.72, 0.56, 1.0),
        term_green: hsla(120.0 / 360.0, 0.54, 0.56, 1.0),
        term_yellow: hsla(40.0 / 360.0, 0.80, 0.60, 1.0),
        term_blue: hsla(217.0 / 360.0, 0.72, 0.60, 1.0),
        term_magenta: hsla(280.0 / 360.0, 0.50, 0.60, 1.0),
        term_cyan: hsla(180.0 / 360.0, 0.60, 0.56, 1.0),
        term_white: hsla(0.0, 0.0, 0.78, 1.0),
        term_bright_black: hsla(0.0, 0.0, 0.35, 1.0),
        term_bright_red: hsla(0.0, 0.80, 0.68, 1.0),
        term_bright_green: hsla(120.0 / 360.0, 0.65, 0.68, 1.0),
        term_bright_yellow: hsla(40.0 / 360.0, 0.90, 0.72, 1.0),
        term_bright_blue: hsla(217.0 / 360.0, 0.80, 0.72, 1.0),
        term_bright_magenta: hsla(280.0 / 360.0, 0.60, 0.72, 1.0),
        term_bright_cyan: hsla(180.0 / 360.0, 0.70, 0.68, 1.0),
        term_bright_white: hsla(0.0, 0.0, 0.93, 1.0),
        term_cursor: hsla(0.0, 0.0, 0.83, 1.0),
    }
});

impl Theme {
    /// Dark theme (Mux-style) — returns a static reference (zero-cost after first call).
    pub fn dark() -> &'static Theme {
        &DARK_THEME
    }
}
