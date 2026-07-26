//! Internal browser tab using wry WebView as a native overlay.
//!
//! The WebView is created as a child of the GPUI window and positioned
//! to match the bounds of the GPUI element on each paint cycle.

use crate::theme::Theme;
use gpui::{
    App, Bounds, Context, Element, ElementId, Entity, EventEmitter, FocusHandle, Focusable,
    GlobalElementId, InspectorElementId, IntoElement, LayoutId, Pixels, SharedString, Window, div,
    prelude::*, px, svg,
};
use std::cell::RefCell;
use std::rc::Rc;
use wry::dpi::{LogicalPosition, LogicalSize};
use wry::{Rect, WebView, WebViewBuilder};

/// Event emitted when the browser tab should be closed.
#[derive(Clone, Debug)]
pub struct WebBrowserCloseRequested;

impl EventEmitter<WebBrowserCloseRequested> for WebBrowserView {}

/// Wrapper around the native wry WebView instance.
struct NativeWebView {
    webview: WebView,
}

impl NativeWebView {
    fn load_url(&self, url: &str) {
        let _ = self.webview.load_url(url);
    }

    fn set_bounds(&self, bounds: Rect) {
        let _ = self.webview.set_bounds(bounds);
    }

    fn set_visible(&self, visible: bool) {
        let _ = self.webview.set_visible(visible);
    }

    fn go_back(&self) {
        let _ = self.webview.evaluate_script("window.history.back()");
    }

    fn go_forward(&self) {
        let _ = self.webview.evaluate_script("window.history.forward()");
    }

    fn reload(&self) {
        let _ = self.webview.reload();
    }

    fn current_url(&self) -> Option<String> {
        self.webview.url().ok()
    }
}

/// Convert GPUI pixel bounds to a wry Rect.
fn bounds_to_wry_rect(bounds: &Bounds<Pixels>) -> Rect {
    Rect {
        position: LogicalPosition::new(
            f32::from(bounds.origin.x) as f64,
            f32::from(bounds.origin.y) as f64,
        )
        .into(),
        size: LogicalSize::new(
            f32::from(bounds.size.width) as f64,
            f32::from(bounds.size.height) as f64,
        )
        .into(),
    }
}

/// Platform-appropriate system UI font name.
fn system_ui_font() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        ".AppleSystemUIFont"
    }
    #[cfg(target_os = "linux")]
    {
        "sans-serif"
    }
    #[cfg(target_os = "windows")]
    {
        "Segoe UI"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "sans-serif"
    }
}

/// A browser tab that renders web content via a native wry WebView overlay.
pub struct WebBrowserView {
    url: String,
    #[allow(dead_code)]
    provider_url: Option<String>,
    native_webview: Rc<RefCell<Option<NativeWebView>>>,
    visible: bool,
    focus_handle: FocusHandle,
}

impl WebBrowserView {
    pub fn new(url: String, provider_url: Option<String>, cx: &mut Context<Self>) -> Self {
        Self {
            url,
            provider_url,
            native_webview: Rc::new(RefCell::new(None)),
            visible: true,
            focus_handle: cx.focus_handle(),
        }
    }

    pub fn navigate(&mut self, url: &str, cx: &mut Context<Self>) {
        self.url = url.to_string();
        if let Some(ref wv) = *self.native_webview.borrow() {
            wv.load_url(url);
        }
        cx.notify();
    }

    pub fn set_visible(&mut self, visible: bool, cx: &mut Context<Self>) {
        if self.visible == visible {
            return;
        }
        self.visible = visible;
        if let Some(ref wv) = *self.native_webview.borrow() {
            wv.set_visible(visible);
        }
        cx.notify();
    }

    #[allow(dead_code)]
    pub fn url(&self) -> &str {
        &self.url
    }

    fn current_display_url(&self) -> String {
        if let Some(ref wv) = *self.native_webview.borrow() {
            wv.current_url().unwrap_or_else(|| self.url.clone())
        } else {
            self.url.clone()
        }
    }
}

impl Focusable for WebBrowserView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for WebBrowserView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::dark();
        let display_url = self.current_display_url();

        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(theme.background)
            .font_family(system_ui_font())
            .track_focus(&self.focus_handle)
            // URL bar
            .child(
                div()
                    .h(px(32.0))
                    .flex()
                    .items_center()
                    .gap(px(4.0))
                    .px(px(8.0))
                    .bg(theme.surface)
                    .border_b_1()
                    .border_color(theme.border)
                    // Back button
                    .child(
                        div()
                            .id("wb-back")
                            .w(px(24.0))
                            .h(px(24.0))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded(px(4.0))
                            .cursor_pointer()
                            .hover(|s| s.bg(theme.hover))
                            .on_click(cx.listener(|this, _, _, cx| {
                                if let Some(ref wv) = *this.native_webview.borrow() {
                                    wv.go_back();
                                }
                                cx.notify();
                            }))
                            .child(
                                svg()
                                    .path("icons/chevron-left.svg")
                                    .size(px(14.0))
                                    .text_color(theme.muted),
                            ),
                    )
                    // Forward button
                    .child(
                        div()
                            .id("wb-forward")
                            .w(px(24.0))
                            .h(px(24.0))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded(px(4.0))
                            .cursor_pointer()
                            .hover(|s| s.bg(theme.hover))
                            .on_click(cx.listener(|this, _, _, cx| {
                                if let Some(ref wv) = *this.native_webview.borrow() {
                                    wv.go_forward();
                                }
                                cx.notify();
                            }))
                            .child(
                                svg()
                                    .path("icons/chevron-right.svg")
                                    .size(px(14.0))
                                    .text_color(theme.muted),
                            ),
                    )
                    // Reload button
                    .child(
                        div()
                            .id("wb-reload")
                            .w(px(24.0))
                            .h(px(24.0))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded(px(4.0))
                            .cursor_pointer()
                            .hover(|s| s.bg(theme.hover))
                            .on_click(cx.listener(|this, _, _, cx| {
                                if let Some(ref wv) = *this.native_webview.borrow() {
                                    wv.reload();
                                }
                                cx.notify();
                            }))
                            .child(
                                svg()
                                    .path("icons/refresh.svg")
                                    .size(px(14.0))
                                    .text_color(theme.foreground),
                            ),
                    )
                    // URL display
                    .child(
                        div()
                            .flex_1()
                            .h(px(22.0))
                            .px(px(8.0))
                            .flex()
                            .items_center()
                            .rounded(px(4.0))
                            .bg(theme.background)
                            .border_1()
                            .border_color(theme.border)
                            .text_size(px(12.0))
                            .text_color(theme.muted)
                            .overflow_hidden()
                            .child(display_url),
                    )
                    // Open in external browser
                    .child(
                        div()
                            .id("wb-external")
                            .w(px(24.0))
                            .h(px(24.0))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded(px(4.0))
                            .cursor_pointer()
                            .hover(|s| s.bg(theme.hover))
                            .on_click({
                                let url = self.url.clone();
                                move |_, _, _| {
                                    let _ = open::that(&url);
                                }
                            })
                            .child(
                                svg()
                                    .path("icons/external-link.svg")
                                    .size(px(14.0))
                                    .text_color(theme.muted),
                            ),
                    ),
            )
            // WebView content area — rendered by custom element
            .child(WebBrowserElement {
                native_webview: self.native_webview.clone(),
                url: self.url.clone(),
                visible: self.visible,
            })
    }
}

/// Custom element that tracks bounds and manages the native wry WebView overlay.
struct WebBrowserElement {
    native_webview: Rc<RefCell<Option<NativeWebView>>>,
    url: String,
    visible: bool,
}

impl IntoElement for WebBrowserElement {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for WebBrowserElement {
    type RequestLayoutState = ();
    type PrepaintState = ();

    fn id(&self) -> Option<ElementId> {
        Some(ElementId::Name(SharedString::from("web-browser-element")))
    }

    fn source_location(&self) -> Option<&'static std::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let layout_id = window.request_layout(
            gpui::Style {
                flex_grow: 1.0,
                size: gpui::Size {
                    width: gpui::Length::Auto,
                    height: gpui::Length::Auto,
                },
                ..Default::default()
            },
            [],
            cx,
        );
        (layout_id, ())
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        _bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        _window: &mut Window,
        _cx: &mut App,
    ) -> Self::PrepaintState {
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        _prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        _cx: &mut App,
    ) {
        let mut native_ref = self.native_webview.borrow_mut();

        // Create the WebView if it doesn't exist yet
        if native_ref.is_none() {
            let wry_bounds = bounds_to_wry_rect(&bounds);
            let result = WebViewBuilder::new()
                .with_url(&self.url)
                .with_bounds(wry_bounds)
                .build_as_child(window);

            match result {
                Ok(webview) => {
                    *native_ref = Some(NativeWebView { webview });
                }
                Err(e) => {
                    tracing::error!("Failed to create WebView: {e}");
                    return;
                }
            }
        }

        if let Some(ref wv) = *native_ref {
            wv.set_bounds(bounds_to_wry_rect(&bounds));
            wv.set_visible(self.visible);
        }
    }
}
