//! Internal browser tab using wry WebView as a native overlay.
//!
//! The WebView is created as a child of the GPUI window and positioned
//! to match the bounds of the GPUI element on each paint cycle.

use crate::theme::Theme;
use gpui::{
    App, Bounds, Context, Element, ElementId, EventEmitter, FocusHandle, Focusable,
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
    _window_teardown: gpui::Subscription,
    webview: WebView,
    #[cfg(target_os = "linux")]
    _display_flush: FlushBrowserDisplay,
    #[cfg(test)]
    page_loads: Rc<std::cell::Cell<usize>>,
}

#[cfg(target_os = "linux")]
struct FlushBrowserDisplay(gdkx11::X11Display);

#[cfg(target_os = "linux")]
impl Drop for FlushBrowserDisplay {
    fn drop(&mut self) {
        use gtk::prelude::*;
        // Wry is declared before this guard: its child destruction must reach
        // the server before GPUI destroys the parent through another connection.
        self.0.upcast_ref::<gtk::gdk::Display>().sync();
    }
}

impl NativeWebView {
    fn load_url(&self, url: &str) {
        if let Err(error) = self.webview.load_url(url) {
            tracing::error!("Failed to navigate browser: {error}");
        }
    }

    fn set_bounds(&self, bounds: Rect) {
        if let Err(error) = self.webview.set_bounds(bounds) {
            tracing::error!("Failed to resize browser: {error}");
        }
    }

    fn set_visible(&self, visible: bool) {
        if let Err(error) = self.webview.set_visible(visible) {
            tracing::error!("Failed to change browser visibility: {error}");
        }
    }

    fn go_back(&self) {
        if let Err(error) = self.webview.evaluate_script("window.history.back()") {
            tracing::error!("Failed to navigate browser history: {error}");
        }
    }

    fn go_forward(&self) {
        if let Err(error) = self.webview.evaluate_script("window.history.forward()") {
            tracing::error!("Failed to navigate browser history: {error}");
        }
    }

    fn reload(&self) {
        if let Err(error) = self.webview.reload() {
            tracing::error!("Failed to reload browser: {error}");
        }
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
                            .hover_style(|s| s.bg(theme.hover))
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
                            .hover_style(|s| s.bg(theme.hover))
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
                            .hover_style(|s| s.bg(theme.hover))
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
                            .hover_style(|s| s.bg(theme.hover))
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
        cx: &mut App,
    ) {
        #[cfg(target_os = "linux")]
        if self.native_webview.borrow().is_none()
            && let Err(error) = ensure_linux_browser_runtime(window, cx)
        {
            tracing::error!("Failed to initialize browser runtime: {error}");
            return;
        }
        #[cfg(not(target_os = "linux"))]
        let _ = cx;
        let mut native_ref = self.native_webview.borrow_mut();

        // Create the WebView if it doesn't exist yet
        if native_ref.is_none() {
            let wry_bounds = bounds_to_wry_rect(&bounds);
            let builder = WebViewBuilder::new()
                .with_url(&self.url)
                .with_bounds(wry_bounds);
            #[cfg(test)]
            let page_loads = Rc::new(std::cell::Cell::new(0));
            #[cfg(test)]
            let builder = builder.with_on_page_load_handler({
                let page_loads = page_loads.clone();
                move |event, _url| {
                    if matches!(event, wry::PageLoadEvent::Finished) {
                        page_loads.set(page_loads.get() + 1);
                    }
                }
            });
            let result = builder.build_as_child(window);

            match result {
                Ok(webview) => {
                    let native = Rc::downgrade(&self.native_webview);
                    let window_id = window.window_handle().window_id();
                    let teardown = cx.on_window_closed(move |_, closed_id| {
                        if closed_id == window_id {
                            let webview = native
                                .upgrade()
                                .and_then(|native| native.borrow_mut().take());
                            // GTK destruction can invoke callbacks; release the cell borrow first.
                            drop(webview);
                        }
                    });
                    *native_ref = Some(NativeWebView {
                        _window_teardown: teardown,
                        webview,
                        #[cfg(target_os = "linux")]
                        _display_flush: FlushBrowserDisplay(
                            cx.global::<LinuxBrowserRuntime>()._display.clone(),
                        ),
                        #[cfg(test)]
                        page_loads,
                    });
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

#[cfg(target_os = "linux")]
struct LinuxBrowserRuntime {
    _display: gdkx11::X11Display,
    pump: Option<gpui::Task<()>>,
    _quit: gpui::Subscription,
}

#[cfg(target_os = "linux")]
impl gpui::Global for LinuxBrowserRuntime {}

#[cfg(target_os = "linux")]
fn ensure_linux_browser_runtime(
    window: &Window,
    cx: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    use gtk::prelude::*;
    use wry::raw_window_handle::{HasWindowHandle, RawWindowHandle};

    if !cx.background_executor().is_main_thread() {
        return Err("GTK browser initialization requires the GPUI foreground thread".into());
    }
    if !matches!(
        HasWindowHandle::window_handle(window)?.as_raw(),
        RawWindowHandle::Xlib(_)
    ) {
        return Err("embedded browser requires an X11 window; Wayland is unsupported".into());
    }
    if gtk::is_initialized() && !gtk::is_initialized_main_thread() {
        return Err("GTK is already initialized on a different thread".into());
    }
    gtk::init()?;
    let display = gtk::gdk::Display::default()
        .ok_or("GTK has no default display")?
        .downcast::<gdkx11::X11Display>()
        .map_err(|_| "GTK browser requires an X11 display")?;
    admit_gtk_display(window, &display)?;
    if cx.has_global::<LinuxBrowserRuntime>() {
        return Ok(());
    }

    let timer = cx.background_executor().clone();
    let pump = cx.foreground_executor().spawn(async move {
        loop {
            // A busy WebKit source must not starve GPUI input or rendering.
            for _ in 0..64 {
                if !gtk::events_pending() {
                    break;
                }
                gtk::main_iteration_do(false);
            }
            timer.timer(std::time::Duration::from_millis(8)).await;
        }
    });
    let quit = cx.on_app_quit(|cx| {
        if let Some(runtime) = cx.try_global::<LinuxBrowserRuntime>() {
            // Keep the display alive until Window's synchronous native-child teardown.
            if runtime.pump.is_some() {
                drop(cx.global_mut::<LinuxBrowserRuntime>().pump.take());
            }
        }
        std::future::ready(())
    });
    cx.set_global(LinuxBrowserRuntime {
        _display: display,
        pump: Some(pump),
        _quit: quit,
    });
    Ok(())
}

#[cfg(target_os = "linux")]
fn admit_gtk_display(
    window: &Window,
    display: &gdkx11::X11Display,
) -> Result<(), Box<dyn std::error::Error>> {
    use wry::raw_window_handle::{
        HasDisplayHandle, HasWindowHandle, RawDisplayHandle, RawWindowHandle,
    };
    use x11rb::{
        connection::Connection,
        protocol::xproto::{self, ConnectionExt as _},
        wrapper::ConnectionExt as _,
        xcb_ffi::XCBConnection,
    };

    let RawDisplayHandle::Xlib(owner) = HasDisplayHandle::display_handle(window)?.as_raw() else {
        return Err("browser parent has no Xlib display".into());
    };
    let RawWindowHandle::Xlib(parent) = HasWindowHandle::window_handle(window)?.as_raw() else {
        return Err("browser parent has no Xlib window".into());
    };
    let owner = owner
        .display
        .ok_or("browser parent has no owned Xlib display")?;
    let bridge = x11_dl::xlib_xcb::Xlib_xcb::open()?;
    // Both Display pointers have live owners throughout these non-owning views.
    let owner_connection = unsafe { (bridge.XGetXCBConnection)(owner.as_ptr().cast()) };
    let gtk_connection = unsafe { (bridge.XGetXCBConnection)(display.xdisplay().cast()) };
    if owner_connection.is_null() || gtk_connection.is_null() {
        return Err("browser display has no associated XCB connection".into());
    }
    let owner_connection =
        unsafe { XCBConnection::from_raw_xcb_connection(owner_connection, false) }?;
    let gtk_connection = unsafe { XCBConnection::from_raw_xcb_connection(gtk_connection, false) }?;
    let parent = u32::try_from(parent.window)?;
    let geometry = owner_connection.get_geometry(parent)?.reply()?;
    let window = owner_connection.generate_id()?;
    let proof = (|| -> Result<(), Box<dyn std::error::Error>> {
        owner_connection
            .create_window(
                0,
                window,
                geometry.root,
                0,
                0,
                1,
                1,
                0,
                xproto::WindowClass::INPUT_ONLY,
                0,
                &xproto::CreateWindowAux::default(),
            )?
            .check()?;
        let nonce = *uuid::Uuid::new_v4().as_bytes();
        owner_connection
            .change_property8(
                xproto::PropMode::REPLACE,
                window,
                xproto::AtomEnum::WM_NAME,
                xproto::AtomEnum::STRING,
                &nonce,
            )?
            .check()?;
        owner_connection.flush()?;
        let property = gtk_connection
            .get_property(
                false,
                window,
                xproto::AtomEnum::WM_NAME,
                xproto::AtomEnum::STRING,
                0,
                4,
            )?
            .reply()?;
        if property.type_ != u32::from(xproto::AtomEnum::STRING)
            || property.format != 8
            || property.bytes_after != 0
            || property.value != nonce
        {
            return Err("GTK display differs from the owned browser parent display".into());
        }
        Ok(())
    })();
    let cleanup = (|| -> Result<(), Box<dyn std::error::Error>> {
        owner_connection.destroy_window(window)?.check()?;
        owner_connection.flush()?;
        Ok(())
    })();
    match (proof, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(format!("{error}; affinity cleanup also failed: {cleanup}").into())
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod native_tests;
