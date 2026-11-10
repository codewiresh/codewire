use super::*;
use crate::{assets, chat::ChatPanel, split_container::SplitContainer};
use gpui::{AsyncApp, Entity, QuitMode, WindowOptions, size};
use std::{
    cell::Cell,
    ffi::CString,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use wry::raw_window_handle::RawWindowHandle;
use x11rb::{
    protocol::xproto::{self, ConnectionExt as _},
    xcb_ffi::XCBConnection,
};

fn on_native_child_teardown(
    window: &Window,
    cx: &App,
    mut on_teardown: impl FnMut() + 'static,
) -> gpui::Subscription {
    let window_id = window.window_handle().window_id();
    cx.on_window_closed(move |_, closed_id| {
        if closed_id == window_id {
            on_teardown();
        }
    })
}

struct FixtureServer {
    address: String,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl FixtureServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("synthetic listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = format!("http://{}/", listener.local_addr().expect("local address"));
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let requests = requests.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => Self::serve(&mut stream, &requests),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => panic!("synthetic listener failed: {error}"),
                    }
                }
            })
        };
        Self {
            address,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    fn serve(stream: &mut TcpStream, requests: &AtomicUsize) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("fixture read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("fixture write timeout");
        let mut request = [0; 4096];
        let count = stream.read(&mut request).expect("read synthetic request");
        if count == 0 {
            return;
        }
        let is_page = request[..count].starts_with(b"GET / HTTP/");
        let body = if is_page {
            requests.fetch_add(1, Ordering::Release);
            "<!doctype html><html><head><title>Codewire native fixture</title></head><body><main><h1>Synthetic native browser</h1><p>No credentials or external resources.</p></main></body></html>"
        } else {
            "not found"
        };
        let status = if is_page { "200 OK" } else { "404 Not Found" };
        write!(stream, "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len()).expect("write fixture response");
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("fixture server completed");
        }
    }
}

struct NativeSample {
    parent: u32,
    child: u32,
    width: u16,
    height: u16,
    visible: bool,
    loads: usize,
}

fn sample(
    browser: &WebBrowserView,
    window: &Window,
    inspector: &XCBConnection,
) -> Option<NativeSample> {
    let native = browser.native_webview.borrow();
    let native = native.as_ref()?;
    let bounds = native.webview.bounds().expect("native bounds");
    let RawWindowHandle::Xlib(parent) =
        wry::raw_window_handle::HasWindowHandle::window_handle(window)
            .expect("real parent handle")
            .as_raw()
    else {
        panic!("parent is not Xlib")
    };
    let parent = u32::try_from(parent.window).expect("X11 XID");
    let width = bounds
        .size
        .to_physical::<u32>(window.scale_factor() as f64)
        .width;
    let height = bounds
        .size
        .to_physical::<u32>(window.scale_factor() as f64)
        .height;
    let children = inspector
        .query_tree(parent)
        .expect("query parent tree")
        .reply()
        .expect("parent exists")
        .children;
    let candidates: Vec<_> = children
        .into_iter()
        .filter_map(|child| {
            let geometry = inspector
                .get_geometry(child)
                .expect("query owned child")
                .reply()
                .expect("child exists");
            (u32::from(geometry.width) == width && u32::from(geometry.height) == height)
                .then_some((child, geometry))
        })
        .collect();
    if candidates.len() != 1 {
        return None;
    }
    let (child, geometry) = &candidates[0];
    let attributes = inspector
        .get_window_attributes(*child)
        .expect("query native mapping")
        .reply()
        .expect("native child exists");
    Some(NativeSample {
        parent,
        child: *child,
        width: geometry.width,
        height: geometry.height,
        visible: attributes.map_state == xproto::MapState::VIEWABLE,
        loads: native.page_loads.get(),
    })
}

async fn until(cx: &mut AsyncApp, stage: &str, mut predicate: impl FnMut(&mut AsyncApp) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(12);
    while !predicate(cx) {
        assert!(
            Instant::now() < deadline,
            "native journey timed out: {stage}"
        );
        cx.background_executor()
            .timer(Duration::from_millis(15))
            .await;
    }
    eprintln!("native browser observed: {stage}");
}

fn require_private_environment() {
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        std::env::var("CODEWIRE_NATIVE_BROWSER_SMOKE").as_deref(),
        Ok("1"),
        "use the isolated native-browser runner"
    );
    let home = std::env::var("HOME").expect("private HOME");
    let root = Path::new(&home)
        .parent()
        .expect("private root")
        .canonicalize()
        .expect("root exists");
    let owner = std::fs::metadata("/proc/self")
        .expect("process owner")
        .uid();
    let root_metadata = std::fs::symlink_metadata(&root).expect("private root exists");
    assert!(root_metadata.is_dir() && root_metadata.mode() & 0o777 == 0o700);
    assert_eq!(root_metadata.uid(), owner);
    assert!(
        root.file_name()
            .expect("root name")
            .to_string_lossy()
            .starts_with("cw-desktop-native-")
    );
    for name in [
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
    ] {
        let path = std::env::var(name).expect("private XDG path");
        let metadata = std::fs::symlink_metadata(&path).expect("private directory exists");
        assert!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.mode() & 0o777 == 0o700
        );
        assert_eq!(metadata.uid(), owner);
        assert!(
            Path::new(&path)
                .canonicalize()
                .expect("canonical directory")
                .starts_with(&root)
        );
    }
    let bus = std::env::var("DBUS_SESSION_BUS_ADDRESS").expect("private bus");
    assert_eq!(bus, format!("unix:path={}/runtime/bus", root.display()));
    assert!(std::env::var_os("WAYLAND_DISPLAY").is_none());
    assert!(std::env::var_os("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS").is_none());
}

struct Journey {
    first: gpui::WindowHandle<SplitContainer>,
    second: gpui::WindowHandle<SplitContainer>,
    browser: Entity<WebBrowserView>,
    other_browser: Entity<WebBrowserView>,
    inspector: Rc<XCBConnection>,
    address: String,
    requests: Arc<AtomicUsize>,
    finished: Rc<Cell<bool>>,
    quit_seen: Rc<Cell<bool>>,
}

impl Journey {
    async fn run(self, cx: &mut AsyncApp) {
        let Self {
            first,
            second,
            browser,
            other_browser,
            inspector,
            address,
            requests,
            finished: finished_for_app,
            quit_seen: quit_seen_for_app,
        } = self;
        let read_first = |cx: &mut AsyncApp| {
            first
                .update(cx, |_split, window, cx| {
                    sample(browser.read(cx), window, &inspector)
                })
                .expect("read first window")
        };
        until(cx, "real page loaded in two windows", |cx| {
            let first = read_first(cx);
            let other = second
                .update(cx, |_split, window, cx| {
                    sample(other_browser.read(cx), window, &inspector)
                })
                .expect("read second window");
            first.is_some_and(|sample| sample.loads >= 1 && sample.visible)
                && other.is_some_and(|sample| sample.loads >= 1 && sample.visible)
                && requests.load(Ordering::Acquire) >= 2
        })
        .await;
        let original = read_first(cx).expect("first native child");
        browser.update(cx, |browser, _cx| {
            browser
                .native_webview
                .borrow()
                .as_ref()
                .expect("native browser")
                .webview
                .reload()
                .expect("reload Wry")
        });
        until(cx, "real reload", |cx| {
            read_first(cx).is_some_and(|sample| sample.loads >= 2)
                && requests.load(Ordering::Acquire) >= 3
        })
        .await;
        first
            .update(cx, |_split, window, _cx| {
                window.resize(size(px(900.0), px(620.0)))
            })
            .expect("resize window");
        until(cx, "native resize", |cx| {
            read_first(cx).is_some_and(|sample| {
                (sample.width, sample.height) != (original.width, original.height)
            })
        })
        .await;
        first
            .update(cx, |split, _window, cx| split.select_tab_by_index(0, cx))
            .expect("switch to chat");
        until(cx, "native hide", |cx| {
            read_first(cx).is_some_and(|sample| !sample.visible)
        })
        .await;
        first
            .update(cx, |split, _window, cx| split.select_tab_by_index(1, cx))
            .expect("switch to browser");
        until(cx, "native show", |cx| {
            read_first(cx).is_some_and(|sample| sample.visible)
        })
        .await;

        let closed_native = read_first(cx).expect("child before tab close");
        let closed_cell =
            browser.read_with(cx, |browser, _cx| Rc::downgrade(&browser.native_webview));
        drop(browser);
        first
            .update(cx, |split, _window, cx| {
                let pane = split.active_pane().expect("active browser pane");
                let pane_id = pane.id;
                let tab_id = pane.active_tab().expect("active browser tab").id;
                split.close_tab(pane_id, tab_id, cx);
            })
            .expect("close actual browser tab");
        until(cx, "ordinary tab close releases native view", |_cx| {
            closed_cell.upgrade().is_none()
        })
        .await;
        assert!(
            inspector
                .get_geometry(closed_native.child)
                .expect("query closed child")
                .reply()
                .is_err()
        );
        assert!(
            inspector
                .get_geometry(closed_native.parent)
                .expect("query retained parent")
                .reply()
                .is_ok()
        );
        let browser = first
            .update(cx, |split, _window, cx| {
                split.open_web_browser(address.clone(), None, cx);
                split
                    .browser_for_url(&address)
                    .expect("reopened browser entity")
            })
            .expect("reopen actual browser tab");
        let read_first = |cx: &mut AsyncApp| {
            first
                .update(cx, |_split, window, cx| {
                    sample(browser.read(cx), window, &inspector)
                })
                .expect("read reopened window")
        };
        until(cx, "browser reopens after tab close", |cx| {
            read_first(cx).is_some_and(|sample| sample.loads >= 1 && sample.visible)
        })
        .await;

        let native = read_first(cx).expect("live child before removal");
        let teardown_seen = Rc::new(Cell::new(false));
        let teardown = first
            .update(cx, |_split, window, _cx| {
                on_native_child_teardown(window, _cx, {
                    let inspector = inspector.clone();
                    let seen = teardown_seen.clone();
                    move || {
                        assert!(
                            inspector
                                .get_geometry(native.parent)
                                .expect("query teardown parent")
                                .reply()
                                .is_ok(),
                            "parent destroyed before child callback"
                        );
                        assert!(
                            inspector
                                .get_geometry(native.child)
                                .expect("query teardown child")
                                .reply()
                                .is_err(),
                            "native child survived its teardown"
                        );
                        seen.set(true);
                    }
                })
            })
            .expect("register ordering assertion");
        first
            .update(cx, |_split, window, _cx| window.remove_window())
            .expect("programmatic removal");
        assert!(
            teardown_seen.get(),
            "programmatic removal skipped native teardown"
        );
        assert!(browser.read_with(cx, |browser, _cx| browser.native_webview.borrow().is_none()));
        assert!(
            inspector
                .get_geometry(native.parent)
                .expect("query removed parent")
                .reply()
                .is_err()
        );
        drop(teardown);
        eprintln!(
            "native browser observed: child-before-parent programmatic removal with retained entity"
        );
        other_browser.update(cx, |browser, _cx| {
            browser
                .native_webview
                .borrow()
                .as_ref()
                .expect("second native browser")
                .webview
                .reload()
                .expect("second reload")
        });
        until(cx, "second window survives first close", |cx| {
            second
                .update(cx, |_split, window, cx| {
                    sample(other_browser.read(cx), window, &inspector)
                })
                .expect("second window read")
                .is_some_and(|sample| sample.loads >= 2)
        })
        .await;
        let other_native = second
            .update(cx, |_split, window, cx| {
                sample(other_browser.read(cx), window, &inspector)
            })
            .expect("second native snapshot")
            .expect("second live child");
        let quitting_cell =
            other_browser.read_with(cx, |browser, _cx| browser.native_webview.clone());
        let quit_teardown = second
            .update(cx, |_split, window, _cx| {
                on_native_child_teardown(window, _cx, {
                    let inspector = inspector.clone();
                    let seen = quit_seen_for_app.clone();
                    move || {
                        assert!(
                            inspector
                                .get_geometry(other_native.parent)
                                .expect("query quitting parent")
                                .reply()
                                .is_ok()
                        );
                        assert!(
                            inspector
                                .get_geometry(other_native.child)
                                .expect("query quitting child")
                                .reply()
                                .is_err()
                        );
                        assert!(
                            quitting_cell.borrow().is_none(),
                            "app quit retained native browser"
                        );
                        seen.set(true);
                    }
                })
            })
            .expect("register quit ordering assertion");
        quit_teardown.detach();
        finished_for_app.set(true);
        cx.update(|cx| cx.quit());
    }
}

#[test]
#[ignore = "requires the isolated Linux Xvfb/DBus native-browser runner"]
fn linux_native_browser_journey() {
    require_private_environment();
    let server = FixtureServer::start();
    eprintln!("synthetic browser origin: {}", server.address);
    let display =
        CString::new(std::env::var("DISPLAY").expect("owned Xvfb display")).expect("display name");
    let (inspector, _) = XCBConnection::connect(Some(&display)).expect("owned X11 observer");
    let inspector = Rc::new(inspector);
    let finished = Rc::new(Cell::new(false));
    let finished_for_app = finished.clone();
    let quit_seen = Rc::new(Cell::new(false));
    let quit_seen_for_app = quit_seen.clone();
    let address = server.address.clone();
    let requests = server.requests.clone();
    gpui_platform::application()
        .with_assets(assets::Assets)
        .with_quit_mode(QuitMode::Explicit)
        .run(move |cx| {
            let make_window = |cx: &mut App| {
                cx.open_window(WindowOptions::default(), |_window, cx| {
                    let chat = cx.new(ChatPanel::new);
                    cx.new(|cx| {
                        let mut split = SplitContainer::new(chat, cx);
                        split.open_web_browser(address.clone(), None, cx);
                        split
                    })
                })
                .expect("open actual browser container")
            };
            let first = make_window(cx);
            let second = make_window(cx);
            let browser = first
                .update(cx, |split, _window, _cx| {
                    split.browser_for_url(&address).expect("browser entity")
                })
                .expect("first window");
            let other_browser = second
                .update(cx, |split, _window, _cx| {
                    split
                        .browser_for_url(&address)
                        .expect("second browser entity")
                })
                .expect("second window");
            let journey = Journey {
                first,
                second,
                browser,
                other_browser,
                inspector,
                address,
                requests,
                finished: finished_for_app,
                quit_seen: quit_seen_for_app,
            };
            cx.spawn(async move |cx| journey.run(cx).await).detach();
        });
    assert!(
        finished.get(),
        "native journey exited before all assertions completed"
    );
    assert!(quit_seen.get(), "app quit skipped native teardown");
    eprintln!("native browser observed: app quit with live browser");
}
