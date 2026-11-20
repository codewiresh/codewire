//! The public Updates page's posts, read from one site of a Liminal CMS
//! through its read API (`GET /api/v1/posts` with the site's bearer key).

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use tracing::Instrument as _;

use crate::state::AppState;

/// How long the page keeps the posts it read before asking Liminal again,
/// how long after a failed read it asks again, and how long it waits for
/// Liminal before showing what it had.
const POSTS_TTL: Duration = Duration::from_secs(300);
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(30);
const POSTS_TIMEOUT: Duration = Duration::from_secs(3);
/// Liminal returns every published post in one list; the page shows the
/// newest of them and reads no more than this many bytes.
const MAX_POSTS: usize = 50;
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// A Liminal site: its origin, the site-scoped read key, and the one origin
/// its post images may come from (none: posts show no images). Debug never
/// prints the key.
#[derive(Clone)]
pub(crate) struct LiminalSite {
    origin: String,
    api_key: String,
    media_origin: Option<String>,
}

impl LiminalSite {
    pub(crate) fn new(origin: String, api_key: String, media_origin: Option<String>) -> Self {
        Self {
            origin,
            api_key,
            media_origin,
        }
    }

    pub(crate) fn media_origin(&self) -> Option<&str> {
        self.media_origin.as_deref()
    }

    pub(crate) fn posts_url(&self) -> String {
        format!("{}/api/v1/posts", self.origin)
    }
}

impl std::fmt::Debug for LiminalSite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiminalSite")
            .field("origin", &self.origin)
            .field("api_key", &"[redacted]")
            .field("media_origin", &self.media_origin)
            .finish()
    }
}

/// One post as the page shows it. `html` has been cleaned here, whatever
/// Liminal did to it first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UpdatePost {
    pub(crate) title: String,
    pub(crate) slug: String,
    /// `2026-11-18`, for the `<time datetime>` attribute.
    pub(crate) date: String,
    /// `Nov 18, 2026`.
    pub(crate) date_label: String,
    pub(crate) html: String,
}

/// The Updates source and the posts it last read.
pub(crate) struct Updates {
    site: LiminalSite,
    http: reqwest::Client,
    read: tokio::sync::Mutex<LastRead>,
}

#[derive(Default)]
struct LastRead {
    posts: Option<(Instant, Arc<Vec<UpdatePost>>)>,
    failed_at: Option<Instant>,
}

impl Updates {
    pub(crate) fn site(&self) -> &LiminalSite {
        &self.site
    }

    pub(crate) fn new(site: LiminalSite) -> Self {
        Self::with_timeout(site, POSTS_TIMEOUT)
    }

    pub(crate) fn with_timeout(site: LiminalSite, timeout: Duration) -> Self {
        Self {
            site,
            http: reqwest::Client::builder()
                .timeout(timeout)
                // The bearer key goes to the configured origin and nowhere else.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("static Updates HTTP client configuration"),
            read: tokio::sync::Mutex::default(),
        }
    }
}

#[derive(Deserialize)]
struct PostList {
    data: Vec<ApiPost>,
}

#[derive(Deserialize)]
struct ApiPost {
    title: String,
    slug: String,
    html: String,
    published_at: Option<DateTime<Utc>>,
}

/// The posts to show, newest first, read at most once per `POSTS_TTL`. When
/// Liminal fails the page keeps the last posts it read, `None` when it has
/// never read any, and asks again only after `RETRY_AFTER_FAILURE`: visitors
/// during an outage wait on no request, and one read in that time can bring
/// the page back.
pub(crate) async fn posts(state: &AppState) -> Option<Arc<Vec<UpdatePost>>> {
    let updates = state.updates.as_deref()?;
    let mut last = updates.read.lock().await;
    let stale = last.posts.as_ref().map(|(_, posts)| posts.clone());
    let fresh = last
        .posts
        .as_ref()
        .is_some_and(|(read_at, _)| read_at.elapsed() < POSTS_TTL);
    let backing_off = last
        .failed_at
        .is_some_and(|failed_at| failed_at.elapsed() < RETRY_AFTER_FAILURE);
    if fresh || backing_off {
        return stale;
    }
    match read_traced(updates).await {
        Ok(posts) => {
            let posts = Arc::new(posts);
            *last = LastRead {
                posts: Some((Instant::now(), posts.clone())),
                failed_at: None,
            };
            Some(posts)
        }
        Err(_) => {
            last.failed_at = Some(Instant::now());
            stale
        }
    }
}

/// Why a read of Liminal failed. It names the kind of failure and Liminal's
/// HTTP status, never the key, a URL or the body.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadFailure {
    Timeout,
    Connect,
    Status(u16),
    TooLarge,
    Parse,
    Request,
}

impl ReadFailure {
    fn outcome(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::Status(_) => "status",
            Self::TooLarge => "too_large",
            Self::Parse => "parse",
            Self::Request => "request",
        }
    }
}

impl From<reqwest::Error> for ReadFailure {
    fn from(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else if let Some(status) = error.status() {
            Self::Status(status.as_u16())
        } else if error.is_connect() {
            Self::Connect
        } else {
            Self::Request
        }
    }
}

/// The one module the dashboard writes logs from, and the level it logs at
/// (#5409); `main` hands this to `obs::init_traces_with_logs_from`.
pub(crate) const LOG_TARGET: (&str, tracing::Level) = (module_path!(), tracing::Level::WARN);

/// One read of Liminal inside an `updates.read` span whose `outcome` (and
/// `http.response.status_code`, for a status failure) says how it went;
/// codewire-server-core's `obs` exports Codewire DEBUG spans where trace
/// export is on. A failed read also writes one warning carrying the same two
/// fields, the dashboard's only log line, so a deployment without trace
/// export still records why.
pub(crate) async fn read_traced(updates: &Updates) -> Result<Vec<UpdatePost>, ReadFailure> {
    let span = tracing::debug_span!(
        "updates.read",
        outcome = tracing::field::Empty,
        http.response.status_code = tracing::field::Empty,
    );
    let read = read_posts(updates).instrument(span.clone()).await;
    match &read {
        Ok(_) => {
            span.record("outcome", "ok");
        }
        Err(ReadFailure::Status(status)) => {
            span.record("outcome", "status");
            span.record("http.response.status_code", status);
            tracing::warn!(
                outcome = "status",
                http.response.status_code = status,
                "the Updates page could not read Liminal and keeps its last posts"
            );
        }
        Err(failure) => {
            span.record("outcome", failure.outcome());
            tracing::warn!(
                outcome = failure.outcome(),
                "the Updates page could not read Liminal and keeps its last posts"
            );
        }
    }
    read
}

async fn read_posts(updates: &Updates) -> Result<Vec<UpdatePost>, ReadFailure> {
    let mut response = updates
        .http
        .get(updates.site.posts_url())
        .bearer_auth(&updates.site.api_key)
        .send()
        .await?
        .error_for_status()?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(ReadFailure::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    let list: PostList = serde_json::from_slice(&body).map_err(|_| ReadFailure::Parse)?;
    Ok(update_posts(list.data, updates.site.media_origin()))
}

fn update_posts(posts: Vec<ApiPost>, media_origin: Option<&str>) -> Vec<UpdatePost> {
    let mut posts: Vec<(DateTime<Utc>, ApiPost)> = posts
        .into_iter()
        .filter_map(|post| Some((post.published_at?, post)))
        .collect();
    posts.sort_by_key(|(published_at, _)| std::cmp::Reverse(*published_at));
    posts
        .into_iter()
        .take(MAX_POSTS)
        .map(|(published_at, post)| UpdatePost {
            title: post.title,
            slug: post.slug,
            date: published_at.format("%Y-%m-%d").to_string(),
            date_label: crate::time_display::calendar_date(published_at.timestamp()),
            html: clean_html(&post.html, media_origin),
        })
        .collect()
}

/// The post HTML the page may show: Liminal's own allowlist, minus `target`,
/// with links only over HTTPS (or `mailto:`), no relative URLs, which would
/// otherwise resolve against this site, and images only from the media
/// origin, the one image host the page's CSP admits.
fn clean_html(html: &str, media_origin: Option<&str>) -> String {
    let media_prefix = media_origin.map(|origin| format!("{origin}/"));
    ammonia::Builder::default()
        .attribute_filter(move |element, attribute, value| {
            if element == "img" && attribute == "src" {
                let on_media_origin = media_prefix
                    .as_deref()
                    .is_some_and(|prefix| value.starts_with(prefix));
                return on_media_origin.then(|| value.into());
            }
            Some(value.into())
        })
        .add_tags(["figure", "figcaption", "hr", "s", "u"])
        .add_tag_attributes("img", ["src", "alt", "width", "height"])
        .add_tag_attributes("a", ["href", "title"])
        .url_schemes(["https", "mailto"].into())
        .url_relative(ammonia::UrlRelative::Deny)
        .link_rel(Some("noopener noreferrer"))
        .clean(html)
        .to_string()
}

/// The posts the `updates.html` design fixture shows.
#[cfg(test)]
pub(crate) fn fixture_posts() -> Vec<UpdatePost> {
    vec![
        UpdatePost {
            title: "Snapshots and forks".to_owned(),
            slug: "snapshots-and-forks".to_owned(),
            date: "2026-11-18".to_owned(),
            date_label: "Nov 18, 2026".to_owned(),
            html: "<p>Capture a sandbox’s disk as a snapshot, then create new sandboxes from it, in the cloud and on a local VM.</p><ul><li>A snapshot lists its size and the sandbox it came from.</li><li>Removing a snapshot leaves its forks running.</li></ul>".to_owned(),
        },
        UpdatePost {
            title: "Local VMs on a Mac".to_owned(),
            slug: "local-vms-on-a-mac".to_owned(),
            date: "2026-11-04".to_owned(),
            date_label: "Nov 4, 2026".to_owned(),
            html: "<p>Local VMs now run on macOS 26 and 27. <a href=\"https://codewire.sh/docs/install\" rel=\"noopener noreferrer\">Install the CLI</a> and create one with <code>cw create --local</code>.</p>".to_owned(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_post(slug: &str, published_at: Option<&str>) -> ApiPost {
        ApiPost {
            title: format!("Post {slug}"),
            slug: slug.to_owned(),
            html: "<p>Body</p>".to_owned(),
            published_at: published_at.map(|value| value.parse().unwrap()),
        }
    }

    #[test]
    fn posts_are_published_newest_first() {
        let posts = update_posts(
            vec![
                api_post("older", Some("2026-11-01T09:00:00Z")),
                api_post("draft", None),
                api_post("newer", Some("2026-11-18T09:00:00Z")),
            ],
            None,
        );
        let slugs: Vec<&str> = posts.iter().map(|post| post.slug.as_str()).collect();
        assert_eq!(slugs, ["newer", "older"]);
        assert_eq!(posts[0].date, "2026-11-18");
        assert_eq!(posts[0].date_label, "Nov 18, 2026");
    }

    #[test]
    fn post_html_keeps_content_and_drops_anything_active() {
        let cleaned = clean_html(
            concat!(
                r#"<p onclick="x()">Hi <a href="https://codewire.sh/docs" target="_blank">docs</a></p>"#,
                r#"<script>alert(1)</script><style>p{}</style><form action="/login"><input></form>"#,
                r#"<iframe src="https://example.com"></iframe>"#,
                r#"<a href="javascript:alert(1)">js</a><a href="/login">relative</a>"#,
                r#"<figure><figcaption>Cap</figcaption></figure>"#,
            ),
            None,
        );
        assert_eq!(
            cleaned,
            concat!(
                r#"<p>Hi <a href="https://codewire.sh/docs" rel="noopener noreferrer">docs</a></p>"#,
                r#"<a rel="noopener noreferrer">js</a><a rel="noopener noreferrer">relative</a>"#,
                r#"<figure><figcaption>Cap</figcaption></figure>"#,
            )
        );
    }

    #[test]
    fn post_images_load_only_from_the_media_origin() {
        let images = concat!(
            r#"<img src="https://media.example.com/a.png" alt="A">"#,
            r#"<img src="http://media.example.com/b.png">"#,
            r#"<img src="https://media.example.com.tracker.test/c.png">"#,
            r#"<img src="https://tracker.test/pixel.gif">"#,
        );
        assert_eq!(
            clean_html(images, Some("https://media.example.com")),
            r#"<img src="https://media.example.com/a.png" alt="A"><img><img><img>"#
        );
        assert_eq!(clean_html(images, None), r#"<img alt="A"><img><img><img>"#);
    }

    /// RUSTSEC-2026-0533: foreign content that would re-parse as raw-text
    /// HTML. Neither `math` nor `svg` is allowed here, so nothing survives.
    #[test]
    fn embedded_math_and_svg_cannot_smuggle_raw_text_tags() {
        for payload in [
            r#"<math><mi><svg><style><img src=x onerror=alert(1)></style></svg></mi></math>"#,
            r#"<svg><foreignObject><math><mi><script>alert(1)</script></mi></math></foreignObject></svg>"#,
            r#"<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>"#,
        ] {
            let cleaned = clean_html(payload, Some("https://media.example.com"));
            for forbidden in ["<style", "<script", "onerror", "<math", "<svg"] {
                assert!(!cleaned.contains(forbidden), "{payload} -> {cleaned}");
            }
        }
    }

    #[test]
    fn no_other_markup_loads_an_image() {
        let cleaned = clean_html(
            concat!(
                r#"<img src="https://media.example.com/a.png" srcset="https://tracker.test/a.png 2x">"#,
                r#"<picture><source srcset="https://tracker.test/b.webp"><img src="https://media.example.com/b.png"></picture>"#,
                r#"<p style="background:url(https://tracker.test/c.png)" background="https://tracker.test/d.png">P</p>"#,
                r#"<video poster="https://tracker.test/e.png"></video><input type="image" src="https://tracker.test/f.png">"#,
            ),
            Some("https://media.example.com"),
        );
        assert!(!cleaned.contains("tracker.test"), "{cleaned}");
        assert!(!cleaned.contains("srcset"), "{cleaned}");
        assert!(!cleaned.contains("<source"), "{cleaned}");
    }
}
