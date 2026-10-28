//! Connection tasks that never hold a request's span (#3581).
//!
//! `kube-client` turns on hyper-util's `tracing` feature, and the workspace
//! unifies it everywhere. With it, `hyper_util::rt::TokioExecutor` spawns
//! every future as `tokio::spawn(fut.in_current_span())`, and hyper and tonic
//! spawn each new connection's driver through it. A request that opens a
//! connection then keeps its span, and every parent of that span, open for
//! the connection's whole life: for an HTTP/2 connection to the Kubernetes API
//! that is until the process exits, so the trace is never exported and the
//! span chain stays in memory. [`DetachedExecutor`] spawns without the span.

/// A hyper and tonic executor whose tasks start with no current span.
#[derive(Clone, Copy, Debug, Default)]
pub struct DetachedExecutor;

impl<F> hyper::rt::Executor<F> for DetachedExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::spawn(fut);
    }
}

/// A Kubernetes client built like `kube::Client::try_from(config)`, with the
/// same connector, timeouts, base URI, auth, extra headers and request span,
/// except that its connections run on [`DetachedExecutor`]. Proxies are
/// refused, as this build of kube refuses them (no `http-proxy` or `socks5`).
/// Exec-plugin client certificates' expiry is not tracked; in-cluster and
/// token kubeconfigs have none.
#[cfg(feature = "kubernetes-identity")]
pub fn kube_client(config: kube::Config) -> kube::Result<kube::Client> {
    use std::time::Duration;

    use http::{Request, Response, header::HeaderMap};
    use hyper::body::Incoming;
    use hyper_util::client::legacy::connect::HttpConnector;
    use kube::client::{Body, ClientBuilder, ConfigExt as _, DynBody};
    use tower::{BoxError, ServiceBuilder, ServiceExt as _};
    use tower_http::{ServiceExt as _, classify::ServerErrorsFailureClass, trace::TraceLayer};
    use tracing::Span;

    if let Some(proxy_url) = config.proxy_url.clone() {
        return Err(kube::Error::ProxyProtocolDisabled {
            proxy_url,
            protocol_feature: "kube/http-proxy",
        });
    }

    let default_ns = config.default_namespace.clone();
    let auth_layer = config.auth_layer()?;

    let mut http = HttpConnector::new();
    http.enforce_http(false);
    let mut connector =
        hyper_timeout::TimeoutConnector::new(config.rustls_https_connector_with_connector(http)?);
    connector.set_connect_timeout(config.connect_timeout);
    connector.set_read_timeout(config.read_timeout);
    connector.set_write_timeout(config.write_timeout);
    let client: hyper_util::client::legacy::Client<_, Body> =
        hyper_util::client::legacy::Builder::new(DetachedExecutor).build(connector);

    let service = ServiceBuilder::new()
        .layer(config.base_uri_layer())
        .option_layer(auth_layer)
        .layer(config.extra_headers_layer()?)
        .layer(
            // The same request span as kube's own stack, so the exported
            // `HTTP` child spans are unchanged.
            TraceLayer::new_for_http()
                .make_span_with(|req: &Request<Body>| {
                    tracing::debug_span!(
                        target: "kube_client::client::builder",
                        "HTTP",
                        http.method = %req.method(),
                        http.url = %req.uri(),
                        http.status_code = tracing::field::Empty,
                        otel.name = req.extensions().get::<&'static str>().unwrap_or(&"HTTP"),
                        otel.kind = "client",
                        otel.status_code = tracing::field::Empty,
                    )
                })
                .on_request(|_req: &Request<Body>, _span: &Span| {})
                .on_response(
                    |res: &Response<Incoming>, _latency: Duration, span: &Span| {
                        let status = res.status();
                        span.record("http.status_code", status.as_u16());
                        if status.is_client_error() || status.is_server_error() {
                            span.record("otel.status_code", "ERROR");
                        }
                    },
                )
                .on_body_chunk(())
                .on_eos(|_: Option<&HeaderMap>, _duration: Duration, _span: &Span| {})
                .on_failure(
                    |class: ServerErrorsFailureClass, _latency: Duration, span: &Span| {
                        span.record("otel.status_code", "ERROR");
                        if let ServerErrorsFailureClass::StatusCode(status) = class {
                            span.record("http.status_code", status.as_u16());
                        }
                    },
                ),
        )
        .map_err(BoxError::from)
        .service(client);

    Ok(ClientBuilder::new(
        service
            .map_response_body(|body| {
                Box::new(http_body_util::BodyExt::map_err(body, BoxError::from)) as Box<DynBody>
            })
            .boxed(),
        default_ns,
    )
    .build())
}

/// [`kube_client`] for the ambient configuration (in-cluster, then
/// `KUBECONFIG`), as `kube::Client::try_default()` infers it.
#[cfg(feature = "kubernetes-identity")]
pub async fn kube_client_default() -> kube::Result<kube::Client> {
    kube_client(
        kube::Config::infer()
            .await
            .map_err(kube::Error::InferConfig)?,
    )
}

/// Run `fut` in a task with no current span and await it. For a client
/// with no executor hook (the Temporal SDK's tonic channel): a connection it
/// opens or reopens inside `fut` then holds no caller span. The caller keeps
/// its own span around the await, and anything that must join its trace
/// carries the context explicitly ([`crate::obs::TraceContext`]).
pub async fn detached<F>(fut: F) -> F::Output
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    match tokio::spawn(fut).await {
        Ok(output) => output,
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => panic!("detached task cancelled: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::layer::SubscriberExt as _;

    /// Records which spans have closed.
    #[derive(Clone, Default)]
    struct Closed(Arc<Mutex<Vec<String>>>);

    impl<S> tracing_subscriber::Layer<S> for Closed
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_close(&self, id: tracing::span::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
            if let Some(span) = ctx.span(&id) {
                self.0.lock().unwrap().push(span.name().to_string());
            }
        }
    }

    /// Spawns a long-lived task inside `request` through `executor`, ends
    /// the request, and says whether `request` closed while the task lives.
    async fn request_closes_while_task_lives<E>(executor: E) -> bool
    where
        E: hyper::rt::Executor<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>>,
    {
        let closed = Closed::default();
        let subscriber = tracing_subscriber::registry().with(closed.clone());
        let _default = tracing::subscriber::set_default(subscriber);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        {
            let request = tracing::info_span!("request");
            let _entered = request.enter();
            // A connection driver: lives until its connection closes.
            executor.execute(Box::pin(async move {
                let _ = stopped.await;
            }));
        }
        tokio::task::yield_now().await;
        let closed_early = closed
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|name| name == "request");
        let _ = stop.send(());
        closed_early
    }

    #[tokio::test]
    async fn hyper_utils_executor_holds_the_request_span() {
        assert!(!request_closes_while_task_lives(hyper_util::rt::TokioExecutor::new()).await);
    }

    #[tokio::test]
    async fn the_detached_executor_never_holds_the_request_span() {
        assert!(request_closes_while_task_lives(super::DetachedExecutor).await);
    }

    /// A connection spawned through hyper-util's executor inside
    /// [`super::detached`] does not hold the caller's span.
    #[tokio::test]
    async fn a_connection_opened_inside_detached_work_never_holds_the_caller_span() {
        use tracing::Instrument as _;

        let closed = Closed::default();
        let subscriber = tracing_subscriber::registry().with(closed.clone());
        let _default = tracing::subscriber::set_default(subscriber);
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        async move {
            super::detached(async move {
                hyper::rt::Executor::execute(&hyper_util::rt::TokioExecutor::new(), async move {
                    let _ = stopped.await;
                });
            })
            .await;
        }
        .instrument(tracing::info_span!("request"))
        .await;
        tokio::task::yield_now().await;
        let closed_early = closed
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|name| name == "request");
        let _ = stop.send(());
        assert!(closed_early);
    }

    /// One Kubernetes API request through `client`, against a server that
    /// keeps the connection open, made inside a `request` span. Says whether
    /// `request` has closed once the response is read and the span dropped.
    #[cfg(feature = "kubernetes-identity")]
    async fn kube_request_span_closes(build: fn(kube::Config) -> kube::Client) -> bool {
        use tracing::Instrument as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(|_| async {
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(
                            http_body_util::Full::new(hyper::body::Bytes::from_static(b"{}")),
                        ))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        let closed = Closed::default();
        let subscriber = tracing_subscriber::registry().with(closed.clone());
        let _default = tracing::subscriber::set_default(subscriber);
        let client = build(kube::Config::new(
            format!("http://{address}").parse().unwrap(),
        ));
        async {
            let request = http::Request::get("/version").body(Vec::new()).unwrap();
            client.request_text(request).await.unwrap();
        }
        .instrument(tracing::info_span!("request"))
        .await;
        tokio::task::yield_now().await;
        closed
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|name| name == "request")
    }

    #[cfg(feature = "kubernetes-identity")]
    #[tokio::test]
    async fn kubes_own_client_holds_the_request_span_while_connected() {
        assert!(!kube_request_span_closes(|config| kube::Client::try_from(config).unwrap()).await);
    }

    #[cfg(feature = "kubernetes-identity")]
    #[tokio::test]
    async fn the_span_free_kube_client_releases_the_request_span() {
        assert!(kube_request_span_closes(|config| super::kube_client(config).unwrap()).await);
    }
}
