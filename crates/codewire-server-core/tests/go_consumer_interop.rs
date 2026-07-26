//! Bounded generated-Go consumer interoperability against the Rust Connect
//! owner. This is deliberately ignored by ordinary Rust correctness runs and
//! selected only for generated-Go, Go SDK, proto, and release verification.

use std::path::PathBuf;
use std::process::Command;

use codewire_server_core::AppBuilder;
use codewire_server_core::auth::AuthState;
use codewire_server_core::connect_testing;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "selected generated-Go consumer interoperability"]
async fn generated_go_client_consumes_rust_connect() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool");
    let (connect, auth) = connect_testing::router(AuthState { pool });
    let app = AppBuilder::new("codewire-go-consumer-interop")
        .with_connect_routes_auth(connect, auth)
        .into_router();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind generated-Go interop listener");
    let address = listener.local_addr().expect("interop listener address");
    let server = tokio::spawn(codewire_server_core::serve_with_listener(app, listener));

    let module = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../libs/gen-go");
    let base_url = format!("http://{address}");
    let output = tokio::task::spawn_blocking(move || {
        Command::new("go")
            .current_dir(module)
            .env("GOWORK", "off")
            .env("CODEWIRE_GO_INTEROP_BASE_URL", base_url)
            .args([
                "test",
                "./interop",
                "-run",
                "^TestGeneratedClientConsumesRustConnect$",
                "-count=1",
                "-timeout=30s",
                "-v",
            ])
            .output()
    })
    .await
    .expect("join generated-Go interop process")
    .expect("execute generated-Go interop process");

    server.abort();
    let _ = server.await;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "generated-Go interop failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("--- SKIP:"),
        "selected generated-Go interop skipped\nstdout:\n{stdout}"
    );
    for case in ["unary", "canonical_error", "server_stream"] {
        let marker = format!("--- PASS: TestGeneratedClientConsumesRustConnect/{case}");
        assert!(
            stdout.contains(&marker),
            "generated-Go interop omitted {case}\nstdout:\n{stdout}"
        );
    }
    let passed = stdout
        .lines()
        .filter(|line| line.trim_start().starts_with("--- PASS:"))
        .count();
    assert_eq!(
        passed, 4,
        "generated-Go interop must pass exactly one test plus three cases\nstdout:\n{stdout}"
    );
}
