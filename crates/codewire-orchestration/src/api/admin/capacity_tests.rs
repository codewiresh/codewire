use axum::Router;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;

use super::*;

const GIB: i64 = 1024 * 1024 * 1024;

fn reservation(cpu_millis: i128, memory_gib: f64) -> Reservation {
    Reservation {
        cpu_millis,
        memory_bytes: (memory_gib * GIB as f64) as i128,
    }
}

fn reserved(cpu_millicores: i64, memory_gib: f64, pods: i64) -> NodeReserved {
    NodeReserved {
        cpu_millicores,
        memory_bytes: (memory_gib * GIB as f64) as i64,
        pods,
        unix_seconds: 1,
    }
}

/// The figures measured on Production (#3583), so this arithmetic stays the one
/// that matched the scheduler there.
#[test]
fn fit_matches_the_counts_measured_on_production() {
    let gib = |value: f64| (value * GIB as f64) as i64;
    let synlinq = (127_950, gib(500.9), 110);
    let tsw = (63_950, gib(994.8), 110);
    let synlinq_now = reserved(9_150, 29.1, 13);
    let tsw_now = reserved(150, 0.6, 3);
    for (each, on_synlinq, on_tsw, limit) in [
        // 1:1 at 130 MiB, as measured: default, xlarge, then the memory shape.
        (reservation(2_750, 9.127), 43, 23, "cpu"),
        (reservation(8_750, 33.127), 13, 7, "cpu"),
    ] {
        let fit = shape_fit("shape", synlinq, Some(synlinq_now), true, Some(each));
        assert_eq!(fit.more, Some(on_synlinq));
        assert_eq!(fit.limit, limit);
        let fit = shape_fit("shape", tsw, Some(tsw_now), true, Some(each));
        assert_eq!(fit.more, Some(on_tsw));
        assert_eq!(fit.limit, limit);
    }
    let memory_shape = reservation(1_750, 33.127);
    let fit = shape_fit("memory", tsw, Some(tsw_now), true, Some(memory_shape));
    assert_eq!((fit.more, fit.limit), (Some(30), "memory"));
    // 2:1 at 1 GiB, as predicted on #3635: tsw still runs out of CPU first.
    let shared = reservation(1_750, 10.0);
    let fit = shape_fit("default", tsw, Some(tsw_now), true, Some(shared));
    assert_eq!((fit.more, fit.limit), (Some(36), "cpu"));
}

#[test]
fn an_unknown_reservation_never_counts_as_room() {
    let node = (64_000, 100 * GIB, 110);
    let each = Some(reservation(1_000, 1.0));
    let fit = shape_fit("small", node, None, true, each);
    assert_eq!((fit.more, fit.limit), (None, ""));
    let fit = shape_fit("small", node, Some(reserved(0, 0.0, 0)), true, None);
    assert_eq!((fit.more, fit.limit), (None, ""));
    // A broken render must not divide by zero into a huge count.
    let fit = shape_fit(
        "small",
        node,
        Some(reserved(0, 0.0, 0)),
        true,
        Some(reservation(0, 1.0)),
    );
    assert_eq!(fit.more, None);
}

#[test]
fn a_full_or_unschedulable_node_fits_none() {
    let node = (4_000, 8 * GIB, 110);
    let each = Some(reservation(1_000, 1.0));
    // Already over its CPU: never negative.
    let fit = shape_fit("small", node, Some(reserved(9_000, 1.0, 3)), true, each);
    assert_eq!((fit.more, fit.limit), (Some(0), "cpu"));
    let fit = shape_fit("small", node, Some(reserved(0, 0.0, 110)), true, each);
    assert_eq!((fit.more, fit.limit), (Some(0), "pods"));
    let fit = shape_fit("small", node, Some(reserved(0, 0.0, 0)), false, each);
    assert_eq!((fit.more, fit.limit), (Some(0), "node"));
}

fn pod(name: &str, node: Option<&str>, phase: &str, idle: bool) -> Pod {
    let labels = if idle {
        json!({MEMBER_POOL_LABEL: "abc"})
    } else {
        json!({})
    };
    serde_json::from_value(json!({
        "metadata": {"name": name, "labels": labels},
        "spec": {"containers": [], "nodeName": node},
        "status": {"phase": phase},
    }))
    .unwrap()
}

#[test]
fn sandboxes_and_idle_members_are_counted_apart() {
    let (by_node, unplaced) = count_sandbox_pods(&[
        pod("a", Some("one"), "Running", false),
        pod("b", Some("one"), "Pending", false),
        pod("c", Some("one"), "Running", true),
        pod("d", Some("two"), "Succeeded", false),
        pod("e", None, "Pending", false),
        pod("f", None, "Pending", true),
    ]);
    assert_eq!(by_node.get("one"), Some(&(2, 1)));
    assert_eq!(by_node.get("two"), None);
    assert_eq!(unplaced, 1);
}

/// A Prometheus on loopback that answers each query from `answer`.
async fn prometheus(
    answer: impl Fn(&str) -> axum::response::Response + Clone + Send + Sync + 'static,
) -> String {
    let service = Router::new().fallback(move |Query(query): Query<HashMap<String, String>>| {
        let answer = answer.clone();
        async move { answer(query.get("query").map(String::as_str).unwrap_or_default()) }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, service).await });
    format!("http://{address}")
}

fn vector(series: &[(&[(&str, &str)], &str)]) -> axum::response::Response {
    let result: Vec<Value> = series
        .iter()
        .map(|(labels, value)| {
            let metric: HashMap<_, _> = labels.iter().copied().collect();
            json!({"metric": metric, "value": [1, value]})
        })
        .collect();
    axum::Json(json!({"status": "success", "data": {"resultType": "vector", "result": result}}))
        .into_response()
}

/// Everything a healthy cluster answers for one node.
fn healthy(query: &str) -> axum::response::Response {
    let node: &[(&str, &str)] = &[("node", "one")];
    let nodename: &[(&str, &str)] = &[("nodename", "one")];
    if query.starts_with("sum by (node, resource)") {
        vector(&[
            (&[("node", "one"), ("resource", "cpu")], "2.5"),
            (&[("node", "one"), ("resource", "memory")], "1073741824"),
            // An unplaced Pod's series, with no node, counts for no node.
            (&[("resource", "cpu")], "9"),
        ])
    } else if query.contains("kube_pod_overhead_cpu_cores") {
        vector(&[(node, "0.25")])
    } else if query.contains("kube_pod_overhead_memory_bytes") {
        vector(&[(node, "1073741824")])
    } else if query.starts_with("count by (node)") {
        vector(&[(node, "13")])
    } else if query.starts_with("max by (node) (timestamp") {
        vector(&[(node, "1700000000")])
    } else if query.contains("node_cpu_seconds_total") {
        vector(&[(nodename, "1.5")])
    } else if query.starts_with("timestamp(node_memory") {
        vector(&[(nodename, "1700000030")])
    } else if query.contains("node_memory_MemAvailable_bytes") {
        vector(&[(nodename, "2147483648")])
    } else {
        panic!("unexpected query {query}")
    }
}

#[tokio::test]
async fn prometheus_gives_each_nodes_numbers_and_their_read_time() {
    let base = prometheus(healthy).await;
    let (reserved, used) =
        read_prometheus(&reqwest::Client::new(), &base, Duration::from_secs(5)).await;
    assert_eq!(
        reserved.get("one"),
        Some(&NodeReserved {
            cpu_millicores: 2_750,
            memory_bytes: 2 * GIB,
            pods: 13,
            unix_seconds: 1_700_000_000,
        })
    );
    assert_eq!(reserved.len(), 1, "an unplaced Pod's series names no node");
    assert_eq!(
        used.get("one"),
        Some(&NodeUsed {
            cpu_millicores: 1_500,
            memory_bytes: 2 * GIB,
            unix_seconds: 1_700_000_030,
        })
    );
}

#[tokio::test]
async fn no_pod_overhead_is_a_real_answer() {
    let base = prometheus(|query| {
        if query.contains("kube_pod_overhead") {
            vector(&[])
        } else {
            healthy(query)
        }
    })
    .await;
    let (reserved, _) =
        read_prometheus(&reqwest::Client::new(), &base, Duration::from_secs(5)).await;
    assert_eq!(reserved["one"].cpu_millicores, 2_500);
    assert_eq!(reserved["one"].memory_bytes, GIB);
}

#[tokio::test]
async fn unset_prometheus_reads_nothing() {
    let (reserved, used) =
        read_prometheus(&reqwest::Client::new(), "", Duration::from_secs(5)).await;
    assert!(reserved.is_empty() && used.is_empty());
}

#[tokio::test]
async fn a_failing_prometheus_leaves_numbers_absent_not_zero() {
    for base in [
        prometheus(|_| StatusCode::SERVICE_UNAVAILABLE.into_response()).await,
        prometheus(|_| "not json".into_response()).await,
        prometheus(|_| {
            axum::Json(json!({"status": "error", "error": "bad query"})).into_response()
        })
        .await,
        prometheus(|_| vector(&[(&[("node", "one"), ("nodename", "one")], "NaN")])).await,
        // Nothing listens here.
        "http://127.0.0.1:9".to_owned(),
    ] {
        let (reserved, used) =
            read_prometheus(&reqwest::Client::new(), &base, Duration::from_secs(5)).await;
        assert!(reserved.is_empty(), "{base}: {reserved:?}");
        assert!(used.is_empty(), "{base}: {used:?}");
    }
}

#[tokio::test]
async fn one_missing_series_leaves_that_node_unknown() {
    let base = prometheus(|query| {
        if query.starts_with("count by (node)") {
            vector(&[])
        } else {
            healthy(query)
        }
    })
    .await;
    let (reserved, used) =
        read_prometheus(&reqwest::Client::new(), &base, Duration::from_secs(5)).await;
    assert!(reserved.is_empty(), "{reserved:?}");
    assert_eq!(used.len(), 1, "usage is its own family");
}

#[tokio::test]
async fn a_slow_prometheus_is_cut_off_at_the_timeout() {
    let service = Router::new().fallback(|| async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        "too late"
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, service).await });
    let started = std::time::Instant::now();
    let (reserved, used) =
        read_prometheus(&reqwest::Client::new(), &base, Duration::from_millis(200)).await;
    assert!(reserved.is_empty() && used.is_empty());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn an_oversized_answer_is_refused() {
    let base = prometheus(|_| "x".repeat(PROMETHEUS_RESPONSE_LIMIT + 1).into_response()).await;
    let (reserved, used) =
        read_prometheus(&reqwest::Client::new(), &base, Duration::from_secs(5)).await;
    assert!(reserved.is_empty() && used.is_empty());
}

#[test]
fn the_setting_is_optional_and_a_bad_form_stops_startup() {
    use crate::worker::create::capacity_prometheus_url;
    assert_eq!(capacity_prometheus_url(None), "");
    assert_eq!(capacity_prometheus_url(Some("  ")), "");
    assert_eq!(
        capacity_prometheus_url(Some("http://prometheus.monitoring.svc:9090/")),
        "http://prometheus.monitoring.svc:9090"
    );
    for bad in [
        "prometheus:9090",
        "ftp://prometheus",
        "http://user:secret@prometheus",
        "http://prometheus?x=1",
    ] {
        let value = bad.to_owned();
        let refused = std::panic::catch_unwind(move || capacity_prometheus_url(Some(&value)));
        assert!(refused.is_err(), "{bad} accepted");
    }
}

fn node(name: &str, cordoned: bool) -> Node {
    serde_json::from_value(json!({
        "metadata": {"name": name},
        "spec": {"unschedulable": cordoned},
        "status": {
            "allocatable": {"cpu": "64", "memory": "100Gi", "pods": "110"},
            "conditions": [{"type": "Ready", "status": "True"}],
        },
    }))
    .unwrap()
}

#[test]
fn the_view_says_what_it_does_not_know() {
    let read = ClusterRead {
        nodes: vec![node("two", false), node("one", true), node("three", false)],
        pods: vec![pod("a", Some("three"), "Running", false)],
        overhead: BTreeMap::new(),
        tolerations: Vec::new(),
    };
    let shapes = [("small", Some(reservation(1_000, 1.0)))];
    let known = BTreeMap::from([
        ("one".to_owned(), reserved(0, 0.0, 0)),
        ("three".to_owned(), reserved(4_000, 10.0, 5)),
    ]);
    let view = assemble(&read, &shapes, &known, &BTreeMap::new(), true);
    let names: Vec<_> = view.nodes.iter().map(|node| node.name.as_str()).collect();
    assert_eq!(names, ["one", "three", "two"], "sorted by name");

    assert!(!view.nodes[0].schedulable);
    assert_eq!(
        view.nodes[0].fits[0].more,
        Some(0),
        "a cordoned node takes none"
    );

    assert_eq!(view.nodes[1].fits[0].more, Some(60));
    assert_eq!(view.nodes[1].sandboxes, 1);
    assert_eq!(
        view.nodes[1].used, None,
        "usage wasn't read: absent, not zero"
    );

    assert_eq!(view.nodes[2].reserved, None);
    assert_eq!(
        view.nodes[2].fits[0].more, None,
        "no reservations: no count"
    );
    assert_eq!(view.nodes[2].allocatable_cpu_millicores, 64_000);
}
