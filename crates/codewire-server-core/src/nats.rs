//! NATS client helper.
//!
//! Wraps `async_nats::connect` with retry-aware defaults. Returns `None`
//! when `nats_url` is unset, so services that don't need NATS just skip
//! initialization. If `NATS_TOKEN` is configured, the token is passed through
//! to the server.
//!
//! [`kv_bucket`] opens a service's JetStream KV bucket with its full
//! configuration, replicas included, so a bucket follows `NATS_KV_REPLICAS`
//! on every start (#3542).

use async_nats::ConnectOptions;
use async_nats::jetstream::{self, kv};

/// Replicas of every KV bucket when `NATS_KV_REPLICAS` is unset: one, for
/// Dev, Kind and CI, which run a single NATS server.
pub const DEFAULT_KV_REPLICAS: usize = 1;

/// Connects to NATS at `url`, returning `Ok(None)` if `url` is `None`.
pub async fn connect(
    url: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<Option<async_nats::Client>> {
    connect_with_login(url, None, token).await
}

/// Connects as this service's own NATS user when `login` (user, password)
/// is set, otherwise with the shared `token`. A service carries both while
/// NATS moves from the one shared token to per-service users (#3542): its
/// own user wins once it has one.
pub async fn connect_with_login(
    url: Option<&str>,
    login: Option<(&str, &str)>,
    token: Option<&str>,
) -> anyhow::Result<Option<async_nats::Client>> {
    let Some(url) = url else {
        return Ok(None);
    };
    let mut options = ConnectOptions::new().connection_timeout(std::time::Duration::from_secs(5));
    if let Some((user, password)) = login {
        options = options.user_and_password(user.to_string(), password.to_string());
    } else if let Some(token) = token {
        options = options.token(token.to_string());
    }
    let client = options.connect(url).await?;
    Ok(Some(client))
}

/// `NATS_KV_REPLICAS`: 1, 3 or 5. JetStream replicates a stream to at most
/// five servers, and an even count adds a server without adding a failure
/// it survives.
pub fn parse_kv_replicas(raw: &str) -> anyhow::Result<usize> {
    let replicas: usize = raw.trim().parse()?;
    anyhow::ensure!(
        matches!(replicas, 1 | 3 | 5),
        "must be 1, 3 or 5, not {replicas}"
    );
    Ok(replicas)
}

/// Opens the KV bucket `config` describes, creating it, or updating it in
/// place when it exists. An existing bucket so takes this start's replicas:
/// NATS adds the new replicas and catches them up, and an unchanged config
/// changes nothing.
///
/// When the update is refused but the bucket can be opened, the bucket is
/// used as it is, with a warning: a replica change never takes the service
/// down. When another replica is creating the same bucket at once, the open
/// after the refusal finds it.
pub async fn kv_bucket(js: &jetstream::Context, config: kv::Config) -> anyhow::Result<kv::Store> {
    let bucket = config.bucket.clone();
    let replicas = config.num_replicas;
    match js.create_or_update_key_value(config).await {
        Ok(store) => Ok(store),
        Err(update_err) => match js.get_key_value(&bucket).await {
            Ok(store) => {
                tracing::warn!(
                    bucket,
                    replicas,
                    error = %update_err,
                    "NATS KV bucket kept its current configuration"
                );
                Ok(store)
            }
            Err(get_err) => Err(anyhow::anyhow!(
                "set up NATS KV bucket {bucket} failed: update={update_err}; get={get_err}"
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_replicas_are_one_three_or_five() {
        assert_eq!(parse_kv_replicas("1").unwrap(), 1);
        assert_eq!(parse_kv_replicas(" 3 ").unwrap(), 3);
        assert_eq!(parse_kv_replicas("5").unwrap(), 5);
        for raw in ["0", "2", "4", "6", "-1", "three", ""] {
            assert!(parse_kv_replicas(raw).is_err(), "{raw:?}");
        }
    }

    /// Production's buckets were created at R1 (#3542). Opened at R3, the same
    /// bucket gains its replicas in place and keeps its keys.
    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream cluster of three or more servers"]
    async fn a_bucket_created_at_one_replica_moves_to_three_in_place() {
        let nats_url = std::env::var("NATS_URL").expect("set NATS_URL to a JetStream cluster");
        let js = jetstream::new(async_nats::connect(nats_url).await.unwrap());
        let config = |replicas| kv::Config {
            bucket: format!("kv-replicas-{}", uuid::Uuid::new_v4().simple()),
            description: "kv_bucket test".into(),
            max_age: std::time::Duration::from_secs(60),
            num_replicas: replicas,
            ..Default::default()
        };
        let mut old = config(1);
        // How the coordinator created it before: no replica count.
        old.num_replicas = 0;
        let bucket = old.bucket.clone();
        let store = js.create_key_value(old).await.unwrap();
        store.put("kept", "value".into()).await.unwrap();

        let mut moved = config(3);
        moved.bucket = bucket.clone();
        let store = kv_bucket(&js, moved.clone()).await.unwrap();
        let mut stream = js.get_stream(format!("KV_{bucket}")).await.unwrap();
        let info = stream.info().await.unwrap();
        assert_eq!(info.config.num_replicas, 3);
        assert_eq!(
            store.get("kept").await.unwrap().as_deref(),
            Some(&b"value"[..])
        );

        // Every start opens it again with the same config: nothing changes.
        kv_bucket(&js, moved).await.unwrap();
        let info = stream.info().await.unwrap();
        assert_eq!(info.config.num_replicas, 3);
        let cluster = info.cluster.as_ref().expect("a clustered stream");
        assert_eq!(cluster.replicas.len(), 2, "a leader and two followers");

        js.delete_key_value(&bucket).await.unwrap();
    }
}
