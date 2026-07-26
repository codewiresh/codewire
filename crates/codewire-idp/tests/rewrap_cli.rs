use std::process::Command;

use sqlx::PgPool;

#[test]
fn connection_failure_does_not_echo_operator_inputs() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let keyring_dir = std::env::temp_dir().join(format!(
        "codewire-idp-rewrap-cli-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&keyring_dir).unwrap();
    let encoded_kek = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
    std::fs::write(keyring_dir.join("v2"), encoded_kek).unwrap();

    let database_url = "postgres://wi9a-user:wi9a-password@127.0.0.1:1/wi9a-database";
    let output = Command::new(env!("CARGO_BIN_EXE_codewire-idp"))
        .arg("rewrap-signing-keks")
        .env("DATABASE_URL", database_url)
        .env("IDP_SIGNING_KEK_DIR", &keyring_dir)
        .env("IDP_SIGNING_ACTIVE_KEK_ID", "v2")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("jwk-rewrap failure_class=database-unavailable"));
    for forbidden in [
        database_url,
        "wi9a-user",
        "wi9a-password",
        "wi9a-database",
        encoded_kek,
        keyring_dir.to_str().unwrap(),
    ] {
        assert!(
            !stderr.contains(forbidden),
            "operator output leaked {forbidden}"
        );
    }

    std::fs::remove_dir_all(keyring_dir).unwrap();
}

#[tokio::test]
async fn command_rewraps_once_and_then_reports_idempotence() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping signing KEK rewrap CLI DB test");
        return;
    };
    let admin = PgPool::connect(&url).await.unwrap();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let db_name = format!("cw_idp_rewrap_cli_{}_{nanos}", std::process::id());
    sqlx::query(&format!(r#"CREATE DATABASE "{db_name}""#))
        .execute(&admin)
        .await
        .unwrap();
    let mut test_url = url::Url::parse(&url).unwrap();
    test_url.set_path(&db_name);
    let db_host = test_url.host_str().unwrap().to_owned();
    let db_port = test_url.port_or_known_default().unwrap().to_string();
    let db_user = test_url.username().to_owned();
    let db_password = test_url.password().unwrap().to_owned();
    let db_sslmode = test_url
        .query_pairs()
        .find_map(|(key, value)| (key == "sslmode").then(|| value.into_owned()))
        .unwrap_or_else(|| "prefer".to_owned());

    let keyring_dir = std::env::temp_dir().join(format!(
        "codewire-idp-rewrap-cli-db-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&keyring_dir).unwrap();
    std::fs::write(
        keyring_dir.join("v1"),
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
    )
    .unwrap();
    std::fs::write(
        keyring_dir.join("v2"),
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    )
    .unwrap();

    let result = async {
        codewire_server_core::migrate::ensure_schema(test_url.as_str()).await?;
        let pool = PgPool::connect(test_url.as_str()).await?;
        let v1_keyring = codewire_idp::SigningKekKeyring::load(&keyring_dir, "v1")?;
        let seed = [61u8; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        let public_json = codewire_idp::jwk::encode_public_key("codewire-cli-rewrap", &public)?;
        let envelope = v1_keyring.encrypt("codewire-cli-rewrap", &public, &seed)?;
        sqlx::query(
            "INSERT INTO jwks \
                (id, public_key, private_key_ciphertext, private_key_nonce, \
                 private_key_kek_id, private_key_format, created_at) \
             VALUES ('codewire-cli-rewrap', $1, $2, $3, $4, $5, NOW())",
        )
        .bind(&public_json)
        .bind(&envelope.ciphertext)
        .bind(&envelope.nonce)
        .bind(&envelope.kek_id)
        .bind(envelope.format)
        .execute(&pool)
        .await?;

        let run_direct = || {
            Command::new(env!("CARGO_BIN_EXE_codewire-idp"))
                .arg("rewrap-signing-keks")
                .env("DATABASE_URL", test_url.as_str())
                .env("IDP_SIGNING_KEK_DIR", &keyring_dir)
                .env("IDP_SIGNING_ACTIVE_KEK_ID", "v2")
                .output()
                .unwrap()
        };
        let run_deployed_config = || {
            Command::new(env!("CARGO_BIN_EXE_codewire-idp"))
                .arg("rewrap-signing-keks")
                .env("DATABASE_URL", "")
                .env("ENVIRONMENT", "development")
                .env("DB_HOST", &db_host)
                .env("DB_PORT", &db_port)
                .env("DB_USER", &db_user)
                .env("DB_PASSWORD", &db_password)
                .env("DB_NAME", &db_name)
                .env("DB_SSLMODE", &db_sslmode)
                .env("IDP_SIGNING_KEK_DIR", &keyring_dir)
                .env("IDP_SIGNING_ACTIVE_KEK_ID", "v2")
                .output()
                .unwrap()
        };
        let first = run_direct();
        anyhow::ensure!(first.status.success());
        anyhow::ensure!(first.stderr.is_empty());
        anyhow::ensure!(
            String::from_utf8(first.stdout)?
                == "jwk-rewrap active_kek_id=v2 total=1 signing=1 rewrapped=1 already_active=0 public_only=0\n"
        );
        let persisted_kek: String = sqlx::query_scalar(
            "SELECT private_key_kek_id FROM jwks WHERE id = 'codewire-cli-rewrap'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(persisted_kek == "v2");

        let second = run_deployed_config();
        anyhow::ensure!(second.status.success());
        anyhow::ensure!(second.stderr.is_empty());
        anyhow::ensure!(
            String::from_utf8(second.stdout)?
                == "jwk-rewrap active_kek_id=v2 total=1 signing=1 rewrapped=0 already_active=1 public_only=0\n"
        );

        pool.close().await;
        anyhow::Ok(())
    }
    .await;

    let _ = sqlx::query(&format!(
        r#"DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)"#
    ))
    .execute(&admin)
    .await;
    std::fs::remove_dir_all(keyring_dir).unwrap();
    result.unwrap();
}
