//! Preview browser capabilities: constraints, indexes, helpers and cascades.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

async fn seed(pool: &PgPool) -> anyhow::Result<()> {
    seed_platform_credential_owners(pool).await?;
    seed_platform_credential(
        pool,
        "preview-retained",
        Some("credential-user-a"),
        None,
        "Retained",
    )
    .await?;
    seed_platform_credential_material(pool, "preview-retained", 1).await?;
    seed_test_tenant_secret_dek(pool, "preview-dek", "user", "credential-user-a").await?;
    sqlx::raw_sql("INSERT INTO tenant_secrets(path,key,dek_id,scope,scope_id,ciphertext,nonce,format,storage_contract_version) \
        VALUES('/users/credential-user-a','PREVIEW_RETAINED','preview-dek','user','credential-user-a',decode(repeat('01',32),'hex'),decode(repeat('02',12),'hex'),1,1); \
        INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES('preview-session','credential-user-a',repeat('a',64),NOW()+interval '1 hour'); \
        INSERT INTO environment_presets(id,org_id,name,slug,project_spec) VALUES('preview-preset','credential-org-a','Preview','preview','{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
        INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,environment_operation_generation,project_spec) \
        VALUES('preview-env','credential-org-a','credential-user-a','sandbox','preview-preset','running','started',1,'{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
        INSERT INTO environment_ports(id,environment_id,port,label,access) VALUES('preview-port','preview-env',3000,'app','creator');")
        .execute(pool).await?;
    Ok(())
}

async fn seed_capabilities(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql("INSERT INTO preview_auth_challenges(id,nonce_hash,client_hash,organization_id,environment_id,port_id,host,return_path,created_at,expires_at,session_id,code_hash,code_expires_at,consumed_at) \
        VALUES('preview-challenge',repeat('b',64),repeat('c',64),'credential-org-a','preview-env','preview-port','app.example.test','/nested?q=1',NOW(),NOW()+interval '5 minutes','preview-session',repeat('d',64),NOW()+interval '1 minute',NOW()); \
        INSERT INTO preview_browser_grants(token_hash,session_id,organization_id,environment_id,port_id,host) \
        VALUES(repeat('e',64),'preview-session','credential-org-a','preview-env','preview-port','app.example.test');")
        .execute(pool).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn preview_fresh_schema_constrains_digests_lifetimes_bindings_and_indexes()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        seed(&pool).await?;
        seed_capabilities(&pool).await?;
        let measured = fingerprint(&pool).await?;
        anyhow::ensure!(measured == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT, "preview31 measured fingerprint: {measured}");
        // Each failure uses a separate transaction: one rejected statement must
        // not hide another assertion behind PostgreSQL's aborted-transaction state.
        for (table, assignment, code) in [
            ("preview_auth_challenges", "nonce_hash='raw-capability'", "23514"),
            ("preview_auth_challenges", "client_hash=repeat('A',64)", "23514"),
            ("preview_auth_challenges", "code_hash=repeat('d',63)", "23514"),
            ("preview_auth_challenges", "host=''", "23514"),
            ("preview_auth_challenges", "host=repeat('h',254)", "23514"),
            ("preview_auth_challenges", "return_path='https://elsewhere.test/'", "23514"),
            ("preview_auth_challenges", "return_path='/'||repeat('x',4096)", "23514"),
            ("preview_auth_challenges", "expires_at=created_at", "23514"),
            ("preview_auth_challenges", "expires_at=created_at+interval '5 minutes 1 second'", "23514"),
            ("preview_auth_challenges", "session_id=NULL", "23514"),
            ("preview_auth_challenges", "code_hash=NULL", "23514"),
            ("preview_auth_challenges", "code_expires_at=NULL", "23514"),
            ("preview_auth_challenges", "code_expires_at=expires_at+interval '1 second'", "23514"),
            ("preview_auth_challenges", "consumed_at=expires_at+interval '1 second'", "23514"),
            ("preview_auth_challenges", "session_id=NULL,code_hash=NULL,code_expires_at=NULL,consumed_at=created_at", "23514"),
            ("preview_auth_challenges", "session_id='missing'", "23503"),
            ("preview_auth_challenges", "organization_id='missing'", "23503"),
            ("preview_auth_challenges", "environment_id='missing'", "23503"),
            ("preview_auth_challenges", "port_id='missing'", "23503"),
            ("preview_browser_grants", "token_hash='raw-token'", "23514"),
            ("preview_browser_grants", "host=''", "23514"),
            ("preview_browser_grants", "host=repeat('h',254)", "23514"),
            ("preview_browser_grants", "session_id='missing'", "23503"),
            ("preview_browser_grants", "organization_id='missing'", "23503"),
            ("preview_browser_grants", "environment_id='missing'", "23503"),
            ("preview_browser_grants", "port_id='missing'", "23503"),
        ] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(&format!("UPDATE {table} SET {assignment}"))
                .execute(&mut *tx).await.expect_err("invalid preview state accepted");
            anyhow::ensure!(error.as_database_error().and_then(|e| e.code()).as_deref() == Some(code), "{table}/{assignment}: {error}");
            tx.rollback().await?;
        }
        let duplicate = sqlx::query("INSERT INTO preview_auth_challenges SELECT 'duplicate',nonce_hash,client_hash,organization_id,environment_id,port_id,host,return_path,created_at,expires_at,session_id,code_hash,code_expires_at,consumed_at FROM preview_auth_challenges")
            .execute(&pool).await.expect_err("duplicate code digest accepted");
        anyhow::ensure!(duplicate.as_database_error().and_then(|e| e.code()).as_deref() == Some("23505"));
        let duplicate_scope = sqlx::query("INSERT INTO preview_browser_grants(token_hash,session_id,organization_id,environment_id,port_id,host) SELECT repeat('f',64),session_id,organization_id,environment_id,port_id,host FROM preview_browser_grants")
            .execute(&pool).await.expect_err("duplicate preview scope accepted");
        anyhow::ensure!(duplicate_scope.as_database_error().and_then(|e| e.code()).as_deref() == Some("23505"));
        let replay = sqlx::query("INSERT INTO preview_auth_challenges SELECT id,nonce_hash,client_hash,organization_id,environment_id,port_id,host,return_path,created_at,expires_at,session_id,repeat('f',64),code_expires_at,NULL FROM preview_auth_challenges")
            .execute(&pool).await.expect_err("consumed challenge ID reused");
        anyhow::ensure!(replay.as_database_error().and_then(|e| e.code()).as_deref() == Some("23505"));
        // SQL permits the complete unbound tuple, not partial authorization or
        // an unbound consumed tombstone. The app allocates only after confirmation.
        sqlx::query("UPDATE preview_auth_challenges SET session_id=NULL,code_hash=NULL,code_expires_at=NULL,consumed_at=NULL").execute(&pool).await?;
        let indexes: Vec<String> = sqlx::query_scalar("SELECT indexname FROM pg_indexes WHERE schemaname='public' AND tablename IN ('preview_auth_challenges','preview_browser_grants') ORDER BY indexname")
            .fetch_all(&pool).await?;
        let mut expected = vec!["preview_auth_challenges_pkey", "preview_auth_challenges_code_hash_key", "preview_browser_grants_pkey", "preview_browser_grants_scope_key"];
        expected.extend(["preview_auth_challenges_client", "preview_auth_challenges_expiry", "preview_auth_challenges_session", "preview_auth_challenges_organization", "preview_auth_challenges_environment", "preview_auth_challenges_port", "preview_browser_grants_session", "preview_browser_grants_organization", "preview_browser_grants_environment", "preview_browser_grants_port"]);
        expected.sort_unstable();
        anyhow::ensure!(indexes == expected);
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn preview_capabilities_cascade_on_session_port_environment_and_owner_removal()
-> anyhow::Result<()> {
    for deletion in [
        "DELETE FROM sessions WHERE id='preview-session'",
        "DELETE FROM environment_ports WHERE id='preview-port'",
        "DELETE FROM environments WHERE id='preview-env'",
        "DELETE FROM organizations WHERE id='credential-org-b'",
        "UPDATE users SET enabled=false WHERE id='credential-user-a'",
    ] {
        let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
        let result = async {
            ensure_schema(&db.url).await?;
            let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
            seed(&pool).await?;
            seed_capabilities(&pool).await?;
            if deletion.contains("organizations") {
                // Isolate the direct organization cascade: environment deletion
                // would otherwise remove both rows first, while its existing
                // organization FK itself intentionally restricts deletion.
                // Cross-resource ownership is separately enforced by the app.
                sqlx::raw_sql("UPDATE preview_auth_challenges SET organization_id='credential-org-b'; UPDATE preview_browser_grants SET organization_id='credential-org-b';")
                    .execute(&pool).await?;
            }
            sqlx::query(deletion).execute(&pool).await?;
            anyhow::ensure!(sqlx::query_scalar::<_, bool>("SELECT NOT EXISTS(SELECT 1 FROM preview_auth_challenges) AND NOT EXISTS(SELECT 1 FROM preview_browser_grants)").fetch_one(&pool).await?, "capability survives {deletion}");
            pool.close().await;
            Ok(())
        }.await;
        result.and(db.drop().await)?;
    }
    Ok(())
}
