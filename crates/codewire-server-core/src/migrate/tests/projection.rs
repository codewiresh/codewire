//! Function-only 23 -> 24 proof. Table fingerprints do not prove SQL authority;
//! check both complete installed function bodies and their owner/search path/ACL.

use super::*;

const VERSION: i64 = 24;
// SHA384 measured directly from accepted canonical 10233aee34b2498863aba0f8bad9d85a7c36b654,
// not from the proposed branch. Prior 1..22 retain their independent pins.
const ACCEPTED_23: &str = "28ba96ad9bf9e8b914f2a524613081636f3e3cc0d6b36545f8fd3c621f8f3a521515fb6d8d6feef253841d0f5be11ec2";
const SQL: &str = include_str!("../../../migrations/0024_platform_environment_projection.sql");

pub(super) fn assert_accepted_prior23() -> anyhow::Result<()> {
    let migration = MIGRATOR
        .iter()
        .find(|m| m.version == 23)
        .context("accepted migration23 missing")?;
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(migration.sql.as_bytes())) == ACCEPTED_23,
        "migration23 differs from accepted canonical10233aee3"
    );
    Ok(())
}

#[test]
fn platform_projection_prior_history_retains_accepted_release() -> anyhow::Result<()> {
    assert_applied_broker_lock_history()?;
    let migration = MIGRATOR
        .iter()
        .find(|m| m.version == 22)
        .context("accepted migration22 missing")?;
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(migration.sql.as_bytes()))
            == FROZEN_BINDING_CONSENT_CHECKSUM
    );
    assert_accepted_prior23()
}

pub(super) async fn definitions(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,String,String,bool,String,String)> = sqlx::query_as(
        "SELECT p.proname::text,pg_catalog.oidvectortypes(p.proargtypes),pg_catalog.pg_get_function_result(p.oid), \
         p.prosecdef AND NOT p.proleakproof AND NOT p.proisstrict AND p.prokind='f' \
         AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[] \
         AND ((p.proname='codewire_platform_projection_metadata' AND p.provolatile='s' AND p.proparallel='s' AND l.lanname='sql') \
           OR (p.proname='codewire_platform_lock_projection_authority' AND p.provolatile='v' AND p.proparallel='u' AND l.lanname='plpgsql')) \
         AND p.proowner=(SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid='public._sqlx_migrations'::regclass) \
         AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner), \
         p.prosrc,pg_catalog.pg_get_functiondef(p.oid) \
         FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace \
         JOIN pg_catalog.pg_language l ON l.oid=p.prolang \
         WHERE n.nspname='public' AND p.proname IN('codewire_platform_projection_metadata','codewire_platform_lock_projection_authority') \
         ORDER BY p.proname,p.oid",
    ).fetch_all(pool).await?;
    anyhow::ensure!(rows.len() == 2, "projection helper inventory changed");
    let bodies: Vec<_> = SQL
        .split("\nAS $$\n")
        .skip(1)
        .map(|part| part.split("\n$$;").next().unwrap())
        .collect();
    anyhow::ensure!(bodies.len() == 2);
    let normalize = |sql: &str| {
        sql.lines()
            .map(|line| line.split_once("--").map_or(line, |(sql, _)| sql))
            .flat_map(str::split_whitespace)
            .collect::<Vec<_>>()
            .join(" ")
    };
    for (index, (name, args, result, private, body, _)) in rows.iter().enumerate() {
        anyhow::ensure!(*private, "projection helper owner/search-path/ACL changed");
        if index == 0 {
            anyhow::ensure!(
                name == "codewire_platform_lock_projection_authority"
                    && args == "text, text, text, text"
                    && result == "boolean"
            );
            anyhow::ensure!(
                normalize(body) == normalize(bodies[1]),
                "projection lock definition changed"
            );
        } else {
            anyhow::ensure!(name == "codewire_platform_projection_metadata" && args == "text");
            anyhow::ensure!(
                result
                    == "TABLE(organization_selected boolean, user_placement text, project_reference text, credential_reference text, ordinary_keys text[], selection_valid boolean)"
            );
            anyhow::ensure!(
                normalize(body) == normalize(bodies[0]),
                "projection metadata definition changed"
            );
        }
    }
    Ok(rows.into_iter().map(|row| row.5).collect())
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn platform_projection_upgrade_retains_accepted_history_envelopes_and_noop()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result=async {
        apply_migrations_before(&db.url,VERSION).await?;
        let pool=PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before=applied_migrations(&pool).await?;
        anyhow::ensure!(before.len()==23 && before[22].0==23);
        seed_platform_credential_owners(&pool).await?;
        seed_platform_credential(&pool,"projection-retained",Some("credential-user-a"),None,"Work").await?;
        seed_platform_credential_material(&pool,"projection-retained",1).await?;
        seed_test_tenant_secret_dek(&pool,"retained-dek","user","credential-user-a").await?;
        sqlx::query("INSERT INTO tenant_secrets(path,key,dek_id,scope,scope_id,ciphertext,nonce,format,storage_contract_version) \
            VALUES('/users/credential-user-a','APP_VALUE','retained-dek','user','credential-user-a',decode(repeat('01',32),'hex'),decode(repeat('02',12),'hex'),1,1)")
            .execute(&pool).await?;
        let rows_sql="SELECT row_to_json(s)::text,row_to_json(d)::text,(to_jsonb(c) - 'ssh_public_key' - 'ssh_fingerprint')::text,row_to_json(m)::text FROM tenant_secrets s \
            JOIN tenant_secret_deks d ON d.dek_id=s.dek_id CROSS JOIN platform_credentials c \
            JOIN platform_credential_material m ON m.credential_id=c.id WHERE c.id='projection-retained'";
        let rows_before:(String,String,String,String)=sqlx::query_as(rows_sql).fetch_one(&pool).await?;
        let old=assert_platform_broker_lock_authority(&pool,true).await?;
        let old_oauth=assert_oauth_publication_authority(&pool).await?;
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool=PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let after=applied_migrations(&pool).await?;
        anyhow::ensure!(after.len()==MIGRATOR.iter().count() && after[..23]==before && after[23].0==24);
        let fingerprint:String=sqlx::query_scalar(include_str!("../../../tests/data/application_schema_fingerprint.sql")).fetch_one(&pool).await?;
        anyhow::ensure!(fingerprint==ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT,"current application schema changed: {fingerprint}");
        anyhow::ensure!(sqlx::query_as::<_,(String,String,String,String)>(rows_sql).fetch_one(&pool).await?==rows_before);
        anyhow::ensure!(assert_platform_broker_lock_authority(&pool,true).await?==old);
        anyhow::ensure!(assert_oauth_publication_authority(&pool).await?==old_oauth);
        let installed=definitions(&pool).await?;
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool=PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await?==after);
        anyhow::ensure!(definitions(&pool).await?==installed);
        anyhow::ensure!(sqlx::query_as::<_,(String,String,String,String)>(rows_sql).fetch_one(&pool).await?==rows_before);
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn platform_projection_failed_migration_rolls_back_ddl_and_ledger() -> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result=async {
        apply_migrations_before(&db.url,VERSION).await?;
        let pool=PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before=applied_migrations(&pool).await?;
        sqlx::raw_sql("CREATE FUNCTION public.codewire_platform_lock_projection_authority(text,text,text,text) RETURNS boolean LANGUAGE sql AS 'SELECT false'")
            .execute(&pool).await?;
        pool.close().await;
        anyhow::ensure!(ensure_schema(&db.url).await.is_err());
        let pool=PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await?==before);
        let rolled_back:bool=sqlx::query_scalar("SELECT to_regprocedure('public.codewire_platform_projection_metadata(text)') IS NULL")
            .fetch_one(&pool).await?;
        anyhow::ensure!(rolled_back,"failed transaction left its first helper installed");
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn platform_projection_rollback_recreates_only_disposable_application_schema()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result=async {
        ensure_schema(&db.url).await?;
        let pool=PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        definitions(&pool).await?;
        sqlx::raw_sql("CREATE SCHEMA rollback_boundary; CREATE TABLE rollback_boundary.keep(id integer); INSERT INTO rollback_boundary.keep VALUES(1);")
            .execute(&pool).await?;
        sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public;").execute(&pool).await?;
        pool.close().await;
        apply_migrations_before(&db.url,VERSION).await?;
        let pool=PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let ledger=applied_migrations(&pool).await?;
        anyhow::ensure!(ledger.len()==23 && ledger[22].0==23);
        let absent:bool=sqlx::query_scalar("SELECT to_regprocedure('public.codewire_platform_projection_metadata(text)') IS NULL \
            AND to_regprocedure('public.codewire_platform_lock_projection_authority(text,text,text,text)') IS NULL")
            .fetch_one(&pool).await?;
        anyhow::ensure!(absent);
        anyhow::ensure!(sqlx::query_scalar::<_,i32>("SELECT id FROM rollback_boundary.keep").fetch_one(&pool).await?==1);
        let fingerprint:String=sqlx::query_scalar(include_str!("../../../tests/data/application_schema_fingerprint.sql")).fetch_one(&pool).await?;
        anyhow::ensure!(fingerprint==ACCEPTED_PRE_SSH_SCHEMA_FINGERPRINT);
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}
