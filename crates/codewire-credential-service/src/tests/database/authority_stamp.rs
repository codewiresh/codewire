//! The authority stamp's catalogue guard. Every relation that runtime
//! credential authority reads must have stamp triggers (migration 35), so a
//! stamp can stand for the decision. The statements are captured at the wire
//! from a real resolve, `evaluate_grants` and the credential record read, and
//! planned with EXPLAIN; nothing here relies on a hand-kept list of queries.

use std::collections::BTreeSet;

use codewire_platform_credentials::PlatformCredentialStore;
use codewire_server_core::authority_stamp::{BILLING_COLUMNS, STAMPED_TABLES};
use sha2::{Digest, Sha256};

use super::*;

/// The SQL-language SECURITY DEFINER helpers runtime authority may call.
/// Their bodies are planned like the statements that call them.
const REVIEWED_SQL: [&str; 4] = [
    "codewire_platform_lock_credential",
    "codewire_platform_lock_environment",
    "codewire_platform_lock_profile",
    "codewire_platform_projection_metadata",
];

/// PL/pgSQL helpers cannot be planned with EXPLAIN. Each is pinned by the
/// SHA-256 of its source and the relations a reviewer read in that source;
/// any change to the source fails here until it is reviewed again.
const PINNED_PLPGSQL: [(&str, &str, &[&str]); 1] = [(
    "codewire_platform_lock_owner",
    "72c281795e0730660adfc6bd442e6e9871a143bba9842278c2c6bc03d58bb7cc",
    &["users", "organizations"],
)];

/// Statements on the path that are not planned: transaction control only.
const UNPLANNED: [&str; 3] = ["BEGIN", "COMMIT", "ROLLBACK"];

#[derive(Default)]
struct Catalogue {
    relations: BTreeSet<String>,
    functions: BTreeSet<String>,
    /// Every relation's own output column list, by relation.
    outputs: Vec<(String, String, Vec<String>)>,
    strings: Vec<String>,
}

impl Catalogue {
    fn walk(&mut self, value: &Value) {
        match value {
            Value::Object(map) => {
                if let (Some(Value::String(schema)), Some(Value::String(relation))) =
                    (map.get("Schema"), map.get("Relation Name"))
                {
                    self.relations.insert(format!("{schema}.{relation}"));
                    let alias = map
                        .get("Alias")
                        .and_then(Value::as_str)
                        .unwrap_or(relation)
                        .to_owned();
                    let output = map
                        .get("Output")
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default();
                    self.outputs.push((relation.clone(), alias, output));
                }
                for value in map.values() {
                    self.walk(value);
                }
            }
            Value::Array(items) => items.iter().for_each(|value| self.walk(value)),
            Value::String(text) => self.strings.push(text.clone()),
            _ => {}
        }
    }
}

/// Whether `text` calls `name`: the name, not the tail of a longer one,
/// directly followed by its argument list.
fn calls(text: &str, name: &str) -> bool {
    let pattern = format!("{name}(");
    text.match_indices(&pattern).any(|(at, _)| {
        text[..at]
            .chars()
            .next_back()
            .is_none_or(|before| !(before.is_ascii_alphanumeric() || before == '_'))
    })
}

/// `source` with its comments removed and every string literal's contents
/// blanked, so a `;` left in the result separates statements.
fn sql_code(source: &str) -> String {
    let mut code = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '-' if chars.peek() == Some(&'-') => {
                for skipped in chars.by_ref() {
                    if skipped == '\n' {
                        code.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut previous = ' ';
                for skipped in chars.by_ref() {
                    if previous == '*' && skipped == '/' {
                        break;
                    }
                    previous = skipped;
                }
                code.push(' ');
            }
            '\'' => {
                // A doubled quote inside a literal ends and reopens it, which
                // keeps the same contents blank.
                code.push('\'');
                for skipped in chars.by_ref() {
                    if skipped == '\'' {
                        break;
                    }
                    code.push(if skipped == ';' { ' ' } else { skipped });
                }
                code.push('\'');
            }
            _ => code.push(character),
        }
    }
    code
}

async fn explain(admin: &sqlx::PgPool, statement: &str) -> Result<Value> {
    let plan: Value = sqlx::raw_sql(&format!(
        "EXPLAIN (GENERIC_PLAN, VERBOSE, FORMAT JSON) {statement}"
    ))
    .fetch_one(admin)
    .await
    .and_then(|row| sqlx::Row::try_get(&row, 0))
    .with_context(|| format!("plan {statement}"))?;
    Ok(plan)
}

/// Every relation and function reachable from `statements`, following the
/// reviewed SQL-language SECURITY DEFINER bodies and pinned PL/pgSQL sources.
/// A call to any function outside `pg_catalog` that is not reviewed here,
/// in any schema, fails closed.
async fn catalogue(admin: &sqlx::PgPool, statements: &[String]) -> Result<Catalogue> {
    let functions: Vec<(String, String, String, bool, String)> = sqlx::query_as(
        "SELECT n.nspname::text, p.proname::text, l.lanname::text, p.prosecdef, p.prosrc \
         FROM pg_catalog.pg_proc p \
         JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace \
         JOIN pg_catalog.pg_language l ON l.oid=p.prolang \
         WHERE n.nspname NOT IN ('pg_catalog','information_schema')",
    )
    .fetch_all(admin)
    .await?;
    let mut found = Catalogue::default();
    let mut pending: Vec<String> = statements.to_vec();
    let mut explained = BTreeSet::new();
    while let Some(statement) = pending.pop() {
        if !explained.insert(statement.clone()) {
            continue;
        }
        let mut plan = Catalogue::default();
        plan.walk(&explain(admin, &statement).await?);
        for (schema, name, language, definer, source) in &functions {
            if !plan.strings.iter().any(|text| calls(text, name))
                || !found.functions.insert(name.clone())
            {
                continue;
            }
            match (schema.as_str(), language.as_str(), *definer) {
                ("public", "sql", true) if REVIEWED_SQL.contains(&name.as_str()) => {
                    let body = sql_code(source);
                    let body = body.trim().trim_end_matches(';').trim();
                    // One statement only: EXPLAIN of a list would run the rest.
                    anyhow::ensure!(
                        !body.contains(';'),
                        "SQL helper {name} has more than one statement"
                    );
                    pending.push(body.to_owned())
                }
                ("public", "plpgsql", _) => {
                    let digest = format!("{:x}", Sha256::digest(source.as_bytes()));
                    let Some((_, _, relations)) =
                        PINNED_PLPGSQL.iter().find(|(pinned, pinned_digest, _)| {
                            pinned == name && *pinned_digest == digest
                        })
                    else {
                        anyhow::bail!(
                            "runtime authority calls unpinned PL/pgSQL {name} (source sha256 {digest})"
                        );
                    };
                    found.relations.extend(
                        relations
                            .iter()
                            .map(|relation| format!("public.{relation}")),
                    );
                }
                _ => anyhow::bail!(
                    "runtime authority calls unreviewed function {schema}.{name} ({language})"
                ),
            }
        }
        found.relations.extend(plan.relations);
        found.outputs.extend(plan.outputs);
        found.strings.extend(plan.strings);
    }
    Ok(found)
}

/// Every statement a full runtime authority resolve, its grant evaluation and
/// the credential record read send, with and without a profile, is planned.
/// Each relation they read has the stamp triggers, every function they call
/// is reviewed, and none reads billing's excluded columns.
#[tokio::test]
#[ignore = "requires isolated synthetic PostgreSQL via TEST_DATABASE_URL"]
async fn every_relation_runtime_authority_reads_is_stamped() -> Result<()> {
    let fixture = Fixture::create().await?;
    let result = async {
        // The account's GitHub connection, so the connection reads and locks
        // run on both paths.
        let github = CredentialId::parse(Uuid::new_v4().to_string())?;
        sqlx::query(
            "INSERT INTO platform_credentials(id,user_id,provider,authentication_kind,display_name,\
             status,revocation_generation,material_generation) \
             VALUES ($1,'synthetic-creator','github','oauth','GitHub','active',1,1)",
        )
        .bind(github.as_str())
        .execute(&fixture.db.pool)
        .await?;
        let mut context = fixture.context.clone();
        context.authorized_credentials.insert(github);
        // The resolve runs as the restricted runtime login. Grants and the
        // record read run as the fixture administrator: the statements, not
        // the login, are catalogued.
        let (resolves, resolve_pool) = StatementCounter::pool(&fixture.pool, 1).await?;
        let (reads, read_pool) = StatementCounter::pool(&fixture.db.pool, 1).await?;
        let authenticator = KubernetesPlatformBridgeAuthenticator::new(
            fixture.kube.client(),
            resolve_pool.clone(),
            Arc::new(TestKekProvider),
        );
        let profiles = PlatformAccessProfileStore::new(read_pool.clone(), builtin_provider_catalog());
        let credentials = PlatformCredentialStore::new(
            read_pool.clone(),
            Arc::new(TestKekProvider),
            builtin_provider_catalog(),
        );
        let credential = fixture
            .profile
            .entries
            .values()
            .next()
            .context("synthetic profile entry")?
            .clone();
        for case in ["personal profile", "no profile"] {
            if case == "no profile" {
                sqlx::query("DELETE FROM platform_environment_access_bindings")
                    .execute(&fixture.db.pool)
                    .await?;
                sqlx::query("UPDATE environments SET project_spec=project_spec-'credentials'")
                    .execute(&fixture.db.pool)
                    .await?;
            }
            authenticator
                .authenticate(&headers(unix_now()? + 600))
                .await?
                .current_session()
                .await?;
            let grants = profiles.evaluate_grants(&context).await?;
            ensure!(!grants.grants.is_empty(), "{case}: no grant evaluated");
            credentials.record(&fixture.owner, &credential).await?;
        }
        let mut statements: Vec<String> = resolves.texts();
        statements.extend(reads.texts());
        statements.sort();
        statements.dedup();
        // No statement on the path is planned large enough to be JIT-compiled.
        ensure_cheap_plans(&fixture.db.pool, &statements).await?;
        let (planned, unplanned): (Vec<String>, Vec<String>) =
            statements.into_iter().partition(|text| {
                let keyword = text
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_ascii_uppercase();
                matches!(keyword.as_str(), "SELECT" | "WITH")
            });
        ensure!(
            unplanned
                .iter()
                .all(|text| UNPLANNED.contains(&text.trim().to_ascii_uppercase().as_str())),
            "runtime authority sends a statement that is neither a read nor transaction control: {unplanned:?}"
        );
        // The scope and metadata read, the environment fence, the bound
        // profile, the credential locks, the GitHub connection, the owned
        // credentials, the record and the transaction timeouts: capture
        // worked if at least these were seen.
        ensure!(planned.len() >= 8, "too few statements captured: {planned:?}");
        let found = catalogue(&fixture.db.pool, &planned).await?;

        let stamped: BTreeSet<String> = STAMPED_TABLES
            .iter()
            .map(|table| format!("public.{}", table.table))
            .collect();
        let unstamped: Vec<&String> = found
            .relations
            .iter()
            .filter(|relation| !relation.starts_with("pg_catalog.") && !stamped.contains(*relation))
            .collect();
        ensure!(
            unstamped.is_empty(),
            "runtime authority reads relations without stamp triggers: {unstamped:?}"
        );
        // The inventory is exact: a stamped table runtime authority no longer
        // reads is a change to review, as is a new one.
        let read: BTreeSet<String> = found
            .relations
            .iter()
            .filter(|relation| relation.starts_with("public."))
            .cloned()
            .collect();
        ensure!(
            read == stamped,
            "runtime authority reads {read:?}; the stamp covers {stamped:?}"
        );
        // The trigger inventory in the database matches.
        let triggered: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT 'public.' || c.relname FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid \
             WHERE starts_with(t.tgname,'codewire_stamp_authority_') AND t.tgenabled IN ('O','A')",
        )
        .fetch_all(&fixture.db.pool)
        .await?;
        ensure!(triggered.into_iter().collect::<BTreeSet<_>>() == stamped);
        // The startup probe accepts the restricted runtime login once it holds
        // the deployed broker's EXECUTE grant on the reader, and nothing else.
        sqlx::query(&format!(
            "GRANT EXECUTE ON FUNCTION public.codewire_platform_authority_stamp(text[],text[]) TO {}",
            quote_ident(&fixture.role)
        ))
        .execute(&fixture.db.pool)
        .await?;
        codewire_server_core::authority_stamp::verify_authority_stamp_schema(&fixture.pool)
            .await?;

        // The billing columns that do not bump env are never read, by name or
        // as a whole environments row.
        for column in BILLING_COLUMNS {
            ensure!(
                !found.strings.iter().any(|text| text.contains(column)),
                "runtime authority reads environments.{column}"
            );
        }
        for (relation, alias, output) in &found.outputs {
            if relation == "environments" {
                ensure!(
                    output.iter().all(|item| item != alias
                        && !item.contains(&format!("{alias}.*"))
                        && !item.contains(&format!("({alias})"))),
                    "runtime authority reads a whole environments row: {output:?}"
                );
            }
        }
        let functions: Vec<&str> = found.functions.iter().map(String::as_str).collect();
        ensure!(
            functions
                == [
                    "codewire_platform_lock_credential",
                    "codewire_platform_lock_environment",
                    "codewire_platform_lock_owner",
                    "codewire_platform_lock_profile",
                    "codewire_platform_projection_metadata",
                ],
            "runtime authority calls {functions:?}"
        );
        resolve_pool.close().await;
        read_pool.close().await;
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[test]
fn sql_code_keeps_statements_and_drops_comments_and_literal_contents() {
    assert_eq!(
        sql_code("-- a; b\nSELECT 'x;y', 1 /* c; d */ FROM t"),
        "\nSELECT 'x y', 1   FROM t"
    );
    assert!(sql_code("SELECT 1; SELECT 2").contains(';'));
    assert!(!sql_code("SELECT 'it''s;' -- ;\n").contains(';'));
}

#[test]
fn calls_matches_whole_function_names_only() {
    assert!(calls(
        "public.codewire_platform_lock_owner('user'::text, $2)",
        "codewire_platform_lock_owner"
    ));
    assert!(calls(
        "codewire_platform_lock_owner($1, $2)",
        "codewire_platform_lock_owner"
    ));
    assert!(!calls(
        "codewire_platform_lock_owner_source_authority($1, $2, NULL::text)",
        "codewire_platform_lock_owner"
    ));
    assert!(!calls("pg_catalog.encode(x, 'hex')", "code"));
}
