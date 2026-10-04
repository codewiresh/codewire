//! The authority stamp installed by migration 35: which tables advance which
//! scope generation, the read function, and a startup probe that checks both.
//!
//! Every write to a row that runtime credential authority reads advances the
//! generation of that row's own scope, in the writer's transaction. A reader
//! can compare the generations of its scopes before and after a decision.
//! Nothing reads the stamp yet; the credential broker will call
//! [`verify_authority_stamp_schema`] at startup before it relies on one.
//!
//! The probe checks the catalog only. It cannot see a trigger that was
//! bypassed by `session_replication_role = replica` or a restore while it was
//! disabled; `docs/dev/DATABASE-MIGRATIONS.md` gives the recovery step. It
//! compares trigger definitions as PostgreSQL deparses them, so a server
//! version that deparses them differently fails it closed until the expected
//! text is reviewed again.

use sqlx::PgPool;

/// A scope kind a stamp names. The database stores [`ScopeKind::as_str`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScopeKind {
    /// Bumped by a TRUNCATE of any stamped table.
    Global,
    /// An environment, by environment id.
    Environment,
    /// A user, by user id: the account row and its organization memberships.
    User,
    /// An organization, by organization id: the row and its secret projects.
    Organization,
    /// An access profile, by profile id: the row, revisions and entries.
    Profile,
    /// The credentials of one owner, `user:<id>` or `organization:<id>`.
    Credentials,
}

impl ScopeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Environment => "env",
            Self::User => "user",
            Self::Organization => "org",
            Self::Profile => "profile",
            Self::Credentials => "creds",
        }
    }
}

/// One table whose writes advance a scope generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StampedTable {
    /// Unqualified table name in the `public` schema.
    pub table: &'static str,
    pub kind: ScopeKind,
    /// How a row names its scope: one of its columns (`id`, `environment_id`,
    /// `user_id`, `org_id` or `profile_id`), or `owner`, which is
    /// `user:<user_id>`, else `organization:<organization_id>`.
    pub key: &'static str,
    /// Columns an UPDATE may change without advancing the generation.
    pub excluded_columns: &'static [&'static str],
}

/// The only columns whose change does not advance a generation: billing's
/// tracking columns on `environments`. Every other column, including one
/// added later, does.
pub const BILLING_COLUMNS: [&str; 2] = ["last_billing_event_at", "total_running_seconds"];

/// Every table that runtime credential authority reads (scope, binding,
/// grants and the credential record), and the scope it advances.
pub const STAMPED_TABLES: [StampedTable; 12] = [
    StampedTable {
        table: "environments",
        kind: ScopeKind::Environment,
        key: "id",
        excluded_columns: &BILLING_COLUMNS,
    },
    StampedTable {
        table: "users",
        kind: ScopeKind::User,
        key: "id",
        excluded_columns: &[],
    },
    StampedTable {
        table: "organizations",
        kind: ScopeKind::Organization,
        key: "id",
        excluded_columns: &[],
    },
    StampedTable {
        table: "org_members",
        kind: ScopeKind::User,
        key: "user_id",
        excluded_columns: &[],
    },
    StampedTable {
        table: "sandbox_environment_backend",
        kind: ScopeKind::Environment,
        key: "environment_id",
        excluded_columns: &[],
    },
    StampedTable {
        table: "sandbox_workspace_bindings",
        kind: ScopeKind::Environment,
        key: "environment_id",
        excluded_columns: &[],
    },
    StampedTable {
        table: "platform_environment_access_bindings",
        kind: ScopeKind::Environment,
        key: "environment_id",
        excluded_columns: &[],
    },
    StampedTable {
        table: "platform_access_profiles",
        kind: ScopeKind::Profile,
        key: "id",
        excluded_columns: &[],
    },
    StampedTable {
        table: "platform_access_profile_revisions",
        kind: ScopeKind::Profile,
        key: "profile_id",
        excluded_columns: &[],
    },
    StampedTable {
        table: "platform_access_profile_entries",
        kind: ScopeKind::Profile,
        key: "profile_id",
        excluded_columns: &[],
    },
    StampedTable {
        table: "platform_credentials",
        kind: ScopeKind::Credentials,
        key: "owner",
        excluded_columns: &[],
    },
    StampedTable {
        table: "secret_projects",
        kind: ScopeKind::Organization,
        key: "org_id",
        excluded_columns: &[],
    },
];

/// AFTER INSERT OR DELETE, for each row.
pub const ROW_TRIGGER: &str = "codewire_stamp_authority_row";
/// AFTER UPDATE, for each row that changed a non-excluded column.
pub const UPDATE_TRIGGER: &str = "codewire_stamp_authority_update";
/// AFTER TRUNCATE, for each statement; advances the global scope.
pub const TRUNCATE_TRIGGER: &str = "codewire_stamp_authority_truncate";
/// The generation table's BEFORE DELETE guard.
pub const RETAINED_TRIGGER: &str = "codewire_platform_authority_generation_retained";
/// The generation table's BEFORE TRUNCATE guard.
pub const RETAINED_TRUNCATE_TRIGGER: &str =
    "codewire_platform_authority_generation_retained_truncate";

pub const GENERATIONS_TABLE: &str = "platform_authority_generations";
pub const GENERATION_SEQUENCE: &str = "platform_authority_generation_seq";
pub const TRIGGER_FUNCTION: &str = "codewire_platform_authority_row_changed";
pub const RETAINED_FUNCTION: &str = "codewire_platform_authority_generation_retained";
/// The read function's exact signature.
pub const READ_FUNCTION: &str = "public.codewire_platform_authority_stamp(text[],text[])";

/// SHA-256 of each function's installed source (`pg_proc.prosrc`), as
/// migration 35 creates it. A replaced body fails the probe.
pub const READ_SOURCE_SHA256: &str =
    "ab54669d3a11dd6d4cb9a89c28eb804fb27149e52baa1fe61a74eee98ad09b84";
pub const TRIGGER_FUNCTION_SOURCE_SHA256: &str =
    "6457d3f647eec54408518ae657b8f4ff4152a64f497524cf6be7a8a739c4b70f";
pub const RETAINED_FUNCTION_SOURCE_SHA256: &str =
    "377d61de7bb51cb8b56ec83c9ae17153abfe689e3b6413d642441941154e4d92";

/// One trigger the probe requires, enabled and exactly as installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedTrigger {
    pub table: &'static str,
    pub name: &'static str,
    /// `pg_get_triggerdef` with `search_path = pg_catalog`, which qualifies
    /// the table and the trigger function.
    pub definition: String,
}

impl StampedTable {
    /// The row triggers' arguments: the scope kind and the key.
    pub fn row_arguments(&self) -> Vec<String> {
        vec![self.kind.as_str().to_owned(), self.key.to_owned()]
    }
}

/// Every trigger migration 35 installs: three per stamped table and the two
/// guards on the generation table.
pub fn expected_triggers() -> Vec<ExpectedTrigger> {
    let mut triggers = Vec::with_capacity(STAMPED_TABLES.len() * 3 + 2);
    for table in &STAMPED_TABLES {
        let name = table.table;
        let arguments = table
            .row_arguments()
            .iter()
            .map(|argument| format!("'{argument}'"))
            .collect::<Vec<_>>()
            .join(", ");
        let function = format!("public.{TRIGGER_FUNCTION}({arguments})");
        let condition = if table.excluded_columns.is_empty() {
            "(to_jsonb(old.*) IS DISTINCT FROM to_jsonb(new.*))".to_owned()
        } else {
            let excluded = format!("'{{{}}}'::text[]", table.excluded_columns.join(","));
            format!(
                "((to_jsonb(old.*) - {excluded}) IS DISTINCT FROM (to_jsonb(new.*) - {excluded}))"
            )
        };
        triggers.push(ExpectedTrigger {
            table: name,
            name: ROW_TRIGGER,
            definition: format!(
                "CREATE TRIGGER {ROW_TRIGGER} AFTER INSERT OR DELETE ON public.{name} \
                 FOR EACH ROW EXECUTE FUNCTION {function}"
            ),
        });
        triggers.push(ExpectedTrigger {
            table: name,
            name: UPDATE_TRIGGER,
            definition: format!(
                "CREATE TRIGGER {UPDATE_TRIGGER} AFTER UPDATE ON public.{name} \
                 FOR EACH ROW WHEN ({condition}) EXECUTE FUNCTION {function}"
            ),
        });
        triggers.push(ExpectedTrigger {
            table: name,
            name: TRUNCATE_TRIGGER,
            definition: format!(
                "CREATE TRIGGER {TRUNCATE_TRIGGER} AFTER TRUNCATE ON public.{name} \
                 FOR EACH STATEMENT EXECUTE FUNCTION public.{TRIGGER_FUNCTION}('global')"
            ),
        });
    }
    triggers.push(ExpectedTrigger {
        table: GENERATIONS_TABLE,
        name: RETAINED_TRIGGER,
        definition: format!(
            "CREATE TRIGGER {RETAINED_TRIGGER} BEFORE DELETE ON public.{GENERATIONS_TABLE} \
             FOR EACH ROW EXECUTE FUNCTION public.{RETAINED_FUNCTION}()"
        ),
    });
    triggers.push(ExpectedTrigger {
        table: GENERATIONS_TABLE,
        name: RETAINED_TRUNCATE_TRIGGER,
        definition: format!(
            "CREATE TRIGGER {RETAINED_TRUNCATE_TRIGGER} BEFORE TRUNCATE ON public.{GENERATIONS_TABLE} \
             FOR EACH STATEMENT EXECUTE FUNCTION public.{RETAINED_FUNCTION}()"
        ),
    });
    triggers
}

/// What the catalog shows for one stamp trigger.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub struct ObservedTrigger {
    pub table: String,
    pub name: String,
    /// `pg_trigger.tgenabled`: `O` or `A` fire in normal sessions.
    pub enabled: String,
    /// `pg_get_triggerdef` with `search_path = pg_catalog`.
    pub definition: String,
}

/// What the catalog shows for the stamp's table, sequence and functions, and
/// what the probing login may do with them.
#[derive(Clone, Debug, Default, PartialEq, Eq, sqlx::FromRow)]
pub struct ObservedObjects {
    pub table_present: bool,
    pub sequence_present: bool,
    pub read_present: bool,
    pub read_definer: bool,
    pub read_search_path_pinned: bool,
    pub read_source_sha256: Option<String>,
    /// Whether the probing login may execute the read function.
    pub read_executable: bool,
    pub trigger_function_present: bool,
    pub trigger_function_definer: bool,
    pub trigger_function_search_path_pinned: bool,
    pub trigger_function_source_sha256: Option<String>,
    pub retained_function_source_sha256: Option<String>,
    /// Whether the probing login may write the generation table directly.
    pub table_writable: bool,
    /// Whether the probing login may use, read or set the sequence.
    pub sequence_usable: bool,
}

/// Why the stamp cannot be relied on.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityStampSchemaError {
    #[error("authority stamp schema is incomplete: {}", .0.join("; "))]
    Incomplete(Vec<String>),
    #[error("authority stamp schema could not be read")]
    Unavailable(#[source] sqlx::Error),
}

const OBJECTS_QUERY: &str = "SELECT \
    g.oid IS NOT NULL AS table_present, \
    q.oid IS NOT NULL AS sequence_present, \
    r.oid IS NOT NULL AS read_present, \
    COALESCE(r.prosecdef, false) AS read_definer, \
    COALESCE(r.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[], false) AS read_search_path_pinned, \
    pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(r.prosrc, 'UTF8')), 'hex') AS read_source_sha256, \
    COALESCE(pg_catalog.has_function_privilege(r.oid, 'EXECUTE'), false) AS read_executable, \
    t.oid IS NOT NULL AS trigger_function_present, \
    COALESCE(t.prosecdef, false) AS trigger_function_definer, \
    COALESCE(t.proconfig = ARRAY['search_path=pg_catalog, pg_temp']::text[], false) \
        AS trigger_function_search_path_pinned, \
    pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(t.prosrc, 'UTF8')), 'hex') \
        AS trigger_function_source_sha256, \
    pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(k.prosrc, 'UTF8')), 'hex') \
        AS retained_function_source_sha256, \
    COALESCE(pg_catalog.has_table_privilege(g.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') \
        OR pg_catalog.has_any_column_privilege(g.oid, 'INSERT,UPDATE,REFERENCES'), false) AS table_writable, \
    COALESCE(pg_catalog.has_sequence_privilege(q.oid, 'USAGE,SELECT,UPDATE'), false) AS sequence_usable \
    FROM (SELECT pg_catalog.to_regprocedure('public.codewire_platform_authority_stamp(text[],text[])') AS read_oid, \
                 pg_catalog.to_regprocedure('public.codewire_platform_authority_row_changed()') AS trigger_oid, \
                 pg_catalog.to_regprocedure('public.codewire_platform_authority_generation_retained()') AS retained_oid, \
                 pg_catalog.to_regclass('public.platform_authority_generations') AS table_oid, \
                 pg_catalog.to_regclass('public.platform_authority_generation_seq') AS sequence_oid) AS f \
    LEFT JOIN pg_catalog.pg_proc AS r ON r.oid = f.read_oid \
    LEFT JOIN pg_catalog.pg_proc AS t ON t.oid = f.trigger_oid \
    LEFT JOIN pg_catalog.pg_proc AS k ON k.oid = f.retained_oid \
    LEFT JOIN pg_catalog.pg_class AS g ON g.oid = f.table_oid AND g.relkind = 'r' \
    LEFT JOIN pg_catalog.pg_class AS q ON q.oid = f.sequence_oid AND q.relkind = 'S'";

const TRIGGERS_QUERY: &str = "SELECT c.relname::text AS table, t.tgname::text AS name, \
    t.tgenabled::text AS enabled, pg_catalog.pg_get_triggerdef(t.oid) AS definition \
    FROM pg_catalog.pg_trigger AS t \
    JOIN pg_catalog.pg_class AS c ON c.oid = t.tgrelid \
    WHERE c.relnamespace = 'public'::pg_catalog.regnamespace AND NOT t.tgisinternal \
      AND t.tgname = ANY($1::text[])";

/// Check that the read function exists unchanged and the probing login may
/// execute it but cannot write the generation table or sequence, and that
/// every expected trigger is present, enabled and unchanged. Reads only the
/// system catalogs, which every login may read.
pub async fn verify_authority_stamp_schema(pool: &PgPool) -> Result<(), AuthorityStampSchemaError> {
    let problems = authority_stamp_schema_problems(pool)
        .await
        .map_err(AuthorityStampSchemaError::Unavailable)?;
    if problems.is_empty() {
        Ok(())
    } else {
        Err(AuthorityStampSchemaError::Incomplete(problems))
    }
}

/// [`verify_authority_stamp_schema`]'s findings, without failing on them.
pub async fn authority_stamp_schema_problems(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    // Deparse with a fixed path, whatever the login's search_path is.
    sqlx::query("SELECT pg_catalog.set_config('search_path', 'pg_catalog', true)")
        .execute(&mut *tx)
        .await?;
    let objects: ObservedObjects = sqlx::query_as(OBJECTS_QUERY).fetch_one(&mut *tx).await?;
    let names = [
        ROW_TRIGGER,
        UPDATE_TRIGGER,
        TRUNCATE_TRIGGER,
        RETAINED_TRIGGER,
        RETAINED_TRUNCATE_TRIGGER,
    ];
    let triggers: Vec<ObservedTrigger> = sqlx::query_as(TRIGGERS_QUERY)
        .bind(&names[..])
        .fetch_all(&mut *tx)
        .await?;
    tx.rollback().await?;
    Ok(schema_problems(&objects, &triggers))
}

/// Every difference between the catalog and migration 35, as non-secret
/// descriptions. Empty when the stamp can be relied on.
pub fn schema_problems(objects: &ObservedObjects, triggers: &[ObservedTrigger]) -> Vec<String> {
    let mut problems = Vec::new();
    let pinned = |observed: &Option<String>, expected: &str| observed.as_deref() == Some(expected);
    for (ok, problem) in [
        (objects.table_present, "generation table is missing"),
        (objects.sequence_present, "generation sequence is missing"),
        (objects.read_present, "read function is missing"),
        (
            objects.read_definer,
            "read function is not SECURITY DEFINER",
        ),
        (
            objects.read_search_path_pinned,
            "read function search path is not pinned",
        ),
        (
            pinned(&objects.read_source_sha256, READ_SOURCE_SHA256),
            "read function source differs from migration 35",
        ),
        (
            objects.read_executable,
            "read function is not executable by this login",
        ),
        (
            objects.trigger_function_present,
            "trigger function is missing",
        ),
        (
            objects.trigger_function_definer,
            "trigger function is not SECURITY DEFINER",
        ),
        (
            objects.trigger_function_search_path_pinned,
            "trigger function search path is not pinned",
        ),
        (
            pinned(
                &objects.trigger_function_source_sha256,
                TRIGGER_FUNCTION_SOURCE_SHA256,
            ),
            "trigger function source differs from migration 35",
        ),
        (
            pinned(
                &objects.retained_function_source_sha256,
                RETAINED_FUNCTION_SOURCE_SHA256,
            ),
            "retained-generation guard source differs from migration 35",
        ),
        (
            !objects.table_writable,
            "generation table is writable by this login",
        ),
        (
            !objects.sequence_usable,
            "generation sequence is usable by this login",
        ),
    ] {
        if !ok {
            problems.push(problem.to_owned());
        }
    }
    for expected in expected_triggers() {
        let label = format!("{}.{}", expected.table, expected.name);
        let Some(observed) = triggers
            .iter()
            .find(|observed| observed.table == expected.table && observed.name == expected.name)
        else {
            problems.push(format!("{label} is missing"));
            continue;
        };
        if !matches!(observed.enabled.as_str(), "O" | "A") {
            problems.push(format!("{label} is not enabled"));
        }
        if observed.definition != expected.definition {
            problems.push(format!("{label} definition differs from migration 35"));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalog as migration 35 leaves it, seen by the broker login.
    fn installed() -> (ObservedObjects, Vec<ObservedTrigger>) {
        let objects = ObservedObjects {
            table_present: true,
            sequence_present: true,
            read_present: true,
            read_definer: true,
            read_search_path_pinned: true,
            read_source_sha256: Some(READ_SOURCE_SHA256.to_owned()),
            read_executable: true,
            trigger_function_present: true,
            trigger_function_definer: true,
            trigger_function_search_path_pinned: true,
            trigger_function_source_sha256: Some(TRIGGER_FUNCTION_SOURCE_SHA256.to_owned()),
            retained_function_source_sha256: Some(RETAINED_FUNCTION_SOURCE_SHA256.to_owned()),
            table_writable: false,
            sequence_usable: false,
        };
        let triggers = expected_triggers()
            .into_iter()
            .map(|expected| ObservedTrigger {
                table: expected.table.to_owned(),
                name: expected.name.to_owned(),
                enabled: "O".to_owned(),
                definition: expected.definition,
            })
            .collect();
        (objects, triggers)
    }

    fn trigger<'a>(
        triggers: &'a mut [ObservedTrigger],
        table: &str,
        name: &str,
    ) -> &'a mut ObservedTrigger {
        triggers
            .iter_mut()
            .find(|trigger| trigger.table == table && trigger.name == name)
            .expect("installed trigger")
    }

    #[test]
    fn the_inventory_covers_each_table_with_three_triggers_and_guards_the_generations() {
        let triggers = expected_triggers();
        assert_eq!(triggers.len(), STAMPED_TABLES.len() * 3 + 2);
        let mut tables: Vec<_> = STAMPED_TABLES.iter().map(|table| table.table).collect();
        tables.sort_unstable();
        tables.dedup();
        assert_eq!(tables.len(), STAMPED_TABLES.len());
        // Only environments excludes columns, and only billing's two.
        for table in &STAMPED_TABLES {
            let expected: &[&str] = if table.table == "environments" {
                &BILLING_COLUMNS
            } else {
                &[]
            };
            assert_eq!(table.excluded_columns, expected, "{}", table.table);
        }
        let credentials = STAMPED_TABLES
            .iter()
            .find(|table| table.table == "platform_credentials")
            .expect("credentials are stamped");
        assert_eq!(credentials.row_arguments(), ["creds", "owner"]);
        let environments = triggers
            .iter()
            .find(|trigger| trigger.table == "environments" && trigger.name == UPDATE_TRIGGER)
            .expect("environments update trigger");
        assert_eq!(
            environments.definition,
            "CREATE TRIGGER codewire_stamp_authority_update AFTER UPDATE ON public.environments \
             FOR EACH ROW WHEN (((to_jsonb(old.*) - '{last_billing_event_at,total_running_seconds}'::text[]) \
             IS DISTINCT FROM (to_jsonb(new.*) - '{last_billing_event_at,total_running_seconds}'::text[]))) \
             EXECUTE FUNCTION public.codewire_platform_authority_row_changed('env', 'id')"
        );
    }

    #[test]
    fn an_installed_catalog_has_no_problems() {
        let (objects, triggers) = installed();
        assert_eq!(schema_problems(&objects, &triggers), Vec::<String>::new());
        // ENABLE ALWAYS also fires in normal sessions.
        let (objects, mut triggers) = installed();
        trigger(&mut triggers, "users", UPDATE_TRIGGER).enabled = "A".to_owned();
        assert!(schema_problems(&objects, &triggers).is_empty());
    }

    #[test]
    fn each_catalog_difference_is_reported() {
        type Change = fn(&mut ObservedObjects, &mut Vec<ObservedTrigger>);
        let cases: [(&str, Change); 16] = [
            (
                "read function is not executable by this login",
                |objects, _| objects.read_executable = false,
            ),
            ("read function is missing", |objects, _| {
                objects.read_present = false
            }),
            (
                "read function source differs from migration 35",
                |objects, _| objects.read_source_sha256 = Some("0".repeat(64)),
            ),
            (
                "trigger function source differs from migration 35",
                |objects, _| objects.trigger_function_source_sha256 = None,
            ),
            (
                "retained-generation guard source differs from migration 35",
                |objects, _| objects.retained_function_source_sha256 = Some(String::new()),
            ),
            ("trigger function is not SECURITY DEFINER", |objects, _| {
                objects.trigger_function_definer = false
            }),
            ("generation table is missing", |objects, _| {
                objects.table_present = false
            }),
            (
                "generation table is writable by this login",
                |objects, _| objects.table_writable = true,
            ),
            (
                "generation sequence is usable by this login",
                |objects, _| objects.sequence_usable = true,
            ),
            (
                "environments.codewire_stamp_authority_update is not enabled",
                |_, triggers| {
                    trigger(triggers, "environments", UPDATE_TRIGGER).enabled = "D".to_owned()
                },
            ),
            // A replica-only trigger does not fire in a normal session.
            (
                "org_members.codewire_stamp_authority_row is not enabled",
                |_, triggers| {
                    trigger(triggers, "org_members", ROW_TRIGGER).enabled = "R".to_owned()
                },
            ),
            (
                "secret_projects.codewire_stamp_authority_truncate is missing",
                |_, triggers| {
                    triggers.retain(|trigger| {
                        !(trigger.table == "secret_projects" && trigger.name == TRUNCATE_TRIGGER)
                    })
                },
            ),
            (
                "platform_authority_generations.codewire_platform_authority_generation_retained is missing",
                |_, triggers| triggers.retain(|trigger| trigger.name != RETAINED_TRIGGER),
            ),
            (
                "platform_credentials.codewire_stamp_authority_row definition differs from migration 35",
                |_, triggers| {
                    let row = trigger(triggers, "platform_credentials", ROW_TRIGGER);
                    row.definition = row
                        .definition
                        .replace("'creds', 'owner'", "'user', 'user_id'")
                },
            ),
            (
                "users.codewire_stamp_authority_row definition differs from migration 35",
                // AFTER INSERT only: a DELETE would no longer bump.
                |_, triggers| {
                    let row = trigger(triggers, "users", ROW_TRIGGER);
                    row.definition = row.definition.replace("INSERT OR DELETE", "INSERT")
                },
            ),
            (
                "users.codewire_stamp_authority_update definition differs from migration 35",
                // Excluding a column anywhere but billing's environments.
                |_, triggers| {
                    let update = trigger(triggers, "users", UPDATE_TRIGGER);
                    update.definition = update.definition.replace(
                        "to_jsonb(old.*) IS DISTINCT FROM to_jsonb(new.*)",
                        "(to_jsonb(old.*) - 'enabled') IS DISTINCT FROM (to_jsonb(new.*) - 'enabled')",
                    )
                },
            ),
        ];
        for (expected, change) in cases {
            let (mut objects, mut triggers) = installed();
            change(&mut objects, &mut triggers);
            let problems = schema_problems(&objects, &triggers);
            assert_eq!(problems, [expected], "{expected}");
        }
        // Dropping one billing exclusion on environments is also a change.
        let (objects, mut triggers) = installed();
        let update = trigger(&mut triggers, "environments", UPDATE_TRIGGER);
        update.definition = update.definition.replace(
            "{last_billing_event_at,total_running_seconds}",
            "{last_billing_event_at}",
        );
        assert_eq!(
            schema_problems(&objects, &triggers),
            ["environments.codewire_stamp_authority_update definition differs from migration 35"]
        );
    }
}
