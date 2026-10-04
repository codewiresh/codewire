//! Authority stamp (migration 35): accepted prior history and disposable
//! database proof for the retained generation table, the stamp triggers on
//! every table runtime credential authority reads, the read function, the
//! startup probe, and both rollback boundaries.

use std::collections::BTreeSet;

use super::*;
use crate::authority_stamp::{
    AuthorityStampSchemaError, STAMPED_TABLES, authority_stamp_schema_problems, expected_triggers,
    verify_authority_stamp_schema,
};

const VERSION: i64 = 35;
// Measured from accepted canonical main a4d598aca65c1ffcfffa57cdae775df29e99473a,
// not the edited branch: SHA384(concatenated binary SHA384(SQL1)..SHA384(SQL34))
// and SHA384(SQL34).
const PRIOR_HISTORY34: &str = "2513689128f703bffca25e18a45a238a0f2cb774a394be9e45f44001f6008b0ce3d39f5b9c394d2e8826b1c8501e7a5a";
const PRIOR34: &str = "8cca018f2f40699d2a852d6bf8e0301e0732bb651fad0c86ef04dfc21945aa4db2b892098d7fb2b93b0fbe0a2b51d2e6";
const READ_FUNCTION: &str = "public.codewire_platform_authority_stamp(text[],text[])";

pub(super) fn assert_accepted_prior34() -> anyhow::Result<()> {
    workspace_binding::assert_accepted_prior33()?;
    let mut digest = Sha384::new();
    let prior: Vec<_> = MIGRATOR.iter().filter(|m| m.version < VERSION).collect();
    anyhow::ensure!(prior.len() == 34);
    for (index, migration) in prior.iter().enumerate() {
        anyhow::ensure!(migration.version == index as i64 + 1);
        digest.update(Sha384::digest(migration.sql.as_bytes()));
    }
    anyhow::ensure!(
        format!("{:x}", digest.finalize()) == PRIOR_HISTORY34,
        "migration1..34 differs from accepted canonical a4d598aca"
    );
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(prior[33].sql.as_bytes())) == PRIOR34,
        "migration34 differs from accepted canonical a4d598aca"
    );
    Ok(())
}

#[test]
fn authority_stamp_upgrade_pins_the_accepted34_history() -> anyhow::Result<()> {
    assert_accepted_prior34()
}

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// Every helper except this migration's three functions.
async fn prior_helpers(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n \
        ON n.oid=p.pronamespace WHERE n.nspname='public' AND starts_with(p.proname,'codewire_') \
        AND NOT starts_with(p.proname,'codewire_platform_authority_') \
        ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)",
    )
    .fetch_all(pool)
    .await?)
}

/// Every non-internal trigger other than this migration's, by table.
async fn prior_triggers(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    let mut triggers: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname || ':' || pg_get_triggerdef(t.oid) FROM pg_trigger t \
         JOIN pg_class c ON c.oid=t.tgrelid \
         WHERE c.relnamespace='public'::regnamespace AND NOT t.tgisinternal \
         AND NOT starts_with(t.tgname,'codewire_stamp_authority_') \
         AND c.relname <> 'platform_authority_generations'",
    )
    .fetch_all(pool)
    .await?;
    triggers.sort();
    Ok(triggers)
}

/// No object of this migration remains.
async fn absent(pool: &PgPool) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT to_regclass('public.platform_authority_generations') IS NULL \
         AND to_regclass('public.platform_authority_generation_seq') IS NULL \
         AND NOT EXISTS (SELECT 1 FROM pg_proc WHERE starts_with(proname,'codewire_platform_authority_')) \
         AND NOT EXISTS (SELECT 1 FROM pg_trigger WHERE starts_with(tgname,'codewire_stamp_authority_'))",
    )
    .fetch_one(pool)
    .await?)
}

const CREATOR: &str = "stamp-creator";
const OTHER: &str = "stamp-other";
const ORG: &str = "stamp-org";
const ORG_B: &str = "stamp-org-b";
const ENV: &str = "stamp-env";
const ENV_B: &str = "stamp-env-b";
const PROFILE: &str = "stamp-profile";
const PROFILE_B: &str = "stamp-profile-b";
const POD: &str = "4e1b3a52-6f0d-4c7e-9a8b-1c2d3e4f5a61";
const POD_2: &str = "4e1b3a52-6f0d-4c7e-9a8b-1c2d3e4f5a62";
const CLAIM: &str = "4e1b3a52-6f0d-4c7e-9a8b-1c2d3e4f5a63";
const SANDBOX: &str = "4e1b3a52-6f0d-4c7e-9a8b-1c2d3e4f5a64";

/// Every scope the mutation fixture observes: (label, kind, id).
const SCOPES: [(&str, &str, &str); 18] = [
    ("global", "global", ""),
    ("env", "env", ENV),
    ("env-b", "env", ENV_B),
    ("env-new", "env", "stamp-env-new"),
    ("user", "user", CREATOR),
    ("user-other", "user", OTHER),
    ("user-new", "user", "stamp-user-new"),
    ("org", "org", ORG),
    ("org-b", "org", ORG_B),
    ("org-new", "org", "stamp-org-new"),
    ("profile", "profile", PROFILE),
    ("profile-b", "profile", PROFILE_B),
    ("profile-new", "profile", "stamp-profile-new"),
    ("creds", "creds", "user:stamp-creator"),
    ("creds-other", "creds", "user:stamp-other"),
    ("creds-org", "creds", "organization:stamp-org"),
    ("creds-org-b", "creds", "organization:stamp-org-b"),
    ("creds-new", "creds", "user:stamp-user-new"),
];

/// The scope generations, in `SCOPES` order, read through the read function
/// in this connection's transaction.
async fn stamp(connection: &mut PgConnection) -> anyhow::Result<Vec<i64>> {
    let mut generations = Vec::with_capacity(SCOPES.len());
    for chunk in SCOPES.chunks(16) {
        let kinds: Vec<&str> = chunk.iter().map(|scope| scope.1).collect();
        let ids: Vec<&str> = chunk.iter().map(|scope| scope.2).collect();
        let read: Vec<i64> = sqlx::query_scalar(
            "SELECT generations FROM public.codewire_platform_authority_stamp($1,$2)",
        )
        .bind(&kinds)
        .bind(&ids)
        .fetch_one(&mut *connection)
        .await?;
        anyhow::ensure!(read.len() == chunk.len());
        generations.extend(read);
    }
    Ok(generations)
}

fn changed(before: &[i64], after: &[i64]) -> BTreeSet<&'static str> {
    SCOPES
        .iter()
        .zip(before.iter().zip(after))
        .filter(|(_, (before, after))| before != after)
        .map(|(scope, _)| scope.0)
        .collect()
}

// Synthetic public key text; only its shape is checked.
const SSH_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnlyExampleOnlyExampleOnlyExampl";

/// One complete authority world, as runtime credential authority reads it:
/// a creator with membership, a running environment with backend, live
/// binding and a personal profile binding, profile revisions and entries,
/// personal and organization credentials, and a secret project.
async fn seed(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(&format!(
        "INSERT INTO users(id,email) VALUES ('{CREATOR}','stamp-creator@example.test'), \
             ('{OTHER}','stamp-other@example.test'); \
         INSERT INTO organizations(id,name,slug,created_by) VALUES \
             ('{ORG}','Stamp','stamp-org-slug','{CREATOR}'), \
             ('{ORG_B}','Stamp B','stamp-org-b-slug','{CREATOR}'); \
         INSERT INTO org_members(id,org_id,user_id,role) VALUES \
             ('stamp-member','{ORG}','{CREATOR}','member'), \
             ('stamp-member-other','{ORG_B}','{OTHER}','member'); \
         INSERT INTO environment_presets(id,org_id,name,slug,project_spec) VALUES \
             ('stamp-preset','{ORG}','Stamp','stamp','{{\"schema_version\":1,\"working_directory\":\"/workspace\"}}'::jsonb); \
         INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state, \
             environment_operation_generation,project_spec) VALUES \
             ('{ENV}','{ORG}','{CREATOR}','sandbox','stamp-preset','running','started',3, \
              '{{\"schema_version\":1,\"working_directory\":\"/workspace\", \
                 \"credentials\":{{\"profile\":\"platform:id:{PROFILE}\"}}, \
                 \"secrets\":{{\"project\":\"platform:id:stamp-project\"}}}}'::jsonb), \
             ('{ENV_B}','{ORG}','{CREATOR}','sandbox','stamp-preset','running','started',1, \
              '{{\"schema_version\":1,\"working_directory\":\"/workspace\"}}'::jsonb); \
         INSERT INTO sandbox_environment_backend(environment_id,namespace,sandbox_claim_name, \
             sandbox_claim_uid,pod_name,setup_complete) VALUES \
             ('{ENV}','stamp-sandboxes','sandbox-stamp','{CLAIM}','sandbox-stamp',true); \
         INSERT INTO sandbox_workspace_bindings(pod_uid,environment_id,namespace,pod_name,claim_uid, \
             sandbox_uid,operation_generation,managed_credential_clients,credential_scope) VALUES \
             ('{POD}','{ENV}','stamp-sandboxes','sandbox-stamp','{CLAIM}','{SANDBOX}',3,'codex','pod'); \
         UPDATE sandbox_environment_backend SET pod_uid='{POD}', bound_at=now() WHERE environment_id='{ENV}'; \
         INSERT INTO platform_credentials(id,user_id,organization_id,provider,authentication_kind, \
             display_name,account_hint,status,revocation_generation,material_generation) VALUES \
             ('stamp-codex','{CREATOR}',NULL,'openai','oauth','Codex','account','active',1,1), \
             ('stamp-spare','{CREATOR}',NULL,'anthropic','api_key','Spare',NULL,'active',1,1), \
             ('stamp-other-key','{OTHER}',NULL,'openai','api_key','Other',NULL,'active',1,1), \
             ('stamp-org-key',NULL,'{ORG}','openai','api_key','Organization',NULL,'active',1,1), \
             ('stamp-org-b-key',NULL,'{ORG_B}','openai','api_key','Organization B',NULL,'active',1,1); \
         INSERT INTO platform_credentials(id,user_id,provider,authentication_kind,display_name, \
             status,revocation_generation,material_generation,ssh_public_key,ssh_fingerprint) VALUES \
             ('stamp-ssh','{CREATOR}','ssh','ssh_key','SSH','active',1,1,'{SSH_KEY}', \
              'SHA256:{}'); \
         INSERT INTO platform_access_profiles(id,user_id,organization_id,name,current_revision) VALUES \
             ('{PROFILE}','{CREATOR}',NULL,'Stamp',1), ('{PROFILE_B}','{CREATOR}',NULL,'Stamp B',1); \
         INSERT INTO platform_access_profile_revisions(profile_id,revision) VALUES \
             ('{PROFILE}',1),('{PROFILE}',2),('{PROFILE_B}',1),('{PROFILE_B}',2); \
         INSERT INTO platform_access_profile_entries(profile_id,revision,capability_slot,credential_id) VALUES \
             ('{PROFILE}',1,'codex','stamp-codex'), ('{PROFILE_B}',2,'codex','stamp-codex'); \
         INSERT INTO platform_environment_access_bindings(environment_id,profile_id,profile_revision, \
             personal_owner_confirmed_by) VALUES ('{ENV}','{PROFILE}',1,'{CREATOR}'); \
         INSERT INTO secret_projects(id,org_id,name) VALUES ('stamp-project','{ORG}','Stamp');",
        "A".repeat(43)
    ))
    .execute(pool)
    .await?;
    Ok(())
}

/// The columns runtime credential authority may read: every column the
/// deployed broker role is granted (tests/e2e/kind/credential-broker.sql),
/// and the columns its two SECURITY DEFINER readers see (`project_spec`,
/// and the secret project's id and organization).
const INPUT_COLUMNS: [(&str, &[&str]); 12] = [
    ("users", &["id", "is_admin", "enabled"]),
    ("organizations", &["id", "deletion_state"]),
    ("org_members", &["id", "org_id", "user_id", "role"]),
    (
        "environments",
        &[
            "id",
            "created_by",
            "org_id",
            "type",
            "state",
            "desired_state",
            "deletion_requested_at",
            "environment_operation_generation",
            "project_spec",
        ],
    ),
    (
        "sandbox_environment_backend",
        &[
            "environment_id",
            "namespace",
            "sandbox_claim_name",
            "sandbox_claim_uid",
            "pod_name",
            "pod_uid",
            "bound_at",
        ],
    ),
    (
        "sandbox_workspace_bindings",
        &[
            "environment_id",
            "pod_uid",
            "claim_uid",
            "sandbox_uid",
            "managed_credential_clients",
            "credential_scope",
            "released_at",
        ],
    ),
    (
        "platform_access_profiles",
        &[
            "id",
            "user_id",
            "organization_id",
            "name",
            "current_revision",
        ],
    ),
    (
        "platform_access_profile_revisions",
        &["profile_id", "revision"],
    ),
    (
        "platform_access_profile_entries",
        &["profile_id", "revision", "capability_slot", "credential_id"],
    ),
    (
        "platform_environment_access_bindings",
        &[
            "environment_id",
            "profile_id",
            "profile_revision",
            "personal_owner_confirmed_by",
        ],
    ),
    (
        "platform_credentials",
        &[
            "id",
            "user_id",
            "organization_id",
            "provider",
            "authentication_kind",
            "display_name",
            "account_hint",
            "status",
            "expires_at_unix",
            "revocation_generation",
            "material_generation",
            "ssh_public_key",
            "ssh_fingerprint",
        ],
    ),
    ("secret_projects", &["id", "org_id"]),
];

/// Input columns no UPDATE can change: the binding is insert-only except its
/// release (migration 34's trigger), and `environments.type` has one allowed
/// value. Each is proven refused below instead.
const UNCHANGEABLE: [(&str, &str); 7] = [
    ("sandbox_workspace_bindings", "environment_id"),
    ("sandbox_workspace_bindings", "pod_uid"),
    ("sandbox_workspace_bindings", "claim_uid"),
    ("sandbox_workspace_bindings", "sandbox_uid"),
    ("sandbox_workspace_bindings", "managed_credential_clients"),
    ("sandbox_workspace_bindings", "credential_scope"),
    ("environments", "type"),
];

struct Mutation {
    table: &'static str,
    /// An updated column, or INSERT, DELETE, TRUNCATE or a named no-op.
    change: &'static str,
    sql: String,
    changed: &'static [&'static str],
}

fn mutation(
    table: &'static str,
    change: &'static str,
    sql: impl Into<String>,
    changed: &'static [&'static str],
) -> Mutation {
    Mutation {
        table,
        change,
        sql: sql.into(),
        changed,
    }
}

fn mutations() -> Vec<Mutation> {
    let env = |set: &str| format!("UPDATE environments SET {set} WHERE id='{ENV}'");
    let backend = |set: &str| {
        format!("UPDATE sandbox_environment_backend SET {set} WHERE environment_id='{ENV}'")
    };
    let access = |set: &str| {
        format!(
            "UPDATE platform_environment_access_bindings SET {set} WHERE environment_id='{ENV}'"
        )
    };
    let credential =
        |set: &str| format!("UPDATE platform_credentials SET {set} WHERE id='stamp-codex'");
    let ssh = |set: &str| format!("UPDATE platform_credentials SET {set} WHERE id='stamp-ssh'");
    let mut cases = vec![
        // environments: every input column bumps env; billing alone and a
        // no-op do not.
        mutation(
            "environments",
            "id",
            format!("UPDATE environments SET id='stamp-env-new' WHERE id='{ENV_B}'"),
            &["env-b", "env-new"],
        ),
        mutation(
            "environments",
            "created_by",
            env(&format!("created_by='{OTHER}'")),
            &["env"],
        ),
        mutation(
            "environments",
            "org_id",
            env(&format!("org_id='{ORG_B}'")),
            &["env"],
        ),
        mutation("environments", "state", env("state='stopping'"), &["env"]),
        mutation(
            "environments",
            "desired_state",
            env("desired_state='stopped'"),
            &["env"],
        ),
        mutation(
            "environments",
            "deletion_requested_at",
            env("deletion_requested_at=now()"),
            &["env"],
        ),
        mutation(
            "environments",
            "environment_operation_generation",
            env("environment_operation_generation=environment_operation_generation+1"),
            &["env"],
        ),
        mutation(
            "environments",
            "project_spec",
            env("project_spec=project_spec-'secrets'"),
            &["env"],
        ),
        // Deny-list: a column runtime authority does not read still bumps.
        mutation("environments", "name", env("name='Renamed'"), &["env"]),
        mutation(
            "environments",
            "billing only",
            env("last_billing_event_at=now(), total_running_seconds=total_running_seconds+60"),
            &[],
        ),
        mutation(
            "environments",
            "billing and state",
            env("last_billing_event_at=now(), state='stopping'"),
            &["env"],
        ),
        mutation("environments", "no-op", env("state=state"), &[]),
        mutation(
            "environments",
            "INSERT",
            "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,project_spec) \
             VALUES ('stamp-env-new','stamp-org','stamp-creator','sandbox','stamp-preset','pending','started', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
            &["env-new"],
        ),
        // The cascade removes its backend, bindings and access binding: all
        // of them are the same env scope, and nothing else changes.
        mutation(
            "environments",
            "DELETE",
            format!("DELETE FROM environments WHERE id='{ENV}'"),
            &["env"],
        ),
        // users
        mutation(
            "users",
            "id",
            "INSERT INTO users(id,email) VALUES ('stamp-user-tmp','stamp-tmp@example.test'); \
             UPDATE users SET id='stamp-user-new' WHERE id='stamp-user-tmp'",
            &["user-new"],
        ),
        mutation(
            "users",
            "is_admin",
            format!("UPDATE users SET is_admin=true WHERE id='{CREATOR}'"),
            &["user"],
        ),
        mutation(
            "users",
            "enabled",
            format!("UPDATE users SET enabled=false WHERE id='{CREATOR}'"),
            &["user"],
        ),
        mutation(
            "users",
            "email",
            format!("UPDATE users SET email='moved@example.test' WHERE id='{CREATOR}'"),
            &["user"],
        ),
        mutation(
            "users",
            "no-op",
            format!("UPDATE users SET name=name WHERE id='{CREATOR}'"),
            &[],
        ),
        mutation(
            "users",
            "INSERT",
            "INSERT INTO users(id,email) VALUES ('stamp-user-new','stamp-new@example.test')",
            &["user-new"],
        ),
        // Cascades remove the user's membership and credential.
        mutation(
            "users",
            "DELETE",
            format!("DELETE FROM users WHERE id='{OTHER}'"),
            &["user-other", "creds-other"],
        ),
        // organizations
        mutation(
            "organizations",
            "id",
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('stamp-org-tmp','Tmp','stamp-org-tmp-slug','stamp-creator'); \
             UPDATE organizations SET id='stamp-org-new' WHERE id='stamp-org-tmp'",
            &["org-new"],
        ),
        mutation(
            "organizations",
            "deletion_state",
            format!(
                "UPDATE organizations SET deletion_state='deleting',deletion_generation=1, \
                 deletion_operation_id='stamp-delete',deletion_workflow_id='stamp-delete', \
                 deletion_requested_at=now(),deletion_phase='queued' WHERE id='{ORG}'"
            ),
            &["org"],
        ),
        mutation(
            "organizations",
            "name",
            format!("UPDATE organizations SET name='Renamed' WHERE id='{ORG}'"),
            &["org"],
        ),
        mutation(
            "organizations",
            "no-op",
            format!("UPDATE organizations SET name=name WHERE id='{ORG}'"),
            &[],
        ),
        mutation(
            "organizations",
            "INSERT",
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('stamp-org-new','New','stamp-org-new-slug','stamp-creator')",
            &["org-new"],
        ),
        // Cascades remove the other member's membership and the credential.
        mutation(
            "organizations",
            "DELETE",
            format!("DELETE FROM organizations WHERE id='{ORG_B}'"),
            &["org-b", "user-other", "creds-org-b"],
        ),
        // org_members: keyed by the member's user.
        mutation(
            "org_members",
            "id",
            "UPDATE org_members SET id='stamp-member-moved' WHERE id='stamp-member'",
            &["user"],
        ),
        mutation(
            "org_members",
            "org_id",
            format!("UPDATE org_members SET org_id='{ORG_B}' WHERE id='stamp-member'"),
            &["user"],
        ),
        mutation(
            "org_members",
            "user_id",
            format!("UPDATE org_members SET user_id='{OTHER}' WHERE id='stamp-member'"),
            &["user", "user-other"],
        ),
        mutation(
            "org_members",
            "role",
            "UPDATE org_members SET role='admin' WHERE id='stamp-member'",
            &["user"],
        ),
        mutation(
            "org_members",
            "no-op",
            "UPDATE org_members SET role=role WHERE id='stamp-member'",
            &[],
        ),
        // A new membership.
        mutation(
            "org_members",
            "INSERT",
            format!(
                "INSERT INTO org_members(id,org_id,user_id,role) VALUES ('stamp-member-new','{ORG}','{OTHER}','member')"
            ),
            &["user-other"],
        ),
        mutation(
            "org_members",
            "DELETE",
            "DELETE FROM org_members WHERE id='stamp-member'",
            &["user"],
        ),
        // sandbox_environment_backend
        mutation(
            "sandbox_environment_backend",
            "environment_id",
            backend(&format!(
                "environment_id='{ENV_B}', pod_uid=NULL, bound_at=NULL"
            )),
            &["env", "env-b"],
        ),
        mutation(
            "sandbox_environment_backend",
            "namespace",
            backend("namespace='moved'"),
            &["env"],
        ),
        mutation(
            "sandbox_environment_backend",
            "sandbox_claim_name",
            backend("sandbox_claim_name='moved'"),
            &["env"],
        ),
        mutation(
            "sandbox_environment_backend",
            "sandbox_claim_uid",
            backend("sandbox_claim_uid='4e1b3a52-6f0d-4c7e-9a8b-1c2d3e4f5a69'"),
            &["env"],
        ),
        mutation(
            "sandbox_environment_backend",
            "pod_name",
            backend("pod_name='moved'"),
            &["env"],
        ),
        mutation(
            "sandbox_environment_backend",
            "pod_uid",
            format!(
                "UPDATE sandbox_workspace_bindings SET released_at=now() WHERE pod_uid='{POD}'; \
                 INSERT INTO sandbox_workspace_bindings(pod_uid,environment_id,namespace,pod_name,claim_uid, \
                 sandbox_uid,operation_generation,managed_credential_clients,credential_scope) VALUES \
                 ('{POD_2}','{ENV}','stamp-sandboxes','sandbox-stamp','{CLAIM}','{SANDBOX}',3,'codex','pod'); \
                 {}",
                backend(&format!("pod_uid='{POD_2}'"))
            ),
            &["env"],
        ),
        mutation(
            "sandbox_environment_backend",
            "bound_at",
            backend("bound_at=bound_at+interval '1 second'"),
            &["env"],
        ),
        mutation(
            "sandbox_environment_backend",
            "pod_ip",
            backend("pod_ip='10.0.0.9'"),
            &["env"],
        ),
        mutation(
            "sandbox_environment_backend",
            "no-op",
            backend("setup_phase=setup_phase"),
            &[],
        ),
        mutation(
            "sandbox_environment_backend",
            "INSERT",
            format!(
                "INSERT INTO sandbox_environment_backend(environment_id,namespace) VALUES ('{ENV_B}','stamp-sandboxes')"
            ),
            &["env-b"],
        ),
        mutation(
            "sandbox_environment_backend",
            "DELETE",
            format!("DELETE FROM sandbox_environment_backend WHERE environment_id='{ENV}'"),
            &["env"],
        ),
        // sandbox_workspace_bindings: insert-only except a release; a row
        // leaves only with its environment (the environments DELETE case).
        mutation(
            "sandbox_workspace_bindings",
            "released_at",
            format!(
                "UPDATE sandbox_workspace_bindings SET released_at=now() WHERE pod_uid='{POD}'"
            ),
            &["env"],
        ),
        mutation(
            "sandbox_workspace_bindings",
            "INSERT",
            format!(
                "INSERT INTO sandbox_workspace_bindings(pod_uid,environment_id,namespace,pod_name,claim_uid, \
                 sandbox_uid,operation_generation,managed_credential_clients,credential_scope,released_at) VALUES \
                 ('{POD_2}','{ENV_B}','stamp-sandboxes','sandbox-b','{CLAIM}','{SANDBOX}',1,'','pod',now())"
            ),
            &["env-b"],
        ),
        mutation(
            "sandbox_workspace_bindings",
            "DELETE",
            format!("DELETE FROM environments WHERE id='{ENV}'"),
            &["env"],
        ),
        mutation(
            "sandbox_workspace_bindings",
            "no-op",
            format!(
                "UPDATE sandbox_workspace_bindings SET released_at=released_at WHERE pod_uid='{POD}'"
            ),
            &[],
        ),
        // platform_environment_access_bindings
        mutation(
            "platform_environment_access_bindings",
            "environment_id",
            access(&format!("environment_id='{ENV_B}'")),
            &["env", "env-b"],
        ),
        mutation(
            "platform_environment_access_bindings",
            "profile_id",
            access(&format!("profile_id='{PROFILE_B}'")),
            &["env"],
        ),
        mutation(
            "platform_environment_access_bindings",
            "profile_revision",
            access("profile_revision=2"),
            &["env"],
        ),
        mutation(
            "platform_environment_access_bindings",
            "personal_owner_confirmed_by",
            access("personal_owner_confirmed_by=NULL"),
            &["env"],
        ),
        mutation(
            "platform_environment_access_bindings",
            "no-op",
            access("profile_revision=profile_revision"),
            &[],
        ),
        mutation(
            "platform_environment_access_bindings",
            "INSERT",
            format!(
                "INSERT INTO platform_environment_access_bindings(environment_id,profile_id,profile_revision) \
                 VALUES ('{ENV_B}','{PROFILE_B}',1)"
            ),
            &["env-b"],
        ),
        mutation(
            "platform_environment_access_bindings",
            "DELETE",
            format!(
                "DELETE FROM platform_environment_access_bindings WHERE environment_id='{ENV}'"
            ),
            &["env"],
        ),
        // platform_access_profiles
        mutation(
            "platform_access_profiles",
            "id",
            format!(
                "INSERT INTO platform_access_profiles(id,user_id,name,current_revision) \
                 VALUES ('stamp-profile-tmp','{CREATOR}','Tmp',1); \
                 UPDATE platform_access_profiles SET id='stamp-profile-new' WHERE id='stamp-profile-tmp'"
            ),
            &["profile-new"],
        ),
        mutation(
            "platform_access_profiles",
            "user_id",
            format!("UPDATE platform_access_profiles SET user_id='{OTHER}' WHERE id='{PROFILE}'"),
            &["profile"],
        ),
        mutation(
            "platform_access_profiles",
            "organization_id",
            format!(
                "UPDATE platform_access_profiles SET user_id=NULL, organization_id='{ORG}' WHERE id='{PROFILE}'"
            ),
            &["profile"],
        ),
        mutation(
            "platform_access_profiles",
            "name",
            format!("UPDATE platform_access_profiles SET name='Renamed' WHERE id='{PROFILE}'"),
            &["profile"],
        ),
        mutation(
            "platform_access_profiles",
            "current_revision",
            format!("UPDATE platform_access_profiles SET current_revision=2 WHERE id='{PROFILE}'"),
            &["profile"],
        ),
        mutation(
            "platform_access_profiles",
            "no-op",
            format!("UPDATE platform_access_profiles SET name=name WHERE id='{PROFILE}'"),
            &[],
        ),
        mutation(
            "platform_access_profiles",
            "INSERT",
            format!(
                "INSERT INTO platform_access_profiles(id,user_id,name,current_revision) \
                 VALUES ('stamp-profile-new','{CREATOR}','New',1)"
            ),
            &["profile-new"],
        ),
        // The cascade removes its revisions and entries, all the same scope.
        mutation(
            "platform_access_profiles",
            "DELETE",
            format!("DELETE FROM platform_access_profiles WHERE id='{PROFILE_B}'"),
            &["profile-b"],
        ),
        // platform_access_profile_revisions
        mutation(
            "platform_access_profile_revisions",
            "profile_id",
            format!(
                "DELETE FROM platform_access_profile_entries WHERE profile_id='{PROFILE_B}' AND revision=2; \
                 UPDATE platform_access_profile_revisions SET profile_id='{PROFILE}', revision=3 \
                 WHERE profile_id='{PROFILE_B}' AND revision=2"
            ),
            &["profile", "profile-b"],
        ),
        mutation(
            "platform_access_profile_revisions",
            "revision",
            format!(
                "UPDATE platform_access_profile_revisions SET revision=3 WHERE profile_id='{PROFILE}' AND revision=2"
            ),
            &["profile"],
        ),
        mutation(
            "platform_access_profile_revisions",
            "no-op",
            format!(
                "UPDATE platform_access_profile_revisions SET revision=revision WHERE profile_id='{PROFILE}'"
            ),
            &[],
        ),
        mutation(
            "platform_access_profile_revisions",
            "INSERT",
            format!(
                "INSERT INTO platform_access_profile_revisions(profile_id,revision) VALUES ('{PROFILE}',3)"
            ),
            &["profile"],
        ),
        mutation(
            "platform_access_profile_revisions",
            "DELETE",
            format!(
                "DELETE FROM platform_access_profile_revisions WHERE profile_id='{PROFILE}' AND revision=2"
            ),
            &["profile"],
        ),
        // platform_access_profile_entries
        mutation(
            "platform_access_profile_entries",
            "profile_id",
            format!(
                "UPDATE platform_access_profile_entries SET profile_id='{PROFILE_B}' \
                 WHERE profile_id='{PROFILE}' AND revision=1"
            ),
            &["profile", "profile-b"],
        ),
        mutation(
            "platform_access_profile_entries",
            "revision",
            format!(
                "UPDATE platform_access_profile_entries SET revision=2 WHERE profile_id='{PROFILE}' AND revision=1"
            ),
            &["profile"],
        ),
        mutation(
            "platform_access_profile_entries",
            "capability_slot",
            format!(
                "UPDATE platform_access_profile_entries SET capability_slot='claude' WHERE profile_id='{PROFILE}'"
            ),
            &["profile"],
        ),
        mutation(
            "platform_access_profile_entries",
            "credential_id",
            format!(
                "UPDATE platform_access_profile_entries SET credential_id='stamp-spare' WHERE profile_id='{PROFILE}'"
            ),
            &["profile"],
        ),
        mutation(
            "platform_access_profile_entries",
            "no-op",
            format!(
                "UPDATE platform_access_profile_entries SET credential_id=credential_id WHERE profile_id='{PROFILE}'"
            ),
            &[],
        ),
        mutation(
            "platform_access_profile_entries",
            "INSERT",
            format!(
                "INSERT INTO platform_access_profile_entries(profile_id,revision,capability_slot,credential_id) \
                 VALUES ('{PROFILE}',1,'claude','stamp-spare')"
            ),
            &["profile"],
        ),
        mutation(
            "platform_access_profile_entries",
            "DELETE",
            format!("DELETE FROM platform_access_profile_entries WHERE profile_id='{PROFILE}'"),
            &["profile"],
        ),
        // platform_credentials: keyed by the owner, old and new.
        mutation(
            "platform_credentials",
            "id",
            credential("id='stamp-codex-moved'"),
            &["creds"],
        ),
        mutation(
            "platform_credentials",
            "user_id",
            credential(&format!("user_id='{OTHER}'")),
            &["creds", "creds-other"],
        ),
        mutation(
            "platform_credentials",
            "organization_id",
            credential(&format!("user_id=NULL, organization_id='{ORG}'")),
            &["creds", "creds-org"],
        ),
        mutation(
            "platform_credentials",
            "provider",
            credential("provider='anthropic'"),
            &["creds"],
        ),
        mutation(
            "platform_credentials",
            "authentication_kind",
            credential("authentication_kind='access_token'"),
            &["creds"],
        ),
        mutation(
            "platform_credentials",
            "display_name",
            credential("display_name='Renamed'"),
            &["creds"],
        ),
        mutation(
            "platform_credentials",
            "account_hint",
            credential("account_hint='moved'"),
            &["creds"],
        ),
        mutation(
            "platform_credentials",
            "status",
            credential("status='refresh_failed'"),
            &["creds"],
        ),
        mutation(
            "platform_credentials",
            "expires_at_unix",
            credential("expires_at_unix=1"),
            &["creds"],
        ),
        mutation(
            "platform_credentials",
            "revocation_generation",
            credential("revocation_generation=2"),
            &["creds"],
        ),
        mutation(
            "platform_credentials",
            "material_generation",
            credential("material_generation=2"),
            &["creds"],
        ),
        mutation(
            "platform_credentials",
            "ssh_public_key",
            ssh(&format!(
                "ssh_public_key='{}'",
                SSH_KEY.replace("Example", "Changed")
            )),
            &["creds"],
        ),
        mutation(
            "platform_credentials",
            "ssh_fingerprint",
            ssh(&format!("ssh_fingerprint='SHA256:{}'", "B".repeat(43))),
            &["creds"],
        ),
        mutation(
            "platform_credentials",
            "no-op",
            credential("status=status"),
            &[],
        ),
        // The account's GitHub connection, then a second (revoked) one.
        mutation(
            "platform_credentials",
            "INSERT",
            format!(
                "INSERT INTO platform_credentials(id,user_id,provider,authentication_kind,display_name,status, \
                 revocation_generation,material_generation) \
                 VALUES ('stamp-github','{CREATOR}','github','oauth','GitHub','active',1,1)"
            ),
            &["creds"],
        ),
        mutation(
            "platform_credentials",
            "INSERT second GitHub connection",
            format!(
                "INSERT INTO platform_credentials(id,user_id,provider,authentication_kind,display_name,status, \
                 revocation_generation,material_generation) VALUES \
                 ('stamp-github','{CREATOR}','github','oauth','GitHub','active',1,1); \
                 INSERT INTO platform_credentials(id,user_id,provider,authentication_kind,display_name,status, \
                 revocation_generation,material_generation) VALUES \
                 ('stamp-github-2','{CREATOR}','github','oauth','GitHub 2','revoked',1,1)"
            ),
            &["creds"],
        ),
        mutation(
            "platform_credentials",
            "INSERT organization credential",
            format!(
                "INSERT INTO platform_credentials(id,organization_id,provider,authentication_kind,display_name, \
                 status,revocation_generation,material_generation) \
                 VALUES ('stamp-org-key-2','{ORG}','anthropic','api_key','Second','active',1,1)"
            ),
            &["creds-org"],
        ),
        mutation(
            "platform_credentials",
            "DELETE",
            "DELETE FROM platform_credentials WHERE id='stamp-codex'",
            &["creds"],
        ),
        // secret_projects: keyed by the organization, old and new.
        mutation(
            "secret_projects",
            "id",
            "UPDATE secret_projects SET id='stamp-project-moved' WHERE id='stamp-project'",
            &["org"],
        ),
        mutation(
            "secret_projects",
            "org_id",
            format!("UPDATE secret_projects SET org_id='{ORG_B}' WHERE id='stamp-project'"),
            &["org", "org-b"],
        ),
        mutation(
            "secret_projects",
            "name",
            "UPDATE secret_projects SET name='Renamed' WHERE id='stamp-project'",
            &["org"],
        ),
        mutation(
            "secret_projects",
            "no-op",
            "UPDATE secret_projects SET name=name WHERE id='stamp-project'",
            &[],
        ),
        // A new project.
        mutation(
            "secret_projects",
            "INSERT",
            format!(
                "INSERT INTO secret_projects(id,org_id,name) VALUES ('stamp-project-new','{ORG}','New')"
            ),
            &["org"],
        ),
        mutation(
            "secret_projects",
            "DELETE",
            "DELETE FROM secret_projects WHERE id='stamp-project'",
            &["org"],
        ),
    ];
    // TRUNCATE removes rows without row triggers, so it bumps global only,
    // including for every table it cascades to.
    for table in &STAMPED_TABLES {
        cases.push(mutation(
            table.table,
            "TRUNCATE",
            format!("TRUNCATE public.{} CASCADE", table.table),
            &["global"],
        ));
    }
    cases
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn authority_stamp_every_input_row_and_column_change_advances_only_its_own_scope()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed(&pool).await?;
        let cases = mutations();
        let mut failures = Vec::new();
        for case in &cases {
            let mut tx = pool.begin().await?;
            let before = stamp(&mut tx).await?;
            if let Err(error) = sqlx::raw_sql(&case.sql).execute(&mut *tx).await {
                failures.push(format!("{}.{}: {error}", case.table, case.change));
                tx.rollback().await?;
                continue;
            }
            let after = stamp(&mut tx).await?;
            tx.rollback().await?;
            let observed = changed(&before, &after);
            let expected: BTreeSet<&str> = case.changed.iter().copied().collect();
            if observed != expected {
                failures.push(format!(
                    "{}.{}: changed {observed:?}, expected {expected:?}",
                    case.table, case.change
                ));
            }
        }
        anyhow::ensure!(
            failures.is_empty(),
            "stamp mutations:\n{}",
            failures.join("\n")
        );

        // Coverage: every stamped table is inserted, updated, deleted and
        // truncated, and every input column is changed, or cannot change.
        for table in &STAMPED_TABLES {
            for change in ["INSERT", "DELETE", "TRUNCATE", "no-op"] {
                anyhow::ensure!(
                    cases
                        .iter()
                        .any(|case| case.table == table.table && case.change == change),
                    "{}: no {change} case",
                    table.table
                );
            }
        }
        for (table, columns) in INPUT_COLUMNS {
            anyhow::ensure!(STAMPED_TABLES.iter().any(|stamped| stamped.table == table));
            for column in columns.iter() {
                let updated = cases.iter().any(|case| {
                    case.table == table && case.change == *column && !case.changed.is_empty()
                });
                anyhow::ensure!(
                    updated || UNCHANGEABLE.contains(&(table, *column)),
                    "{table}.{column}: no update case"
                );
            }
        }
        anyhow::ensure!(INPUT_COLUMNS.len() == STAMPED_TABLES.len());

        // The unchangeable input columns are refused in place, so they cannot
        // change without a stamped INSERT or DELETE.
        for (table, column) in UNCHANGEABLE {
            let sql = if table == "environments" {
                format!("UPDATE environments SET type='workspace' WHERE id='{ENV}'")
            } else {
                format!("UPDATE {table} SET {column}=NULL WHERE pod_uid='{POD}'")
            };
            let mut tx = pool.begin().await?;
            let error = sqlx::query(&sql)
                .execute(&mut *tx)
                .await
                .expect_err("unchangeable input column changed");
            tx.rollback().await?;
            anyhow::ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"),
                "{table}.{column}: {error}"
            );
        }

        // Committed bumps are visible to another session, and generations
        // only grow.
        let mut session = PgConnection::connect(&db.url).await?;
        let before = stamp(&mut session).await?;
        sqlx::query("UPDATE org_members SET role='admin' WHERE id='stamp-member'")
            .execute(&pool)
            .await?;
        let after = stamp(&mut session).await?;
        anyhow::ensure!(changed(&before, &after) == BTreeSet::from(["user"]));
        anyhow::ensure!(after[4] > before[4]);
        session.close().await?;
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

/// The startup probe as the migration owner: everything is installed, and
/// the owner, unlike the broker, can write the generation table and sequence.
async fn assert_installed_for_owner(pool: &PgPool) -> anyhow::Result<()> {
    let problems = authority_stamp_schema_problems(pool).await?;
    anyhow::ensure!(
        problems
            == [
                "generation table is writable by this login",
                "generation sequence is usable by this login",
            ],
        "{problems:?}"
    );
    Ok(())
}

/// Every stamp trigger and generation-table guard as `table:name:definition`
/// and its enabled state, deparsed with `search_path = pg_catalog` as the
/// startup probe does.
async fn installed_triggers(pool: &PgPool) -> anyhow::Result<Vec<(String, String)>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_catalog.set_config('search_path', 'pg_catalog', true)")
        .execute(&mut *tx)
        .await?;
    let mut rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname || ':' || t.tgname || ':' || pg_get_triggerdef(t.oid), t.tgenabled::text \
         FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal \
         AND c.relnamespace='public'::regnamespace \
         AND (starts_with(t.tgname,'codewire_stamp_authority_') \
              OR c.relname='platform_authority_generations')",
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.rollback().await?;
    rows.sort();
    Ok(rows)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn authority_stamp_fresh_schema_installs_enabled_triggers_retained_generations_and_reader()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(embedded_max_version()? >= VERSION);
        let measured = fingerprint(&pool).await?;
        anyhow::ensure!(
            measured == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT,
            "authority stamp measured fingerprint: {measured}"
        );
        assert_installed_for_owner(&pool).await?;

        // Every stamped table has its three triggers, enabled, exactly as
        // reviewed, and the generation table its two guards.
        let observed = installed_triggers(&pool).await?;
        let definitions: Vec<String> = observed.iter().map(|row| row.0.clone()).collect();
        let mut expected: Vec<String> = expected_triggers()
            .into_iter()
            .map(|trigger| format!("{}:{}:{}", trigger.table, trigger.name, trigger.definition))
            .collect();
        expected.sort();
        anyhow::ensure!(
            definitions == expected,
            "stamp triggers changed:\n{}",
            definitions.join("\n")
        );
        anyhow::ensure!(observed.iter().all(|row| row.1 == "O"), "a stamp trigger is not enabled");
        // The stamp triggers sort after every other AFTER trigger on their
        // tables, so the generation row is the last lock a statement takes.
        let last: Vec<(String, String)> = sqlx::query_as(
            "SELECT c.relname::text, max(t.tgname)::text FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid \
             WHERE c.relnamespace='public'::regnamespace AND c.relname = ANY($1) \
             AND (t.tgtype & 1) = 1 AND (t.tgtype & 2) = 0 AND (t.tgtype & 64) = 0 \
             GROUP BY c.relname",
        )
        .bind(STAMPED_TABLES.iter().map(|table| table.table).collect::<Vec<_>>())
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(last.len() == STAMPED_TABLES.len());
        anyhow::ensure!(
            last.iter().all(|(_, name)| name == "codewire_stamp_authority_update"),
            "{last:?}"
        );

        // Function authority: migration-owned, fixed search path, executable
        // by no one else. Only the trigger and read functions are definers.
        let functions: Vec<(String, bool, String, String, bool)> = sqlx::query_as(
            "SELECT p.proname::text, p.prosecdef, l.lanname::text, p.provolatile::text, \
             p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[] \
             AND p.proowner=(SELECT c.relowner FROM pg_catalog.pg_class c \
                             WHERE c.oid='public._sqlx_migrations'::regclass) \
             AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(\
                 COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner) \
             FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang \
             WHERE starts_with(p.proname,'codewire_platform_authority_') ORDER BY 1",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            functions
                == [
                    (
                        String::from("codewire_platform_authority_generation_retained"),
                        false,
                        String::from("plpgsql"),
                        String::from("v"),
                        true
                    ),
                    (
                        String::from("codewire_platform_authority_row_changed"),
                        true,
                        String::from("plpgsql"),
                        String::from("v"),
                        true
                    ),
                    (
                        String::from("codewire_platform_authority_stamp"),
                        true,
                        String::from("sql"),
                        String::from("v"),
                        true
                    ),
                ],
            "{functions:?}"
        );

        // Installation bumped global once, from a clock-derived sequence.
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT scope_kind, scope_id, generation FROM platform_authority_generations",
        )
        .fetch_all(&pool)
        .await?;
        let installed_after = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros()
            - 3_600_000_000) as i64;
        anyhow::ensure!(
            matches!(rows.as_slice(), [(kind, id, generation)]
                if kind == "global" && id.is_empty() && *generation > installed_after),
            "{rows:?}"
        );

        // The reader: request order, 0 for a scope never bumped, and no row
        // for malformed input.
        let (generations, observed_at): (Vec<i64>, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT * FROM codewire_platform_authority_stamp(ARRAY['env','global','creds'], \
             ARRAY['stamp-absent','','user:stamp-absent'])",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(generations == [0, rows[0].2, 0], "{generations:?}");
        anyhow::ensure!((chrono::Utc::now() - observed_at).num_seconds().abs() < 60);
        for (kinds, ids) in [
            ("ARRAY[]::text[]", "ARRAY[]::text[]"),
            ("ARRAY['env','env']", "ARRAY['a']"),
            ("ARRAY['env']", "ARRAY['a','b']"),
            ("ARRAY['environment']", "ARRAY['a']"),
            ("ARRAY[NULL::text]", "ARRAY['a']"),
            ("ARRAY['env']", "ARRAY[NULL::text]"),
            ("array_fill('env'::text, ARRAY[17])", "array_fill('a'::text, ARRAY[17])"),
            ("ARRAY[['env']]", "ARRAY[['a']]"),
            // One malformed pair among valid ones refuses the whole read.
            ("ARRAY['global','creds']", "ARRAY['','stamp-creator']"),
        ] {
            let rows: i64 = sqlx::query_scalar(&format!(
                "SELECT count(*) FROM codewire_platform_authority_stamp({kinds},{ids})"
            ))
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(rows == 0, "malformed stamp input {kinds} {ids} returned a row");
        }

        // The reader accepts exactly the (kind, id) pairs the generation table
        // can hold, so a wrongly built key is refused instead of reading a
        // generation of 0 forever.
        for (kind, id, valid) in [
            ("global", "", true),
            ("global", "x", false),
            ("env", "stamp-env", true),
            ("env", "", false),
            ("user", "stamp-creator", true),
            ("user", "", false),
            ("org", "stamp-org", true),
            ("org", "", false),
            ("profile", "stamp-profile", true),
            ("profile", "", false),
            ("creds", "user:stamp-creator", true),
            ("creds", "organization:stamp-org", true),
            ("creds", "stamp-creator", false),
            ("creds", "user:", false),
            ("creds", "organization:", false),
            ("creds", "", false),
            ("environment", "stamp-env", false),
            ("", "", false),
        ] {
            let read: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM codewire_platform_authority_stamp(ARRAY[$1], ARRAY[$2])",
            )
            .bind(kind)
            .bind(id)
            .fetch_one(&pool)
            .await?;
            let mut tx = pool.begin().await?;
            let stored = sqlx::query(
                "INSERT INTO platform_authority_generations(scope_kind,scope_id,generation) \
                 VALUES ($1,$2,1) ON CONFLICT DO NOTHING",
            )
            .bind(kind)
            .bind(id)
            .execute(&mut *tx)
            .await;
            tx.rollback().await?;
            anyhow::ensure!(
                (read == 1) == valid && stored.is_ok() == valid,
                "({kind:?}, {id:?}): reader {read} row(s), table {stored:?}, expected valid={valid}"
            );
        }

        // Generations are never deleted, so a scope can never read 0 again.
        for statement in [
            "DELETE FROM platform_authority_generations",
            "TRUNCATE platform_authority_generations",
        ] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(statement)
                .execute(&mut *tx)
                .await
                .expect_err("authority generation deleted");
            tx.rollback().await?;
            anyhow::ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514")
                    && error.to_string().contains("never deleted"),
                "{statement}: {error}"
            );
        }
        // A key column the row does not have, or a misconfigured trigger,
        // fails the write instead of silently skipping the bump.
        for (arguments, code) in [("'env', 'environment_id'", "42703"), ("'env', 'nope'", "39P01"), ("'env'", "39P01")] {
            let mut tx = pool.begin().await?;
            sqlx::raw_sql(&format!(
                "CREATE TABLE public.stamp_probe(id text); \
                 CREATE TRIGGER stamp_probe AFTER INSERT ON public.stamp_probe FOR EACH ROW \
                 EXECUTE FUNCTION public.codewire_platform_authority_row_changed({arguments});"
            ))
            .execute(&mut *tx)
            .await?;
            let error = sqlx::query("INSERT INTO public.stamp_probe VALUES ('x')")
                .execute(&mut *tx)
                .await
                .expect_err("misconfigured stamp trigger accepted a write");
            tx.rollback().await?;
            anyhow::ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some(code),
                "{arguments}: {error}"
            );
        }
        // The table's own constraints.
        for (kind, id) in [("global", "x"), ("env", ""), ("creds", "x"), ("creds", "user:"), ("member", "x")] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(
                "INSERT INTO platform_authority_generations(scope_kind,scope_id,generation) VALUES ($1,$2,1)",
            )
            .bind(kind)
            .bind(id)
            .execute(&mut *tx)
            .await
            .expect_err("invalid authority scope accepted");
            tx.rollback().await?;
            anyhow::ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"),
                "{kind}:{id}: {error}"
            );
        }
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

/// A restricted login that may write one stamped table needs no grant on the
/// generations; the broker-like login reads only through the function; and
/// the probe reports a missing EXECUTE grant and a disabled trigger.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL with synthetic role creation"]
async fn authority_stamp_restricted_writers_need_no_grant_and_the_probe_finds_gaps()
-> anyhow::Result<()> {
    let admin_url = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin_url).await?;
    let role = format!("cw_authority_stamp_{}", uuid::Uuid::new_v4().simple());
    let mut created_role = false;
    let result = async {
        ensure_schema(&db.url).await?;
        let admin = PgPoolOptions::new().max_connections(2).connect(&db.url).await?;
        seed(&admin).await?;
        // Fixed public synthetic credential, used only with this disposable role.
        const PASSWORD: &str = "synthetic-authority-stamp-test-only";
        let ident = quote_ident(&role);
        sqlx::query(&format!(
            "CREATE ROLE {ident} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS \
             PASSWORD '{PASSWORD}'"
        ))
        .execute(&admin)
        .await?;
        created_role = true;
        for grant in [
            format!("GRANT CONNECT ON DATABASE {} TO {ident}", quote_ident(&db.name)),
            format!("GRANT USAGE ON SCHEMA public TO {ident}"),
            format!("GRANT SELECT,INSERT,UPDATE,DELETE ON public.org_members TO {ident}"),
        ] {
            sqlx::query(&grant).execute(&admin).await?;
        }
        let mut url = url::Url::parse(&db.url)?;
        url.set_username(&role)
            .map_err(|_| anyhow::anyhow!("synthetic role username"))?;
        url.set_password(Some(PASSWORD))
            .map_err(|_| anyhow::anyhow!("synthetic role password"))?;
        let restricted = PgPoolOptions::new().max_connections(1).connect(url.as_str()).await?;
        let result = async {
            // The writer bumps through the definer trigger function.
            let mut session = admin.acquire().await?;
            let before = stamp(&mut session).await?;
            sqlx::query("UPDATE org_members SET role='admin' WHERE id='stamp-member'")
                .execute(&restricted)
                .await?;
            sqlx::query(
                "INSERT INTO org_members(id,org_id,user_id,role) \
                 VALUES ('stamp-restricted','stamp-org','stamp-other','member')",
            )
            .execute(&restricted)
            .await?;
            let after = stamp(&mut session).await?;
            drop(session);
            anyhow::ensure!(changed(&before, &after) == BTreeSet::from(["user", "user-other"]));
            // It cannot read, write or advance the generations itself, call
            // the reader, or run the trigger function.
            for statement in [
                "SELECT * FROM public.platform_authority_generations",
                "INSERT INTO public.platform_authority_generations VALUES ('env','x',1)",
                "UPDATE public.platform_authority_generations SET generation=1",
                "SELECT nextval('public.platform_authority_generation_seq')",
                "SELECT * FROM public.codewire_platform_authority_stamp(ARRAY['global'],ARRAY[''])",
                "SELECT public.codewire_platform_authority_row_changed()",
            ] {
                let error = sqlx::query(statement)
                    .execute(&restricted)
                    .await
                    .expect_err("restricted login reached the authority stamp");
                anyhow::ensure!(
                    error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501"),
                    "{statement}: {error}"
                );
            }
            // The probe reads only the catalog and names the missing grant.
            match verify_authority_stamp_schema(&restricted).await {
                Err(AuthorityStampSchemaError::Incomplete(problems)) => anyhow::ensure!(
                    problems == ["read function is not executable by this login"],
                    "{problems:?}"
                ),
                other => anyhow::bail!("probe accepted a login without EXECUTE: {other:?}"),
            }
            // The deployed broker grant: EXECUTE on the reader only.
            sqlx::query(&format!("GRANT EXECUTE ON FUNCTION {READ_FUNCTION} TO {ident}"))
                .execute(&admin)
                .await?;
            verify_authority_stamp_schema(&restricted).await?;
            let generations: Vec<i64> = sqlx::query_scalar(
                "SELECT generations FROM public.codewire_platform_authority_stamp(ARRAY['user'],ARRAY['stamp-other'])",
            )
            .fetch_one(&restricted)
            .await?;
            anyhow::ensure!(generations == [after[5]]);
            let error = sqlx::query("SELECT * FROM public.platform_authority_generations")
                .execute(&restricted)
                .await
                .expect_err("reader gained table access");
            anyhow::ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some("42501")
            );
            // A disabled trigger stops bumps; the probe reports it until it is
            // enabled again.
            sqlx::query("ALTER TABLE public.platform_credentials DISABLE TRIGGER codewire_stamp_authority_update")
                .execute(&admin)
                .await?;
            match verify_authority_stamp_schema(&restricted).await {
                Err(AuthorityStampSchemaError::Incomplete(problems)) => anyhow::ensure!(
                    problems == ["platform_credentials.codewire_stamp_authority_update is not enabled"],
                    "{problems:?}"
                ),
                other => anyhow::bail!("probe accepted a disabled trigger: {other:?}"),
            }
            sqlx::query("ALTER TABLE public.platform_credentials ENABLE TRIGGER codewire_stamp_authority_update")
                .execute(&admin)
                .await?;
            verify_authority_stamp_schema(&restricted).await?;
            // A broker that could set the sequence back or write a generation
            // could make a changed scope read an old value again.
            for (grant, problem) in [
                (
                    "UPDATE ON SEQUENCE public.platform_authority_generation_seq",
                    "generation sequence is usable by this login",
                ),
                (
                    "USAGE ON SEQUENCE public.platform_authority_generation_seq",
                    "generation sequence is usable by this login",
                ),
                (
                    "SELECT ON SEQUENCE public.platform_authority_generation_seq",
                    "generation sequence is usable by this login",
                ),
                (
                    "UPDATE (generation) ON public.platform_authority_generations",
                    "generation table is writable by this login",
                ),
                (
                    "INSERT ON public.platform_authority_generations",
                    "generation table is writable by this login",
                ),
            ] {
                sqlx::query(&format!("GRANT {grant} TO {ident}"))
                    .execute(&admin)
                    .await?;
                let observed = authority_stamp_schema_problems(&restricted).await;
                sqlx::query(&format!("REVOKE {grant} FROM {ident}"))
                    .execute(&admin)
                    .await?;
                let observed = observed?;
                anyhow::ensure!(observed == [problem], "{grant}: {observed:?}");
            }
            verify_authority_stamp_schema(&restricted).await?;
            Ok(())
        }
        .await;
        restricted.close().await;
        admin.close().await;
        result
    }
    .await;
    let dropped = db.drop().await;
    let role_cleanup = async {
        if created_role {
            let mut admin = PgConnection::connect(&admin_url).await?;
            sqlx::query(&format!("DROP ROLE {}", quote_ident(&role)))
                .execute(&mut admin)
                .await?;
            admin.close().await?;
        }
        Ok(())
    }
    .await;
    result.and(dropped).and(role_cleanup)
}

/// Every pre-existing row an upgrade could touch.
async fn rows(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    let mut result = Vec::new();
    for table in STAMPED_TABLES.iter().map(|table| table.table) {
        result.push(
            sqlx::query_scalar(&format!(
                "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text \
                 FROM public.{table} t"
            ))
            .fetch_one(pool)
            .await?,
        );
    }
    Ok(result)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn authority_stamp_upgrade_preserves34_rows_helpers_and_second_startup() -> anyhow::Result<()>
{
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        anyhow::ensure!(before.len() == 34 && before[33].0 == 34);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT
        );
        seed(&pool).await?;
        let original = rows(&pool).await?;
        let old_helpers = prior_helpers(&pool).await?;
        let old_triggers = prior_triggers(&pool).await?;
        pool.close().await;

        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let after = applied_migrations(&pool).await?;
        anyhow::ensure!(
            after.len() == MIGRATOR.iter().count() && after[..34] == before && after[34].0 == VERSION
        );
        // No existing row changes and no scope is backfilled: every scope
        // reads 0 until its first write, and the global scope is installed.
        anyhow::ensure!(rows(&pool).await? == original);
        anyhow::ensure!(prior_helpers(&pool).await? == old_helpers);
        anyhow::ensure!(prior_triggers(&pool).await? == old_triggers);
        anyhow::ensure!(
            sqlx::query_scalar::<_, Vec<String>>(
                "SELECT array_agg(scope_kind||':'||scope_id) FROM platform_authority_generations"
            )
            .fetch_one(&pool)
            .await?
                == ["global:"]
        );
        let measured = fingerprint(&pool).await?;
        anyhow::ensure!(
            measured == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT,
            "authority stamp measured fingerprint: {measured}"
        );
        assert_installed_for_owner(&pool).await?;
        // Writes after the upgrade bump; a second startup changes nothing.
        let mut session = pool.acquire().await?;
        let first = stamp(&mut session).await?;
        drop(session);
        sqlx::query("UPDATE environments SET state='stopping' WHERE id=$1")
            .bind(ENV)
            .execute(&pool)
            .await?;
        let mut session = pool.acquire().await?;
        let bumped = stamp(&mut session).await?;
        drop(session);
        anyhow::ensure!(changed(&first, &bumped) == BTreeSet::from(["env"]));
        let generations: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT scope_kind, scope_id, generation FROM platform_authority_generations ORDER BY 1,2",
        )
        .fetch_all(&pool)
        .await?;
        let with_stamp = rows(&pool).await?;
        pool.close().await;

        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == after);
        anyhow::ensure!(rows(&pool).await? == with_stamp);
        anyhow::ensure!(
            sqlx::query_as::<_, (String, String, i64)>(
                "SELECT scope_kind, scope_id, generation FROM platform_authority_generations ORDER BY 1,2",
            )
            .fetch_all(&pool)
            .await?
                == generations
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL with event-trigger creation"]
async fn authority_stamp_failed_forward_rolls_back_table_triggers_functions_and_ledger_then_retries()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        seed(&pool).await?;
        let original = rows(&pool).await?;
        let old_helpers = prior_helpers(&pool).await?;
        let old_triggers = prior_triggers(&pool).await?;
        // Fail on the last trigger, after the sequence, table, functions and
        // every other trigger exist.
        sqlx::raw_sql(
            "CREATE SCHEMA migration_failure; CREATE FUNCTION migration_failure.reject_last_trigger() \
             RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN \
             IF (SELECT count(*) FROM pg_trigger WHERE starts_with(tgname,'codewire_stamp_authority_')) = 36 THEN \
             RAISE EXCEPTION 'synthetic failure after the last stamp trigger'; END IF; END; $$; \
             CREATE EVENT TRIGGER stamp_failure ON ddl_command_end WHEN TAG IN ('CREATE TRIGGER') \
             EXECUTE FUNCTION migration_failure.reject_last_trigger();",
        )
        .execute(&pool)
        .await?;
        pool.close().await;
        let error = ensure_schema(&db.url)
            .await
            .err()
            .context("forced migration35 failure accepted")?;
        anyhow::ensure!(format!("{error:#}").contains("synthetic failure after the last stamp trigger"));
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(
            absent(&pool).await?
                && applied_migrations(&pool).await? == before
                && rows(&pool).await? == original
                && prior_helpers(&pool).await? == old_helpers
                && prior_triggers(&pool).await? == old_triggers
        );
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT
        );
        sqlx::raw_sql("DROP EVENT TRIGGER stamp_failure; DROP SCHEMA migration_failure CASCADE;")
            .execute(&pool)
            .await?;
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(
            !absent(&pool).await?
                && applied_migrations(&pool).await?.len() == MIGRATOR.iter().count()
                && rows(&pool).await? == original
        );
        assert_installed_for_owner(&pool).await?;
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

/// The documented in-place rollback. The migration adds only derived state (a
/// table, a sequence, three functions and their triggers), so dropping them
/// and the ledger row restores version 34 without touching any other row.
const AUTHORITY_STAMP_DOWN: &str = "BEGIN; \
    DROP TRIGGER codewire_stamp_authority_row ON public.environments; \
    DROP TRIGGER codewire_stamp_authority_update ON public.environments; \
    DROP TRIGGER codewire_stamp_authority_truncate ON public.environments; \
    DROP TRIGGER codewire_stamp_authority_row ON public.users; \
    DROP TRIGGER codewire_stamp_authority_update ON public.users; \
    DROP TRIGGER codewire_stamp_authority_truncate ON public.users; \
    DROP TRIGGER codewire_stamp_authority_row ON public.organizations; \
    DROP TRIGGER codewire_stamp_authority_update ON public.organizations; \
    DROP TRIGGER codewire_stamp_authority_truncate ON public.organizations; \
    DROP TRIGGER codewire_stamp_authority_row ON public.org_members; \
    DROP TRIGGER codewire_stamp_authority_update ON public.org_members; \
    DROP TRIGGER codewire_stamp_authority_truncate ON public.org_members; \
    DROP TRIGGER codewire_stamp_authority_row ON public.sandbox_environment_backend; \
    DROP TRIGGER codewire_stamp_authority_update ON public.sandbox_environment_backend; \
    DROP TRIGGER codewire_stamp_authority_truncate ON public.sandbox_environment_backend; \
    DROP TRIGGER codewire_stamp_authority_row ON public.sandbox_workspace_bindings; \
    DROP TRIGGER codewire_stamp_authority_update ON public.sandbox_workspace_bindings; \
    DROP TRIGGER codewire_stamp_authority_truncate ON public.sandbox_workspace_bindings; \
    DROP TRIGGER codewire_stamp_authority_row ON public.platform_environment_access_bindings; \
    DROP TRIGGER codewire_stamp_authority_update ON public.platform_environment_access_bindings; \
    DROP TRIGGER codewire_stamp_authority_truncate ON public.platform_environment_access_bindings; \
    DROP TRIGGER codewire_stamp_authority_row ON public.platform_access_profiles; \
    DROP TRIGGER codewire_stamp_authority_update ON public.platform_access_profiles; \
    DROP TRIGGER codewire_stamp_authority_truncate ON public.platform_access_profiles; \
    DROP TRIGGER codewire_stamp_authority_row ON public.platform_access_profile_revisions; \
    DROP TRIGGER codewire_stamp_authority_update ON public.platform_access_profile_revisions; \
    DROP TRIGGER codewire_stamp_authority_truncate ON public.platform_access_profile_revisions; \
    DROP TRIGGER codewire_stamp_authority_row ON public.platform_access_profile_entries; \
    DROP TRIGGER codewire_stamp_authority_update ON public.platform_access_profile_entries; \
    DROP TRIGGER codewire_stamp_authority_truncate ON public.platform_access_profile_entries; \
    DROP TRIGGER codewire_stamp_authority_row ON public.platform_credentials; \
    DROP TRIGGER codewire_stamp_authority_update ON public.platform_credentials; \
    DROP TRIGGER codewire_stamp_authority_truncate ON public.platform_credentials; \
    DROP TRIGGER codewire_stamp_authority_row ON public.secret_projects; \
    DROP TRIGGER codewire_stamp_authority_update ON public.secret_projects; \
    DROP TRIGGER codewire_stamp_authority_truncate ON public.secret_projects; \
    DROP TABLE public.platform_authority_generations; \
    DROP FUNCTION public.codewire_platform_authority_stamp(text[], text[]); \
    DROP FUNCTION public.codewire_platform_authority_row_changed(); \
    DROP FUNCTION public.codewire_platform_authority_generation_retained(); \
    DROP SEQUENCE public.platform_authority_generation_seq; \
    DELETE FROM public._sqlx_migrations WHERE version = 35; \
    COMMIT;";

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn authority_stamp_down_restores34_in_place_and_keeps_every_other_row() -> anyhow::Result<()>
{
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let old_helpers = prior_helpers(&pool).await?;
        let old_triggers = prior_triggers(&pool).await?;
        pool.close().await;
        apply_migrations_before(&db.url, VERSION + 1).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed(&pool).await?;
        let original = rows(&pool).await?;
        let ledger = applied_migrations(&pool).await?;
        anyhow::ensure!(ledger.len() == 35 && ledger[34].0 == VERSION);
        let mut session = pool.acquire().await?;
        let installed = stamp(&mut session).await?;
        drop(session);
        anyhow::ensure!(
            installed
                .iter()
                .filter(|generation| **generation > 0)
                .count()
                > 1
        );

        sqlx::raw_sql(AUTHORITY_STAMP_DOWN).execute(&pool).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger[..34]);
        anyhow::ensure!(absent(&pool).await?);
        anyhow::ensure!(prior_helpers(&pool).await? == old_helpers);
        anyhow::ensure!(prior_triggers(&pool).await? == old_triggers);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT
        );
        anyhow::ensure!(rows(&pool).await? == original);
        // Version-34 writers keep working without the stamp.
        sqlx::query("UPDATE environments SET state='stopping' WHERE id=$1")
            .bind(ENV)
            .execute(&pool)
            .await?;
        let rolled_back = rows(&pool).await?;
        pool.close().await;

        // Rolling forward applies 35 cleanly. Every tuple read now differs
        // from every tuple read before the rollback: the global scope is new
        // and above every earlier value, although the write above was not
        // stamped.
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        anyhow::ensure!(applied_migrations(&pool).await?.len() == MIGRATOR.iter().count());
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);
        anyhow::ensure!(rows(&pool).await? == rolled_back);
        assert_installed_for_owner(&pool).await?;
        let mut session = pool.acquire().await?;
        let reinstalled = stamp(&mut session).await?;
        drop(session);
        anyhow::ensure!(reinstalled[0] > *installed.iter().max().unwrap_or(&0));
        anyhow::ensure!(reinstalled[1..].iter().all(|generation| *generation == 0));
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn authority_stamp_rollback_replays34_only_in_disposable_application_schema()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        seed(&pool).await?;
        let old_helpers = prior_helpers(&pool).await?;
        let ledger = applied_migrations(&pool).await?;
        sqlx::raw_sql(
            "CREATE SCHEMA rollback_boundary; CREATE TABLE rollback_boundary.keep(id integer); \
             INSERT INTO rollback_boundary.keep VALUES(1); DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
        )
        .execute(&pool)
        .await?;
        pool.close().await;
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger[..34]);
        let prior_checksum: String = sqlx::query_scalar(
            "SELECT encode(checksum,'hex') FROM public._sqlx_migrations WHERE version=34 AND success",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(prior_checksum == PRIOR34);
        anyhow::ensure!(absent(&pool).await? && prior_helpers(&pool).await? == old_helpers);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT
        );
        anyhow::ensure!(
            sqlx::query_scalar::<_, bool>(
                "SELECT NOT EXISTS(SELECT 1 FROM environments) \
                 AND NOT EXISTS(SELECT 1 FROM platform_credentials)"
            )
            .fetch_one(&pool)
            .await?
        );
        anyhow::ensure!(
            sqlx::query_scalar::<_, i32>("SELECT id FROM rollback_boundary.keep")
                .fetch_one(&pool)
                .await?
                == 1
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
