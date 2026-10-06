//! Disposable-PostgreSQL proof of which bindings the credential relay serves.
//! Only synthetic rows in an isolated test database are used.

use anyhow::{Result, ensure};

use super::*;
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "relay-creator";
const ORGANIZATION: &str = "relay-organization";
const PRESET: &str = "relay-preset";
const NAMESPACE: &str = "relay-sandboxes";
const OTHER_NAMESPACE: &str = "relay-other-sandboxes";

struct Environment {
    id: &'static str,
    namespace: &'static str,
}

const LIVE: Environment = Environment {
    id: "6f1d1e9a-0b1c-4a52-9a4e-2c1f00000001",
    namespace: NAMESPACE,
};
const RELEASED: Environment = Environment {
    id: "6f1d1e9a-0b1c-4a52-9a4e-2c1f00000002",
    namespace: NAMESPACE,
};
const UNBOUND: Environment = Environment {
    id: "6f1d1e9a-0b1c-4a52-9a4e-2c1f00000003",
    namespace: NAMESPACE,
};
const ELSEWHERE: Environment = Environment {
    id: "6f1d1e9a-0b1c-4a52-9a4e-2c1f00000004",
    namespace: OTHER_NAMESPACE,
};

async fn seed(db: &TestDatabase, environment: &Environment) -> Result<()> {
    sqlx::query(
        "INSERT INTO environments \
         (id,org_id,created_by,preset_id,type,state,desired_state,project_spec, \
          environment_operation_generation) \
         VALUES ($1,$2,$3,$4,'sandbox','running','started', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb,3)",
    )
    .bind(environment.id)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO sandbox_environment_backend \
         (environment_id,namespace,sandbox_claim_name,sandbox_claim_uid) VALUES ($1,$2,$3,$4)",
    )
    .bind(environment.id)
    .bind(environment.namespace)
    .bind(format!("sandbox-{}", environment.id))
    .bind(Uuid::new_v4().to_string())
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// Binds a fresh Pod of `environment` at `generation`, releasing any earlier
/// binding, as the recorder does. Returns the new Pod's UID.
async fn bind(db: &TestDatabase, environment: &Environment, generation: i64) -> Result<String> {
    let pod_uid = Uuid::new_v4().to_string();
    let mut tx = db.pool.begin().await?;
    sqlx::query(
        "UPDATE sandbox_workspace_bindings SET released_at = GREATEST(now(), bound_at) \
          WHERE environment_id = $1 AND released_at IS NULL",
    )
    .bind(environment.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO sandbox_workspace_bindings(pod_uid,environment_id,namespace,pod_name, \
           claim_uid,sandbox_uid,operation_generation,managed_credential_clients,credential_scope) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pod')",
    )
    .bind(&pod_uid)
    .bind(environment.id)
    .bind(environment.namespace)
    .bind(format!("pod-{pod_uid}"))
    .bind(Uuid::new_v4().to_string())
    .bind(Uuid::new_v4().to_string())
    .bind(generation)
    .bind(codewire_access::ManagedCredentialClients::default().encode())
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE sandbox_environment_backend SET pod_uid = $2, bound_at = now() \
          WHERE environment_id = $1",
    )
    .bind(environment.id)
    .bind(&pod_uid)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(pod_uid)
}

async fn release(db: &TestDatabase, environment: &Environment) -> Result<()> {
    let mut tx = db.pool.begin().await?;
    sqlx::query(
        "UPDATE sandbox_workspace_bindings SET released_at = GREATEST(now(), bound_at) \
          WHERE environment_id = $1 AND released_at IS NULL",
    )
    .bind(environment.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE sandbox_environment_backend SET pod_uid = NULL, bound_at = NULL \
          WHERE environment_id = $1",
    )
    .bind(environment.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

fn target(environment: &Environment, pod_uid: &str, generation: u64) -> Target {
    Target {
        environment_id: Uuid::parse_str(environment.id).unwrap(),
        pod_uid: pod_uid.to_owned(),
        generation,
        scope: WorkspaceCredentialScope::Pod,
    }
}

/// Every seeded environment is running, so the broker can admit each.
fn running(environment: &Environment, pod_uid: &str, generation: u64) -> Live {
    Live {
        target: target(environment, pod_uid, generation),
        admissible: true,
    }
}

async fn set_state(
    db: &TestDatabase,
    environment: &Environment,
    state: &str,
    desired: &str,
) -> Result<()> {
    sqlx::query("UPDATE environments SET state = $2, desired_state = $3 WHERE id = $1")
        .bind(environment.id)
        .bind(state)
        .bind(desired)
        .execute(&db.pool)
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_relay_serves_exactly_the_live_bindings_of_its_namespace() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user(CREATOR).await?;
        db.organization(ORGANIZATION).await?;
        sqlx::query(
            "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
             VALUES ($1,$2,'Relay','relay', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
        )
        .bind(PRESET)
        .bind(ORGANIZATION)
        .execute(&db.pool)
        .await?;
        for environment in [&LIVE, &RELEASED, &UNBOUND, &ELSEWHERE] {
            seed(&db, environment).await?;
        }
        ensure!(live_targets(&db.pool, NAMESPACE).await?.is_empty());

        let live = bind(&db, &LIVE, 3).await?;
        bind(&db, &RELEASED, 3).await?;
        let elsewhere = bind(&db, &ELSEWHERE, 3).await?;
        release(&db, &RELEASED).await?;
        let targets = live_targets(&db.pool, NAMESPACE).await?;
        ensure!(targets == [running(&LIVE, &live, 3)], "{targets:?}");
        ensure!(
            live_targets(&db.pool, OTHER_NAMESPACE).await? == [running(&ELSEWHERE, &elsewhere, 3)]
        );
        // The pass for one environment reads only its binding, in its
        // namespace.
        let live_id = Uuid::parse_str(LIVE.id)?;
        ensure!(live_target(&db.pool, NAMESPACE, live_id).await? == Some(running(&LIVE, &live, 3)));
        ensure!(
            live_target(&db.pool, OTHER_NAMESPACE, live_id)
                .await?
                .is_none()
        );
        ensure!(
            live_target(&db.pool, NAMESPACE, Uuid::parse_str(RELEASED.id)?)
                .await?
                .is_none()
        );

        // Bound while it starts: relayed, but the broker cannot admit it
        // until it runs; nor once it is asked to stop.
        for (state, desired) in [
            ("creating", "started"),
            ("starting", "started"),
            ("running", "stopped"),
        ] {
            set_state(&db, &LIVE, state, desired).await?;
            let starting = live_target(&db.pool, NAMESPACE, live_id).await?;
            ensure!(
                starting
                    == Some(Live {
                        target: target(&LIVE, &live, 3),
                        admissible: false,
                    }),
                "{state}/{desired}: {starting:?}"
            );
        }
        set_state(&db, &LIVE, "running", "started").await?;

        // A replaced Pod is a different relay target, and the released
        // binding before it is never served again.
        let replacement = bind(&db, &LIVE, 4).await?;
        let targets = live_targets(&db.pool, NAMESPACE).await?;
        ensure!(targets == [running(&LIVE, &replacement, 4)], "{targets:?}");
        let plan = plan(
            [target(&LIVE, &live, 3)].iter(),
            &[target(&LIVE, &replacement, 4)],
        );
        ensure!(plan.stop == [live_id]);
        ensure!(plan.start == [target(&LIVE, &replacement, 4)]);

        // A stop releases the binding: nothing is relayed for it.
        release(&db, &LIVE).await?;
        ensure!(live_targets(&db.pool, NAMESPACE).await?.is_empty());
        Ok(())
    }
    .await;
    db.finish(result).await
}
