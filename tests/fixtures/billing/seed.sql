-- Contract-suite fixture for the billing service.
--
-- Loaded by CI (build-test.yml integration + kind-e2e jobs) after
-- the baseline schema, before the billing Connect contract runs with
-- BILLING_SEEDED=1. The plan keys and tokens here are asserted by
-- crates/codewire-billing/tests/wire_contract.rs — keep the fixture and
-- retained Connect assertions in sync.
--
-- The schema baseline now materializes the default catalog (#69), so
-- every catalog insert here is ON CONFLICT DO NOTHING: fixture rows
-- that collide with a default (org/starter) defer to it — the values
-- are identical by construction.
--
-- Session tokens are non-secret fixture values in an ephemeral CI database.
-- Even fixtures store only their digests so rehearsal covers the production
-- hash-only shape.

INSERT INTO users (id, email, email_verified, name, is_admin)
VALUES
    ('usr_contract_admin', 'contract-admin@codewire.test', true, 'Contract Admin', true),
    ('usr_contract_user',  'contract-user@codewire.test',  true, 'Contract User',  false);

-- ip_address/user_agent are set (not NULL) to match the production session
-- shape exercised by the Rust authentication boundary.
INSERT INTO sessions (id, user_id, token_hash, expires_at, ip_address, user_agent)
VALUES
    ('ses_contract_admin', 'usr_contract_admin', encode(digest('contract-admin-session-token', 'sha256'), 'hex'), NOW() + INTERVAL '4 hours', '127.0.0.1', 'contract-suite'),
    ('ses_contract_user',  'usr_contract_user',  encode(digest('contract-user-session-token', 'sha256'), 'hex'),  NOW() + INTERVAL '4 hours', '127.0.0.1', 'contract-suite'),
    -- Expired on purpose: presenting it must yield 401, and the sliding-
    -- expiry UPDATE must not resurrect it.
    ('ses_contract_stale', 'usr_contract_user',  encode(digest('contract-stale-session-token', 'sha256'), 'hex'), NOW() - INTERVAL '1 minute', '127.0.0.1', 'contract-suite');

INSERT INTO billing_catalog_plans (
    resource_type, plan_key, display_name, price_cents,
    included_devs, max_concurrent_ws, max_team_members,
    storage_gb, is_contact_us, is_admin_only,
    included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours,
    cpu_overage_cents, mem_overage_cents, disk_overage_cents,
    archived_at
) VALUES
    ('org', 'starter', 'Starter', 4900,
     1, 5, 1,
     50, false, false,
     0, 0, 0,
     0, 0, 0,
     NULL),
    ('sandbox', 'standard', 'Standard', 900,
     1, 5, 5,
     20, false, false,
     100, 200, 300,
     0.5, 0.25, 0.125,
     NULL),
    ('sandbox', 'internal-admin', 'Internal (admin only)', 0,
     1, 50, 50,
     200, false, true,
     1000, 2000, 3000,
     0, 0, 0,
     NULL),
    ('sandbox', 'legacy', 'Legacy (archived)', 500,
     1, 1, 1,
     10, false, false,
     50, 100, 150,
     1.0, 0.5, 0.25,
     NOW())
ON CONFLICT (resource_type, plan_key) DO NOTHING;

INSERT INTO billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id)
VALUES ('sandbox', 'standard', 'test', 'subscription', 'price_contract_fixture')
ON CONFLICT (resource_type, plan_key, stripe_mode, price_kind) DO NOTHING;

INSERT INTO billing_catalog_settings (setting_key, int_value)
VALUES ('trial_days', 14)
ON CONFLICT (setting_key) DO NOTHING;

-- Org-scoped billing fixture: both contract users are members of
-- org_contract_1 (admin=owner, user=member), so an unknown org ID exercises
-- the 404 path. org_checkout_guard is a separate owner-only fixture for
-- checkout duplicate-subscription assertions; it keeps org_contract_1 overview
-- expectations stable.
INSERT INTO organizations (id, name, slug, created_by, created_at, updated_at)
VALUES
    ('org_contract_1', 'Contract Org', 'contract-org', 'usr_contract_admin', NOW(), NOW()),
    ('org_checkout_guard', 'Checkout Guard Org', 'checkout-guard', 'usr_contract_admin', NOW(), NOW());

-- Fixed created_at (not NOW()) so the members list is deterministic and
-- ORDER BY created_at ASC is stable: admin (owner) first, then the member.
INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
VALUES
    ('orgm_contract_1', 'org_contract_1', 'usr_contract_admin', 'owner',  '2026-01-10 00:00:00', '2026-01-10 00:00:00'),
    ('orgm_contract_2', 'org_contract_1', 'usr_contract_user',  'member', '2026-01-11 00:00:00', '2026-01-11 00:00:00'),
    ('orgm_checkout_guard_1', 'org_checkout_guard', 'usr_contract_admin', 'owner', '2026-01-12 00:00:00', '2026-01-12 00:00:00');

-- Fixed cw_ API key for the Connect contract suite (connectcore): the
-- machine-credential flavor. Raw value (never stored):
--   cw_c0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0de
-- key_hash is SHA-256 of the full raw string; key_prefix the 8 hex chars
-- after cw_ (the indexed lookup), matching auth.HashAPIKey/PrefixFromKey.
INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix)
VALUES
    ('ak_contract_1', 'usr_contract_user', 'org_contract_1', 'connectcore-contract-key',
     '71d95780c239ca3bbf72d107828808437d5d105d0cc5a894c98e6984ee4613c4', 'c0dec0de');

-- Fixed opaque OIDC product bearer for the ingress Connect-auth and
-- coordinator boundary. Raw value (never stored):
-- at_kind_connect_oidc_codewire_api. It carries exactly the product scope and
-- belongs to the non-admin contract user.
INSERT INTO oidc_clients (id, name, application_type, auth_method, redirect_uris)
VALUES ('oidc_kind_connect', 'Kind Connect contract', 'native', 'none',
        ARRAY['http://localhost:9878/callback']);

INSERT INTO oidc_access_tokens (token_hash, client_id, user_id, scopes, expires_at)
VALUES (encode(digest('at_kind_connect_oidc_codewire_api', 'sha256'), 'hex'),
        'oidc_kind_connect', 'usr_contract_user', ARRAY['openid', 'codewire.api'],
        NOW() + INTERVAL '4 hours');

-- Seeded assignments for the member (orgm_contract_2) so the assignments GET
-- is deterministic.
-- ORDER BY assignment -> developer, viewer.
INSERT INTO org_member_assignments (id, org_member_id, assignment, granted_by)
VALUES
    ('omasn_contract_1', 'orgm_contract_2', 'developer', 'usr_contract_admin'),
    ('omasn_contract_2', 'orgm_contract_2', 'viewer',    'usr_contract_admin');

-- A seeded PENDING invitation in org_contract_1 (fixed id/capability/timestamps,
-- expires in the future) drives the invitations list, the 409 "pending
-- invitation already exists" create branch, and the revoke success/404 rows.
-- invited_by = the org owner.
INSERT INTO org_invitations (id, org_id, email, role, invited_by, token_hash, status, expires_at, created_at, assignments)
VALUES ('inv_contract_1', 'org_contract_1', 'invitee@codewire.test', 'member', 'usr_contract_admin',
        encode(digest('invtoken_contract_1', 'sha256'), 'hex'), 'pending',
        '2027-01-01 00:00:00', '2026-01-20 00:00:00', ARRAY['viewer']);

-- A seeded empty secret project (org_id FK → organizations). Encrypted values
-- are created through the API so fixtures never duplicate envelope logic.
INSERT INTO secret_projects (id, org_id, name, created_at)
VALUES ('secproj_contract_1', 'org_contract_1', 'contract-project', '2026-01-05 00:00:00');

-- One invoice fully populated (billing periods set — the case the Go
-- handler silently dropped), one with the nullable columns NULL.
INSERT INTO stripe_invoices (id, org_id, stripe_invoice_id, status, amount_due, amount_paid, currency,
                             hosted_invoice_url, invoice_pdf, period_start, period_end, created_at)
VALUES
    ('inv_fixture_1', 'org_contract_1', 'in_fixture_1', 'paid', 4900, 4900, 'usd',
     'https://stripe.test/hosted', 'https://stripe.test/pdf',
     '2026-05-01 00:00:00', '2026-06-01 00:00:00', '2026-06-02 10:30:00'),
    ('inv_fixture_2', 'org_contract_1', 'in_fixture_2', 'open', 900, 0, 'usd',
     NULL, NULL, NULL, NULL, '2026-06-03 11:00:00');

-- One event with metadata + amount, one with the nullable columns NULL.
INSERT INTO billing_events (event_type, org_id, amount_cents, currency, stripe_item_id, metadata, created_at)
VALUES
    ('invoice_paid', 'org_contract_1', 4900, 'usd', 'in_fixture_1',
     '{"source":"fixture"}', '2026-06-02 10:30:00+00'),
    ('environment_usage', 'org_contract_1', NULL, 'usd', NULL,
     '{"elapsed_seconds":3600,"cpu_millicores":2000,"memory_mb":4096}', '2026-06-05 09:00:00+00');

-- Effective-plan + usage fixture for the overview/usage endpoints:
-- an active environment subscription (the highest-priority source in
-- ResolveEffectiveOrgEnvironmentPlan), one environment with legacy accrued
-- runtime, and one canonical sandbox-running-session row. The session row
-- intentionally differs from the retired billing_events/environment totals so
-- the contract catches regressions to the stale usage stream.
INSERT INTO environment_subscriptions (id, org_id, plan, status, stripe_subscription_id, created_at, updated_at)
VALUES ('envsub_contract_1', 'org_contract_1', 'starter', 'active', 'sub_contract_fixture', NOW(), NOW());

INSERT INTO org_subscriptions (id, org_id, plan, status, stripe_subscription_id, created_at, updated_at)
VALUES ('orgsub_checkout_guard_1', 'org_checkout_guard', 'starter', 'active', 'sub_checkout_guard_fixture', NOW(), NOW());

-- Org-scoped so createEnvironment's preset_id path accepts it. The foreign
-- preset belongs to a different organization; global presets are always
-- explicitly official after the clean cutover.
INSERT INTO environment_presets (id, org_id, name, project_spec)
VALUES ('preset_contract_1', 'org_contract_1', 'contract-preset', '{"schema_version":1,"working_directory":"/workspace"}'::jsonb);

INSERT INTO environment_presets (id, org_id, name, project_spec)
VALUES ('preset_contract_foreign', 'org_checkout_guard', 'contract-preset-foreign', '{"schema_version":1,"working_directory":"/workspace"}'::jsonb);

-- Slugged + a pre-registered port: pin the slug-conflict (409) and
-- port-conflict (409) branches with idempotent checks.
INSERT INTO environment_presets (id, org_id, name, slug, project_spec)
VALUES ('preset_contract_slugged', 'org_contract_1', 'contract-preset-slugged', 'contract', '{"schema_version":1,"working_directory":"/workspace"}'::jsonb);

INSERT INTO environments (id, org_id, created_by, type, state, name, preset_id, cpu_millicores, memory_mb, total_running_seconds, project_spec)
VALUES ('env_contract_1', 'org_contract_1', 'usr_contract_user', 'sandbox', 'running', 'contract-env', 'preset_contract_1', 2000, 4096, 7200, '{"schema_version":1,"working_directory":"/workspace"}'::jsonb);

INSERT INTO sandbox_running_sessions (
    id, environment_id, organization_id, runtime_type, runtime_uid,
    runtime_name, runtime_namespace, cpu_millicores, memory_mib, disk_gib,
    runtime_class, started_at, last_observed_at, ended_at, end_reason,
    created_at, updated_at
)
VALUES (
    'srs_contract_1', 'env_contract_1', 'org_contract_1', 'sandbox',
    'runtime-contract-1', 'contract-env', 'default', 1000, 2048, 7,
    'kata-qemu', date_trunc('month', now()),
    date_trunc('month', now()) + interval '2 hours',
    date_trunc('month', now()) + interval '2 hours',
    'completed', now(), now()
);

-- Admin-created + destroyed: exercises the environments read surface's
-- access-denied path (the contract user is neither creator nor org
-- admin and holds no grant) and the include_destroyed list filter,
-- WITHOUT touching billing usage aggregates (destroyed is excluded).
INSERT INTO environments (id, org_id, created_by, type, state, name, preset_id, cpu_millicores, memory_mb, total_running_seconds, destroyed_at, project_spec)
VALUES ('env_contract_2', 'org_contract_1', 'usr_contract_admin', 'sandbox', 'destroyed', 'contract-env-destroyed', 'preset_contract_1', 1000, 2048, 60, NOW(), '{"schema_version":1,"working_directory":"/workspace"}'::jsonb);

INSERT INTO environment_ports (id, environment_id, port, label, access)
VALUES ('port_contract_1', 'env_contract_1', 3000, 'web', 'creator');

-- Second org (user-only membership): reaches the logs handler's
-- org-mismatch 404 (an env the caller can access, via an org it does
-- not belong to). Unknown-org billing 404 checks are unaffected.
INSERT INTO organizations (id, name, slug, created_by, created_at, updated_at)
VALUES ('org_contract_2', 'Contract Org Two', 'contract-org-two', 'usr_contract_user', NOW(), NOW());

INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
VALUES ('orgm_contract_3', 'org_contract_2', 'usr_contract_user', 'owner', NOW(), NOW());

-- Throwaway second member of org_contract_2 (owner = usr_contract_user),
-- dedicated to the member role-change/remove contract cycle: it is promoted
-- then deleted in-test. Lives in org_contract_2 so it does NOT perturb the
-- org_contract_1 members-list row (#215).
INSERT INTO users (id, email, email_verified, name, is_admin)
VALUES ('usr_contract_member2', 'member2@codewire.test', true, 'Contract Member Two', false);

INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
VALUES ('orgm_contract_4', 'org_contract_2', 'usr_contract_member2', 'member', '2026-01-12 00:00:00', '2026-01-12 00:00:00');

-- Two pending invitations in org_contract_2 (owner = usr_contract_user) for
-- the revoke success + 404 "already processed" cycle. org_contract_2
-- invitations are not listed by the org_contract_1 contract rows, so these
-- don't perturb the org_contract_1 list.
INSERT INTO org_invitations (id, org_id, email, role, invited_by, token_hash, status, expires_at, created_at, assignments)
VALUES
    ('inv_rev_go', 'org_contract_2', 'revgo@codewire.test', 'member', 'usr_contract_user', encode(digest('tok_rev_go', 'sha256'), 'hex'), 'pending', '2027-01-01 00:00:00', '2026-01-22 00:00:00', ARRAY['viewer']),
    ('inv_rev_rs', 'org_contract_2', 'revrs@codewire.test', 'member', 'usr_contract_user', encode(digest('tok_rev_rs', 'sha256'), 'hex'), 'pending', '2027-01-01 00:00:00', '2026-01-22 00:00:00', ARRAY['viewer']);

-- Invitation-accept fixtures. A revoked invitation (400 "invitation is
-- revoked", status-checked before email) and an email-mismatch pending one
-- (403) are non-mutating, shared safely. For the SUCCESS path (mints
-- membership — non-idempotent), each fixture invitation addresses
-- usr_contract_user's email (contract-user@codewire.test). usr_contract_user
-- is not a member of org_contract_3/4.
INSERT INTO organizations (id, name, slug, created_by, created_at, updated_at)
VALUES
    ('org_contract_3', 'Contract Org Three', 'contract-org-three', 'usr_contract_admin', NOW(), NOW()),
    ('org_contract_4', 'Contract Org Four',  'contract-org-four',  'usr_contract_admin', NOW(), NOW());

INSERT INTO org_invitations (id, org_id, email, role, invited_by, token_hash, status, expires_at, created_at, assignments)
VALUES
    ('inv_accept_revoked',  'org_contract_1', 'whoever@codewire.test',      'member', 'usr_contract_admin', encode(digest('tok_accept_revoked', 'sha256'), 'hex'),  'revoked', '2027-01-01 00:00:00', '2026-01-23 00:00:00', ARRAY['viewer']),
    ('inv_accept_mismatch', 'org_contract_1', 'someone-else@codewire.test', 'member', 'usr_contract_admin', encode(digest('tok_accept_mismatch', 'sha256'), 'hex'), 'pending', '2027-01-01 00:00:00', '2026-01-23 00:00:00', ARRAY['viewer']),
    ('inv_accept_go', 'org_contract_3', 'contract-user@codewire.test', 'member', 'usr_contract_admin', encode(digest('tok_accept_go', 'sha256'), 'hex'), 'pending', '2027-01-01 00:00:00', '2026-01-24 00:00:00', ARRAY['viewer']),
    ('inv_accept_rs', 'org_contract_4', 'contract-user@codewire.test', 'member', 'usr_contract_admin', encode(digest('tok_accept_rs', 'sha256'), 'hex'), 'pending', '2027-01-01 00:00:00', '2026-01-24 00:00:00', ARRAY['viewer']);

-- Terminal log fixture: the SSE stream closes after the initial batch
-- (phase=complete), making the stream diffable end-to-end. Fixed
-- timestamps pin created_at ordering and rendering.
INSERT INTO environment_logs (id, environment_id, phase, status, message, metadata, created_at)
VALUES
    ('log_contract_1', 'env_contract_2', 'setup', 'completed', 'setup finished', '{"step": 1}', '2026-06-01 10:00:00+00'),
    ('log_contract_2', 'env_contract_2', 'complete', 'completed', NULL, NULL, '2026-06-01 10:00:01+00');

-- Admin audit-log fixture (#38): a single deterministic row with a UNIQUE
-- action so the admin audit-log contract can filter to exactly it. user_id
-- joins to usr_contract_admin for the email; metadata is fixed jsonb.
INSERT INTO audit_logs (id, "timestamp", action, user_id, ip_address, user_agent, metadata, severity)
VALUES ('audit_contract_1', '2026-01-15 12:00:00', 'contract.audit.fixture', 'usr_contract_admin',
        '203.0.113.7', 'contract-suite', '{"n": 1, "resource": "fixture"}', 'info');

-- Admin lifecycle-journal fixture (#38): a dedicated env in org_contract_2
-- (which has NO env-list contract row, so it doesn't perturb the env read
-- surface) + one deterministic journal entry. The admin journal
-- query is by environment_id, so this env is never touched by the
-- env-lifecycle contract rows (those use env_contract_1/2).
INSERT INTO environments (id, org_id, created_by, type, state, name, preset_id, cpu_millicores, memory_mb, total_running_seconds, project_spec)
VALUES ('env_contract_journal', 'org_contract_2', 'usr_contract_user', 'sandbox', 'running', 'contract-env-journal', 'preset_contract_foreign', 1000, 2048, 0, '{"schema_version":1,"working_directory":"/workspace"}'::jsonb);

INSERT INTO environment_lifecycle_journal
    (id, environment_id, kind, actor, phase, status, from_state, to_state, checkpoint, reason, metadata, created_at)
VALUES ('elj_contract_1', 'env_contract_journal', 'transition', 'usr_contract_admin',
        'provision', 'completed', 'pending', 'running', 'ckpt-1', 'manual start',
        '{"k": "v"}', '2026-02-01 09:00:00+00');

-- Admin startup timing fixture (#38): recent phase logs on the same
-- dedicated environment. Timestamps are relative so the startup-summary
-- percentile window includes them whenever the contract runs.
INSERT INTO environment_logs (id, environment_id, phase, status, message, metadata, created_at)
VALUES
    ('log_startup_1', 'env_contract_journal', 'create_claim', 'completed', 'claim created', '{"duration_ms": 100}', NOW() - INTERVAL '4 minutes'),
    ('log_startup_2', 'env_contract_journal', 'wait_for_ready', 'completed', 'sandbox ready', '{"duration_ms": 250.9}', NOW() - INTERVAL '3 minutes'),
    ('log_startup_3', 'env_contract_journal', 'gateway_ready', 'completed', NULL, '{"duration_ms": 75}', NOW() - INTERVAL '2 minutes'),
    ('log_startup_4', 'env_contract_journal', 'file_ready', 'completed', NULL, NULL, NOW() - INTERVAL '1 minute');
