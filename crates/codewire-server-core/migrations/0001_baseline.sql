-- Codewire application schema baseline.
-- Generated from the accepted pre-launch application schema.
-- Future schema changes are immutable migrations beginning at 0002.

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TABLE public.accounts (
    id text NOT NULL,
    user_id text NOT NULL,
    provider_id text NOT NULL,
    account_id text NOT NULL,
    password text,
    access_token text,
    refresh_token text,
    access_token_expires_at timestamp without time zone,
    refresh_token_expires_at timestamp without time zone,
    scope text,
    id_token text,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);

CREATE TABLE public.admin_invoice_credits (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    stripe_invoice_id text NOT NULL,
    credit_kind text NOT NULL,
    amount_cents integer NOT NULL,
    stripe_invoice_item_id text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.api_keys (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    user_id text NOT NULL,
    org_id text NOT NULL,
    name text NOT NULL,
    key_hash text NOT NULL,
    key_prefix text NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    last_used_at timestamp without time zone,
    expires_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    disabled_at timestamp without time zone
);

CREATE TABLE public.audit_logs (
    id text NOT NULL,
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL,
    action text NOT NULL,
    user_id text,
    target_user_id text,
    ip_address text,
    user_agent text,
    metadata jsonb,
    severity text DEFAULT 'info'::text NOT NULL
);

CREATE TABLE public.billing_catalog_plans (
    resource_type text NOT NULL,
    plan_key text NOT NULL,
    display_name text NOT NULL,
    price_cents integer NOT NULL,
    included_devs integer DEFAULT 0 NOT NULL,
    max_concurrent_ws integer DEFAULT 0 NOT NULL,
    max_team_members integer DEFAULT 0 NOT NULL,
    storage_gb integer DEFAULT 0 NOT NULL,
    is_contact_us boolean DEFAULT false NOT NULL,
    is_admin_only boolean DEFAULT false NOT NULL,
    included_cpu_hours integer DEFAULT 0 NOT NULL,
    included_mem_gb_hours integer DEFAULT 0 NOT NULL,
    included_disk_gb_hours integer DEFAULT 0 NOT NULL,
    cpu_overage_cents double precision DEFAULT 0 NOT NULL,
    mem_overage_cents double precision DEFAULT 0 NOT NULL,
    disk_overage_cents double precision DEFAULT 0 NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    archived_at timestamp without time zone
);

CREATE TABLE public.billing_catalog_prices (
    resource_type text NOT NULL,
    plan_key text NOT NULL,
    stripe_mode text NOT NULL,
    price_kind text DEFAULT 'subscription'::text NOT NULL,
    stripe_price_id text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    archived_at timestamp without time zone,
    CONSTRAINT billing_catalog_prices_kind_check CHECK ((price_kind = ANY (ARRAY['subscription'::text, 'seat_addon'::text]))),
    CONSTRAINT billing_catalog_prices_mode_check CHECK ((stripe_mode = ANY (ARRAY['test'::text, 'live'::text])))
);

CREATE TABLE public.billing_catalog_settings (
    setting_key text NOT NULL,
    int_value integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.billing_catalog_subscription_migrations (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    resource_type text NOT NULL,
    source_plan_key text NOT NULL,
    target_plan_key text NOT NULL,
    target_stripe_price_id text NOT NULL,
    proration_behavior text DEFAULT 'none'::text NOT NULL,
    migrated_count integer DEFAULT 0 NOT NULL,
    skipped_count integer DEFAULT 0 NOT NULL,
    failed_count integer DEFAULT 0 NOT NULL,
    created_by text,
    metadata jsonb,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.billing_events (
    id bigint NOT NULL,
    event_type text NOT NULL,
    org_id text,
    amount_cents integer,
    currency text DEFAULT 'usd'::text,
    stripe_item_id text,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.billing_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.billing_events_id_seq OWNED BY public.billing_events.id;

CREATE TABLE public.data_deletion_requests (
    id text NOT NULL,
    user_id text NOT NULL,
    requested_at timestamp without time zone DEFAULT now() NOT NULL,
    scheduled_for timestamp without time zone NOT NULL,
    completed_at timestamp without time zone,
    status text DEFAULT 'pending'::text NOT NULL,
    deleted_data jsonb
);

CREATE TABLE public.device_auth_codes (
    id text NOT NULL,
    device_code text NOT NULL,
    user_code text NOT NULL,
    user_id text,
    status text DEFAULT 'pending'::text NOT NULL,
    ip_address text,
    user_agent text,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.environment_access (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    environment_id text NOT NULL,
    user_id text NOT NULL,
    permission text NOT NULL,
    granted_by text NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    CONSTRAINT environment_access_permission_check CHECK ((permission = ANY (ARRAY['owner'::text, 'operator'::text, 'viewer'::text])))
);

CREATE TABLE public.environment_lifecycle_journal (
    id text NOT NULL,
    environment_id text NOT NULL,
    kind text NOT NULL,
    actor text NOT NULL,
    phase text,
    status text,
    from_state text,
    to_state text,
    checkpoint text,
    reason text,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.environment_logs (
    id text NOT NULL,
    environment_id text NOT NULL,
    phase text NOT NULL,
    status text NOT NULL,
    message text,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.environment_operation_generation_claims (
    environment_id text NOT NULL,
    workflow_run_id text NOT NULL,
    generation bigint NOT NULL,
    scheduled_at_unix_nanos bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT environment_operation_generation__scheduled_at_unix_nanos_check CHECK ((scheduled_at_unix_nanos >= 0)),
    CONSTRAINT environment_operation_generation_claims_generation_check CHECK ((generation > 0)),
    CONSTRAINT environment_operation_generation_claims_workflow_run_id_check CHECK ((btrim(workflow_run_id) <> ''::text))
);

CREATE TABLE public.environment_ports (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    environment_id text NOT NULL,
    port integer NOT NULL,
    label text NOT NULL,
    access text DEFAULT 'creator'::text NOT NULL,
    dns_record_id text,
    created_at timestamp without time zone DEFAULT now(),
    deletion_requested_at timestamp without time zone,
    CONSTRAINT environment_ports_access_check CHECK ((access = ANY (ARRAY['public'::text, 'org_members'::text, 'creator'::text]))),
    CONSTRAINT environment_ports_label_check CHECK ((label ~ '^[a-z0-9][a-z0-9-]{0,20}[a-z0-9]$'::text)),
    CONSTRAINT environment_ports_port_check CHECK (((port > 0) AND (port < 65536)))
);

CREATE TABLE public.environment_presets (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text,
    name text NOT NULL,
    slug text,
    description text,
    official boolean DEFAULT false,
    language text,
    build_status text DEFAULT 'ready'::text NOT NULL,
    build_error text,
    default_cpu_millicores integer DEFAULT 2000 NOT NULL,
    default_memory_mb integer DEFAULT 4096 NOT NULL,
    default_disk_gb integer DEFAULT 10 NOT NULL,
    default_ttl_seconds integer,
    default_setup_config jsonb,
    default_secret_project_id text,
    created_at timestamp without time zone DEFAULT now()
);

CREATE TABLE public.environment_quotas (
    org_id text NOT NULL,
    max_concurrent_environments integer DEFAULT 10 NOT NULL,
    max_concurrent_sandbox integer DEFAULT 50 NOT NULL,
    max_cpu_millicores integer DEFAULT 32000 NOT NULL,
    max_memory_mb integer DEFAULT 65536 NOT NULL
);

CREATE TABLE public.environment_sessions (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    environment_id text NOT NULL,
    name text NOT NULL,
    pid integer,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    ended_at timestamp without time zone,
    CONSTRAINT environment_sessions_status_check CHECK ((status = ANY (ARRAY['active'::text, 'ended'::text, 'error'::text])))
);

CREATE TABLE public.environment_subscriptions (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    plan text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    stripe_subscription_id text,
    stripe_price_id text,
    trial_start timestamp without time zone,
    trial_end timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);

CREATE TABLE public.environment_usage_billing (
    org_id text NOT NULL,
    billing_period_start timestamp without time zone NOT NULL,
    last_cpu_hours double precision DEFAULT 0 NOT NULL,
    last_mem_gb_hours double precision DEFAULT 0 NOT NULL,
    last_disk_gb_hours double precision DEFAULT 0 NOT NULL,
    last_overage_cents integer DEFAULT 0 NOT NULL,
    stripe_invoice_item_id text,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.environments (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    created_by text NOT NULL,
    type text NOT NULL,
    name text,
    state text DEFAULT 'pending'::text NOT NULL,
    desired_state text DEFAULT 'started'::text NOT NULL,
    error_reason text,
    recoverable boolean DEFAULT true NOT NULL,
    state_changed_at timestamp without time zone DEFAULT now() NOT NULL,
    retry_count integer DEFAULT 0 NOT NULL,
    ttl_seconds integer,
    shutdown_at timestamp without time zone,
    cpu_millicores integer DEFAULT 2000 NOT NULL,
    memory_mb integer DEFAULT 4096 NOT NULL,
    disk_gb integer DEFAULT 10 NOT NULL,
    auth_token text,
    last_billing_event_at timestamp without time zone,
    total_running_seconds integer DEFAULT 0 NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    started_at timestamp without time zone,
    stopped_at timestamp without time zone,
    destroyed_at timestamp without time zone,
    setup_config jsonb,
    secret_project_id text,
    preset_id text,
    deletion_requested_at timestamp without time zone,
    deletion_requested_by text,
    deletion_grace_until timestamp without time zone,
    protected boolean DEFAULT false NOT NULL,
    ttl_warning_sent_at timestamp without time zone,
    environment_operation_generation bigint DEFAULT 0 NOT NULL,
    external_cleanup_completed_at timestamp without time zone,
    CONSTRAINT chk_env_preset_id CHECK (((type <> 'sandbox'::text) OR (preset_id IS NOT NULL))),
    CONSTRAINT environments_desired_state_check CHECK ((desired_state = ANY (ARRAY['started'::text, 'stopped'::text, 'destroyed'::text, 'archived'::text, 'resized'::text]))),
    CONSTRAINT environments_external_cleanup_completed_check CHECK (((external_cleanup_completed_at IS NULL) OR ((state = 'destroyed'::text) AND (desired_state = 'destroyed'::text)))),
    CONSTRAINT environments_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'pending_build'::text, 'building'::text, 'build_failed'::text, 'pulling_snapshot'::text, 'creating'::text, 'starting'::text, 'running'::text, 'stopping'::text, 'stopped'::text, 'archiving'::text, 'archived'::text, 'restoring'::text, 'resizing'::text, 'destroying'::text, 'destroyed'::text, 'error'::text, 'unknown'::text]))),
    CONSTRAINT environments_type_check CHECK ((type = 'sandbox'::text))
);

CREATE TABLE public.github_oauth_states (
    state text NOT NULL,
    user_id text NOT NULL,
    return_url text DEFAULT ''::text NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

CREATE TABLE public.jwks (
    id text NOT NULL,
    public_key text NOT NULL,
    created_at timestamp without time zone NOT NULL,
    expires_at timestamp without time zone,
    private_key_ciphertext bytea,
    private_key_nonce bytea,
    private_key_kek_id text,
    private_key_format smallint,
    CONSTRAINT jwks_private_key_envelope_shape_check CHECK ((num_nonnulls(private_key_ciphertext, private_key_nonce, private_key_kek_id, private_key_format) = ANY (ARRAY[0, 4])))
);

CREATE TABLE public.local_secrets (
    path text NOT NULL,
    key text NOT NULL,
    value text DEFAULT ''::text NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);

CREATE TABLE public.oidc_access_tokens (
    token_hash text NOT NULL,
    client_id text NOT NULL,
    user_id text NOT NULL,
    scopes text[] NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.oidc_auth_requests (
    id text NOT NULL,
    client_id text NOT NULL,
    scopes text[] NOT NULL,
    redirect_uri text NOT NULL,
    state text,
    nonce text,
    response_type text DEFAULT 'code'::text NOT NULL,
    response_mode text,
    code_challenge text,
    code_challenge_method text,
    audience text[],
    user_id text,
    auth_time timestamp with time zone,
    code text,
    done boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

CREATE TABLE public.oidc_clients (
    id text NOT NULL,
    secret text,
    name text,
    application_type text DEFAULT 'web'::text NOT NULL,
    auth_method text DEFAULT 'client_secret_basic'::text NOT NULL,
    redirect_uris text[] NOT NULL,
    post_logout_redirect_uris text[],
    grant_types text[] DEFAULT '{authorization_code}'::text[] NOT NULL,
    response_types text[] DEFAULT '{code}'::text[] NOT NULL,
    scopes text[] DEFAULT '{openid,profile,email}'::text[] NOT NULL,
    skip_consent boolean DEFAULT true NOT NULL,
    access_token_lifetime interval DEFAULT '01:00:00'::interval NOT NULL,
    refresh_token_lifetime interval,
    id_token_lifetime interval DEFAULT '01:00:00'::interval NOT NULL,
    clock_skew interval DEFAULT '00:00:00'::interval NOT NULL,
    disabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.oidc_refresh_tokens (
    id text NOT NULL,
    token_hash text NOT NULL,
    client_id text NOT NULL,
    user_id text NOT NULL,
    scopes text[] NOT NULL,
    audience text[],
    auth_time timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.org_invitations (
    id text NOT NULL,
    org_id text NOT NULL,
    email text NOT NULL,
    role text DEFAULT 'member'::text NOT NULL,
    invited_by text NOT NULL,
    token text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    accepted_at timestamp without time zone,
    assignments text[] DEFAULT ARRAY['viewer'::text] NOT NULL
);

CREATE TABLE public.org_member_assignments (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_member_id text NOT NULL,
    assignment text NOT NULL,
    granted_by text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT org_member_assignments_assignment_check CHECK ((assignment = ANY (ARRAY['viewer'::text, 'developer'::text, 'environments_admin'::text, 'sandboxes_admin'::text, 'billing_admin'::text, 'auditor'::text, 'super_admin'::text])))
);

CREATE TABLE public.org_members (
    id text NOT NULL,
    org_id text NOT NULL,
    user_id text NOT NULL,
    role text DEFAULT 'member'::text NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);

CREATE TABLE public.org_subscriptions (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    plan text DEFAULT 'starter'::text NOT NULL,
    status text DEFAULT 'trialing'::text NOT NULL,
    stripe_subscription_id text,
    seat_count integer DEFAULT 0 NOT NULL,
    trial_start timestamp without time zone,
    trial_end timestamp without time zone,
    current_period_start timestamp without time zone,
    current_period_end timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);

CREATE TABLE public.organization_deletion_operations (
    id text NOT NULL,
    organization_id text NOT NULL,
    generation bigint NOT NULL,
    requested_by text NOT NULL,
    workflow_id text NOT NULL,
    state text DEFAULT 'pending_start'::text NOT NULL,
    phase text DEFAULT 'write_fenced'::text NOT NULL,
    failure_code text,
    start_attempts integer DEFAULT 0 NOT NULL,
    last_start_attempt_at timestamp without time zone,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_deletion_operations_failure_code_check CHECK (((failure_code IS NULL) OR (failure_code ~ '^[a-z0-9_]{1,128}$'::text))),
    CONSTRAINT organization_deletion_operations_generation_check CHECK ((generation > 0)),
    CONSTRAINT organization_deletion_operations_phase_check CHECK ((phase ~ '^[a-z0-9_]{1,128}$'::text)),
    CONSTRAINT organization_deletion_operations_start_attempts_check CHECK ((start_attempts >= 0)),
    CONSTRAINT organization_deletion_operations_state_check CHECK ((state = ANY (ARRAY['pending_start'::text, 'started'::text, 'failed'::text, 'completed'::text]))),
    CONSTRAINT organization_deletion_operations_terminal_metadata_check CHECK ((((state = 'pending_start'::text) AND (started_at IS NULL) AND (completed_at IS NULL) AND (failure_code IS NULL)) OR ((state = 'started'::text) AND (started_at IS NOT NULL) AND (completed_at IS NULL) AND (failure_code IS NULL)) OR ((state = 'failed'::text) AND (completed_at IS NULL) AND (failure_code IS NOT NULL)) OR ((state = 'completed'::text) AND (completed_at IS NOT NULL) AND (failure_code IS NULL))))
);

CREATE TABLE public.organization_mutation_leases (
    id text NOT NULL,
    organization_id text NOT NULL,
    mutation_class text NOT NULL,
    state text DEFAULT 'active'::text NOT NULL,
    admitted_at timestamp without time zone DEFAULT now() NOT NULL,
    deadline_at timestamp without time zone NOT NULL,
    released_at timestamp without time zone,
    resolution_required_at timestamp without time zone,
    resolved_at timestamp without time zone,
    recovery_code text,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_mutation_leases_class_check CHECK ((mutation_class = ANY (ARRAY['control_plane_database'::text, 'environment_runtime_dispatch'::text, 'tenant_secret_provider'::text, 'billing_provider'::text]))),
    CONSTRAINT organization_mutation_leases_deadline_check CHECK ((deadline_at > admitted_at)),
    CONSTRAINT organization_mutation_leases_recovery_code_check CHECK (((recovery_code IS NULL) OR (recovery_code ~ '^[a-z0-9_]{1,128}$'::text))),
    CONSTRAINT organization_mutation_leases_state_check CHECK ((state = ANY (ARRAY['active'::text, 'released'::text, 'resolution_required'::text, 'resolved'::text]))),
    CONSTRAINT organization_mutation_leases_terminal_metadata_check CHECK ((((state = 'active'::text) AND (released_at IS NULL) AND (resolution_required_at IS NULL) AND (resolved_at IS NULL) AND (recovery_code IS NULL)) OR ((state = 'released'::text) AND (released_at IS NOT NULL) AND (resolution_required_at IS NULL) AND (resolved_at IS NULL) AND (recovery_code IS NULL)) OR ((state = 'resolution_required'::text) AND (released_at IS NULL) AND (resolution_required_at IS NOT NULL) AND (resolved_at IS NULL) AND (recovery_code IS NOT NULL)) OR ((state = 'resolved'::text) AND (released_at IS NULL) AND (resolution_required_at IS NOT NULL) AND (resolved_at IS NOT NULL) AND (recovery_code IS NOT NULL))))
);

CREATE TABLE public.organizations (
    id text NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    created_by text NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    stripe_customer_id text,
    billing_plan text DEFAULT 'none'::text NOT NULL,
    billing_status text DEFAULT 'none'::text NOT NULL,
    trial_ends_at timestamp without time zone,
    deletion_state text DEFAULT 'active'::text NOT NULL,
    deletion_generation bigint DEFAULT 0 NOT NULL,
    deletion_requested_by text,
    deletion_requested_at timestamp without time zone,
    deletion_operation_id text,
    deletion_workflow_id text,
    deletion_phase text,
    deletion_failure_code text,
    CONSTRAINT organizations_deletion_failure_code_check CHECK (((deletion_failure_code IS NULL) OR (deletion_failure_code ~ '^[a-z0-9_]{1,128}$'::text))),
    CONSTRAINT organizations_deletion_generation_check CHECK ((deletion_generation >= 0)),
    CONSTRAINT organizations_deletion_metadata_check CHECK ((((deletion_state = 'active'::text) AND (deletion_operation_id IS NULL) AND (deletion_workflow_id IS NULL) AND (deletion_requested_by IS NULL) AND (deletion_requested_at IS NULL) AND (deletion_phase IS NULL) AND (deletion_failure_code IS NULL)) OR ((deletion_state = 'deleting'::text) AND (deletion_generation > 0) AND (deletion_operation_id IS NOT NULL) AND (deletion_workflow_id IS NOT NULL) AND (deletion_requested_at IS NOT NULL) AND (deletion_phase IS NOT NULL) AND (deletion_failure_code IS NULL)) OR ((deletion_state = 'delete_failed'::text) AND (deletion_generation > 0) AND (deletion_operation_id IS NOT NULL) AND (deletion_workflow_id IS NOT NULL) AND (deletion_requested_at IS NOT NULL) AND (deletion_phase IS NOT NULL) AND (deletion_failure_code IS NOT NULL)))),
    CONSTRAINT organizations_deletion_phase_check CHECK (((deletion_phase IS NULL) OR (deletion_phase ~ '^[a-z0-9_]{1,128}$'::text))),
    CONSTRAINT organizations_deletion_state_check CHECK ((deletion_state = ANY (ARRAY['active'::text, 'deleting'::text, 'delete_failed'::text])))
);

CREATE TABLE public.rate_limit (
    id text NOT NULL,
    key text NOT NULL,
    count integer NOT NULL,
    last_request bigint NOT NULL
);

CREATE TABLE public.repo_configs (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    repo_url text NOT NULL,
    preset_id text,
    setup_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_by text NOT NULL,
    updated_at timestamp without time zone DEFAULT now()
);

CREATE TABLE public.runtime_transport_zones (
    name text NOT NULL,
    runtime_region text NOT NULL,
    peer_relay jsonb DEFAULT '{}'::jsonb NOT NULL,
    direct_udp jsonb DEFAULT '{}'::jsonb NOT NULL,
    stun jsonb DEFAULT '{}'::jsonb NOT NULL,
    derp jsonb DEFAULT '{}'::jsonb NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.sandbox_environment_backend (
    environment_id text NOT NULL,
    namespace text NOT NULL,
    sandbox_claim_name text,
    pod_name text,
    pod_ip text,
    agent_port integer DEFAULT 9090 NOT NULL,
    snapshot_ref text,
    setup_phase integer DEFAULT 0 NOT NULL,
    setup_complete boolean DEFAULT false NOT NULL,
    setup_error text,
    wireguard_public_key text,
    sandbox_claim_uid text,
    setup_owner_generation bigint,
    setup_owner_activity_id text,
    setup_owner_attempt integer,
    setup_owner_phase integer,
    setup_owner_status text,
    setup_owner_pod_uid text,
    CONSTRAINT chk_sandbox_setup_owner_coherent CHECK ((((setup_owner_generation IS NULL) AND (setup_owner_activity_id IS NULL) AND (setup_owner_attempt IS NULL) AND (setup_owner_phase IS NULL) AND (setup_owner_status IS NULL) AND (setup_owner_pod_uid IS NULL)) OR ((setup_owner_generation IS NOT NULL) AND (setup_owner_generation > 0) AND (setup_owner_activity_id IS NOT NULL) AND (btrim(setup_owner_activity_id) <> ''::text) AND (setup_owner_attempt IS NOT NULL) AND (setup_owner_attempt > 0) AND (setup_owner_phase IS NOT NULL) AND (setup_owner_phase >= 0) AND (setup_owner_status IS NOT NULL) AND (((setup_owner_status = 'claimed'::text) AND (setup_owner_pod_uid IS NULL)) OR ((setup_owner_status = ANY (ARRAY['running'::text, 'reaping'::text])) AND (setup_owner_pod_uid IS NOT NULL) AND (btrim(setup_owner_pod_uid) <> ''::text))))))
);

CREATE TABLE public.sandbox_running_sessions (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    environment_id text NOT NULL,
    organization_id text NOT NULL,
    runtime_type text DEFAULT 'sandbox'::text NOT NULL,
    runtime_uid text NOT NULL,
    runtime_name text NOT NULL,
    runtime_namespace text NOT NULL,
    cpu_millicores integer NOT NULL,
    memory_mib integer NOT NULL,
    disk_gib integer NOT NULL,
    runtime_class text,
    started_at timestamp with time zone NOT NULL,
    last_observed_at timestamp with time zone NOT NULL,
    ended_at timestamp with time zone,
    end_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.sandbox_template_config (
    preset_id text NOT NULL,
    image_ref text NOT NULL,
    sandbox_template_name text NOT NULL,
    persistent_storage boolean DEFAULT false NOT NULL
);

CREATE TABLE public.secret_projects (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    name text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.sessions (
    id text NOT NULL,
    user_id text NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    ip_address text,
    user_agent text,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    token_hash text NOT NULL,
    CONSTRAINT sessions_token_hash_format_check CHECK (((token_hash IS NULL) OR (token_hash ~ '^[0-9a-f]{64}$'::text)))
);

CREATE TABLE public.stripe_invoices (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    stripe_invoice_id text NOT NULL,
    stripe_subscription_id text,
    status text NOT NULL,
    amount_due integer NOT NULL,
    amount_paid integer DEFAULT 0 NOT NULL,
    currency text DEFAULT 'usd'::text NOT NULL,
    hosted_invoice_url text,
    invoice_pdf text,
    period_start timestamp without time zone,
    period_end timestamp without time zone,
    receipt_sent_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);

CREATE TABLE public.stripe_webhook_events (
    id text NOT NULL,
    event_type text NOT NULL,
    processed_at timestamp without time zone DEFAULT now()
);

CREATE TABLE public.two_factor (
    id text NOT NULL,
    user_id text NOT NULL,
    secret text,
    backup_codes text
);

CREATE TABLE public.two_factor_tokens (
    id text NOT NULL,
    user_id text NOT NULL,
    token text NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT now()
);

CREATE TABLE public.user_git_credentials (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    host text NOT NULL,
    auth_type text NOT NULL,
    username text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.user_github_tokens (
    user_id text NOT NULL,
    access_token text NOT NULL,
    refresh_token text,
    token_type text DEFAULT 'bearer'::text NOT NULL,
    expires_at timestamp with time zone,
    refresh_token_expires_at timestamp with time zone,
    installation_id bigint,
    github_username text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.user_login_keys (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    user_id text NOT NULL,
    name text NOT NULL,
    public_key text NOT NULL,
    fingerprint text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.user_ssh_keys (
    user_id text NOT NULL,
    public_key text NOT NULL,
    key_fingerprint text NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    regenerated_at timestamp without time zone
);

CREATE TABLE public.users (
    id text NOT NULL,
    email text NOT NULL,
    email_verified boolean DEFAULT false,
    name text,
    image text,
    is_admin boolean DEFAULT false,
    two_factor_enabled boolean DEFAULT false,
    failed_login_attempts integer DEFAULT 0,
    locked_until timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    git_name text,
    git_email text
);

CREATE TABLE public.verifications (
    id text NOT NULL,
    identifier text NOT NULL,
    value text NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);

ALTER TABLE ONLY public.billing_events ALTER COLUMN id SET DEFAULT nextval('public.billing_events_id_seq'::regclass);

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.admin_invoice_credits
    ADD CONSTRAINT admin_invoice_credits_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.admin_invoice_credits
    ADD CONSTRAINT admin_invoice_credits_stripe_invoice_id_credit_kind_key UNIQUE (stripe_invoice_id, credit_kind);

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.billing_catalog_plans
    ADD CONSTRAINT billing_catalog_plans_pkey PRIMARY KEY (resource_type, plan_key);

ALTER TABLE ONLY public.billing_catalog_prices
    ADD CONSTRAINT billing_catalog_prices_pkey PRIMARY KEY (resource_type, plan_key, stripe_mode, price_kind);

ALTER TABLE ONLY public.billing_catalog_settings
    ADD CONSTRAINT billing_catalog_settings_pkey PRIMARY KEY (setting_key);

ALTER TABLE ONLY public.billing_catalog_subscription_migrations
    ADD CONSTRAINT billing_catalog_subscription_migrations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.billing_events
    ADD CONSTRAINT billing_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.data_deletion_requests
    ADD CONSTRAINT data_deletion_requests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.device_auth_codes
    ADD CONSTRAINT device_auth_codes_device_code_key UNIQUE (device_code);

ALTER TABLE ONLY public.device_auth_codes
    ADD CONSTRAINT device_auth_codes_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.device_auth_codes
    ADD CONSTRAINT device_auth_codes_user_code_key UNIQUE (user_code);

ALTER TABLE ONLY public.environment_access
    ADD CONSTRAINT environment_access_environment_id_user_id_key UNIQUE (environment_id, user_id);

ALTER TABLE ONLY public.environment_access
    ADD CONSTRAINT environment_access_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.environment_lifecycle_journal
    ADD CONSTRAINT environment_lifecycle_journal_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.environment_logs
    ADD CONSTRAINT environment_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.environment_operation_generation_claims
    ADD CONSTRAINT environment_operation_generation__environment_id_generation_key UNIQUE (environment_id, generation);

ALTER TABLE ONLY public.environment_operation_generation_claims
    ADD CONSTRAINT environment_operation_generation_claims_pkey PRIMARY KEY (environment_id, workflow_run_id);

ALTER TABLE ONLY public.environment_ports
    ADD CONSTRAINT environment_ports_environment_id_label_key UNIQUE (environment_id, label);

ALTER TABLE ONLY public.environment_ports
    ADD CONSTRAINT environment_ports_environment_id_port_key UNIQUE (environment_id, port);

ALTER TABLE ONLY public.environment_ports
    ADD CONSTRAINT environment_ports_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.environment_presets
    ADD CONSTRAINT environment_presets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.environment_quotas
    ADD CONSTRAINT environment_quotas_pkey PRIMARY KEY (org_id);

ALTER TABLE ONLY public.environment_sessions
    ADD CONSTRAINT environment_sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.environment_subscriptions
    ADD CONSTRAINT environment_subscriptions_org_id_key UNIQUE (org_id);

ALTER TABLE ONLY public.environment_subscriptions
    ADD CONSTRAINT environment_subscriptions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.environment_subscriptions
    ADD CONSTRAINT environment_subscriptions_stripe_subscription_id_key UNIQUE (stripe_subscription_id);

ALTER TABLE ONLY public.environment_usage_billing
    ADD CONSTRAINT environment_usage_billing_pkey PRIMARY KEY (org_id, billing_period_start);

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.github_oauth_states
    ADD CONSTRAINT github_oauth_states_pkey PRIMARY KEY (state);

ALTER TABLE ONLY public.jwks
    ADD CONSTRAINT jwks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.local_secrets
    ADD CONSTRAINT local_secrets_pkey PRIMARY KEY (path, key);

ALTER TABLE ONLY public.oidc_access_tokens
    ADD CONSTRAINT oidc_access_tokens_pkey PRIMARY KEY (token_hash);

ALTER TABLE ONLY public.oidc_auth_requests
    ADD CONSTRAINT oidc_auth_requests_code_key UNIQUE (code);

ALTER TABLE ONLY public.oidc_auth_requests
    ADD CONSTRAINT oidc_auth_requests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oidc_clients
    ADD CONSTRAINT oidc_clients_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oidc_refresh_tokens
    ADD CONSTRAINT oidc_refresh_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oidc_refresh_tokens
    ADD CONSTRAINT oidc_refresh_tokens_token_key UNIQUE (token_hash);

ALTER TABLE ONLY public.org_invitations
    ADD CONSTRAINT org_invitations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.org_invitations
    ADD CONSTRAINT org_invitations_token_key UNIQUE (token);

ALTER TABLE ONLY public.org_member_assignments
    ADD CONSTRAINT org_member_assignments_org_member_id_assignment_key UNIQUE (org_member_id, assignment);

ALTER TABLE ONLY public.org_member_assignments
    ADD CONSTRAINT org_member_assignments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.org_members
    ADD CONSTRAINT org_members_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.org_subscriptions
    ADD CONSTRAINT org_subscriptions_org_id_key UNIQUE (org_id);

ALTER TABLE ONLY public.org_subscriptions
    ADD CONSTRAINT org_subscriptions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.org_subscriptions
    ADD CONSTRAINT org_subscriptions_stripe_subscription_id_key UNIQUE (stripe_subscription_id);

ALTER TABLE ONLY public.organization_deletion_operations
    ADD CONSTRAINT organization_deletion_operations_org_generation_key UNIQUE (organization_id, generation);

ALTER TABLE ONLY public.organization_deletion_operations
    ADD CONSTRAINT organization_deletion_operations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.organization_deletion_operations
    ADD CONSTRAINT organization_deletion_operations_workflow_id_key UNIQUE (workflow_id);

ALTER TABLE ONLY public.organization_mutation_leases
    ADD CONSTRAINT organization_mutation_leases_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_slug_key UNIQUE (slug);

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_stripe_customer_id_key UNIQUE (stripe_customer_id);

ALTER TABLE ONLY public.rate_limit
    ADD CONSTRAINT rate_limit_key_key UNIQUE (key);

ALTER TABLE ONLY public.rate_limit
    ADD CONSTRAINT rate_limit_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.repo_configs
    ADD CONSTRAINT repo_configs_org_id_repo_url_key UNIQUE (org_id, repo_url);

ALTER TABLE ONLY public.repo_configs
    ADD CONSTRAINT repo_configs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.runtime_transport_zones
    ADD CONSTRAINT runtime_transport_zones_pkey PRIMARY KEY (name);

ALTER TABLE ONLY public.sandbox_environment_backend
    ADD CONSTRAINT sandbox_environment_backend_pkey PRIMARY KEY (environment_id);

ALTER TABLE ONLY public.sandbox_running_sessions
    ADD CONSTRAINT sandbox_running_sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sandbox_template_config
    ADD CONSTRAINT sandbox_template_config_pkey PRIMARY KEY (preset_id);

ALTER TABLE ONLY public.secret_projects
    ADD CONSTRAINT secret_projects_org_id_name_key UNIQUE (org_id, name);

ALTER TABLE ONLY public.secret_projects
    ADD CONSTRAINT secret_projects_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.stripe_invoices
    ADD CONSTRAINT stripe_invoices_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.stripe_invoices
    ADD CONSTRAINT stripe_invoices_stripe_invoice_id_key UNIQUE (stripe_invoice_id);

ALTER TABLE ONLY public.stripe_webhook_events
    ADD CONSTRAINT stripe_webhook_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.two_factor
    ADD CONSTRAINT two_factor_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.two_factor_tokens
    ADD CONSTRAINT two_factor_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.two_factor_tokens
    ADD CONSTRAINT two_factor_tokens_token_key UNIQUE (token);

ALTER TABLE ONLY public.user_git_credentials
    ADD CONSTRAINT user_git_credentials_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_git_credentials
    ADD CONSTRAINT user_git_credentials_user_id_host_key UNIQUE (user_id, host);

ALTER TABLE ONLY public.user_github_tokens
    ADD CONSTRAINT user_github_tokens_pkey PRIMARY KEY (user_id);

ALTER TABLE ONLY public.user_login_keys
    ADD CONSTRAINT user_login_keys_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_ssh_keys
    ADD CONSTRAINT user_ssh_keys_pkey PRIMARY KEY (user_id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.verifications
    ADD CONSTRAINT verifications_pkey PRIMARY KEY (id);

CREATE INDEX audit_logs_action_timestamp_idx ON public.audit_logs USING btree (action, "timestamp");

CREATE INDEX audit_logs_user_timestamp_idx ON public.audit_logs USING btree (user_id, "timestamp");

CREATE INDEX billing_catalog_subscription_migrations_created_at_idx ON public.billing_catalog_subscription_migrations USING btree (created_at DESC);

CREATE INDEX environments_external_cleanup_pending_idx ON public.environments USING btree (state_changed_at, id) WHERE ((desired_state = 'destroyed'::text) AND (external_cleanup_completed_at IS NULL));

CREATE INDEX idx_admin_invoice_credits_org_created ON public.admin_invoice_credits USING btree (org_id, created_at DESC);

CREATE INDEX idx_api_keys_prefix ON public.api_keys USING btree (key_prefix);

CREATE INDEX idx_api_keys_user ON public.api_keys USING btree (user_id);

CREATE INDEX idx_billing_events_org ON public.billing_events USING btree (org_id, created_at DESC);

CREATE INDEX idx_billing_events_type ON public.billing_events USING btree (event_type, created_at DESC);

CREATE INDEX idx_device_auth_device_code ON public.device_auth_codes USING btree (device_code);

CREATE INDEX idx_device_auth_user_code ON public.device_auth_codes USING btree (user_code);

CREATE INDEX idx_env_access_env ON public.environment_access USING btree (environment_id);

CREATE INDEX idx_env_access_user ON public.environment_access USING btree (user_id);

CREATE INDEX idx_env_lifecycle_journal_env_checkpoint_created_at ON public.environment_lifecycle_journal USING btree (environment_id, checkpoint, created_at DESC) WHERE (checkpoint IS NOT NULL);

CREATE INDEX idx_env_lifecycle_journal_env_created_at ON public.environment_lifecycle_journal USING btree (environment_id, created_at DESC);

CREATE INDEX idx_env_lifecycle_journal_env_kind_created_at ON public.environment_lifecycle_journal USING btree (environment_id, kind, created_at DESC);

CREATE INDEX idx_environment_logs_env_id ON public.environment_logs USING btree (environment_id, created_at);

CREATE INDEX idx_environment_logs_env_phase_created_at ON public.environment_logs USING btree (environment_id, phase, created_at DESC);

CREATE INDEX idx_environment_ports_env ON public.environment_ports USING btree (environment_id);

CREATE INDEX idx_environments_deletion_grace ON public.environments USING btree (deletion_grace_until) WHERE ((deletion_grace_until IS NOT NULL) AND (state <> ALL (ARRAY['destroyed'::text, 'destroying'::text])));

CREATE INDEX idx_environments_org ON public.environments USING btree (org_id);

CREATE INDEX idx_environments_reconcile ON public.environments USING btree (state, state_changed_at) WHERE (state <> ALL (ARRAY['destroyed'::text, 'build_failed'::text]));

CREATE INDEX idx_environments_sync ON public.environments USING btree (desired_state) WHERE (state <> desired_state);

CREATE INDEX idx_environments_ttl ON public.environments USING btree (shutdown_at) WHERE ((shutdown_at IS NOT NULL) AND (state <> ALL (ARRAY['destroyed'::text, 'destroying'::text])));

CREATE INDEX idx_environments_type_state ON public.environments USING btree (type, state);

CREATE UNIQUE INDEX idx_presets_slug_org ON public.environment_presets USING btree (slug, org_id) WHERE (slug IS NOT NULL);

CREATE INDEX idx_sandbox_backend_claim ON public.sandbox_environment_backend USING btree (namespace, sandbox_claim_name);

CREATE INDEX idx_sandbox_backend_claim_uid ON public.sandbox_environment_backend USING btree (namespace, sandbox_claim_uid);

CREATE INDEX idx_sandbox_backend_pod_name ON public.sandbox_environment_backend USING btree (pod_name) WHERE (pod_name IS NOT NULL);

CREATE INDEX idx_sandbox_running_sessions_env_started ON public.sandbox_running_sessions USING btree (environment_id, started_at);

CREATE INDEX idx_sandbox_running_sessions_open ON public.sandbox_running_sessions USING btree (organization_id, runtime_namespace) WHERE (ended_at IS NULL);

CREATE UNIQUE INDEX idx_sandbox_running_sessions_open_uid ON public.sandbox_running_sessions USING btree (runtime_type, runtime_uid) WHERE (ended_at IS NULL);

CREATE INDEX idx_sandbox_running_sessions_org_period ON public.sandbox_running_sessions USING btree (organization_id, started_at, ended_at);

CREATE INDEX idx_secret_projects_org ON public.secret_projects USING btree (org_id);

CREATE INDEX idx_two_factor_tokens_token ON public.two_factor_tokens USING btree (token);

CREATE INDEX idx_user_login_keys_user ON public.user_login_keys USING btree (user_id);

CREATE INDEX oidc_auth_requests_code_idx ON public.oidc_auth_requests USING btree (code) WHERE (code IS NOT NULL);

CREATE INDEX oidc_auth_requests_expires_idx ON public.oidc_auth_requests USING btree (expires_at);

CREATE UNIQUE INDEX org_members_org_user_idx ON public.org_members USING btree (org_id, user_id);

CREATE INDEX organization_deletion_operations_organization_idx ON public.organization_deletion_operations USING btree (organization_id, generation DESC);

CREATE INDEX organization_deletion_operations_pending_start_idx ON public.organization_deletion_operations USING btree (created_at, id) WHERE (state = 'pending_start'::text);

CREATE INDEX organization_mutation_leases_organization_idx ON public.organization_mutation_leases USING btree (organization_id, admitted_at, id);

CREATE INDEX organization_mutation_leases_unresolved_idx ON public.organization_mutation_leases USING btree (organization_id, mutation_class, deadline_at, admitted_at, id) WHERE (state = ANY (ARRAY['active'::text, 'resolution_required'::text]));

CREATE INDEX runtime_transport_zones_enabled_idx ON public.runtime_transport_zones USING btree (enabled);

CREATE INDEX runtime_transport_zones_region_idx ON public.runtime_transport_zones USING btree (runtime_region);

CREATE UNIQUE INDEX two_factor_user_id_idx ON public.two_factor USING btree (user_id);

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.admin_invoice_credits
    ADD CONSTRAINT admin_invoice_credits_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.billing_catalog_subscription_migrations
    ADD CONSTRAINT billing_catalog_subscription_migrations_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.data_deletion_requests
    ADD CONSTRAINT data_deletion_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.device_auth_codes
    ADD CONSTRAINT device_auth_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

ALTER TABLE ONLY public.environment_access
    ADD CONSTRAINT environment_access_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.environment_access
    ADD CONSTRAINT environment_access_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES public.users(id);

ALTER TABLE ONLY public.environment_access
    ADD CONSTRAINT environment_access_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.environment_lifecycle_journal
    ADD CONSTRAINT environment_lifecycle_journal_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.environment_logs
    ADD CONSTRAINT environment_logs_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.environment_operation_generation_claims
    ADD CONSTRAINT environment_operation_generation_claims_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.environment_ports
    ADD CONSTRAINT environment_ports_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.environment_presets
    ADD CONSTRAINT environment_presets_default_secret_project_id_fkey FOREIGN KEY (default_secret_project_id) REFERENCES public.secret_projects(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.environment_presets
    ADD CONSTRAINT environment_presets_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.environment_quotas
    ADD CONSTRAINT environment_quotas_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.environment_sessions
    ADD CONSTRAINT environment_sessions_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.environment_subscriptions
    ADD CONSTRAINT environment_subscriptions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.environment_usage_billing
    ADD CONSTRAINT environment_usage_billing_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_deletion_requested_by_fkey FOREIGN KEY (deletion_requested_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_preset_id_fkey FOREIGN KEY (preset_id) REFERENCES public.environment_presets(id);

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_secret_project_id_fkey FOREIGN KEY (secret_project_id) REFERENCES public.secret_projects(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.github_oauth_states
    ADD CONSTRAINT github_oauth_states_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oidc_auth_requests
    ADD CONSTRAINT oidc_auth_requests_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oidc_clients(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oidc_auth_requests
    ADD CONSTRAINT oidc_auth_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oidc_refresh_tokens
    ADD CONSTRAINT oidc_refresh_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oidc_clients(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.oidc_refresh_tokens
    ADD CONSTRAINT oidc_refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.org_invitations
    ADD CONSTRAINT org_invitations_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.org_invitations
    ADD CONSTRAINT org_invitations_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.org_member_assignments
    ADD CONSTRAINT org_member_assignments_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES public.users(id);

ALTER TABLE ONLY public.org_member_assignments
    ADD CONSTRAINT org_member_assignments_org_member_id_fkey FOREIGN KEY (org_member_id) REFERENCES public.org_members(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.org_members
    ADD CONSTRAINT org_members_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.org_members
    ADD CONSTRAINT org_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.org_subscriptions
    ADD CONSTRAINT org_subscriptions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_deletion_requested_by_fkey FOREIGN KEY (deletion_requested_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.repo_configs
    ADD CONSTRAINT repo_configs_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.repo_configs
    ADD CONSTRAINT repo_configs_preset_id_fkey FOREIGN KEY (preset_id) REFERENCES public.environment_presets(id);

ALTER TABLE ONLY public.sandbox_environment_backend
    ADD CONSTRAINT sandbox_environment_backend_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.sandbox_running_sessions
    ADD CONSTRAINT sandbox_running_sessions_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.sandbox_running_sessions
    ADD CONSTRAINT sandbox_running_sessions_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.sandbox_template_config
    ADD CONSTRAINT sandbox_template_config_preset_id_fkey FOREIGN KEY (preset_id) REFERENCES public.environment_presets(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.secret_projects
    ADD CONSTRAINT secret_projects_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.stripe_invoices
    ADD CONSTRAINT stripe_invoices_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.two_factor_tokens
    ADD CONSTRAINT two_factor_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.two_factor
    ADD CONSTRAINT two_factor_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_git_credentials
    ADD CONSTRAINT user_git_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_github_tokens
    ADD CONSTRAINT user_github_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_login_keys
    ADD CONSTRAINT user_login_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_ssh_keys
    ADD CONSTRAINT user_ssh_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


-- Repository-defined billing catalog reference rows.
INSERT INTO public.billing_catalog_plans (
    resource_type, plan_key, display_name, price_cents,
    included_devs, max_concurrent_ws, max_team_members,
    storage_gb, is_contact_us, is_admin_only,
    included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours,
    cpu_overage_cents, mem_overage_cents, disk_overage_cents
) VALUES
    ('org', 'starter',    'Starter',    4900,  1, 5,   1,  50,   false, false, 0, 0, 0, 0, 0, 0),
    ('org', 'pro',        'Pro',        19900, 10, 25, 15, 250,  false, false, 0, 0, 0, 0, 0, 0),
    ('org', 'team',       'Team',       49900, 30, 100, -1, 1000, false, false, 0, 0, 0, 0, 0, 0),
    ('org', 'enterprise', 'Enterprise', -1,   -1, -1, -1, -1,   true,  false, 0, 0, 0, 0, 0, 0),
    ('sandbox', 'starter',    'Starter',    4900,  0, 10,  1,  0, false, false, 200,  400,  50000,  5.04, 1.62, 0.01),
    ('sandbox', 'pro',        'Pro',        19900, 0, 50,  15, 0, false, false, 1000, 2000, 200000, 5.04, 1.62, 0.01),
    ('sandbox', 'team',       'Team',       49900, 0, 200, -1, 0, false, false, 3000, 6000, 500000, 5.04, 1.62, 0.01),
    ('sandbox', 'enterprise', 'Enterprise', -1,    0, -1,  -1, 0, true,  false, 0,    0,    0,      0,    0,    0),
    ('sandbox', 'unlimited',  'Unlimited',  0,     0, -1,  -1, 0, false, true,  0,    0,    0,      5.04, 1.62, 0.01)
ON CONFLICT (resource_type, plan_key) DO NOTHING;

INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id) VALUES
    ('org', 'starter', 'test', 'subscription', 'price_1T2AZTIezUhNxMWsk0Yw8SDc'),
    ('org', 'pro',     'test', 'subscription', 'price_1T2AZkIezUhNxMWsFJYUOFI6'),
    ('org', 'team',    'test', 'subscription', 'price_1T2Aa1IezUhNxMWs4o4LUr5u'),
    ('org', 'starter', 'live', 'subscription', 'price_1T2AyyEeXpf2Q0A6LwPKBvM6'),
    ('org', 'pro',     'live', 'subscription', 'price_1T2AzOEeXpf2Q0A6eaihCdpC'),
    ('org', 'team',    'live', 'subscription', 'price_1T2AzoEeXpf2Q0A6TUqO1saR'),
    ('org', 'seat', 'test', 'seat_addon', 'price_1T2AdJIezUhNxMWsiLcJ0zyH'),
    ('org', 'seat', 'live', 'seat_addon', 'price_1T2B02EeXpf2Q0A60GxTU2Y1'),
    ('sandbox', 'starter',   'test', 'subscription', 'price_TODO_TEST_SANDBOX_STARTER'),
    ('sandbox', 'pro',       'test', 'subscription', 'price_TODO_TEST_SANDBOX_PRO'),
    ('sandbox', 'team',      'test', 'subscription', 'price_TODO_TEST_SANDBOX_TEAM'),
    ('sandbox', 'unlimited', 'test', 'subscription', 'price_TODO_TEST_SANDBOX_UNLIMITED'),
    ('sandbox', 'starter',   'live', 'subscription', 'price_TODO_LIVE_SANDBOX_STARTER'),
    ('sandbox', 'pro',       'live', 'subscription', 'price_TODO_LIVE_SANDBOX_PRO'),
    ('sandbox', 'team',      'live', 'subscription', 'price_TODO_LIVE_SANDBOX_TEAM'),
    ('sandbox', 'unlimited', 'live', 'subscription', 'price_TODO_LIVE_SANDBOX_UNLIMITED')
ON CONFLICT (resource_type, plan_key, stripe_mode, price_kind) DO NOTHING;

INSERT INTO public.billing_catalog_settings (setting_key, int_value) VALUES
    ('trial_days', 14),
    ('extra_seat_cents', 1800)
ON CONFLICT (setting_key) DO NOTHING;
