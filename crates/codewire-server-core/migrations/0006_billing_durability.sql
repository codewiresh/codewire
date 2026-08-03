-- Durable billing foundation. All changes are additive so source rollback
-- leaves historical operation and webhook records readable.

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS billing_exempt boolean NOT NULL DEFAULT false;

ALTER TABLE sandbox_running_sessions
    ADD COLUMN IF NOT EXISTS runtime_tier text NOT NULL DEFAULT 'standard';

ALTER TABLE environment_usage_billing
    ADD COLUMN IF NOT EXISTS runtime_tier text NOT NULL DEFAULT 'standard';

ALTER TABLE stripe_webhook_events
    ADD COLUMN IF NOT EXISTS stripe_created_at timestamp without time zone,
    ADD COLUMN IF NOT EXISTS processed_at timestamp without time zone NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS billing_external_operations (
    id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    billing_period_start timestamp without time zone NOT NULL,
    operation_kind text NOT NULL,
    idempotency_key text NOT NULL,
    requested_amount_cents integer NOT NULL,
    provider_object_id text,
    provider_state text NOT NULL DEFAULT 'pending',
    created_at timestamp without time zone NOT NULL DEFAULT now(),
    completed_at timestamp without time zone,
    UNIQUE (idempotency_key)
);

CREATE INDEX IF NOT EXISTS billing_external_operations_org_period_idx
    ON billing_external_operations (organization_id, billing_period_start, created_at DESC);

-- The ordering cursor is deliberately on the mutable subscription rows, not
-- the event receipt: a delayed Stripe event cannot regress current state.
ALTER TABLE org_subscriptions
    ADD COLUMN IF NOT EXISTS stripe_event_created_at timestamp without time zone,
    ADD COLUMN IF NOT EXISTS stripe_event_id text;

ALTER TABLE environment_subscriptions
    ADD COLUMN IF NOT EXISTS stripe_event_created_at timestamp without time zone,
    ADD COLUMN IF NOT EXISTS stripe_event_id text;
