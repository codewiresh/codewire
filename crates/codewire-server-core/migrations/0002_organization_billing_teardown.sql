-- Durable billing evidence for one organization-deletion generation.
-- Provider identifiers are retained outside the organization foreign-key
-- boundary so cancellation can be retried after local billing rows disappear.

CREATE TABLE organization_deletion_billing_phases (
    operation_id text PRIMARY KEY,
    organization_id text NOT NULL,
    generation bigint NOT NULL,
    stripe_customer_id text,
    state text NOT NULL DEFAULT 'pending',
    failure_code text,
    final_usage_completed_at timestamp without time zone,
    checkout_sessions_expired_at timestamp without time zone,
    subscriptions_verified_at timestamp without time zone,
    completed_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL DEFAULT NOW(),
    updated_at timestamp without time zone NOT NULL DEFAULT NOW(),
    CONSTRAINT organization_deletion_billing_generation_check
        CHECK (generation > 0),
    CONSTRAINT organization_deletion_billing_state_check
        CHECK (state IN ('pending', 'running', 'failed', 'completed')),
    CONSTRAINT organization_deletion_billing_failure_code_check
        CHECK (failure_code IS NULL OR failure_code ~ '^[a-z0-9_]{1,128}$'),
    CONSTRAINT organization_deletion_billing_terminal_metadata_check CHECK (
        (state IN ('pending', 'running') AND failure_code IS NULL AND completed_at IS NULL)
        OR (state = 'failed' AND failure_code IS NOT NULL AND completed_at IS NULL)
        OR (state = 'completed' AND failure_code IS NULL
            AND final_usage_completed_at IS NOT NULL
            AND checkout_sessions_expired_at IS NOT NULL
            AND subscriptions_verified_at IS NOT NULL
            AND completed_at IS NOT NULL)
    ),
    CONSTRAINT organization_deletion_billing_operation_fkey
        FOREIGN KEY (operation_id)
        REFERENCES organization_deletion_operations(id)
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX organization_deletion_billing_generation_idx
    ON organization_deletion_billing_phases (organization_id, generation);

CREATE TABLE organization_deletion_billing_subscriptions (
    operation_id text NOT NULL,
    organization_id text NOT NULL,
    generation bigint NOT NULL,
    stripe_subscription_id text NOT NULL,
    state text NOT NULL DEFAULT 'captured',
    captured_at timestamp without time zone NOT NULL DEFAULT NOW(),
    verified_terminal_at timestamp without time zone,
    updated_at timestamp without time zone NOT NULL DEFAULT NOW(),
    CONSTRAINT organization_deletion_billing_subscriptions_pkey
        PRIMARY KEY (operation_id, stripe_subscription_id),
    CONSTRAINT organization_deletion_billing_subscriptions_generation_check
        CHECK (generation > 0),
    CONSTRAINT organization_deletion_billing_subscriptions_state_check
        CHECK (state IN ('captured', 'terminal')),
    CONSTRAINT organization_deletion_billing_subscriptions_terminal_check CHECK (
        (state = 'captured' AND verified_terminal_at IS NULL)
        OR (state = 'terminal' AND verified_terminal_at IS NOT NULL)
    ),
    CONSTRAINT organization_deletion_billing_subscriptions_operation_fkey
        FOREIGN KEY (operation_id)
        REFERENCES organization_deletion_operations(id)
        ON DELETE CASCADE
);

CREATE INDEX organization_deletion_billing_subscriptions_org_idx
    ON organization_deletion_billing_subscriptions
       (organization_id, generation, state, stripe_subscription_id);
