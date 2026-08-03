-- Product-facing isolation tier. Existing environments retain the historical
-- Standard behavior, and the value is intentionally immutable after create.
ALTER TABLE environments
    ADD COLUMN isolation_tier text NOT NULL DEFAULT 'standard';

ALTER TABLE environments
    ADD CONSTRAINT environments_isolation_tier_check
    CHECK (isolation_tier IN ('standard', 'confidential'));

-- #44 made the billing tier durable. A single organization/month watermark
-- cannot truthfully represent both standard and confidential usage. Keep an
-- additive, per-tier ledger so a source revert remains compatible with the
-- original table and all historical records remain readable.
CREATE TABLE environment_usage_billing_tiers (
    org_id text NOT NULL REFERENCES organizations(id),
    billing_period_start timestamp without time zone NOT NULL,
    runtime_tier text NOT NULL,
    last_cpu_hours double precision NOT NULL DEFAULT 0,
    last_mem_gb_hours double precision NOT NULL DEFAULT 0,
    last_disk_gb_hours double precision NOT NULL DEFAULT 0,
    last_overage_cents integer NOT NULL DEFAULT 0,
    stripe_invoice_item_id text,
    updated_at timestamp without time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, billing_period_start, runtime_tier),
    CONSTRAINT environment_usage_billing_tiers_runtime_tier_check
        CHECK (runtime_tier IN ('standard', 'confidential'))
);

INSERT INTO environment_usage_billing_tiers
    (org_id, billing_period_start, runtime_tier, last_cpu_hours, last_mem_gb_hours,
     last_disk_gb_hours, last_overage_cents, stripe_invoice_item_id, updated_at)
SELECT org_id, billing_period_start, runtime_tier, last_cpu_hours, last_mem_gb_hours,
       last_disk_gb_hours, last_overage_cents, stripe_invoice_item_id, updated_at
FROM environment_usage_billing
ON CONFLICT (org_id, billing_period_start, runtime_tier) DO NOTHING;
