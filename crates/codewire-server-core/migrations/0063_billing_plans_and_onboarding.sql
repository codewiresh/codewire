-- Monthly USD billing plans, per-cycle compute allowances and first-run
-- onboarding state (#6659, docs/dev/BILLING.md "Plans and monthly allowances").
--
-- billing_plan_definitions: the three self-serve plans (payg, pro, max) with
-- their monthly prices in USD cents, included monthly compute allowances in
-- nano-USD, concurrency and VM-shape caps, team-member caps, and optional
-- Stripe Price IDs per mode. NULL concurrency or team-member cap means
-- unlimited.
--
-- billing_plan_allowances: one non-rolling compute allowance bucket per paid
-- subscription billing cycle, keyed by stripe_invoice_id for idempotent grant
-- on invoice.paid. Metering draws from the active cycle's allowance before
-- drawing prepaid credit in billing_credit_balances.
--
-- org_subscriptions.cancel_at_period_end: mirrors Stripe's scheduled
-- cancellation flag so the Billing page can show "Ends <date>" without a
-- second Stripe read.
--
-- users.onboarding_completed_at: NULL while a new user has not yet finished
-- the first-run onboarding overlay; backfilled for every existing user so
-- existing accounts are never intercepted on deploy.
--
-- billing_rate_cards: updates the default Regular and Discounted cards from
-- the pre-launch EUR defaults to the USD defaults ($0.050/vCPU-hr,
-- $0.016/GiB-hr memory, $0.0001/GiB-hr disk; Discounted at half) when still
-- at their initial EUR values.
--
-- Compatible: the tables are new, the new columns on org_subscriptions and
-- users have a constant default or are nullable so no rows are rewritten, and
-- older binaries ignore all of them. Rollback drops the trigger, function,
-- two new tables, and the two added columns.

CREATE TABLE public.billing_plan_definitions (
    plan_key text NOT NULL,
    display_name text NOT NULL,
    monthly_price_cents integer NOT NULL,
    included_compute_nano_usd bigint NOT NULL,
    max_concurrent_sandboxes integer,
    max_vcpu integer NOT NULL,
    max_memory_gib integer NOT NULL,
    max_disk_gib integer NOT NULL,
    max_team_members integer,
    stripe_price_id_test text,
    stripe_price_id_live text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT billing_plan_definitions_pkey PRIMARY KEY (plan_key),
    CONSTRAINT billing_plan_definitions_plan_key_check
        CHECK (plan_key IN ('payg', 'pro', 'max')),
    CONSTRAINT billing_plan_definitions_amounts_check CHECK (
        monthly_price_cents >= 0
        AND included_compute_nano_usd >= 0
    ),
    CONSTRAINT billing_plan_definitions_limits_check CHECK (
        (max_concurrent_sandboxes IS NULL OR max_concurrent_sandboxes > 0)
        AND max_vcpu > 0
        AND max_memory_gib > 0
        AND max_disk_gib > 0
        AND (max_team_members IS NULL OR max_team_members > 0)
    )
);

INSERT INTO public.billing_plan_definitions
    (plan_key, display_name, monthly_price_cents, included_compute_nano_usd,
     max_concurrent_sandboxes, max_vcpu, max_memory_gib, max_disk_gib,
     max_team_members)
VALUES
    ('payg', 'Pay as you go', 0, 0, 3, 8, 16, 100, 1),
    ('pro', 'Pro', 4000, 100000000000, 10, 8, 16, 100, 5),
    ('max', 'Max', 10000, 250000000000, NULL, 16, 32, 200, NULL);

CREATE TABLE public.billing_plan_allowances (
    id bigint GENERATED ALWAYS AS IDENTITY,
    organization_id text NOT NULL,
    plan_key text NOT NULL,
    period_start timestamp with time zone NOT NULL,
    period_end timestamp with time zone NOT NULL,
    granted_nano_usd bigint NOT NULL,
    drawn_nano_usd bigint DEFAULT 0 NOT NULL,
    stripe_invoice_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT billing_plan_allowances_pkey PRIMARY KEY (id),
    CONSTRAINT billing_plan_allowances_invoice_key UNIQUE (stripe_invoice_id),
    CONSTRAINT billing_plan_allowances_organization_id_fkey
        FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE,
    CONSTRAINT billing_plan_allowances_plan_key_fkey
        FOREIGN KEY (plan_key) REFERENCES public.billing_plan_definitions(plan_key),
    CONSTRAINT billing_plan_allowances_period_check
        CHECK (period_end > period_start),
    CONSTRAINT billing_plan_allowances_amounts_check CHECK (
        granted_nano_usd >= 0
        AND drawn_nano_usd >= 0
        AND drawn_nano_usd <= granted_nano_usd
    ),
    CONSTRAINT billing_plan_allowances_invoice_id_check
        CHECK (octet_length(stripe_invoice_id) BETWEEN 1 AND 255)
);

CREATE INDEX billing_plan_allowances_org_period_idx
    ON public.billing_plan_allowances USING btree (organization_id, period_end DESC);

CREATE FUNCTION public.codewire_notify_plan_allowance_change() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    PERFORM pg_catalog.pg_notify('credit_changes', NEW.organization_id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER billing_plan_allowances_credit_changes
    AFTER INSERT OR UPDATE OF granted_nano_usd, drawn_nano_usd
    ON public.billing_plan_allowances
    FOR EACH ROW
    EXECUTE FUNCTION public.codewire_notify_plan_allowance_change();

REVOKE ALL ON FUNCTION public.codewire_notify_plan_allowance_change() FROM PUBLIC;

ALTER TABLE ONLY public.org_subscriptions
    ADD COLUMN cancel_at_period_end boolean DEFAULT false NOT NULL;

ALTER TABLE ONLY public.users
    ADD COLUMN onboarding_completed_at timestamp with time zone;

UPDATE public.users
SET onboarding_completed_at = COALESCE(created_at AT TIME ZONE 'UTC', now())
WHERE onboarding_completed_at IS NULL;

UPDATE public.billing_rate_cards
SET cpu_nano_eur_per_vcpu_hour = 50000000,
    memory_nano_eur_per_gib_hour = 16000000,
    disk_nano_eur_per_gib_hour = 100000,
    updated_at = now()
WHERE rate_card = 'regular'
  AND cpu_nano_eur_per_vcpu_hour = 43800000
  AND memory_nano_eur_per_gib_hour = 14100000
  AND disk_nano_eur_per_gib_hour = 87000;

UPDATE public.billing_rate_cards
SET cpu_nano_eur_per_vcpu_hour = 25000000,
    memory_nano_eur_per_gib_hour = 8000000,
    disk_nano_eur_per_gib_hour = 50000,
    updated_at = now()
WHERE rate_card = 'discounted'
  AND cpu_nano_eur_per_vcpu_hour = 21900000
  AND memory_nano_eur_per_gib_hour = 7050000
  AND disk_nano_eur_per_gib_hour = 43500;
