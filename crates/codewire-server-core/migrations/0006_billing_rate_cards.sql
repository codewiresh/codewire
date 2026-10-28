-- Rate cards and prepaid compute credit (#3381).
--
-- Each organization has an administrator-assigned rate card: Regular (the
-- default), Discounted (hidden, lower rates) or Unlimited (no charge and no
-- quota). Rates are integers in nano-euros per unit-hour, so a per-second
-- draw never rounds through floating point.
--
-- Credit is an append-only ledger of grants, usage, top-ups and
-- adjustments. Each organization's balance is the sum of its ledger, kept
-- by a trigger in the inserting transaction, so every writer keeps it exact
-- and nothing else can change it.
--
-- Metering draws each running session's allocated size from its
-- organization's credit up to a watermark on the session. A card added
-- through Stripe grants EUR 50 once per organization and once per card, and
-- automatic top-ups charge the card when the balance runs out (owner,
-- 2026-10-24: EUR 20, on by default, adjustable or off).
--
-- Compatible: the tables are new, the organization columns have constant
-- defaults or are nullable, and the session column is nullable, so older
-- code that reads none of them keeps working. Rollback drops the five organization columns, the
-- session column and its index, the five tables and the three functions.

CREATE TABLE public.billing_rate_cards (
    rate_card text NOT NULL,
    display_name text NOT NULL,
    cpu_nano_eur_per_vcpu_hour bigint NOT NULL,
    memory_nano_eur_per_gib_hour bigint NOT NULL,
    disk_nano_eur_per_gib_hour bigint NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT billing_rate_cards_pkey PRIMARY KEY (rate_card),
    CONSTRAINT billing_rate_cards_rate_card_check
        CHECK (rate_card IN ('regular', 'discounted', 'unlimited')),
    CONSTRAINT billing_rate_cards_rates_check CHECK (
        cpu_nano_eur_per_vcpu_hour >= 0
        AND memory_nano_eur_per_gib_hour >= 0
        AND disk_nano_eur_per_gib_hour >= 0
    ),
    CONSTRAINT billing_rate_cards_unlimited_charges_nothing_check CHECK (
        rate_card <> 'unlimited'
        OR (cpu_nano_eur_per_vcpu_hour = 0
            AND memory_nano_eur_per_gib_hour = 0
            AND disk_nano_eur_per_gib_hour = 0)
    )
);

-- Regular is the previous overage rates in euros (owner, 2026-10-24):
-- EUR 0.0438 per vCPU-hour, 0.0141 per GiB-hour of memory and 0.000087 per
-- GiB-hour of disk. Discounted is half of Regular until the owner sets it.
INSERT INTO public.billing_rate_cards
    (rate_card, display_name, cpu_nano_eur_per_vcpu_hour,
     memory_nano_eur_per_gib_hour, disk_nano_eur_per_gib_hour)
VALUES
    ('regular', 'Regular', 43800000, 14100000, 87000),
    ('discounted', 'Discounted', 21900000, 7050000, 43500),
    ('unlimited', 'Unlimited', 0, 0, 0);

ALTER TABLE ONLY public.organizations
    ADD COLUMN rate_card text DEFAULT 'regular' NOT NULL;
ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_rate_card_fkey
    FOREIGN KEY (rate_card) REFERENCES public.billing_rate_cards(rate_card);

-- Automatic top-up, and since when a charging organization has had no
-- credit and no way to get it (no card, top-up off, or a failed charge).
ALTER TABLE ONLY public.organizations
    ADD COLUMN auto_top_up_enabled boolean DEFAULT true NOT NULL,
    ADD COLUMN auto_top_up_cents integer DEFAULT 2000 NOT NULL,
    ADD COLUMN credit_exhausted_at timestamp with time zone,
    ADD CONSTRAINT organizations_auto_top_up_cents_check
        CHECK (auto_top_up_cents BETWEEN 500 AND 100000);

-- Organizations that were never charged keep not being charged: those
-- exempt from billing and those on the administrator-only unlimited plan.
UPDATE public.organizations AS o
SET rate_card = 'unlimited'
WHERE o.billing_exempt
   OR (o.billing_plan = 'unlimited'
       AND o.billing_status IN ('active', 'trialing', 'past_due'))
   OR EXISTS (
       SELECT 1 FROM public.environment_subscriptions AS es
       WHERE es.org_id = o.id AND es.plan = 'unlimited'
         AND es.status IN ('active', 'trialing', 'past_due'))
   OR EXISTS (
       SELECT 1 FROM public.org_subscriptions AS os
       WHERE os.org_id = o.id AND os.plan = 'unlimited'
         AND os.status IN ('active', 'trialing', 'past_due'));

-- A session's usage is drawn up to credit_drawn_through, or from its start
-- while that is NULL. Usage from before credit existed is never drawn.
ALTER TABLE ONLY public.sandbox_running_sessions
    ADD COLUMN credit_drawn_through timestamp with time zone;
UPDATE public.sandbox_running_sessions
SET credit_drawn_through = COALESCE(ended_at, now());
CREATE INDEX sandbox_running_sessions_credit_due_idx
    ON public.sandbox_running_sessions USING btree (organization_id)
    WHERE ended_at IS NULL OR credit_drawn_through IS NULL OR credit_drawn_through < ended_at;

CREATE TABLE public.billing_credit_ledger (
    id bigint GENERATED ALWAYS AS IDENTITY,
    organization_id text NOT NULL,
    entry_kind text NOT NULL,
    amount_nano_eur bigint NOT NULL,
    idempotency_key text NOT NULL,
    rate_card text,
    usage_started_at timestamp with time zone,
    usage_ended_at timestamp with time zone,
    actor_user_id text,
    reason text,
    provider_object_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT billing_credit_ledger_pkey PRIMARY KEY (id),
    CONSTRAINT billing_credit_ledger_idempotency_key UNIQUE (organization_id, idempotency_key),
    CONSTRAINT billing_credit_ledger_organization_id_fkey
        FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE,
    CONSTRAINT billing_credit_ledger_rate_card_fkey
        FOREIGN KEY (rate_card) REFERENCES public.billing_rate_cards(rate_card),
    CONSTRAINT billing_credit_ledger_entry_kind_check
        CHECK (entry_kind IN ('grant', 'usage', 'top_up', 'adjustment')),
    -- Grants and top-ups add credit, usage draws it, and an adjustment is
    -- either but never zero.
    CONSTRAINT billing_credit_ledger_amount_check CHECK (
        CASE entry_kind
            WHEN 'usage' THEN amount_nano_eur < 0
            WHEN 'adjustment' THEN amount_nano_eur <> 0
            ELSE amount_nano_eur > 0
        END
    ),
    -- A usage row names its window and the card it was drawn at; no other
    -- row does.
    CONSTRAINT billing_credit_ledger_usage_window_check CHECK (
        CASE entry_kind
            WHEN 'usage' THEN usage_started_at IS NOT NULL
                AND usage_ended_at IS NOT NULL
                AND usage_ended_at > usage_started_at
                AND rate_card IS NOT NULL
            ELSE usage_started_at IS NULL
                AND usage_ended_at IS NULL
                AND rate_card IS NULL
        END
    ),
    -- An administrator's adjustment names who made it and why.
    CONSTRAINT billing_credit_ledger_adjustment_check CHECK (
        entry_kind <> 'adjustment'
        OR (actor_user_id IS NOT NULL AND reason IS NOT NULL AND reason <> '')
    ),
    CONSTRAINT billing_credit_ledger_idempotency_key_check
        CHECK (octet_length(idempotency_key) BETWEEN 1 AND 255),
    CONSTRAINT billing_credit_ledger_reason_check
        CHECK (reason IS NULL OR octet_length(reason) <= 1000)
);

CREATE INDEX billing_credit_ledger_organization_recent_idx
    ON public.billing_credit_ledger USING btree (organization_id, id DESC);

CREATE TABLE public.billing_credit_balances (
    organization_id text NOT NULL,
    balance_nano_eur bigint NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT billing_credit_balances_pkey PRIMARY KEY (organization_id),
    CONSTRAINT billing_credit_balances_organization_id_fkey
        FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE
);

-- Ledger rows are never changed, and are removed only with their
-- organization (the foreign key's cascade runs one trigger level down).
CREATE FUNCTION public.codewire_billing_credit_ledger_immutable() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF TG_OP = 'DELETE' AND pg_catalog.pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'billing credit ledger entries are immutable';
END;
$$;

CREATE TRIGGER billing_credit_ledger_immutable
    BEFORE DELETE OR UPDATE ON public.billing_credit_ledger
    FOR EACH ROW EXECUTE FUNCTION public.codewire_billing_credit_ledger_immutable();

-- Each ledger row moves its organization's balance in the same transaction.
CREATE FUNCTION public.codewire_billing_credit_ledger_apply() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    INSERT INTO public.billing_credit_balances AS b (organization_id, balance_nano_eur)
    VALUES (NEW.organization_id, NEW.amount_nano_eur)
    ON CONFLICT (organization_id) DO UPDATE
        SET balance_nano_eur = b.balance_nano_eur + EXCLUDED.balance_nano_eur,
            updated_at = pg_catalog.now();
    RETURN NULL;
END;
$$;

CREATE TRIGGER billing_credit_ledger_apply
    AFTER INSERT ON public.billing_credit_ledger
    FOR EACH ROW EXECUTE FUNCTION public.codewire_billing_credit_ledger_apply();

-- Only the ledger trigger, or the organization's cascade, writes a balance.
CREATE FUNCTION public.codewire_billing_credit_balance_derived() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF pg_catalog.pg_trigger_depth() > 1 THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'a billing credit balance changes only through the ledger';
END;
$$;

CREATE TRIGGER billing_credit_balance_derived
    BEFORE INSERT OR UPDATE OR DELETE ON public.billing_credit_balances
    FOR EACH ROW EXECUTE FUNCTION public.codewire_billing_credit_balance_derived();

-- Each card's fingerprint grants once. The row outlives its organization,
-- so deleting and recreating an organization never grants the card again.
CREATE TABLE public.billing_card_grants (
    card_fingerprint text NOT NULL,
    organization_id text,
    setup_intent_id text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT billing_card_grants_pkey PRIMARY KEY (card_fingerprint),
    CONSTRAINT billing_card_grants_organization_id_fkey
        FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE SET NULL,
    CONSTRAINT billing_card_grants_fingerprint_check
        CHECK (octet_length(card_fingerprint) BETWEEN 1 AND 255)
);

-- One automatic top-up charge. Its id is the Stripe idempotency key, so a
-- retry after a crash resumes the same charge; at most one is pending per
-- organization.
CREATE TABLE public.billing_top_ups (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    organization_id text NOT NULL,
    amount_cents integer NOT NULL,
    state text DEFAULT 'pending' NOT NULL,
    stripe_invoice_id text,
    failure_code text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT billing_top_ups_pkey PRIMARY KEY (id),
    CONSTRAINT billing_top_ups_stripe_invoice_id_key UNIQUE (stripe_invoice_id),
    CONSTRAINT billing_top_ups_organization_id_fkey
        FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE,
    CONSTRAINT billing_top_ups_amount_check CHECK (amount_cents BETWEEN 500 AND 100000),
    CONSTRAINT billing_top_ups_state_check CHECK (
        (state = 'pending' AND completed_at IS NULL AND failure_code IS NULL)
        OR (state = 'paid' AND completed_at IS NOT NULL AND stripe_invoice_id IS NOT NULL
            AND failure_code IS NULL)
        OR (state = 'failed' AND completed_at IS NOT NULL
            AND failure_code ~ '^[a-z0-9_]{1,128}$')
    )
);

CREATE UNIQUE INDEX billing_top_ups_one_pending_idx
    ON public.billing_top_ups USING btree (organization_id) WHERE state = 'pending';

REVOKE ALL ON FUNCTION public.codewire_billing_credit_ledger_immutable() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.codewire_billing_credit_ledger_apply() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.codewire_billing_credit_balance_derived() FROM PUBLIC;
