-- The credit ledger outlives its organization (#4823; owner, 2026-11-15:
-- leftover credit is forfeited at deletion, with a warning first, and
-- support refunds it by hand). Until now the ledger cascaded with the
-- organization row, so deleting an organization erased every purchase,
-- top-up and usage entry Codewire had recorded for it.
--
-- - The ledger no longer references organizations, so its rows stay, keyed
--   by the deleted organization's ID. The balance still cascades: a deleted
--   organization has no balance, only its history.
-- - A `forfeited` entry records what was left when the organization was
--   deleted. It draws the balance to zero, so it is negative, names who
--   deleted the organization, and carries the organization's Stripe
--   customer, if any, as its provider object.
-- - The immutability trigger now refuses every change and delete, and no
--   entry lands once a deletion's billing phase is complete (below).
--
-- Compatible: older code never writes `forfeited`, and reads a deleted
-- organization's ledger nowhere. Rolling back is forward only
-- (docs/dev/DATABASE-MIGRATIONS.md).

ALTER TABLE public.billing_credit_ledger
    DROP CONSTRAINT billing_credit_ledger_organization_id_fkey;

ALTER TABLE public.billing_credit_ledger
    DROP CONSTRAINT billing_credit_ledger_entry_kind_check,
    ADD CONSTRAINT billing_credit_ledger_entry_kind_check
        CHECK (entry_kind IN ('grant', 'usage', 'top_up', 'adjustment', 'forfeited')),
    -- Grants and top-ups add credit, usage and a forfeit draw it, and an
    -- adjustment is either but never zero.
    DROP CONSTRAINT billing_credit_ledger_amount_check,
    ADD CONSTRAINT billing_credit_ledger_amount_check CHECK (
        CASE entry_kind
            WHEN 'usage' THEN amount_nano_eur < 0
            WHEN 'forfeited' THEN amount_nano_eur < 0
            WHEN 'adjustment' THEN amount_nano_eur <> 0
            ELSE amount_nano_eur > 0
        END
    ),
    -- A forfeit names the person who deleted the organization.
    ADD CONSTRAINT billing_credit_ledger_forfeited_check CHECK (
        entry_kind <> 'forfeited' OR actor_user_id IS NOT NULL
    );

-- Ledger rows are never changed or removed. Until now a delete one trigger
-- level down was let through, for the organization cascade; with the
-- cascade gone, that would only let some other trigger delete history.
CREATE OR REPLACE FUNCTION public.codewire_billing_credit_ledger_immutable() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'billing credit ledger entries are immutable';
END;
$$;

-- Once an organization's deletion has finished its billing phase, its
-- credit is final: the phase drew the last usage and recorded any forfeit,
-- so no entry may land before the organization row is deleted. This holds
-- whatever the balance was, also at zero or below, where no forfeit is
-- written. The organization row is key-share locked first: that conflicts
-- with the billing phase's FOR UPDATE, which commits its forfeit and its
-- completion, so an entry racing it waits, then sees the completion and is
-- refused; it doesn't conflict with an ordinary update of the organization. After the
-- organization is gone, its balance row is gone too, and the balance's
-- foreign key refuses any entry. Locks are always taken organization row
-- first, then balance row (here and in the billing phase), so a ledger
-- writer and the phase never wait on each other in opposite orders.
CREATE FUNCTION public.codewire_billing_credit_ledger_deletion_fence() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    PERFORM 1 FROM public.organizations
        WHERE id = NEW.organization_id FOR KEY SHARE;
    IF EXISTS (
        SELECT 1
        FROM public.organizations o
        JOIN public.organization_deletion_billing_phases phase
          ON phase.operation_id = o.deletion_operation_id
         AND phase.organization_id = o.id
        WHERE o.id = NEW.organization_id AND phase.state = 'completed'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'the organization is being deleted and its credit is final';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER billing_credit_ledger_deletion_fence
    BEFORE INSERT ON public.billing_credit_ledger
    FOR EACH ROW EXECUTE FUNCTION public.codewire_billing_credit_ledger_deletion_fence();
