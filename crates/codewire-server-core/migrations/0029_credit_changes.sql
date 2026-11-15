-- Credit changes (#4754, #4758): every change to an organization's compute
-- credit is notified on `credit_changes` with the organization's ID as text,
-- so billing settles it at once and the console's live updates show it
-- (private-docs designs/live-updates.md). Until now billing noticed only on
-- its minute's tick, so the console said "out of credit" up to a minute late
-- going out and coming back.
--
-- One notice for each kind of change, from the database itself, so a writer
-- in any service is covered:
-- - a ledger row (usage, a top-up, a purchase, a grant, an administrator's
--   adjustment, a snapshot charge), from the trigger that rolls it into the
--   balance;
-- - the organization's automatic top-up setting or its out-of-credit mark.
--
-- A notice is sent at commit and never for a rolled-back transaction, and
-- Postgres folds identical notices within one transaction, so a write of many
-- ledger rows for one organization wakes a listener once.
--
-- Compatible: the ledger function keeps its effect and gains the notice; the
-- organizations trigger only notifies. Older code ignores both. Rolling back
-- is forward only (docs/dev/DATABASE-MIGRATIONS.md).

CREATE OR REPLACE FUNCTION public.codewire_billing_credit_ledger_apply() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    INSERT INTO public.billing_credit_balances AS b (organization_id, balance_nano_eur)
    VALUES (NEW.organization_id, NEW.amount_nano_eur)
    ON CONFLICT (organization_id) DO UPDATE
        SET balance_nano_eur = b.balance_nano_eur + EXCLUDED.balance_nano_eur,
            updated_at = pg_catalog.now();
    PERFORM pg_catalog.pg_notify('credit_changes', NEW.organization_id);
    RETURN NULL;
END;
$$;

CREATE FUNCTION public.codewire_notify_credit_change() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    PERFORM pg_catalog.pg_notify('credit_changes', NEW.id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER organizations_credit_changes
    AFTER UPDATE OF auto_top_up_enabled, auto_top_up_cents, credit_exhausted_at
    ON public.organizations
    FOR EACH ROW
    WHEN (OLD.auto_top_up_enabled IS DISTINCT FROM NEW.auto_top_up_enabled
          OR OLD.auto_top_up_cents IS DISTINCT FROM NEW.auto_top_up_cents
          OR OLD.credit_exhausted_at IS DISTINCT FROM NEW.credit_exhausted_at)
    EXECUTE FUNCTION public.codewire_notify_credit_change();

REVOKE ALL ON FUNCTION public.codewire_notify_credit_change() FROM PUBLIC;
