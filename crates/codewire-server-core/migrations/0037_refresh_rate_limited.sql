-- A refresh the provider rate-limited (#4975; docs/dev/SECRETS-AND-CREDENTIALS.md,
-- "A refresh the provider rate-limited"). A started attempt the provider
-- answered 429, with the whole response read, is closed as `rate_limited`,
-- with the time its wait ends; no refresh of that credential begins before
-- then. The attempt begun after the wait is `after_rate_limit` and cannot be
-- rate-limited again, so any failure of it is terminal: one wait, one retry,
-- held for every replica and across restarts.
--
-- Compatible: the new columns default to NULL and false, and no row changes.
-- Older code reads a `rate_limited` row as a corrupt record: it answers an
-- error for that credential and begins no refresh of it, and never marks it
-- for reconnecting.
-- Rollback: delete the `rate_limited` rows, restore the two checks as in
-- 0001_baseline.sql, then drop the constraint and the two columns.

ALTER TABLE public.platform_credential_refresh_attempts
    ADD COLUMN rate_limited_until timestamp with time zone,
    ADD COLUMN after_rate_limit boolean DEFAULT false NOT NULL;

ALTER TABLE public.platform_credential_refresh_attempts
    DROP CONSTRAINT platform_credential_refresh_attempts_state_check,
    ADD CONSTRAINT platform_credential_refresh_attempts_state_check CHECK (state = ANY (ARRAY[
        'reserved'::text, 'started'::text, 'staged'::text, 'committed'::text,
        'unknown'::text, 'cancelled'::text, 'rate_limited'::text])),
    DROP CONSTRAINT platform_credential_refresh_attempts_started_check,
    ADD CONSTRAINT platform_credential_refresh_attempts_started_check CHECK (
        ((state = ANY (ARRAY['reserved'::text, 'cancelled'::text]))
            AND (started_at IS NULL) AND (started_until IS NULL))
        OR ((state = ANY (ARRAY['started'::text, 'staged'::text, 'committed'::text,
                                'unknown'::text, 'rate_limited'::text]))
            AND (started_at IS NOT NULL) AND (started_until IS NOT NULL)
            AND (started_until > started_at))),
    ADD CONSTRAINT platform_credential_refresh_attempts_rate_limited_check CHECK (
        ((state = 'rate_limited'::text) = (rate_limited_until IS NOT NULL))
        AND (rate_limited_until IS NULL OR rate_limited_until > started_at));
