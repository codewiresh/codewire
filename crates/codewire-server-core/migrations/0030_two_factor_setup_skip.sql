-- A browser session may skip two-factor setup. The choice belongs to that one
-- session: it ends at sign-out or expiry, and the next sign-in asks again. It
-- never affects an account that has already enabled two-factor authentication.
ALTER TABLE public.sessions ADD COLUMN two_factor_setup_skipped_at timestamp without time zone;
