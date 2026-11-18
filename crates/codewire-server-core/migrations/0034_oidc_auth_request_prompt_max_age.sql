-- OIDC `prompt` and `max_age` on stored authorization requests.
--
-- A client may ask for a fresh sign-in (`prompt=login`) or for one no older
-- than `max_age` seconds. The provider sends the user to sign in, and the
-- sign-in resumes the stored request. These columns keep both values through
-- that round trip, so the resumed request accepts only a session the user
-- signed in to after the original request (or within `max_age` of it), not an
-- older one presented at the callback directly.
--
-- Compatible: both columns are nullable and older code neither writes nor
-- reads them; a request an older replica stores has neither. Rollback drops
-- the constraint and the columns.

ALTER TABLE public.oidc_auth_requests
    ADD COLUMN prompt text,
    ADD COLUMN max_age bigint,
    ADD CONSTRAINT oidc_auth_requests_max_age_check CHECK (max_age IS NULL OR max_age >= 0);
