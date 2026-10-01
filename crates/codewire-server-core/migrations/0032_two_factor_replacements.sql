-- Replacing an enrolled authenticator keeps the current factor active until a
-- code from the new one verifies. A pending replacement belongs to one account
-- and to the one browser session that proved the account: it disappears with
-- either, expires after ten minutes and allows five confirmation attempts. Only
-- the encrypted pending secret is stored, in the same base64 AES-256-GCM layout
-- as two_factor.secret; no plaintext secret or recovery code is stored here.
CREATE TABLE public.two_factor_replacements (
    id text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    user_id text NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    session_id text NOT NULL REFERENCES public.sessions(id) ON DELETE CASCADE,
    secret text NOT NULL CHECK (
        length(secret) BETWEEN 40 AND 1024 AND secret ~ '^[A-Za-z0-9+/]+={0,2}$'
    ),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT two_factor_replacements_user_key UNIQUE (user_id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes')
);
CREATE INDEX two_factor_replacements_session ON public.two_factor_replacements(session_id);
CREATE INDEX two_factor_replacements_expiry ON public.two_factor_replacements(expires_at);

-- A disabled account cannot start a replacement, matching every other factor
-- and capability writer. Disablement deletes sessions, which cascades here.
CREATE TRIGGER codewire_require_enabled_two_factor_replacement
BEFORE INSERT ON public.two_factor_replacements
FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

-- The newest time step accepted for this factor. A fresh proof must use a later
-- step, so a code already used to sign in or to prove the account cannot be
-- replayed. NULL means no step has been recorded yet.
ALTER TABLE public.two_factor
    ADD COLUMN last_totp_step bigint CHECK (last_totp_step IS NULL OR last_totp_step >= 0);
