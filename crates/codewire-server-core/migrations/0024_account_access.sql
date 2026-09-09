-- Account access is additive and defaults existing users to enabled, so the
-- existing account population retains access when the enforcement readers roll
-- out. Access-request writers may set this state explicitly when that product
-- flow is introduced.
ALTER TABLE public.users
    ADD COLUMN enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN access_reason text;

ALTER TABLE public.users
    ADD CONSTRAINT users_access_reason_length_check
    CHECK (
        access_reason IS NULL
        OR (
            char_length(access_reason) BETWEEN 1 AND 2000
            AND access_reason ~ '[^[:space:]]'
        )
    );

CREATE INDEX users_access_review_idx
    ON public.users (enabled, email_verified, created_at DESC)
    WHERE access_reason IS NOT NULL;

-- Account disablement deletes each of these bearer-capability families by
-- user_id. Keep revocation bounded to the affected account as those tables
-- grow; none of the preceding schema versions indexes every predicate.
CREATE INDEX sessions_user_id_idx ON public.sessions (user_id);
CREATE INDEX oidc_auth_requests_user_id_idx ON public.oidc_auth_requests (user_id);
CREATE INDEX oidc_access_tokens_user_id_idx ON public.oidc_access_tokens (user_id);
CREATE INDEX oidc_refresh_tokens_user_id_idx ON public.oidc_refresh_tokens (user_id);
CREATE INDEX oidc_device_authorizations_user_id_idx
    ON public.oidc_device_authorizations (user_id);
CREATE INDEX two_factor_tokens_user_id_idx ON public.two_factor_tokens (user_id);

-- A user disable is security revocation, not suspension. Remove every
-- Codewire-issued bearer capability in the same transaction and retain API
-- key rows only as disabled, expired records, so re-enabling the account
-- cannot revive an old raw key. Identity factors and user-owned configuration
-- remain intact: re-enabling still requires a fresh authentication.
CREATE FUNCTION public.codewire_revoke_user_capabilities()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF OLD.enabled AND NOT NEW.enabled THEN
        DELETE FROM public.sessions WHERE user_id = NEW.id;
        UPDATE public.api_keys
        SET disabled_at = COALESCE(disabled_at, pg_catalog.clock_timestamp()),
            expires_at = LEAST(
                COALESCE(expires_at, pg_catalog.clock_timestamp()),
                pg_catalog.clock_timestamp()
            )
        WHERE user_id = NEW.id;
        DELETE FROM public.oidc_auth_requests WHERE user_id = NEW.id;
        DELETE FROM public.oidc_access_tokens WHERE user_id = NEW.id;
        DELETE FROM public.oidc_refresh_tokens WHERE user_id = NEW.id;
        DELETE FROM public.oidc_device_authorizations WHERE user_id = NEW.id;
        DELETE FROM public.two_factor_tokens WHERE user_id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.codewire_revoke_user_capabilities() FROM PUBLIC;

CREATE TRIGGER codewire_revoke_user_capabilities_on_disable
AFTER UPDATE OF enabled ON public.users
FOR EACH ROW
WHEN (OLD.enabled AND NOT NEW.enabled)
EXECUTE FUNCTION public.codewire_revoke_user_capabilities();

-- These guards are a rolling predecessor-writer compatibility boundary. They
-- take FOR SHARE before creating a capability or moving one to a different
-- owner, so an issuer that wins first is purged by the disabling transaction
-- and an issuer that arrives after disable is denied. UPDATE transition
-- writers already own their capability row, so they use NOWAIT for the user
-- lock: a concurrent disablement makes that writer abort rather than forming
-- a capability -> user cycle against disablement's user -> capability order.
-- Ordinary updates of an existing capability deliberately do not take this
-- user lock: disablement already serializes through and purges that row, and
-- a second lock would invert the user -> capability order. These guards do
-- not make an older service binary runnable against this version-24 SQLx
-- ledger; the documented rollback boundary rebuilds only a disposable
-- application schema from prior source.
CREATE FUNCTION public.codewire_require_enabled_account()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.user_id IS NULL THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        BEGIN
            PERFORM u.id
            FROM public.users AS u
            WHERE u.id = NEW.user_id AND u.enabled
            FOR SHARE NOWAIT;
        EXCEPTION WHEN lock_not_available THEN
            RAISE EXCEPTION USING
                ERRCODE = '55P03',
                MESSAGE = 'account access transition conflicts with disablement';
        END;
    ELSE
        PERFORM u.id
        FROM public.users AS u
        WHERE u.id = NEW.user_id AND u.enabled
        FOR SHARE;
    END IF;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'account access is disabled';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.codewire_require_enabled_account() FROM PUBLIC;

CREATE FUNCTION public.codewire_require_enabled_api_key()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    -- The revocation trigger marks existing keys disabled and expired while
    -- the owner row is already disabled. A disabled key is not a bearer
    -- capability and must remain mutable for administrative cleanup; clearing
    -- disabled_at after re-enable cannot undo its retired expiry.
    IF NEW.disabled_at IS NOT NULL THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        BEGIN
            PERFORM u.id
            FROM public.users AS u
            WHERE u.id = NEW.user_id AND u.enabled
            FOR SHARE NOWAIT;
        EXCEPTION WHEN lock_not_available THEN
            RAISE EXCEPTION USING
                ERRCODE = '55P03',
                MESSAGE = 'account access transition conflicts with disablement';
        END;
    ELSE
        PERFORM u.id
        FROM public.users AS u
        WHERE u.id = NEW.user_id AND u.enabled
        FOR SHARE;
    END IF;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'account access is disabled';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.codewire_require_enabled_api_key() FROM PUBLIC;

CREATE TRIGGER codewire_require_enabled_session
BEFORE INSERT ON public.sessions
FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

CREATE TRIGGER codewire_require_enabled_api_key
BEFORE INSERT ON public.api_keys
FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_api_key();

CREATE TRIGGER codewire_require_enabled_api_key_reactivation
BEFORE UPDATE OF disabled_at ON public.api_keys
FOR EACH ROW
WHEN (OLD.disabled_at IS NOT NULL AND NEW.disabled_at IS NULL)
EXECUTE FUNCTION public.codewire_require_enabled_api_key();

CREATE TRIGGER codewire_require_enabled_oidc_auth_request
BEFORE INSERT ON public.oidc_auth_requests
FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

CREATE TRIGGER codewire_require_enabled_oidc_auth_request_subject
BEFORE UPDATE OF user_id ON public.oidc_auth_requests
FOR EACH ROW
WHEN (OLD.user_id IS DISTINCT FROM NEW.user_id AND NEW.user_id IS NOT NULL)
EXECUTE FUNCTION public.codewire_require_enabled_account();

CREATE TRIGGER codewire_require_enabled_oidc_access_token
BEFORE INSERT ON public.oidc_access_tokens
FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

CREATE TRIGGER codewire_require_enabled_oidc_refresh_token
BEFORE INSERT ON public.oidc_refresh_tokens
FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

CREATE TRIGGER codewire_require_enabled_oidc_device_authorization
BEFORE INSERT ON public.oidc_device_authorizations
FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

CREATE TRIGGER codewire_require_enabled_oidc_device_authorization_subject
BEFORE UPDATE OF user_id ON public.oidc_device_authorizations
FOR EACH ROW
WHEN (OLD.user_id IS DISTINCT FROM NEW.user_id AND NEW.user_id IS NOT NULL)
EXECUTE FUNCTION public.codewire_require_enabled_account();

CREATE TRIGGER codewire_require_enabled_two_factor_token
BEFORE INSERT ON public.two_factor_tokens
FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

CREATE TRIGGER codewire_require_enabled_two_factor
BEFORE INSERT ON public.two_factor
FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

-- Migration 0023 created this helper. Replacing it here preserves its exact
-- signature and least-privilege grants while adding the account-access fence
-- needed by OAuth operations that began before an administrator disables a
-- user. Applied migration bytes remain untouched.
CREATE OR REPLACE FUNCTION public.codewire_lock_oauth_bearer_authority(
    token_digest text, original_user_id text, original_client_id text,
    original_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    -- Fixed lock order matches the credential store's owner-first fence.
    -- SHARE, not KEY SHARE, also blocks non-key authorization changes.
    PERFORM u.id FROM public.users AS u
    WHERE u.id = $2 AND u.enabled
    FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    PERFORM c.id FROM public.oidc_clients AS c
    WHERE c.id = $3 AND NOT c.disabled FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    PERFORM t.token_hash FROM public.oidc_access_tokens AS t
    WHERE t.token_hash = $1 AND t.user_id = $2 AND t.client_id = $3
      AND t.expires_at = $4 AND 'codewire.api' = ANY(t.scopes)
    FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    -- NOW() is the transaction-start timestamp and can precede a long lock
    -- wait. Check the original immutable expiry after every lock has settled.
    RETURN $4 > pg_catalog.clock_timestamp();
END;
$$;
REVOKE ALL ON FUNCTION public.codewire_lock_oauth_bearer_authority(text, text, text, timestamptz) FROM PUBLIC;
