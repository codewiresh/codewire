-- User tokens (#5688): opaque access tokens for the product API that a `cw`
-- sign-in exchanges for its own (`cw auth token`), each with a lifetime the
-- person chose, or none, and no refresh token. One row per token, by the
-- SHA-256 digest of its value; the id names it in Settings and the audit log.
--
-- A token ends with its sign-in (`sign_in_id`, from 0057): revoking any of
-- that sign-in's tokens deletes its user tokens in the same transaction. A
-- password reset, account deletion and refresh-token reuse delete the user's,
-- and deleting the user or the client deletes its rows. Disabling an account
-- deletes them with its other OAuth tokens (codewire_revoke_user_capabilities,
-- replaced below with one more line), and none can be stored for a disabled
-- account (codewire_require_enabled_account, as for access tokens).
--
-- Deleting a row ends the streams it admitted, as for an access token, under
-- its own revocation kind, `user_token`, keyed by the token's id, and writes
-- `user_token.revoked` to the audit log with the token's id and sign-in, so
-- every way a token ends is audited. A delete cascading from the user's own
-- removes the row's user from the audit row, which can't name a deleted user.
--
-- Compatible: the table and the kind are new. An older binary never reads
-- the table, so a rollback refuses every user token, and it ignores a
-- revocation kind it doesn't know. Rollback, in this order: put back the
-- baseline's codewire_revoke_user_capabilities (without the oidc_user_tokens
-- line), or disabling an account fails on the missing table; drop the two
-- triggers, the streams function and the table; then put back 0054's kind
-- check, after deleting any `user_token` revocation rows.

CREATE TABLE public.oidc_user_tokens (
    id text NOT NULL,
    token_hash text NOT NULL,
    client_id text NOT NULL,
    user_id text NOT NULL,
    sign_in_id text NOT NULL,
    scopes text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    -- NULL lives until it is revoked.
    expires_at timestamp with time zone,
    CONSTRAINT oidc_user_tokens_pkey PRIMARY KEY (id),
    CONSTRAINT oidc_user_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT oidc_user_tokens_token_hash_format_check
        CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT oidc_user_tokens_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES public.oidc_clients(id) ON DELETE CASCADE,
    CONSTRAINT oidc_user_tokens_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
);

CREATE INDEX oidc_user_tokens_sign_in_id_idx
    ON public.oidc_user_tokens USING btree (sign_in_id);
CREATE INDEX oidc_user_tokens_user_id_idx
    ON public.oidc_user_tokens USING btree (user_id);

ALTER TABLE public.credential_revocations
    DROP CONSTRAINT credential_revocations_kind_check,
    ADD CONSTRAINT credential_revocations_kind_check
        CHECK (kind IN ('user', 'session', 'oauth_token', 'oauth_grant', 'api_key',
                        'membership', 'organization', 'user_token'));

CREATE FUNCTION public.codewire_revoke_user_token_streams() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    PERFORM public.codewire_record_credential_revocation('user_token', OLD.id, OLD.user_id);
    INSERT INTO public.audit_logs (id, "timestamp", action, user_id, metadata, severity)
    VALUES (
        pg_catalog.gen_random_uuid()::text,
        pg_catalog.now(),
        'user_token.revoked',
        (SELECT u.id FROM public.users AS u WHERE u.id = OLD.user_id),
        pg_catalog.jsonb_build_object(
            'user_token_id', OLD.id,
            'sign_in_id', OLD.sign_in_id,
            'client_id', OLD.client_id
        ),
        'info'
    );
    RETURN NULL;
END;
$$;

-- As for access tokens, removing an expired row is not a revocation: expiry
-- never ends a stream (#3827).
CREATE TRIGGER oidc_user_tokens_revoke_streams_on_delete
    AFTER DELETE ON public.oidc_user_tokens
    FOR EACH ROW
    WHEN (OLD.expires_at IS NULL OR OLD.expires_at > now())
    EXECUTE FUNCTION public.codewire_revoke_user_token_streams();

REVOKE ALL ON FUNCTION public.codewire_revoke_user_token_streams() FROM PUBLIC;

CREATE TRIGGER codewire_require_enabled_oidc_user_token
    BEFORE INSERT ON public.oidc_user_tokens
    FOR EACH ROW
    EXECUTE FUNCTION public.codewire_require_enabled_account();

-- The baseline's body, with the user tokens deleted beside the access tokens.
CREATE OR REPLACE FUNCTION public.codewire_revoke_user_capabilities() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
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
        DELETE FROM public.oidc_user_tokens WHERE user_id = NEW.id;
        DELETE FROM public.oidc_refresh_tokens WHERE user_id = NEW.id;
        DELETE FROM public.oidc_device_authorizations WHERE user_id = NEW.id;
        DELETE FROM public.two_factor_tokens WHERE user_id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$;
