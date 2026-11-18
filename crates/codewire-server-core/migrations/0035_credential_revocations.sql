-- Credential revocations (#3586): a log of each loss of authority that must
-- end a stream already admitted, and a wake-up on `credential_revocations`
-- (docs/dev/AUTH-POLICY.md, "Account access revocation"; private-docs
-- designs/stream-revocation.md).
--
-- Only database code writes the log, so no service call site has to remember
-- to; a repository check refuses service code that writes it (cw-security,
-- 2026-11-17: the services run as the database's owner, #5166, so a grant
-- could not enforce it). A row is written when:
-- - a user is disabled or deleted while enabled;
-- - a browser session or an OAuth access token is deleted before it expired.
--   Expired rows removed by cleanup write nothing, since expiry never ends a
--   stream (#3827);
-- - an API key is disabled, or deleted while enabled;
-- - refresh-token reuse revokes a grant, through codewire_revoke_oauth_grant.
--
-- A row holds ids and token hashes, never a credential. Rows older than an
-- hour are removed by the writing function: a reader holds a gap in the
-- sequence (an uncommitted or rolled-back write) at most that long, and
-- admission looks back that far.
--
-- The wake-up carries no payload, so Postgres folds a transaction's wake-ups
-- into one; a listener reads the rows by sequence.
--
-- Compatible: new table, functions and triggers; older code ignores them.
-- Rollback: drop the triggers, then the functions, then the table.

CREATE TABLE public.credential_revocations (
    seq bigint GENERATED ALWAYS AS IDENTITY,
    kind text NOT NULL,
    credential_id text NOT NULL,
    user_id text NOT NULL,
    revoked_at timestamp with time zone DEFAULT now() NOT NULL,
    -- The writing transaction. A stream registers with a snapshot taken
    -- before its admission is re-read, and a row whose transaction that
    -- snapshot already sees never ends it: the re-read decided on it.
    xact xid8 DEFAULT pg_current_xact_id() NOT NULL,
    CONSTRAINT credential_revocations_pkey PRIMARY KEY (seq),
    CONSTRAINT credential_revocations_kind_check
        CHECK (kind IN ('user', 'session', 'oauth_token', 'oauth_grant', 'api_key'))
);

CREATE INDEX credential_revocations_credential_idx
    ON public.credential_revocations (kind, credential_id);
CREATE INDEX credential_revocations_user_idx
    ON public.credential_revocations (user_id);
CREATE INDEX credential_revocations_revoked_at_idx
    ON public.credential_revocations (revoked_at);

CREATE FUNCTION public.codewire_record_credential_revocation(
    revoked_kind text, revoked_credential_id text, revoked_user_id text
) RETURNS void
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    DELETE FROM public.credential_revocations
     WHERE revoked_at < pg_catalog.now() - interval '1 hour';
    INSERT INTO public.credential_revocations (kind, credential_id, user_id)
    VALUES (revoked_kind, revoked_credential_id, revoked_user_id);
    PERFORM pg_catalog.pg_notify('credential_revocations', '');
END;
$$;

-- The refresh-token reuse path calls this inside its own transaction: the
-- grant is the user and the client, so a stream admitted by an access token
-- of that grant ends even when the token itself has since expired.
CREATE FUNCTION public.codewire_revoke_oauth_grant(grant_user_id text, grant_client_id text)
    RETURNS void
    LANGUAGE sql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
    SELECT public.codewire_record_credential_revocation('oauth_grant', grant_client_id, grant_user_id);
$$;

CREATE FUNCTION public.codewire_revoke_user_streams() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    PERFORM public.codewire_record_credential_revocation('user', OLD.id, OLD.id);
    RETURN NULL;
END;
$$;

CREATE FUNCTION public.codewire_revoke_session_streams() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    PERFORM public.codewire_record_credential_revocation('session', OLD.id, OLD.user_id);
    RETURN NULL;
END;
$$;

CREATE FUNCTION public.codewire_revoke_access_token_streams() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    PERFORM public.codewire_record_credential_revocation('oauth_token', OLD.token_hash, OLD.user_id);
    RETURN NULL;
END;
$$;

CREATE FUNCTION public.codewire_revoke_api_key_streams() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    PERFORM public.codewire_record_credential_revocation('api_key', OLD.id, OLD.user_id);
    RETURN NULL;
END;
$$;

CREATE TRIGGER users_revoke_streams_on_disable
    AFTER UPDATE OF enabled ON public.users
    FOR EACH ROW
    WHEN (OLD.enabled AND NOT NEW.enabled)
    EXECUTE FUNCTION public.codewire_revoke_user_streams();

CREATE TRIGGER users_revoke_streams_on_delete
    AFTER DELETE ON public.users
    FOR EACH ROW
    WHEN (OLD.enabled)
    EXECUTE FUNCTION public.codewire_revoke_user_streams();

-- `sessions.expires_at` has no time zone; it compares with now() as the
-- session lookups do.
CREATE TRIGGER sessions_revoke_streams_on_delete
    AFTER DELETE ON public.sessions
    FOR EACH ROW
    WHEN (OLD.expires_at > now())
    EXECUTE FUNCTION public.codewire_revoke_session_streams();

CREATE TRIGGER oidc_access_tokens_revoke_streams_on_delete
    AFTER DELETE ON public.oidc_access_tokens
    FOR EACH ROW
    WHEN (OLD.expires_at > now())
    EXECUTE FUNCTION public.codewire_revoke_access_token_streams();

CREATE TRIGGER api_keys_revoke_streams_on_disable
    AFTER UPDATE OF disabled_at ON public.api_keys
    FOR EACH ROW
    WHEN (OLD.disabled_at IS NULL AND NEW.disabled_at IS NOT NULL)
    EXECUTE FUNCTION public.codewire_revoke_api_key_streams();

CREATE TRIGGER api_keys_revoke_streams_on_delete
    AFTER DELETE ON public.api_keys
    FOR EACH ROW
    WHEN (OLD.disabled_at IS NULL)
    EXECUTE FUNCTION public.codewire_revoke_api_key_streams();

REVOKE ALL ON FUNCTION public.codewire_record_credential_revocation(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.codewire_revoke_oauth_grant(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.codewire_revoke_user_streams() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.codewire_revoke_session_streams() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.codewire_revoke_access_token_streams() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.codewire_revoke_api_key_streams() FROM PUBLIC;
