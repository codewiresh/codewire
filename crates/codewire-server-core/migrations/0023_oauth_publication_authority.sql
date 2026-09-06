-- Long-running enrollment retains the original OAuth access-token identity,
-- never the raw bearer. This fixed helper fences its publication transaction
-- against user deletion, client disable/deletion and exact-token revocation.
-- It authenticates no caller by itself; only the trusted enrollment service
-- receives its exact EXECUTE grant. No role or table grant is created here.
CREATE FUNCTION public.codewire_lock_oauth_bearer_authority(
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
    PERFORM u.id FROM public.users AS u WHERE u.id = $2 FOR SHARE;
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
