-- Browser credential management retains one exact authenticated session
-- reference without giving the isolated credential service table authority.
CREATE FUNCTION public.codewire_authenticate_credential_session(token_digest text)
RETURNS TABLE(session_id text, user_id text, is_admin boolean, expires_at timestamptz)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET TimeZone = 'UTC'
AS $$
    WITH refreshed AS (
        UPDATE public.sessions AS s
           SET expires_at = GREATEST(s.expires_at, NOW() + interval '8 hours'),
               updated_at = NOW()
          FROM public.users AS u
         WHERE s.token_hash = $1
           AND $1 ~ '^[0-9a-f]{64}$'
           AND s.expires_at > NOW()
           AND s.user_id = u.id
           AND u.enabled
         RETURNING s.id, s.user_id, u.is_admin, s.expires_at
    )
    SELECT r.id, r.user_id, r.is_admin, r.expires_at AT TIME ZONE 'UTC'
      FROM refreshed AS r
$$;

CREATE FUNCTION public.codewire_lock_credential_session_authority(
    original_session_id text, token_digest text, original_user_id text,
    original_expires_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET TimeZone = 'UTC'
AS $$
BEGIN
    PERFORM u.id FROM public.users AS u WHERE u.id = $3 AND u.enabled FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    PERFORM s.id FROM public.sessions AS s
    WHERE s.id = $1 AND s.token_hash = $2 AND s.user_id = $3
      AND $2 ~ '^[0-9a-f]{64}$'
      AND s.expires_at >= $4
    FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    -- A later authentication may extend the row, but never this captured
    -- authority. The wall check therefore uses its original fixed expiry.
    RETURN $4 > pg_catalog.clock_timestamp();
END;
$$;

REVOKE ALL ON FUNCTION public.codewire_authenticate_credential_session(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.codewire_lock_credential_session_authority(text, text, text, timestamptz) FROM PUBLIC;
