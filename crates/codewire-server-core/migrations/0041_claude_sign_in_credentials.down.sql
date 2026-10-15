-- In-place rollback is safe only while no Claude sign-in exists: the prior
-- schema cannot hold one, and its owner's login must not be discarded to make
-- a rollback succeed. Revoke and delete each one first, or restore the
-- accepted prior schema from a separately owned backup.
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM public.platform_credentials
              WHERE authentication_kind = 'claude_sign_in') THEN
        RAISE EXCEPTION 'Claude sign-in credentials prevent in-place rollback';
    END IF;
END $$;
ALTER TABLE public.platform_credentials
    DROP CONSTRAINT platform_credentials_claude_sign_in_check,
    DROP CONSTRAINT platform_credentials_authentication_kind_check,
    ADD CONSTRAINT platform_credentials_authentication_kind_check CHECK (
        authentication_kind IN ('oauth', 'api_key', 'access_token', 'github_app', 'ssh_key')
    );
