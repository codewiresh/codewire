-- Claude Code's own claude.ai sign-in (#2559): a personal OAuth login whose
-- refresh token rotates, enrolled by Codewire. It is its own authentication
-- kind, so it is never confused with a pasted Claude subscription token, which
-- stays the anthropic provider's 'oauth' kind with its raw material unchanged.
-- Like every OAuth login it is personal: only a user holds one, and only for
-- the anthropic provider. Existing rows are untouched.
ALTER TABLE public.platform_credentials
    DROP CONSTRAINT platform_credentials_authentication_kind_check,
    ADD CONSTRAINT platform_credentials_authentication_kind_check CHECK (
        authentication_kind IN (
            'oauth', 'api_key', 'access_token', 'github_app', 'ssh_key', 'claude_sign_in'
        )
    ),
    ADD CONSTRAINT platform_credentials_claude_sign_in_check CHECK (
        authentication_kind <> 'claude_sign_in'
        OR (provider = 'anthropic' AND user_id IS NOT NULL AND organization_id IS NULL)
    );
