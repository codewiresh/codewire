-- Fresh typed SSH enrollment. No legacy key import, runtime capability or
-- material format translation. Public identity and protected envelope are
-- published together by the existing isolated credential authority.
ALTER TABLE public.platform_credentials
    ADD COLUMN ssh_public_key text,
    ADD COLUMN ssh_fingerprint text;

ALTER TABLE public.platform_credentials
    DROP CONSTRAINT platform_credentials_authentication_kind_check,
    ADD CONSTRAINT platform_credentials_authentication_kind_check CHECK (
        authentication_kind IN ('oauth', 'api_key', 'access_token', 'github_app', 'ssh_key')
    ),
    ADD CONSTRAINT platform_credentials_ssh_identity_check CHECK (
        (provider = 'ssh') = (authentication_kind = 'ssh_key')
        AND (ssh_public_key IS NOT NULL) = (authentication_kind = 'ssh_key')
        AND (ssh_fingerprint IS NOT NULL) = (authentication_kind = 'ssh_key')
        AND (authentication_kind <> 'ssh_key' OR account_hint IS NULL)
    ),
    ADD CONSTRAINT platform_credentials_ssh_public_key_check CHECK (
        octet_length(ssh_public_key) BETWEEN 1 AND 4096
        AND ssh_public_key ~ '^(ssh-ed25519|ssh-rsa) [A-Za-z0-9+/]+={0,2}$'
        AND octet_length(split_part(ssh_public_key, ' ', 2)) >= 20
        AND octet_length(split_part(ssh_public_key, ' ', 2)) % 4 = 0
        AND ssh_public_key !~ '[[:cntrl:]]'
    ),
    ADD CONSTRAINT platform_credentials_ssh_fingerprint_check CHECK (
        octet_length(ssh_fingerprint) = 50
        AND ssh_fingerprint ~ '^SHA256:[A-Za-z0-9+/]{43}$'
        AND ssh_fingerprint !~ '[[:cntrl:]]'
    );

-- Existing metadata SELECT and credential INSERT permissions suffice. In
-- particular, this migration neither changes the immutable credential SHARE
-- helper nor grants public identity UPDATE to the restricted broker role.
