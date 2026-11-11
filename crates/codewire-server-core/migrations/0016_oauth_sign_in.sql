-- Sign in with GitHub or Google (#4062).
--
-- A provider identity is an `accounts` row with `provider_id` 'github' or
-- 'google' and `account_id` the provider's stable subject (GitHub's numeric
-- user id, Google's `sub`). One identity belongs to at most one Codewire user,
-- so a partial unique index covers exactly those two providers. Being partial,
-- it cannot fail on the existing 'credential' rows, whose `account_id` is the
-- email and which this migration leaves alone. No provider token is stored.
--
-- `oauth_states` holds the short-lived, single-use rows of a provider round
-- trip. The IdP stores only the SHA-256 of each random handle; the browser
-- (or, for a link confirmation, an email) holds the handle. A row is one of:
--   * 'sign_in': a started sign-in, with its PKCE verifier, an OIDC nonce for
--     Google, and the return target (an OIDC auth request id or a same-origin
--     path). The callback deletes it in the statement that reads it.
--     `client_address_hash` (a keyed hash of the starting client's address,
--     never the address) bounds how many a client can hold at once.
--   * 'link': the same for a signed-in user linking a provider from Settings
--     (that user is `user_id`). Nothing writes it until that slice ships.
--   * 'sign_up': a provider identity with no Codewire account, waiting between
--     the callback and the completion page. `provider_identity` holds the
--     provider subject, email and display name; completing sign-up deletes it.
--   * 'link_confirm': a provider identity whose verified email matches the
--     account `user_id`, waiting at most 30 minutes for that account's own
--     email address to confirm the link. One per account and provider; a new
--     one replaces the old, and confirming deletes it. `requester_hash` is the
--     SHA-256 of a second secret held in a cookie by the browser that started
--     the sign-in: the emailed link completes only in that browser, so a
--     stranger who triggers the email cannot have the account's owner link
--     the stranger's identity.
-- The IdP deletes expired rows whenever it starts or finishes a round trip.
-- A user's rows go with the user.
--
-- Compatible: the index constrains only provider rows, which older code never
-- writes, and the table is new, so older code reads nothing from it. Rollback
-- drops the table and the index, which forgets round trips and confirmations
-- in flight; linked identities stay as plain `accounts` rows.

CREATE UNIQUE INDEX accounts_provider_identity_key
    ON public.accounts USING btree (provider_id, account_id)
    WHERE (provider_id = ANY (ARRAY['github'::text, 'google'::text]));

CREATE TABLE public.oauth_states (
    id text NOT NULL,
    token_hash text NOT NULL,
    provider text NOT NULL,
    intent text NOT NULL,
    user_id text,
    pkce_verifier text,
    nonce text,
    return_auth_request_id text,
    return_to text,
    provider_identity jsonb,
    client_address_hash text,
    requester_hash text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT oauth_states_pkey PRIMARY KEY (id),
    CONSTRAINT oauth_states_token_hash_key UNIQUE (token_hash),
    CONSTRAINT oauth_states_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT oauth_states_token_hash_format_check CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT oauth_states_provider_check
        CHECK (provider = ANY (ARRAY['github'::text, 'google'::text])),
    -- Only a link or a link confirmation names a user; only a pending sign-up
    -- or a link confirmation carries an identity; only a round trip in flight
    -- carries a PKCE verifier, a Google one a nonce, and a client address; a
    -- link confirmation returns nowhere and lives at most 30 minutes.
    CONSTRAINT oauth_states_intent_shape_check CHECK (
        CASE intent
            WHEN 'sign_in' THEN user_id IS NULL AND provider_identity IS NULL
                AND pkce_verifier IS NOT NULL
                AND (nonce IS NOT NULL) = (provider = 'google')
            WHEN 'link' THEN user_id IS NOT NULL AND provider_identity IS NULL
                AND pkce_verifier IS NOT NULL
                AND (nonce IS NOT NULL) = (provider = 'google')
            WHEN 'sign_up' THEN user_id IS NULL AND provider_identity IS NOT NULL
                AND pkce_verifier IS NULL AND nonce IS NULL
                AND client_address_hash IS NULL
            WHEN 'link_confirm' THEN user_id IS NOT NULL AND provider_identity IS NOT NULL
                AND pkce_verifier IS NULL AND nonce IS NULL
                AND client_address_hash IS NULL
                AND return_auth_request_id IS NULL AND return_to IS NULL
                AND expires_at <= created_at + interval '30 minutes'
            ELSE false
        END
    ),
    CONSTRAINT oauth_states_pkce_verifier_check
        CHECK (pkce_verifier ~ '^[A-Za-z0-9._~-]{43,128}$'),
    CONSTRAINT oauth_states_nonce_check CHECK (char_length(nonce) BETWEEN 16 AND 128),
    CONSTRAINT oauth_states_return_auth_request_id_check
        CHECK (char_length(return_auth_request_id) BETWEEN 1 AND 256),
    CONSTRAINT oauth_states_return_to_check
        CHECK (char_length(return_to) BETWEEN 1 AND 2048 AND return_to ~ '^/'),
    CONSTRAINT oauth_states_provider_identity_check
        CHECK (jsonb_typeof(provider_identity) = 'object'),
    CONSTRAINT oauth_states_client_address_hash_check
        CHECK (client_address_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT oauth_states_requester_hash_check
        CHECK (requester_hash ~ '^[0-9a-f]{64}$'),
    -- Exactly a link confirmation is bound to the browser that asked for it.
    CONSTRAINT oauth_states_requester_shape_check
        CHECK ((intent = 'link_confirm') = (requester_hash IS NOT NULL)),
    CONSTRAINT oauth_states_expiry_check
        CHECK (expires_at > created_at AND expires_at <= created_at + interval '1 hour')
);

CREATE INDEX oauth_states_expires_at_idx ON public.oauth_states USING btree (expires_at);
CREATE INDEX oauth_states_user_id_idx ON public.oauth_states USING btree (user_id)
    WHERE (user_id IS NOT NULL);
CREATE UNIQUE INDEX oauth_states_link_confirm_key
    ON public.oauth_states USING btree (user_id, provider)
    WHERE (intent = 'link_confirm'::text);
CREATE INDEX oauth_states_client_address_idx
    ON public.oauth_states USING btree (client_address_hash)
    WHERE (intent = 'sign_in'::text);
