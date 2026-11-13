-- Consumed OIDC refresh tokens: one row per refresh token the provider has
-- exchanged, kept until the token would have expired.
--
-- Refresh tokens rotate: each exchange deletes the presented token and issues
-- a new one. A rotated token presented again was copied, by whoever holds it
-- now or by the client that rotated it. Either way the provider cannot tell
-- which copy is legitimate, so it revokes every refresh and access token that
-- user holds for that client (RFC 9700 section 4.14.2). This table is how it
-- recognises a rotated token: the exchange records its digest here in the
-- same transaction that deletes it. Rows past their expiry are removed as new
-- ones are written.
--
-- Deleting the user or the client deletes its rows.
--
-- Compatible: the table is new, and older code neither reads nor writes it; a
-- token an older replica exchanges is simply not recorded. Rollback drops the
-- table, which ends reuse detection; tokens and sign-ins are unaffected.

CREATE TABLE public.oidc_consumed_refresh_tokens (
    token_hash text NOT NULL,
    client_id text NOT NULL,
    user_id text NOT NULL,
    consumed_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT oidc_consumed_refresh_tokens_pkey PRIMARY KEY (token_hash),
    CONSTRAINT oidc_consumed_refresh_tokens_token_hash_format_check
        CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT oidc_consumed_refresh_tokens_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES public.oidc_clients(id) ON DELETE CASCADE,
    CONSTRAINT oidc_consumed_refresh_tokens_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
);

CREATE INDEX oidc_consumed_refresh_tokens_expires_at_idx
    ON public.oidc_consumed_refresh_tokens USING btree (expires_at);
