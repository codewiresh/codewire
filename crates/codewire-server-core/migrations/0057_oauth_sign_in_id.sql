-- Each OAuth access and refresh token names the sign-in it belongs to
-- (#5688). The IdP mints the id when a code or device code is exchanged and
-- copies it on every refresh, so revoking any of a sign-in's tokens ends the
-- whole sign-in, as `cw logout` means. Rows from before keep NULL: revoking
-- one ends only that token, as today, and its first refresh starts a
-- sign-in. No row is changed.
--
-- Rollback: an older binary never reads or writes the column, and revokes
-- by digest only. Dropping the column and its two indexes undoes this.
ALTER TABLE public.oidc_access_tokens ADD COLUMN sign_in_id text;
ALTER TABLE public.oidc_refresh_tokens ADD COLUMN sign_in_id text;

CREATE INDEX oidc_access_tokens_sign_in_id_idx
    ON public.oidc_access_tokens (sign_in_id) WHERE sign_in_id IS NOT NULL;
CREATE INDEX oidc_refresh_tokens_sign_in_id_idx
    ON public.oidc_refresh_tokens (sign_in_id) WHERE sign_in_id IS NOT NULL;
