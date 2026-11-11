-- When an account's Codewire CLI was first issued tokens through the device
-- sign-in: the dashboard's Get started checklist ticks "Install the CLI" from
-- it. The IdP sets it once, in the statement that redeems an approved device
-- grant, and never clears it, so signing the CLI out does not un-tick the
-- step. API keys do not set it.
--
-- Adding a nullable column changes no existing row, and code that does not
-- read it ignores it. An account that already holds a token issued to a
-- device-grant client is marked at its earliest such token.
ALTER TABLE public.users ADD COLUMN cli_signed_in_at timestamp with time zone;

UPDATE public.users AS account
   SET cli_signed_in_at = earliest.issued_at
  FROM (
      SELECT token.user_id, min(token.created_at) AS issued_at
        FROM (
            SELECT user_id, client_id, created_at FROM public.oidc_refresh_tokens
            UNION ALL
            SELECT user_id, client_id, created_at FROM public.oidc_access_tokens
        ) AS token
        JOIN public.oidc_clients AS client ON client.id = token.client_id
       WHERE 'urn:ietf:params:oauth:grant-type:device_code' = ANY (client.grant_types)
       GROUP BY token.user_id
  ) AS earliest
 WHERE account.id = earliest.user_id;
