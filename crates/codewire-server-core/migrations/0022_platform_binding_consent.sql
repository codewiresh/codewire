-- Confirmation is an explicit choice for this exact binding, never inferred
-- from account enrollment or organization membership. Existing rows remain
-- unconfirmed; runtime denies personal-profile use until explicitly rebound.
ALTER TABLE public.platform_environment_access_bindings
    ADD COLUMN personal_owner_confirmed_by text
    REFERENCES public.users(id) ON DELETE SET NULL;

-- Profile management may fence credential metadata without permission to
-- mutate credential lifecycle state or read protected material. The caller
-- must authenticate and authorize the exact scope before using this helper.
CREATE FUNCTION public.codewire_platform_lock_credential(
    credential_id text, user_scope text, organization_scope text
)
RETURNS TABLE (
    provider text, authentication_kind text, display_name text, account_hint text,
    status text, expires_at_unix bigint, revocation_generation bigint
)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT c.provider, c.authentication_kind, c.display_name, c.account_hint,
           c.status, c.expires_at_unix, c.revocation_generation
    FROM public.platform_credentials AS c
    WHERE c.id = $1 AND (c.user_id = $2 OR c.organization_id = $3)
    FOR SHARE OF c;
$$;
REVOKE ALL ON FUNCTION public.codewire_platform_lock_credential(text, text, text) FROM PUBLIC;
