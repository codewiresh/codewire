-- This fixed metadata fence is not authentication. The trusted caller first
-- retains OAuthBearerAuthority's original user/client/token locks in this same
-- transaction, then locks the exact owner/source scope before reading it.
-- No platform environment, Pod identity, secret value, role or table grant is
-- created or consulted. Deployment separately grants this exact signature.
CREATE FUNCTION public.codewire_platform_lock_owner_source_authority(
    user_id text, organization_id text, project_id text
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    -- SHARE also fences non-key changes to membership and deletion state.
    -- Preserve the owner-first order after the original OAuth authority fence.
    PERFORM u.id FROM public.users AS u WHERE u.id = $1 FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    PERFORM o.id FROM public.organizations AS o
        WHERE o.id = $2 AND o.deletion_state = 'active' FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    PERFORM m.id FROM public.org_members AS m
        WHERE m.org_id = $2 AND m.user_id = $1 AND m.role <> '' FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    -- NULL means no selected project, never a wildcard project selection.
    IF $3 IS NOT NULL THEN
        PERFORM p.id FROM public.secret_projects AS p
            WHERE p.id = $3 AND p.org_id = $2 FOR SHARE;
        IF NOT FOUND THEN RETURN false; END IF;
    END IF;
    RETURN true;
END;
$$;
REVOKE ALL ON FUNCTION public.codewire_platform_lock_owner_source_authority(text, text, text) FROM PUBLIC;
