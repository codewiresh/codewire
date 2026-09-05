-- The broker may fence owner/grant metadata without UPDATE authority over it.
-- These functions belong to the canonical migration owner, never the broker.
-- Deployment grants EXECUTE on these exact signatures to its restricted login;
-- this migration neither creates a login nor changes any table privileges.
-- SQLx applies creation and PUBLIC revocation in one migration transaction.

CREATE FUNCTION public.codewire_platform_lock_owner(owner_kind text, owner_id text)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF $1 = 'user' THEN
        PERFORM u.id FROM public.users AS u WHERE u.id = $2 FOR SHARE;
        RETURN FOUND;
    ELSIF $1 = 'organization' THEN
        -- KEY SHARE would not fence a non-key deletion-state update.
        PERFORM o.id FROM public.organizations AS o
        WHERE o.id = $2 AND o.deletion_state = 'active' FOR SHARE;
        RETURN FOUND;
    END IF;
    RETURN false;
END;
$$;
REVOKE ALL ON FUNCTION public.codewire_platform_lock_owner(text, text) FROM PUBLIC;

CREATE FUNCTION public.codewire_platform_lock_environment(
    environment_id text, user_id text, organization_id text
)
RETURNS TABLE (
    environment_operation_generation bigint, desired_state text, state text
)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT e.environment_operation_generation, e.desired_state, e.state
    FROM public.environments AS e
    WHERE e.id = $1 AND e.created_by = $2 AND e.org_id = $3
    FOR SHARE OF e;
$$;
REVOKE ALL ON FUNCTION public.codewire_platform_lock_environment(text, text, text) FROM PUBLIC;

CREATE FUNCTION public.codewire_platform_lock_profile(
    profile_id text, user_scope text, organization_scope text
)
RETURNS TABLE (
    user_id text, organization_id text, name text, current_revision bigint
)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    -- One nullable scope is intentional for exact-owner reads; runtime context
    -- may authorize both its user and organization. Neither is a wildcard.
    SELECT p.user_id, p.organization_id, p.name, p.current_revision
    FROM public.platform_access_profiles AS p
    WHERE p.id = $1 AND (p.user_id = $2 OR p.organization_id = $3)
    FOR SHARE OF p;
$$;
REVOKE ALL ON FUNCTION public.codewire_platform_lock_profile(text, text, text) FROM PUBLIC;
