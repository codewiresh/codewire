-- The isolated broker may inspect canonical application-source selections and
-- ordinary configuration KEY NAMES, never full project_spec/configuration values.
-- These functions are authority primitives, not authentication. The service
-- first verifies exact live gateway/workspace Pod identities and their lineage.
-- No login, table grant, secret write or new lifecycle generation is added.

CREATE FUNCTION public.codewire_platform_projection_metadata(environment_id text)
RETURNS TABLE (
    organization_selected boolean,
    user_placement text,
    project_reference text,
    credential_reference text,
    ordinary_keys text[],
    selection_valid boolean
)
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT
        CASE WHEN jsonb_typeof(s->'organization') = 'boolean'
             THEN (s->>'organization')::boolean ELSE false END,
        CASE WHEN jsonb_typeof(s->'user') = 'string' THEN left(s->>'user', 129) END,
        CASE WHEN jsonb_typeof(s->'project') = 'string' THEN left(s->>'project', 129) END,
        CASE WHEN jsonb_typeof(c->'profile') = 'string' THEN left(c->>'profile', 129) END,
        ARRAY(SELECT left(k, 256) FROM jsonb_object_keys(
            CASE WHEN jsonb_typeof(e.project_spec->'environment') = 'object'
                 THEN e.project_spec->'environment' ELSE '{}'::jsonb END
        ) AS keys(k) ORDER BY k LIMIT 257),
        coalesce(
            jsonb_typeof(e.project_spec) = 'object'
            AND NOT e.project_spec ? 'access'
            AND (e.project_spec->'secrets' IS NULL OR e.project_spec->'secrets' = 'null'::jsonb
                 OR (jsonb_typeof(s) = 'object' AND s - ARRAY['organization','user','project'] = '{}'::jsonb))
            AND (s->'organization' IS NULL OR jsonb_typeof(s->'organization') = 'boolean')
            AND (s->'user' IS NULL OR s->'user' = 'null'::jsonb OR s->'user' = '"platform"'::jsonb)
            AND (s->'project' IS NULL OR s->'project' = 'null'::jsonb OR jsonb_typeof(s->'project') = 'string')
            AND (s->'project' IS NULL OR s->'project' = 'null'::jsonb OR EXISTS (
                SELECT 1 FROM public.secret_projects AS p
                WHERE p.org_id=e.org_id AND 'platform:id:' || p.id = s->>'project'))
            AND (e.project_spec->'credentials' IS NULL OR e.project_spec->'credentials' = 'null'::jsonb
                 OR (jsonb_typeof(c) = 'object' AND c - ARRAY['profile'] = '{}'::jsonb
                     AND jsonb_typeof(c->'profile') = 'string'))
            AND (e.project_spec->'environment' IS NULL OR jsonb_typeof(e.project_spec->'environment') = 'object'),
            false)
    FROM public.environments AS e
    CROSS JOIN LATERAL (SELECT e.project_spec->'secrets' AS s, e.project_spec->'credentials' AS c) AS selectors
    WHERE e.id = $1;
$$;
REVOKE ALL ON FUNCTION public.codewire_platform_projection_metadata(text) FROM PUBLIC;

CREATE FUNCTION public.codewire_platform_lock_projection_authority(
    environment_id text, creator_id text, organization_id text, project_id text
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    selected record;
BEGIN
    -- Lock order is shared by capture and final release: user, organization,
    -- membership, environment, selected project, then per-tenant scope locks.
    -- SHARE (not KEY SHARE) fences non-key revocation/state changes.
    PERFORM u.id FROM public.users AS u WHERE u.id = $2 FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM o.id FROM public.organizations AS o
        WHERE o.id = $3 AND o.deletion_state = 'active' FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM m.id FROM public.org_members AS m
        WHERE m.org_id = $3 AND m.user_id = $2 AND m.role <> '' FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM e.id FROM public.environments AS e
        WHERE e.id = $1 AND e.created_by = $2 AND e.org_id = $3
          AND e.type = 'sandbox' AND e.state = 'running' AND e.desired_state = 'started'
          AND e.deletion_requested_at IS NULL AND e.environment_operation_generation > 0
        FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT * INTO selected FROM public.codewire_platform_projection_metadata($1);
    IF NOT FOUND OR NOT selected.selection_valid THEN RETURN false; END IF;
    PERFORM s.environment_id FROM public.sandbox_environment_backend AS s
        WHERE s.environment_id = $1 FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM b.environment_id FROM public.platform_environment_access_bindings AS b
        WHERE b.environment_id = $1 FOR SHARE;
    PERFORM p.id FROM public.platform_access_profiles AS p
        JOIN public.platform_environment_access_bindings AS b ON b.profile_id = p.id
        WHERE b.environment_id = $1 FOR SHARE OF p;
    IF $4 IS NULL THEN
        IF selected.project_reference IS NOT NULL THEN RETURN false; END IF;
    ELSE
        IF selected.project_reference IS DISTINCT FROM 'platform:id:' || $4 THEN RETURN false; END IF;
        PERFORM p.id FROM public.secret_projects AS p WHERE p.id = $4 AND p.org_id = $3 FOR SHARE;
        IF NOT FOUND THEN RETURN false; END IF;
    END IF;
    RETURN true;
END;
$$;
REVOKE ALL ON FUNCTION public.codewire_platform_lock_projection_authority(text,text,text,text) FROM PUBLIC;
