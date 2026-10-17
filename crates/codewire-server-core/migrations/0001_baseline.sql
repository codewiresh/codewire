-- Codewire application schema baseline.
--
-- The single pre-launch migration: the complete application schema and the
-- reference rows the control plane needs on an empty database, generated from
-- the full reviewed migration history that preceded it (schema fingerprint
-- 6a6a17eb52120fa37b56eef07bff233eed562ddd5f9dc755191381bbf77e3401). Later
-- schema changes are new immutable migrations after this file.

SET check_function_bodies = false;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';

--
-- Name: codewire_authenticate_credential_session(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_authenticate_credential_session(token_digest text) RETURNS TABLE(session_id text, user_id text, is_admin boolean, expires_at timestamp with time zone)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    SET "TimeZone" TO 'UTC'
    AS $_$
    WITH refreshed AS (
        UPDATE public.sessions AS s
           SET expires_at = GREATEST(s.expires_at, NOW() + interval '8 hours'),
               updated_at = NOW()
          FROM public.users AS u
         WHERE s.token_hash = $1
           AND $1 ~ '^[0-9a-f]{64}$'
           AND s.expires_at > NOW()
           AND s.user_id = u.id
           AND u.enabled
         RETURNING s.id, s.user_id, u.is_admin, s.expires_at
    )
    SELECT r.id, r.user_id, r.is_admin, r.expires_at AT TIME ZONE 'UTC'
      FROM refreshed AS r
$_$;

--
-- Name: codewire_cw_runtime_request_immutable(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_cw_runtime_request_immutable() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'cw runtime request evidence is retained';
    END IF;
    IF ROW(NEW.request_id,NEW.organization_id,NEW.environment_id,NEW.actor_user_id,
           NEW.via_api_key,NEW.delegated_organization_id,
           NEW.pod_uid,NEW.fingerprint,NEW.request_json,NEW.binding_json,
           NEW.expected_store_generation,NEW.owner_id,NEW.mutation_lease_id,NEW.admitted_at)
       IS DISTINCT FROM
       ROW(OLD.request_id,OLD.organization_id,OLD.environment_id,OLD.actor_user_id,
           OLD.via_api_key,OLD.delegated_organization_id,
           OLD.pod_uid,OLD.fingerprint,OLD.request_json,OLD.binding_json,
           OLD.expected_store_generation,OLD.owner_id,OLD.mutation_lease_id,OLD.admitted_at) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'cw runtime request identity is immutable';
    END IF;
    IF OLD.phase IN ('succeeded','failed','unknown') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'cw runtime terminal evidence is immutable';
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
    IF NOT (
        (OLD.phase IN ('admitted','acknowledged') AND NEW.phase = 'issued'
         AND NEW.checkpoint = OLD.checkpoint + 1
         AND NEW.acknowledgements = OLD.acknowledgements)
        OR (OLD.phase = 'issued' AND NEW.phase = 'acknowledged'
            AND NEW.checkpoint = OLD.checkpoint AND NEW.effect = OLD.effect
            AND NEW.issued_at = OLD.issued_at
            AND jsonb_array_length(NEW.acknowledgements) = jsonb_array_length(OLD.acknowledgements) + 1
            AND NEW.acknowledgements - (jsonb_array_length(NEW.acknowledgements) - 1) = OLD.acknowledgements)
        OR (OLD.phase = 'acknowledged' AND NEW.phase = 'succeeded'
            AND NEW.checkpoint = OLD.checkpoint AND NEW.effect = OLD.effect
            AND NEW.issued_at = OLD.issued_at AND NEW.acknowledgements = OLD.acknowledgements)
        OR (OLD.phase = 'admitted' AND NEW.phase = 'failed'
            AND NEW.checkpoint = 0 AND NEW.effect IS NULL AND NEW.issued_at IS NULL
            AND NEW.acknowledgements = OLD.acknowledgements)
        OR (OLD.phase = 'acknowledged' AND NEW.phase = 'failed'
            AND NEW.checkpoint = OLD.checkpoint AND NEW.effect = OLD.effect
            AND NEW.issued_at = OLD.issued_at AND NEW.acknowledgements = OLD.acknowledgements)
        OR (OLD.phase = 'issued' AND NEW.phase IN ('failed','unknown')
            AND NEW.checkpoint = OLD.checkpoint AND NEW.effect = OLD.effect
            AND NEW.issued_at = OLD.issued_at AND NEW.acknowledgements = OLD.acknowledgements)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'cw runtime checkpoint cannot be replayed';
    END IF;
    RETURN NEW;
END;
$$;

--
-- Name: codewire_lock_credential_session_authority(text, text, text, timestamp with time zone); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_lock_credential_session_authority(original_session_id text, token_digest text, original_user_id text, original_expires_at timestamp with time zone) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    SET "TimeZone" TO 'UTC'
    AS $_$
BEGIN
    PERFORM u.id FROM public.users AS u WHERE u.id = $3 AND u.enabled FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    PERFORM s.id FROM public.sessions AS s
    WHERE s.id = $1 AND s.token_hash = $2 AND s.user_id = $3
      AND $2 ~ '^[0-9a-f]{64}$'
      AND s.expires_at >= $4
    FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    -- A later authentication may extend the row, but never this captured
    -- authority. The wall check therefore uses its original fixed expiry.
    RETURN $4 > pg_catalog.clock_timestamp();
END;
$_$;

--
-- Name: codewire_lock_oauth_bearer_authority(text, text, text, timestamp with time zone); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_lock_oauth_bearer_authority(token_digest text, original_user_id text, original_client_id text, original_expires_at timestamp with time zone) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
BEGIN
    -- Fixed lock order matches the credential store's owner-first fence.
    -- SHARE, not KEY SHARE, also blocks non-key authorization changes.
    PERFORM u.id FROM public.users AS u
    WHERE u.id = $2 AND u.enabled
    FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    PERFORM c.id FROM public.oidc_clients AS c
    WHERE c.id = $3 AND NOT c.disabled FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    PERFORM t.token_hash FROM public.oidc_access_tokens AS t
    WHERE t.token_hash = $1 AND t.user_id = $2 AND t.client_id = $3
      AND t.expires_at = $4 AND 'codewire.api' = ANY(t.scopes)
    FOR SHARE;
    IF NOT FOUND THEN RETURN false; END IF;

    -- NOW() is the transaction-start timestamp and can precede a long lock
    -- wait. Check the original immutable expiry after every lock has settled.
    RETURN $4 > pg_catalog.clock_timestamp();
END;
$_$;

--
-- Name: codewire_platform_lock_credential(text, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_platform_lock_credential(credential_id text, user_scope text, organization_scope text) RETURNS TABLE(provider text, authentication_kind text, display_name text, account_hint text, status text, expires_at_unix bigint, revocation_generation bigint)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
    SELECT c.provider, c.authentication_kind, c.display_name, c.account_hint,
           c.status, c.expires_at_unix, c.revocation_generation
    FROM public.platform_credentials AS c
    WHERE c.id = $1 AND (c.user_id = $2 OR c.organization_id = $3)
    FOR SHARE OF c;
$_$;

--
-- Name: codewire_platform_lock_environment(text, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_platform_lock_environment(environment_id text, user_id text, organization_id text) RETURNS TABLE(environment_operation_generation bigint, desired_state text, state text)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
    SELECT e.environment_operation_generation, e.desired_state, e.state
    FROM public.environments AS e
    WHERE e.id = $1 AND e.created_by = $2 AND e.org_id = $3
    FOR SHARE OF e;
$_$;

--
-- Name: codewire_platform_lock_owner(text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_platform_lock_owner(owner_kind text, owner_id text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
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
$_$;

--
-- Name: codewire_platform_lock_owner_source_authority(text, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_platform_lock_owner_source_authority(user_id text, organization_id text, project_id text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
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
$_$;

--
-- Name: codewire_platform_lock_profile(text, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_platform_lock_profile(profile_id text, user_scope text, organization_scope text) RETURNS TABLE(user_id text, organization_id text, name text, current_revision bigint)
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
    -- One nullable scope is intentional for exact-owner reads; runtime context
    -- may authorize both its user and organization. Neither is a wildcard.
    SELECT p.user_id, p.organization_id, p.name, p.current_revision
    FROM public.platform_access_profiles AS p
    WHERE p.id = $1 AND (p.user_id = $2 OR p.organization_id = $3)
    FOR SHARE OF p;
$_$;

--
-- Name: codewire_platform_lock_projection_authority(text, text, text, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_platform_lock_projection_authority(environment_id text, creator_id text, organization_id text, project_id text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
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
$_$;

--
-- Name: codewire_platform_projection_metadata(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_platform_projection_metadata(environment_id text) RETURNS TABLE(organization_selected boolean, user_placement text, project_reference text, credential_reference text, ordinary_keys text[], selection_valid boolean)
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
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
$_$;

--
-- Name: codewire_require_enabled_account(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_require_enabled_account() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF NEW.user_id IS NULL THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        BEGIN
            PERFORM u.id
            FROM public.users AS u
            WHERE u.id = NEW.user_id AND u.enabled
            FOR SHARE NOWAIT;
        EXCEPTION WHEN lock_not_available THEN
            RAISE EXCEPTION USING
                ERRCODE = '55P03',
                MESSAGE = 'account access transition conflicts with disablement';
        END;
    ELSE
        PERFORM u.id
        FROM public.users AS u
        WHERE u.id = NEW.user_id AND u.enabled
        FOR SHARE;
    END IF;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'account access is disabled';
    END IF;
    RETURN NEW;
END;
$$;

--
-- Name: codewire_require_enabled_api_key(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_require_enabled_api_key() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    -- The revocation trigger marks existing keys disabled and expired while
    -- the owner row is already disabled. A disabled key is not a bearer
    -- capability and must remain mutable for administrative cleanup; clearing
    -- disabled_at after re-enable cannot undo its retired expiry.
    IF NEW.disabled_at IS NOT NULL THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        BEGIN
            PERFORM u.id
            FROM public.users AS u
            WHERE u.id = NEW.user_id AND u.enabled
            FOR SHARE NOWAIT;
        EXCEPTION WHEN lock_not_available THEN
            RAISE EXCEPTION USING
                ERRCODE = '55P03',
                MESSAGE = 'account access transition conflicts with disablement';
        END;
    ELSE
        PERFORM u.id
        FROM public.users AS u
        WHERE u.id = NEW.user_id AND u.enabled
        FOR SHARE;
    END IF;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'account access is disabled';
    END IF;
    RETURN NEW;
END;
$$;

--
-- Name: codewire_revoke_user_capabilities(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_revoke_user_capabilities() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF OLD.enabled AND NOT NEW.enabled THEN
        DELETE FROM public.sessions WHERE user_id = NEW.id;
        UPDATE public.api_keys
        SET disabled_at = COALESCE(disabled_at, pg_catalog.clock_timestamp()),
            expires_at = LEAST(
                COALESCE(expires_at, pg_catalog.clock_timestamp()),
                pg_catalog.clock_timestamp()
            )
        WHERE user_id = NEW.id;
        DELETE FROM public.oidc_auth_requests WHERE user_id = NEW.id;
        DELETE FROM public.oidc_access_tokens WHERE user_id = NEW.id;
        DELETE FROM public.oidc_refresh_tokens WHERE user_id = NEW.id;
        DELETE FROM public.oidc_device_authorizations WHERE user_id = NEW.id;
        DELETE FROM public.two_factor_tokens WHERE user_id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$;

--
-- Name: codewire_workspace_binding_immutable(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.codewire_workspace_binding_immutable() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF pg_trigger_depth() <= 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'workspace binding is removed only with its environment';
        END IF;
        RETURN OLD;
    END IF;
    IF ROW(
           NEW.pod_uid,
           NEW.environment_id,
           NEW.namespace,
           NEW.pod_name,
           NEW.claim_uid,
           NEW.sandbox_uid,
           NEW.workspace_pvc_uid,
           NEW.operation_generation,
           NEW.projection_selection_sha256,
           NEW.managed_credential_clients,
           NEW.credential_scope,
           NEW.bound_at
       ) IS DISTINCT FROM ROW(
           OLD.pod_uid,
           OLD.environment_id,
           OLD.namespace,
           OLD.pod_name,
           OLD.claim_uid,
           OLD.sandbox_uid,
           OLD.workspace_pvc_uid,
           OLD.operation_generation,
           OLD.projection_selection_sha256,
           OLD.managed_credential_clients,
           OLD.credential_scope,
           OLD.bound_at
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'workspace binding is immutable except its release';
    END IF;
    IF OLD.released_at IS NOT NULL
       AND NEW.released_at IS DISTINCT FROM OLD.released_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'workspace binding release is final';
    END IF;
    RETURN NEW;
END;
$$;

--
-- Name: enforce_confidential_storage_manifest_immutability(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_confidential_storage_manifest_immutability() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.volume_id IS NOT NULL
       AND ROW(
           NEW.volume_id,
           NEW.volume_version,
           NEW.manifest_schema_version,
           NEW.device_size_bytes,
           NEW.luks_uuid,
           NEW.protection_profile,
           NEW.protection_profile_version,
           NEW.backing_claim_name
       ) IS DISTINCT FROM ROW(
           OLD.volume_id,
           OLD.volume_version,
           OLD.manifest_schema_version,
           OLD.device_size_bytes,
           OLD.luks_uuid,
           OLD.protection_profile,
           OLD.protection_profile_version,
           OLD.backing_claim_name
       ) THEN
        RAISE EXCEPTION 'confidential storage volume core is immutable';
    END IF;

    IF OLD.sha256_fingerprint IS NOT NULL
       AND NEW.sha256_fingerprint IS DISTINCT FROM OLD.sha256_fingerprint THEN
        RAISE EXCEPTION 'confidential storage key fingerprint is immutable';
    END IF;

    IF OLD.manifest_uri IS NOT NULL
       AND ROW(NEW.manifest_uri, NEW.manifest_sha256_fingerprint)
           IS DISTINCT FROM
           ROW(OLD.manifest_uri, OLD.manifest_sha256_fingerprint) THEN
        RAISE EXCEPTION 'confidential storage manifest content is immutable';
    END IF;

    RETURN NEW;
END
$$;

--
-- Name: environment_platform_agent_conversation_guard(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.environment_platform_agent_conversation_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'platform agent conversation evidence is retained'; END IF;
    IF ROW(NEW.environment_id,NEW.pod_uid,NEW.session_id,NEW.driver_id,NEW.binding_json,
        NEW.support_image_sha256,NEW.support_image_size,NEW.agent) IS DISTINCT FROM
        ROW(OLD.environment_id,OLD.pod_uid,OLD.session_id,OLD.driver_id,OLD.binding_json,
        OLD.support_image_sha256,OLD.support_image_size,OLD.agent) THEN
        RAISE EXCEPTION 'platform agent original conversation is immutable';
    END IF;
    IF NEW.launch_generation<>OLD.launch_generation AND
        NEW.launch_generation::numeric<>OLD.launch_generation::numeric+1 THEN
        RAISE EXCEPTION 'platform agent generation must advance once';
    END IF;
    RETURN NEW;
END;
$$;

--
-- Name: environment_platform_agent_request_guard(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.environment_platform_agent_request_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'platform agent request evidence is retained'; END IF;
    IF ROW(NEW.request_id,NEW.organization_id,NEW.environment_id,NEW.actor_user_id,NEW.via_api_key,
        NEW.delegated_organization_id,NEW.pod_uid,NEW.fingerprint,NEW.mutation_json,NEW.binding_json,
        NEW.owner_id,NEW.mutation_lease_id,NEW.cleanup_of,NEW.admitted_at)
        IS DISTINCT FROM ROW(OLD.request_id,OLD.organization_id,OLD.environment_id,OLD.actor_user_id,OLD.via_api_key,
        OLD.delegated_organization_id,OLD.pod_uid,OLD.fingerprint,OLD.mutation_json,OLD.binding_json,
        OLD.owner_id,OLD.mutation_lease_id,OLD.cleanup_of,OLD.admitted_at) THEN
        RAISE EXCEPTION 'platform agent request identity is immutable';
    END IF;
    IF OLD.phase IN ('completed','rejected','unknown') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'platform agent terminal evidence is immutable';
    END IF;
    IF NEW.phase<>OLD.phase AND NOT (
        (OLD.phase='admitted' AND NEW.phase IN ('issued','rejected')) OR
        (OLD.phase='issued' AND NEW.phase IN ('completed','rejected','unknown'))) THEN
        RAISE EXCEPTION 'platform agent request cannot replay';
    END IF;
    IF OLD.issued_at IS NOT NULL AND NEW.issued_at IS DISTINCT FROM OLD.issued_at THEN
        RAISE EXCEPTION 'platform agent issue evidence is immutable';
    END IF;
    RETURN NEW;
END;
$$;

--
-- Name: accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.accounts (
    id text NOT NULL,
    user_id text NOT NULL,
    provider_id text NOT NULL,
    account_id text NOT NULL,
    password text,
    access_token text,
    refresh_token text,
    access_token_expires_at timestamp without time zone,
    refresh_token_expires_at timestamp without time zone,
    scope text,
    id_token text,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);

--
-- Name: admin_invoice_credits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_invoice_credits (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    stripe_invoice_id text NOT NULL,
    credit_kind text NOT NULL,
    amount_cents integer NOT NULL,
    stripe_invoice_item_id text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);

--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    user_id text NOT NULL,
    org_id text NOT NULL,
    name text NOT NULL,
    key_hash text NOT NULL,
    key_prefix text NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    last_used_at timestamp without time zone,
    expires_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    disabled_at timestamp without time zone
);

--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_logs (
    id text NOT NULL,
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL,
    action text NOT NULL,
    user_id text,
    target_user_id text,
    ip_address text,
    user_agent text,
    metadata jsonb,
    severity text DEFAULT 'info'::text NOT NULL
);

--
-- Name: billing_catalog_plans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_catalog_plans (
    resource_type text NOT NULL,
    plan_key text NOT NULL,
    display_name text NOT NULL,
    price_cents integer NOT NULL,
    included_devs integer DEFAULT 0 NOT NULL,
    max_concurrent_ws integer DEFAULT 0 NOT NULL,
    max_team_members integer DEFAULT 0 NOT NULL,
    storage_gb integer DEFAULT 0 NOT NULL,
    is_contact_us boolean DEFAULT false NOT NULL,
    is_admin_only boolean DEFAULT false NOT NULL,
    included_cpu_hours integer DEFAULT 0 NOT NULL,
    included_mem_gb_hours integer DEFAULT 0 NOT NULL,
    included_disk_gb_hours integer DEFAULT 0 NOT NULL,
    cpu_overage_cents double precision DEFAULT 0 NOT NULL,
    mem_overage_cents double precision DEFAULT 0 NOT NULL,
    disk_overage_cents double precision DEFAULT 0 NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    archived_at timestamp without time zone
);

--
-- Name: billing_catalog_prices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_catalog_prices (
    resource_type text NOT NULL,
    plan_key text NOT NULL,
    stripe_mode text NOT NULL,
    price_kind text DEFAULT 'subscription'::text NOT NULL,
    stripe_price_id text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    archived_at timestamp without time zone,
    CONSTRAINT billing_catalog_prices_kind_check CHECK ((price_kind = ANY (ARRAY['subscription'::text, 'seat_addon'::text]))),
    CONSTRAINT billing_catalog_prices_mode_check CHECK ((stripe_mode = ANY (ARRAY['test'::text, 'live'::text])))
);

--
-- Name: billing_catalog_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_catalog_settings (
    setting_key text NOT NULL,
    int_value integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);

--
-- Name: billing_catalog_subscription_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_catalog_subscription_migrations (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    resource_type text NOT NULL,
    source_plan_key text NOT NULL,
    target_plan_key text NOT NULL,
    target_stripe_price_id text NOT NULL,
    proration_behavior text DEFAULT 'none'::text NOT NULL,
    migrated_count integer DEFAULT 0 NOT NULL,
    skipped_count integer DEFAULT 0 NOT NULL,
    failed_count integer DEFAULT 0 NOT NULL,
    created_by text,
    metadata jsonb,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);

--
-- Name: billing_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_events (
    id bigint NOT NULL,
    event_type text NOT NULL,
    org_id text,
    amount_cents integer,
    currency text DEFAULT 'usd'::text,
    stripe_item_id text,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: billing_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.billing_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

--
-- Name: billing_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.billing_events_id_seq OWNED BY public.billing_events.id;

--
-- Name: billing_external_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_external_operations (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    organization_id text NOT NULL,
    billing_period_start timestamp without time zone NOT NULL,
    operation_kind text NOT NULL,
    idempotency_key text NOT NULL,
    requested_amount_cents integer NOT NULL,
    provider_object_id text,
    provider_state text DEFAULT 'pending'::text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    completed_at timestamp without time zone
);

--
-- Name: confidential_storage_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.confidential_storage_keys (
    environment_id text NOT NULL,
    kbs_uri text NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    sha256_fingerprint text,
    state text DEFAULT 'provisioning'::text NOT NULL,
    last_redacted_error text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    ready_at timestamp without time zone,
    deleting_at timestamp without time zone,
    deleted_at timestamp without time zone,
    openbao_path text NOT NULL,
    manifest_uri text,
    volume_id text,
    volume_version text,
    manifest_schema_version integer,
    device_size_bytes bigint,
    luks_uuid text,
    protection_profile text,
    backing_claim_name text,
    manifest_sha256_fingerprint text,
    protection_profile_version integer,
    CONSTRAINT confidential_storage_keys_fingerprint_check CHECK (((sha256_fingerprint IS NULL) OR (sha256_fingerprint ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT confidential_storage_keys_openbao_path_check CHECK ((openbao_path = ('confidential-storage/'::text || environment_id))),
    CONSTRAINT confidential_storage_keys_state_check CHECK ((state = ANY (ARRAY['provisioning'::text, 'ready'::text, 'deleting'::text, 'deleted'::text, 'error'::text]))),
    CONSTRAINT confidential_storage_keys_uri_check CHECK ((kbs_uri = ('kbs:///default/codewire-workspace-luks/'::text || environment_id))),
    CONSTRAINT confidential_storage_keys_version_check CHECK ((version > 0)),
    CONSTRAINT confidential_storage_manifest_tuple_check CHECK ((((manifest_uri IS NULL) AND (volume_id IS NULL) AND (volume_version IS NULL) AND (manifest_schema_version IS NULL) AND (device_size_bytes IS NULL) AND (luks_uuid IS NULL) AND (protection_profile IS NULL) AND (protection_profile_version IS NULL) AND (backing_claim_name IS NULL) AND (manifest_sha256_fingerprint IS NULL)) OR ((volume_id IS NOT NULL) AND (volume_version IS NOT NULL) AND (manifest_schema_version IS NOT NULL) AND (device_size_bytes IS NOT NULL) AND (luks_uuid IS NOT NULL) AND (protection_profile IS NOT NULL) AND (backing_claim_name IS NOT NULL) AND (volume_id = environment_id) AND (((manifest_schema_version = 2) AND (volume_version = (environment_id || '-v2'::text)) AND (protection_profile_version IS NULL) AND (state = ANY (ARRAY['deleting'::text, 'deleted'::text]))) OR ((manifest_schema_version = 3) AND (volume_version = (environment_id || '-v3'::text)) AND (protection_profile_version = 1))) AND (device_size_bytes > 0) AND ((device_size_bytes % (4096)::bigint) = 0) AND (luks_uuid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text) AND (protection_profile = 'luks2-integrity-rw'::text) AND (backing_claim_name = 'workspace'::text) AND (((manifest_uri IS NULL) AND (manifest_sha256_fingerprint IS NULL)) OR ((sha256_fingerprint IS NOT NULL) AND (manifest_uri IS NOT NULL) AND (manifest_sha256_fingerprint ~ '^[0-9a-f]{64}$'::text) AND (manifest_uri = ('kbs:///default/codewire-storage-manifests/sha256-'::text || manifest_sha256_fingerprint)))))))
);

--
-- Name: data_deletion_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.data_deletion_requests (
    id text NOT NULL,
    user_id text NOT NULL,
    requested_at timestamp without time zone DEFAULT now() NOT NULL,
    scheduled_for timestamp without time zone NOT NULL,
    completed_at timestamp without time zone,
    status text DEFAULT 'pending'::text NOT NULL,
    deleted_data jsonb
);

--
-- Name: environment_access; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_access (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    environment_id text NOT NULL,
    user_id text NOT NULL,
    permission text NOT NULL,
    granted_by text NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    CONSTRAINT environment_access_permission_check CHECK ((permission = ANY (ARRAY['owner'::text, 'operator'::text, 'viewer'::text])))
);

--
-- Name: environment_cw_runtime_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_cw_runtime_requests (
    request_id uuid NOT NULL,
    organization_id text NOT NULL,
    environment_id text NOT NULL,
    actor_user_id text NOT NULL,
    via_api_key boolean NOT NULL,
    delegated_organization_id text,
    pod_uid uuid NOT NULL,
    fingerprint text NOT NULL,
    request_json jsonb NOT NULL,
    binding_json jsonb NOT NULL,
    expected_store_generation text NOT NULL,
    owner_id uuid NOT NULL,
    mutation_lease_id text NOT NULL,
    phase text DEFAULT 'admitted'::text NOT NULL,
    checkpoint integer DEFAULT 0 NOT NULL,
    effect text,
    acknowledgements jsonb DEFAULT '[]'::jsonb NOT NULL,
    error_code text,
    admitted_at timestamp with time zone DEFAULT now() NOT NULL,
    issued_at timestamp with time zone,
    terminal_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT environment_cw_runtime_request_coordinates CHECK (((((binding_json ->> 'organization_id'::text) = organization_id) AND ((binding_json ->> 'environment_id'::text) = environment_id) AND ((binding_json ->> 'pod_uid'::text) = (pod_uid)::text) AND (jsonb_typeof((request_json -> 'expected_store_generation'::text)) = 'string'::text) AND ((request_json ->> 'expected_store_generation'::text) = expected_store_generation)) IS TRUE)),
    CONSTRAINT environment_cw_runtime_request_delegation CHECK ((((via_api_key AND (delegated_organization_id = organization_id)) OR ((NOT via_api_key) AND (delegated_organization_id IS NULL))) IS TRUE)),
    CONSTRAINT environment_cw_runtime_request_phase_metadata CHECK (((((phase = 'admitted'::text) AND (checkpoint = 0) AND (effect IS NULL) AND (issued_at IS NULL) AND (terminal_at IS NULL) AND (error_code IS NULL) AND (jsonb_array_length(acknowledgements) = 0)) OR ((phase = 'issued'::text) AND (checkpoint > 0) AND (effect IS NOT NULL) AND (issued_at IS NOT NULL) AND (terminal_at IS NULL) AND (error_code IS NULL) AND (jsonb_array_length(acknowledgements) = (checkpoint - 1))) OR ((phase = 'acknowledged'::text) AND (checkpoint > 0) AND (effect IS NOT NULL) AND (issued_at IS NOT NULL) AND (terminal_at IS NULL) AND (error_code IS NULL) AND (jsonb_array_length(acknowledgements) = checkpoint)) OR ((phase = 'succeeded'::text) AND (checkpoint > 0) AND (effect = ANY (ARRAY['update'::text, 'rollback'::text, 'cleanup'::text])) AND (issued_at IS NOT NULL) AND (terminal_at IS NOT NULL) AND (error_code IS NULL) AND (jsonb_array_length(acknowledgements) = checkpoint)) OR ((phase = 'failed'::text) AND (terminal_at IS NOT NULL) AND (error_code IS NOT NULL) AND (((checkpoint = 0) AND (effect IS NULL) AND (issued_at IS NULL) AND (jsonb_array_length(acknowledgements) = 0)) OR ((checkpoint > 0) AND (effect IS NOT NULL) AND (issued_at IS NOT NULL) AND ((jsonb_array_length(acknowledgements) = (checkpoint - 1)) OR (jsonb_array_length(acknowledgements) = checkpoint))))) OR ((phase = 'unknown'::text) AND (checkpoint > 0) AND (effect IS NOT NULL) AND (issued_at IS NOT NULL) AND (terminal_at IS NOT NULL) AND (error_code IS NOT NULL) AND (jsonb_array_length(acknowledgements) = (checkpoint - 1)))) IS TRUE)),
    CONSTRAINT environment_cw_runtime_requests_acknowledgements_check CHECK (((jsonb_typeof(acknowledgements) = 'array'::text) AND (jsonb_array_length(acknowledgements) <= 16) AND (octet_length((acknowledgements)::text) <= 32768))),
    CONSTRAINT environment_cw_runtime_requests_actor_user_id_check CHECK (((octet_length(actor_user_id) >= 1) AND (octet_length(actor_user_id) <= 128))),
    CONSTRAINT environment_cw_runtime_requests_binding_json_check CHECK (((jsonb_typeof(binding_json) = 'object'::text) AND (octet_length((binding_json)::text) <= 32768))),
    CONSTRAINT environment_cw_runtime_requests_checkpoint_check CHECK (((checkpoint >= 0) AND (checkpoint <= 16))),
    CONSTRAINT environment_cw_runtime_requests_delegated_organization_id_check CHECK (((octet_length(delegated_organization_id) >= 1) AND (octet_length(delegated_organization_id) <= 128))),
    CONSTRAINT environment_cw_runtime_requests_effect_check CHECK ((effect = ANY (ARRAY['bootstrap'::text, 'staging'::text, 'update'::text, 'rollback'::text, 'cleanup'::text]))),
    CONSTRAINT environment_cw_runtime_requests_environment_id_check CHECK ((environment_id ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'::text)),
    CONSTRAINT environment_cw_runtime_requests_error_code_check CHECK ((error_code ~ '^[a-z0-9_]{1,96}$'::text)),
    CONSTRAINT environment_cw_runtime_requests_expected_store_generation_check CHECK (((expected_store_generation ~ '^(0|[1-9][0-9]{0,19})$'::text) AND ((length(expected_store_generation) < 20) OR ((expected_store_generation COLLATE "C") <= '18446744073709551615'::text)))),
    CONSTRAINT environment_cw_runtime_requests_fingerprint_check CHECK ((fingerprint ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT environment_cw_runtime_requests_mutation_lease_id_check CHECK (((octet_length(mutation_lease_id) >= 1) AND (octet_length(mutation_lease_id) <= 128))),
    CONSTRAINT environment_cw_runtime_requests_organization_id_check CHECK (((octet_length(organization_id) >= 1) AND (octet_length(organization_id) <= 128))),
    CONSTRAINT environment_cw_runtime_requests_owner_id_check CHECK ((owner_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT environment_cw_runtime_requests_phase_check CHECK ((phase = ANY (ARRAY['admitted'::text, 'issued'::text, 'acknowledged'::text, 'succeeded'::text, 'failed'::text, 'unknown'::text]))),
    CONSTRAINT environment_cw_runtime_requests_pod_uid_check CHECK ((pod_uid <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT environment_cw_runtime_requests_request_id_check CHECK ((request_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT environment_cw_runtime_requests_request_json_check CHECK (((jsonb_typeof(request_json) = 'object'::text) AND (octet_length((request_json)::text) <= 32768)))
);

--
-- Name: environment_lifecycle_journal; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_lifecycle_journal (
    id text NOT NULL,
    environment_id text NOT NULL,
    kind text NOT NULL,
    actor text NOT NULL,
    phase text,
    status text,
    from_state text,
    to_state text,
    checkpoint text,
    reason text,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: environment_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_logs (
    id text NOT NULL,
    environment_id text NOT NULL,
    phase text NOT NULL,
    status text NOT NULL,
    message text,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: environment_operation_generation_claims; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_operation_generation_claims (
    environment_id text NOT NULL,
    workflow_run_id text NOT NULL,
    generation bigint NOT NULL,
    scheduled_at_unix_nanos bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT environment_operation_generation__scheduled_at_unix_nanos_check CHECK ((scheduled_at_unix_nanos >= 0)),
    CONSTRAINT environment_operation_generation_claims_generation_check CHECK ((generation > 0)),
    CONSTRAINT environment_operation_generation_claims_workflow_run_id_check CHECK ((btrim(workflow_run_id) <> ''::text))
);

--
-- Name: environment_platform_agent_conversations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_platform_agent_conversations (
    environment_id text NOT NULL,
    pod_uid uuid NOT NULL,
    session_id text NOT NULL,
    driver_id uuid NOT NULL,
    binding_json jsonb NOT NULL,
    support_image_sha256 text NOT NULL,
    support_image_size bigint NOT NULL,
    agent text NOT NULL,
    launch_generation text NOT NULL,
    active_request_id uuid,
    cleanup_request_id uuid,
    known_clean boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT environment_platform_agent_conversat_support_image_sha256_check CHECK ((support_image_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT environment_platform_agent_conversatio_support_image_size_check CHECK (((support_image_size >= 4) AND (support_image_size <= 268435456))),
    CONSTRAINT environment_platform_agent_conversation_launch_generation_check CHECK (((launch_generation ~ '^[1-9][0-9]{0,19}$'::text) AND ((length(launch_generation) < 20) OR (launch_generation <= '18446744073709551615'::text)))),
    CONSTRAINT environment_platform_agent_conversations_agent_check CHECK ((agent = ANY (ARRAY['codex'::text, 'claude'::text]))),
    CONSTRAINT environment_platform_agent_conversations_binding_json_check CHECK (((jsonb_typeof(binding_json) = 'object'::text) AND (octet_length((binding_json)::text) <= 32768))),
    CONSTRAINT environment_platform_agent_conversations_check CHECK (((session_id = ('session-'::text || (driver_id)::text)) AND (driver_id <> '00000000-0000-0000-0000-000000000000'::uuid))),
    CONSTRAINT environment_platform_agent_conversations_check1 CHECK ((((binding_json ->> 'environment_id'::text) = environment_id) AND ((binding_json ->> 'pod_uid'::text) = (pod_uid)::text))),
    CONSTRAINT environment_platform_agent_conversations_check2 CHECK (((cleanup_request_id IS NULL) OR ((active_request_id IS NOT NULL) AND (cleanup_request_id <> active_request_id)))),
    CONSTRAINT environment_platform_agent_conversations_session_id_check CHECK ((session_id ~ '^session-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text))
);

--
-- Name: environment_platform_agent_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_platform_agent_requests (
    request_id uuid NOT NULL,
    organization_id text NOT NULL,
    environment_id text NOT NULL,
    actor_user_id text NOT NULL,
    via_api_key boolean NOT NULL,
    delegated_organization_id text,
    pod_uid uuid NOT NULL,
    fingerprint text NOT NULL,
    mutation_json jsonb NOT NULL,
    binding_json jsonb NOT NULL,
    owner_id uuid NOT NULL,
    mutation_lease_id text NOT NULL,
    cleanup_of uuid,
    phase text DEFAULT 'admitted'::text NOT NULL,
    receipt_json jsonb,
    reason_code text DEFAULT ''::text NOT NULL,
    admitted_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    issued_at timestamp with time zone,
    terminal_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT environment_platform_agent_requests_actor_user_id_check CHECK (((length(actor_user_id) >= 1) AND (length(actor_user_id) <= 256))),
    CONSTRAINT environment_platform_agent_requests_binding_json_check CHECK (((jsonb_typeof(binding_json) = 'object'::text) AND (octet_length((binding_json)::text) <= 32768))),
    CONSTRAINT environment_platform_agent_requests_check CHECK (((via_api_key = (delegated_organization_id IS NOT NULL)) AND ((delegated_organization_id IS NULL) OR (delegated_organization_id = organization_id)))),
    CONSTRAINT environment_platform_agent_requests_check1 CHECK (((cleanup_of IS NULL) OR ((cleanup_of <> request_id) AND ((mutation_json ->> 'action'::text) = 'stop'::text)))),
    CONSTRAINT environment_platform_agent_requests_check2 CHECK ((NOT ((mutation_json ->> 'cleanup_of_request_id'::text) IS DISTINCT FROM (cleanup_of)::text))),
    CONSTRAINT environment_platform_agent_requests_check3 CHECK ((((mutation_json ->> 'request_id'::text) = (request_id)::text) AND ((binding_json ->> 'organization_id'::text) = organization_id) AND ((binding_json ->> 'environment_id'::text) = environment_id) AND ((binding_json ->> 'pod_uid'::text) = (pod_uid)::text))),
    CONSTRAINT environment_platform_agent_requests_check4 CHECK ((((phase = 'admitted'::text) AND (issued_at IS NULL) AND (terminal_at IS NULL) AND (receipt_json IS NULL) AND (reason_code = ''::text)) OR ((phase = 'issued'::text) AND (issued_at IS NOT NULL) AND (terminal_at IS NULL) AND (receipt_json IS NULL) AND (reason_code = ''::text)) OR ((phase = 'completed'::text) AND (issued_at IS NOT NULL) AND (terminal_at IS NOT NULL) AND (receipt_json IS NOT NULL) AND (reason_code = ''::text)) OR ((phase = 'rejected'::text) AND (issued_at IS NOT NULL) AND (terminal_at IS NOT NULL) AND (receipt_json IS NOT NULL) AND (reason_code = 'platform-agent-command-refused'::text)) OR ((phase = 'rejected'::text) AND (terminal_at IS NOT NULL) AND (issued_at IS NULL) AND (receipt_json IS NULL) AND (reason_code = ANY (ARRAY['platform-agent-cancelled-before-dispatch'::text, 'platform-agent-preissue-refused'::text]))) OR ((phase = 'unknown'::text) AND (issued_at IS NOT NULL) AND (terminal_at IS NOT NULL) AND (reason_code = 'platform-agent-dispatch-unknown'::text)))),
    CONSTRAINT environment_platform_agent_requests_environment_id_check CHECK ((length(environment_id) = 36)),
    CONSTRAINT environment_platform_agent_requests_fingerprint_check CHECK ((fingerprint ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT environment_platform_agent_requests_mutation_json_check CHECK (((jsonb_typeof(mutation_json) = 'object'::text) AND (octet_length((mutation_json)::text) <= 32768))),
    CONSTRAINT environment_platform_agent_requests_organization_id_check CHECK (((length(organization_id) >= 1) AND (length(organization_id) <= 256))),
    CONSTRAINT environment_platform_agent_requests_owner_id_check CHECK ((owner_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT environment_platform_agent_requests_phase_check CHECK ((phase = ANY (ARRAY['admitted'::text, 'issued'::text, 'completed'::text, 'rejected'::text, 'unknown'::text]))),
    CONSTRAINT environment_platform_agent_requests_pod_uid_check CHECK ((pod_uid <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT environment_platform_agent_requests_reason_code_check CHECK ((reason_code = ANY (ARRAY[''::text, 'platform-agent-command-refused'::text, 'platform-agent-preissue-refused'::text, 'platform-agent-cancelled-before-dispatch'::text, 'platform-agent-dispatch-unknown'::text]))),
    CONSTRAINT environment_platform_agent_requests_receipt_json_check CHECK (((jsonb_typeof(receipt_json) = 'object'::text) AND (octet_length((receipt_json)::text) <= 32768))),
    CONSTRAINT environment_platform_agent_requests_request_id_check CHECK ((request_id <> '00000000-0000-0000-0000-000000000000'::uuid))
);

--
-- Name: environment_ports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_ports (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    environment_id text NOT NULL,
    port integer NOT NULL,
    label text NOT NULL,
    access text DEFAULT 'creator'::text NOT NULL,
    dns_record_id text,
    created_at timestamp without time zone DEFAULT now(),
    deletion_requested_at timestamp without time zone,
    CONSTRAINT environment_ports_access_check CHECK ((access = ANY (ARRAY['public'::text, 'org_members'::text, 'creator'::text]))),
    CONSTRAINT environment_ports_label_check CHECK ((label ~ '^[a-z0-9][a-z0-9-]{0,20}[a-z0-9]$'::text)),
    CONSTRAINT environment_ports_port_check CHECK (((port > 0) AND (port < 65536)))
);

--
-- Name: environment_presets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_presets (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text,
    name text NOT NULL,
    slug text,
    description text,
    official boolean DEFAULT false NOT NULL,
    language text,
    build_status text DEFAULT 'ready'::text NOT NULL,
    build_error text,
    default_ttl_seconds integer,
    created_at timestamp without time zone DEFAULT now(),
    project_spec jsonb NOT NULL,
    auto_image_ref text,
    CONSTRAINT environment_presets_auto_image_matches_project_spec CHECK (((auto_image_ref IS NULL) OR ((project_spec ->> 'image'::text) = auto_image_ref))),
    CONSTRAINT environment_presets_auto_image_ref_nonempty CHECK (((auto_image_ref IS NULL) OR (auto_image_ref <> ''::text))),
    CONSTRAINT environment_presets_scope_consistent CHECK ((official = (org_id IS NULL)))
);

--
-- Name: environment_quotas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_quotas (
    org_id text NOT NULL,
    max_concurrent_environments integer DEFAULT 10 NOT NULL,
    max_concurrent_sandbox integer DEFAULT 50 NOT NULL,
    max_cpu_millicores integer DEFAULT 32000 NOT NULL,
    max_memory_mb integer DEFAULT 65536 NOT NULL
);

--
-- Name: environment_resize_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_resize_operations (
    id text NOT NULL,
    org_id text NOT NULL,
    environment_id text NOT NULL,
    request_id text NOT NULL,
    previous_cpu_millicores integer NOT NULL,
    previous_memory_mb integer NOT NULL,
    previous_disk_gb integer NOT NULL,
    desired_cpu_millicores integer NOT NULL,
    desired_memory_mb integer NOT NULL,
    desired_disk_gb integer NOT NULL,
    last_applied_cpu_millicores integer NOT NULL,
    last_applied_memory_mb integer NOT NULL,
    last_applied_disk_gb integer NOT NULL,
    previous_state text NOT NULL,
    previous_desired_state text NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    force boolean DEFAULT false NOT NULL,
    disruption_policy text DEFAULT 'live_only'::text NOT NULL,
    planned_mode text NOT NULL,
    applied_mode text,
    pod_replaced boolean DEFAULT false NOT NULL,
    reserved_cpu_millicores integer DEFAULT 0 NOT NULL,
    reserved_memory_mb integer DEFAULT 0 NOT NULL,
    failure_code text,
    failure_message text,
    previous_pod_uid text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    completed_at timestamp without time zone,
    CONSTRAINT environment_resize_operations_applied_mode_check CHECK (((applied_mode IS NULL) OR (applied_mode = ANY (ARRAY['noop'::text, 'apply_on_start'::text, 'in_place'::text, 'restart'::text])))),
    CONSTRAINT environment_resize_operations_completion_mode_check CHECK (((state <> 'completed'::text) OR (applied_mode IS NOT NULL))),
    CONSTRAINT environment_resize_operations_disk_no_shrink_check CHECK ((desired_disk_gb >= previous_disk_gb)),
    CONSTRAINT environment_resize_operations_disruption_policy_check CHECK ((disruption_policy = ANY (ARRAY['live_only'::text, 'allow_restart'::text]))),
    CONSTRAINT environment_resize_operations_failure_check CHECK ((((state = 'failed'::text) AND (failure_code IS NOT NULL) AND (btrim(failure_code) <> ''::text) AND (failure_message IS NOT NULL) AND (btrim(failure_message) <> ''::text)) OR ((state <> 'failed'::text) AND (failure_code IS NULL) AND (failure_message IS NULL)))),
    CONSTRAINT environment_resize_operations_planned_mode_check CHECK ((planned_mode = ANY (ARRAY['noop'::text, 'apply_on_start'::text, 'in_place'::text, 'restart'::text]))),
    CONSTRAINT environment_resize_operations_previous_desired_state_check CHECK ((previous_desired_state = ANY (ARRAY['started'::text, 'stopped'::text]))),
    CONSTRAINT environment_resize_operations_previous_state_check CHECK ((previous_state = ANY (ARRAY['running'::text, 'stopped'::text]))),
    CONSTRAINT environment_resize_operations_reservations_nonnegative_check CHECK (((reserved_cpu_millicores >= 0) AND (reserved_memory_mb >= 0))),
    CONSTRAINT environment_resize_operations_resources_positive_check CHECK (((previous_cpu_millicores > 0) AND (previous_memory_mb > 0) AND (previous_disk_gb > 0) AND (desired_cpu_millicores > 0) AND (desired_memory_mb > 0) AND (desired_disk_gb > 0) AND (last_applied_cpu_millicores > 0) AND (last_applied_memory_mb > 0) AND (last_applied_disk_gb > 0))),
    CONSTRAINT environment_resize_operations_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'applying'::text, 'restarting'::text, 'completed'::text, 'failed'::text]))),
    CONSTRAINT environment_resize_operations_terminal_check CHECK ((((state = ANY (ARRAY['completed'::text, 'failed'::text])) AND (completed_at IS NOT NULL)) OR ((state <> ALL (ARRAY['completed'::text, 'failed'::text])) AND (completed_at IS NULL))))
);

--
-- Name: environment_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_sessions (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    environment_id text NOT NULL,
    name text NOT NULL,
    pid integer,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    ended_at timestamp without time zone,
    CONSTRAINT environment_sessions_status_check CHECK ((status = ANY (ARRAY['active'::text, 'ended'::text, 'error'::text])))
);

--
-- Name: environment_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_subscriptions (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    plan text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    stripe_subscription_id text,
    stripe_price_id text,
    trial_start timestamp without time zone,
    trial_end timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    stripe_event_created_at timestamp without time zone,
    stripe_event_id text
);

--
-- Name: environment_usage_billing; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_usage_billing (
    org_id text NOT NULL,
    billing_period_start timestamp without time zone NOT NULL,
    last_cpu_hours double precision DEFAULT 0 NOT NULL,
    last_mem_gb_hours double precision DEFAULT 0 NOT NULL,
    last_disk_gb_hours double precision DEFAULT 0 NOT NULL,
    last_overage_cents integer DEFAULT 0 NOT NULL,
    stripe_invoice_item_id text,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    runtime_tier text DEFAULT 'standard'::text NOT NULL
);

--
-- Name: environment_usage_billing_tiers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment_usage_billing_tiers (
    org_id text NOT NULL,
    billing_period_start timestamp without time zone NOT NULL,
    runtime_tier text NOT NULL,
    last_cpu_hours double precision DEFAULT 0 NOT NULL,
    last_mem_gb_hours double precision DEFAULT 0 NOT NULL,
    last_disk_gb_hours double precision DEFAULT 0 NOT NULL,
    last_overage_cents integer DEFAULT 0 NOT NULL,
    stripe_invoice_item_id text,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT environment_usage_billing_tiers_runtime_tier_check CHECK ((runtime_tier = ANY (ARRAY['standard'::text, 'confidential'::text])))
);

--
-- Name: environments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environments (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    created_by text NOT NULL,
    type text NOT NULL,
    name text,
    state text DEFAULT 'pending'::text NOT NULL,
    desired_state text DEFAULT 'started'::text NOT NULL,
    error_reason text,
    recoverable boolean DEFAULT true NOT NULL,
    state_changed_at timestamp without time zone DEFAULT now() NOT NULL,
    retry_count integer DEFAULT 0 NOT NULL,
    ttl_seconds integer,
    shutdown_at timestamp without time zone,
    cpu_millicores integer DEFAULT 2000 NOT NULL,
    memory_mb integer DEFAULT 4096 NOT NULL,
    disk_gb integer DEFAULT 10 NOT NULL,
    last_billing_event_at timestamp without time zone,
    total_running_seconds integer DEFAULT 0 NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    started_at timestamp without time zone,
    stopped_at timestamp without time zone,
    destroyed_at timestamp without time zone,
    preset_id text,
    deletion_requested_at timestamp without time zone,
    deletion_requested_by text,
    deletion_grace_until timestamp without time zone,
    protected boolean DEFAULT false NOT NULL,
    ttl_warning_sent_at timestamp without time zone,
    environment_operation_generation bigint DEFAULT 0 NOT NULL,
    external_cleanup_completed_at timestamp without time zone,
    isolation_tier text DEFAULT 'standard'::text NOT NULL,
    project_spec jsonb NOT NULL,
    CONSTRAINT chk_env_preset_id CHECK (((type <> 'sandbox'::text) OR (preset_id IS NOT NULL))),
    CONSTRAINT environments_desired_state_check CHECK ((desired_state = ANY (ARRAY['started'::text, 'stopped'::text, 'destroyed'::text, 'archived'::text, 'resized'::text]))),
    CONSTRAINT environments_external_cleanup_completed_check CHECK (((external_cleanup_completed_at IS NULL) OR ((state = 'destroyed'::text) AND (desired_state = 'destroyed'::text)))),
    CONSTRAINT environments_isolation_tier_check CHECK ((isolation_tier = ANY (ARRAY['standard'::text, 'confidential'::text]))),
    CONSTRAINT environments_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'pending_build'::text, 'building'::text, 'build_failed'::text, 'pulling_snapshot'::text, 'creating'::text, 'starting'::text, 'running'::text, 'stopping'::text, 'stopped'::text, 'archiving'::text, 'archived'::text, 'restoring'::text, 'resizing'::text, 'destroying'::text, 'destroyed'::text, 'error'::text, 'unknown'::text]))),
    CONSTRAINT environments_type_check CHECK ((type = 'sandbox'::text))
);

--
-- Name: jwks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.jwks (
    id text NOT NULL,
    public_key text NOT NULL,
    created_at timestamp without time zone NOT NULL,
    expires_at timestamp without time zone,
    private_key_ciphertext bytea,
    private_key_nonce bytea,
    private_key_kek_id text,
    private_key_format smallint,
    CONSTRAINT jwks_private_key_envelope_shape_check CHECK ((num_nonnulls(private_key_ciphertext, private_key_nonce, private_key_kek_id, private_key_format) = ANY (ARRAY[0, 4])))
);

--
-- Name: oidc_access_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_access_tokens (
    token_hash text NOT NULL,
    client_id text NOT NULL,
    user_id text NOT NULL,
    scopes text[] NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: oidc_auth_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_auth_requests (
    id text NOT NULL,
    client_id text NOT NULL,
    scopes text[] NOT NULL,
    redirect_uri text NOT NULL,
    state text,
    nonce text,
    response_type text DEFAULT 'code'::text NOT NULL,
    response_mode text,
    code_challenge text,
    code_challenge_method text,
    audience text[],
    user_id text,
    auth_time timestamp with time zone,
    done boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    code_hash text,
    CONSTRAINT oidc_auth_requests_code_hash_format_check CHECK (((code_hash IS NULL) OR (code_hash ~ '^[0-9a-f]{64}$'::text)))
);

--
-- Name: oidc_clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_clients (
    id text NOT NULL,
    secret text,
    name text,
    application_type text DEFAULT 'web'::text NOT NULL,
    auth_method text DEFAULT 'client_secret_basic'::text NOT NULL,
    redirect_uris text[] NOT NULL,
    post_logout_redirect_uris text[],
    grant_types text[] DEFAULT '{authorization_code}'::text[] NOT NULL,
    response_types text[] DEFAULT '{code}'::text[] NOT NULL,
    scopes text[] DEFAULT '{openid,profile,email}'::text[] NOT NULL,
    skip_consent boolean DEFAULT true NOT NULL,
    access_token_lifetime interval DEFAULT '01:00:00'::interval NOT NULL,
    refresh_token_lifetime interval,
    id_token_lifetime interval DEFAULT '01:00:00'::interval NOT NULL,
    clock_skew interval DEFAULT '00:00:00'::interval NOT NULL,
    disabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: oidc_device_authorizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_device_authorizations (
    client_id text NOT NULL,
    scopes text[] NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    user_id text,
    auth_time bigint,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    device_code_hash text NOT NULL,
    user_code_hash text NOT NULL,
    CONSTRAINT oidc_device_authorizations_device_code_hash_format_check CHECK ((device_code_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT oidc_device_authorizations_resolution_check CHECK ((((status = ANY (ARRAY['pending'::text, 'denied'::text])) AND (user_id IS NULL) AND (auth_time IS NULL)) OR ((status = 'approved'::text) AND (user_id IS NOT NULL)))),
    CONSTRAINT oidc_device_authorizations_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'denied'::text]))),
    CONSTRAINT oidc_device_authorizations_user_code_hash_format_check CHECK ((user_code_hash ~ '^[0-9a-f]{64}$'::text))
);

--
-- Name: oidc_refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_refresh_tokens (
    id text NOT NULL,
    token_hash text NOT NULL,
    client_id text NOT NULL,
    user_id text NOT NULL,
    scopes text[] NOT NULL,
    audience text[],
    auth_time timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: org_invitations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.org_invitations (
    id text NOT NULL,
    org_id text NOT NULL,
    email text NOT NULL,
    role text DEFAULT 'member'::text NOT NULL,
    invited_by text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    accepted_at timestamp without time zone,
    assignments text[] DEFAULT ARRAY['viewer'::text] NOT NULL,
    token_hash text NOT NULL,
    CONSTRAINT org_invitations_token_hash_format_check CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text))
);

--
-- Name: org_member_assignments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.org_member_assignments (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_member_id text NOT NULL,
    assignment text NOT NULL,
    granted_by text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT org_member_assignments_assignment_check CHECK ((assignment = ANY (ARRAY['viewer'::text, 'developer'::text, 'environments_admin'::text, 'sandboxes_admin'::text, 'billing_admin'::text, 'auditor'::text, 'super_admin'::text])))
);

--
-- Name: org_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.org_members (
    id text NOT NULL,
    org_id text NOT NULL,
    user_id text NOT NULL,
    role text DEFAULT 'member'::text NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);

--
-- Name: org_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.org_subscriptions (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    plan text DEFAULT 'starter'::text NOT NULL,
    status text DEFAULT 'trialing'::text NOT NULL,
    stripe_subscription_id text,
    seat_count integer DEFAULT 0 NOT NULL,
    trial_start timestamp without time zone,
    trial_end timestamp without time zone,
    current_period_start timestamp without time zone,
    current_period_end timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    stripe_event_created_at timestamp without time zone,
    stripe_event_id text
);

--
-- Name: organization_deletion_billing_phases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization_deletion_billing_phases (
    operation_id text NOT NULL,
    organization_id text NOT NULL,
    generation bigint NOT NULL,
    stripe_customer_id text,
    state text DEFAULT 'pending'::text NOT NULL,
    failure_code text,
    final_usage_completed_at timestamp without time zone,
    checkout_sessions_expired_at timestamp without time zone,
    subscriptions_verified_at timestamp without time zone,
    completed_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_deletion_billing_failure_code_check CHECK (((failure_code IS NULL) OR (failure_code ~ '^[a-z0-9_]{1,128}$'::text))),
    CONSTRAINT organization_deletion_billing_generation_check CHECK ((generation > 0)),
    CONSTRAINT organization_deletion_billing_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'running'::text, 'failed'::text, 'completed'::text]))),
    CONSTRAINT organization_deletion_billing_terminal_metadata_check CHECK ((((state = ANY (ARRAY['pending'::text, 'running'::text])) AND (failure_code IS NULL) AND (completed_at IS NULL)) OR ((state = 'failed'::text) AND (failure_code IS NOT NULL) AND (completed_at IS NULL)) OR ((state = 'completed'::text) AND (failure_code IS NULL) AND (final_usage_completed_at IS NOT NULL) AND (checkout_sessions_expired_at IS NOT NULL) AND (subscriptions_verified_at IS NOT NULL) AND (completed_at IS NOT NULL))))
);

--
-- Name: organization_deletion_billing_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization_deletion_billing_subscriptions (
    operation_id text NOT NULL,
    organization_id text NOT NULL,
    generation bigint NOT NULL,
    stripe_subscription_id text NOT NULL,
    state text DEFAULT 'captured'::text NOT NULL,
    captured_at timestamp without time zone DEFAULT now() NOT NULL,
    verified_terminal_at timestamp without time zone,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_deletion_billing_subscriptions_generation_check CHECK ((generation > 0)),
    CONSTRAINT organization_deletion_billing_subscriptions_state_check CHECK ((state = ANY (ARRAY['captured'::text, 'terminal'::text]))),
    CONSTRAINT organization_deletion_billing_subscriptions_terminal_check CHECK ((((state = 'captured'::text) AND (verified_terminal_at IS NULL)) OR ((state = 'terminal'::text) AND (verified_terminal_at IS NOT NULL))))
);

--
-- Name: organization_deletion_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization_deletion_operations (
    id text NOT NULL,
    organization_id text NOT NULL,
    generation bigint NOT NULL,
    requested_by text NOT NULL,
    workflow_id text NOT NULL,
    state text DEFAULT 'pending_start'::text NOT NULL,
    phase text DEFAULT 'write_fenced'::text NOT NULL,
    failure_code text,
    start_attempts integer DEFAULT 0 NOT NULL,
    last_start_attempt_at timestamp without time zone,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_deletion_operations_failure_code_check CHECK (((failure_code IS NULL) OR (failure_code ~ '^[a-z0-9_]{1,128}$'::text))),
    CONSTRAINT organization_deletion_operations_generation_check CHECK ((generation > 0)),
    CONSTRAINT organization_deletion_operations_phase_check CHECK ((phase ~ '^[a-z0-9_]{1,128}$'::text)),
    CONSTRAINT organization_deletion_operations_start_attempts_check CHECK ((start_attempts >= 0)),
    CONSTRAINT organization_deletion_operations_state_check CHECK ((state = ANY (ARRAY['pending_start'::text, 'started'::text, 'failed'::text, 'completed'::text]))),
    CONSTRAINT organization_deletion_operations_terminal_metadata_check CHECK ((((state = 'pending_start'::text) AND (started_at IS NULL) AND (completed_at IS NULL) AND (failure_code IS NULL)) OR ((state = 'started'::text) AND (started_at IS NOT NULL) AND (completed_at IS NULL) AND (failure_code IS NULL)) OR ((state = 'failed'::text) AND (completed_at IS NULL) AND (failure_code IS NOT NULL)) OR ((state = 'completed'::text) AND (completed_at IS NOT NULL) AND (failure_code IS NULL))))
);

--
-- Name: organization_mutation_leases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization_mutation_leases (
    id text NOT NULL,
    organization_id text NOT NULL,
    mutation_class text NOT NULL,
    state text DEFAULT 'active'::text NOT NULL,
    admitted_at timestamp without time zone DEFAULT now() NOT NULL,
    deadline_at timestamp without time zone NOT NULL,
    released_at timestamp without time zone,
    resolution_required_at timestamp without time zone,
    resolved_at timestamp without time zone,
    recovery_code text,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    environment_id text,
    CONSTRAINT organization_mutation_leases_class_check CHECK ((mutation_class = ANY (ARRAY['control_plane_database'::text, 'environment_runtime_dispatch'::text, 'tenant_secret_provider'::text, 'billing_provider'::text]))),
    CONSTRAINT organization_mutation_leases_deadline_check CHECK ((deadline_at > admitted_at)),
    CONSTRAINT organization_mutation_leases_environment_scope_check CHECK (((environment_id IS NULL) OR ((mutation_class = 'environment_runtime_dispatch'::text) AND (environment_id <> ''::text)))),
    CONSTRAINT organization_mutation_leases_recovery_code_check CHECK (((recovery_code IS NULL) OR (recovery_code ~ '^[a-z0-9_]{1,128}$'::text))),
    CONSTRAINT organization_mutation_leases_state_check CHECK ((state = ANY (ARRAY['active'::text, 'released'::text, 'resolution_required'::text, 'resolved'::text]))),
    CONSTRAINT organization_mutation_leases_terminal_metadata_check CHECK ((((state = 'active'::text) AND (released_at IS NULL) AND (resolution_required_at IS NULL) AND (resolved_at IS NULL) AND (recovery_code IS NULL)) OR ((state = 'released'::text) AND (released_at IS NOT NULL) AND (resolution_required_at IS NULL) AND (resolved_at IS NULL) AND (recovery_code IS NULL)) OR ((state = 'resolution_required'::text) AND (released_at IS NULL) AND (resolution_required_at IS NOT NULL) AND (resolved_at IS NULL) AND (recovery_code IS NOT NULL)) OR ((state = 'resolved'::text) AND (released_at IS NULL) AND (resolution_required_at IS NOT NULL) AND (resolved_at IS NOT NULL) AND (recovery_code IS NOT NULL))))
);

--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    id text NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    created_by text NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    stripe_customer_id text,
    billing_plan text DEFAULT 'none'::text NOT NULL,
    billing_status text DEFAULT 'none'::text NOT NULL,
    trial_ends_at timestamp without time zone,
    deletion_state text DEFAULT 'active'::text NOT NULL,
    deletion_generation bigint DEFAULT 0 NOT NULL,
    deletion_requested_by text,
    deletion_requested_at timestamp without time zone,
    deletion_operation_id text,
    deletion_workflow_id text,
    deletion_phase text,
    deletion_failure_code text,
    billing_exempt boolean DEFAULT false NOT NULL,
    CONSTRAINT organizations_deletion_failure_code_check CHECK (((deletion_failure_code IS NULL) OR (deletion_failure_code ~ '^[a-z0-9_]{1,128}$'::text))),
    CONSTRAINT organizations_deletion_generation_check CHECK ((deletion_generation >= 0)),
    CONSTRAINT organizations_deletion_metadata_check CHECK ((((deletion_state = 'active'::text) AND (deletion_operation_id IS NULL) AND (deletion_workflow_id IS NULL) AND (deletion_requested_by IS NULL) AND (deletion_requested_at IS NULL) AND (deletion_phase IS NULL) AND (deletion_failure_code IS NULL)) OR ((deletion_state = 'deleting'::text) AND (deletion_generation > 0) AND (deletion_operation_id IS NOT NULL) AND (deletion_workflow_id IS NOT NULL) AND (deletion_requested_at IS NOT NULL) AND (deletion_phase IS NOT NULL) AND (deletion_failure_code IS NULL)) OR ((deletion_state = 'delete_failed'::text) AND (deletion_generation > 0) AND (deletion_operation_id IS NOT NULL) AND (deletion_workflow_id IS NOT NULL) AND (deletion_requested_at IS NOT NULL) AND (deletion_phase IS NOT NULL) AND (deletion_failure_code IS NOT NULL)))),
    CONSTRAINT organizations_deletion_phase_check CHECK (((deletion_phase IS NULL) OR (deletion_phase ~ '^[a-z0-9_]{1,128}$'::text))),
    CONSTRAINT organizations_deletion_state_check CHECK ((deletion_state = ANY (ARRAY['active'::text, 'deleting'::text, 'delete_failed'::text]))),
    CONSTRAINT organizations_route_slug_check CHECK ((((length(slug) >= 3) AND (length(slug) <= 48)) AND (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'::text) AND (slug <> ALL (ARRAY['accept-invite'::text, 'admin'::text, 'api'::text, 'assets'::text, 'auth'::text, 'connect'::text, 'dashboard'::text, 'device'::text, 'docs'::text, 'forgot-password'::text, 'grpc'::text, 'healthz'::text, 'login'::text, 'oauth'::text, 'organizations'::text, 'preview'::text, 'reset-password'::text, 'settings'::text, 'setup-2fa'::text, 'signup'::text, 'ssh-proxy'::text, 'terminal'::text, 'two-factor'::text, 'verify-email'::text]))))
);

--
-- Name: platform_access_profile_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_access_profile_entries (
    profile_id text NOT NULL,
    revision bigint NOT NULL,
    capability_slot text NOT NULL,
    credential_id text NOT NULL,
    CONSTRAINT platform_access_profile_entries_capability_slot_check CHECK (((octet_length(capability_slot) >= 1) AND (octet_length(capability_slot) <= 128))),
    CONSTRAINT platform_access_profile_entries_credential_id_check CHECK (((octet_length(credential_id) >= 1) AND (octet_length(credential_id) <= 128))),
    CONSTRAINT platform_access_profile_entries_revision_check CHECK ((revision > 0)),
    CONSTRAINT platform_access_profile_entries_slot_check CHECK ((capability_slot <> 'github'::text))
);

--
-- Name: platform_access_profile_revisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_access_profile_revisions (
    profile_id text NOT NULL,
    revision bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_access_profile_revisions_revision_check CHECK ((revision > 0))
);

--
-- Name: platform_access_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_access_profiles (
    id text NOT NULL,
    user_id text,
    organization_id text,
    name text NOT NULL,
    current_revision bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_access_profiles_current_revision_check CHECK ((current_revision > 0)),
    CONSTRAINT platform_access_profiles_id_check CHECK (((octet_length(id) >= 1) AND (octet_length(id) <= 128))),
    CONSTRAINT platform_access_profiles_name_check CHECK (((octet_length(name) >= 1) AND (octet_length(name) <= 128))),
    CONSTRAINT platform_access_profiles_owner_check CHECK (((user_id IS NOT NULL) <> (organization_id IS NOT NULL)))
);

--
-- Name: platform_credential_material; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_credential_material (
    credential_id text NOT NULL,
    material_generation bigint NOT NULL,
    kek_provider text NOT NULL,
    key_name text NOT NULL,
    key_version bigint NOT NULL,
    wrapped_dek bytea NOT NULL,
    wrapped_format smallint NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    format smallint NOT NULL,
    CONSTRAINT platform_credential_material_ciphertext_check CHECK (((octet_length(ciphertext) >= 16) AND (octet_length(ciphertext) <= 1048592))),
    CONSTRAINT platform_credential_material_format_check CHECK ((format = 1)),
    CONSTRAINT platform_credential_material_kek_provider_check CHECK ((kek_provider = 'openbao-transit'::text)),
    CONSTRAINT platform_credential_material_key_version_check CHECK (((key_version > 0) AND (key_version <= '4294967295'::bigint))),
    CONSTRAINT platform_credential_material_material_generation_check CHECK ((material_generation > 0)),
    CONSTRAINT platform_credential_material_nonce_check CHECK ((octet_length(nonce) = 12)),
    CONSTRAINT platform_credential_material_wrapped_dek_check CHECK (((octet_length(wrapped_dek) >= 1) AND (octet_length(wrapped_dek) <= 65536))),
    CONSTRAINT platform_credential_material_wrapped_format_check CHECK ((wrapped_format = 1))
);

--
-- Name: platform_credential_refresh_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_credential_refresh_attempts (
    credential_id text NOT NULL,
    attempt_id uuid NOT NULL,
    expected_revocation_generation bigint NOT NULL,
    expected_material_generation bigint NOT NULL,
    state text NOT NULL,
    reserved_until timestamp with time zone NOT NULL,
    started_at timestamp with time zone,
    started_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_credential_refresh__expected_material_generation_check CHECK (((expected_material_generation > 0) AND (expected_material_generation < '9223372036854775807'::bigint))),
    CONSTRAINT platform_credential_refresh__expected_revocation_generati_check CHECK (((expected_revocation_generation > 0) AND (expected_revocation_generation < '9223372036854775807'::bigint))),
    CONSTRAINT platform_credential_refresh_attempts_attempt_id_check CHECK ((attempt_id <> '00000000-0000-0000-0000-000000000000'::uuid)),
    CONSTRAINT platform_credential_refresh_attempts_started_check CHECK ((((state = ANY (ARRAY['reserved'::text, 'cancelled'::text])) AND (started_at IS NULL) AND (started_until IS NULL)) OR ((state = ANY (ARRAY['started'::text, 'staged'::text, 'committed'::text, 'unknown'::text])) AND (started_at IS NOT NULL) AND (started_until IS NOT NULL) AND (started_until > started_at)))),
    CONSTRAINT platform_credential_refresh_attempts_state_check CHECK ((state = ANY (ARRAY['reserved'::text, 'started'::text, 'staged'::text, 'committed'::text, 'unknown'::text, 'cancelled'::text])))
);

--
-- Name: platform_credential_refresh_material; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_credential_refresh_material (
    attempt_id uuid NOT NULL,
    kek_provider text NOT NULL,
    key_name text NOT NULL,
    key_version bigint NOT NULL,
    wrapped_dek bytea NOT NULL,
    wrapped_format smallint NOT NULL,
    ciphertext bytea,
    nonce bytea,
    format smallint,
    CONSTRAINT platform_credential_refresh_material_ciphertext_check CHECK (((octet_length(ciphertext) >= 16) AND (octet_length(ciphertext) <= 1048592))),
    CONSTRAINT platform_credential_refresh_material_envelope_check CHECK ((((ciphertext IS NULL) AND (nonce IS NULL) AND (format IS NULL)) OR ((ciphertext IS NOT NULL) AND (nonce IS NOT NULL) AND (format IS NOT NULL)))),
    CONSTRAINT platform_credential_refresh_material_format_check CHECK ((format = 1)),
    CONSTRAINT platform_credential_refresh_material_kek_provider_check CHECK ((kek_provider = 'openbao-transit'::text)),
    CONSTRAINT platform_credential_refresh_material_key_version_check CHECK (((key_version > 0) AND (key_version <= '4294967295'::bigint))),
    CONSTRAINT platform_credential_refresh_material_nonce_check CHECK ((octet_length(nonce) = 12)),
    CONSTRAINT platform_credential_refresh_material_wrapped_dek_check CHECK (((octet_length(wrapped_dek) >= 1) AND (octet_length(wrapped_dek) <= 65536))),
    CONSTRAINT platform_credential_refresh_material_wrapped_format_check CHECK ((wrapped_format = 1))
);

--
-- Name: platform_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_credentials (
    id text NOT NULL,
    user_id text,
    organization_id text,
    provider text NOT NULL,
    authentication_kind text NOT NULL,
    display_name text NOT NULL,
    account_hint text,
    status text NOT NULL,
    expires_at_unix bigint,
    revocation_generation bigint NOT NULL,
    material_generation bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    ssh_public_key text,
    ssh_fingerprint text,
    CONSTRAINT platform_credentials_account_hint_check CHECK (((octet_length(account_hint) >= 1) AND (octet_length(account_hint) <= 256))),
    CONSTRAINT platform_credentials_authentication_kind_check CHECK ((authentication_kind = ANY (ARRAY['oauth'::text, 'api_key'::text, 'access_token'::text, 'github_app'::text, 'ssh_key'::text, 'claude_sign_in'::text]))),
    CONSTRAINT platform_credentials_claude_sign_in_check CHECK (((authentication_kind <> 'claude_sign_in'::text) OR ((provider = 'anthropic'::text) AND (user_id IS NOT NULL) AND (organization_id IS NULL)))),
    CONSTRAINT platform_credentials_display_name_check CHECK (((octet_length(display_name) >= 1) AND (octet_length(display_name) <= 256))),
    CONSTRAINT platform_credentials_expiry_check CHECK ((expires_at_unix >= 0)),
    CONSTRAINT platform_credentials_material_generation_check CHECK ((material_generation > 0)),
    CONSTRAINT platform_credentials_owner_check CHECK (((user_id IS NOT NULL) <> (organization_id IS NOT NULL))),
    CONSTRAINT platform_credentials_revocation_generation_check CHECK ((revocation_generation > 0)),
    CONSTRAINT platform_credentials_ssh_fingerprint_check CHECK (((octet_length(ssh_fingerprint) = 50) AND (ssh_fingerprint ~ '^SHA256:[A-Za-z0-9+/]{43}$'::text) AND (ssh_fingerprint !~ '[[:cntrl:]]'::text))),
    CONSTRAINT platform_credentials_ssh_identity_check CHECK ((((provider = 'ssh'::text) = (authentication_kind = 'ssh_key'::text)) AND ((ssh_public_key IS NOT NULL) = (authentication_kind = 'ssh_key'::text)) AND ((ssh_fingerprint IS NOT NULL) = (authentication_kind = 'ssh_key'::text)) AND ((authentication_kind <> 'ssh_key'::text) OR (account_hint IS NULL)))),
    CONSTRAINT platform_credentials_ssh_public_key_check CHECK ((((octet_length(ssh_public_key) >= 1) AND (octet_length(ssh_public_key) <= 4096)) AND (ssh_public_key ~ '^(ssh-ed25519|ssh-rsa) [A-Za-z0-9+/]+={0,2}$'::text) AND (octet_length(split_part(ssh_public_key, ' '::text, 2)) >= 20) AND ((octet_length(split_part(ssh_public_key, ' '::text, 2)) % 4) = 0) AND (ssh_public_key !~ '[[:cntrl:]]'::text))),
    CONSTRAINT platform_credentials_status_check CHECK ((status = ANY (ARRAY['active'::text, 'expired'::text, 'refresh_failed'::text, 'revoked'::text])))
);

--
-- Name: platform_environment_access_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_environment_access_bindings (
    environment_id text NOT NULL,
    profile_id text NOT NULL,
    profile_revision bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    personal_owner_confirmed_by text,
    CONSTRAINT platform_environment_access_bindings_profile_revision_check CHECK ((profile_revision > 0))
);

--
-- Name: preview_auth_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.preview_auth_challenges (
    id text NOT NULL,
    nonce_hash text NOT NULL,
    client_hash text NOT NULL,
    organization_id text NOT NULL,
    environment_id text NOT NULL,
    port_id text NOT NULL,
    host text NOT NULL,
    return_path text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    session_id text,
    code_hash text,
    code_expires_at timestamp with time zone,
    consumed_at timestamp with time zone,
    CONSTRAINT preview_auth_challenges_check CHECK (((expires_at > created_at) AND (expires_at <= (created_at + '00:05:00'::interval)))),
    CONSTRAINT preview_auth_challenges_check1 CHECK (((consumed_at IS NULL) OR ((code_hash IS NOT NULL) AND (consumed_at <= expires_at)))),
    CONSTRAINT preview_auth_challenges_check2 CHECK ((((session_id IS NULL) AND (code_hash IS NULL) AND (code_expires_at IS NULL)) OR ((session_id IS NOT NULL) AND (code_hash IS NOT NULL) AND (code_expires_at IS NOT NULL) AND (code_expires_at <= expires_at)))),
    CONSTRAINT preview_auth_challenges_client_hash_check CHECK ((client_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT preview_auth_challenges_code_hash_check CHECK ((code_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT preview_auth_challenges_host_check CHECK (((length(host) >= 1) AND (length(host) <= 253))),
    CONSTRAINT preview_auth_challenges_nonce_hash_check CHECK ((nonce_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT preview_auth_challenges_return_path_check CHECK ((((length(return_path) >= 1) AND (length(return_path) <= 4096)) AND ("left"(return_path, 1) = '/'::text)))
);

--
-- Name: preview_browser_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.preview_browser_grants (
    token_hash text NOT NULL,
    session_id text NOT NULL,
    organization_id text NOT NULL,
    environment_id text NOT NULL,
    port_id text NOT NULL,
    host text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT preview_browser_grants_host_check CHECK (((length(host) >= 1) AND (length(host) <= 253))),
    CONSTRAINT preview_browser_grants_token_hash_check CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text))
);

--
-- Name: rate_limit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rate_limit (
    id text NOT NULL,
    key text NOT NULL,
    count integer NOT NULL,
    last_request bigint NOT NULL
);

--
-- Name: repo_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.repo_configs (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    repo_url text NOT NULL,
    created_by text NOT NULL,
    updated_at timestamp without time zone DEFAULT now(),
    project_spec jsonb NOT NULL
);

--
-- Name: runtime_transport_zones; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.runtime_transport_zones (
    name text NOT NULL,
    runtime_region text NOT NULL,
    peer_relay jsonb DEFAULT '{}'::jsonb NOT NULL,
    direct_udp jsonb DEFAULT '{}'::jsonb NOT NULL,
    stun jsonb DEFAULT '{}'::jsonb NOT NULL,
    derp jsonb DEFAULT '{}'::jsonb NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: sandbox_environment_backend; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sandbox_environment_backend (
    environment_id text NOT NULL,
    namespace text NOT NULL,
    sandbox_claim_name text,
    pod_name text,
    pod_ip text,
    agent_port integer DEFAULT 9090 NOT NULL,
    snapshot_ref text,
    setup_phase integer DEFAULT 0 NOT NULL,
    setup_complete boolean DEFAULT false NOT NULL,
    setup_error text,
    wireguard_public_key text,
    sandbox_claim_uid text,
    setup_owner_generation bigint,
    setup_owner_activity_id text,
    setup_owner_attempt integer,
    setup_owner_phase integer,
    setup_owner_status text,
    setup_owner_pod_uid text,
    pod_uid text,
    bound_at timestamp with time zone,
    workspace_pvc_uid text,
    CONSTRAINT chk_sandbox_backend_binding_coherent CHECK (((pod_uid IS NULL) = (bound_at IS NULL))),
    CONSTRAINT chk_sandbox_backend_workspace_pvc_uid CHECK ((workspace_pvc_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'::text)),
    CONSTRAINT chk_sandbox_setup_owner_coherent CHECK ((((setup_owner_generation IS NULL) AND (setup_owner_activity_id IS NULL) AND (setup_owner_attempt IS NULL) AND (setup_owner_phase IS NULL) AND (setup_owner_status IS NULL) AND (setup_owner_pod_uid IS NULL)) OR ((setup_owner_generation IS NOT NULL) AND (setup_owner_generation > 0) AND (setup_owner_activity_id IS NOT NULL) AND (btrim(setup_owner_activity_id) <> ''::text) AND (setup_owner_attempt IS NOT NULL) AND (setup_owner_attempt > 0) AND (setup_owner_phase IS NOT NULL) AND (setup_owner_phase >= 0) AND (setup_owner_status IS NOT NULL) AND (((setup_owner_status = 'claimed'::text) AND (setup_owner_pod_uid IS NULL)) OR ((setup_owner_status = ANY (ARRAY['running'::text, 'reaping'::text])) AND (setup_owner_pod_uid IS NOT NULL) AND (btrim(setup_owner_pod_uid) <> ''::text))))))
);

--
-- Name: sandbox_running_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sandbox_running_sessions (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    environment_id text NOT NULL,
    organization_id text NOT NULL,
    runtime_type text DEFAULT 'sandbox'::text NOT NULL,
    runtime_uid text NOT NULL,
    runtime_name text NOT NULL,
    runtime_namespace text NOT NULL,
    cpu_millicores integer NOT NULL,
    memory_mib integer NOT NULL,
    disk_gib integer NOT NULL,
    runtime_class text,
    started_at timestamp with time zone NOT NULL,
    last_observed_at timestamp with time zone NOT NULL,
    ended_at timestamp with time zone,
    end_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    runtime_tier text DEFAULT 'standard'::text NOT NULL
);

--
-- Name: sandbox_ssh_host_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sandbox_ssh_host_keys (
    pod_uid text NOT NULL,
    environment_id text NOT NULL,
    operation_generation bigint NOT NULL,
    public_key text NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT sandbox_ssh_host_keys_operation_generation_check CHECK ((operation_generation > 0)),
    CONSTRAINT sandbox_ssh_host_keys_pod_uid_check CHECK ((pod_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'::text)),
    CONSTRAINT sandbox_ssh_host_keys_public_key_check CHECK ((public_key ~ '^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43}$'::text))
);

--
-- Name: sandbox_template_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sandbox_template_config (
    preset_id text NOT NULL,
    image_ref text NOT NULL,
    sandbox_template_name text NOT NULL,
    persistent_storage boolean DEFAULT false NOT NULL
);

--
-- Name: sandbox_workspace_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sandbox_workspace_bindings (
    pod_uid text NOT NULL,
    environment_id text NOT NULL,
    namespace text NOT NULL,
    pod_name text NOT NULL,
    claim_uid text NOT NULL,
    sandbox_uid text NOT NULL,
    workspace_pvc_uid text,
    operation_generation bigint NOT NULL,
    projection_selection_sha256 text,
    managed_credential_clients text NOT NULL,
    credential_scope text NOT NULL,
    bound_at timestamp with time zone DEFAULT now() NOT NULL,
    released_at timestamp with time zone,
    CONSTRAINT sandbox_workspace_bindings_claim_uid_check CHECK ((claim_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'::text)),
    CONSTRAINT sandbox_workspace_bindings_credential_scope_check CHECK ((credential_scope = ANY (ARRAY['environment'::text, 'pod'::text]))),
    CONSTRAINT sandbox_workspace_bindings_namespace_check CHECK ((btrim(namespace) <> ''::text)),
    CONSTRAINT sandbox_workspace_bindings_operation_generation_check CHECK ((operation_generation > 0)),
    CONSTRAINT sandbox_workspace_bindings_pod_name_check CHECK ((btrim(pod_name) <> ''::text)),
    CONSTRAINT sandbox_workspace_bindings_pod_uid_check CHECK ((pod_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'::text)),
    CONSTRAINT sandbox_workspace_bindings_projection_selection_sha256_check CHECK ((projection_selection_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT sandbox_workspace_bindings_released_after_bound CHECK (((released_at IS NULL) OR (released_at >= bound_at))),
    CONSTRAINT sandbox_workspace_bindings_sandbox_uid_check CHECK ((sandbox_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'::text)),
    CONSTRAINT sandbox_workspace_bindings_workspace_pvc_uid_check CHECK ((workspace_pvc_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'::text))
);

--
-- Name: secret_projects; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secret_projects (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    name text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);

--
-- Name: sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sessions (
    id text NOT NULL,
    user_id text NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    ip_address text,
    user_agent text,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    token_hash text NOT NULL,
    two_factor_setup_skipped_at timestamp without time zone,
    CONSTRAINT sessions_token_hash_format_check CHECK (((token_hash IS NULL) OR (token_hash ~ '^[0-9a-f]{64}$'::text)))
);

--
-- Name: stripe_invoices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.stripe_invoices (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    stripe_invoice_id text NOT NULL,
    stripe_subscription_id text,
    status text NOT NULL,
    amount_due integer NOT NULL,
    amount_paid integer DEFAULT 0 NOT NULL,
    currency text DEFAULT 'usd'::text NOT NULL,
    hosted_invoice_url text,
    invoice_pdf text,
    period_start timestamp without time zone,
    period_end timestamp without time zone,
    receipt_sent_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);

--
-- Name: stripe_webhook_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.stripe_webhook_events (
    id text NOT NULL,
    event_type text NOT NULL,
    processed_at timestamp without time zone DEFAULT now(),
    stripe_created_at timestamp without time zone
);

--
-- Name: tenant_secret_deks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_secret_deks (
    dek_id text DEFAULT (gen_random_uuid())::text NOT NULL,
    scope text NOT NULL,
    scope_id text NOT NULL,
    provider text NOT NULL,
    key_name text NOT NULL,
    key_version bigint NOT NULL,
    wrapped_dek text NOT NULL,
    format smallint DEFAULT 1 NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tenant_secret_deks_format_check CHECK ((format = 1)),
    CONSTRAINT tenant_secret_deks_key_name_check CHECK ((key_name = 'tenant-dek'::text)),
    CONSTRAINT tenant_secret_deks_key_version_check CHECK (((key_version >= 1) AND (key_version <= '4294967295'::bigint))),
    CONSTRAINT tenant_secret_deks_provider_check CHECK ((provider = 'openbao-transit'::text)),
    CONSTRAINT tenant_secret_deks_revision_check CHECK ((revision > 0)),
    CONSTRAINT tenant_secret_deks_scope_check CHECK ((scope = ANY (ARRAY['org'::text, 'user'::text]))),
    CONSTRAINT tenant_secret_deks_scope_id_check CHECK ((((length(scope_id) >= 1) AND (length(scope_id) <= 255)) AND (scope_id ~ '^[A-Za-z0-9_-]+$'::text))),
    CONSTRAINT tenant_secret_deks_wrapped_shape_check CHECK ((((length(wrapped_dek) >= 12) AND (length(wrapped_dek) <= 4096)) AND (wrapped_dek ~ '^vault:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2}$'::text) AND (split_part(wrapped_dek, ':'::text, 2) = ('v'::text || (key_version)::text))))
);

--
-- Name: tenant_secret_kek_canary; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_secret_kek_canary (
    singleton boolean DEFAULT true NOT NULL,
    provider text NOT NULL,
    key_name text NOT NULL,
    key_version bigint NOT NULL,
    wrapped_dek text NOT NULL,
    format smallint DEFAULT 1 NOT NULL,
    expected_authority_id text NOT NULL,
    plaintext_sha256 bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    verified_at timestamp with time zone,
    CONSTRAINT tenant_secret_kek_canary_digest_check CHECK ((octet_length(plaintext_sha256) = 32)),
    CONSTRAINT tenant_secret_kek_canary_format_check CHECK ((format = 1)),
    CONSTRAINT tenant_secret_kek_canary_key_name_check CHECK ((key_name = 'tenant-dek'::text)),
    CONSTRAINT tenant_secret_kek_canary_key_version_check CHECK (((key_version >= 1) AND (key_version <= '4294967295'::bigint))),
    CONSTRAINT tenant_secret_kek_canary_provider_check CHECK ((provider = 'openbao-transit'::text)),
    CONSTRAINT tenant_secret_kek_canary_singleton_check CHECK (singleton),
    CONSTRAINT tenant_secret_kek_canary_wrapped_shape_check CHECK ((((length(expected_authority_id) >= 1) AND (length(expected_authority_id) <= 255)) AND (expected_authority_id ~ '^[A-Za-z0-9_.:-]+$'::text) AND ((length(wrapped_dek) >= 12) AND (length(wrapped_dek) <= 4096)) AND (wrapped_dek ~ '^vault:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2}$'::text) AND (split_part(wrapped_dek, ':'::text, 2) = ('v'::text || (key_version)::text))))
);

--
-- Name: tenant_secrets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_secrets (
    path text NOT NULL,
    key text NOT NULL,
    dek_id text NOT NULL,
    scope text NOT NULL,
    scope_id text NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    format smallint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    storage_contract_version smallint DEFAULT 0 NOT NULL,
    CONSTRAINT tenant_secrets_key_check CHECK ((((length(key) >= 1) AND (length(key) <= 255)) AND (key ~ '^[A-Za-z_][A-Za-z0-9_]*$'::text))),
    CONSTRAINT tenant_secrets_path_scope_check CHECK ((((scope = 'org'::text) AND ((path = ('/org-secrets/'::text || scope_id)) OR (path ~ (('^/projects/'::text || scope_id) || '/[A-Za-z0-9_-]{1,255}$'::text)))) OR ((scope = 'user'::text) AND (path = ('/users/'::text || scope_id))))),
    CONSTRAINT tenant_secrets_payload_check CHECK (((octet_length(ciphertext) >= 16) AND (octet_length(nonce) = 12) AND (format = 1))),
    CONSTRAINT tenant_secrets_storage_contract_version_check CHECK ((storage_contract_version = 1))
);

--
-- Name: two_factor; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.two_factor (
    id text NOT NULL,
    user_id text NOT NULL,
    secret text,
    backup_codes text,
    last_totp_step bigint,
    CONSTRAINT two_factor_last_totp_step_check CHECK (((last_totp_step IS NULL) OR (last_totp_step >= 0)))
);

--
-- Name: two_factor_replacements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.two_factor_replacements (
    id text NOT NULL,
    user_id text NOT NULL,
    session_id text NOT NULL,
    secret text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT two_factor_replacements_attempts_check CHECK (((attempts >= 0) AND (attempts <= 5))),
    CONSTRAINT two_factor_replacements_check CHECK (((expires_at > created_at) AND (expires_at <= (created_at + '00:10:00'::interval)))),
    CONSTRAINT two_factor_replacements_id_check CHECK ((id ~ '^[0-9a-f]{32}$'::text)),
    CONSTRAINT two_factor_replacements_secret_check CHECK ((((length(secret) >= 40) AND (length(secret) <= 1024)) AND (secret ~ '^[A-Za-z0-9+/]+={0,2}$'::text)))
);

--
-- Name: two_factor_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.two_factor_tokens (
    id text NOT NULL,
    user_id text NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    token_hash text NOT NULL,
    CONSTRAINT two_factor_tokens_token_hash_format_check CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text))
);

--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id text NOT NULL,
    email text NOT NULL,
    email_verified boolean DEFAULT false,
    name text,
    image text,
    is_admin boolean DEFAULT false,
    two_factor_enabled boolean DEFAULT false,
    failed_login_attempts integer DEFAULT 0,
    locked_until timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    git_name text,
    git_email text,
    enabled boolean DEFAULT true NOT NULL,
    access_reason text,
    CONSTRAINT users_access_reason_length_check CHECK (((access_reason IS NULL) OR (((char_length(access_reason) >= 1) AND (char_length(access_reason) <= 2000)) AND (access_reason ~ '[^[:space:]]'::text))))
);

--
-- Name: verifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.verifications (
    id text NOT NULL,
    identifier text NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now(),
    purpose text NOT NULL,
    token_hash text NOT NULL,
    CONSTRAINT verifications_purpose_check CHECK ((purpose = ANY (ARRAY['email_verification'::text, 'password_reset'::text]))),
    CONSTRAINT verifications_token_hash_format_check CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text))
);

--
-- Name: billing_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_events ALTER COLUMN id SET DEFAULT nextval('public.billing_events_id_seq'::regclass);

--
-- Name: accounts accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id);

--
-- Name: admin_invoice_credits admin_invoice_credits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_invoice_credits
    ADD CONSTRAINT admin_invoice_credits_pkey PRIMARY KEY (id);

--
-- Name: admin_invoice_credits admin_invoice_credits_stripe_invoice_id_credit_kind_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_invoice_credits
    ADD CONSTRAINT admin_invoice_credits_stripe_invoice_id_credit_kind_key UNIQUE (stripe_invoice_id, credit_kind);

--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);

--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);

--
-- Name: billing_catalog_plans billing_catalog_plans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_catalog_plans
    ADD CONSTRAINT billing_catalog_plans_pkey PRIMARY KEY (resource_type, plan_key);

--
-- Name: billing_catalog_prices billing_catalog_prices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_catalog_prices
    ADD CONSTRAINT billing_catalog_prices_pkey PRIMARY KEY (resource_type, plan_key, stripe_mode, price_kind);

--
-- Name: billing_catalog_settings billing_catalog_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_catalog_settings
    ADD CONSTRAINT billing_catalog_settings_pkey PRIMARY KEY (setting_key);

--
-- Name: billing_catalog_subscription_migrations billing_catalog_subscription_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_catalog_subscription_migrations
    ADD CONSTRAINT billing_catalog_subscription_migrations_pkey PRIMARY KEY (id);

--
-- Name: billing_events billing_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_events
    ADD CONSTRAINT billing_events_pkey PRIMARY KEY (id);

--
-- Name: billing_external_operations billing_external_operations_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_external_operations
    ADD CONSTRAINT billing_external_operations_idempotency_key_key UNIQUE (idempotency_key);

--
-- Name: billing_external_operations billing_external_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_external_operations
    ADD CONSTRAINT billing_external_operations_pkey PRIMARY KEY (id);

--
-- Name: confidential_storage_keys confidential_storage_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.confidential_storage_keys
    ADD CONSTRAINT confidential_storage_keys_pkey PRIMARY KEY (environment_id);

--
-- Name: data_deletion_requests data_deletion_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_deletion_requests
    ADD CONSTRAINT data_deletion_requests_pkey PRIMARY KEY (id);

--
-- Name: environment_access environment_access_environment_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_access
    ADD CONSTRAINT environment_access_environment_id_user_id_key UNIQUE (environment_id, user_id);

--
-- Name: environment_access environment_access_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_access
    ADD CONSTRAINT environment_access_pkey PRIMARY KEY (id);

--
-- Name: environment_cw_runtime_requests environment_cw_runtime_requests_mutation_lease_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_cw_runtime_requests
    ADD CONSTRAINT environment_cw_runtime_requests_mutation_lease_id_key UNIQUE (mutation_lease_id);

--
-- Name: environment_cw_runtime_requests environment_cw_runtime_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_cw_runtime_requests
    ADD CONSTRAINT environment_cw_runtime_requests_pkey PRIMARY KEY (request_id);

--
-- Name: environment_lifecycle_journal environment_lifecycle_journal_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_lifecycle_journal
    ADD CONSTRAINT environment_lifecycle_journal_pkey PRIMARY KEY (id);

--
-- Name: environment_logs environment_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_logs
    ADD CONSTRAINT environment_logs_pkey PRIMARY KEY (id);

--
-- Name: environment_operation_generation_claims environment_operation_generation__environment_id_generation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_operation_generation_claims
    ADD CONSTRAINT environment_operation_generation__environment_id_generation_key UNIQUE (environment_id, generation);

--
-- Name: environment_operation_generation_claims environment_operation_generation_claims_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_operation_generation_claims
    ADD CONSTRAINT environment_operation_generation_claims_pkey PRIMARY KEY (environment_id, workflow_run_id);

--
-- Name: environment_platform_agent_conversations environment_platform_agent_conversations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_platform_agent_conversations
    ADD CONSTRAINT environment_platform_agent_conversations_pkey PRIMARY KEY (environment_id, pod_uid, session_id);

--
-- Name: environment_platform_agent_requests environment_platform_agent_requests_mutation_lease_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_platform_agent_requests
    ADD CONSTRAINT environment_platform_agent_requests_mutation_lease_id_key UNIQUE (mutation_lease_id);

--
-- Name: environment_platform_agent_requests environment_platform_agent_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_platform_agent_requests
    ADD CONSTRAINT environment_platform_agent_requests_pkey PRIMARY KEY (request_id);

--
-- Name: environment_ports environment_ports_environment_id_label_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_ports
    ADD CONSTRAINT environment_ports_environment_id_label_key UNIQUE (environment_id, label);

--
-- Name: environment_ports environment_ports_environment_id_port_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_ports
    ADD CONSTRAINT environment_ports_environment_id_port_key UNIQUE (environment_id, port);

--
-- Name: environment_ports environment_ports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_ports
    ADD CONSTRAINT environment_ports_pkey PRIMARY KEY (id);

--
-- Name: environment_presets environment_presets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_presets
    ADD CONSTRAINT environment_presets_pkey PRIMARY KEY (id);

--
-- Name: environment_quotas environment_quotas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_quotas
    ADD CONSTRAINT environment_quotas_pkey PRIMARY KEY (org_id);

--
-- Name: environment_resize_operations environment_resize_operations_environment_request_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_resize_operations
    ADD CONSTRAINT environment_resize_operations_environment_request_key UNIQUE (environment_id, request_id);

--
-- Name: environment_resize_operations environment_resize_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_resize_operations
    ADD CONSTRAINT environment_resize_operations_pkey PRIMARY KEY (id);

--
-- Name: environment_sessions environment_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_sessions
    ADD CONSTRAINT environment_sessions_pkey PRIMARY KEY (id);

--
-- Name: environment_subscriptions environment_subscriptions_org_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_subscriptions
    ADD CONSTRAINT environment_subscriptions_org_id_key UNIQUE (org_id);

--
-- Name: environment_subscriptions environment_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_subscriptions
    ADD CONSTRAINT environment_subscriptions_pkey PRIMARY KEY (id);

--
-- Name: environment_subscriptions environment_subscriptions_stripe_subscription_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_subscriptions
    ADD CONSTRAINT environment_subscriptions_stripe_subscription_id_key UNIQUE (stripe_subscription_id);

--
-- Name: environment_usage_billing environment_usage_billing_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_usage_billing
    ADD CONSTRAINT environment_usage_billing_pkey PRIMARY KEY (org_id, billing_period_start);

--
-- Name: environment_usage_billing_tiers environment_usage_billing_tiers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_usage_billing_tiers
    ADD CONSTRAINT environment_usage_billing_tiers_pkey PRIMARY KEY (org_id, billing_period_start, runtime_tier);

--
-- Name: environments environments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_pkey PRIMARY KEY (id);

--
-- Name: jwks jwks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jwks
    ADD CONSTRAINT jwks_pkey PRIMARY KEY (id);

--
-- Name: oidc_access_tokens oidc_access_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_access_tokens
    ADD CONSTRAINT oidc_access_tokens_pkey PRIMARY KEY (token_hash);

--
-- Name: oidc_auth_requests oidc_auth_requests_code_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_auth_requests
    ADD CONSTRAINT oidc_auth_requests_code_hash_key UNIQUE (code_hash);

--
-- Name: oidc_auth_requests oidc_auth_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_auth_requests
    ADD CONSTRAINT oidc_auth_requests_pkey PRIMARY KEY (id);

--
-- Name: oidc_clients oidc_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_clients
    ADD CONSTRAINT oidc_clients_pkey PRIMARY KEY (id);

--
-- Name: oidc_device_authorizations oidc_device_authorizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_device_authorizations
    ADD CONSTRAINT oidc_device_authorizations_pkey PRIMARY KEY (device_code_hash);

--
-- Name: oidc_device_authorizations oidc_device_authorizations_user_code_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_device_authorizations
    ADD CONSTRAINT oidc_device_authorizations_user_code_hash_key UNIQUE (user_code_hash);

--
-- Name: oidc_refresh_tokens oidc_refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_refresh_tokens
    ADD CONSTRAINT oidc_refresh_tokens_pkey PRIMARY KEY (id);

--
-- Name: oidc_refresh_tokens oidc_refresh_tokens_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_refresh_tokens
    ADD CONSTRAINT oidc_refresh_tokens_token_key UNIQUE (token_hash);

--
-- Name: org_invitations org_invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_invitations
    ADD CONSTRAINT org_invitations_pkey PRIMARY KEY (id);

--
-- Name: org_invitations org_invitations_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_invitations
    ADD CONSTRAINT org_invitations_token_hash_key UNIQUE (token_hash);

--
-- Name: org_member_assignments org_member_assignments_org_member_id_assignment_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_member_assignments
    ADD CONSTRAINT org_member_assignments_org_member_id_assignment_key UNIQUE (org_member_id, assignment);

--
-- Name: org_member_assignments org_member_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_member_assignments
    ADD CONSTRAINT org_member_assignments_pkey PRIMARY KEY (id);

--
-- Name: org_members org_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_members
    ADD CONSTRAINT org_members_pkey PRIMARY KEY (id);

--
-- Name: org_subscriptions org_subscriptions_org_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_subscriptions
    ADD CONSTRAINT org_subscriptions_org_id_key UNIQUE (org_id);

--
-- Name: org_subscriptions org_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_subscriptions
    ADD CONSTRAINT org_subscriptions_pkey PRIMARY KEY (id);

--
-- Name: org_subscriptions org_subscriptions_stripe_subscription_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_subscriptions
    ADD CONSTRAINT org_subscriptions_stripe_subscription_id_key UNIQUE (stripe_subscription_id);

--
-- Name: organization_deletion_billing_phases organization_deletion_billing_phases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_deletion_billing_phases
    ADD CONSTRAINT organization_deletion_billing_phases_pkey PRIMARY KEY (operation_id);

--
-- Name: organization_deletion_billing_subscriptions organization_deletion_billing_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_deletion_billing_subscriptions
    ADD CONSTRAINT organization_deletion_billing_subscriptions_pkey PRIMARY KEY (operation_id, stripe_subscription_id);

--
-- Name: organization_deletion_operations organization_deletion_operations_org_generation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_deletion_operations
    ADD CONSTRAINT organization_deletion_operations_org_generation_key UNIQUE (organization_id, generation);

--
-- Name: organization_deletion_operations organization_deletion_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_deletion_operations
    ADD CONSTRAINT organization_deletion_operations_pkey PRIMARY KEY (id);

--
-- Name: organization_deletion_operations organization_deletion_operations_workflow_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_deletion_operations
    ADD CONSTRAINT organization_deletion_operations_workflow_id_key UNIQUE (workflow_id);

--
-- Name: organization_mutation_leases organization_mutation_leases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_mutation_leases
    ADD CONSTRAINT organization_mutation_leases_pkey PRIMARY KEY (id);

--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);

--
-- Name: organizations organizations_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_slug_key UNIQUE (slug);

--
-- Name: organizations organizations_stripe_customer_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_stripe_customer_id_key UNIQUE (stripe_customer_id);

--
-- Name: platform_access_profile_entries platform_access_profile_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_access_profile_entries
    ADD CONSTRAINT platform_access_profile_entries_pkey PRIMARY KEY (profile_id, revision, capability_slot);

--
-- Name: platform_access_profile_revisions platform_access_profile_revisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_access_profile_revisions
    ADD CONSTRAINT platform_access_profile_revisions_pkey PRIMARY KEY (profile_id, revision);

--
-- Name: platform_access_profiles platform_access_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_access_profiles
    ADD CONSTRAINT platform_access_profiles_pkey PRIMARY KEY (id);

--
-- Name: platform_credential_material platform_credential_material_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_credential_material
    ADD CONSTRAINT platform_credential_material_pkey PRIMARY KEY (credential_id);

--
-- Name: platform_credential_refresh_attempts platform_credential_refresh_attempts_attempt_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_credential_refresh_attempts
    ADD CONSTRAINT platform_credential_refresh_attempts_attempt_id_key UNIQUE (attempt_id);

--
-- Name: platform_credential_refresh_attempts platform_credential_refresh_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_credential_refresh_attempts
    ADD CONSTRAINT platform_credential_refresh_attempts_pkey PRIMARY KEY (credential_id);

--
-- Name: platform_credential_refresh_material platform_credential_refresh_material_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_credential_refresh_material
    ADD CONSTRAINT platform_credential_refresh_material_pkey PRIMARY KEY (attempt_id);

--
-- Name: platform_credentials platform_credentials_id_material_generation_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_credentials
    ADD CONSTRAINT platform_credentials_id_material_generation_key UNIQUE (id, material_generation);

--
-- Name: platform_credentials platform_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_credentials
    ADD CONSTRAINT platform_credentials_pkey PRIMARY KEY (id);

--
-- Name: platform_environment_access_bindings platform_environment_access_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_environment_access_bindings
    ADD CONSTRAINT platform_environment_access_bindings_pkey PRIMARY KEY (environment_id);

--
-- Name: preview_auth_challenges preview_auth_challenges_code_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.preview_auth_challenges
    ADD CONSTRAINT preview_auth_challenges_code_hash_key UNIQUE (code_hash);

--
-- Name: preview_auth_challenges preview_auth_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.preview_auth_challenges
    ADD CONSTRAINT preview_auth_challenges_pkey PRIMARY KEY (id);

--
-- Name: preview_browser_grants preview_browser_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.preview_browser_grants
    ADD CONSTRAINT preview_browser_grants_pkey PRIMARY KEY (token_hash);

--
-- Name: preview_browser_grants preview_browser_grants_scope_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.preview_browser_grants
    ADD CONSTRAINT preview_browser_grants_scope_key UNIQUE (session_id, organization_id, environment_id, port_id, host);

--
-- Name: rate_limit rate_limit_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rate_limit
    ADD CONSTRAINT rate_limit_key_key UNIQUE (key);

--
-- Name: rate_limit rate_limit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rate_limit
    ADD CONSTRAINT rate_limit_pkey PRIMARY KEY (id);

--
-- Name: repo_configs repo_configs_org_id_repo_url_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.repo_configs
    ADD CONSTRAINT repo_configs_org_id_repo_url_key UNIQUE (org_id, repo_url);

--
-- Name: repo_configs repo_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.repo_configs
    ADD CONSTRAINT repo_configs_pkey PRIMARY KEY (id);

--
-- Name: runtime_transport_zones runtime_transport_zones_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runtime_transport_zones
    ADD CONSTRAINT runtime_transport_zones_pkey PRIMARY KEY (name);

--
-- Name: sandbox_environment_backend sandbox_environment_backend_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_environment_backend
    ADD CONSTRAINT sandbox_environment_backend_pkey PRIMARY KEY (environment_id);

--
-- Name: sandbox_running_sessions sandbox_running_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_running_sessions
    ADD CONSTRAINT sandbox_running_sessions_pkey PRIMARY KEY (id);

--
-- Name: sandbox_ssh_host_keys sandbox_ssh_host_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_ssh_host_keys
    ADD CONSTRAINT sandbox_ssh_host_keys_pkey PRIMARY KEY (pod_uid);

--
-- Name: sandbox_template_config sandbox_template_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_template_config
    ADD CONSTRAINT sandbox_template_config_pkey PRIMARY KEY (preset_id);

--
-- Name: sandbox_workspace_bindings sandbox_workspace_bindings_environment_id_pod_uid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_workspace_bindings
    ADD CONSTRAINT sandbox_workspace_bindings_environment_id_pod_uid_key UNIQUE (environment_id, pod_uid);

--
-- Name: sandbox_workspace_bindings sandbox_workspace_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_workspace_bindings
    ADD CONSTRAINT sandbox_workspace_bindings_pkey PRIMARY KEY (pod_uid);

--
-- Name: secret_projects secret_projects_org_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_projects
    ADD CONSTRAINT secret_projects_org_id_name_key UNIQUE (org_id, name);

--
-- Name: secret_projects secret_projects_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_projects
    ADD CONSTRAINT secret_projects_pkey PRIMARY KEY (id);

--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);

--
-- Name: sessions sessions_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_token_hash_key UNIQUE (token_hash);

--
-- Name: stripe_invoices stripe_invoices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stripe_invoices
    ADD CONSTRAINT stripe_invoices_pkey PRIMARY KEY (id);

--
-- Name: stripe_invoices stripe_invoices_stripe_invoice_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stripe_invoices
    ADD CONSTRAINT stripe_invoices_stripe_invoice_id_key UNIQUE (stripe_invoice_id);

--
-- Name: stripe_webhook_events stripe_webhook_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stripe_webhook_events
    ADD CONSTRAINT stripe_webhook_events_pkey PRIMARY KEY (id);

--
-- Name: tenant_secret_deks tenant_secret_deks_identity_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_secret_deks
    ADD CONSTRAINT tenant_secret_deks_identity_key UNIQUE (dek_id, scope, scope_id);

--
-- Name: tenant_secret_deks tenant_secret_deks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_secret_deks
    ADD CONSTRAINT tenant_secret_deks_pkey PRIMARY KEY (dek_id);

--
-- Name: tenant_secret_deks tenant_secret_deks_scope_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_secret_deks
    ADD CONSTRAINT tenant_secret_deks_scope_key UNIQUE (scope, scope_id);

--
-- Name: tenant_secret_kek_canary tenant_secret_kek_canary_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_secret_kek_canary
    ADD CONSTRAINT tenant_secret_kek_canary_pkey PRIMARY KEY (singleton);

--
-- Name: tenant_secrets tenant_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_secrets
    ADD CONSTRAINT tenant_secrets_pkey PRIMARY KEY (path, key);

--
-- Name: two_factor two_factor_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.two_factor
    ADD CONSTRAINT two_factor_pkey PRIMARY KEY (id);

--
-- Name: two_factor_replacements two_factor_replacements_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.two_factor_replacements
    ADD CONSTRAINT two_factor_replacements_pkey PRIMARY KEY (id);

--
-- Name: two_factor_replacements two_factor_replacements_user_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.two_factor_replacements
    ADD CONSTRAINT two_factor_replacements_user_key UNIQUE (user_id);

--
-- Name: two_factor_tokens two_factor_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.two_factor_tokens
    ADD CONSTRAINT two_factor_tokens_pkey PRIMARY KEY (id);

--
-- Name: two_factor_tokens two_factor_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.two_factor_tokens
    ADD CONSTRAINT two_factor_tokens_token_hash_key UNIQUE (token_hash);

--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);

--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

--
-- Name: verifications verifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verifications
    ADD CONSTRAINT verifications_pkey PRIMARY KEY (id);

--
-- Name: verifications verifications_purpose_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verifications
    ADD CONSTRAINT verifications_purpose_token_hash_key UNIQUE (purpose, token_hash);

--
-- Name: audit_logs_action_timestamp_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_logs_action_timestamp_idx ON public.audit_logs USING btree (action, "timestamp");

--
-- Name: audit_logs_user_timestamp_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_logs_user_timestamp_idx ON public.audit_logs USING btree (user_id, "timestamp");

--
-- Name: billing_catalog_subscription_migrations_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX billing_catalog_subscription_migrations_created_at_idx ON public.billing_catalog_subscription_migrations USING btree (created_at DESC);

--
-- Name: billing_external_operations_org_period_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX billing_external_operations_org_period_idx ON public.billing_external_operations USING btree (organization_id, billing_period_start, created_at DESC);

--
-- Name: confidential_storage_keys_state_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX confidential_storage_keys_state_idx ON public.confidential_storage_keys USING btree (state, updated_at);

--
-- Name: environment_cw_runtime_one_unresolved_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX environment_cw_runtime_one_unresolved_owner ON public.environment_cw_runtime_requests USING btree (environment_id) WHERE (phase = ANY (ARRAY['admitted'::text, 'issued'::text, 'acknowledged'::text, 'unknown'::text]));

--
-- Name: environment_cw_runtime_organization_requests; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX environment_cw_runtime_organization_requests ON public.environment_cw_runtime_requests USING btree (organization_id, environment_id, admitted_at);

--
-- Name: environment_platform_agent_request_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX environment_platform_agent_request_scope ON public.environment_platform_agent_requests USING btree (organization_id, environment_id, request_id);

--
-- Name: environment_resize_operations_one_active_per_environment; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX environment_resize_operations_one_active_per_environment ON public.environment_resize_operations USING btree (environment_id) WHERE (state = ANY (ARRAY['pending'::text, 'applying'::text, 'restarting'::text]));

--
-- Name: environment_resize_operations_org_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX environment_resize_operations_org_created_idx ON public.environment_resize_operations USING btree (org_id, created_at DESC);

--
-- Name: environments_external_cleanup_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX environments_external_cleanup_pending_idx ON public.environments USING btree (state_changed_at, id) WHERE ((desired_state = 'destroyed'::text) AND (external_cleanup_completed_at IS NULL));

--
-- Name: idx_admin_invoice_credits_org_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_admin_invoice_credits_org_created ON public.admin_invoice_credits USING btree (org_id, created_at DESC);

--
-- Name: idx_api_keys_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_prefix ON public.api_keys USING btree (key_prefix);

--
-- Name: idx_api_keys_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_user ON public.api_keys USING btree (user_id);

--
-- Name: idx_billing_events_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_billing_events_org ON public.billing_events USING btree (org_id, created_at DESC);

--
-- Name: idx_billing_events_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_billing_events_type ON public.billing_events USING btree (event_type, created_at DESC);

--
-- Name: idx_env_access_env; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_env_access_env ON public.environment_access USING btree (environment_id);

--
-- Name: idx_env_access_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_env_access_user ON public.environment_access USING btree (user_id);

--
-- Name: idx_env_lifecycle_journal_env_checkpoint_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_env_lifecycle_journal_env_checkpoint_created_at ON public.environment_lifecycle_journal USING btree (environment_id, checkpoint, created_at DESC) WHERE (checkpoint IS NOT NULL);

--
-- Name: idx_env_lifecycle_journal_env_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_env_lifecycle_journal_env_created_at ON public.environment_lifecycle_journal USING btree (environment_id, created_at DESC);

--
-- Name: idx_env_lifecycle_journal_env_kind_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_env_lifecycle_journal_env_kind_created_at ON public.environment_lifecycle_journal USING btree (environment_id, kind, created_at DESC);

--
-- Name: idx_environment_logs_env_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_environment_logs_env_id ON public.environment_logs USING btree (environment_id, created_at);

--
-- Name: idx_environment_logs_env_phase_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_environment_logs_env_phase_created_at ON public.environment_logs USING btree (environment_id, phase, created_at DESC);

--
-- Name: idx_environment_ports_env; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_environment_ports_env ON public.environment_ports USING btree (environment_id);

--
-- Name: idx_environment_presets_auto_image_org; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_environment_presets_auto_image_org ON public.environment_presets USING btree (org_id, auto_image_ref) WHERE (auto_image_ref IS NOT NULL);

--
-- Name: idx_environment_presets_official_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_environment_presets_official_slug ON public.environment_presets USING btree (slug) WHERE (official AND (org_id IS NULL) AND (slug IS NOT NULL));

--
-- Name: idx_environments_deletion_grace; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_environments_deletion_grace ON public.environments USING btree (deletion_grace_until) WHERE ((deletion_grace_until IS NOT NULL) AND (state <> ALL (ARRAY['destroyed'::text, 'destroying'::text])));

--
-- Name: idx_environments_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_environments_org ON public.environments USING btree (org_id);

--
-- Name: idx_environments_reconcile; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_environments_reconcile ON public.environments USING btree (state, state_changed_at) WHERE (state <> ALL (ARRAY['destroyed'::text, 'build_failed'::text]));

--
-- Name: idx_environments_sync; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_environments_sync ON public.environments USING btree (desired_state) WHERE (state <> desired_state);

--
-- Name: idx_environments_ttl; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_environments_ttl ON public.environments USING btree (shutdown_at) WHERE ((shutdown_at IS NOT NULL) AND (state <> ALL (ARRAY['destroyed'::text, 'destroying'::text])));

--
-- Name: idx_environments_type_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_environments_type_state ON public.environments USING btree (type, state);

--
-- Name: idx_presets_slug_org; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_presets_slug_org ON public.environment_presets USING btree (slug, org_id) WHERE (slug IS NOT NULL);

--
-- Name: idx_sandbox_backend_claim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sandbox_backend_claim ON public.sandbox_environment_backend USING btree (namespace, sandbox_claim_name);

--
-- Name: idx_sandbox_backend_claim_uid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sandbox_backend_claim_uid ON public.sandbox_environment_backend USING btree (namespace, sandbox_claim_uid);

--
-- Name: idx_sandbox_backend_pod_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sandbox_backend_pod_name ON public.sandbox_environment_backend USING btree (pod_name) WHERE (pod_name IS NOT NULL);

--
-- Name: idx_sandbox_running_sessions_env_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sandbox_running_sessions_env_started ON public.sandbox_running_sessions USING btree (environment_id, started_at);

--
-- Name: idx_sandbox_running_sessions_open; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sandbox_running_sessions_open ON public.sandbox_running_sessions USING btree (organization_id, runtime_namespace) WHERE (ended_at IS NULL);

--
-- Name: idx_sandbox_running_sessions_open_uid; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_sandbox_running_sessions_open_uid ON public.sandbox_running_sessions USING btree (runtime_type, runtime_uid) WHERE (ended_at IS NULL);

--
-- Name: idx_sandbox_running_sessions_org_period; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sandbox_running_sessions_org_period ON public.sandbox_running_sessions USING btree (organization_id, started_at, ended_at);

--
-- Name: idx_secret_projects_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secret_projects_org ON public.secret_projects USING btree (org_id);

--
-- Name: oidc_access_tokens_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oidc_access_tokens_user_id_idx ON public.oidc_access_tokens USING btree (user_id);

--
-- Name: oidc_auth_requests_code_hash_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oidc_auth_requests_code_hash_idx ON public.oidc_auth_requests USING btree (code_hash) WHERE (code_hash IS NOT NULL);

--
-- Name: oidc_auth_requests_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oidc_auth_requests_expires_idx ON public.oidc_auth_requests USING btree (expires_at);

--
-- Name: oidc_auth_requests_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oidc_auth_requests_user_id_idx ON public.oidc_auth_requests USING btree (user_id);

--
-- Name: oidc_device_authorizations_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oidc_device_authorizations_expires_at_idx ON public.oidc_device_authorizations USING btree (expires_at);

--
-- Name: oidc_device_authorizations_user_code_hash_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oidc_device_authorizations_user_code_hash_idx ON public.oidc_device_authorizations USING btree (user_code_hash);

--
-- Name: oidc_device_authorizations_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oidc_device_authorizations_user_id_idx ON public.oidc_device_authorizations USING btree (user_id);

--
-- Name: oidc_refresh_tokens_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oidc_refresh_tokens_user_id_idx ON public.oidc_refresh_tokens USING btree (user_id);

--
-- Name: org_members_org_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX org_members_org_user_idx ON public.org_members USING btree (org_id, user_id);

--
-- Name: organization_deletion_billing_generation_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX organization_deletion_billing_generation_idx ON public.organization_deletion_billing_phases USING btree (organization_id, generation);

--
-- Name: organization_deletion_billing_subscriptions_org_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organization_deletion_billing_subscriptions_org_idx ON public.organization_deletion_billing_subscriptions USING btree (organization_id, generation, state, stripe_subscription_id);

--
-- Name: organization_deletion_operations_organization_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organization_deletion_operations_organization_idx ON public.organization_deletion_operations USING btree (organization_id, generation DESC);

--
-- Name: organization_deletion_operations_pending_start_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organization_deletion_operations_pending_start_idx ON public.organization_deletion_operations USING btree (created_at, id) WHERE (state = 'pending_start'::text);

--
-- Name: organization_mutation_leases_organization_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organization_mutation_leases_organization_idx ON public.organization_mutation_leases USING btree (organization_id, admitted_at, id);

--
-- Name: organization_mutation_leases_unresolved_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX organization_mutation_leases_unresolved_idx ON public.organization_mutation_leases USING btree (organization_id, mutation_class, deadline_at, admitted_at, id) WHERE (state = ANY (ARRAY['active'::text, 'resolution_required'::text]));

--
-- Name: platform_access_profile_entries_credential_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX platform_access_profile_entries_credential_idx ON public.platform_access_profile_entries USING btree (credential_id, profile_id, revision);

--
-- Name: platform_access_profiles_organization_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX platform_access_profiles_organization_name_key ON public.platform_access_profiles USING btree (organization_id, lower(name)) WHERE (organization_id IS NOT NULL);

--
-- Name: platform_access_profiles_user_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX platform_access_profiles_user_name_key ON public.platform_access_profiles USING btree (user_id, lower(name)) WHERE (user_id IS NOT NULL);

--
-- Name: platform_credentials_organization_display_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX platform_credentials_organization_display_name_key ON public.platform_credentials USING btree (organization_id, lower(display_name)) WHERE (organization_id IS NOT NULL);

--
-- Name: platform_credentials_user_display_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX platform_credentials_user_display_name_key ON public.platform_credentials USING btree (user_id, lower(display_name)) WHERE (user_id IS NOT NULL);

--
-- Name: platform_credentials_user_github_singleton_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX platform_credentials_user_github_singleton_key ON public.platform_credentials USING btree (user_id) WHERE ((user_id IS NOT NULL) AND (provider = 'github'::text) AND (authentication_kind = 'oauth'::text) AND (status = 'active'::text));

--
-- Name: platform_environment_access_bindings_profile_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX platform_environment_access_bindings_profile_idx ON public.platform_environment_access_bindings USING btree (profile_id, profile_revision);

--
-- Name: preview_auth_challenges_client; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX preview_auth_challenges_client ON public.preview_auth_challenges USING btree (client_hash, created_at);

--
-- Name: preview_auth_challenges_environment; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX preview_auth_challenges_environment ON public.preview_auth_challenges USING btree (environment_id);

--
-- Name: preview_auth_challenges_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX preview_auth_challenges_expiry ON public.preview_auth_challenges USING btree (expires_at);

--
-- Name: preview_auth_challenges_organization; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX preview_auth_challenges_organization ON public.preview_auth_challenges USING btree (organization_id);

--
-- Name: preview_auth_challenges_port; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX preview_auth_challenges_port ON public.preview_auth_challenges USING btree (port_id);

--
-- Name: preview_auth_challenges_session; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX preview_auth_challenges_session ON public.preview_auth_challenges USING btree (session_id);

--
-- Name: preview_browser_grants_environment; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX preview_browser_grants_environment ON public.preview_browser_grants USING btree (environment_id);

--
-- Name: preview_browser_grants_organization; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX preview_browser_grants_organization ON public.preview_browser_grants USING btree (organization_id);

--
-- Name: preview_browser_grants_port; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX preview_browser_grants_port ON public.preview_browser_grants USING btree (port_id);

--
-- Name: preview_browser_grants_session; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX preview_browser_grants_session ON public.preview_browser_grants USING btree (session_id);

--
-- Name: runtime_transport_zones_enabled_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX runtime_transport_zones_enabled_idx ON public.runtime_transport_zones USING btree (enabled);

--
-- Name: runtime_transport_zones_region_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX runtime_transport_zones_region_idx ON public.runtime_transport_zones USING btree (runtime_region);

--
-- Name: sandbox_ssh_host_keys_environment_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sandbox_ssh_host_keys_environment_idx ON public.sandbox_ssh_host_keys USING btree (environment_id);

--
-- Name: sandbox_workspace_bindings_live_environment; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sandbox_workspace_bindings_live_environment ON public.sandbox_workspace_bindings USING btree (environment_id) WHERE (released_at IS NULL);

--
-- Name: sessions_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_user_id_idx ON public.sessions USING btree (user_id);

--
-- Name: tenant_secrets_dek_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tenant_secrets_dek_id_idx ON public.tenant_secrets USING btree (dek_id);

--
-- Name: two_factor_replacements_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX two_factor_replacements_expiry ON public.two_factor_replacements USING btree (expires_at);

--
-- Name: two_factor_replacements_session; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX two_factor_replacements_session ON public.two_factor_replacements USING btree (session_id);

--
-- Name: two_factor_tokens_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX two_factor_tokens_user_id_idx ON public.two_factor_tokens USING btree (user_id);

--
-- Name: two_factor_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX two_factor_user_id_idx ON public.two_factor USING btree (user_id);

--
-- Name: users_access_review_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_access_review_idx ON public.users USING btree (enabled, email_verified, created_at DESC) WHERE (access_reason IS NOT NULL);

--
-- Name: api_keys codewire_require_enabled_api_key; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_require_enabled_api_key BEFORE INSERT ON public.api_keys FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_api_key();

--
-- Name: api_keys codewire_require_enabled_api_key_reactivation; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_require_enabled_api_key_reactivation BEFORE UPDATE OF disabled_at ON public.api_keys FOR EACH ROW WHEN (((old.disabled_at IS NOT NULL) AND (new.disabled_at IS NULL))) EXECUTE FUNCTION public.codewire_require_enabled_api_key();

--
-- Name: oidc_access_tokens codewire_require_enabled_oidc_access_token; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_require_enabled_oidc_access_token BEFORE INSERT ON public.oidc_access_tokens FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

--
-- Name: oidc_auth_requests codewire_require_enabled_oidc_auth_request; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_require_enabled_oidc_auth_request BEFORE INSERT ON public.oidc_auth_requests FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

--
-- Name: oidc_auth_requests codewire_require_enabled_oidc_auth_request_subject; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_require_enabled_oidc_auth_request_subject BEFORE UPDATE OF user_id ON public.oidc_auth_requests FOR EACH ROW WHEN (((old.user_id IS DISTINCT FROM new.user_id) AND (new.user_id IS NOT NULL))) EXECUTE FUNCTION public.codewire_require_enabled_account();

--
-- Name: oidc_device_authorizations codewire_require_enabled_oidc_device_authorization; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_require_enabled_oidc_device_authorization BEFORE INSERT ON public.oidc_device_authorizations FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

--
-- Name: oidc_device_authorizations codewire_require_enabled_oidc_device_authorization_subject; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_require_enabled_oidc_device_authorization_subject BEFORE UPDATE OF user_id ON public.oidc_device_authorizations FOR EACH ROW WHEN (((old.user_id IS DISTINCT FROM new.user_id) AND (new.user_id IS NOT NULL))) EXECUTE FUNCTION public.codewire_require_enabled_account();

--
-- Name: oidc_refresh_tokens codewire_require_enabled_oidc_refresh_token; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_require_enabled_oidc_refresh_token BEFORE INSERT ON public.oidc_refresh_tokens FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

--
-- Name: sessions codewire_require_enabled_session; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_require_enabled_session BEFORE INSERT ON public.sessions FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

--
-- Name: two_factor codewire_require_enabled_two_factor; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_require_enabled_two_factor BEFORE INSERT ON public.two_factor FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

--
-- Name: two_factor_replacements codewire_require_enabled_two_factor_replacement; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_require_enabled_two_factor_replacement BEFORE INSERT ON public.two_factor_replacements FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

--
-- Name: two_factor_tokens codewire_require_enabled_two_factor_token; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_require_enabled_two_factor_token BEFORE INSERT ON public.two_factor_tokens FOR EACH ROW EXECUTE FUNCTION public.codewire_require_enabled_account();

--
-- Name: users codewire_revoke_user_capabilities_on_disable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_revoke_user_capabilities_on_disable AFTER UPDATE OF enabled ON public.users FOR EACH ROW WHEN ((old.enabled AND (NOT new.enabled))) EXECUTE FUNCTION public.codewire_revoke_user_capabilities();

--
-- Name: sandbox_workspace_bindings codewire_workspace_binding_cascade_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_workspace_binding_cascade_only BEFORE DELETE ON public.sandbox_workspace_bindings FOR EACH ROW EXECUTE FUNCTION public.codewire_workspace_binding_immutable();

--
-- Name: sandbox_workspace_bindings codewire_workspace_binding_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER codewire_workspace_binding_immutable BEFORE UPDATE ON public.sandbox_workspace_bindings FOR EACH ROW EXECUTE FUNCTION public.codewire_workspace_binding_immutable();

--
-- Name: confidential_storage_keys confidential_storage_manifest_immutability; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER confidential_storage_manifest_immutability BEFORE UPDATE OF sha256_fingerprint, manifest_uri, volume_id, volume_version, manifest_schema_version, device_size_bytes, luks_uuid, protection_profile, protection_profile_version, backing_claim_name, manifest_sha256_fingerprint ON public.confidential_storage_keys FOR EACH ROW EXECUTE FUNCTION public.enforce_confidential_storage_manifest_immutability();

--
-- Name: environment_cw_runtime_requests environment_cw_runtime_request_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER environment_cw_runtime_request_immutable BEFORE DELETE OR UPDATE ON public.environment_cw_runtime_requests FOR EACH ROW EXECUTE FUNCTION public.codewire_cw_runtime_request_immutable();

--
-- Name: environment_platform_agent_conversations environment_platform_agent_conversation_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER environment_platform_agent_conversation_immutable BEFORE DELETE OR UPDATE ON public.environment_platform_agent_conversations FOR EACH ROW EXECUTE FUNCTION public.environment_platform_agent_conversation_guard();

--
-- Name: environment_platform_agent_requests environment_platform_agent_request_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER environment_platform_agent_request_immutable BEFORE DELETE OR UPDATE ON public.environment_platform_agent_requests FOR EACH ROW EXECUTE FUNCTION public.environment_platform_agent_request_guard();

--
-- Name: accounts accounts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: admin_invoice_credits admin_invoice_credits_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_invoice_credits
    ADD CONSTRAINT admin_invoice_credits_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

--
-- Name: api_keys api_keys_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

--
-- Name: api_keys api_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

--
-- Name: audit_logs audit_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;

--
-- Name: billing_catalog_subscription_migrations billing_catalog_subscription_migrations_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_catalog_subscription_migrations
    ADD CONSTRAINT billing_catalog_subscription_migrations_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;

--
-- Name: billing_external_operations billing_external_operations_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_external_operations
    ADD CONSTRAINT billing_external_operations_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

--
-- Name: confidential_storage_keys confidential_storage_keys_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.confidential_storage_keys
    ADD CONSTRAINT confidential_storage_keys_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: data_deletion_requests data_deletion_requests_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.data_deletion_requests
    ADD CONSTRAINT data_deletion_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);

--
-- Name: environment_access environment_access_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_access
    ADD CONSTRAINT environment_access_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: environment_access environment_access_granted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_access
    ADD CONSTRAINT environment_access_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES public.users(id);

--
-- Name: environment_access environment_access_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_access
    ADD CONSTRAINT environment_access_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: environment_lifecycle_journal environment_lifecycle_journal_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_lifecycle_journal
    ADD CONSTRAINT environment_lifecycle_journal_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: environment_logs environment_logs_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_logs
    ADD CONSTRAINT environment_logs_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: environment_operation_generation_claims environment_operation_generation_claims_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_operation_generation_claims
    ADD CONSTRAINT environment_operation_generation_claims_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: environment_ports environment_ports_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_ports
    ADD CONSTRAINT environment_ports_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: environment_presets environment_presets_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_presets
    ADD CONSTRAINT environment_presets_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

--
-- Name: environment_quotas environment_quotas_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_quotas
    ADD CONSTRAINT environment_quotas_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

--
-- Name: environment_resize_operations environment_resize_operations_environment_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_resize_operations
    ADD CONSTRAINT environment_resize_operations_environment_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: environment_resize_operations environment_resize_operations_org_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_resize_operations
    ADD CONSTRAINT environment_resize_operations_org_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

--
-- Name: environment_sessions environment_sessions_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_sessions
    ADD CONSTRAINT environment_sessions_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: environment_subscriptions environment_subscriptions_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_subscriptions
    ADD CONSTRAINT environment_subscriptions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

--
-- Name: environment_usage_billing environment_usage_billing_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_usage_billing
    ADD CONSTRAINT environment_usage_billing_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

--
-- Name: environment_usage_billing_tiers environment_usage_billing_tiers_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment_usage_billing_tiers
    ADD CONSTRAINT environment_usage_billing_tiers_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

--
-- Name: environments environments_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);

--
-- Name: environments environments_deletion_requested_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_deletion_requested_by_fkey FOREIGN KEY (deletion_requested_by) REFERENCES public.users(id) ON DELETE SET NULL;

--
-- Name: environments environments_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

--
-- Name: environments environments_preset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environments
    ADD CONSTRAINT environments_preset_id_fkey FOREIGN KEY (preset_id) REFERENCES public.environment_presets(id);

--
-- Name: oidc_auth_requests oidc_auth_requests_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_auth_requests
    ADD CONSTRAINT oidc_auth_requests_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oidc_clients(id) ON DELETE CASCADE;

--
-- Name: oidc_auth_requests oidc_auth_requests_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_auth_requests
    ADD CONSTRAINT oidc_auth_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: oidc_device_authorizations oidc_device_authorizations_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_device_authorizations
    ADD CONSTRAINT oidc_device_authorizations_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oidc_clients(id) ON DELETE CASCADE;

--
-- Name: oidc_device_authorizations oidc_device_authorizations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_device_authorizations
    ADD CONSTRAINT oidc_device_authorizations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: oidc_refresh_tokens oidc_refresh_tokens_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_refresh_tokens
    ADD CONSTRAINT oidc_refresh_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oidc_clients(id) ON DELETE CASCADE;

--
-- Name: oidc_refresh_tokens oidc_refresh_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_refresh_tokens
    ADD CONSTRAINT oidc_refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: org_invitations org_invitations_invited_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_invitations
    ADD CONSTRAINT org_invitations_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: org_invitations org_invitations_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_invitations
    ADD CONSTRAINT org_invitations_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

--
-- Name: org_member_assignments org_member_assignments_granted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_member_assignments
    ADD CONSTRAINT org_member_assignments_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES public.users(id);

--
-- Name: org_member_assignments org_member_assignments_org_member_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_member_assignments
    ADD CONSTRAINT org_member_assignments_org_member_id_fkey FOREIGN KEY (org_member_id) REFERENCES public.org_members(id) ON DELETE CASCADE;

--
-- Name: org_members org_members_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_members
    ADD CONSTRAINT org_members_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

--
-- Name: org_members org_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_members
    ADD CONSTRAINT org_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: org_subscriptions org_subscriptions_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.org_subscriptions
    ADD CONSTRAINT org_subscriptions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

--
-- Name: organization_deletion_billing_phases organization_deletion_billing_operation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_deletion_billing_phases
    ADD CONSTRAINT organization_deletion_billing_operation_fkey FOREIGN KEY (operation_id) REFERENCES public.organization_deletion_operations(id) ON DELETE CASCADE;

--
-- Name: organization_deletion_billing_subscriptions organization_deletion_billing_subscriptions_operation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_deletion_billing_subscriptions
    ADD CONSTRAINT organization_deletion_billing_subscriptions_operation_fkey FOREIGN KEY (operation_id) REFERENCES public.organization_deletion_operations(id) ON DELETE CASCADE;

--
-- Name: organizations organizations_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: organizations organizations_deletion_requested_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_deletion_requested_by_fkey FOREIGN KEY (deletion_requested_by) REFERENCES public.users(id) ON DELETE SET NULL;

--
-- Name: platform_access_profile_entries platform_access_profile_entries_profile_id_revision_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_access_profile_entries
    ADD CONSTRAINT platform_access_profile_entries_profile_id_revision_fkey FOREIGN KEY (profile_id, revision) REFERENCES public.platform_access_profile_revisions(profile_id, revision) ON DELETE CASCADE;

--
-- Name: platform_access_profile_revisions platform_access_profile_revisions_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_access_profile_revisions
    ADD CONSTRAINT platform_access_profile_revisions_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.platform_access_profiles(id) ON DELETE CASCADE;

--
-- Name: platform_access_profiles platform_access_profiles_current_revision_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_access_profiles
    ADD CONSTRAINT platform_access_profiles_current_revision_fkey FOREIGN KEY (id, current_revision) REFERENCES public.platform_access_profile_revisions(profile_id, revision) DEFERRABLE INITIALLY DEFERRED;

--
-- Name: platform_access_profiles platform_access_profiles_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_access_profiles
    ADD CONSTRAINT platform_access_profiles_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

--
-- Name: platform_access_profiles platform_access_profiles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_access_profiles
    ADD CONSTRAINT platform_access_profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: platform_credential_material platform_credential_material_generation_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_credential_material
    ADD CONSTRAINT platform_credential_material_generation_fkey FOREIGN KEY (credential_id, material_generation) REFERENCES public.platform_credentials(id, material_generation) ON DELETE CASCADE;

--
-- Name: platform_credential_refresh_attempts platform_credential_refresh_attempts_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_credential_refresh_attempts
    ADD CONSTRAINT platform_credential_refresh_attempts_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.platform_credentials(id) ON DELETE CASCADE;

--
-- Name: platform_credential_refresh_material platform_credential_refresh_material_attempt_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_credential_refresh_material
    ADD CONSTRAINT platform_credential_refresh_material_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES public.platform_credential_refresh_attempts(attempt_id) ON DELETE CASCADE;

--
-- Name: platform_credentials platform_credentials_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_credentials
    ADD CONSTRAINT platform_credentials_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

--
-- Name: platform_credentials platform_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_credentials
    ADD CONSTRAINT platform_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: platform_environment_access_bindings platform_environment_access_bi_personal_owner_confirmed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_environment_access_bindings
    ADD CONSTRAINT platform_environment_access_bi_personal_owner_confirmed_by_fkey FOREIGN KEY (personal_owner_confirmed_by) REFERENCES public.users(id) ON DELETE SET NULL;

--
-- Name: platform_environment_access_bindings platform_environment_access_bi_profile_id_profile_revision_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_environment_access_bindings
    ADD CONSTRAINT platform_environment_access_bi_profile_id_profile_revision_fkey FOREIGN KEY (profile_id, profile_revision) REFERENCES public.platform_access_profile_revisions(profile_id, revision) ON DELETE RESTRICT;

--
-- Name: platform_environment_access_bindings platform_environment_access_bindings_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_environment_access_bindings
    ADD CONSTRAINT platform_environment_access_bindings_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: preview_auth_challenges preview_auth_challenges_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.preview_auth_challenges
    ADD CONSTRAINT preview_auth_challenges_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: preview_auth_challenges preview_auth_challenges_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.preview_auth_challenges
    ADD CONSTRAINT preview_auth_challenges_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

--
-- Name: preview_auth_challenges preview_auth_challenges_port_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.preview_auth_challenges
    ADD CONSTRAINT preview_auth_challenges_port_id_fkey FOREIGN KEY (port_id) REFERENCES public.environment_ports(id) ON DELETE CASCADE;

--
-- Name: preview_auth_challenges preview_auth_challenges_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.preview_auth_challenges
    ADD CONSTRAINT preview_auth_challenges_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.sessions(id) ON DELETE CASCADE;

--
-- Name: preview_browser_grants preview_browser_grants_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.preview_browser_grants
    ADD CONSTRAINT preview_browser_grants_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: preview_browser_grants preview_browser_grants_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.preview_browser_grants
    ADD CONSTRAINT preview_browser_grants_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

--
-- Name: preview_browser_grants preview_browser_grants_port_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.preview_browser_grants
    ADD CONSTRAINT preview_browser_grants_port_id_fkey FOREIGN KEY (port_id) REFERENCES public.environment_ports(id) ON DELETE CASCADE;

--
-- Name: preview_browser_grants preview_browser_grants_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.preview_browser_grants
    ADD CONSTRAINT preview_browser_grants_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.sessions(id) ON DELETE CASCADE;

--
-- Name: repo_configs repo_configs_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.repo_configs
    ADD CONSTRAINT repo_configs_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

--
-- Name: sandbox_environment_backend sandbox_environment_backend_binding_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_environment_backend
    ADD CONSTRAINT sandbox_environment_backend_binding_fkey FOREIGN KEY (environment_id, pod_uid) REFERENCES public.sandbox_workspace_bindings(environment_id, pod_uid);

--
-- Name: sandbox_environment_backend sandbox_environment_backend_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_environment_backend
    ADD CONSTRAINT sandbox_environment_backend_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: sandbox_running_sessions sandbox_running_sessions_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_running_sessions
    ADD CONSTRAINT sandbox_running_sessions_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: sandbox_running_sessions sandbox_running_sessions_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_running_sessions
    ADD CONSTRAINT sandbox_running_sessions_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

--
-- Name: sandbox_ssh_host_keys sandbox_ssh_host_keys_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_ssh_host_keys
    ADD CONSTRAINT sandbox_ssh_host_keys_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: sandbox_template_config sandbox_template_config_preset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_template_config
    ADD CONSTRAINT sandbox_template_config_preset_id_fkey FOREIGN KEY (preset_id) REFERENCES public.environment_presets(id) ON DELETE CASCADE;

--
-- Name: sandbox_workspace_bindings sandbox_workspace_bindings_environment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sandbox_workspace_bindings
    ADD CONSTRAINT sandbox_workspace_bindings_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE;

--
-- Name: secret_projects secret_projects_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_projects
    ADD CONSTRAINT secret_projects_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);

--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: stripe_invoices stripe_invoices_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stripe_invoices
    ADD CONSTRAINT stripe_invoices_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

--
-- Name: tenant_secrets tenant_secrets_dek_scope_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_secrets
    ADD CONSTRAINT tenant_secrets_dek_scope_fkey FOREIGN KEY (dek_id, scope, scope_id) REFERENCES public.tenant_secret_deks(dek_id, scope, scope_id);

--
-- Name: two_factor_replacements two_factor_replacements_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.two_factor_replacements
    ADD CONSTRAINT two_factor_replacements_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.sessions(id) ON DELETE CASCADE;

--
-- Name: two_factor_replacements two_factor_replacements_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.two_factor_replacements
    ADD CONSTRAINT two_factor_replacements_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: two_factor_tokens two_factor_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.two_factor_tokens
    ADD CONSTRAINT two_factor_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: two_factor two_factor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.two_factor
    ADD CONSTRAINT two_factor_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

--
-- Name: FUNCTION codewire_authenticate_credential_session(token_digest text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_authenticate_credential_session(token_digest text) FROM PUBLIC;

--
-- Name: FUNCTION codewire_cw_runtime_request_immutable(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_cw_runtime_request_immutable() FROM PUBLIC;

--
-- Name: FUNCTION codewire_lock_credential_session_authority(original_session_id text, token_digest text, original_user_id text, original_expires_at timestamp with time zone); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_lock_credential_session_authority(original_session_id text, token_digest text, original_user_id text, original_expires_at timestamp with time zone) FROM PUBLIC;

--
-- Name: FUNCTION codewire_lock_oauth_bearer_authority(token_digest text, original_user_id text, original_client_id text, original_expires_at timestamp with time zone); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_lock_oauth_bearer_authority(token_digest text, original_user_id text, original_client_id text, original_expires_at timestamp with time zone) FROM PUBLIC;

--
-- Name: FUNCTION codewire_platform_lock_credential(credential_id text, user_scope text, organization_scope text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_platform_lock_credential(credential_id text, user_scope text, organization_scope text) FROM PUBLIC;

--
-- Name: FUNCTION codewire_platform_lock_environment(environment_id text, user_id text, organization_id text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_platform_lock_environment(environment_id text, user_id text, organization_id text) FROM PUBLIC;

--
-- Name: FUNCTION codewire_platform_lock_owner(owner_kind text, owner_id text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_platform_lock_owner(owner_kind text, owner_id text) FROM PUBLIC;

--
-- Name: FUNCTION codewire_platform_lock_owner_source_authority(user_id text, organization_id text, project_id text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_platform_lock_owner_source_authority(user_id text, organization_id text, project_id text) FROM PUBLIC;

--
-- Name: FUNCTION codewire_platform_lock_profile(profile_id text, user_scope text, organization_scope text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_platform_lock_profile(profile_id text, user_scope text, organization_scope text) FROM PUBLIC;

--
-- Name: FUNCTION codewire_platform_lock_projection_authority(environment_id text, creator_id text, organization_id text, project_id text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_platform_lock_projection_authority(environment_id text, creator_id text, organization_id text, project_id text) FROM PUBLIC;

--
-- Name: FUNCTION codewire_platform_projection_metadata(environment_id text); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_platform_projection_metadata(environment_id text) FROM PUBLIC;

--
-- Name: FUNCTION codewire_require_enabled_account(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_require_enabled_account() FROM PUBLIC;

--
-- Name: FUNCTION codewire_require_enabled_api_key(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_require_enabled_api_key() FROM PUBLIC;

--
-- Name: FUNCTION codewire_revoke_user_capabilities(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_revoke_user_capabilities() FROM PUBLIC;

--
-- Name: FUNCTION codewire_workspace_binding_immutable(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.codewire_workspace_binding_immutable() FROM PUBLIC;

--
-- Name: FUNCTION environment_platform_agent_conversation_guard(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.environment_platform_agent_conversation_guard() FROM PUBLIC;

--
-- Name: FUNCTION environment_platform_agent_request_guard(); Type: ACL; Schema: public; Owner: -
--

REVOKE ALL ON FUNCTION public.environment_platform_agent_request_guard() FROM PUBLIC;

--
--

--
-- Reference rows
--

INSERT INTO public.billing_catalog_plans (resource_type, plan_key, display_name, price_cents, included_devs, max_concurrent_ws, max_team_members, storage_gb, is_contact_us, is_admin_only, included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours, cpu_overage_cents, mem_overage_cents, disk_overage_cents, created_at, updated_at, archived_at) VALUES ('org', 'starter', 'Starter', 4900, 1, 5, 1, 50, false, false, 0, 0, 0, 0, 0, 0, '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_plans (resource_type, plan_key, display_name, price_cents, included_devs, max_concurrent_ws, max_team_members, storage_gb, is_contact_us, is_admin_only, included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours, cpu_overage_cents, mem_overage_cents, disk_overage_cents, created_at, updated_at, archived_at) VALUES ('org', 'pro', 'Pro', 19900, 10, 25, 15, 250, false, false, 0, 0, 0, 0, 0, 0, '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_plans (resource_type, plan_key, display_name, price_cents, included_devs, max_concurrent_ws, max_team_members, storage_gb, is_contact_us, is_admin_only, included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours, cpu_overage_cents, mem_overage_cents, disk_overage_cents, created_at, updated_at, archived_at) VALUES ('org', 'team', 'Team', 49900, 30, 100, -1, 1000, false, false, 0, 0, 0, 0, 0, 0, '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_plans (resource_type, plan_key, display_name, price_cents, included_devs, max_concurrent_ws, max_team_members, storage_gb, is_contact_us, is_admin_only, included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours, cpu_overage_cents, mem_overage_cents, disk_overage_cents, created_at, updated_at, archived_at) VALUES ('org', 'enterprise', 'Enterprise', -1, -1, -1, -1, -1, true, false, 0, 0, 0, 0, 0, 0, '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_plans (resource_type, plan_key, display_name, price_cents, included_devs, max_concurrent_ws, max_team_members, storage_gb, is_contact_us, is_admin_only, included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours, cpu_overage_cents, mem_overage_cents, disk_overage_cents, created_at, updated_at, archived_at) VALUES ('sandbox', 'starter', 'Starter', 4900, 0, 10, 1, 0, false, false, 200, 400, 50000, 5.04, 1.62, 0.01, '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_plans (resource_type, plan_key, display_name, price_cents, included_devs, max_concurrent_ws, max_team_members, storage_gb, is_contact_us, is_admin_only, included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours, cpu_overage_cents, mem_overage_cents, disk_overage_cents, created_at, updated_at, archived_at) VALUES ('sandbox', 'pro', 'Pro', 19900, 0, 50, 15, 0, false, false, 1000, 2000, 200000, 5.04, 1.62, 0.01, '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_plans (resource_type, plan_key, display_name, price_cents, included_devs, max_concurrent_ws, max_team_members, storage_gb, is_contact_us, is_admin_only, included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours, cpu_overage_cents, mem_overage_cents, disk_overage_cents, created_at, updated_at, archived_at) VALUES ('sandbox', 'team', 'Team', 49900, 0, 200, -1, 0, false, false, 3000, 6000, 500000, 5.04, 1.62, 0.01, '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_plans (resource_type, plan_key, display_name, price_cents, included_devs, max_concurrent_ws, max_team_members, storage_gb, is_contact_us, is_admin_only, included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours, cpu_overage_cents, mem_overage_cents, disk_overage_cents, created_at, updated_at, archived_at) VALUES ('sandbox', 'enterprise', 'Enterprise', -1, 0, -1, -1, 0, true, false, 0, 0, 0, 0, 0, 0, '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_plans (resource_type, plan_key, display_name, price_cents, included_devs, max_concurrent_ws, max_team_members, storage_gb, is_contact_us, is_admin_only, included_cpu_hours, included_mem_gb_hours, included_disk_gb_hours, cpu_overage_cents, mem_overage_cents, disk_overage_cents, created_at, updated_at, archived_at) VALUES ('sandbox', 'unlimited', 'Unlimited', 0, 0, -1, -1, 0, false, true, 0, 0, 0, 5.04, 1.62, 0.01, '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);

INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('org', 'starter', 'test', 'subscription', 'price_1T2AZTIezUhNxMWsk0Yw8SDc', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('org', 'pro', 'test', 'subscription', 'price_1T2AZkIezUhNxMWsFJYUOFI6', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('org', 'team', 'test', 'subscription', 'price_1T2Aa1IezUhNxMWs4o4LUr5u', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('org', 'starter', 'live', 'subscription', 'price_1T2AyyEeXpf2Q0A6LwPKBvM6', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('org', 'pro', 'live', 'subscription', 'price_1T2AzOEeXpf2Q0A6eaihCdpC', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('org', 'team', 'live', 'subscription', 'price_1T2AzoEeXpf2Q0A6TUqO1saR', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('org', 'seat', 'test', 'seat_addon', 'price_1T2AdJIezUhNxMWsiLcJ0zyH', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('org', 'seat', 'live', 'seat_addon', 'price_1T2B02EeXpf2Q0A60GxTU2Y1', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('sandbox', 'starter', 'test', 'subscription', 'price_TODO_TEST_SANDBOX_STARTER', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('sandbox', 'pro', 'test', 'subscription', 'price_TODO_TEST_SANDBOX_PRO', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('sandbox', 'team', 'test', 'subscription', 'price_TODO_TEST_SANDBOX_TEAM', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('sandbox', 'unlimited', 'test', 'subscription', 'price_TODO_TEST_SANDBOX_UNLIMITED', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('sandbox', 'starter', 'live', 'subscription', 'price_TODO_LIVE_SANDBOX_STARTER', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('sandbox', 'pro', 'live', 'subscription', 'price_TODO_LIVE_SANDBOX_PRO', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('sandbox', 'team', 'live', 'subscription', 'price_TODO_LIVE_SANDBOX_TEAM', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);
INSERT INTO public.billing_catalog_prices (resource_type, plan_key, stripe_mode, price_kind, stripe_price_id, created_at, updated_at, archived_at) VALUES ('sandbox', 'unlimited', 'live', 'subscription', 'price_TODO_LIVE_SANDBOX_UNLIMITED', '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174', NULL);

INSERT INTO public.billing_catalog_settings (setting_key, int_value, created_at, updated_at) VALUES ('trial_days', 14, '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174');
INSERT INTO public.billing_catalog_settings (setting_key, int_value, created_at, updated_at) VALUES ('extra_seat_cents', 1800, '2026-10-17 13:54:25.07174', '2026-10-17 13:54:25.07174');
