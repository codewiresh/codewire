-- Membership revocations (#3586): leaving or losing an organization, or its
-- deletion starting, ends the streams already admitted into its environments
-- (docs/dev/AUTH-POLICY.md, "Account access revocation"; private-docs
-- designs/stream-revocation.md, "Next", and cw-security's rulings of
-- 2026-11-20).
--
-- Two kinds join the log, each naming the organization in its own column:
-- - `membership`: a user left the organization or was removed from it. Any
--   delete of an `org_members` row writes it, whatever removed the row: a
--   removal, leaving, an account deletion or the end of an organization's
--   deletion.
-- - `organization`: the organization's deletion started. One row names the
--   organization alone and ends every member's streams into it.
--
-- `credential_id` and `user_id` stay NOT NULL, as 0035 made them, so no
-- existing reader changes: both kinds repeat the organization in
-- `credential_id`, and `organization` names no user (an empty `user_id`,
-- which matches no user). The check says which columns each kind sets.
--
-- 0035's writer is left as it is; the org-aware writer is a new function
-- that prunes and wakes listeners the same way. The triggers run as the role
-- doing the DML, and that writer grants no EXECUTE to PUBLIC, so removing a
-- member or starting a deletion must run as the owner, as the services do
-- (#5166). A restricted role doing either would fail, and a migration test
-- shows it.
--
-- Compatible: a new nullable column, a wider check, new functions and
-- triggers. Older code reads the rows it knows and logs the new kinds as
-- unreadable, ending nothing.
-- Rollback: drop the two triggers and the three functions, delete the new
-- kinds' rows, restore the 0035 check, and drop the index and the column.

ALTER TABLE public.credential_revocations
    ADD COLUMN org_id text;

ALTER TABLE public.credential_revocations
    DROP CONSTRAINT credential_revocations_kind_check;

ALTER TABLE public.credential_revocations
    ADD CONSTRAINT credential_revocations_kind_check CHECK (
        kind IN (
            'user', 'session', 'oauth_token', 'oauth_grant', 'api_key',
            'membership', 'organization'
        )
    );

ALTER TABLE public.credential_revocations
    ADD CONSTRAINT credential_revocations_kind_columns_check CHECK (
        CASE kind
            WHEN 'membership' THEN
                org_id IS NOT NULL AND credential_id = org_id AND user_id <> ''
            WHEN 'organization' THEN
                org_id IS NOT NULL AND credential_id = org_id AND user_id = ''
            ELSE org_id IS NULL
        END
    );

CREATE INDEX credential_revocations_org_idx
    ON public.credential_revocations (org_id);

CREATE FUNCTION public.codewire_record_organization_revocation(
    revoked_kind text, revoked_org_id text, revoked_user_id text
) RETURNS void
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    DELETE FROM public.credential_revocations
     WHERE revoked_at < pg_catalog.now() - interval '1 hour';
    INSERT INTO public.credential_revocations (kind, credential_id, user_id, org_id)
    VALUES (revoked_kind, revoked_org_id, revoked_user_id, revoked_org_id);
    PERFORM pg_catalog.pg_notify('credential_revocations', '');
END;
$$;

CREATE FUNCTION public.codewire_revoke_membership_streams() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    PERFORM public.codewire_record_organization_revocation('membership', OLD.org_id, OLD.user_id);
    RETURN NULL;
END;
$$;

CREATE FUNCTION public.codewire_revoke_organization_streams() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    PERFORM public.codewire_record_organization_revocation('organization', NEW.id, '');
    RETURN NULL;
END;
$$;

CREATE TRIGGER org_members_revoke_streams_on_delete
    AFTER DELETE ON public.org_members
    FOR EACH ROW
    EXECUTE FUNCTION public.codewire_revoke_membership_streams();

CREATE TRIGGER organizations_revoke_streams_on_deleting
    AFTER UPDATE OF deletion_state ON public.organizations
    FOR EACH ROW
    WHEN (NEW.deletion_state = 'deleting' AND OLD.deletion_state IS DISTINCT FROM 'deleting')
    EXECUTE FUNCTION public.codewire_revoke_organization_streams();

REVOKE ALL ON FUNCTION public.codewire_record_organization_revocation(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.codewire_revoke_membership_streams() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.codewire_revoke_organization_streams() FROM PUBLIC;
