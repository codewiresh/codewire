-- A hosted environment's membership in one hosted Codewire Mesh network.
--
-- The attachment is recorded once, at create, by the creating user. It never
-- moves to another network. Its status is what the environment's daemon last
-- reported for the Pod named in status_pod_uid; a report for an earlier Pod
-- reads as pending.
CREATE TABLE public.environment_mesh_attachments (
    environment_id text NOT NULL,
    org_id text NOT NULL,
    network_id text NOT NULL,
    node_name text NOT NULL,
    attached_by_user_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    failure text DEFAULT ''::text NOT NULL,
    status_pod_uid text,
    status_changed_at timestamp with time zone,
    CONSTRAINT environment_mesh_attachments_pkey PRIMARY KEY (environment_id),
    CONSTRAINT environment_mesh_attachments_environment_fkey FOREIGN KEY (environment_id)
        REFERENCES public.environments(id) ON DELETE CASCADE,
    CONSTRAINT environment_mesh_attachments_network_id_check
        CHECK ((network_id ~ '^[A-Za-z0-9_-]{1,128}$'::text)),
    CONSTRAINT environment_mesh_attachments_node_name_check
        CHECK ((node_name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$'::text)),
    CONSTRAINT environment_mesh_attachments_status_check
        CHECK ((status = ANY (ARRAY['pending'::text, 'attached'::text, 'failed'::text, 'revoked'::text]))),
    CONSTRAINT environment_mesh_attachments_failure_check
        CHECK (((status = 'failed'::text) AND (failure = ANY (ARRAY['mesh_unreachable'::text, 'network_not_found'::text, 'not_a_member'::text, 'node_name_taken'::text, 'refused'::text])))
            OR ((status <> 'failed'::text) AND (failure = ''::text))),
    CONSTRAINT environment_mesh_attachments_status_pod_check
        CHECK (((status = 'pending'::text) AND (status_pod_uid IS NULL))
            OR ((status_pod_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'::text) AND (status_changed_at IS NOT NULL)))
);

CREATE INDEX environment_mesh_attachments_network_idx
    ON public.environment_mesh_attachments USING btree (org_id, network_id);

-- One-use Mesh enrollment codes issued to a bound workspace Pod. Only the
-- SHA-256 of a code is stored. A code admits exactly the Pod and operation
-- generation it was issued for, once, before expires_at.
CREATE TABLE public.environment_mesh_enrollments (
    code_sha256 text NOT NULL,
    environment_id text NOT NULL,
    pod_uid text NOT NULL,
    operation_generation bigint NOT NULL,
    org_id text NOT NULL,
    network_id text NOT NULL,
    node_name text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    CONSTRAINT environment_mesh_enrollments_pkey PRIMARY KEY (code_sha256),
    CONSTRAINT environment_mesh_enrollments_attachment_fkey FOREIGN KEY (environment_id)
        REFERENCES public.environment_mesh_attachments(environment_id) ON DELETE CASCADE,
    CONSTRAINT environment_mesh_enrollments_code_sha256_check
        CHECK ((code_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT environment_mesh_enrollments_pod_uid_check
        CHECK ((pod_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'::text)),
    CONSTRAINT environment_mesh_enrollments_operation_generation_check
        CHECK ((operation_generation > 0)),
    CONSTRAINT environment_mesh_enrollments_lifetime_check
        CHECK (((expires_at > issued_at) AND (expires_at <= (issued_at + '00:01:00'::interval)))),
    CONSTRAINT environment_mesh_enrollments_consumed_check
        CHECK (((consumed_at IS NULL) OR (consumed_at <= expires_at)))
);

CREATE INDEX environment_mesh_enrollments_environment_idx
    ON public.environment_mesh_enrollments USING btree (environment_id, expires_at);
