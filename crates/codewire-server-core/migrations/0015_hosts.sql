-- Hosts (#3609, slice 1): computers that users enroll to provide VMs.
--
-- A host belongs to one organization and one owner, the user who enrolled
-- it. It is identified by its id, which never changes; its name is unique
-- among the organization's hosts that are not revoked, so a revoked host's
-- name can be reused while its record stays for the audit. The host's
-- Ed25519 public key (32 bytes) is how the host authenticates itself; the
-- private key never leaves the computer. A key belongs to one host record
-- ever, revoked or not.
--
-- Enrolling grants nothing. `provide` is the owner's separate opt-in, with
-- limits: at least a maximum VM count; vCPU, memory and disk caps are
-- optional. Only the owner may place environments on a host unless they
-- grant it to named members (host_grants) or to the whole organization
-- (organization_grant). A grant never follows from membership alone.
--
-- last_seen_at is written by the host session: a host unheard for 45
-- seconds is offline. revoked_at is set by the owner or an organization
-- admin and is final for that record.
--
-- Deleting the owner's account deletes their hosts; deleting the
-- organization deletes its hosts. Grants go with their host or grantee.
--
-- Compatible: the tables are new, and older code reads nothing from them.
-- Rollback drops both tables and their indexes, which forgets every host.

CREATE TABLE public.hosts (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    org_id text NOT NULL,
    owner_user_id text NOT NULL,
    name text NOT NULL,
    platform text NOT NULL,
    capability_version integer NOT NULL,
    public_key bytea NOT NULL,
    provide boolean DEFAULT false NOT NULL,
    max_vms integer,
    max_vcpus integer,
    max_memory_mib bigint,
    max_disk_gib bigint,
    organization_grant boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoked_by text,
    CONSTRAINT hosts_pkey PRIMARY KEY (id),
    CONSTRAINT hosts_org_id_fkey
        FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE,
    CONSTRAINT hosts_owner_user_id_fkey
        FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT hosts_revoked_by_fkey
        FOREIGN KEY (revoked_by) REFERENCES public.users(id) ON DELETE SET NULL,
    -- A DNS label, so a command line can carry it (`--on host:NAME`).
    CONSTRAINT hosts_name_check
        CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT hosts_platform_check
        CHECK (platform = ANY (ARRAY['linux-x86_64-kvm'::text, 'darwin-arm64-vz'::text])),
    CONSTRAINT hosts_capability_version_check CHECK (capability_version >= 1),
    CONSTRAINT hosts_public_key_check CHECK (octet_length(public_key) = 32),
    CONSTRAINT hosts_public_key_key UNIQUE (public_key),
    CONSTRAINT hosts_limits_check CHECK (
        (max_vms IS NULL OR max_vms BETWEEN 1 AND 1024)
        AND (max_vcpus IS NULL OR max_vcpus BETWEEN 1 AND 4096)
        AND (max_memory_mib IS NULL OR max_memory_mib BETWEEN 256 AND 67108864)
        AND (max_disk_gib IS NULL OR max_disk_gib BETWEEN 1 AND 1048576)
    ),
    -- Providing needs at least a VM count.
    CONSTRAINT hosts_provide_needs_max_vms_check CHECK (NOT provide OR max_vms IS NOT NULL),
    CONSTRAINT hosts_revoked_by_needs_revoked_at_check
        CHECK (revoked_by IS NULL OR revoked_at IS NOT NULL)
);

-- One live name per organization.
CREATE UNIQUE INDEX hosts_org_name_key
    ON public.hosts USING btree (org_id, name)
    WHERE (revoked_at IS NULL);

-- An organization's list, and the account-deletion cascade.
CREATE INDEX hosts_org_id_idx ON public.hosts USING btree (org_id, created_at, id);
CREATE INDEX hosts_owner_user_id_idx ON public.hosts USING btree (owner_user_id);

CREATE TABLE public.host_grants (
    host_id text NOT NULL,
    user_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT host_grants_pkey PRIMARY KEY (host_id, user_id),
    CONSTRAINT host_grants_host_id_fkey
        FOREIGN KEY (host_id) REFERENCES public.hosts(id) ON DELETE CASCADE,
    CONSTRAINT host_grants_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
);

CREATE INDEX host_grants_user_id_idx ON public.host_grants USING btree (user_id);
