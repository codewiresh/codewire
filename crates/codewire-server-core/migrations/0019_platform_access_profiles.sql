-- Access profiles select explicit typed capabilities. Revisions are immutable:
-- an environment remains bound to its selected revision until explicitly rebound.
CREATE TABLE public.platform_access_profiles (
    id text PRIMARY KEY CHECK (octet_length(id) BETWEEN 1 AND 128),
    user_id text REFERENCES public.users(id) ON DELETE CASCADE,
    organization_id text REFERENCES public.organizations(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 128),
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT platform_access_profiles_owner_check CHECK (
        (user_id IS NOT NULL) <> (organization_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX platform_access_profiles_user_name_key
    ON public.platform_access_profiles (user_id, lower(name))
    WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX platform_access_profiles_organization_name_key
    ON public.platform_access_profiles (organization_id, lower(name))
    WHERE organization_id IS NOT NULL;

CREATE TABLE public.platform_access_profile_revisions (
    profile_id text NOT NULL REFERENCES public.platform_access_profiles(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (profile_id, revision)
);

ALTER TABLE public.platform_access_profiles
    ADD CONSTRAINT platform_access_profiles_current_revision_fkey
    FOREIGN KEY (id, current_revision)
    REFERENCES public.platform_access_profile_revisions(profile_id, revision)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE public.platform_access_profile_entries (
    profile_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    capability_slot text NOT NULL CHECK (octet_length(capability_slot) BETWEEN 1 AND 128),
    credential_id text NOT NULL CHECK (octet_length(credential_id) BETWEEN 1 AND 128),
    PRIMARY KEY (profile_id, revision, capability_slot),
    FOREIGN KEY (profile_id, revision)
        REFERENCES public.platform_access_profile_revisions(profile_id, revision) ON DELETE CASCADE
);

-- The store prevents deletion of credentials referenced by a current profile
-- or any bound revision under the credential row lock. An unbound historical
-- revision may retain a non-secret identity after credential deletion, as in
-- local placement; an unconditional credential FK would forbid that behavior.
CREATE INDEX platform_access_profile_entries_credential_idx
    ON public.platform_access_profile_entries (credential_id, profile_id, revision);

CREATE TABLE public.platform_environment_access_bindings (
    environment_id text PRIMARY KEY REFERENCES public.environments(id) ON DELETE CASCADE,
    profile_id text NOT NULL,
    profile_revision bigint NOT NULL CHECK (profile_revision > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (profile_id, profile_revision)
        REFERENCES public.platform_access_profile_revisions(profile_id, revision) ON DELETE RESTRICT
);

CREATE INDEX platform_environment_access_bindings_profile_idx
    ON public.platform_environment_access_bindings (profile_id, profile_revision);
