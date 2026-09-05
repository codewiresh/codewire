-- ProjectSpec is the sole persisted environment-intent contract. This is a
-- deliberate pre-launch clean break: no existing row is translated, copied,
-- or accepted through a compatibility shape. The same empty-state boundary
-- retires the raw per-environment auth token, account login-key registry,
-- generated workspace SSH key, generic Git-password, and platform GitHub
-- OAuth credential products.
LOCK TABLE
    public.environment_presets,
    public.environments,
    public.repo_configs,
    public.tenant_secrets,
    public.user_login_keys,
    public.user_ssh_keys,
    public.user_git_credentials,
    public.github_oauth_states,
    public.user_github_tokens
IN ACCESS EXCLUSIVE MODE;

DO $preflight$
BEGIN
    IF EXISTS (SELECT 1 FROM public.environment_presets) THEN
        RAISE EXCEPTION
            'canonical ProjectSpec cutover requires environment_presets to be empty';
    END IF;

    IF EXISTS (SELECT 1 FROM public.environments) THEN
        RAISE EXCEPTION
            'canonical ProjectSpec cutover requires environments to be empty';
    END IF;

    IF EXISTS (SELECT 1 FROM public.repo_configs) THEN
        RAISE EXCEPTION
            'canonical ProjectSpec cutover requires repo_configs to be empty';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.tenant_secrets
        WHERE length(key) NOT BETWEEN 1 AND 255
           OR key !~ '^[A-Za-z_][A-Za-z0-9_]*$'
    ) THEN
        RAISE EXCEPTION
            'canonical workload-secret key cutover requires all tenant_secrets keys to be canonical';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.tenant_secrets
        WHERE scope = 'user'
          AND path = '/users/' || scope_id
          AND (
              key = 'SSH_PRIVATE_KEY'
              OR left(key, 10) = 'GIT_TOKEN_'
          )
    ) THEN
        RAISE EXCEPTION
            'credential product cutover requires legacy user credential secrets to be absent';
    END IF;

    IF EXISTS (SELECT 1 FROM public.user_login_keys) THEN
        RAISE EXCEPTION
            'credential product cutover requires user_login_keys to be empty';
    END IF;

    IF EXISTS (SELECT 1 FROM public.user_ssh_keys) THEN
        RAISE EXCEPTION
            'credential product cutover requires user_ssh_keys to be empty';
    END IF;

    IF EXISTS (SELECT 1 FROM public.user_git_credentials) THEN
        RAISE EXCEPTION
            'credential product cutover requires user_git_credentials to be empty';
    END IF;

    IF EXISTS (SELECT 1 FROM public.github_oauth_states) THEN
        RAISE EXCEPTION
            'credential product cutover requires github_oauth_states to be empty';
    END IF;

    IF EXISTS (SELECT 1 FROM public.user_github_tokens) THEN
        RAISE EXCEPTION
            'credential product cutover requires user_github_tokens to be empty';
    END IF;
END
$preflight$;

DROP TABLE public.user_login_keys;
DROP TABLE public.user_ssh_keys;
DROP TABLE public.user_git_credentials;
DROP TABLE public.github_oauth_states;
DROP TABLE public.user_github_tokens;

ALTER TABLE public.tenant_secrets
    DROP CONSTRAINT tenant_secrets_key_check,
    ADD COLUMN storage_contract_version smallint NOT NULL DEFAULT 1,
    ADD CONSTRAINT tenant_secrets_key_check CHECK (
        length(key) BETWEEN 1 AND 255
        AND key ~ '^[A-Za-z_][A-Za-z0-9_]*$'
    );

ALTER TABLE public.tenant_secrets
    ALTER COLUMN storage_contract_version SET DEFAULT 0,
    ADD CONSTRAINT tenant_secrets_storage_contract_version_check CHECK (
        storage_contract_version = 1
    );

ALTER TABLE public.environment_presets
    DROP CONSTRAINT environment_presets_default_secret_project_id_fkey,
    ALTER COLUMN official SET NOT NULL,
    DROP COLUMN default_cpu_millicores,
    DROP COLUMN default_memory_mb,
    DROP COLUMN default_disk_gb,
    DROP COLUMN default_setup_config,
    DROP COLUMN default_secret_project_id,
    ADD COLUMN project_spec jsonb NOT NULL,
    ADD COLUMN auto_image_ref text,
    ADD CONSTRAINT environment_presets_auto_image_ref_nonempty
        CHECK (auto_image_ref IS NULL OR auto_image_ref <> ''),
    ADD CONSTRAINT environment_presets_auto_image_matches_project_spec
        CHECK (auto_image_ref IS NULL OR project_spec ->> 'image' = auto_image_ref),
    ADD CONSTRAINT environment_presets_scope_consistent
        CHECK (official = (org_id IS NULL));

CREATE UNIQUE INDEX idx_environment_presets_official_slug
    ON public.environment_presets (slug)
    WHERE official AND org_id IS NULL AND slug IS NOT NULL;

CREATE UNIQUE INDEX idx_environment_presets_auto_image_org
    ON public.environment_presets (org_id, auto_image_ref)
    WHERE auto_image_ref IS NOT NULL;

ALTER TABLE public.environments
    DROP CONSTRAINT environments_secret_project_id_fkey,
    DROP COLUMN auth_token,
    DROP COLUMN setup_config,
    DROP COLUMN secret_project_id,
    ADD COLUMN project_spec jsonb NOT NULL;

ALTER TABLE public.repo_configs
    DROP CONSTRAINT repo_configs_preset_id_fkey,
    DROP COLUMN preset_id,
    DROP COLUMN setup_config,
    ADD COLUMN project_spec jsonb NOT NULL;
