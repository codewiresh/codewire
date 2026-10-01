-- Preview access is a separate, narrowly scoped browser capability. No raw
-- browser-session token, authorization code or preview grant is stored here.
CREATE TABLE public.preview_auth_challenges (
    id text PRIMARY KEY,
    nonce_hash text NOT NULL CHECK (nonce_hash ~ '^[0-9a-f]{64}$'),
    client_hash text NOT NULL CHECK (client_hash ~ '^[0-9a-f]{64}$'),
    organization_id text NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    environment_id text NOT NULL REFERENCES public.environments(id) ON DELETE CASCADE,
    port_id text NOT NULL REFERENCES public.environment_ports(id) ON DELETE CASCADE,
    host text NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
    return_path text NOT NULL CHECK (length(return_path) BETWEEN 1 AND 4096 AND left(return_path, 1) = '/'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    session_id text REFERENCES public.sessions(id) ON DELETE CASCADE,
    code_hash text UNIQUE CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    code_expires_at timestamptz,
    consumed_at timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
    CHECK (consumed_at IS NULL OR (code_hash IS NOT NULL AND consumed_at <= expires_at)),
    CHECK ((session_id IS NULL AND code_hash IS NULL AND code_expires_at IS NULL)
        OR (session_id IS NOT NULL AND code_hash IS NOT NULL AND code_expires_at IS NOT NULL
            AND code_expires_at <= expires_at))
);
CREATE INDEX preview_auth_challenges_expiry ON public.preview_auth_challenges(expires_at);
CREATE INDEX preview_auth_challenges_client ON public.preview_auth_challenges(client_hash, created_at);
CREATE INDEX preview_auth_challenges_session ON public.preview_auth_challenges(session_id);
CREATE INDEX preview_auth_challenges_organization ON public.preview_auth_challenges(organization_id);
CREATE INDEX preview_auth_challenges_environment ON public.preview_auth_challenges(environment_id);
CREATE INDEX preview_auth_challenges_port ON public.preview_auth_challenges(port_id);

CREATE TABLE public.preview_browser_grants (
    token_hash text PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    session_id text NOT NULL REFERENCES public.sessions(id) ON DELETE CASCADE,
    organization_id text NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    environment_id text NOT NULL REFERENCES public.environments(id) ON DELETE CASCADE,
    port_id text NOT NULL REFERENCES public.environment_ports(id) ON DELETE CASCADE,
    host text NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT preview_browser_grants_scope_key
        UNIQUE (session_id, organization_id, environment_id, port_id, host)
);
CREATE INDEX preview_browser_grants_session ON public.preview_browser_grants(session_id);
CREATE INDEX preview_browser_grants_organization ON public.preview_browser_grants(organization_id);
CREATE INDEX preview_browser_grants_environment ON public.preview_browser_grants(environment_id);
CREATE INDEX preview_browser_grants_port ON public.preview_browser_grants(port_id);
