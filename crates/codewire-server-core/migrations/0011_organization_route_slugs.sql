-- Organization slugs now occupy the first path segment of authenticated
-- dashboard URLs. Fail before mutation if existing data would collide with a
-- public/system route or violate the canonical URL-safe shape.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.organizations
        WHERE length(slug) NOT BETWEEN 3 AND 48
           OR slug !~ '^[a-z0-9]+(-[a-z0-9]+)*$'
           OR slug = ANY (ARRAY[
               'accept-invite', 'admin', 'api', 'assets', 'auth', 'connect',
               'dashboard', 'device', 'docs', 'forgot-password', 'grpc',
               'healthz', 'login', 'oauth', 'organizations', 'preview',
               'reset-password', 'settings', 'setup-2fa', 'signup',
               'ssh-proxy', 'terminal', 'two-factor', 'verify-email'
           ])
    ) THEN
        RAISE EXCEPTION
            'organization slug data conflicts with canonical dashboard routes';
    END IF;
END
$$;

ALTER TABLE public.organizations
    ADD CONSTRAINT organizations_route_slug_check CHECK (
        length(slug) BETWEEN 3 AND 48
        AND slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'
        AND slug <> ALL (ARRAY[
            'accept-invite', 'admin', 'api', 'assets', 'auth', 'connect',
            'dashboard', 'device', 'docs', 'forgot-password', 'grpc',
            'healthz', 'login', 'oauth', 'organizations', 'preview',
            'reset-password', 'settings', 'setup-2fa', 'signup',
            'ssh-proxy', 'terminal', 'two-factor', 'verify-email'
        ])
    );

-- Rollback boundary (execute only after reverting root-level organization
-- routes):
-- ALTER TABLE public.organizations DROP CONSTRAINT organizations_route_slug_check;
