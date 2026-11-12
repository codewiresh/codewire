-- /privacy and /terms are public pages, the privacy policy and the terms of
-- service, so neither can be an organization's route slug. The services
-- refuse both through RESERVED_ORGANIZATION_SLUGS
-- (crates/codewire-server-core/src/organization_slug.rs); this keeps the
-- database's check the same list.
--
-- Replacing the check validates every existing organization. If one already
-- uses either slug, the migration fails inside its transaction and changes
-- nothing; rename that organization first. No row is changed.
ALTER TABLE public.organizations DROP CONSTRAINT organizations_route_slug_check;

ALTER TABLE public.organizations ADD CONSTRAINT organizations_route_slug_check CHECK ((((length(slug) >= 3) AND (length(slug) <= 48)) AND (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'::text) AND (slug <> ALL (ARRAY['accept-invite'::text, 'admin'::text, 'api'::text, 'assets'::text, 'auth'::text, 'connect'::text, 'dashboard'::text, 'device'::text, 'docs'::text, 'forgot-password'::text, 'grpc'::text, 'healthz'::text, 'login'::text, 'oauth'::text, 'organizations'::text, 'preview'::text, 'privacy'::text, 'reset-password'::text, 'settings'::text, 'setup-2fa'::text, 'signup'::text, 'ssh-proxy'::text, 'terminal'::text, 'terms'::text, 'two-factor'::text, 'verify-email'::text]))));
