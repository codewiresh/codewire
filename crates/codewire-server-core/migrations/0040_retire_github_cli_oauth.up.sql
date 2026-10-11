-- Native GitHub App device login (#2488) replaces gh CLI enrollment. A GitHub
-- OAuth row cannot tell a gh CLI token from a Codewire App token, and the
-- platform can refresh neither as the App. Every GitHub OAuth connection is
-- removed; its protected material and refresh attempts cascade (0018, 0020).
-- No profile holds a GitHub credential ID (0029). Owners connect GitHub again.
-- Removed provider tokens stay valid at GitHub until they expire or are
-- revoked there.
DELETE FROM public.platform_credentials
 WHERE provider = 'github'
   AND authentication_kind = 'oauth';
