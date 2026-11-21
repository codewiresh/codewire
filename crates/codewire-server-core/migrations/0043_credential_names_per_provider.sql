-- Credential names are unique per owner and provider (#4928;
-- docs/dev/SECRETS-AND-CREDENTIALS.md, "Credential names"): a Claude sign-in
-- and a Codex sign-in may both be named after the same account, while two
-- credentials of one provider still may not share a name, ignoring case.
--
-- The per-provider indexes are created before the per-owner ones are dropped,
-- in this one transaction, so uniqueness never lapses. They only relax the
-- rule: every existing row already satisfies them.
--
-- Compatible: older code inserts and renames as before; a duplicate within a
-- provider is still refused with 23505. Older code resolving a bare name that
-- two providers now share would pick one, so the name lookups that take a
-- provider ship with this migration.
-- Rollback: recreate the old indexes, then drop these:
--   CREATE UNIQUE INDEX platform_credentials_user_display_name_key
--       ON public.platform_credentials (user_id, lower(display_name))
--       WHERE user_id IS NOT NULL;
--   CREATE UNIQUE INDEX platform_credentials_organization_display_name_key
--       ON public.platform_credentials (organization_id, lower(display_name))
--       WHERE organization_id IS NOT NULL;
--   DROP INDEX public.platform_credentials_user_provider_display_name_key;
--   DROP INDEX public.platform_credentials_organization_provider_display_name_key;
-- It fails once two providers' credentials of one owner share a name: rename
-- one of them first.

CREATE UNIQUE INDEX platform_credentials_user_provider_display_name_key
    ON public.platform_credentials (user_id, provider, lower(display_name))
    WHERE user_id IS NOT NULL;

CREATE UNIQUE INDEX platform_credentials_organization_provider_display_name_key
    ON public.platform_credentials (organization_id, provider, lower(display_name))
    WHERE organization_id IS NOT NULL;

DROP INDEX public.platform_credentials_user_display_name_key;
DROP INDEX public.platform_credentials_organization_display_name_key;
