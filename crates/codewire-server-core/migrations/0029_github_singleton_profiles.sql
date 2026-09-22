-- GitHub is one account-level connection. Every personal profile includes it,
-- so profiles never retain the connection's credential ID.

-- Fail before rewriting any profile if the existing data does not have an
-- unambiguous active GitHub singleton for each user. This is deliberately not
-- a silent "winner" selection.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM public.platform_credentials AS credential
         WHERE credential.user_id IS NOT NULL
           AND credential.provider = 'github'
           AND credential.authentication_kind = 'oauth'
           AND credential.status = 'active'
         GROUP BY credential.user_id
        HAVING count(*) <> 1
    ) THEN
        RAISE EXCEPTION 'multiple active GitHub credentials for one user'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

-- Every personal profile includes the owner's one GitHub connection, resolved
-- at launch. A pinned GitHub credential ID is discarded; no revision changes.
DELETE FROM public.platform_access_profile_entries
 WHERE capability_slot = 'github';

ALTER TABLE public.platform_access_profile_entries
    ADD CONSTRAINT platform_access_profile_entries_slot_check
    CHECK (capability_slot <> 'github');

-- Obsolete non-active GitHub OAuth rows no longer carry a profile reference.
-- Their protected material is removed by the existing credential cascade.
DELETE FROM public.platform_credentials
 WHERE provider = 'github'
   AND authentication_kind = 'oauth'
   AND status <> 'active';

CREATE UNIQUE INDEX platform_credentials_user_github_singleton_key
    ON public.platform_credentials (user_id)
    WHERE user_id IS NOT NULL
      AND provider = 'github'
      AND authentication_kind = 'oauth'
      AND status = 'active';
