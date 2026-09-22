-- GitHub is one account-level connection. Profiles retain only a boolean
-- capability selection and never retain the connection's credential ID.

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

ALTER TABLE public.platform_access_profile_revisions
    ADD COLUMN include_github boolean NOT NULL DEFAULT false;

-- Every historical revision that selected GitHub keeps that selection. The
-- credential ID is intentionally discarded: runtime resolves the current
-- user-owned singleton and rechecks its active provider access.
UPDATE public.platform_access_profile_revisions AS revision
   SET include_github = true
 WHERE EXISTS (
    SELECT 1
      FROM public.platform_access_profile_entries AS entry
     WHERE entry.profile_id = revision.profile_id
       AND entry.revision = revision.revision
       AND entry.capability_slot = 'github'
);

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
