-- Each user's default personal credential profile (#3550).
--
-- A user with any personal profile has exactly one default: the store makes
-- a user's first profile the default, changes it only to another of their own
-- profiles, and refuses to delete it. The composite foreign key admits only
-- the user's own personal profile and, with no ON DELETE action, refuses the
-- deletion of a default profile here too. The default goes with its user.
ALTER TABLE ONLY public.platform_access_profiles
    ADD CONSTRAINT platform_access_profiles_id_user_id_key UNIQUE (id, user_id);

CREATE TABLE public.platform_access_profile_defaults (
    user_id text NOT NULL,
    profile_id text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_access_profile_defaults_pkey PRIMARY KEY (user_id),
    CONSTRAINT platform_access_profile_defaults_profile_id_key UNIQUE (profile_id),
    CONSTRAINT platform_access_profile_defaults_user_id_fkey FOREIGN KEY (user_id)
        REFERENCES public.users(id) ON DELETE CASCADE,
    CONSTRAINT platform_access_profile_defaults_profile_fkey FOREIGN KEY (profile_id, user_id)
        REFERENCES public.platform_access_profiles(id, user_id)
);

-- Existing users: the oldest personal profile, the same rule that makes a
-- user's first profile their default.
INSERT INTO public.platform_access_profile_defaults (user_id, profile_id)
SELECT DISTINCT ON (p.user_id) p.user_id, p.id
FROM public.platform_access_profiles AS p
WHERE p.user_id IS NOT NULL
ORDER BY p.user_id, p.created_at, p.id;
