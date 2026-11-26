-- A binding's personal confirmation given with a user token (#5688,
-- docs/dev/SECRETS-AND-CREDENTIALS.md, "Who may bind a personal profile").
--
-- platform_environment_access_bindings.personal_owner_confirmed_by_user_token:
-- the creator, when a user token gave the personal confirmation. A sign-in's
-- confirmation stays in personal_owner_confirmed_by, as before. At most one of
-- the two is set, so a binding records which credential confirmed it, and only
-- a sign-in's confirmation admits the direct delivery exceptions.
--
-- The column is nullable with no default, so no row is rewritten, and every
-- existing binding is a sign-in's or an organization's. Rollback drops it: an
-- older binary reads only personal_owner_confirmed_by, finds no confirmation on
-- a user token's binding and denies its personal grants until it is bound again.
ALTER TABLE ONLY public.platform_environment_access_bindings
    ADD COLUMN personal_owner_confirmed_by_user_token text,
    ADD CONSTRAINT platform_env_access_bindings_one_personal_confirmation
        CHECK (personal_owner_confirmed_by IS NULL OR personal_owner_confirmed_by_user_token IS NULL),
    ADD CONSTRAINT platform_env_access_bindings_user_token_confirmation_fkey
        FOREIGN KEY (personal_owner_confirmed_by_user_token) REFERENCES public.users(id) ON DELETE SET NULL;
