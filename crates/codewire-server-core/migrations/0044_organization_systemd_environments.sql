-- Systemd environments (#5638, docs/dev/SYSTEMD-WORKSPACE.md).
--
-- organizations.systemd_environments_enabled: the organization is opted in,
-- as for confidential environments. Off for every organization, existing and
-- new: only a global administrator opts one in. A systemd create also needs
-- the deployment's systemd workspace image repository.
--
-- environments.systemd_workspace: the environment is a systemd workspace,
-- decided once at create and read by every later render, so a later change
-- to the deployment's setting never turns an environment into one or back.
-- False for every existing environment.
--
-- Adding columns with a constant default rewrites no rows, and older code
-- that does not read them keeps working.
ALTER TABLE ONLY public.organizations
    ADD COLUMN systemd_environments_enabled boolean DEFAULT false NOT NULL;

ALTER TABLE ONLY public.environments
    ADD COLUMN systemd_workspace boolean DEFAULT false NOT NULL;
