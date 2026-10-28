-- Organizations opt in to confidential environments (#2497).
--
-- Off for every organization, existing and new: only a global administrator
-- opts one in. A confidential create or start also needs the deployment's
-- confidential-storage switch and a confidential catalog entry for the
-- organization's plan. Adding a column with a constant default rewrites no
-- rows, and older code that does not read it keeps working.
ALTER TABLE ONLY public.organizations
    ADD COLUMN confidential_environments_enabled boolean DEFAULT false NOT NULL;
