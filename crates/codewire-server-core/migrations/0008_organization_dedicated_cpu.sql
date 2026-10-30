-- Dedicated CPU (#3635): a sandbox of an organization that has it reserves one
-- CPU per vCPU, whatever CPU sharing the deployment sets.
--
-- Off for every organization, existing and new: only a global administrator
-- sets it. Adding a column with a constant default rewrites no rows, and older
-- code that does not read it keeps working.
ALTER TABLE ONLY public.organizations
    ADD COLUMN dedicated_cpu boolean DEFAULT false NOT NULL;
