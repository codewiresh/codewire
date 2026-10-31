-- A stable name for why an environment stopped short, beside error_reason, its
-- message for the user: no_capacity when the cluster has no room (#3635).
--
-- Adding a nullable column rewrites no rows, and older code that does not read
-- it keeps working. A create or start refused for lack of room is the only
-- writer.
ALTER TABLE ONLY public.environments
    ADD COLUMN error_code text;
