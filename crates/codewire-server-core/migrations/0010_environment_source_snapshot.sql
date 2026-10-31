-- The hosted disk snapshot an environment's workspace disk was restored from
-- (#3046 H2).
--
-- It renders into the environment's PVC template, and a Pod replacement or
-- re-claim renders the same. There is no foreign key: a snapshot may be deleted
-- while environments made from it live on, since each has its own disk.
--
-- Compatible: the column is new, nullable and unread by older code. Rollback
-- drops the column; no environment needs it after its PVC exists.

ALTER TABLE public.environments
    ADD COLUMN source_snapshot_id text;
