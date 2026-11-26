-- A standard Sandbox's paused stretch is a billing session of its own
-- (#5529, docs/dev/BILLING.md, "A suspended stretch").
--
-- sandbox_running_sessions.rate_kind: 'running', every existing row's and
-- every session's but a paused standard Sandbox's, or 'paused', which draws
-- only its disk at the rate card's storage rate.
--
-- pause_generation, pause_sequence: the last pause record the session loop
-- applied, by its boot and sequence, carried from session to session at each
-- split so a record is never applied twice. Both NULL until one is applied.
--
-- paused_seen_at: while a session is paused, when the latest record said so,
-- from which a gap is measured. NULL otherwise.
--
-- review_reason: 'pause_records_gap' on a running session opened by a gap in
-- a paused Sandbox's records, which an operator reviews; NULL otherwise.
--
-- Every column is nullable or has a constant default, so no row is rewritten,
-- and older code keeps working: it reads every session as running. Rollback
-- drops them; a paused session then draws as running from that moment.
ALTER TABLE ONLY public.sandbox_running_sessions
    ADD COLUMN rate_kind text DEFAULT 'running' NOT NULL,
    ADD COLUMN pause_generation bigint,
    ADD COLUMN pause_sequence bigint,
    ADD COLUMN paused_seen_at timestamp with time zone,
    ADD COLUMN review_reason text,
    ADD CONSTRAINT sandbox_running_sessions_rate_kind_check
        CHECK (rate_kind IN ('running', 'paused')),
    ADD CONSTRAINT sandbox_running_sessions_pause_mark_check
        CHECK ((pause_generation IS NULL) = (pause_sequence IS NULL)
               AND COALESCE(pause_generation >= 0 AND pause_sequence >= 0, true)),
    ADD CONSTRAINT sandbox_running_sessions_review_reason_check
        CHECK (review_reason IS NULL OR review_reason = 'pause_records_gap');
