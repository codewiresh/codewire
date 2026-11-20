-- The operator's feedback email outbox (#5466): one row per piece of
-- feedback, written by SubmitFeedback in the feedback's own transaction and
-- sent by idp, which holds the transactional-email credentials and the
-- operator address (`CODEWIRE_OPERATOR_EMAIL`).
--
-- A row names only its feedback. It holds no copy of the message, the
-- sender's name or any address: idp reads those from feedback, users and
-- organizations when it sends, so the reply address is the account's at that
-- moment.
--
-- A pending row is due once next_attempt_at has passed. A sender claims it
-- by setting claimed_until, a lease, and adding one to attempts; attempts
-- also fences the claimant's result, so a sender whose lease ran out cannot
-- overwrite a newer claim. A failed attempt is retried after a delay until
-- the sender's attempt bound, then the row is failed. A row past the hourly
-- email limit, or on a server with no operator address or no mail, is
-- skipped: its feedback stays on the admin page.
--
-- Deleting the feedback (with its sender's account) deletes its row, so
-- feedback from a deleted account is never emailed.
--
-- Compatible: the table is new and older code reads nothing from it; an
-- older SubmitFeedback simply writes no row, and its feedback is not emailed.
-- Rollback drops the table: feedback is unaffected, and emails not yet sent
-- are never sent.

CREATE TABLE public.feedback_notices (
    feedback_id text NOT NULL,
    status text DEFAULT 'pending' NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    claimed_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sent_at timestamp with time zone,
    CONSTRAINT feedback_notices_pkey PRIMARY KEY (feedback_id),
    CONSTRAINT feedback_notices_feedback_id_fkey
        FOREIGN KEY (feedback_id) REFERENCES public.feedback(id) ON DELETE CASCADE,
    CONSTRAINT feedback_notices_status_check
        CHECK (status IN ('pending', 'sent', 'failed', 'skipped')),
    CONSTRAINT feedback_notices_attempts_check CHECK (attempts >= 0),
    CONSTRAINT feedback_notices_sent_at_check
        CHECK ((status = 'sent') = (sent_at IS NOT NULL)),
    CONSTRAINT feedback_notices_claim_check
        CHECK (status = 'pending' OR claimed_until IS NULL)
);

CREATE INDEX feedback_notices_due_idx
    ON public.feedback_notices (next_attempt_at)
    WHERE status = 'pending';
