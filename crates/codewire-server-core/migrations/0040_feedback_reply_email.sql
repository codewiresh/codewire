-- An anonymous sender's reply address (#5466; owner, 2026-11-19: "just ask
-- for email if they aren't signed in so we have something for anons").
--
-- `cw feedback` asks a sender who is not signed in for an optional address
-- the team can answer them at. It is stored as given and never verified;
-- the operator's feedback email shows it in its body and never makes it a
-- Reply-To, and the server never mails it. A signed-in row never holds one:
-- its answer goes to the account's own address.
--
-- Compatible: the column is new and nullable; older code neither writes nor
-- reads it. Rollback drops the column and its constraints, which forgets the
-- addresses given.

ALTER TABLE public.feedback
    ADD COLUMN reply_email text,
    ADD CONSTRAINT feedback_reply_email_anonymous_check
        CHECK (reply_email IS NULL OR user_id IS NULL),
    ADD CONSTRAINT feedback_reply_email_check
        CHECK (reply_email IS NULL OR (
            char_length(reply_email) BETWEEN 3 AND 254
            AND reply_email ~ '^[!-~]+$'
        ));
