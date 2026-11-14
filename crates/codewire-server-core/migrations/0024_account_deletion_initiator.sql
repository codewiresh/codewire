-- Who began an account deletion (#4541). Until now only the account itself
-- could; an admin and the purge of email sign-ups that never verify can now
-- too, through the same operation and workflow.
--
-- `initiator` names who asked. `actor_user_id` and `actor_email` record the
-- admin who asked, kept here because an audit entry's user id is cleared when
-- that admin's own account is deleted; there is deliberately no foreign key.
-- `notify_email` says whether the "your account was deleted" mail is sent:
-- never to an address nobody proved, so never for the purge.
ALTER TABLE public.account_deletion_operations
    ADD COLUMN initiator text DEFAULT 'self'::text NOT NULL,
    ADD COLUMN notify_email boolean DEFAULT true NOT NULL,
    ADD COLUMN actor_user_id text,
    ADD COLUMN actor_email text,
    ADD CONSTRAINT account_deletion_operations_initiator_check
        CHECK (initiator = ANY (ARRAY['self'::text, 'admin'::text, 'unverified_purge'::text])),
    ADD CONSTRAINT account_deletion_operations_actor_check CHECK (
        (initiator = 'admin'::text) = (actor_user_id IS NOT NULL)
        AND (actor_user_id IS NULL) = (actor_email IS NULL)
        AND (initiator <> 'unverified_purge'::text OR NOT notify_email)
    );
