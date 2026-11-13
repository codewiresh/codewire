-- Organization invitation email outbox (#3847): one row per invitation,
-- written by CreateInvitation in the invitation's own transaction and sent
-- by idp, which holds the transactional-email credentials.
--
-- A row holds only what the email shows: the recipient, the organization's
-- id, name and slug, the inviter's display name or address, and the role.
-- It never holds the invitation token or any other secret: only the token's
-- digest is stored, on the invitation, and the email links to signing in,
-- not to the token (decided on #3840, 2026-11-12).
--
-- A pending row is due once next_attempt_at has passed. A sender claims it
-- by setting claimed_until, a lease, and adding one to attempts; attempts
-- also fences the claimant's result, so a sender whose lease ran out cannot
-- overwrite a newer claim. A failed attempt is retried after a delay until
-- the sender's attempt bound, then the row is failed. A row whose invitation
-- is no longer pending (revoked, accepted or expired) is skipped. last_error
-- is a short, provider-neutral reason the inviter sees.
--
-- Deleting the invitation (with its organization or its inviter) deletes
-- its row.
--
-- Compatible: the table is new and older code reads nothing from it; an
-- older CreateInvitation simply writes no row, and its invitation shows no
-- email status. Rollback drops the table: invitations are unaffected, and
-- emails not yet sent are never sent.

CREATE TABLE public.org_invitation_emails (
    invitation_id text NOT NULL,
    recipient text NOT NULL,
    org_id text NOT NULL,
    org_name text NOT NULL,
    org_slug text NOT NULL,
    inviter text NOT NULL,
    role text NOT NULL,
    status text DEFAULT 'pending' NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    claimed_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sent_at timestamp with time zone,
    CONSTRAINT org_invitation_emails_pkey PRIMARY KEY (invitation_id),
    CONSTRAINT org_invitation_emails_invitation_id_fkey
        FOREIGN KEY (invitation_id) REFERENCES public.org_invitations(id) ON DELETE CASCADE,
    CONSTRAINT org_invitation_emails_role_check
        CHECK (role IN ('owner', 'admin', 'member')),
    CONSTRAINT org_invitation_emails_status_check
        CHECK (status IN ('pending', 'sent', 'failed', 'skipped')),
    CONSTRAINT org_invitation_emails_attempts_check CHECK (attempts >= 0),
    CONSTRAINT org_invitation_emails_last_error_check
        CHECK (char_length(last_error) BETWEEN 1 AND 200),
    CONSTRAINT org_invitation_emails_sent_at_check
        CHECK ((status = 'sent') = (sent_at IS NOT NULL)),
    CONSTRAINT org_invitation_emails_claim_check
        CHECK (status = 'pending' OR claimed_until IS NULL)
);

CREATE INDEX org_invitation_emails_due_idx
    ON public.org_invitation_emails (next_attempt_at)
    WHERE status = 'pending';
