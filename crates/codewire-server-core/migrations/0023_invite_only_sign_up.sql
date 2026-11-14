-- Invite-only sign-up on a server with no mail (#4121). There, nothing can
-- prove who owns an address, so the owner's rule is that the admin vouches
-- for it: by handing someone an invite link, by creating the admin at setup,
-- or by enabling a waiting account.
--
-- users.email_vouched_by records which of those vouched for the address. A
-- vouched address is never verified: email_verified stays false, so every
-- reader of email_verified (provider auto-linking, ListMyInvitations) treats
-- the account as unverified, including code from before this migration. The
-- second check makes an old writer's mailbox verification of a vouched
-- account fail instead of turning it into a verified one.
--
-- Compatible: the column is new and nullable, and existing rows are neither
-- vouched nor affected by the checks; older code never writes the column and
-- reads nothing new. Rollback drops the checks and the column. Vouched
-- accounts then read as plain unverified accounts.
ALTER TABLE public.users ADD COLUMN email_vouched_by text;
ALTER TABLE public.users ADD CONSTRAINT users_email_vouched_by_check
    CHECK (email_vouched_by = ANY (ARRAY['invitation'::text, 'bootstrap'::text, 'admin'::text]));
ALTER TABLE public.users ADD CONSTRAINT users_email_vouched_not_verified
    CHECK (email_vouched_by IS NULL OR email_verified IS NOT TRUE);
