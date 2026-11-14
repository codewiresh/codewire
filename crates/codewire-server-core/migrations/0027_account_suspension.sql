-- Account suspension (#3297 item 4): an administrator's one-step response to
-- abuse. Suspending an account disables it (the
-- codewire_revoke_user_capabilities trigger revokes its sessions, OIDC tokens
-- and API keys) and records when and by which administrator. Each
-- organization the account is the only owner of records the same; such an
-- organization refuses creates and starts, and the worker stops its running
-- environments. The audit log keeps the history and the reason.
--
-- suspended_by names the administrator and is not a foreign key: deleting an
-- administrator's account must not change or block a suspension it made. An
-- organization's suspended_for names the suspended account whose suspension
-- marked it, so unsuspending that account clears exactly those organizations
-- even if their owners changed meanwhile; it is set exactly when suspended_at
-- is.
--
-- A suspended account is never enabled (users_suspended_disabled_check), so
-- any path that enables an account fails closed on a suspended one; only
-- unsuspension, which clears suspended_at in the same statement, enables it.
--
-- Compatible: the five columns are new and nullable, and older code reads
-- none of them. Under older code a suspended account stays disabled, but its
-- organizations no longer refuse creates. Rollback drops the five columns
-- with the same effect.

ALTER TABLE public.users
    ADD COLUMN suspended_at timestamp with time zone,
    ADD COLUMN suspended_by text,
    ADD CONSTRAINT users_suspended_by_check
        CHECK (suspended_by IS NULL OR suspended_at IS NOT NULL),
    ADD CONSTRAINT users_suspended_disabled_check
        CHECK (NOT (enabled AND suspended_at IS NOT NULL));

ALTER TABLE public.organizations
    ADD COLUMN suspended_at timestamp with time zone,
    ADD COLUMN suspended_by text,
    ADD COLUMN suspended_for text,
    ADD CONSTRAINT organizations_suspended_by_check
        CHECK (suspended_by IS NULL OR suspended_at IS NOT NULL),
    ADD CONSTRAINT organizations_suspended_for_check
        CHECK ((suspended_for IS NULL) = (suspended_at IS NULL));
