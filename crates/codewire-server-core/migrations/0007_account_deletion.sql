-- Account deletion (#3679).
--
-- A user deletes their own account. The request disables the account at once
-- (the existing trigger revokes its sessions, tokens and keys) and records one
-- operation here; a durable workflow then deletes the user's personal
-- organizations through the organization deletion path, deletes their Stripe
-- customers, deletes the user and sends the confirmation mail. Each phase is
-- recorded, so a retry resumes where the last attempt stopped and the account
-- is never enabled with part of it gone.
--
-- Rows that must outlive the user and name them, such as environments they
-- created in a shared organization or audit entries, are moved to one
-- disabled "Deleted user" before the user row is deleted. Every NOT NULL
-- column keeps a value, a shared organization the user created is not
-- cascaded away with them, and the email is free to sign up again.
--
-- The operation keeps the user id until the user is deleted and the address
-- until the confirmation mail is sent; a completed operation holds neither.
-- A trigger keeps an account being deleted, and the "Deleted user", disabled.
--
-- Compatible: the table is new and the "Deleted user" row is disabled with no
-- credential, so it can neither sign in nor be found by older code that does
-- not look for it. Rollback drops the trigger, its function and the table,
-- and deletes the "Deleted user" once nothing references it.

INSERT INTO public.users (id, email, name, email_verified, enabled)
VALUES ('deleted-user', 'deleted-user@deleted.codewire.invalid', 'Deleted user', false, false)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE public.account_deletion_operations (
    id text NOT NULL,
    user_id text,
    workflow_id text NOT NULL,
    state text DEFAULT 'pending_start'::text NOT NULL,
    phase text DEFAULT 'requested'::text NOT NULL,
    email text,
    personal_organization_ids text[] DEFAULT '{}'::text[] NOT NULL,
    stripe_customer_ids text[] DEFAULT '{}'::text[] NOT NULL,
    start_attempts integer DEFAULT 0 NOT NULL,
    last_start_attempt_at timestamp with time zone,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT account_deletion_operations_pkey PRIMARY KEY (id),
    CONSTRAINT account_deletion_operations_state_check
        CHECK (state = ANY (ARRAY['pending_start'::text, 'started'::text, 'completed'::text])),
    CONSTRAINT account_deletion_operations_phase_check
        CHECK (phase = ANY (ARRAY['requested'::text, 'organizations_deleted'::text,
                                  'stripe_customers_deleted'::text, 'user_deleted'::text,
                                  'completed'::text])),
    CONSTRAINT account_deletion_operations_start_attempts_check CHECK (start_attempts >= 0),
    -- The user id stays until the user row is deleted; the address until the
    -- mail is sent, which completes the operation.
    CONSTRAINT account_deletion_operations_identity_check CHECK (
        (phase = ANY (ARRAY['user_deleted'::text, 'completed'::text])) = (user_id IS NULL)
        AND ((phase = 'completed'::text) = (state = 'completed'::text))
        AND ((state = 'completed'::text) = (completed_at IS NOT NULL))
        AND (state <> 'completed'::text OR email IS NULL)
    )
);

-- One deletion at a time per user.
CREATE UNIQUE INDEX account_deletion_operations_user_idx
    ON public.account_deletion_operations USING btree (user_id)
    WHERE (user_id IS NOT NULL);

CREATE INDEX account_deletion_operations_pending_idx
    ON public.account_deletion_operations USING btree (requested_at)
    WHERE (state = 'pending_start'::text);

-- Nothing re-enables an account while its deletion is in progress, or the
-- "Deleted user" ever: a half-deleted account must stay unusable.
CREATE FUNCTION public.codewire_account_deletion_keeps_disabled() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    IF NEW.enabled AND NOT OLD.enabled AND (
        NEW.id = 'deleted-user'
        OR EXISTS (SELECT 1 FROM public.account_deletion_operations WHERE user_id = NEW.id)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'an account being deleted stays disabled';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER users_account_deletion_keeps_disabled
    BEFORE UPDATE OF enabled ON public.users
    FOR EACH ROW EXECUTE FUNCTION public.codewire_account_deletion_keeps_disabled();
