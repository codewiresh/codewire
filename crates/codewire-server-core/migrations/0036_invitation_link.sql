-- An invitation email's link (#4121, #3840): a random token minted when the
-- email is sent, stored only as its purpose-bound hash in verifications, with
-- the invitation id as its identifier. It names the invitation for the
-- invitation page and admits one sign-up at exactly the invited address. It
-- never accepts an invitation, signs anyone in or links a provider.
--
-- It lives only while its invitation is pending. It expires with its
-- invitation, a new email replaces it, and the trigger below deletes an
-- invitation's links when the invitation is accepted, revoked or expired, or
-- deleted with its organization. Writers from before this migration never
-- mint one. Rollback drops the triggers and the function, deletes the
-- invitation_link rows and restores the previous purpose check.
ALTER TABLE public.verifications DROP CONSTRAINT verifications_purpose_check;
ALTER TABLE public.verifications ADD CONSTRAINT verifications_purpose_check
    CHECK (purpose = ANY (ARRAY['email_verification'::text, 'password_reset'::text, 'resend_verification'::text, 'invitation_link'::text]));

CREATE FUNCTION public.codewire_invitation_forgets_its_links() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
    DELETE FROM public.verifications
     WHERE purpose = 'invitation_link' AND identifier = OLD.id;
    RETURN NULL;
END;
$$;

CREATE TRIGGER org_invitations_closed_forget_links
    AFTER UPDATE OF status ON public.org_invitations
    FOR EACH ROW WHEN (NEW.status <> 'pending')
    EXECUTE FUNCTION public.codewire_invitation_forgets_its_links();

CREATE TRIGGER org_invitations_deleted_forget_links
    AFTER DELETE ON public.org_invitations
    FOR EACH ROW EXECUTE FUNCTION public.codewire_invitation_forgets_its_links();
