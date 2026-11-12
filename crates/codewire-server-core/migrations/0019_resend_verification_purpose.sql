-- A sign-in with the right password to an account that never verified its
-- email gets a short-lived, single-use token, stored hashed, that asks for a
-- new verification link (#4322). Its identifier is the user id.
ALTER TABLE verifications DROP CONSTRAINT verifications_purpose_check;
ALTER TABLE verifications ADD CONSTRAINT verifications_purpose_check
    CHECK (purpose = ANY (ARRAY['email_verification'::text, 'password_reset'::text, 'resend_verification'::text]));
