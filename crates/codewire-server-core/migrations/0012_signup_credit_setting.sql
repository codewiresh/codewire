-- The sign-up credit: what a new organization is granted once at creation, in
-- euro cents (#3381). It replaces the EUR 50 a first card granted (owner,
-- 2026-11-10). A platform admin sets it on the admin Billing page; 0 is off.
--
-- Adding one settings row changes no existing row, and code that does not read
-- it ignores it. billing_card_grants stays until no release writes it.
INSERT INTO public.billing_catalog_settings (setting_key, int_value)
VALUES ('signup_credit_cents', 0);
