-- Managed disposable Kind only, after the standard migration owner has
-- installed the schema. This is a real restricted login, not SET ROLE in an
-- owner connection. It has only encrypted application-reader column grants,
-- never a plaintext getter, full project_spec or owner/profile/secret mutation.
BEGIN;
CREATE ROLE codewire_credential_broker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS NOINHERIT
    PASSWORD 'kind-credential-broker-synthetic-only';
GRANT CONNECT ON DATABASE codewire TO codewire_credential_broker;
GRANT USAGE ON SCHEMA public TO codewire_credential_broker;
GRANT SELECT (id,is_admin,enabled) ON public.users TO codewire_credential_broker;
GRANT SELECT (id,deletion_state) ON public.organizations TO codewire_credential_broker;
GRANT SELECT (id,org_id,user_id,role) ON public.org_members TO codewire_credential_broker;
GRANT SELECT (id,created_by,org_id,type,state,desired_state,deletion_requested_at,environment_operation_generation)
    ON public.environments TO codewire_credential_broker;
GRANT SELECT (environment_id,namespace,sandbox_claim_name,sandbox_claim_uid,pod_name)
    ON public.sandbox_environment_backend TO codewire_credential_broker;
GRANT SELECT (id,user_id,organization_id,name,current_revision)
    ON public.platform_access_profiles TO codewire_credential_broker;
GRANT SELECT (profile_id,revision,include_github) ON public.platform_access_profile_revisions TO codewire_credential_broker;
GRANT SELECT ON public.platform_access_profile_entries TO codewire_credential_broker;
GRANT SELECT (environment_id,profile_id,profile_revision,personal_owner_confirmed_by)
    ON public.platform_environment_access_bindings TO codewire_credential_broker;
GRANT SELECT,INSERT,DELETE ON public.platform_credentials TO codewire_credential_broker;
-- SSH enrollment inserts its derived public key/fingerprint atomically. It
-- needs no UPDATE on either column; generic replacement remains prohibited.
GRANT UPDATE (status,expires_at_unix,revocation_generation,material_generation,updated_at,account_hint,display_name)
    ON public.platform_credentials TO codewire_credential_broker;
GRANT SELECT,INSERT,DELETE ON public.platform_credential_material TO codewire_credential_broker;
GRANT SELECT,INSERT,UPDATE,DELETE ON public.platform_credential_refresh_attempts TO codewire_credential_broker;
GRANT SELECT,INSERT,UPDATE,DELETE ON public.platform_credential_refresh_material TO codewire_credential_broker;
GRANT EXECUTE ON FUNCTION public.codewire_platform_lock_owner(text,text) TO codewire_credential_broker;
GRANT EXECUTE ON FUNCTION public.codewire_platform_lock_environment(text,text,text) TO codewire_credential_broker;
GRANT EXECUTE ON FUNCTION public.codewire_platform_lock_profile(text,text,text) TO codewire_credential_broker;
GRANT EXECUTE ON FUNCTION public.codewire_platform_lock_credential(text,text,text) TO codewire_credential_broker;
GRANT EXECUTE ON FUNCTION public.codewire_platform_projection_metadata(text) TO codewire_credential_broker;
GRANT EXECUTE ON FUNCTION public.codewire_platform_lock_projection_authority(text,text,text,text)
    TO codewire_credential_broker;
GRANT SELECT (path,key,scope,scope_id,dek_id,ciphertext,nonce,format,storage_contract_version)
    ON public.tenant_secrets TO codewire_credential_broker;
GRANT SELECT (dek_id,scope,scope_id,provider,key_name,key_version,wrapped_dek,format,revision)
    ON public.tenant_secret_deks TO codewire_credential_broker;
GRANT SELECT (token_hash,user_id,client_id,scopes,expires_at)
    ON public.oidc_access_tokens TO codewire_credential_broker;
GRANT SELECT (id,disabled) ON public.oidc_clients TO codewire_credential_broker;
GRANT EXECUTE ON FUNCTION public.codewire_lock_oauth_bearer_authority(text,text,text,timestamptz)
TO codewire_credential_broker;
GRANT EXECUTE ON FUNCTION public.codewire_authenticate_credential_session(text)
TO codewire_credential_broker;
GRANT EXECUTE ON FUNCTION public.codewire_lock_credential_session_authority(text,text,text,timestamptz)
TO codewire_credential_broker;
COMMIT;
