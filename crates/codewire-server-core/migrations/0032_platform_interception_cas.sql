-- Hosted interception CAs (#4001 step N1, #5030): one CA per Sandbox Pod,
-- kept by the credential service for the Pod's whole life
-- (docs/dev/SECRETS-AND-CREDENTIALS.md, "Hosted interception CA").
--
-- The credential service inserts a Pod's row at its first admission, bound or
-- not, with INSERT ... ON CONFLICT DO NOTHING, and only reads it afterwards.
-- The private key is sealed like platform_credential_material: a DEK in the
-- platform scope for that Pod UID, and AES-GCM ciphertext whose associated
-- data names the Pod UID, so a row copied to another Pod does not open. The
-- certificate is public and stored in the clear, and so are the Pod's
-- namespace and name, by which the sweep reads whether the Pod still exists.
--
-- Its environment is never chosen by the inserter (cw-security, #4001):
-- - insert: the row's environment is the Pod's live binding's, or NULL while
--   the Pod is unbound; an insert naming one, or for a Pod whose binding was
--   released, is refused;
-- - bind: the binding's insert attaches it, once; another environment is
--   refused;
-- - release: the binding's release deletes it, in the same transaction;
-- - unbound Pods: the credential service's sweep calls
--   forget_interception_ca, which deletes only a row with no live binding.
-- Each of these takes the same transaction-scoped advisory lock on the Pod
-- UID, so an insert racing a release either sees the release or is deleted
-- by it. The functions are owned by the migration owner, pin search_path and
-- name every relation; the credential service's role is granted SELECT,
-- INSERT and EXECUTE on forget_interception_ca only, outside this history
-- (tests/e2e/kind/credential-broker.sql and infra's credential database
-- grants), and no role may DELETE or UPDATE rows directly.
--
-- Compatible: the table and functions are new, and older code reads nothing
-- from them; the triggers on sandbox_workspace_bindings touch only this
-- table. Rollback drops them, which ends every hosted Pod's interception
-- trust; a Pod's guest then refuses a redial with another CA and fails closed.

CREATE TABLE public.platform_interception_cas (
    pod_uid text NOT NULL,
    pod_namespace text NOT NULL,
    pod_name text NOT NULL,
    environment_id text,
    attached_at timestamp with time zone,
    certificate_der bytea NOT NULL,
    not_before timestamp with time zone NOT NULL,
    not_after timestamp with time zone NOT NULL,
    kek_provider text NOT NULL,
    key_name text NOT NULL,
    key_version bigint NOT NULL,
    wrapped_dek bytea NOT NULL,
    wrapped_format smallint NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    format smallint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_interception_cas_pkey PRIMARY KEY (pod_uid),
    CONSTRAINT platform_interception_cas_environment_id_fkey
        FOREIGN KEY (environment_id) REFERENCES public.environments(id) ON DELETE CASCADE,
    CONSTRAINT platform_interception_cas_pod_uid_check
        CHECK ((pod_uid ~ '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'::text)),
    -- Kubernetes names: a DNS label for the namespace, a DNS subdomain for
    -- the Pod.
    CONSTRAINT platform_interception_cas_pod_namespace_check
        CHECK ((pod_namespace ~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT platform_interception_cas_pod_name_check
        CHECK ((pod_name ~ '^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$'::text)),
    CONSTRAINT platform_interception_cas_attached_check
        CHECK (((environment_id IS NULL) = (attached_at IS NULL))),
    CONSTRAINT platform_interception_cas_certificate_der_check
        CHECK (((octet_length(certificate_der) >= 1) AND (octet_length(certificate_der) <= 4096))),
    CONSTRAINT platform_interception_cas_validity_check CHECK ((not_after > not_before)),
    -- A PKCS#8 P-256 key and AES-GCM's 16-byte tag.
    CONSTRAINT platform_interception_cas_ciphertext_check
        CHECK (((octet_length(ciphertext) >= 17) AND (octet_length(ciphertext) <= 512))),
    CONSTRAINT platform_interception_cas_format_check CHECK ((format = 1)),
    CONSTRAINT platform_interception_cas_kek_provider_check
        CHECK ((kek_provider = 'openbao-transit'::text)),
    CONSTRAINT platform_interception_cas_key_version_check
        CHECK (((key_version > 0) AND (key_version <= '4294967295'::bigint))),
    CONSTRAINT platform_interception_cas_nonce_check CHECK ((octet_length(nonce) = 12)),
    CONSTRAINT platform_interception_cas_wrapped_dek_check
        CHECK (((octet_length(wrapped_dek) >= 1) AND (octet_length(wrapped_dek) <= 65536))),
    CONSTRAINT platform_interception_cas_wrapped_format_check CHECK ((wrapped_format = 1))
);

REVOKE ALL ON public.platform_interception_cas FROM PUBLIC;

-- One Pod UID's lock, taken by every function below.
CREATE FUNCTION public.codewire_interception_ca_lock(pod_uid text) RETURNS void
    LANGUAGE sql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
    SELECT pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('codewire.interception-ca:' || $1, 0));
$_$;

REVOKE ALL ON FUNCTION public.codewire_interception_ca_lock(pod_uid text) FROM PUBLIC;

-- Insert: the environment comes from the Pod's live binding, never from the
-- inserter, and a Pod whose binding was released gets no row.
CREATE FUNCTION public.codewire_interception_ca_insert() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
BEGIN
    IF NEW.environment_id IS NOT NULL OR NEW.attached_at IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'an interception CA''s environment comes only from its Pod''s binding';
    END IF;
    PERFORM public.codewire_interception_ca_lock(NEW.pod_uid);
    IF EXISTS (
        SELECT 1 FROM public.sandbox_workspace_bindings AS w
        WHERE w.pod_uid = NEW.pod_uid AND w.released_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'the Pod''s binding was released';
    END IF;
    SELECT w.environment_id, pg_catalog.now() INTO NEW.environment_id, NEW.attached_at
    FROM public.sandbox_workspace_bindings AS w
    WHERE w.pod_uid = NEW.pod_uid AND w.released_at IS NULL;
    RETURN NEW;
END;
$_$;

REVOKE ALL ON FUNCTION public.codewire_interception_ca_insert() FROM PUBLIC;

CREATE TRIGGER codewire_interception_ca_insert BEFORE INSERT ON public.platform_interception_cas
    FOR EACH ROW EXECUTE FUNCTION public.codewire_interception_ca_insert();

-- Nothing in a row changes once it is stored, except the one attach.
CREATE FUNCTION public.codewire_interception_ca_immutable() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
BEGIN
    IF OLD.environment_id IS NOT NULL
       OR NEW.environment_id IS NULL
       OR ROW(NEW.pod_uid, NEW.pod_namespace, NEW.pod_name, NEW.certificate_der,
              NEW.not_before, NEW.not_after,
              NEW.kek_provider, NEW.key_name, NEW.key_version, NEW.wrapped_dek,
              NEW.wrapped_format, NEW.ciphertext, NEW.nonce, NEW.format, NEW.created_at)
          IS DISTINCT FROM
          ROW(OLD.pod_uid, OLD.pod_namespace, OLD.pod_name, OLD.certificate_der,
              OLD.not_before, OLD.not_after,
              OLD.kek_provider, OLD.key_name, OLD.key_version, OLD.wrapped_dek,
              OLD.wrapped_format, OLD.ciphertext, OLD.nonce, OLD.format, OLD.created_at)
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'an interception CA is attached to its environment once and otherwise never changes';
    END IF;
    RETURN NEW;
END;
$_$;

REVOKE ALL ON FUNCTION public.codewire_interception_ca_immutable() FROM PUBLIC;

CREATE TRIGGER codewire_interception_ca_immutable BEFORE UPDATE ON public.platform_interception_cas
    FOR EACH ROW EXECUTE FUNCTION public.codewire_interception_ca_immutable();

-- Bind: a new binding attaches its Pod's row, in the binding's transaction.
-- A row already attached to another environment refuses the binding.
CREATE FUNCTION public.codewire_interception_ca_attach() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
BEGIN
    PERFORM public.codewire_interception_ca_lock(NEW.pod_uid);
    IF EXISTS (
        SELECT 1 FROM public.platform_interception_cas AS c
        WHERE c.pod_uid = NEW.pod_uid AND c.environment_id IS NOT NULL
          AND c.environment_id <> NEW.environment_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'the Pod''s interception CA is attached to another environment';
    END IF;
    UPDATE public.platform_interception_cas
    SET environment_id = NEW.environment_id, attached_at = pg_catalog.now()
    WHERE pod_uid = NEW.pod_uid AND environment_id IS NULL;
    RETURN NULL;
END;
$_$;

REVOKE ALL ON FUNCTION public.codewire_interception_ca_attach() FROM PUBLIC;

CREATE TRIGGER codewire_interception_ca_attach AFTER INSERT ON public.sandbox_workspace_bindings
    FOR EACH ROW EXECUTE FUNCTION public.codewire_interception_ca_attach();

-- Release: the binding's release deletes its Pod's row, in the release's
-- transaction.
CREATE FUNCTION public.codewire_interception_ca_release() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
BEGIN
    PERFORM public.codewire_interception_ca_lock(NEW.pod_uid);
    DELETE FROM public.platform_interception_cas WHERE pod_uid = NEW.pod_uid;
    RETURN NULL;
END;
$_$;

REVOKE ALL ON FUNCTION public.codewire_interception_ca_release() FROM PUBLIC;

CREATE TRIGGER codewire_interception_ca_release AFTER UPDATE OF released_at
    ON public.sandbox_workspace_bindings
    FOR EACH ROW WHEN (((old.released_at IS NULL) AND (new.released_at IS NOT NULL)))
    EXECUTE FUNCTION public.codewire_interception_ca_release();

-- The sweep: a Pod gone from the cluster with no live binding leaves no row.
-- A misused call can only make that Pod's interception fail closed.
CREATE FUNCTION public.forget_interception_ca(pod_uid text) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
BEGIN
    PERFORM public.codewire_interception_ca_lock($1);
    DELETE FROM public.platform_interception_cas AS c
    WHERE c.pod_uid = $1
      AND NOT EXISTS (
          SELECT 1 FROM public.sandbox_workspace_bindings AS w
          WHERE w.pod_uid = $1 AND w.released_at IS NULL
      );
    RETURN FOUND;
END;
$_$;

REVOKE ALL ON FUNCTION public.forget_interception_ca(pod_uid text) FROM PUBLIC;
