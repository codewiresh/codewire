-- Hosted egress lockdown refusals (#5068): orchestration's lockdown check
-- records the refusal that failed a sandbox Pod closed, so the environment's
-- enforcement status reads FAILED_CLOSED with its reason.
--
-- Rollback: ALTER TABLE public.sandbox_egress_enforcement
--               DROP COLUMN lockdown_refusal;

-- Written only by orchestration, never from a cw-egress report, and kept
-- over any report until the Pod's lockdown passes, it is bound elsewhere or
-- it is released. The exact refusal is for operators; the public status says
-- only that the lockdown was not applied.
ALTER TABLE public.sandbox_egress_enforcement
    ADD COLUMN lockdown_refusal text,
    ADD CONSTRAINT sandbox_egress_enforcement_lockdown_refusal_check CHECK (
        lockdown_refusal IS NULL OR lockdown_refusal = ANY (ARRAY[
            'not_broker_mode'::text,
            'not_labelled_for_its_binding'::text,
            'policy_unmanaged'::text,
            'policy_missing'::text,
            'policy_differs'::text,
            'policy_does_not_select'::text
        ])
    );
