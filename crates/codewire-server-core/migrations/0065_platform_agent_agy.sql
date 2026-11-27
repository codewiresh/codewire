-- Allow Antigravity CLI ('agy') managed agent conversations on platform Pods.
ALTER TABLE public.environment_platform_agent_conversations
    DROP CONSTRAINT environment_platform_agent_conversations_agent_check,
    ADD CONSTRAINT environment_platform_agent_conversations_agent_check
        CHECK ((agent = ANY (ARRAY['codex'::text, 'claude'::text, 'agy'::text])));
