-- In-place rollback is safe only before this delivery has admitted a request.
-- Once used, restore/replay the accepted prior schema from a separately owned
-- backup; never discard Issued/Unknown evidence or erase a deletion barrier.
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM environment_platform_agent_requests) OR
        EXISTS(SELECT 1 FROM environment_platform_agent_conversations) THEN
        RAISE EXCEPTION 'platform agent evidence prevents in-place rollback';
    END IF;
END $$;
DROP TABLE environment_platform_agent_conversations;
DROP TABLE environment_platform_agent_requests;
DROP FUNCTION environment_platform_agent_conversation_guard();
DROP FUNCTION environment_platform_agent_request_guard();
