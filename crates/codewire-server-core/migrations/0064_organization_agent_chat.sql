-- Per-organization opt-in to the Sandbox Agent Chat tab and streaming agent
-- sessions. Off by default; toggled by a global administrator in /admin.
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS agent_chat BOOLEAN NOT NULL DEFAULT FALSE;
