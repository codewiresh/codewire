-- Admin-set rate limits (#3297). A platform admin's global count for a named
-- limit, and per-user counts for a limit counted per user. A missing row means
-- the limit's code default; only counts are stored, the windows stay in code.
-- An override is deleted with its user. updated_by names the admin, like an
-- audit row's actor.
CREATE TABLE public.rate_limit_settings (
    name text PRIMARY KEY,
    max_requests integer NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamp without time zone NOT NULL DEFAULT now(),
    CONSTRAINT rate_limit_settings_name_check CHECK (name ~ '^[a-z][a-z0-9_]{0,62}$'),
    CONSTRAINT rate_limit_settings_max_requests_check CHECK (max_requests >= 0)
);

CREATE TABLE public.rate_limit_overrides (
    user_id text NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    name text NOT NULL,
    max_requests integer NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamp without time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, name),
    CONSTRAINT rate_limit_overrides_name_check CHECK (name ~ '^[a-z][a-z0-9_]{0,62}$'),
    CONSTRAINT rate_limit_overrides_max_requests_check CHECK (max_requests >= 0)
);
