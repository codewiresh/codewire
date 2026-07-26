WITH relations AS (
    SELECT
        c.relname AS relation_name,
        c.relkind::text AS relation_kind,
        c.relpersistence::text AS persistence,
        c.relrowsecurity AS row_security,
        c.relforcerowsecurity AS force_row_security
    FROM pg_catalog.pg_class AS c
    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p', 'S', 'v', 'm')
      AND c.relname <> '_sqlx_migrations'
),
columns AS (
    SELECT
        c.relname AS relation_name,
        a.attnum AS ordinal,
        a.attname AS column_name,
        pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
        a.attnotnull AS not_null,
        a.attidentity::text AS identity_kind,
        a.attgenerated::text AS generated_kind,
        coll.collname AS collation,
        pg_catalog.pg_get_expr(d.adbin, d.adrelid, true) AS default_expression
    FROM pg_catalog.pg_attribute AS a
    JOIN pg_catalog.pg_class AS c ON c.oid = a.attrelid
    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
    LEFT JOIN pg_catalog.pg_attrdef AS d
      ON d.adrelid = a.attrelid AND d.adnum = a.attnum
    LEFT JOIN pg_catalog.pg_collation AS coll ON coll.oid = a.attcollation
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p', 'v', 'm')
      AND c.relname <> '_sqlx_migrations'
      AND a.attnum > 0
      AND NOT a.attisdropped
),
constraints AS (
    SELECT
        c.relname AS relation_name,
        con.conname AS constraint_name,
        con.contype::text AS constraint_type,
        con.condeferrable AS deferrable,
        con.condeferred AS initially_deferred,
        con.convalidated AS validated,
        pg_catalog.pg_get_constraintdef(con.oid, true) AS definition
    FROM pg_catalog.pg_constraint AS con
    JOIN pg_catalog.pg_class AS c ON c.oid = con.conrelid
    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname <> '_sqlx_migrations'
),
indexes AS (
    SELECT
        table_class.relname AS relation_name,
        index_class.relname AS index_name,
        idx.indisunique AS unique_index,
        idx.indisprimary AS primary_index,
        idx.indisexclusion AS exclusion_index,
        idx.indisvalid AS valid,
        pg_catalog.pg_get_indexdef(index_class.oid, 0, true) AS definition,
        pg_catalog.pg_get_expr(idx.indpred, idx.indrelid, true) AS predicate
    FROM pg_catalog.pg_index AS idx
    JOIN pg_catalog.pg_class AS table_class ON table_class.oid = idx.indrelid
    JOIN pg_catalog.pg_class AS index_class ON index_class.oid = idx.indexrelid
    JOIN pg_catalog.pg_namespace AS n ON n.oid = table_class.relnamespace
    WHERE n.nspname = 'public'
      AND table_class.relname <> '_sqlx_migrations'
),
sequences AS (
    SELECT
        c.relname AS sequence_name,
        pg_catalog.format_type(s.seqtypid, NULL) AS data_type,
        s.seqstart AS start_value,
        s.seqincrement AS increment_by,
        s.seqmin AS min_value,
        s.seqmax AS max_value,
        s.seqcache AS cache_size,
        s.seqcycle AS cycle
    FROM pg_catalog.pg_sequence AS s
    JOIN pg_catalog.pg_class AS c ON c.oid = s.seqrelid
    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
),
extensions AS (
    SELECT ext.extname AS extension_name
    FROM pg_catalog.pg_extension AS ext
    JOIN pg_catalog.pg_namespace AS n ON n.oid = ext.extnamespace
    WHERE n.nspname = 'public'
),
plan_rows AS (
    SELECT pg_catalog.jsonb_build_object(
        'resource_type', resource_type,
        'plan_key', plan_key,
        'display_name', display_name,
        'price_cents', price_cents,
        'included_devs', included_devs,
        'max_concurrent_ws', max_concurrent_ws,
        'max_team_members', max_team_members,
        'storage_gb', storage_gb,
        'is_contact_us', is_contact_us,
        'is_admin_only', is_admin_only,
        'included_cpu_hours', included_cpu_hours,
        'included_mem_gb_hours', included_mem_gb_hours,
        'included_disk_gb_hours', included_disk_gb_hours,
        'cpu_overage_cents', cpu_overage_cents,
        'mem_overage_cents', mem_overage_cents,
        'disk_overage_cents', disk_overage_cents,
        'archived', archived_at IS NOT NULL
    ) AS value
    FROM public.billing_catalog_plans
),
price_rows AS (
    SELECT pg_catalog.jsonb_build_object(
        'resource_type', resource_type,
        'plan_key', plan_key,
        'stripe_mode', stripe_mode,
        'price_kind', price_kind,
        'stripe_price_id', stripe_price_id,
        'archived', archived_at IS NOT NULL
    ) AS value
    FROM public.billing_catalog_prices
),
setting_rows AS (
    SELECT pg_catalog.jsonb_build_object(
        'setting_key', setting_key,
        'int_value', int_value
    ) AS value
    FROM public.billing_catalog_settings
),
fingerprint AS (
SELECT pg_catalog.jsonb_build_object(
    'relations', COALESCE((
        SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(r) ORDER BY relation_name)
        FROM relations AS r
    ), '[]'::jsonb),
    'columns', COALESCE((
        SELECT pg_catalog.jsonb_agg(
            pg_catalog.to_jsonb(c) - 'ordinal' ORDER BY relation_name, ordinal
        )
        FROM columns AS c
    ), '[]'::jsonb),
    'constraints', COALESCE((
        SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(c) ORDER BY relation_name, constraint_name)
        FROM constraints AS c
    ), '[]'::jsonb),
    'indexes', COALESCE((
        SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(i) ORDER BY relation_name, index_name)
        FROM indexes AS i
    ), '[]'::jsonb),
    'sequences', COALESCE((
        SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(s) ORDER BY sequence_name)
        FROM sequences AS s
    ), '[]'::jsonb),
    'extensions', COALESCE((
        SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(e) ORDER BY extension_name)
        FROM extensions AS e
    ), '[]'::jsonb),
    'static_rows', pg_catalog.jsonb_build_object(
        'billing_catalog_plans', COALESCE((
            SELECT pg_catalog.jsonb_agg(value ORDER BY value->>'resource_type', value->>'plan_key')
            FROM plan_rows
        ), '[]'::jsonb),
        'billing_catalog_prices', COALESCE((
            SELECT pg_catalog.jsonb_agg(
                value ORDER BY value->>'resource_type', value->>'plan_key',
                value->>'stripe_mode', value->>'price_kind'
            )
            FROM price_rows
        ), '[]'::jsonb),
        'billing_catalog_settings', COALESCE((
            SELECT pg_catalog.jsonb_agg(value ORDER BY value->>'setting_key')
            FROM setting_rows
        ), '[]'::jsonb)
    )
) AS value
)
SELECT pg_catalog.encode(public.digest(value::text, 'sha256'), 'hex')
FROM fingerprint;
