SELECT
   'EXPLAIN SELECT * FROM(' || pg_catalog.quote_ident(rtrim(pg_catalog.pg_get_viewdef(c.oid), ';')) || ') AS "' || pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(c.relname) || '";'
FROM pg_class c
LEFT JOIN pg_catalog.pg_namespace n ON (n.oid = c.relnamespace AND n.nspname NOT IN('pg_toast', 'pg_catalog', 'information_schema', 'cstore'))
WHERE c.relkind = 'v'::"char" and c.oid > 16384;