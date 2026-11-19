-- Deterministic, read-only description of the application schema (schema "public").
-- Run with: psql -X -At -f drizzle-schema-fingerprint.sql
-- Ownership, grants and the "drizzle" bookkeeping schema are deliberately excluded: they differ by environment.
-- A database built by `drizzle-kit migrate` and one built by applying drizzle/*.sql with psql must print identical output.
SELECT line FROM (
  SELECT 1 AS k, c.relname || '|' || a.attname AS sort,
         'column ' || c.relname || '.' || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) ||
         CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE '' END ||
         COALESCE(' DEFAULT ' || pg_get_expr(d.adbin, d.adrelid), '') AS line
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid AND c.relkind = 'r'
    JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
    LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
   WHERE a.attnum > 0 AND NOT a.attisdropped
  UNION ALL
  SELECT 2, c.relname || '|' || k.conname,
         'constraint ' || c.relname || ' ' || k.conname || ' ' || pg_get_constraintdef(k.oid)
    FROM pg_constraint k
    JOIN pg_class c ON c.oid = k.conrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
  UNION ALL
  SELECT 3, indexname, 'index ' || indexdef FROM pg_indexes WHERE schemaname = 'public'
  UNION ALL
  SELECT 4, t.typname || '|' || lpad(e.enumsortorder::text, 6, '0'),
         'enum ' || t.typname || ' ' || e.enumlabel
    FROM pg_type t
    JOIN pg_enum e ON e.enumtypid = t.oid
    JOIN pg_namespace n ON n.oid = t.typnamespace AND n.nspname = 'public'
  UNION ALL
  SELECT 5, c.relname, 'relation ' || c.relkind::text || ' ' || c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
   WHERE c.relkind IN ('r', 'v', 'm', 'S', 'f', 'p')
) fingerprint
ORDER BY k, sort;
