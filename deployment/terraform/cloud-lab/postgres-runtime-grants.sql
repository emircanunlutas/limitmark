-- Repeatable runtime privileges for the public inquiry runtime.
-- Run as the MIGRATION role (the table owner) after every migration:
--   psql -v ON_ERROR_STOP=1 -v app_role=limitmark_lab_app -f postgres-runtime-grants.sql
--
-- Derived from src/lib/inquiry-repository.ts (PostgresInquiryRepository.create), the only
-- database code the laboratory runtime executes:
--   INSERT ... ON CONFLICT (submission_token) DO NOTHING RETURNING id  -> INSERT + SELECT(id, submission_token)
--   SELECT id, payload_fingerprint FROM inquiries WHERE submission_token = $1
--   INSERT INTO inquiry_events / notification_outbox (no RETURNING)
-- There are no UPDATE/DELETE statements and no sequences (all keys are gen_random_uuid()).
-- Foreign-key checks run with the owner's rights, so the runtime needs no access to referenced rows.
--
-- Deliberately NOT done: ALTER DEFAULT PRIVILEGES ... GRANT. A table added by a later migration gets
-- no runtime access until it is reviewed and listed here; tests/cloud-lab-database-privileges.test.ts
-- fails if a schema table is neither granted nor explicitly marked as having no runtime access.

BEGIN;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM :"app_role";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM :"app_role";
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM :"app_role";
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM :"app_role";

GRANT INSERT ON public.inquiries TO :"app_role";
GRANT SELECT (id, submission_token, payload_fingerprint) ON public.inquiries TO :"app_role";
GRANT INSERT ON public.inquiry_events TO :"app_role";
GRANT INSERT ON public.notification_outbox TO :"app_role";

COMMIT;
