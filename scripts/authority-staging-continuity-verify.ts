import { STAGING_CONTINUITY_TRANSPORT_REFUSAL } from "../operator/staging-gate7-continuity";

// Gate 8 Phase 1A: live staging continuity verification -- CLOSED / TOOLING
// REQUIRED. The Wrangler preview transport a live read would need can register
// a workers.dev subdomain when none exists and uploads a temporary preview
// Worker, and a pre-existing subdomain cannot currently be verified positively
// without a new provider credential or an unreviewed API client. This revision
// therefore contains no transport at all: it reads no argument, environment
// variable, file or credential, spawns nothing, opens no socket and always
// refuses. The Gate 7 expected state and its validator live in
// operator/staging-gate7-continuity.ts and are exercised only with synthetic
// snapshots. A future transport requires its own design and review.

process.stderr.write(STAGING_CONTINUITY_TRANSPORT_REFUSAL);
process.exitCode = 2;
