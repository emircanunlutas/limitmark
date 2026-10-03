/**
 * Live check that a probe TIMEOUT cancels transactional work instead of merely ceasing to wait for it.
 *
 *   tsx --conditions=react-server lab/failure/cancel-selftest.ts 16|17 [pause|stop]
 *
 * Against a disposable PostgreSQL: warm a pool, make the database unavailable (docker pause: a black hole that later RESUMES the backlog; or
 * stop), issue probes that time out, restore the database, wait, and then read the SERVER's state:
 *  - none of the timed-out probes' submissions exists (their transactions did not commit after recovery);
 *  - exactly the successful probes' rows exist;
 *  - no runtime backend is left active or idle-in-transaction;
 *  - the reported concurrency (unsettled operations) was 1 and ends at 0.
 * The previous pattern (Promise.race only) is replayed on the same fixture to show it DOES commit timed-out work (informational premise).
 */
import { randomBytes } from "node:crypto";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "../../src/lib/db/schema";
import { PostgresInquiryRepository } from "../../src/lib/inquiry-repository";
import { createPayloadFingerprint } from "../../src/lib/payload-fingerprint";
import { requestSchema } from "../../src/lib/request-schema";
import { EvidenceRun, collectEnvironment, collectGitState } from "../evidence/manifest";
import { evidenceSafeError } from "../evidence/redact";
import { controlLabContainer } from "../host/docker";
import { assertVersion, labDbDown, labDbUp, migratorUrl, runtimeUrl, teardownOnCrash } from "../postgres/lab-db";
import { probeWithCancellation, type CancellableProbe } from "./postgres-outage";

const request = requestSchema.parse({ name: "Cancel Lab", email: "cancel@example.test", company: "Synthetic", service: "web", system: "s", objective: "o", environment: "staging", authority: "authorized", protection: "unknown" });
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const submission = () => { const token = randomBytes(32).toString("base64url"); return { token, input: { request, submissionToken: token, payloadFingerprint: createPayloadFingerprint(request) } }; };

type Handle = { client: postgres.Sql; repository: PostgresInquiryRepository };

async function main(): Promise<void> {
  const version = assertVersion(process.argv[2]);
  const mode = process.argv[3] === "stop" ? "stop" : "pause";
  teardownOnCrash([version], { tolerateKnownPostgresJsFault: true });
  const evidence = new EvidenceRun("cancel-selftest", `cancel-selftest-pg${version}-${mode}`);
  const state = await labDbUp(version);
  const checks: { name: string; ok: boolean; detail: string }[] = [];
  const record = (name: string, ok: boolean, detail: string) => { checks.push({ name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name} - ${detail}`); };
  let failure: string | null = null;
  const owner = postgres(migratorUrl(state), { max: 1, prepare: false, onnotice: () => undefined });
  const handles: Handle[] = [];
  const open = (): Handle => {
    const client = postgres(runtimeUrl(state), { max: 5, connect_timeout: 5, prepare: false, onnotice: () => undefined, connection: { statement_timeout: 3_000, idle_in_transaction_session_timeout: 3_000 } });
    const handle = { client, repository: new PostgresInquiryRepository(drizzle(client, { schema })) };
    handles.push(handle);
    return handle;
  };
  const rowsFor = async (tokens: string[]) => tokens.length === 0 ? 0 : Number((await owner`SELECT count(*)::int AS n FROM inquiries WHERE submission_token IN ${owner(tokens)}`)[0].n);
  const total = async () => Number((await owner`SELECT count(*)::int AS n FROM inquiries`)[0].n);
  const running = async () => Number((await owner`SELECT count(*)::int AS n FROM pg_stat_activity WHERE usename = 'lab_runtime' AND datname = current_database() AND pid <> pg_backend_pid() AND state IN ('active', 'idle in transaction', 'idle in transaction (aborted)')`)[0].n);
  const outage = (start: boolean) => controlLabContainer(start ? (mode === "pause" ? "pause" : "stop") : (mode === "pause" ? "unpause" : "start"), state.container, "postgres");
  try {
    // ---- legacy premise: Promise.race only stops WAITING
    {
      const legacy = open();
      await legacy.repository.create(submission().input);
      const before = await total();
      const abandoned: string[] = [];
      await outage(true);
      for (let i = 0; i < 3; i++) {
        const { token, input } = submission();
        abandoned.push(token);
        await Promise.race([legacy.repository.create(input).catch(() => undefined), sleep(1_000)]);
      }
      await outage(false);
      await sleep(3_000);
      const committed = await rowsFor(abandoned);
      record("premise (informational): the previous Promise.race-only pattern lets timed-out probes COMMIT after recovery", true, `${committed} of 3 reported-timeout probes committed (${(await total()) - before} new rows)`);
      await legacy.client.end({ timeout: 2 }).catch(() => undefined);
      await owner`TRUNCATE TABLE notification_outbox, admin_notes, inquiry_events, inquiries`;
    }

    // ---- the corrected pattern
    const probe: CancellableProbe<Handle> = { current: open(), open, destroy: (handle) => handle.client.end({ timeout: 0 }), unsettled: 0, maxUnsettled: 0, abandoned: 0 };
    const okTokens: string[] = [], timedOutTokens: string[] = [];
    const issue = async (timeoutMs: number) => {
      const { token, input } = submission();
      const outcome = await probeWithCancellation(probe, (handle) => handle.repository.create(input), timeoutMs);
      (outcome.ok ? okTokens : timedOutTokens).push(token);
      return outcome.ok;
    };
    await issue(5_000); await issue(5_000);
    await outage(true);
    for (let i = 0; i < 4; i++) await issue(1_000);
    const unsettledDuring = probe.unsettled;
    await outage(false);
    for (let i = 0; i < 20 && !(await issue(5_000)); i++) await sleep(500); // recovery: probes succeed again
    await sleep(4_000); // generous: anything left running would have resumed and committed by now
    const committedAfterTimeout = await rowsFor(timedOutTokens);
    const expectedRows = okTokens.length;
    const actualRows = await total();
    const leftover = await running();
    record("timed-out transactional work did NOT commit after recovery", committedAfterTimeout === 0 && timedOutTokens.length >= 4, `${committedAfterTimeout} of ${timedOutTokens.length} timed-out submissions exist`);
    record("exactly the successful probes' rows exist (nothing hidden, nothing lost)", actualRows === expectedRows, `${actualRows} rows, ${expectedRows} successful probes`);
    await Promise.all(handles.map((handle) => handle.client.end({ timeout: 2 }).catch(() => undefined)));
    await sleep(1_000);
    const afterClose = await running();
    record("no hidden backend work remains (runtime backends active / in a transaction)", leftover === 0 && afterClose === 0, `while pooled: ${leftover}, after closing pools: ${afterClose}`);
    record("reported concurrency matches reality: never more than one probe unsettled, none at the end", probe.maxUnsettled === 1 && probe.unsettled === 0 && unsettledDuring === 0, `max unsettled ${probe.maxUnsettled}, at end ${probe.unsettled}, abandoned pools ${probe.abandoned}`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    failure = evidenceSafeError(error);
  } finally {
    await owner.end({ timeout: 2 }).catch(() => undefined);
    await labDbDown(version).catch((error) => { failure ??= `teardown: ${evidenceSafeError(error)}`; });
  }
  const pass = !failure && checks.filter((c) => !c.name.startsWith("premise")).every((c) => c.ok) && checks.length >= 5;
  evidence.addJsonArtifact("cancel-checks.json", { checks });
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(state.serverVersion), target: { id: `postgres-lab-${version}`, class: "lab-local", ownership: "lab-container-port" },
    workload: { id: "probe-timeout-cancellation", phases: [] }, ceilings: { scope: "per-process; not campaign- or fleet-wide" }, thresholds: null, engine: "node-postgres",
    result: failure ? "ERROR" : pass ? "PASS" : "FAIL", resultReasons: failure ? [failure] : checks.filter((c) => !c.ok).map((c) => c.name.slice(0, 120)), metrics: { checks: checks.length, mode },
  });
  console.log(`cancel self-test PG${version} (${mode}): ${failure ? `ERROR ${failure}` : pass ? "PASS" : "FAIL"} evidence=${evidence.id}`);
  process.exit(pass ? 0 : 1);
}

if (require.main === module) {
  main().catch((error) => { console.error(error instanceof Error ? error.message : error); process.exit(1); });
}
