import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { ModuleKind, transpileModule } from "typescript";
import * as mutationInput from "../src/lib/admin-inquiry-mutation-input";
import { parseMutationTarget, parseNoteMutation, parseStatusMutation } from "../src/lib/admin-inquiry-mutation-input";
import { parseInquiryAuditDetail } from "../src/lib/inquiry-audit";
import { inquiryStatusValues } from "../src/lib/db/schema";
import {
  canTransitionInquiryStatus,
  inquiryStatusTransitionGraph,
  isInquiryStatus,
} from "../src/lib/inquiry-status-workflow";

const id = "00000000-0000-4000-8000-000000000042";
function form(values: Record<string, string>): FormData {
  const data = new FormData();
  for (const [key, value] of Object.entries(values)) data.set(key, value);
  return data;
}

test("the transition graph is exhaustive, authoritative, and conservative", () => {
  assert.deepEqual(new Set(Object.keys(inquiryStatusTransitionGraph)), new Set(inquiryStatusValues));
  assert.equal(isInquiryStatus("scheduled"), false);
  assert.equal(canTransitionInquiryStatus("received", "in_review"), true);
  assert.equal(canTransitionInquiryStatus("received", "declined"), true);
  assert.equal(canTransitionInquiryStatus("in_review", "awaiting_scope"), true);
  assert.equal(canTransitionInquiryStatus("awaiting_scope", "proposal_sent"), true);
  assert.equal(canTransitionInquiryStatus("proposal_sent", "approved"), true);
  assert.equal(canTransitionInquiryStatus("approved", "completed"), true);
  assert.deepEqual(inquiryStatusTransitionGraph.completed, []);
  assert.deepEqual(inquiryStatusTransitionGraph.declined, []);
  assert.deepEqual(inquiryStatusTransitionGraph.archived, []);
  for (const current of inquiryStatusValues) {
    for (const next of inquiryStatusValues) {
      assert.equal(canTransitionInquiryStatus(current, next), inquiryStatusTransitionGraph[current].includes(next as never));
    }
  }
});

test("mutation inputs reject invalid UUIDs, revisions, statuses, and notes", () => {
  assert.deepEqual(parseMutationTarget(form({ inquiryId: id, expectedRevision: "0" })), { inquiryId: id, expectedRevision: 0 });
  for (const [inquiryId, expectedRevision] of [["not-a-uuid", "0"], [id, "-1"], [id, "1.5"], [id, "01"], [id, "2147483647"], [id, "9007199254740992"]]) {
    assert.equal(parseMutationTarget(form({ inquiryId, expectedRevision })), null);
  }
  assert.equal(parseStatusMutation(form({ inquiryId: id, expectedRevision: "0", newStatus: "scheduled" })), null);
  assert.equal(parseNoteMutation(form({ inquiryId: id, expectedRevision: "0", content: "   " })), null);
  assert.equal(parseNoteMutation(form({ inquiryId: id, expectedRevision: "0", content: "x".repeat(10_001) })), null);
  assert.equal(parseNoteMutation(form({ inquiryId: id, expectedRevision: "0", content: " <b>plain</b> " }))?.content, "<b>plain</b>");
});

test("client-supplied actor identity is neither parsed nor accepted", () => {
  const data = form({ inquiryId: id, expectedRevision: "2", newStatus: "in_review", actorIdentifier: "attacker@example.test" });
  assert.deepEqual(parseStatusMutation(data), { inquiryId: id, expectedRevision: 2, newStatus: "in_review" });
});

test("audit metadata accepts only bounded known shapes and ignores malformed data", () => {
  assert.deepEqual(parseInquiryAuditDetail("status_changed", { previousStatus: "received", newStatus: "in_review" }), { kind: "status_changed", previousStatus: "received", newStatus: "in_review" });
  assert.deepEqual(parseInquiryAuditDetail("archived", { previousStatus: "approved" }), { kind: "archived", previousStatus: "approved" });
  assert.deepEqual(parseInquiryAuditDetail("restored", { restoredStatus: "declined" }), { kind: "restored", restoredStatus: "declined" });
  for (const malformed of [null, "raw", { previousStatus: "received", newStatus: "scheduled" }, { previousStatus: "received", newStatus: "in_review", customer: "secret" }]) {
    assert.equal(parseInquiryAuditDetail("status_changed", malformed), null);
  }
});

test("every Server Action independently authorizes before parsing or repository access", async () => {
  const source = await readFile(new URL("../src/app/admin/inquiries/actions.ts", import.meta.url), "utf8");
  const names = ["changeInquiryStatusAction", "addInquiryNoteAction", "archiveInquiryAction", "restoreInquiryAction"];
  for (const [index, name] of names.entries()) {
    const start = source.indexOf(`export async function ${name}`);
    const end = index + 1 < names.length ? source.indexOf(`export async function ${names[index + 1]}`) : source.length;
    const action = source.slice(start, end);
    assert.ok(start >= 0);
    assert.ok(action.indexOf("await requireAdmin()") >= 0);
    assert.ok(action.indexOf("await requireAdmin()") < action.indexOf("parse"));
    assert.ok(action.indexOf("parse") < action.indexOf("runMutation("));
    assert.doesNotMatch(action, /getAdminInquiryMutationRepository/);
    assert.doesNotMatch(action, /formData\.get\([^)]*actor|actorIdentifier:\s*formData|error\.message|sql/i);
    assert.match(action, /admin\.email/);
  }
  assert.match(source, /async function runMutation\([\s\S]*?await getAdminInquiryMutationRepository\(\)/);
});

test("direct-origin mutation requests still depend on a verified Access identity", async () => {
  const [actionSource, authSource] = await Promise.all([
    readFile(new URL("../src/app/admin/inquiries/actions.ts", import.meta.url), "utf8"),
    readFile(new URL("../src/lib/admin-auth-core.ts", import.meta.url), "utf8"),
  ]);
  assert.match(actionSource, /await requireAdmin\(\)/);
  assert.match(authSource, /if \(!token\) return null/);
  assert.doesNotMatch(authSource, /CF_Authorization|x-user-email|x-forwarded-email/i);
});

test("an unacknowledged commit is not retried or presented as a confirmed rollback", async () => {
  const source = await readFile(new URL("../src/app/admin/inquiries/actions.ts", import.meta.url), "utf8");
  const actionExports: { addInquiryNoteAction?: (data: FormData) => Promise<never> } = {};
  let committedNotes = 0;
  let committedEventId = "";
  let committedActor = "";
  const generatedId = "00000000-0000-4000-8000-000000000043";
  const redirected = new Error("redirect");
  let destination = "";
  const dependencies: Record<string, unknown> = {
    "next/cache": { revalidatePath: () => assert.fail("An unknown outcome must not be treated as success") },
    "next/navigation": { redirect: (path: string) => { destination = path; throw redirected; } },
    "@/lib/admin-auth": { requireAdmin: async () => ({ email: "verified-admin@example.test" }) },
    "@/lib/admin-inquiry-mutation-input": mutationInput,
    "@/lib/admin-inquiry-data": {
      getAdminInquiryMutationRepository: async () => ({
        addNote: async (input: { eventId: string; identity: { actorIdentifier: string } }) => {
          // Model COMMIT succeeding before the driver loses its acknowledgement.
          committedNotes += 1;
          committedEventId = input.eventId;
          committedActor = input.identity.actorIdentifier;
          throw new Error("connection closed after COMMIT; private database detail");
        },
      }),
    },
  };
  runInNewContext(transpileModule(source, { compilerOptions: { module: ModuleKind.CommonJS } }).outputText, {
    exports: actionExports,
    crypto: { randomUUID: () => generatedId },
    require: (name: string) => {
      assert.ok(Object.hasOwn(dependencies, name), `Unexpected dependency: ${name}`);
      return dependencies[name];
    },
  });
  await assert.rejects(
    actionExports.addInquiryNoteAction!(form({ inquiryId: id, expectedRevision: "0", content: "Committed note", eventId: id })),
    (error: unknown) => error === redirected,
  );
  assert.equal(committedNotes, 1);
  assert.equal(committedActor, "verified-admin@example.test");
  assert.equal(committedEventId, generatedId);
  assert.equal(destination, `/admin/inquiries/${id}?receipt=${committedEventId}`);
});
