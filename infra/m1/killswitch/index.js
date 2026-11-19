"use strict";
/* eslint-disable @typescript-eslint/no-require-imports -- Cloud Functions gen2 registers a CommonJS handler export without a framework dependency; scoped to this file only */
// Cloud Functions entry point (not deployed). Reads the Pub/Sub message, asks decide.js what to delete, deletes ONLY those labeled instances, waits for them to disappear and FAILS
// (so Pub/Sub redelivers the event) if any deletion failed or any labeled instance remains. It uses the Compute REST API with the function service-account token from the metadata
// server: no third-party package is needed or declared.
const { decide, executeDeletes, settle } = require("./decide");

const METADATA_TOKEN = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
const COMPUTE = "https://compute.googleapis.com/compute/v1";

async function token() {
  const response = await fetch(METADATA_TOKEN, { headers: { "Metadata-Flavor": "Google" }, signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw new Error("metadata-token");
  return (await response.json()).access_token;
}

async function listInstances(project, zone, accessToken) {
  const found = [];
  let pageToken = "";
  do {
    const response = await fetch(`${COMPUTE}/projects/${project}/zones/${zone}/instances${pageToken ? `?pageToken=${encodeURIComponent(pageToken)}` : ""}`, { headers: { Authorization: `Bearer ${accessToken}` }, signal: AbortSignal.timeout(20000) });
    if (!response.ok) throw new Error(`list-${project}-${response.status}`);
    const body = await response.json();
    for (const instance of body.items || []) found.push({ name: instance.name, project, createdMs: Date.parse(instance.creationTimestamp), labels: instance.labels || {} });
    pageToken = body.nextPageToken || "";
  } while (pageToken);
  return found;
}

exports.handle = async (cloudEvent) => {
  const raw = cloudEvent && cloudEvent.data && cloudEvent.data.message && cloudEvent.data.message.data;
  let message = null;
  try { message = raw ? JSON.parse(Buffer.from(raw, "base64").toString("utf8")) : null; } catch { message = null; }
  const config = { campaignId: process.env.M1_CAMPAIGN_ID, runId: process.env.M1_RUN_ID, runMaxSeconds: Number(process.env.M1_RUN_MAX_SECONDS), stopFraction: Number(process.env.M1_STOP_FRACTION) };
  const zone = process.env.M1_ZONE;
  const accessToken = await token();
  const listAll = async () => { const all = []; for (const project of String(process.env.M1_PROJECTS).split(",")) all.push(...await listInstances(project, zone, accessToken)); return all; };
  const decision = decide(message, Date.now(), await listAll(), config);
  console.log(JSON.stringify({ action: decision.action, reason: decision.reason, targets: decision.targets.map((t) => `${t.project}/${t.name}`) }));
  if (decision.action !== "delete") return;
  const outcome = await executeDeletes(decision.targets, async (target) => {
    const response = await fetch(`${COMPUTE}/projects/${target.project}/zones/${zone}/instances/${target.name}`, { method: "DELETE", headers: { Authorization: `Bearer ${accessToken}` }, signal: AbortSignal.timeout(20000) });
    if (response.status === 404) return "gone";
    if (!response.ok) throw new Error(`delete-${response.status}`);
    return "deleted";
  }, { timeoutMs: 25000 });
  console.log(JSON.stringify({ deleteOutcome: outcome }));
  // a deletion is asynchronous: wait for the labeled instances to disappear, and FAIL (so Pub/Sub retries) if any remain or any deletion failed
  const runScoped = decision.reason.startsWith("run-");
  const left = await settle(listAll, config, { attempts: 6, intervalMs: 5000, runScoped, nowMs: Date.now, sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)) });
  if (outcome.failed.length > 0 || left.remaining.length > 0) throw new Error(`stop-incomplete:${JSON.stringify({ failed: outcome.failed, remaining: left.remaining })}`);
};
