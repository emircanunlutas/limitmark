import { readFile } from "node:fs/promises";
import {
  createAuthorityAttestationSigner,
  type AuthorityAttestationSigner,
  type AuthorityAttestationSignerConfig,
} from "../../workers/admission-service/authority-attestation-signer";
import type { DurableStorageLike } from "../../workers/admission-service/authority";
import { ATTESTATION_SIGNER_BINDINGS } from "../../workers/admission-service/authority-attestation-config";
import { parseAuthorityResultTrustManifest, type AuthorityResultTrustManifest } from "../../src/lib/authority-result-trust";

/**
 * Deterministic seams for the Slice 2A Authority producer tests. Key material is ONLY the RFC 8032 test vectors already frozen
 * in tests/fixtures/authority-result-attestation-v2.golden.json (TEST KEYS - NEVER PROVISION). Nothing is generated here.
 */
type Role = "production" | "staging";
interface RfcKey { privateKeyPkcs8: string; publicKey: string; fingerprint: string }

let loaded: Promise<Record<Role, RfcKey>> | undefined;
export function rfcKeys(): Promise<Record<Role, RfcKey>> {
  loaded ??= readFile(new URL("../fixtures/authority-result-attestation-v2.golden.json", import.meta.url), "utf8")
    .then((text) => (JSON.parse(text) as { keys: Record<Role, RfcKey> }).keys);
  return loaded;
}

export async function rfcSignerConfig(role: Role): Promise<AuthorityAttestationSignerConfig> {
  const key = (await rfcKeys())[role];
  return { environment: role, writerKeyFingerprint: key.fingerprint, privateKey: key.privateKeyPkcs8, publicKey: key.publicKey };
}

/** The explicit TEST-ONLY runtime configuration a local workerd/Node test hands an Authority: the RFC vectors under the same binding
 * NAMES the active runtime reads. Nothing in the active runtime defaults to these values. */
export async function rfcSignerBindings(role: Role): Promise<Record<string, string>> {
  const key = (await rfcKeys())[role];
  const names = ATTESTATION_SIGNER_BINDINGS[role];
  return { [names.privateKey]: key.privateKeyPkcs8, [names.publicKey]: key.publicKey, [names.writerKeyFingerprint]: key.fingerprint };
}

let trust: Promise<AuthorityResultTrustManifest> | undefined;
/** The tracked TEST trust manifest (RFC test keys for both environments), parsed by the frozen parser. */
export function rfcTrustManifest(): Promise<AuthorityResultTrustManifest> {
  trust ??= readFile(new URL("../fixtures/authority-result-trust-v1.test.json", import.meta.url), "utf8").then((text) => parseAuthorityResultTrustManifest(text));
  return trust;
}

export async function healthySigner(role: Role): Promise<AuthorityAttestationSigner> {
  return createAuthorityAttestationSigner(await rfcSignerConfig(role));
}

export interface SignerEvents { readonly log: string[] }

/** Wraps a real signer, recording every call into `events.log` (shared with the SQL log so ordering is provable) and
 * optionally failing `ready` or `sign` on demand. The wrapped signer's own readiness/sign logic still runs when not failing. */
export function instrumentSigner(inner: AuthorityAttestationSigner, events: SignerEvents,
  faults: { ready?: boolean; sign?: boolean } = {}): AuthorityAttestationSigner {
  return Object.freeze({
    environment: inner.environment,
    authorityId: inner.authorityId,
    policyEpoch: inner.policyEpoch,
    writerKeyFingerprint: inner.writerKeyFingerprint,
    async ready(nowMs: number) {
      events.log.push(`ready:${nowMs}`);
      if (faults.ready) throw new Error("injected-ready-failure");
      await inner.ready(nowMs);
    },
    async sign(statement: Parameters<AuthorityAttestationSigner["sign"]>[0]) {
      events.log.push("sign");
      if (faults.sign) throw new Error("injected-sign-failure");
      return inner.sign(statement);
    },
  });
}

/** Storage wrapper that records every SQL statement and transaction boundary into `events.log`. */
export function instrumentStorage(inner: DurableStorageLike, events: SignerEvents): DurableStorageLike {
  return {
    sql: { exec: (query, ...bindings) => { events.log.push(`sql:${query.trim().split(/\s+/u).slice(0, 3).join(" ")}`); return inner.sql.exec(query, ...bindings); } },
    transactionSync: (callback) => {
      events.log.push("tx:begin");
      const result = inner.transactionSync(callback);
      events.log.push("tx:commit");
      return result;
    },
  };
}

/** A scripted Authority clock: returns the given readings in order (repeating the last) and records each read. */
export function scriptedClock(...readings: number[]) {
  const reads: number[] = [];
  return { reads, now: () => { const value = readings[Math.min(reads.length, readings.length - 1)]; reads.push(value); return value; } };
}
