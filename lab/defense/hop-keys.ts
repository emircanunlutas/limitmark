/**
 * Lab trust root and TEST-ONLY proof oracle for BA0 Slice 2.
 *
 * The harness plays the control owner of a disposable run: it generates two distinct Ed25519 keypairs (K_P for the Plane-to-Boundary hop,
 * K_B for the Boundary-to-App hop), distinct audience ids and kids, and hands each process only what it needs, over IPC and never by env,
 * argv, file or evidence:
 *
 *   Plane     K_P private                              (signs PB)
 *   Boundary  K_P public, K_B private                  (verifies PB, signs BA)
 *   App       K_B public, K_P public                   (verifies BA and the PB lineage; NO private key)
 *
 * The oracle below can mint proofs for arbitrary facts (misbound, expired, forged, wrong role...) so the direct-path tests can prove those
 * are refused. It is a lab capability ONLY: this file is under lab/, is never imported by defense/ or src/, is not reachable from any
 * request or IPC message, and ENCODES independently of defense/ (from the written format, using node:crypto directly) so a format bug in
 * defense/ surfaces as a failed positive control. Oracle hop ids start at ORACLE_HOP_BASE and can never equal a Plane sequence number.
 */
import { createHash, generateKeyPairSync, randomBytes, sign as edSign, type KeyObject } from "node:crypto";
import { ORACLE_HOP_BASE } from "../../defense/core/ledger";
import type { BoundaryInit, BoundaryLimits } from "../../defense/boundary/protocol";
import type { PlaneHopInit } from "../../defense/plane/protocol";
import type { AppInit } from "../../defense/origin/app-protocol";
import type { ChannelOptions } from "../../defense/core/ledger";

const FORM = "application/x-www-form-urlencoded";
const id22 = (): string => randomBytes(16).toString("base64url");
const sha256b64 = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("base64url");

export type OracleRequest = { method: "GET" | "POST"; target: string; host: string; origin?: string; contentType?: string; body: Buffer };

/** The canonical pairs the format calls for: bound names only, sorted, values as the wire carries them. */
export function oraclePairs(request: OracleRequest): [string, string][] {
  const pairs: [string, string][] = [["host", request.host]];
  if (request.origin !== undefined) pairs.push(["origin", request.origin]);
  if (request.method === "POST") pairs.push(["content-type", request.contentType ?? FORM]);
  return pairs.sort(([a], [b]) => (a < b ? -1 : 1));
}

export type KeyChoice = "P" | "B" | "attacker";
export type MintSpec = {
  request: OracleRequest;
  corr: string;
  kid?: string;
  aud?: string;
  role?: string;
  domain?: string;
  key?: KeyChoice;
  iat?: number;
  exp?: number;
  jti?: string;
  hop?: number;
  /** Replace the signed body digest / length (to forge a binding without changing the wire). */
  bodySha256?: string;
  bodyLen?: number;
  /** Drop the last payload element (a wrong field count). */
  truncate?: boolean;
};
export type BaSpec = MintSpec & { pb: { header: string; jti: string } };
export type Minted = { header: string; jti: string; hop: number };

export class HopTrustRoot {
  readonly boundaryId = id22();
  readonly appId = id22();
  readonly kidP = `pb-${randomBytes(6).toString("base64url")}`;
  readonly kidB = `ba-${randomBytes(6).toString("base64url")}`;
  private readonly keysP = generateKeyPairSync("ed25519");
  private readonly keysB = generateKeyPairSync("ed25519");
  private readonly keysAttacker = generateKeyPairSync("ed25519");
  private oracleHop = ORACLE_HOP_BASE;

  private static der(key: KeyObject, type: "pkcs8" | "spki"): string { return key.export({ type, format: "der" }).toString("base64url"); }
  private pick(choice: KeyChoice): KeyObject { return choice === "P" ? this.keysP.privateKey : choice === "B" ? this.keysB.privateKey : this.keysAttacker.privateKey; }

  // ---- init messages: each process gets exactly the key material its role needs

  planeInit(lifetimeMs: number): PlaneHopInit {
    return { privateKey: HopTrustRoot.der(this.keysP.privateKey, "pkcs8"), kid: this.kidP, boundaryId: this.boundaryId, lifetimeMs };
  }
  boundaryInit(appPort: number, limits: BoundaryLimits, channel?: ChannelOptions): Omit<BoundaryInit, "type"> {
    return {
      appPort, publicKeyP: HopTrustRoot.der(this.keysP.publicKey, "spki"), kidP: this.kidP, boundaryId: this.boundaryId,
      privateKeyB: HopTrustRoot.der(this.keysB.privateKey, "pkcs8"), kidB: this.kidB, appId: this.appId, limits, channel,
    };
  }
  appInit(limits: AppInit["limits"], channel?: ChannelOptions, maxConcurrent?: number): Omit<AppInit, "type"> {
    return {
      publicKeyB: HopTrustRoot.der(this.keysB.publicKey, "spki"), kidB: this.kidB, publicKeyP: HopTrustRoot.der(this.keysP.publicKey, "spki"), kidP: this.kidP,
      appId: this.appId, boundaryId: this.boundaryId, limits, channel, maxConcurrent,
    };
  }
  /** Every distinct piece of key material, so a test can prove none of it reaches evidence or an unintended process. */
  keyMaterial(): { privateP: string; privateB: string; publicP: string; publicB: string } {
    return {
      privateP: HopTrustRoot.der(this.keysP.privateKey, "pkcs8"), privateB: HopTrustRoot.der(this.keysB.privateKey, "pkcs8"),
      publicP: HopTrustRoot.der(this.keysP.publicKey, "spki"), publicB: HopTrustRoot.der(this.keysB.publicKey, "spki"),
    };
  }

  // ---- oracle (independent encoder)

  nextHop(): number { return ++this.oracleHop; }

  private envelope(payload: unknown[], domain: string, key: KeyChoice): string {
    const bytes = Buffer.from(JSON.stringify(payload), "utf8");
    const signature = edSign(null, Buffer.concat([Buffer.from(domain, "utf8"), bytes]), this.pick(key));
    return `${bytes.toString("base64url")}.${signature.toString("base64url")}`;
  }

  private requestFields(spec: MintSpec): unknown[] {
    return [spec.request.method, spec.request.target, oraclePairs(spec.request), spec.bodyLen ?? spec.request.body.length, spec.bodySha256 ?? sha256b64(spec.request.body)];
  }

  /** A Plane-to-Boundary proof, genuine unless the spec says otherwise. */
  mintPb(spec: MintSpec): Minted {
    const now = Date.now();
    const iat = spec.iat ?? now;
    const jti = spec.jti ?? id22();
    const hop = spec.hop ?? this.nextHop();
    const payload: unknown[] = [spec.role ?? "ba0-pb-v2", spec.kid ?? this.kidP, spec.aud ?? this.boundaryId, iat, spec.exp ?? iat + 4_000, jti, hop, spec.corr, ...this.requestFields(spec)];
    return { header: this.envelope(spec.truncate ? payload.slice(0, -1) : payload, spec.domain ?? "ba0:pb:ed25519:v2\0", spec.key ?? "P"), jti, hop };
  }

  /** A Boundary-to-App proof, genuine (signed with K_B, committing to `pb`) unless the spec says otherwise. */
  mintBa(spec: BaSpec): Minted {
    const iat = spec.iat ?? Date.now();
    const jti = spec.jti ?? id22();
    const hop = spec.hop ?? this.nextHop();
    const payload: unknown[] = [
      spec.role ?? "ba0-ba-v2", spec.kid ?? this.kidB, spec.aud ?? this.appId, iat, spec.exp ?? iat + 1_500, jti, hop, spec.corr, ...this.requestFields(spec),
      spec.pb.jti, sha256b64(Buffer.from(spec.pb.header, "utf8")),
    ];
    return { header: this.envelope(spec.truncate ? payload.slice(0, -1) : payload, spec.domain ?? "ba0:ba:ed25519:v2\0", spec.key ?? "B"), jti, hop };
  }

  /** Both authorities exercised by the lab: a genuine PB and a genuine BA committing to it, for the same request and hop. */
  mintChain(request: OracleRequest, corr: string): { pb: Minted; ba: Minted } {
    const pb = this.mintPb({ request, corr });
    const ba = this.mintBa({ request, corr, hop: pb.hop, pb });
    return { pb, ba };
  }
}
