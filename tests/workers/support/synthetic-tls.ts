import { generateKeyPairSync, sign } from "node:crypto";

const bytes = (...parts: Uint8Array[]) => Buffer.concat(parts);
function der(tag: number, content: Uint8Array): Buffer {
  const size = content.length;
  const length = size < 128 ? Buffer.from([size]) : size < 256 ? Buffer.from([0x81, size]) : Buffer.from([0x82, size >> 8, size & 255]);
  return bytes(Buffer.from([tag]), length, content);
}
const sequence = (...parts: Uint8Array[]) => der(0x30, bytes(...parts));
const oid = (hex: string) => der(0x06, Buffer.from(hex, "hex"));
const integer = (value: number) => der(0x02, Buffer.from([value]));
const pem = (label: string, value: Uint8Array) => `-----BEGIN ${label}-----\n${Buffer.from(value).toString("base64").match(/.{1,64}/gu)!.join("\n")}\n-----END ${label}-----\n`;

/** Ephemeral localhost certificate; no key material is stored in the repository. */
export function syntheticTlsCertificate(): { key: string; cert: string } {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const subject = sequence(der(0x31, sequence(oid("550403"), der(0x0c, Buffer.from("localhost")))));
  const algorithm = sequence(oid("2a8648ce3d040302")); // ecdsa-with-SHA256
  const now = new Date();
  const from = new Date(now.getTime() - 60_000);
  const until = new Date(now.getTime() + 3_600_000);
  const utc = (date: Date) => der(0x17, Buffer.from(`${String(date.getUTCFullYear()).slice(-2)}${String(date.getUTCMonth() + 1).padStart(2, "0")}${String(date.getUTCDate()).padStart(2, "0")}${String(date.getUTCHours()).padStart(2, "0")}${String(date.getUTCMinutes()).padStart(2, "0")}${String(date.getUTCSeconds()).padStart(2, "0")}Z`));
  const names = sequence(der(0x82, Buffer.from("localhost")), der(0x87, Buffer.from([127, 0, 0, 1])));
  const extensions = der(0xa3, sequence(sequence(oid("551d11"), der(0x04, names))));
  const tbs = sequence(der(0xa0, integer(2)), integer(1), algorithm, subject, sequence(utc(from), utc(until)), subject,
    pair.publicKey.export({ format: "der", type: "spki" }), extensions);
  const signature = sign("sha256", tbs, pair.privateKey);
  const cert = sequence(tbs, algorithm, der(0x03, bytes(Buffer.from([0]), signature)));
  return { key: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(), cert: pem("CERTIFICATE", cert) };
}
