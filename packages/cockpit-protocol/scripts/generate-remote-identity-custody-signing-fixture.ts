/**
 * Regenerate `fixtures/remote-identity-custody-signing-v1.json`.
 *
 * Run with a TS runner (e.g. `pnpm --filter @flycockpit/cockpit-protocol exec
 * tsx scripts/generate-remote-identity-custody-signing-fixture.ts`). The
 * committed fixture pins ONE valid low-S P1363 ECDSA/P-256 signature over the
 * possession-proof signing message; ECDSA is randomized, so regeneration
 * rewrites the signature and public key, which is expected. The unsigned proof,
 * domain, message, and digest are deterministic.
 */
import { writeFileSync } from "node:fs";
import {
  encodePossessionProof,
  PossessionPurpose,
  possessionProofSigningMessage,
  possessionSignatureDomain,
  remoteIdentitySha256,
  SubjectKind,
} from "../src/remote-identity-protocol";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// P-256 group order n and n/2, for low-S normalization.
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_N = N >> 1n;
const toBig = (b: Uint8Array) => b.reduce((acc, x) => (acc << 8n) | BigInt(x), 0n);
const toBytes = (v: bigint) => {
  const out = new Uint8Array(32);
  let n = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
};

const PURPOSE = PossessionPurpose.attempt_daemon;

// Build the 175-byte unsigned proof via the production codec (placeholder low-S
// signature sliced off), then the domain/message/digest.
const placeholder = new Uint8Array(64);
placeholder[31] = 1;
placeholder[63] = 1;
const fullPlaceholder = encodePossessionProof({
  purpose: PURPOSE,
  subjectKind: SubjectKind.daemon,
  subjectId: new Uint8Array(16).fill(0x11),
  certificateId: new Uint8Array(16).fill(0x22),
  generation: 7n,
  requestId: new Uint8Array(16).fill(0x33),
  issuerStatusDigest: new Uint8Array(32).fill(0x44),
  challenge: new Uint8Array(32).fill(0x55),
  transcriptDigest: new Uint8Array(32).fill(0x66),
  issuedAt: 1000n,
  expiresAt: 1060n,
  signatureP1363: placeholder,
});
const unsigned = fullPlaceholder.slice(0, 175);
const domain = possessionSignatureDomain(PURPOSE);
// Copy into a fresh ArrayBuffer-backed view so the message is a `BufferSource`
// (WebCrypto rejects `Uint8Array<ArrayBufferLike>`, which may be SharedArrayBuffer-backed).
const message = new Uint8Array(possessionProofSigningMessage(unsigned, PURPOSE));
const digest = await remoteIdentitySha256(message);

// Generate a P-256 key and sign the message; normalize to low-S.
const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
  "sign",
  "verify",
]);
const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
const pubX = raw.slice(1, 33);
const pubY = raw.slice(33, 65);

let low: Uint8Array | undefined;
let high: Uint8Array | undefined;
while (!low) {
  const s64 = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, message),
  );
  const r = s64.slice(0, 32);
  const sBig = toBig(s64.slice(32, 64));
  const rBig = toBig(r);
  if (rBig === 0n || sBig === 0n || rBig >= N) continue;
  const sLow = sBig > HALF_N ? N - sBig : sBig;
  const sHigh = N - sLow;
  if (sLow === 0n || sHigh <= HALF_N) continue;
  const l = new Uint8Array(64);
  l.set(r, 0);
  l.set(toBytes(sLow), 32);
  const h = new Uint8Array(64);
  h.set(r, 0);
  h.set(toBytes(sHigh), 32);
  const okLow = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    keyPair.publicKey,
    l,
    message,
  );
  const okHigh = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    keyPair.publicKey,
    h,
    message,
  );
  if (okLow && okHigh) {
    low = l;
    high = h;
  }
}

const fixture = {
  schemaVersion: 1,
  description:
    "One valid low-S P1363 ECDSA/P-256 signature over the possession-proof signing message, pinning the digest-vs-message contract across Rust and TypeScript.",
  purpose: PURPOSE,
  purposeName: "attempt_daemon",
  subjectKind: SubjectKind.daemon,
  unsignedProof: hex(unsigned),
  domain: hex(domain),
  message: hex(message),
  digest: hex(digest),
  publicKey: { x: hex(pubX), y: hex(pubY) },
  signatureLowS: hex(low),
  signatureHighS: hex(high as Uint8Array),
};

writeFileSync(
  new URL("../fixtures/remote-identity-custody-signing-v1.json", import.meta.url),
  `${JSON.stringify(fixture, null, 2)}\n`,
);
