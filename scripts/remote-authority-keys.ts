#!/usr/bin/env node
import { generateKeyPairSync } from "node:crypto";
import { lstat, open, readFile, rename, unlink } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import {
  type AuthorityPrivateKey,
  type AuthorityRingFile,
  authorityRetirementFloor,
  authorityRingDigest,
  parseAuthorityConfig,
  parseAuthorityRingFile,
  publicAuthorityRing,
  validateFrozenSigningJournalProof,
  validateThreeDigestPlan,
} from "../packages/api/src/lib/remote-authority";
import { readAuthorityRingFile } from "../packages/api/src/lib/remote-authority-file";

const [command, ...argv] = process.argv.slice(2);
const flags = new Map<string, string>();
for (let i = 0; i < argv.length; i += 2) {
  const key = argv[i],
    value = argv[i + 1];
  if (!key?.startsWith("--") || value === undefined)
    throw new Error("every option requires an explicit value");
  flags.set(key.slice(2), value);
}
const required = (name: string) => {
  const value = flags.get(name);
  if (!value) throw new Error(`--${name} is required`);
  return value;
};
const config = () =>
  parseAuthorityConfig({
    issuer: required("issuer"),
    deploymentId: required("deployment-id"),
    digests: flags.get("digests") ?? JSON.stringify(["0".repeat(64)]),
  });
async function load(path: string) {
  if (!isAbsolute(path)) throw new Error("input path must be absolute");
  return readAuthorityRingFile(path);
}
async function loadPrivateJson(path: string) {
  if (!isAbsolute(path)) throw new Error("proof path must be absolute");
  const info = await lstat(path);
  if (info.isSymbolicLink() || !info.isFile() || (info.mode & 0o077) !== 0)
    throw new Error("proof must be an owner-private regular file");
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}
async function write(path: string, ring: AuthorityRingFile) {
  if (!isAbsolute(path) || resolve(path) === resolve(flags.get("input") ?? "."))
    throw new Error("output must be an explicit different absolute path");
  const temp = resolve(
      dirname(path),
      `.remote-authority-${process.pid}-${crypto.randomUUID()}.tmp`,
    ),
    handle = await open(temp, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(ring, null, 2)}\n`);
    await handle.sync();
    await handle.close();
    await rename(temp, path);
    const directory = await open(dirname(path), "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  } catch (error) {
    await handle.close().catch(() => {});
    await unlink(temp).catch(() => {});
    throw error;
  }
}
function newKey(state: "current" | "verification_only"): AuthorityPrivateKey {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }),
    jwk = privateKey.export({ format: "jwk" });
  if (!jwk.x || !jwk.y || !jwk.d) throw new Error("key generation failed");
  return {
    kid: crypto.randomUUID().replaceAll("-", ""),
    alg: "ES256",
    kty: "EC",
    crv: "P-256",
    x: jwk.x,
    y: jwk.y,
    d: jwk.d,
    state,
    activatedAt: required("activated-at"),
    retireAt: null,
  };
}
function checkExpected(ring: AuthorityRingFile, digest: string) {
  if (
    ring.revision !== required("expected-revision") ||
    ring.authorityEpoch !== required("expected-epoch") ||
    digest !== required("expected-digest")
  )
    throw new Error("expected prior revision/digest/epoch conflict");
}
const increment = (value: string) => (BigInt(value) + 1n).toString();
async function main() {
  const cfg = config(),
    output = required("output");
  let ring: AuthorityRingFile;
  if (command === "initialize") {
    ring = {
      schemaVersion: 1,
      revision: "1",
      authorityEpoch: "1",
      currentKid: "",
      keys: [newKey("current")],
    };
    ring.currentKid = ring.keys[0]!.kid;
  } else {
    const prior = await load(required("input")),
      digest = authorityRingDigest(prior, cfg);
    checkExpected(prior, digest);
    if (command === "publish") {
      const key = newKey("verification_only");
      ring = {
        ...prior,
        revision: increment(prior.revision),
        authorityEpoch: increment(prior.authorityEpoch),
        keys: [...prior.keys, key].sort((a, b) =>
          Buffer.compare(Buffer.from(a.kid), Buffer.from(b.kid)),
        ),
      };
      const promoted = parseAuthorityRingFile({
        ...ring,
        revision: increment(ring.revision),
        authorityEpoch: increment(ring.authorityEpoch),
        currentKid: key.kid,
        keys: ring.keys.map((item) => ({
          ...item,
          state:
            item.kid === key.kid
              ? "current"
              : item.kid === prior.currentKid
                ? "verification_only"
                : item.state,
        })),
      });
      validateThreeDigestPlan(
        publicAuthorityRing(prior, cfg),
        publicAuthorityRing(parseAuthorityRingFile(ring), cfg),
        publicAuthorityRing(promoted, cfg),
      );
    } else if (command === "promote") {
      const kid = required("kid");
      ring = {
        ...prior,
        revision: increment(prior.revision),
        authorityEpoch: increment(prior.authorityEpoch),
        currentKid: kid,
        keys: prior.keys.map((k) => ({
          ...k,
          state:
            k.kid === kid ? "current" : k.kid === prior.currentKid ? "verification_only" : k.state,
        })),
      };
      const base = await load(required("base"));
      validateThreeDigestPlan(
        publicAuthorityRing(base, cfg),
        publicAuthorityRing(prior, cfg),
        publicAuthorityRing(parseAuthorityRingFile(ring), cfg),
      );
    } else if (command === "retire") {
      const kid = required("kid"),
        target = prior.keys.find((key) => key.kid === kid),
        proof = validateFrozenSigningJournalProof(
          await loadPrivateJson(required("signing-journal-proof")),
          { deploymentId: cfg.deploymentId, kid },
        ),
        cutoff = BigInt(proof.cutoff),
        now = BigInt(required("effective-at"));
      if (target?.state !== "verification_only" || target.retireAt !== null)
        throw new Error("only an unretired verification-only key may retire");
      if (now < BigInt(authorityRetirementFloor(cutoff.toString())))
        throw new Error("retirement floor not reached");
      ring = {
        ...prior,
        revision: increment(prior.revision),
        authorityEpoch: increment(prior.authorityEpoch),
        keys: prior.keys.map((k) => (k.kid === kid ? { ...k, retireAt: now.toString() } : k)),
      };
    } else if (command === "revoke") {
      const kid = required("kid");
      if (
        kid === prior.currentKid &&
        !prior.keys.some((k) => k.kid !== kid && k.state !== "revoked")
      )
        throw new Error("cannot revoke sole signer");
      const replacement = required("replacement-kid"),
        replacementKey = prior.keys.find((k) => k.kid === replacement);
      if (!replacementKey || replacementKey.state === "revoked" || replacement === kid)
        throw new Error("replacement signer is invalid");
      if (kid !== prior.currentKid && replacement !== prior.currentKid)
        throw new Error("verification-only revocation must retain current signer");
      ring = {
        ...prior,
        revision: increment(prior.revision),
        authorityEpoch: increment(prior.authorityEpoch),
        currentKid: replacement,
        keys: prior.keys.map((k) => ({
          ...k,
          state: k.kid === kid ? "revoked" : k.kid === replacement ? "current" : k.state,
        })),
      };
    } else throw new Error("command must be initialize, publish, promote, retire, or revoke");
  }
  ring = parseAuthorityRingFile(ring);
  await write(output, ring);
  const digest = authorityRingDigest(ring, cfg);
  process.stdout.write(
    `${JSON.stringify({ revision: ring.revision, digest, authorityEpoch: ring.authorityEpoch, currentKid: ring.currentKid })}\n`,
  );
}
await main();
