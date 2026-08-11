import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";

const commit = "cfe25410979a87391bb9ac8d4d4bef64e9f268c6";
const expected = "e1b0c4100b6c6e76378705a4954c3293f3752a55b586a3a252cecbfc937538c9";
const url = `https://raw.githubusercontent.com/rweather/noise-c/${commit}/tests/vector/cacophony.txt`;
const response = await fetch(url);
if (!response.ok) throw new Error(`source_fetch_failed:${response.status}`);
const source = Buffer.from(await response.arrayBuffer());
if (createHash("sha256").update(source).digest("hex") !== expected)
  throw new Error("source_hash_mismatch");
const parsed = JSON.parse(source.toString("utf8"));
const vectors = parsed.vectors.filter(
  (vector) => vector.name === "Noise_NN_25519_ChaChaPoly_SHA256",
);
if (vectors.length === 0) throw new Error("zero_official_vectors");
await writeFile(
  new URL("../fixtures/noise-c-nn-25519-chachapoly-sha256.extracted.json", import.meta.url),
  `${JSON.stringify({ commit, sourceSha256: expected, vectors }, null, 2)}\n`,
  { flag: "wx" },
);
