import { readFileSync } from "node:fs";

const cargo = readFileSync(new URL("../Cargo.toml", import.meta.url), "utf8");
const provenance = JSON.parse(readFileSync(new URL("../PROVENANCE.json", import.meta.url), "utf8"));
const required = [
  ["snow", "=0.10.0"],
  ["wasm-bindgen", "=0.2.126"],
  ["getrandom", "=0.3.4"],
  ["uniffi", "=0.29.4"],
  ["uniffi_bindgen", "=0.29.4"],
  ["uniffi_build", "=0.29.4"],
];
for (const [name, version] of required) {
  if (!cargo.includes(`${name} =`) || !cargo.includes(version)) {
    throw new Error(`remote Noise pin drift: ${name} ${version}`);
  }
}
if (
  provenance.tools["wasm-bindgen-cli"] !== "0.2.126" ||
  provenance.tools["wasm-pack"] !== "0.13.1"
) {
  throw new Error("remote Noise tool pin drift");
}
if (!cargo.includes('target_arch = "wasm32"') || cargo.match(/wasm_js/g)?.length !== 1) {
  throw new Error("wasm_js must occur exactly once in the wasm32 target dependency");
}
for (const forbidden of ["ring", "openssl", "sodium", "libp2p"]) {
  if (cargo.toLowerCase().includes(forbidden))
    throw new Error(`forbidden crypto backend: ${forbidden}`);
}
