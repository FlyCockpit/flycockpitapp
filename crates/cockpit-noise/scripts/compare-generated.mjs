import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { relative, resolve } from "node:path";

function manifest(root) {
  const absolute = resolve(root);
  const files = [];
  function visit(directory) {
    for (const name of readdirSync(directory).sort()) {
      const path = resolve(directory, name);
      if (statSync(path).isDirectory()) visit(path);
      else {
        files.push([
          relative(absolute, path),
          createHash("sha256").update(readFileSync(path)).digest("hex"),
        ]);
      }
    }
  }
  visit(absolute);
  return JSON.stringify(files);
}

const [first, second] = process.argv.slice(2);
if (!first || !second || manifest(first) !== manifest(second)) {
  throw new Error("remote Noise generated bindings are not reproducible");
}
