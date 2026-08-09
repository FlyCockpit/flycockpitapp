import { execFile } from "node:child_process";
import { chmod, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const exec = promisify(execFile),
  root = resolve(import.meta.dirname, "../../../.."),
  script = resolve(root, "scripts/remote-authority-keys.ts"),
  common = [
    "--issuer",
    "https://authority.example",
    "--deployment-id",
    "prod_1",
    "--activated-at",
    "1",
  ];

async function run(args: string[]) {
  const result = await exec("pnpm", ["exec", "tsx", script, ...args], { cwd: root });
  return JSON.parse(result.stdout) as {
    revision: string;
    digest: string;
    authorityEpoch: string;
    currentKid: string;
  };
}

describe("remote_authority_key_cli_state_machine", () => {
  it("initializes, publishes, promotes, retires and revokes through explicit private paths", async () => {
    const dir = await mkdtemp(resolve(tmpdir(), "remote-authority-cli-"));
    await chmod(dir, 0o700);
    const d0Path = resolve(dir, "d0.json"),
      d1Path = resolve(dir, "d1.json"),
      d2Path = resolve(dir, "d2.json"),
      retiredPath = resolve(dir, "retired.json"),
      revokedPath = resolve(dir, "revoked.json"),
      proofPath = resolve(dir, "proof.json"),
      d0 = await run(["initialize", ...common, "--output", d0Path]),
      d1 = await run([
        "publish",
        ...common,
        "--input",
        d0Path,
        "--output",
        d1Path,
        "--expected-revision",
        d0.revision,
        "--expected-digest",
        d0.digest,
        "--expected-epoch",
        d0.authorityEpoch,
      ]),
      d1Ring = JSON.parse(await readFile(d1Path, "utf8")) as { keys: Array<{ kid: string }> },
      k1 = d1Ring.keys.find((key) => key.kid !== d0.currentKid)!.kid,
      d2 = await run([
        "promote",
        ...common,
        "--input",
        d1Path,
        "--base",
        d0Path,
        "--output",
        d2Path,
        "--kid",
        k1,
        "--expected-revision",
        d1.revision,
        "--expected-digest",
        d1.digest,
        "--expected-epoch",
        d1.authorityEpoch,
      ]);
    await writeFile(
      proofPath,
      JSON.stringify({
        schemaVersion: 1,
        deploymentId: "prod_1",
        kid: d0.currentKid,
        state: "frozen",
        cutoff: "100",
        frozenAt: "101",
        rows: [{ mintId: "mint-1", state: "finalized", signedAt: "100" }],
      }),
      { mode: 0o600 },
    );
    const retireArgs = [
      "retire",
      ...common,
      "--input",
      d2Path,
      "--output",
      retiredPath,
      "--kid",
      d0.currentKid,
      "--signing-journal-proof",
      proofPath,
      "--expected-revision",
      d2.revision,
      "--expected-digest",
      d2.digest,
      "--expected-epoch",
      d2.authorityEpoch,
    ];
    await expect(run([...retireArgs, "--effective-at", "2592159"])).rejects.toThrow();
    await writeFile(
      proofPath,
      JSON.stringify({
        schemaVersion: 1,
        deploymentId: "other",
        kid: d0.currentKid,
        state: "frozen",
        cutoff: "100",
        frozenAt: "101",
        rows: [{ mintId: "mint-1", state: "finalized", signedAt: "100" }],
      }),
      { mode: 0o600 },
    );
    await expect(run([...retireArgs, "--effective-at", "2592160"])).rejects.toThrow();
    await writeFile(
      proofPath,
      JSON.stringify({
        schemaVersion: 1,
        deploymentId: "prod_1",
        kid: d0.currentKid,
        state: "frozen",
        cutoff: "100",
        frozenAt: "101",
        rows: [{ mintId: "mint-1", state: "finalized", signedAt: "100" }],
      }),
      { mode: 0o600 },
    );
    const retired = await run([...retireArgs, "--effective-at", "2592160"]);
    expect(retired.revision).toBe("4");
    const revoked = await run([
      "revoke",
      ...common,
      "--input",
      d1Path,
      "--output",
      revokedPath,
      "--kid",
      k1,
      "--replacement-kid",
      d0.currentKid,
      "--expected-revision",
      d1.revision,
      "--expected-digest",
      d1.digest,
      "--expected-epoch",
      d1.authorityEpoch,
    ]);
    expect(revoked.currentKid).toBe(d0.currentKid);
    for (const path of [d0Path, d1Path, d2Path, retiredPath, revokedPath])
      expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect(JSON.stringify({ d0, d1, d2, retired, revoked })).not.toContain('"d":');
  }, 30_000);

  it("rejects stale expectations and malformed cutoff proof before publishing output", async () => {
    const dir = await mkdtemp(resolve(tmpdir(), "remote-authority-cli-conflict-"));
    await chmod(dir, 0o700);
    const input = resolve(dir, "input.json"),
      output = resolve(dir, "output.json");
    const initialized = await run(["initialize", ...common, "--output", input]);
    await expect(
      run([
        "publish",
        ...common,
        "--input",
        input,
        "--output",
        output,
        "--expected-revision",
        "0",
        "--expected-digest",
        initialized.digest,
        "--expected-epoch",
        initialized.authorityEpoch,
      ]),
    ).rejects.toThrow();
    await expect(readFile(output)).rejects.toThrow();
    await expect(
      run([
        "revoke",
        ...common,
        "--input",
        input,
        "--output",
        output,
        "--kid",
        initialized.currentKid,
        "--replacement-kid",
        "missing",
        "--expected-revision",
        initialized.revision,
        "--expected-digest",
        initialized.digest,
        "--expected-epoch",
        initialized.authorityEpoch,
      ]),
    ).rejects.toThrow("cannot revoke sole signer");
    await expect(
      run([
        "promote",
        ...common,
        "--input",
        input,
        "--base",
        input,
        "--output",
        output,
        "--kid",
        "missing",
        "--expected-revision",
        initialized.revision,
        "--expected-digest",
        initialized.digest,
        "--expected-epoch",
        initialized.authorityEpoch,
      ]),
    ).rejects.toThrow();

    await expect(
      run([
        "revoke",
        ...common,
        "--input",
        input,
        "--output",
        output,
        "--kid",
        "missing",
        "--replacement-kid",
        initialized.currentKid,
        "--expected-revision",
        initialized.revision,
        "--expected-digest",
        initialized.digest,
        "--expected-epoch",
        initialized.authorityEpoch,
      ]),
    ).rejects.toThrow("revocation target is invalid");

    await expect(run(["initialize", ...common, "--output", input])).rejects.toThrow(
      "output path already exists",
    );

    await expect(
      run([
        "publish",
        ...common,
        "--input",
        input,
        "--output",
        input,
        "--expected-revision",
        initialized.revision,
        "--expected-digest",
        initialized.digest,
        "--expected-epoch",
        initialized.authorityEpoch,
      ]),
    ).rejects.toThrow("output must be an explicit different absolute path");
  });
});
