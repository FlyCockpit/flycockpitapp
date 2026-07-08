// Standalone CLI entry for `prisma db seed` (wired via the `prisma.seed`
// field in package.json). Keeps seed.ts free of side effects on import so the
// BullMQ worker and the inline (no-queue) admin path can both `import { runSeed }`
// without executing it. This wrapper owns process lifecycle: run, print the
// summary, disconnect the shared client, exit with the right code.
import prisma from "../src/index";
import { runSeed } from "./seed";

runSeed()
  .then((result) => {
    if (result.summary.length === 0) {
      console.log("[seed] Done — seed script is empty (nothing to seed).");
    } else {
      console.log("[seed] Done:");
      for (const line of result.summary) console.log(`  • ${line}`);
    }
  })
  .catch((error) => {
    console.error("[seed] Failed:", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
