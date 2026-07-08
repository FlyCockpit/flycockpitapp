// Database seed logic.
//
// This file exports `runSeed()` so the SAME function can be invoked three ways
// without duplicating logic:
//
//   1. CLI               — `prisma db seed` → prisma/seed.cli.ts calls runSeed()
//   2. BullMQ worker     — apps/worker/src/handlers/seed.ts calls runSeed()
//   3. Inline (no queue) — if you rip out BullMQ, the admin "Run seed" button
//      runs runSeed() synchronously inside the request. See
//      inline seed execution if the worker is removed.
//
// IMPORTANT — this is a template stub. It is intentionally empty. The admin
// "Run seed" button is a *mechanism*; this function is the *content*, and it is
// yours to write. Nothing here makes any safety guarantee about code you add:
//
//   * Make it IDEMPOTENT. The button can be clicked repeatedly; use `upsert`
//     (not `create`) and guard against duplicate rows / unique-constraint
//     crashes on re-run.
//   * Keep it SHORT if you ever run it via the inline (no-queue) path — that
//     path blocks the HTTP request and cannot be cancelled mid-write. A seed
//     that takes longer than a few seconds must stay on the BullMQ queue.
//   * Push a human-readable line into `summary` for each thing you do — the
//     admin page renders them verbatim so the operator can see what happened.
//
// Reuses the shared, adapter-configured Prisma client (one connection, correct
// driver wiring) instead of `new PrismaClient()`. Do NOT call `$disconnect()`
// here — the client is shared with the worker/server process. The CLI wrapper
// (seed.cli.ts) owns disconnect for the standalone `prisma db seed` case.
import prisma from "../src/index";

export type SeedResult = {
  /** One line per thing the seed did, rendered verbatim in the admin UI. */
  summary: string[];
};

export async function runSeed(): Promise<SeedResult> {
  const summary: string[] = [];

  // ───────────────────────────────────────────────────────────────────────
  // Add your seed data here. Example (delete this block when you write one):
  //
  //   const admin = await prisma.user.upsert({
  //     where: { email: "admin@example.com" },
  //     update: {},
  //     create: { email: "admin@example.com", name: "Admin", role: "admin" },
  //   });
  //   summary.push(`Ensured admin user ${admin.email}`);
  // ───────────────────────────────────────────────────────────────────────

  // Touches the shared client so the empty stub still type-checks the import.
  // Delete this line as soon as you add a real seed statement above.
  void prisma;

  return { summary };
}
