import {
  activateDuePolicies,
  PostgresPolicyStore,
  type SqlClient,
} from "@flycockpit/api/lib/remote-public-policy-storage";
import prisma from "@flycockpit/db";
import type { ActivateDuePoliciesJobData } from "@flycockpit/queue";
import type { Job } from "bullmq";

/**
 * BullMQ wakeup for the public-service-policy activation state machine. The job
 * carries no correctness payload: every predicate is a DB-time check inside the
 * store, so this handler just drives the production {@link activateDuePolicies}
 * scan over the Postgres rows and resumes from durable state on every firing.
 */
export async function handleActivateDuePoliciesJob(job: Job<ActivateDuePoliciesJobData>) {
  const store = new PostgresPolicyStore(prisma as unknown as SqlClient);
  const outcomes = await activateDuePolicies({ store });
  return { jobId: job.id, advanced: outcomes.length, outcomes };
}
