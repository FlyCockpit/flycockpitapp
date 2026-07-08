import { useSessionBridge } from "@/hooks/use-session-bridge";

/**
 * Headless bridge that activates the real better-auth session subscription and
 * feeds it into `useSessionStore`. Mounted lazily (React.lazy) from the root so
 * the better-auth client + its `get-session` request load AFTER first paint
 * instead of competing with hydration. Renders nothing.
 */
export default function SessionSync() {
  useSessionBridge();
  return null;
}
