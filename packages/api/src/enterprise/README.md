# Enterprise Boundary

Everything in this directory is licensed under the FlyCockpit Enterprise License (see `LICENSE` in this directory), not the Apache License 2.0 that covers the rest of the repository. Enterprise-only routers and services live here so future extraction to a private package remains mechanical.

Core code must not import statically from this directory. The only sanctioned references are profile-gated dynamic imports at composition points — currently `packages/api/src/routers/index.ts` (router mount) and `apps/worker/src/index.ts` (queue handler) — so that `oss` deployments never load or execute this code. Modules reachable *only* through those gated imports (currently `apps/worker/src/handlers/enterprise-log-export.ts`) may import this directory statically; they are part of the gated surface. Type-only imports and test files are fine anywhere; type imports are erased at compile time, and development/testing use is permitted by the license.
