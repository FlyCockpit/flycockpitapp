---
title: CLI Device Login Manual Verification
---

Use this smoke test after starting the web/server stack with a browser signed in to the account that will own the instance.

## Flow

1. Request a device code as the CLI client:

   ```sh
   curl -sS -X POST "$SERVER_URL/api/auth/device/code" \
     -H 'content-type: application/json' \
     -d '{"client_id":"cockpit-cli","scope":"account:instance"}'
   ```

2. Open the returned `verification_uri_complete` in the browser, or visit `/$lang/device?user_code=<user_code>`.

3. Approve the code. The page first claims the code with `GET /api/auth/device?user_code=<user_code>`, then posts approve/deny through Better Auth.

4. Poll the token endpoint from the stub CLI until approval succeeds. Better Auth may return snake_case fields, and pending authorization is an expected 400 response while the browser step is incomplete.

5. Register the instance through oRPC. Raw callers must use the oRPC envelope:

   ```sh
   curl -sS -X POST "$SERVER_URL/rpc/instances/register" \
     -H 'content-type: application/json' \
     -H "cookie: better-auth.session_token=<session-token-from-device-flow>" \
     -d '{"json":{"hostname":"devbox","os":"linux","arch":"x64","cliVersion":"0.1.0"}}'
   ```

6. Confirm the response contains `json.instanceId`, `json.instanceToken`, and `json.account`. Store the instance token once; the server keeps only its digest and lookup prefix.

7. Mint a connector token:

   ```sh
   curl -sS -X POST "$SERVER_URL/rpc/instances/mintConnectorToken" \
     -H 'content-type: application/json' \
     -d '{"json":{"instanceId":"<instance-id>","instanceToken":"<instance-token>"}}'
   ```

8. Visit `/$lang/instances`, confirm the instance appears, revoke it, then repeat step 7 and confirm the revoked instance receives a forbidden response.
