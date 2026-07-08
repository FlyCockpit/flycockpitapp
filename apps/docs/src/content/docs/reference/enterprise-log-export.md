---
title: Enterprise Log Export
---

Enterprise deployments can mandate source-redacted cockpit-cli session log sync for org-owned accounts and generate fine-tuning artifacts from the collected events.

## Manual verification

1. Start an enterprise-profile deployment with a valid license file and object storage configured.
2. Sign in as an admin and open `/admin/enterprise`.
3. Bootstrap the enterprise org, enable mandated collection, and confirm the policy version increments.
4. Seed fixture events for two member-owned instances through the enterprise ingest endpoint.
5. Queue one raw NDJSON export and one chat JSONL export.
6. Download both artifacts when ready.
7. Sanity-check JSONL locally:

   ```sh
   python - <<'PY'
   import json, pathlib
   for path in pathlib.Path('.').glob('*.jsonl'):
       for line in path.read_text().splitlines():
           json.loads(line)
   PY
   ```

Each artifact is accompanied by a manifest with event, session, user, instance, and event-kind counts. Audit rows are written for export creation, completion, failure, and download.
