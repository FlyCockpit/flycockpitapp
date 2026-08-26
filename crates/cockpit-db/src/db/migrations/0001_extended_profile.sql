-- Deferred local product domains excluded from the public local-v0.1 schema.
-- Enabled only by the explicit `extended` local-capability build profile.

-- ---- scheduled_jobs --------------------------------------------------------

CREATE TABLE scheduled_jobs (
    id                TEXT    PRIMARY KEY,
    owner             TEXT    NOT NULL,
    schedule_json     TEXT    NOT NULL CHECK (
        json_valid(schedule_json) AND json_type(schedule_json) = 'object'
        AND length(CAST(schedule_json AS BLOB)) <= 65536
    ),
    payload_json      TEXT    NOT NULL CHECK (
        json_valid(payload_json)
        AND length(CAST(payload_json AS BLOB)) <= 1048576
    ),
    enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    missed_run_policy TEXT    NOT NULL CHECK (missed_run_policy IN ('skip', 'run_once_on_start')),
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL CHECK (updated_at >= created_at),
    last_run_at       INTEGER,
    next_run_at       INTEGER,
    last_result_json  TEXT CHECK (
        last_result_json IS NULL OR (
            json_valid(last_result_json)
            AND length(CAST(last_result_json AS BLOB)) <= 1048576
        )
    ),
    failure_count     INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    backoff_until     INTEGER,
    disabled_notice   TEXT
);

CREATE INDEX idx_scheduled_jobs_next_run
    ON scheduled_jobs(enabled, next_run_at);

CREATE INDEX idx_scheduled_jobs_owner
    ON scheduled_jobs(owner);

-- Explicit, versioned image-generation monetary policy. JSON is validated by
-- the typed boundary before insertion; old versions remain referenced by the
-- immutable ledger and are never rewritten by a settings change.
CREATE TABLE image_spend_policy_versions (
    project_key  TEXT NOT NULL,
    version      INTEGER NOT NULL CHECK(version >= 1),
    epoch_policy_version INTEGER NOT NULL CHECK(epoch_policy_version >= 1),
    settings_json TEXT NOT NULL,
    saved_at_ms  INTEGER NOT NULL,
    -- Server-owned rolling-epoch anchor. Present iff the policy's project_epoch
    -- is Rolling; the anchor is never stored inside settings_json so it can
    -- never be supplied or altered through the user-constructible settings type.
    rolling_anchor_unix_ms INTEGER,
    rolling_anchor_sequence INTEGER CHECK(rolling_anchor_sequence IS NULL OR rolling_anchor_sequence >= 1),
    PRIMARY KEY(project_key, version),
    CHECK((rolling_anchor_unix_ms IS NULL) = (rolling_anchor_sequence IS NULL))
);

CREATE TABLE image_spend_reservations (
    reservation_id TEXT PRIMARY KEY,
    plan_digest TEXT NOT NULL,
    session_id TEXT NOT NULL,
    project_key TEXT NOT NULL,
    policy_version INTEGER NOT NULL CHECK(policy_version >= 1),
    epoch_policy_version INTEGER NOT NULL CHECK(epoch_policy_version >= 1),
    epoch_sequence INTEGER NOT NULL CHECK(epoch_sequence >= 0),
    reserved_usd_micros BLOB CHECK(reserved_usd_micros IS NULL OR length(reserved_usd_micros)=8),
    cost_unknown INTEGER NOT NULL CHECK(cost_unknown IN (0,1)),
    state TEXT NOT NULL CHECK(state IN ('reserved','released','reconciled','budget_violation')),
    release_proof_identity TEXT,
    created_at_ms INTEGER NOT NULL,
    released_at_ms INTEGER,
    FOREIGN KEY(project_key,policy_version) REFERENCES image_spend_policy_versions(project_key,version) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK((cost_unknown=1 AND reserved_usd_micros IS NULL) OR (cost_unknown=0 AND reserved_usd_micros IS NOT NULL))
);

CREATE TABLE image_spend_attempts (
    reservation_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    maximum_usd_micros BLOB CHECK(maximum_usd_micros IS NULL OR length(maximum_usd_micros)=8),
    PRIMARY KEY(reservation_id,attempt_id),
    FOREIGN KEY(reservation_id) REFERENCES image_spend_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

-- One immutable external-effect identity per paid attempt. The referenced
-- journal row is prepared in the same transaction as this binding and must
-- reach `dispatching` before provider contact. Acceptance ambiguity and
-- definitive rejection therefore come only from the generic journal graph.
CREATE TABLE image_spend_attempt_dispatches (
    reservation_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    external_operation_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY(reservation_id,attempt_id),
    FOREIGN KEY(reservation_id,attempt_id) REFERENCES image_spend_attempts(reservation_id,attempt_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY(external_operation_id) REFERENCES external_journal_operations(operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE image_spend_scope_usage (
    reservation_id TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK(scope_kind IN ('request','session','project')),
    scope_key TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    epoch_policy_version INTEGER NOT NULL CHECK(epoch_policy_version >= 0),
    epoch_sequence INTEGER NOT NULL CHECK(epoch_sequence >= 0),
    reserved_usd_micros BLOB NOT NULL CHECK(length(reserved_usd_micros)=8),
    charged_usd_micros BLOB NOT NULL CHECK(length(charged_usd_micros)=8),
    debt_usd_micros BLOB NOT NULL CHECK(length(debt_usd_micros)=8),
    PRIMARY KEY(reservation_id,scope_kind),
    FOREIGN KEY(reservation_id) REFERENCES image_spend_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE INDEX idx_image_spend_scope_budget ON image_spend_scope_usage(scope_kind,scope_key,policy_version,epoch_sequence);
CREATE INDEX idx_image_spend_reservation_policy ON image_spend_reservations(project_key,policy_version);

-- Raw provider billing payloads are intentionally absent. Only a normalized,
-- non-secret evidence reference and authoritative integer amount are durable.
CREATE TABLE image_spend_cost_events (
    cost_identity TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    actual_usd_micros BLOB NOT NULL CHECK(length(actual_usd_micros)=8),
    evidence_ref TEXT NOT NULL,
    recorded_at_ms INTEGER NOT NULL,
    FOREIGN KEY(reservation_id,attempt_id) REFERENCES image_spend_attempts(reservation_id,attempt_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE INDEX idx_image_spend_cost_reservation ON image_spend_cost_events(reservation_id);
CREATE UNIQUE INDEX uq_image_spend_cost_attempt ON image_spend_cost_events(reservation_id,attempt_id);

CREATE TABLE image_spend_debt_resolutions (
    reservation_id TEXT NOT NULL,
    resolution_ref TEXT NOT NULL,
    resolved_debt_usd_micros BLOB NOT NULL CHECK(length(resolved_debt_usd_micros)=8 AND resolved_debt_usd_micros <> X'0000000000000000'),
    resolved_at_ms INTEGER NOT NULL,
    PRIMARY KEY(reservation_id,resolution_ref),
    FOREIGN KEY(reservation_id) REFERENCES image_spend_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE image_spend_epoch_heads (
    project_key TEXT NOT NULL,
    epoch_policy_version INTEGER NOT NULL,
    epoch_sequence INTEGER NOT NULL CHECK(epoch_sequence >= 1),
    membership_key TEXT NOT NULL,
    interval_start_ms INTEGER NOT NULL,
    resolved_at_ms INTEGER NOT NULL,
    PRIMARY KEY(project_key,epoch_policy_version)
);

-- Provider-neutral image generation. Plans are immutable canonical bytes;
-- mutable projections cite monotonically increasing row and journal versions.
CREATE TABLE image_generation_plans (
    job_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    plan_digest TEXT NOT NULL UNIQUE CHECK(length(plan_digest) = 64),
    canonical_plan BLOB NOT NULL,
    slot_count INTEGER NOT NULL CHECK(slot_count > 0),
    max_attempt_count INTEGER NOT NULL CHECK(max_attempt_count > 0),
    deadline_boot_id TEXT NOT NULL CHECK(length(deadline_boot_id) = 36 AND deadline_boot_id <> '00000000-0000-0000-0000-000000000000'),
    enqueue_started_monotonic_ms INTEGER NOT NULL CHECK(enqueue_started_monotonic_ms >= 0),
    operation_deadline_monotonic_ms INTEGER NOT NULL,
    CHECK(operation_deadline_monotonic_ms > enqueue_started_monotonic_ms),
    UNIQUE(job_id,plan_digest)
);

CREATE TABLE image_generation_jobs (
    job_id TEXT PRIMARY KEY REFERENCES image_generation_plans(job_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('created','validating','awaiting_authorization','queued','dispatching','submission_unknown','running','cancellation_requested','downloading','validating_output','publishing','completed','completed_after_cancel','partially_failed','failed','cancelled')),
    version INTEGER NOT NULL CHECK(version >= 1),
    terminal_event_version INTEGER,
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    CHECK(terminal_event_version IS NULL OR terminal_event_version >= 1)
);

-- Terminal-event counts are a DISJOINT partition of the job's slots: every slot
-- contributes to EXACTLY ONE column, keyed by (state, and for published slots
-- the result_after_cancel bit). The six buckets are ordinary-published
-- (published & result_after_cancel=0), late-published-after-cancel
-- (published & result_after_cancel=1), failed, cancelled, late-still-quarantined
-- (late_quarantined), and discarded. Because the partitions are mutually
-- exclusive by construction and every terminal slot lands in one, the sum equals
-- slot_count identically -- not by an ordering accident. A late-then-published
-- slot is counted once (late_published_count), never double-counted as both
-- published and "late".
CREATE TABLE image_generation_terminal_events (
    event_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL UNIQUE REFERENCES image_generation_jobs(job_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    job_version INTEGER NOT NULL CHECK(job_version>=1),
    terminal_state TEXT NOT NULL CHECK(terminal_state IN ('completed','completed_after_cancel','partially_failed','failed','cancelled')),
    slot_count INTEGER NOT NULL CHECK(slot_count>0),
    published_count INTEGER NOT NULL CHECK(published_count>=0),
    failed_count INTEGER NOT NULL CHECK(failed_count>=0),
    cancelled_count INTEGER NOT NULL CHECK(cancelled_count>=0),
    late_published_count INTEGER NOT NULL CHECK(late_published_count>=0),
    late_quarantined_count INTEGER NOT NULL CHECK(late_quarantined_count>=0),
    discarded_count INTEGER NOT NULL CHECK(discarded_count>=0),
    emitted_at_unix_ms INTEGER NOT NULL,
    UNIQUE(job_id,job_version),
    CHECK(published_count+failed_count+cancelled_count+late_published_count+late_quarantined_count+discarded_count=slot_count)
);
CREATE TRIGGER image_generation_terminal_event_immutable BEFORE UPDATE ON image_generation_terminal_events BEGIN SELECT RAISE(ABORT,'image generation terminal event is immutable'); END;
CREATE TRIGGER image_generation_terminal_event_no_delete BEFORE DELETE ON image_generation_terminal_events BEGIN SELECT RAISE(ABORT,'image generation terminal event is immutable'); END;
CREATE TRIGGER image_generation_terminal_event_insert_guard BEFORE INSERT ON image_generation_terminal_events
WHEN NOT EXISTS(
  SELECT 1 FROM image_generation_jobs j WHERE j.job_id=NEW.job_id AND j.terminal_event_version IS NULL AND NEW.job_version=j.version+1
) OR NEW.slot_count<>(SELECT count(*) FROM image_generation_slots s WHERE s.job_id=NEW.job_id)
 OR NEW.published_count<>(SELECT count(*) FROM image_generation_slots s WHERE s.job_id=NEW.job_id AND s.state='published' AND s.result_after_cancel=0)
 OR NEW.failed_count<>(SELECT count(*) FROM image_generation_slots s WHERE s.job_id=NEW.job_id AND s.state='failed')
 OR NEW.cancelled_count<>(SELECT count(*) FROM image_generation_slots s WHERE s.job_id=NEW.job_id AND s.state='cancelled')
 OR NEW.late_published_count<>(SELECT count(*) FROM image_generation_slots s WHERE s.job_id=NEW.job_id AND s.state='published' AND s.result_after_cancel=1)
 OR NEW.late_quarantined_count<>(SELECT count(*) FROM image_generation_slots s WHERE s.job_id=NEW.job_id AND s.state='late_quarantined')
 OR NEW.discarded_count<>(SELECT count(*) FROM image_generation_slots s WHERE s.job_id=NEW.job_id AND s.state='discarded')
 OR EXISTS(SELECT 1 FROM image_generation_slots s WHERE s.job_id=NEW.job_id AND s.state NOT IN ('published','failed','cancelled','discarded','late_quarantined'))
 OR NEW.terminal_state<>(CASE
   WHEN EXISTS(SELECT 1 FROM image_generation_slots s WHERE s.job_id=NEW.job_id AND s.result_after_cancel=1) THEN 'completed_after_cancel'
   WHEN NEW.published_count=NEW.slot_count THEN 'completed'
   WHEN NEW.published_count>0 THEN 'partially_failed'
   WHEN NEW.failed_count>0 THEN 'failed'
   ELSE 'cancelled' END)
BEGIN SELECT RAISE(ABORT,'image generation terminal event projection differs'); END;
CREATE TRIGGER image_generation_job_terminal_event_required BEFORE UPDATE ON image_generation_jobs
WHEN NEW.state IN ('completed','completed_after_cancel','partially_failed','failed','cancelled')
 AND NOT EXISTS(SELECT 1 FROM image_generation_terminal_events e WHERE e.job_id=NEW.job_id AND e.job_version=NEW.version AND e.terminal_state=NEW.state AND NEW.terminal_event_version=NEW.version)
BEGIN SELECT RAISE(ABORT,'image generation terminal state requires exact event'); END;
CREATE TRIGGER image_generation_job_terminal_event_forbidden BEFORE UPDATE ON image_generation_jobs
WHEN NEW.state NOT IN ('completed','completed_after_cancel','partially_failed','failed','cancelled') AND NEW.terminal_event_version IS NOT NULL
BEGIN SELECT RAISE(ABORT,'nonterminal image generation job cannot cite terminal event'); END;

-- Durable bookkeeping for the scheduler-error attention threshold. One row per
-- (worker_boot_id, job_id, slot_id, attempt_number, stage). `failure_count` is
-- incremented once per recorded scheduler pass error. When it reaches the
-- attention threshold a SINGLE `needs_attention` row is raised and its id is
-- stamped into `attention_interrupt_id`; further failures for the same tuple in
-- the same boot bump `failure_count`/`last_failed_at_unix_ms` but never raise a
-- second attention row. This is bookkeeping only -- the operator attention
-- channel remains the shared `needs_attention` table.
CREATE TABLE image_generation_scheduler_error_counts (
    worker_boot_id TEXT NOT NULL CHECK(length(worker_boot_id)=36 AND worker_boot_id<>'00000000-0000-0000-0000-000000000000'),
    job_id TEXT NOT NULL,
    slot_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK(attempt_number>=1),
    stage TEXT NOT NULL,
    failure_count INTEGER NOT NULL CHECK(failure_count>=1),
    attention_interrupt_id TEXT,
    first_failed_at_unix_ms INTEGER NOT NULL,
    last_failed_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY(worker_boot_id, job_id, slot_id, attempt_number, stage)
);

CREATE TABLE image_generation_slots (
    job_id TEXT NOT NULL REFERENCES image_generation_jobs(job_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    slot_id TEXT NOT NULL,
    slot_index INTEGER NOT NULL CHECK(slot_index >= 0),
    sample_index INTEGER NOT NULL CHECK(sample_index >= 0),
    managed_artifact_id TEXT NOT NULL,
    max_attempt_count INTEGER NOT NULL CHECK(max_attempt_count > 0),
    state TEXT NOT NULL CHECK(state IN ('planned','queued','dispatching','submission_unknown','running','cancellation_requested','downloading','validating','ready_to_publish','published','late_quarantined','failed','cancelled','discarded')),
    version INTEGER NOT NULL CHECK(version >= 1),
    applied_cancellation_version INTEGER,
    result_after_cancel INTEGER NOT NULL DEFAULT 0 CHECK(result_after_cancel IN (0,1)),
    published_disposition TEXT CHECK(published_disposition IN ('ordinary','late_authorized')),
    published_disposition_generation INTEGER CHECK(published_disposition_generation>=1),
    failure_reason TEXT,
    PRIMARY KEY(job_id,slot_id),
    UNIQUE(job_id,slot_index),
    UNIQUE(managed_artifact_id),
    CHECK(
      (state IN ('planned','queued','ready_to_publish') AND applied_cancellation_version IS NULL AND result_after_cancel=0) OR
      (state IN ('dispatching','submission_unknown','running','downloading') AND result_after_cancel=0) OR
      (state='cancellation_requested' AND applied_cancellation_version IS NOT NULL AND result_after_cancel=0) OR
      (state='validating' AND ((applied_cancellation_version IS NULL AND result_after_cancel=0) OR (applied_cancellation_version IS NOT NULL AND result_after_cancel=1))) OR
      (state='published' AND ((applied_cancellation_version IS NULL AND result_after_cancel=0) OR (applied_cancellation_version IS NOT NULL AND result_after_cancel=1))) OR
      (state IN ('late_quarantined','discarded') AND applied_cancellation_version IS NOT NULL AND result_after_cancel=1) OR
      (state='cancelled' AND applied_cancellation_version IS NOT NULL AND result_after_cancel=0) OR
      (state='failed' AND ((applied_cancellation_version IS NULL AND result_after_cancel=0) OR applied_cancellation_version IS NOT NULL))
    ),
    CHECK((state='published' AND published_disposition IS NOT NULL AND published_disposition_generation=version) OR (state!='published' AND published_disposition IS NULL AND published_disposition_generation IS NULL))
);

CREATE TABLE image_generation_attempts (
    job_id TEXT NOT NULL,
    slot_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK(attempt_number >= 1),
    provider_request_identity TEXT NOT NULL,
    provider_idempotency_identity TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('planned','preparing','prepared','dispatching','accepted','submission_unknown','reconciling','running','downloading','cancellation_requested','response_adopted','failed_not_submitted','rejected_not_accepted','cancelled','succeeded','completed_after_cancel','failed_after_acceptance')),
    version INTEGER NOT NULL CHECK(version >= 1),
    external_operation_id TEXT UNIQUE,
    observed_journal_version INTEGER,
    applied_cancellation_version INTEGER,
    response_digest TEXT CHECK(response_digest IS NULL OR length(response_digest)=64),
    nonacceptance_evidence_digest TEXT CHECK(nonacceptance_evidence_digest IS NULL OR length(nonacceptance_evidence_digest)=64),
    -- Dispatch-time destination/health proof bound at prepare (never reused across
    -- a location-class or configuration-generation change; a stale proof cannot be
    -- reissued because prepare always re-runs revalidation and writes the fresh
    -- result under the single 'prepared' transition below). Credential material is
    -- never stored here -- only opaque endpoint/config/epoch identifiers and the
    -- connection observation (connected IP, location class, and a digest of the
    -- ordered connection hops).
    dispatch_proof_endpoint_id TEXT,
    dispatch_proof_config_generation INTEGER CHECK(dispatch_proof_config_generation IS NULL OR dispatch_proof_config_generation >= 0),
    dispatch_proof_refresh_epoch INTEGER CHECK(dispatch_proof_refresh_epoch IS NULL OR dispatch_proof_refresh_epoch >= 0),
    dispatch_proof_connected_ip TEXT,
    dispatch_proof_location_class TEXT CHECK(dispatch_proof_location_class IS NULL OR dispatch_proof_location_class IN ('loopback','private_lan','public_network','forbidden')),
    dispatch_proof_hops_digest TEXT CHECK(dispatch_proof_hops_digest IS NULL OR length(dispatch_proof_hops_digest)=64),
    PRIMARY KEY(job_id,slot_id,attempt_number),
    UNIQUE(provider_request_identity),
    UNIQUE(provider_idempotency_identity),
    FOREIGN KEY(job_id,slot_id) REFERENCES image_generation_slots(job_id,slot_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY(external_operation_id) REFERENCES external_journal_operations(operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK((external_operation_id IS NULL AND observed_journal_version IS NULL) OR (external_operation_id IS NOT NULL AND observed_journal_version >= 1)),
    -- The six proof columns are written as one indivisible group or not at all,
    -- so a half-written proof can never exist.
    CHECK((dispatch_proof_endpoint_id IS NULL AND dispatch_proof_config_generation IS NULL AND dispatch_proof_refresh_epoch IS NULL AND dispatch_proof_connected_ip IS NULL AND dispatch_proof_location_class IS NULL AND dispatch_proof_hops_digest IS NULL) OR (dispatch_proof_endpoint_id IS NOT NULL AND dispatch_proof_config_generation IS NOT NULL AND dispatch_proof_refresh_epoch IS NOT NULL AND dispatch_proof_connected_ip IS NOT NULL AND dispatch_proof_location_class IS NOT NULL AND dispatch_proof_hops_digest IS NOT NULL)),
    -- A 'prepared' or 'dispatching' attempt cannot exist without its proof: both
    -- states are reached in production only through prepare_image_generation_dispatch_conn
    -- (the single writer of 'prepared', which binds the full proof in the same
    -- UPDATE) and begin_image_generation_handoff_conn ('prepared' -> 'dispatching').
    -- This is the DB-level fail-closed invariant behind that single-writer discipline,
    -- so no attempt can be handed to a provider without a successful revalidation.
    CHECK(state NOT IN ('prepared','dispatching') OR dispatch_proof_endpoint_id IS NOT NULL)
);
CREATE TABLE image_generation_handoff_evidence (
 job_id TEXT NOT NULL, slot_id TEXT NOT NULL, attempt_number INTEGER NOT NULL,
 external_operation_id TEXT NOT NULL UNIQUE,
 outcome TEXT NOT NULL CHECK(outcome IN ('accepted','definitively_rejected','submission_unknown')),
 evidence BLOB NOT NULL CHECK(length(evidence) BETWEEN 1 AND 65536),
 evidence_digest TEXT NOT NULL CHECK(length(evidence_digest)=64),
 recorded_at_unix_ms INTEGER NOT NULL,
 PRIMARY KEY(job_id,slot_id,attempt_number),
 FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT,
 FOREIGN KEY(external_operation_id) REFERENCES external_journal_operations(operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TRIGGER image_generation_handoff_evidence_immutable BEFORE UPDATE ON image_generation_handoff_evidence BEGIN SELECT RAISE(ABORT,'image generation handoff evidence is immutable'); END;
CREATE TRIGGER image_generation_handoff_evidence_no_delete BEFORE DELETE ON image_generation_handoff_evidence BEGIN SELECT RAISE(ABORT,'image generation handoff evidence is immutable'); END;

CREATE TABLE image_generation_response_fetches (
 job_id TEXT NOT NULL, slot_id TEXT NOT NULL, attempt_number INTEGER NOT NULL,
 response_digest TEXT NOT NULL CHECK(length(response_digest)=64),
 response_bytes BLOB NOT NULL CHECK(length(response_bytes) BETWEEN 1 AND 67108864),
 fetch_evidence BLOB NOT NULL CHECK(length(fetch_evidence) BETWEEN 1 AND 65536),
 fetch_evidence_digest TEXT NOT NULL CHECK(length(fetch_evidence_digest)=64),
 fetched_at_unix_ms INTEGER NOT NULL,
 PRIMARY KEY(job_id,slot_id,attempt_number),
 FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TRIGGER image_generation_response_fetch_immutable BEFORE UPDATE ON image_generation_response_fetches BEGIN SELECT RAISE(ABORT,'image generation response fetch is immutable'); END;
CREATE TRIGGER image_generation_response_fetch_no_delete BEFORE DELETE ON image_generation_response_fetches BEGIN SELECT RAISE(ABORT,'image generation response fetch is immutable'); END;
CREATE TRIGGER image_generation_response_fetch_guard BEFORE INSERT ON image_generation_response_fetches
WHEN NOT EXISTS(SELECT 1 FROM image_generation_attempts a JOIN image_generation_handoff_evidence h USING(job_id,slot_id,attempt_number) WHERE a.job_id=NEW.job_id AND a.slot_id=NEW.slot_id AND a.attempt_number=NEW.attempt_number AND a.state IN ('accepted','downloading','cancellation_requested') AND h.outcome='accepted')
BEGIN SELECT RAISE(ABORT,'response fetch lacks accepted handoff authority'); END;
CREATE TABLE image_generation_response_fetch_outcomes (
 job_id TEXT NOT NULL, slot_id TEXT NOT NULL, attempt_number INTEGER NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN ('fetched','definitive_failure','outcome_unknown')),
 safe_reason TEXT CHECK((outcome='definitive_failure' AND length(safe_reason) BETWEEN 1 AND 128) OR (outcome!='definitive_failure' AND safe_reason IS NULL)),
 evidence BLOB NOT NULL CHECK(length(evidence) BETWEEN 1 AND 65536),
 evidence_digest TEXT NOT NULL CHECK(length(evidence_digest)=64),
 recorded_at_unix_ms INTEGER NOT NULL,
 PRIMARY KEY(job_id,slot_id,attempt_number),
 FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TRIGGER image_generation_response_fetch_outcome_immutable BEFORE UPDATE ON image_generation_response_fetch_outcomes BEGIN SELECT RAISE(ABORT,'image generation response fetch outcome is immutable'); END;
CREATE TRIGGER image_generation_response_fetch_outcome_no_delete BEFORE DELETE ON image_generation_response_fetch_outcomes BEGIN SELECT RAISE(ABORT,'image generation response fetch outcome is immutable'); END;
CREATE TRIGGER image_generation_response_fetch_outcome_guard BEFORE INSERT ON image_generation_response_fetch_outcomes
WHEN NOT EXISTS(SELECT 1 FROM image_generation_attempts a JOIN image_generation_handoff_evidence h USING(job_id,slot_id,attempt_number) WHERE a.job_id=NEW.job_id AND a.slot_id=NEW.slot_id AND a.attempt_number=NEW.attempt_number AND a.state IN ('accepted','downloading','cancellation_requested') AND h.outcome='accepted')
BEGIN SELECT RAISE(ABORT,'response fetch outcome lacks accepted handoff authority'); END;
CREATE TABLE image_generation_response_reconciliation_claims (
 job_id TEXT NOT NULL, slot_id TEXT NOT NULL, attempt_number INTEGER NOT NULL,
 claim_generation INTEGER NOT NULL CHECK(claim_generation>=1), worker_boot_id TEXT NOT NULL,
 claimed_at_unix_ms INTEGER NOT NULL, expires_at_unix_ms INTEGER NOT NULL CHECK(expires_at_unix_ms>claimed_at_unix_ms AND expires_at_unix_ms<=claimed_at_unix_ms+60000),
 PRIMARY KEY(job_id,slot_id,attempt_number,claim_generation),
 FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_response_fetch_outcomes(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TABLE image_generation_response_reconciliations (
 job_id TEXT NOT NULL, slot_id TEXT NOT NULL, attempt_number INTEGER NOT NULL, claim_generation INTEGER NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN ('fetched','definitive_failure','outcome_unknown')),
 safe_reason TEXT CHECK((outcome='definitive_failure' AND length(safe_reason) BETWEEN 1 AND 128) OR (outcome!='definitive_failure' AND safe_reason IS NULL)),
 evidence BLOB NOT NULL CHECK(length(evidence) BETWEEN 1 AND 65536), evidence_digest TEXT NOT NULL CHECK(length(evidence_digest)=64),
 response_digest TEXT CHECK((outcome='fetched')=(response_digest IS NOT NULL) AND (response_digest IS NULL OR length(response_digest)=64)), response_bytes BLOB CHECK((outcome='fetched')=(response_bytes IS NOT NULL) AND (response_bytes IS NULL OR length(response_bytes) BETWEEN 1 AND 67108864)),
 recorded_at_unix_ms INTEGER NOT NULL,
 PRIMARY KEY(job_id,slot_id,attempt_number,claim_generation),
 FOREIGN KEY(job_id,slot_id,attempt_number,claim_generation) REFERENCES image_generation_response_reconciliation_claims(job_id,slot_id,attempt_number,claim_generation) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TRIGGER image_generation_response_reconciliation_immutable BEFORE UPDATE ON image_generation_response_reconciliations BEGIN SELECT RAISE(ABORT,'image response reconciliation is immutable'); END;
CREATE TRIGGER image_generation_response_reconciliation_no_delete BEFORE DELETE ON image_generation_response_reconciliations BEGIN SELECT RAISE(ABORT,'image response reconciliation is immutable'); END;
CREATE TABLE image_generation_response_publication_intents (
 publication_operation_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, slot_id TEXT NOT NULL, attempt_number INTEGER NOT NULL,
 artifact_id TEXT NOT NULL UNIQUE, component_id TEXT NOT NULL UNIQUE, temporary_name TEXT NOT NULL, destination_name TEXT NOT NULL,
 response_digest TEXT NOT NULL CHECK(length(response_digest)=64), state TEXT NOT NULL CHECK(state IN ('pending','applied','security_blocked')),
 version INTEGER NOT NULL CHECK(version>=1), held_evidence_json TEXT, recovery_evidence_json TEXT, failure_evidence_digest TEXT,
 created_at_unix_ms INTEGER NOT NULL, decided_at_unix_ms INTEGER,
 FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CHECK((state='pending' AND held_evidence_json IS NULL AND recovery_evidence_json IS NULL AND failure_evidence_digest IS NULL AND decided_at_unix_ms IS NULL) OR (state='applied' AND held_evidence_json IS NOT NULL AND recovery_evidence_json IS NULL AND failure_evidence_digest IS NULL AND decided_at_unix_ms IS NOT NULL) OR (state='security_blocked' AND recovery_evidence_json IS NOT NULL AND failure_evidence_digest IS NOT NULL AND decided_at_unix_ms IS NOT NULL))
);
CREATE TRIGGER image_generation_response_publication_intent_guard BEFORE INSERT ON image_generation_response_publication_intents
WHEN NOT EXISTS(SELECT 1 FROM image_generation_response_fetches f JOIN image_generation_attempts a USING(job_id,slot_id,attempt_number) WHERE f.job_id=NEW.job_id AND f.slot_id=NEW.slot_id AND f.attempt_number=NEW.attempt_number AND f.response_digest=NEW.response_digest AND a.state IN ('accepted','downloading','cancellation_requested','response_adopted','completed_after_cancel'))
BEGIN SELECT RAISE(ABORT,'response publication intent lacks fetched authority'); END;
CREATE TRIGGER image_generation_response_publication_intent_transition BEFORE UPDATE ON image_generation_response_publication_intents
WHEN OLD.state!='pending' OR NEW.version!=OLD.version+1 OR NEW.state NOT IN ('applied','security_blocked') OR NEW.publication_operation_id!=OLD.publication_operation_id OR NEW.job_id!=OLD.job_id OR NEW.slot_id!=OLD.slot_id OR NEW.attempt_number!=OLD.attempt_number OR NEW.artifact_id!=OLD.artifact_id OR NEW.component_id!=OLD.component_id OR NEW.temporary_name!=OLD.temporary_name OR NEW.destination_name!=OLD.destination_name OR NEW.response_digest!=OLD.response_digest
BEGIN SELECT RAISE(ABORT,'forbidden response publication intent transition'); END;
CREATE TRIGGER image_generation_response_publication_intent_no_delete BEFORE DELETE ON image_generation_response_publication_intents BEGIN SELECT RAISE(ABORT,'response publication intent is durable'); END;

CREATE TABLE image_generation_scheduler_claims (
 job_id TEXT NOT NULL,
 slot_id TEXT NOT NULL,
 attempt_number INTEGER NOT NULL CHECK(attempt_number>=1),
 worker_boot_id TEXT NOT NULL CHECK(length(worker_boot_id)=36 AND worker_boot_id=lower(worker_boot_id)),
 claim_generation INTEGER NOT NULL CHECK(claim_generation>=1),
 claimed_at_unix_ms INTEGER NOT NULL,
 expires_at_unix_ms INTEGER NOT NULL CHECK(expires_at_unix_ms>claimed_at_unix_ms AND expires_at_unix_ms<=claimed_at_unix_ms+60000),
 PRIMARY KEY(job_id,slot_id,attempt_number,claim_generation),
 FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TABLE image_generation_scheduler_claim_consumptions (
 job_id TEXT NOT NULL, slot_id TEXT NOT NULL, attempt_number INTEGER NOT NULL, claim_generation INTEGER NOT NULL,
 consumed_at_unix_ms INTEGER NOT NULL,
 PRIMARY KEY(job_id,slot_id,attempt_number,claim_generation),
 FOREIGN KEY(job_id,slot_id,attempt_number,claim_generation) REFERENCES image_generation_scheduler_claims(job_id,slot_id,attempt_number,claim_generation) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TRIGGER image_generation_scheduler_claim_consumption_immutable BEFORE UPDATE ON image_generation_scheduler_claim_consumptions BEGIN SELECT RAISE(ABORT,'image generation scheduler claim consumption is immutable'); END;
CREATE TRIGGER image_generation_scheduler_claim_consumption_no_delete BEFORE DELETE ON image_generation_scheduler_claim_consumptions BEGIN SELECT RAISE(ABORT,'image generation scheduler claim consumption is immutable'); END;
CREATE TABLE image_generation_attempt_activation_facts (
 job_id TEXT NOT NULL, slot_id TEXT NOT NULL, attempt_number INTEGER NOT NULL,
 activation_reason TEXT NOT NULL CHECK(activation_reason IN ('initial','authoritative_retry')),
 prior_attempt_number INTEGER,
 activated_at_unix_ms INTEGER NOT NULL,
 PRIMARY KEY(job_id,slot_id,attempt_number),
 FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CHECK((activation_reason='initial' AND attempt_number=1 AND prior_attempt_number IS NULL) OR (activation_reason='authoritative_retry' AND attempt_number>1 AND prior_attempt_number=attempt_number-1))
);
CREATE TABLE image_generation_reconciliation_claims (
 job_id TEXT NOT NULL, slot_id TEXT NOT NULL, attempt_number INTEGER NOT NULL, claim_generation INTEGER NOT NULL CHECK(claim_generation>=1),
 worker_boot_id TEXT NOT NULL, claimed_at_unix_ms INTEGER NOT NULL, expires_at_unix_ms INTEGER NOT NULL CHECK(expires_at_unix_ms>claimed_at_unix_ms AND expires_at_unix_ms<=claimed_at_unix_ms+60000),
 PRIMARY KEY(job_id,slot_id,attempt_number,claim_generation),
 FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TABLE image_generation_reconciliation_claim_completions (
 job_id TEXT NOT NULL, slot_id TEXT NOT NULL, attempt_number INTEGER NOT NULL, claim_generation INTEGER NOT NULL,
 completed_at_unix_ms INTEGER NOT NULL,
 PRIMARY KEY(job_id,slot_id,attempt_number,claim_generation),
 FOREIGN KEY(job_id,slot_id,attempt_number,claim_generation) REFERENCES image_generation_reconciliation_claims(job_id,slot_id,attempt_number,claim_generation) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TABLE image_generation_provider_cancel_evidence (
 job_id TEXT NOT NULL,slot_id TEXT NOT NULL,attempt_number INTEGER NOT NULL,
 external_operation_id TEXT NOT NULL UNIQUE,outcome TEXT NOT NULL CHECK(outcome IN ('cancelled','too_late_or_accepted','outcome_unknown')),
 evidence_digest TEXT NOT NULL CHECK(length(evidence_digest)=64),recorded_at_unix_ms INTEGER NOT NULL,
 PRIMARY KEY(job_id,slot_id,attempt_number),
 FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TABLE image_generation_provider_cancel_claims (
 job_id TEXT NOT NULL,slot_id TEXT NOT NULL,attempt_number INTEGER NOT NULL,
 claim_generation INTEGER NOT NULL CHECK(claim_generation>=1),worker_boot_id TEXT NOT NULL,
 claimed_at_unix_ms INTEGER NOT NULL,expires_at_unix_ms INTEGER NOT NULL
   CHECK(expires_at_unix_ms>claimed_at_unix_ms AND expires_at_unix_ms<=claimed_at_unix_ms+60000),
 PRIMARY KEY(job_id,slot_id,attempt_number,claim_generation),
 FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TRIGGER image_generation_provider_cancel_evidence_immutable BEFORE UPDATE ON image_generation_provider_cancel_evidence BEGIN SELECT RAISE(ABORT,'image provider cancel evidence is immutable'); END;
CREATE TRIGGER image_generation_provider_cancel_evidence_no_delete BEFORE DELETE ON image_generation_provider_cancel_evidence BEGIN SELECT RAISE(ABORT,'image provider cancel evidence is immutable'); END;
CREATE TRIGGER image_generation_provider_cancel_claim_immutable BEFORE UPDATE ON image_generation_provider_cancel_claims BEGIN SELECT RAISE(ABORT,'image provider cancel claim is immutable'); END;
CREATE TRIGGER image_generation_provider_cancel_claim_no_delete BEFORE DELETE ON image_generation_provider_cancel_claims BEGIN SELECT RAISE(ABORT,'image provider cancel claim is immutable'); END;
CREATE TRIGGER image_generation_reconciliation_claim_immutable BEFORE UPDATE ON image_generation_reconciliation_claims BEGIN SELECT RAISE(ABORT,'image reconciliation claim is immutable'); END;
CREATE TRIGGER image_generation_reconciliation_claim_no_delete BEFORE DELETE ON image_generation_reconciliation_claims BEGIN SELECT RAISE(ABORT,'image reconciliation claim is immutable'); END;
CREATE TRIGGER image_generation_reconciliation_completion_immutable BEFORE UPDATE ON image_generation_reconciliation_claim_completions BEGIN SELECT RAISE(ABORT,'image reconciliation completion is immutable'); END;
CREATE TRIGGER image_generation_reconciliation_completion_no_delete BEFORE DELETE ON image_generation_reconciliation_claim_completions BEGIN SELECT RAISE(ABORT,'image reconciliation completion is immutable'); END;
CREATE TRIGGER image_generation_attempt_activation_immutable BEFORE UPDATE ON image_generation_attempt_activation_facts BEGIN SELECT RAISE(ABORT,'image generation attempt activation is immutable'); END;
CREATE TRIGGER image_generation_attempt_activation_no_delete BEFORE DELETE ON image_generation_attempt_activation_facts BEGIN SELECT RAISE(ABORT,'image generation attempt activation is immutable'); END;
CREATE TABLE image_generation_attempt_media_snapshots (
 job_id TEXT NOT NULL,
 slot_id TEXT NOT NULL,
 attempt_number INTEGER NOT NULL,
 plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64),
 canonical_media_plan BLOB NOT NULL CHECK(length(canonical_media_plan)>0 AND length(canonical_media_plan)<=65536),
 media_plan_digest TEXT NOT NULL CHECK(length(media_plan_digest)=64),
 PRIMARY KEY(job_id,slot_id,attempt_number),
 FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT,
 FOREIGN KEY(job_id,plan_digest) REFERENCES image_generation_plans(job_id,plan_digest) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TRIGGER image_generation_attempt_media_snapshot_immutable BEFORE UPDATE ON image_generation_attempt_media_snapshots BEGIN SELECT RAISE(ABORT,'image generation media snapshot is immutable'); END;
CREATE TRIGGER image_generation_attempt_media_snapshot_no_delete BEFORE DELETE ON image_generation_attempt_media_snapshots BEGIN SELECT RAISE(ABORT,'image generation media snapshot is immutable'); END;
CREATE TRIGGER image_generation_scheduler_claim_immutable BEFORE UPDATE ON image_generation_scheduler_claims BEGIN SELECT RAISE(ABORT,'image generation scheduler claim is immutable'); END;
CREATE TRIGGER image_generation_scheduler_claim_no_delete BEFORE DELETE ON image_generation_scheduler_claims BEGIN SELECT RAISE(ABORT,'image generation scheduler claim is immutable'); END;
CREATE TRIGGER image_generation_scheduler_claim_insert_guard BEFORE INSERT ON image_generation_scheduler_claims
WHEN NOT EXISTS(SELECT 1 FROM image_generation_attempt_activation_facts a WHERE a.job_id=NEW.job_id AND a.slot_id=NEW.slot_id AND a.attempt_number=NEW.attempt_number)
 OR (NEW.claim_generation=1 AND EXISTS(SELECT 1 FROM image_generation_scheduler_claims c WHERE c.job_id=NEW.job_id AND c.slot_id=NEW.slot_id AND c.attempt_number=NEW.attempt_number))
 OR (NEW.claim_generation>1 AND NOT EXISTS(SELECT 1 FROM image_generation_scheduler_claims c WHERE c.job_id=NEW.job_id AND c.slot_id=NEW.slot_id AND c.attempt_number=NEW.attempt_number AND c.claim_generation=NEW.claim_generation-1 AND (c.expires_at_unix_ms<=CAST(unixepoch('subsec')*1000 AS INTEGER) OR EXISTS(SELECT 1 FROM image_generation_scheduler_claim_consumptions x WHERE x.job_id=c.job_id AND x.slot_id=c.slot_id AND x.attempt_number=c.attempt_number AND x.claim_generation=c.claim_generation)) AND c.claim_generation=(SELECT MAX(m.claim_generation) FROM image_generation_scheduler_claims m WHERE m.job_id=NEW.job_id AND m.slot_id=NEW.slot_id AND m.attempt_number=NEW.attempt_number)))
BEGIN SELECT RAISE(ABORT,'image generation scheduler claim generation is not available'); END;

CREATE TABLE image_generation_cancellation_facts (
    job_id TEXT PRIMARY KEY REFERENCES image_generation_jobs(job_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    cancellation_version INTEGER NOT NULL CHECK(cancellation_version >= 1),
    requested_at_unix_ms INTEGER NOT NULL,
    request_operation_id TEXT NOT NULL UNIQUE,
    UNIQUE(job_id,cancellation_version)
);

CREATE TABLE image_generation_deadline_expiry_facts (
    job_id TEXT PRIMARY KEY REFERENCES image_generation_jobs(job_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    schema_version INTEGER NOT NULL CHECK(schema_version=1),
    state TEXT NOT NULL CHECK(state IN ('cleanup_required','cancellation_requested')),
    deadline_boot_id TEXT NOT NULL,
    deadline_monotonic_ms INTEGER NOT NULL CHECK(deadline_monotonic_ms>=0),
    observed_boot_id TEXT NOT NULL,
    observed_monotonic_ms INTEGER NOT NULL CHECK(observed_monotonic_ms>=0),
    cancellation_version INTEGER NOT NULL CHECK(cancellation_version>=1),
    cancellation_operation_id TEXT NOT NULL UNIQUE,
    cleanup_operation_id TEXT NOT NULL UNIQUE,
    media_reservation_id TEXT NOT NULL,
    media_reservation_version INTEGER NOT NULL CHECK(media_reservation_version>=1),
    spend_reservation_id TEXT NOT NULL,
    spend_reservation_version INTEGER NOT NULL CHECK(spend_reservation_version>=1),
    recorded_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY(job_id,cancellation_version) REFERENCES image_generation_cancellation_facts(job_id,cancellation_version) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TRIGGER image_generation_deadline_expiry_immutable BEFORE UPDATE ON image_generation_deadline_expiry_facts BEGIN SELECT RAISE(ABORT,'image generation deadline expiry evidence is immutable'); END;
CREATE TRIGGER image_generation_deadline_expiry_no_delete BEFORE DELETE ON image_generation_deadline_expiry_facts BEGIN SELECT RAISE(ABORT,'image generation deadline expiry evidence is immutable'); END;

CREATE TABLE image_generation_cancelled_result_facts (
    job_id TEXT NOT NULL,
    slot_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    cancellation_version INTEGER NOT NULL,
    response_digest TEXT NOT NULL CHECK(length(response_digest)=64),
    journal_terminal_version INTEGER NOT NULL CHECK(journal_terminal_version >= 1),
    ordering TEXT NOT NULL CHECK(ordering IN ('response_after_cancellation','response_adopted_before_cancellation')),
    PRIMARY KEY(job_id,slot_id,attempt_number),
    FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY(job_id,cancellation_version) REFERENCES image_generation_cancellation_facts(job_id,cancellation_version) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE image_generation_publication_right_facts (
    job_id TEXT NOT NULL,
    slot_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    slot_version INTEGER NOT NULL CHECK(slot_version >= 1),
    artifact_generation INTEGER NOT NULL CHECK(artifact_generation >= 1),
    committed_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY(job_id,slot_id),
    FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TABLE image_generation_reconciliation_evidence (
 job_id TEXT NOT NULL, slot_id TEXT NOT NULL, attempt_number INTEGER NOT NULL,
 journal_version INTEGER NOT NULL CHECK(journal_version>=1),
 evidence_digest TEXT NOT NULL CHECK(length(evidence_digest)=64 AND evidence_digest NOT GLOB '*[^0-9a-f]*'),
 provider_request_identity TEXT NOT NULL,
 provider_idempotency_identity TEXT NOT NULL,
 journal_payload_digest TEXT NOT NULL CHECK(length(journal_payload_digest)=64 AND journal_payload_digest NOT GLOB '*[^0-9a-f]*'),
 outcome TEXT NOT NULL CHECK(outcome IN ('authoritative_nonacceptance','authoritative_accepted','authoritative_failure')),
 PRIMARY KEY(job_id,slot_id,attempt_number,journal_version),
 FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT ON UPDATE RESTRICT
);

-- Managed image artifacts are a separate retained aggregate. They are never
-- attachment rows and user-published copies are never members of this graph.
CREATE TABLE image_generation_artifacts (
 artifact_id TEXT PRIMARY KEY,
 job_id TEXT NOT NULL,
 slot_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('allocating','writing','retained','late_quarantined','cleanup_pending','deleting','tombstoned','security_blocked')),
 generation INTEGER NOT NULL CHECK(generation>=1),
 expected_component_count INTEGER NOT NULL CHECK(expected_component_count>=1),
 active_lease_count INTEGER NOT NULL DEFAULT 0 CHECK(active_lease_count>=0),
 component_set_digest TEXT NOT NULL CHECK(length(component_set_digest)=64 AND component_set_digest NOT GLOB '*[^0-9a-f]*'),
 component_set_json TEXT NOT NULL,
 eligibility_at_unix_ms INTEGER,
 immediate_cleanup INTEGER NOT NULL DEFAULT 0 CHECK(immediate_cleanup IN (0,1)),
 terminal_reason TEXT,
 created_at_unix_ms INTEGER NOT NULL,
 updated_at_unix_ms INTEGER NOT NULL,
 UNIQUE(job_id,slot_id),
 FOREIGN KEY(job_id,slot_id) REFERENCES image_generation_slots(job_id,slot_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CHECK((state='tombstoned' AND terminal_reason IS NOT NULL) OR state!='tombstoned')
);

CREATE TABLE image_generation_artifact_components (
 artifact_id TEXT NOT NULL REFERENCES image_generation_artifacts(artifact_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 component_id TEXT NOT NULL,
 component_kind TEXT NOT NULL CHECK(component_kind IN ('primary','normalized_raster','sanitized_svg','thumbnail','model_payload')),
 state TEXT NOT NULL CHECK(state IN ('planned','writing','ready','cleanup_pending','deleting','tombstoned','security_blocked')),
 generation INTEGER NOT NULL CHECK(generation>=1),
 relative_storage_key TEXT NOT NULL,
 byte_length_hi INTEGER NOT NULL CHECK(byte_length_hi BETWEEN 0 AND 4294967295),
 byte_length_lo INTEGER NOT NULL CHECK(byte_length_lo BETWEEN 0 AND 4294967295),
 sha256 TEXT NOT NULL CHECK(length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
 stable_identity_json TEXT,
 expected_link_count INTEGER NOT NULL DEFAULT 1 CHECK(expected_link_count=1),
 resource_reservation_id TEXT NOT NULL,
 release_operation_id TEXT NOT NULL UNIQUE,
 deletion_evidence_digest TEXT CHECK(deletion_evidence_digest IS NULL OR (length(deletion_evidence_digest)=64 AND deletion_evidence_digest NOT GLOB '*[^0-9a-f]*')),
 PRIMARY KEY(artifact_id,component_id),
 UNIQUE(artifact_id,component_kind),
 UNIQUE(relative_storage_key),
 CHECK((state='tombstoned' AND deletion_evidence_digest IS NOT NULL) OR state!='tombstoned')
);

CREATE TABLE image_generation_artifact_cleanup_intents (
 cleanup_operation_id TEXT PRIMARY KEY,
 artifact_id TEXT NOT NULL REFERENCES image_generation_artifacts(artifact_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 expected_artifact_generation INTEGER NOT NULL CHECK(expected_artifact_generation>=1),
 reason TEXT NOT NULL CHECK(reason IN ('retention_expired','discard_late_result','invalid_output','restart_recovery','owner_recovery')),
 state TEXT NOT NULL CHECK(state IN ('pending','deleting','completed','security_blocked')),
 version INTEGER NOT NULL CHECK(version>=1),
 created_at_unix_ms INTEGER NOT NULL,
 completed_at_unix_ms INTEGER,
 UNIQUE(artifact_id),
 CHECK((state='completed')=(completed_at_unix_ms IS NOT NULL))
);

CREATE TABLE image_generation_component_release_facts (
 artifact_id TEXT NOT NULL,
 component_id TEXT NOT NULL,
 release_operation_id TEXT NOT NULL,
 deletion_evidence_digest TEXT NOT NULL CHECK(length(deletion_evidence_digest)=64 AND deletion_evidence_digest NOT GLOB '*[^0-9a-f]*'),
 committed_at_unix_ms INTEGER NOT NULL,
 PRIMARY KEY(artifact_id,component_id),
 UNIQUE(release_operation_id),
 FOREIGN KEY(artifact_id,component_id) REFERENCES image_generation_artifact_components(artifact_id,component_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE image_generation_artifact_references (
 reference_id TEXT PRIMARY KEY,
 artifact_id TEXT NOT NULL REFERENCES image_generation_artifacts(artifact_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 reference_kind TEXT NOT NULL CHECK(reference_kind IN ('message','tool','publication_operation')),
 released_at_unix_ms INTEGER
);

CREATE TABLE image_generation_artifact_authorization_facts (
 authorization_digest TEXT PRIMARY KEY CHECK(length(authorization_digest)=64 AND authorization_digest NOT GLOB '*[^0-9a-f]*'),
 artifact_id TEXT NOT NULL REFERENCES image_generation_artifacts(artifact_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 artifact_generation INTEGER NOT NULL CHECK(artifact_generation>=1),
 job_id TEXT NOT NULL,
 job_generation INTEGER NOT NULL CHECK(job_generation>=1),
 slot_id TEXT NOT NULL,
 slot_generation INTEGER NOT NULL CHECK(slot_generation>=1),
 consumer_purpose TEXT NOT NULL CHECK(consumer_purpose IN ('serve_artifact','serve_thumbnail','tool_input','model_input','internal_verification','internal_cleanup')),
 consumer_route TEXT NOT NULL CHECK(consumer_route IN ('artifact_full','artifact_range','thumbnail','tool','model_payload','verification','cleanup')),
 principal_digest TEXT NOT NULL CHECK(length(principal_digest)=64 AND principal_digest NOT GLOB '*[^0-9a-f]*'),
 created_at_unix_ms INTEGER NOT NULL,
 revoked_at_unix_ms INTEGER,
 FOREIGN KEY(job_id,slot_id) REFERENCES image_generation_slots(job_id,slot_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE image_generation_artifact_leases (
 lease_id TEXT PRIMARY KEY,
 artifact_id TEXT NOT NULL,
 artifact_generation INTEGER NOT NULL CHECK(artifact_generation>=1),
 owning_job_id TEXT NOT NULL,
 owning_job_generation INTEGER NOT NULL CHECK(owning_job_generation>=1),
 owning_slot_id TEXT NOT NULL,
 owning_slot_generation INTEGER NOT NULL CHECK(owning_slot_generation>=1),
 published_disposition TEXT NOT NULL CHECK(published_disposition IN ('ordinary','late_authorized')),
 published_disposition_generation INTEGER NOT NULL CHECK(published_disposition_generation>=1),
 component_id TEXT NOT NULL,
 component_kind TEXT NOT NULL CHECK(component_kind IN ('primary','normalized_raster','sanitized_svg','thumbnail','model_payload')),
 component_generation INTEGER NOT NULL CHECK(component_generation>=1),
 component_checksum TEXT NOT NULL CHECK(length(component_checksum)=64 AND component_checksum NOT GLOB '*[^0-9a-f]*'),
 consumer_purpose TEXT NOT NULL CHECK(consumer_purpose IN ('serve_artifact','serve_thumbnail','tool_input','model_input','internal_verification','internal_cleanup')),
 consumer_route TEXT NOT NULL CHECK(consumer_route IN ('artifact_full','artifact_range','thumbnail','tool','model_payload','verification','cleanup')),
 read_kind TEXT NOT NULL CHECK(read_kind IN ('full','range')),
 range_start_hi INTEGER NOT NULL CHECK(range_start_hi BETWEEN 0 AND 4294967295),
 range_start_lo INTEGER NOT NULL CHECK(range_start_lo BETWEEN 0 AND 4294967295),
 requested_length_hi INTEGER NOT NULL CHECK(requested_length_hi BETWEEN 0 AND 4294967295),
 requested_length_lo INTEGER NOT NULL CHECK(requested_length_lo BETWEEN 0 AND 4294967295),
 component_set_digest TEXT NOT NULL CHECK(length(component_set_digest)=64 AND component_set_digest NOT GLOB '*[^0-9a-f]*'),
 authorization_digest TEXT NOT NULL CHECK(length(authorization_digest)=64 AND authorization_digest NOT GLOB '*[^0-9a-f]*'),
 daemon_boot_id TEXT NOT NULL,
 committed_at_monotonic INTEGER NOT NULL CHECK(committed_at_monotonic>=0),
 deadline_monotonic INTEGER NOT NULL,
 released_at INTEGER,
 FOREIGN KEY(artifact_id,component_id) REFERENCES image_generation_artifact_components(artifact_id,component_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 FOREIGN KEY(owning_job_id,owning_slot_id) REFERENCES image_generation_slots(job_id,slot_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CHECK(deadline_monotonic=committed_at_monotonic+60000),
 CHECK((consumer_purpose='serve_artifact' AND consumer_route IN ('artifact_full','artifact_range')) OR
       (consumer_purpose='serve_thumbnail' AND consumer_route='thumbnail') OR
       (consumer_purpose='tool_input' AND consumer_route='tool') OR
       (consumer_purpose='model_input' AND consumer_route='model_payload') OR
       (consumer_purpose='internal_verification' AND consumer_route='verification') OR
       (consumer_purpose='internal_cleanup' AND consumer_route='cleanup')),
 CHECK((read_kind='range' AND consumer_route='artifact_range' AND (requested_length_hi>0 OR requested_length_lo>0)) OR
       (read_kind='full' AND consumer_route!='artifact_range' AND range_start_hi=0 AND range_start_lo=0))
);

CREATE TABLE image_generation_late_publication_leases (
 publication_operation_id TEXT PRIMARY KEY,
 artifact_id TEXT NOT NULL REFERENCES image_generation_artifacts(artifact_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 artifact_generation INTEGER NOT NULL CHECK(artifact_generation>=1),
 job_id TEXT NOT NULL,
 slot_id TEXT NOT NULL,
 expected_slot_version INTEGER NOT NULL CHECK(expected_slot_version>=1),
 component_set_digest TEXT NOT NULL CHECK(length(component_set_digest)=64 AND component_set_digest NOT GLOB '*[^0-9a-f]*'),
 component_set_json TEXT NOT NULL,
 authorization_digest TEXT NOT NULL CHECK(length(authorization_digest)=64 AND authorization_digest NOT GLOB '*[^0-9a-f]*'),
 output_authority_digest TEXT NOT NULL CHECK(length(output_authority_digest)=64 AND output_authority_digest NOT GLOB '*[^0-9a-f]*'),
 output_authority_generation INTEGER NOT NULL CHECK(output_authority_generation>=1),
 destination_name TEXT NOT NULL,
 temporary_name TEXT NOT NULL,
 created_at_unix_ms INTEGER NOT NULL,
 deadline_unix_ms INTEGER NOT NULL,
 worker_boot_id TEXT,
 claim_generation INTEGER CHECK(claim_generation IS NULL OR claim_generation>=1),
 state TEXT NOT NULL CHECK(state IN ('reserved','copy_authorized','copy_committed','published','aborted','expired','security_blocked','delete_authorized')),
 version INTEGER NOT NULL CHECK(version>=1),
 temporary_evidence_json TEXT,
 output_evidence_json TEXT,
 recovery_evidence_json TEXT,
 decided_at_unix_ms INTEGER,
 FOREIGN KEY(job_id,slot_id) REFERENCES image_generation_slots(job_id,slot_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CHECK(deadline_unix_ms=created_at_unix_ms+300000),
 CHECK((worker_boot_id IS NULL)=(claim_generation IS NULL)),
 CHECK((state='reserved' AND temporary_evidence_json IS NULL AND output_evidence_json IS NULL AND decided_at_unix_ms IS NULL) OR
       (state='copy_authorized' AND temporary_evidence_json IS NOT NULL AND output_evidence_json IS NULL AND recovery_evidence_json IS NULL AND decided_at_unix_ms IS NULL) OR
       (state='copy_committed' AND temporary_evidence_json IS NOT NULL AND output_evidence_json IS NOT NULL AND recovery_evidence_json IS NULL AND decided_at_unix_ms IS NULL) OR
       (state='delete_authorized' AND temporary_evidence_json IS NOT NULL AND output_evidence_json IS NOT NULL AND recovery_evidence_json IS NOT NULL AND json_valid(output_evidence_json) AND json_extract(output_evidence_json,'$.kind')='output_durable' AND json_valid(recovery_evidence_json) AND json_extract(recovery_evidence_json,'$.kind')='security_ambiguous' AND decided_at_unix_ms IS NULL) OR
       (state='published' AND output_evidence_json IS NOT NULL AND decided_at_unix_ms IS NOT NULL) OR
       (state IN ('aborted','expired','security_blocked') AND recovery_evidence_json IS NOT NULL AND decided_at_unix_ms IS NOT NULL))
);
CREATE TABLE image_generation_late_publication_authorization_facts (
 authorization_digest TEXT PRIMARY KEY CHECK(length(authorization_digest)=64 AND authorization_digest NOT GLOB '*[^0-9a-f]*'),
 artifact_id TEXT NOT NULL REFERENCES image_generation_artifacts(artifact_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 artifact_generation INTEGER NOT NULL CHECK(artifact_generation>=1),
 job_id TEXT NOT NULL,
 slot_id TEXT NOT NULL,
 slot_generation INTEGER NOT NULL CHECK(slot_generation>=1),
 component_set_digest TEXT NOT NULL CHECK(length(component_set_digest)=64 AND component_set_digest NOT GLOB '*[^0-9a-f]*'),
 output_authority_digest TEXT NOT NULL CHECK(length(output_authority_digest)=64 AND output_authority_digest NOT GLOB '*[^0-9a-f]*'),
 output_authority_generation INTEGER NOT NULL CHECK(output_authority_generation>=1),
 destination_name TEXT NOT NULL,
 temporary_name TEXT NOT NULL,
 principal_digest TEXT NOT NULL CHECK(length(principal_digest)=64 AND principal_digest NOT GLOB '*[^0-9a-f]*'),
 created_at_unix_ms INTEGER NOT NULL,
 revoked_at_unix_ms INTEGER,
 FOREIGN KEY(job_id,slot_id) REFERENCES image_generation_slots(job_id,slot_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE UNIQUE INDEX image_generation_one_live_late_publication
ON image_generation_late_publication_leases(artifact_id)
WHERE state IN ('reserved','copy_authorized','copy_committed','security_blocked','delete_authorized');
CREATE TABLE image_generation_user_published_outputs (
 publication_operation_id TEXT PRIMARY KEY REFERENCES image_generation_late_publication_leases(publication_operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 artifact_id TEXT NOT NULL REFERENCES image_generation_artifacts(artifact_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 artifact_generation INTEGER NOT NULL CHECK(artifact_generation>=1),
 output_authority_digest TEXT NOT NULL CHECK(length(output_authority_digest)=64 AND output_authority_digest NOT GLOB '*[^0-9a-f]*'),
 output_authority_generation INTEGER NOT NULL CHECK(output_authority_generation>=1),
 destination_name TEXT NOT NULL,
 output_evidence_json TEXT NOT NULL,
 committed_at_unix_ms INTEGER NOT NULL
);
CREATE TABLE image_generation_artifact_security_recovery_audits (
 recovery_operation_id TEXT PRIMARY KEY,
 artifact_id TEXT NOT NULL REFERENCES image_generation_artifacts(artifact_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 artifact_generation INTEGER NOT NULL CHECK(artifact_generation>=1),
 job_id TEXT NOT NULL,
 slot_id TEXT NOT NULL,
 slot_generation INTEGER NOT NULL CHECK(slot_generation>=1),
 principal_digest TEXT NOT NULL CHECK(length(principal_digest)=64 AND principal_digest NOT GLOB '*[^0-9a-f]*'),
 component_set_digest TEXT NOT NULL CHECK(length(component_set_digest)=64 AND component_set_digest NOT GLOB '*[^0-9a-f]*'),
 component_identity_digest TEXT NOT NULL CHECK(length(component_identity_digest)=64 AND component_identity_digest NOT GLOB '*[^0-9a-f]*'),
 publication_operation_id TEXT,
 publication_lease_version INTEGER CHECK(publication_lease_version IS NULL OR publication_lease_version>=1),
 output_identity_digest TEXT CHECK(output_identity_digest IS NULL OR (length(output_identity_digest)=64 AND output_identity_digest NOT GLOB '*[^0-9a-f]*')),
 disposition TEXT NOT NULL CHECK(disposition IN ('retain_blocked','resume_verified_cleanup','remove_verified_external_copy','complete_verified_late_publication')),
 state TEXT NOT NULL CHECK(state IN ('recorded','applied','denied','proof_failed','stale')),
 outcome_digest TEXT CHECK(outcome_digest IS NULL OR (length(outcome_digest)=64 AND outcome_digest NOT GLOB '*[^0-9a-f]*')),
 created_at_unix_ms INTEGER NOT NULL,
 decided_at_unix_ms INTEGER,
 FOREIGN KEY(job_id,slot_id) REFERENCES image_generation_slots(job_id,slot_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 FOREIGN KEY(publication_operation_id) REFERENCES image_generation_late_publication_leases(publication_operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CHECK((state='recorded' AND decided_at_unix_ms IS NULL AND outcome_digest IS NULL) OR (state!='recorded' AND decided_at_unix_ms IS NOT NULL AND outcome_digest IS NOT NULL)),
 CHECK((publication_operation_id IS NULL AND publication_lease_version IS NULL AND output_identity_digest IS NULL) OR (publication_operation_id IS NOT NULL AND publication_lease_version IS NOT NULL AND output_identity_digest IS NOT NULL))
);
CREATE TABLE image_generation_artifact_security_recovery_attempts (
 recovery_operation_id TEXT PRIMARY KEY,
 principal_digest TEXT NOT NULL CHECK(length(principal_digest)=64 AND principal_digest NOT GLOB '*[^0-9a-f]*'),
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
 state TEXT NOT NULL CHECK(state IN ('received','validated','denied')),
 outcome_digest TEXT CHECK(outcome_digest IS NULL OR (length(outcome_digest)=64 AND outcome_digest NOT GLOB '*[^0-9a-f]*')),
 created_at_unix_ms INTEGER NOT NULL,
 decided_at_unix_ms INTEGER,
 CHECK((state='received' AND outcome_digest IS NULL AND decided_at_unix_ms IS NULL) OR (state!='received' AND outcome_digest IS NOT NULL AND decided_at_unix_ms IS NOT NULL))
);
CREATE TABLE image_generation_artifact_security_recovery_components (
 recovery_operation_id TEXT NOT NULL REFERENCES image_generation_artifact_security_recovery_audits(recovery_operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 artifact_id TEXT NOT NULL,
 component_id TEXT NOT NULL,
 component_kind TEXT NOT NULL CHECK(component_kind IN ('primary','normalized_raster','sanitized_svg','thumbnail','model_payload')),
 component_generation INTEGER NOT NULL CHECK(component_generation>=1),
 stable_identity_digest TEXT NOT NULL CHECK(length(stable_identity_digest)=64 AND stable_identity_digest NOT GLOB '*[^0-9a-f]*'),
 security_digest TEXT NOT NULL CHECK(length(security_digest)=64 AND security_digest NOT GLOB '*[^0-9a-f]*'),
 sha256 TEXT NOT NULL CHECK(length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
 PRIMARY KEY(recovery_operation_id,component_id),
 FOREIGN KEY(artifact_id,component_id) REFERENCES image_generation_artifact_components(artifact_id,component_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TRIGGER image_generation_security_recovery_component_insert_guard BEFORE INSERT ON image_generation_artifact_security_recovery_components
WHEN NOT EXISTS(SELECT 1 FROM image_generation_artifact_security_recovery_audits r JOIN image_generation_artifact_components c ON c.artifact_id=r.artifact_id WHERE r.recovery_operation_id=NEW.recovery_operation_id AND r.artifact_id=NEW.artifact_id AND r.state='recorded' AND c.component_id=NEW.component_id AND c.component_kind=NEW.component_kind AND c.generation=NEW.component_generation AND c.sha256=NEW.sha256 AND json_valid(c.stable_identity_json)=1 AND json_extract(c.stable_identity_json,'$.identityDigest')=NEW.stable_identity_digest AND json_extract(c.stable_identity_json,'$.securityDigest')=NEW.security_digest AND c.state IN ('ready','security_blocked'))
BEGIN SELECT RAISE(ABORT,'security recovery component lacks exact held identity'); END;
CREATE TRIGGER image_generation_security_recovery_component_immutable BEFORE UPDATE ON image_generation_artifact_security_recovery_components BEGIN SELECT RAISE(ABORT,'security recovery component identity is immutable'); END;
CREATE TRIGGER image_generation_security_recovery_component_delete_forbidden BEFORE DELETE ON image_generation_artifact_security_recovery_components BEGIN SELECT RAISE(ABORT,'security recovery component identity is durable'); END;
CREATE TRIGGER image_generation_security_recovery_attempt_identity_immutable BEFORE UPDATE OF recovery_operation_id,principal_digest,request_digest,created_at_unix_ms ON image_generation_artifact_security_recovery_attempts BEGIN SELECT RAISE(ABORT,'security recovery attempt identity is immutable'); END;
CREATE TRIGGER image_generation_security_recovery_attempt_transition_guard BEFORE UPDATE OF state,outcome_digest,decided_at_unix_ms ON image_generation_artifact_security_recovery_attempts WHEN OLD.state!='received' OR NEW.state NOT IN ('validated','denied') OR NEW.outcome_digest IS NULL OR NEW.decided_at_unix_ms IS NULL BEGIN SELECT RAISE(ABORT,'security recovery attempt outcome is invalid'); END;
CREATE TRIGGER image_generation_security_recovery_attempt_delete_forbidden BEFORE DELETE ON image_generation_artifact_security_recovery_attempts BEGIN SELECT RAISE(ABORT,'security recovery attempt audit is durable'); END;

CREATE TABLE image_generation_artifact_transitions(from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_artifact_transitions VALUES
('allocating','writing'),('allocating','cleanup_pending'),('allocating','security_blocked'),
('writing','retained'),('writing','late_quarantined'),('writing','cleanup_pending'),('writing','security_blocked'),
('retained','cleanup_pending'),('retained','security_blocked'),
('late_quarantined','retained'),('late_quarantined','cleanup_pending'),('late_quarantined','security_blocked'),
('cleanup_pending','deleting'),('cleanup_pending','security_blocked'),
('deleting','tombstoned'),('deleting','security_blocked'),
('security_blocked','cleanup_pending'),('security_blocked','retained');
CREATE TABLE image_generation_component_transitions(from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_component_transitions VALUES
('planned','writing'),('planned','cleanup_pending'),('planned','security_blocked'),
('writing','ready'),('writing','cleanup_pending'),('writing','security_blocked'),
('ready','cleanup_pending'),('ready','security_blocked'),
('cleanup_pending','deleting'),('cleanup_pending','security_blocked'),
('deleting','tombstoned'),('deleting','security_blocked'),
('security_blocked','cleanup_pending');
CREATE TABLE image_generation_cleanup_transitions(from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_cleanup_transitions VALUES
('pending','deleting'),('pending','security_blocked'),('deleting','completed'),('deleting','security_blocked'),('security_blocked','pending');
CREATE TABLE image_generation_late_publication_transitions(from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_late_publication_transitions VALUES
('reserved','copy_authorized'),('reserved','aborted'),('reserved','expired'),('reserved','security_blocked'),
('copy_authorized','copy_committed'),('copy_authorized','aborted'),('copy_authorized','security_blocked'),
('copy_committed','published'),('copy_committed','security_blocked'),('security_blocked','published'),('security_blocked','delete_authorized'),('delete_authorized','aborted'),('delete_authorized','security_blocked');

CREATE TRIGGER image_generation_artifact_transition_guard BEFORE UPDATE OF state,generation ON image_generation_artifacts
WHEN NEW.generation!=OLD.generation+1 OR NOT EXISTS(SELECT 1 FROM image_generation_artifact_transitions WHERE from_state=OLD.state AND to_state=NEW.state)
BEGIN SELECT RAISE(ABORT,'forbidden image artifact transition'); END;
CREATE TRIGGER image_generation_artifact_slot_binding_guard BEFORE INSERT ON image_generation_artifacts
WHEN NOT EXISTS(SELECT 1 FROM image_generation_slots s WHERE s.job_id=NEW.job_id AND s.slot_id=NEW.slot_id AND s.managed_artifact_id=NEW.artifact_id)
BEGIN SELECT RAISE(ABORT,'image artifact is not the sealed slot artifact'); END;
CREATE TRIGGER image_generation_artifact_identity_immutable BEFORE UPDATE OF artifact_id,job_id,slot_id,expected_component_count,component_set_digest,component_set_json,created_at_unix_ms ON image_generation_artifacts
BEGIN SELECT RAISE(ABORT,'image artifact identity graph is immutable'); END;
CREATE TRIGGER image_generation_artifact_delete_forbidden BEFORE DELETE ON image_generation_artifacts
BEGIN SELECT RAISE(ABORT,'image artifact tombstones are retained'); END;
CREATE TRIGGER image_generation_component_insert_guard BEFORE INSERT ON image_generation_artifact_components
WHEN (SELECT state FROM image_generation_artifacts WHERE artifact_id=NEW.artifact_id)!='allocating'
BEGIN SELECT RAISE(ABORT,'image artifact component graph is sealed'); END;
CREATE TRIGGER image_generation_component_identity_immutable BEFORE UPDATE OF artifact_id,component_id,component_kind,relative_storage_key,byte_length_hi,byte_length_lo,sha256,expected_link_count,resource_reservation_id,release_operation_id ON image_generation_artifact_components
BEGIN SELECT RAISE(ABORT,'image artifact component identity is immutable'); END;
CREATE TRIGGER image_generation_component_delete_forbidden BEFORE DELETE ON image_generation_artifact_components
BEGIN SELECT RAISE(ABORT,'image artifact component tombstones are retained'); END;
CREATE TRIGGER image_generation_component_transition_guard BEFORE UPDATE OF state,generation ON image_generation_artifact_components
WHEN NEW.generation!=OLD.generation+1 OR NOT EXISTS(SELECT 1 FROM image_generation_component_transitions WHERE from_state=OLD.state AND to_state=NEW.state)
BEGIN SELECT RAISE(ABORT,'forbidden image artifact component transition'); END;
CREATE TRIGGER image_generation_cleanup_transition_guard BEFORE UPDATE OF state,version ON image_generation_artifact_cleanup_intents
WHEN NEW.version!=OLD.version+1 OR NOT EXISTS(SELECT 1 FROM image_generation_cleanup_transitions WHERE from_state=OLD.state AND to_state=NEW.state)
BEGIN SELECT RAISE(ABORT,'forbidden image artifact cleanup transition'); END;
CREATE TRIGGER image_generation_late_publication_transition_guard BEFORE UPDATE OF state,version ON image_generation_late_publication_leases
WHEN NEW.version!=OLD.version+1 OR ((NEW.state!=OLD.state AND NOT EXISTS(SELECT 1 FROM image_generation_late_publication_transitions WHERE from_state=OLD.state AND to_state=NEW.state)) OR (NEW.state=OLD.state AND NOT (OLD.state='reserved' AND NEW.claim_generation>COALESCE(OLD.claim_generation,0))))
BEGIN SELECT RAISE(ABORT,'forbidden late image publication transition'); END;
CREATE TRIGGER image_generation_late_publication_insert_guard BEFORE INSERT ON image_generation_late_publication_leases
WHEN NOT EXISTS(SELECT 1 FROM image_generation_artifacts a JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id JOIN image_generation_late_publication_authorization_facts f ON f.authorization_digest=NEW.authorization_digest
 WHERE a.artifact_id=NEW.artifact_id AND a.generation=NEW.artifact_generation AND a.state='late_quarantined' AND a.active_lease_count=0 AND a.component_set_digest=NEW.component_set_digest AND a.component_set_json=NEW.component_set_json AND a.job_id=NEW.job_id AND a.slot_id=NEW.slot_id
 AND s.version=NEW.expected_slot_version AND s.state='late_quarantined' AND s.result_after_cancel=1 AND s.applied_cancellation_version IS NOT NULL
 AND f.artifact_id=a.artifact_id AND f.artifact_generation=a.generation AND f.job_id=a.job_id AND f.slot_id=a.slot_id AND f.slot_generation=s.version AND f.component_set_digest=a.component_set_digest AND f.output_authority_digest=NEW.output_authority_digest AND f.output_authority_generation=NEW.output_authority_generation AND f.destination_name=NEW.destination_name AND f.temporary_name=NEW.temporary_name AND f.revoked_at_unix_ms IS NULL
 AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_cleanup_intents i WHERE i.artifact_id=a.artifact_id)
 AND (SELECT count(*) FROM image_generation_artifact_components c WHERE c.artifact_id=a.artifact_id AND c.state='ready')=a.expected_component_count)
BEGIN SELECT RAISE(ABORT,'late publication reservation lacks exact authority'); END;
CREATE TRIGGER image_generation_late_publication_evidence_guard BEFORE UPDATE OF state ON image_generation_late_publication_leases
WHEN (NEW.state='copy_authorized' AND (NEW.temporary_evidence_json IS NULL OR OLD.state!='reserved' OR CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)>=OLD.deadline_unix_ms))
 OR (NEW.state='copy_committed' AND (NEW.output_evidence_json IS NULL OR OLD.state!='copy_authorized'))
 OR (NEW.state='delete_authorized' AND (OLD.state!='security_blocked' OR NEW.output_evidence_json IS NULL OR NEW.recovery_evidence_json IS NULL OR NEW.decided_at_unix_ms IS NOT NULL))
 OR (NEW.state IN ('aborted','expired','security_blocked') AND NEW.recovery_evidence_json IS NULL)
 OR (NEW.state='expired' AND (OLD.state!='reserved' OR CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)<OLD.deadline_unix_ms))
 OR (NEW.state='published' AND (OLD.state NOT IN ('copy_committed','security_blocked') OR NOT EXISTS(SELECT 1 FROM image_generation_user_published_outputs o WHERE o.publication_operation_id=NEW.publication_operation_id AND o.artifact_id=NEW.artifact_id AND o.artifact_generation=NEW.artifact_generation AND o.output_authority_digest=NEW.output_authority_digest AND o.output_authority_generation=NEW.output_authority_generation AND o.destination_name=NEW.destination_name AND o.output_evidence_json=NEW.output_evidence_json)))
BEGIN SELECT RAISE(ABORT,'late publication transition lacks state-dependent evidence'); END;
CREATE TRIGGER image_generation_artifact_retained_projection_guard BEFORE UPDATE OF state ON image_generation_artifacts
WHEN NEW.state IN ('retained','late_quarantined') AND (((SELECT count(*) FROM image_generation_artifact_components c WHERE c.artifact_id=NEW.artifact_id)!=NEW.expected_component_count) OR ((SELECT count(*) FROM image_generation_artifact_components c WHERE c.artifact_id=NEW.artifact_id AND c.state='ready')!=NEW.expected_component_count))
BEGIN SELECT RAISE(ABORT,'retained image artifact lacks complete ready component set'); END;
CREATE TRIGGER image_generation_artifact_late_publication_guard BEFORE UPDATE OF state ON image_generation_artifacts
WHEN OLD.state='late_quarantined' AND NEW.state='retained' AND NOT EXISTS(SELECT 1 FROM image_generation_late_publication_leases p WHERE p.artifact_id=NEW.artifact_id AND p.state='published' AND p.artifact_generation=OLD.generation)
BEGIN SELECT RAISE(ABORT,'late artifact retention lacks exact published disposition lease'); END;
CREATE TRIGGER image_generation_artifact_security_recovery_guard BEFORE UPDATE OF state ON image_generation_artifacts
WHEN OLD.state='security_blocked' AND NEW.state='cleanup_pending' AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_cleanup_intents i WHERE i.artifact_id=NEW.artifact_id AND i.reason='owner_recovery' AND i.expected_artifact_generation=NEW.generation)
BEGIN SELECT RAISE(ABORT,'security-blocked artifact lacks Owner recovery intent'); END;
CREATE TRIGGER image_generation_artifact_security_publication_guard BEFORE UPDATE OF state ON image_generation_artifacts
WHEN OLD.state='security_blocked' AND NEW.state='retained' AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_security_recovery_audits r JOIN image_generation_late_publication_leases p ON p.publication_operation_id=r.publication_operation_id WHERE r.artifact_id=NEW.artifact_id AND r.artifact_generation=OLD.generation AND r.disposition='complete_verified_late_publication' AND r.state='applied' AND p.state='published')
BEGIN SELECT RAISE(ABORT,'security-blocked artifact lacks verified Owner publication'); END;
CREATE TRIGGER image_generation_component_security_recovery_guard BEFORE UPDATE OF state ON image_generation_artifact_components
WHEN OLD.state='security_blocked' AND NEW.state='cleanup_pending' AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_cleanup_intents i WHERE i.artifact_id=NEW.artifact_id AND i.reason='owner_recovery')
BEGIN SELECT RAISE(ABORT,'security-blocked component lacks Owner recovery intent'); END;
CREATE TRIGGER image_generation_artifact_tombstone_projection_guard BEFORE UPDATE OF state ON image_generation_artifacts
WHEN NEW.state='tombstoned' AND (EXISTS(SELECT 1 FROM image_generation_artifact_components c WHERE c.artifact_id=NEW.artifact_id AND c.state!='tombstoned') OR EXISTS(SELECT 1 FROM image_generation_artifact_components c LEFT JOIN image_generation_component_release_facts r ON r.artifact_id=c.artifact_id AND r.component_id=c.component_id WHERE c.artifact_id=NEW.artifact_id AND r.component_id IS NULL))
BEGIN SELECT RAISE(ABORT,'image artifact tombstone lacks component deletion and release evidence'); END;
CREATE TRIGGER image_generation_component_tombstone_guard BEFORE UPDATE OF state ON image_generation_artifact_components
WHEN NEW.state='tombstoned' AND NOT EXISTS(SELECT 1 FROM image_generation_component_release_facts r WHERE r.artifact_id=NEW.artifact_id AND r.component_id=NEW.component_id AND r.deletion_evidence_digest=NEW.deletion_evidence_digest)
BEGIN SELECT RAISE(ABORT,'component tombstone lacks matching release evidence'); END;
CREATE TRIGGER image_generation_release_guard BEFORE INSERT ON image_generation_component_release_facts
WHEN NOT EXISTS(SELECT 1 FROM image_generation_artifact_components c WHERE c.artifact_id=NEW.artifact_id AND c.component_id=NEW.component_id AND c.state='deleting' AND c.release_operation_id=NEW.release_operation_id AND c.deletion_evidence_digest=NEW.deletion_evidence_digest)
BEGIN SELECT RAISE(ABORT,'resource release precedes verified component deletion evidence'); END;
CREATE TRIGGER image_generation_release_immutable BEFORE UPDATE ON image_generation_component_release_facts BEGIN SELECT RAISE(ABORT,'component release evidence is immutable'); END;
CREATE TRIGGER image_generation_release_delete_forbidden BEFORE DELETE ON image_generation_component_release_facts BEGIN SELECT RAISE(ABORT,'component release evidence is immutable'); END;
CREATE TRIGGER image_generation_cleanup_identity_immutable BEFORE UPDATE OF cleanup_operation_id,artifact_id,expected_artifact_generation,reason,created_at_unix_ms ON image_generation_artifact_cleanup_intents BEGIN SELECT RAISE(ABORT,'cleanup intent identity is immutable'); END;
CREATE TRIGGER image_generation_cleanup_delete_forbidden BEFORE DELETE ON image_generation_artifact_cleanup_intents BEGIN SELECT RAISE(ABORT,'cleanup intent is durable'); END;
CREATE TRIGGER image_generation_lease_identity_immutable BEFORE UPDATE OF lease_id,artifact_id,artifact_generation,owning_job_id,owning_job_generation,owning_slot_id,owning_slot_generation,published_disposition,published_disposition_generation,component_id,component_kind,component_generation,component_checksum,consumer_purpose,consumer_route,read_kind,range_start_hi,range_start_lo,requested_length_hi,requested_length_lo,component_set_digest,authorization_digest,daemon_boot_id,committed_at_monotonic,deadline_monotonic ON image_generation_artifact_leases BEGIN SELECT RAISE(ABORT,'artifact lease identity is immutable'); END;
CREATE TRIGGER image_generation_lease_delete_forbidden BEFORE DELETE ON image_generation_artifact_leases BEGIN SELECT RAISE(ABORT,'artifact lease is durable'); END;
CREATE TRIGGER image_generation_lease_insert_guard BEFORE INSERT ON image_generation_artifact_leases
WHEN NOT EXISTS(SELECT 1 FROM image_generation_artifacts a JOIN image_generation_jobs j ON j.job_id=a.job_id JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id JOIN image_generation_artifact_components c ON c.artifact_id=a.artifact_id JOIN image_generation_artifact_authorization_facts f ON f.authorization_digest=NEW.authorization_digest
 WHERE a.artifact_id=NEW.artifact_id AND a.state='retained' AND a.generation=NEW.artifact_generation AND a.component_set_digest=NEW.component_set_digest AND a.active_lease_count=(SELECT count(*) FROM image_generation_artifact_leases l WHERE l.artifact_id=a.artifact_id AND l.released_at IS NULL)
 AND j.job_id=NEW.owning_job_id AND j.version=NEW.owning_job_generation AND s.slot_id=NEW.owning_slot_id AND s.state='published' AND s.version=NEW.owning_slot_generation AND NEW.published_disposition_generation=s.published_disposition_generation AND NEW.published_disposition=s.published_disposition
 AND ((s.published_disposition='ordinary' AND s.result_after_cancel=0) OR (s.published_disposition='late_authorized' AND s.result_after_cancel=1 AND s.applied_cancellation_version IS NOT NULL))
 AND c.component_id=NEW.component_id AND c.component_kind=NEW.component_kind AND c.state='ready' AND c.generation=NEW.component_generation AND c.sha256=NEW.component_checksum
 AND f.artifact_id=a.artifact_id AND f.artifact_generation=a.generation AND f.job_id=j.job_id AND f.job_generation=j.version AND f.slot_id=s.slot_id AND f.slot_generation=s.version AND f.consumer_purpose=NEW.consumer_purpose AND f.consumer_route=NEW.consumer_route AND f.revoked_at_unix_ms IS NULL
 AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_cleanup_intents i WHERE i.artifact_id=a.artifact_id)
 AND ((NEW.consumer_purpose='serve_artifact' AND NEW.consumer_route IN ('artifact_full','artifact_range')) OR (NEW.consumer_purpose='serve_thumbnail' AND NEW.consumer_route='thumbnail') OR (NEW.consumer_purpose='tool_input' AND NEW.consumer_route='tool') OR (NEW.consumer_purpose='model_input' AND NEW.consumer_route='model_payload') OR (NEW.consumer_purpose='internal_verification' AND NEW.consumer_route='verification') OR (NEW.consumer_purpose='internal_cleanup' AND NEW.consumer_route='cleanup'))
 AND ((NEW.read_kind='full' AND NEW.consumer_route!='artifact_range' AND NEW.range_start_hi=0 AND NEW.range_start_lo=0 AND NEW.requested_length_hi=c.byte_length_hi AND NEW.requested_length_lo=c.byte_length_lo) OR
      (NEW.read_kind='range' AND NEW.consumer_route='artifact_range' AND (NEW.requested_length_hi>0 OR NEW.requested_length_lo>0) AND NEW.range_start_hi+NEW.requested_length_hi+CASE WHEN NEW.range_start_lo+NEW.requested_length_lo>=4294967296 THEN 1 ELSE 0 END<=4294967295 AND (NEW.range_start_hi+NEW.requested_length_hi+CASE WHEN NEW.range_start_lo+NEW.requested_length_lo>=4294967296 THEN 1 ELSE 0 END<c.byte_length_hi OR (NEW.range_start_hi+NEW.requested_length_hi+CASE WHEN NEW.range_start_lo+NEW.requested_length_lo>=4294967296 THEN 1 ELSE 0 END=c.byte_length_hi AND (NEW.range_start_lo+NEW.requested_length_lo)%4294967296<=c.byte_length_lo))))
)
BEGIN SELECT RAISE(ABORT,'artifact lease lacks exact current authority'); END;
CREATE TRIGGER image_generation_lease_count_insert AFTER INSERT ON image_generation_artifact_leases
BEGIN UPDATE image_generation_artifacts SET active_lease_count=active_lease_count+1 WHERE artifact_id=NEW.artifact_id; END;
CREATE TRIGGER image_generation_lease_release_guard BEFORE UPDATE OF released_at ON image_generation_artifact_leases
WHEN OLD.released_at IS NOT NULL OR NEW.released_at IS NULL OR NEW.released_at<OLD.committed_at_monotonic
BEGIN SELECT RAISE(ABORT,'artifact lease release is not monotonic'); END;
CREATE TRIGGER image_generation_lease_count_release AFTER UPDATE OF released_at ON image_generation_artifact_leases
WHEN OLD.released_at IS NULL AND NEW.released_at IS NOT NULL
BEGIN UPDATE image_generation_artifacts SET active_lease_count=active_lease_count-1 WHERE artifact_id=NEW.artifact_id AND active_lease_count>0; END;
CREATE TRIGGER image_generation_active_lease_count_guard BEFORE UPDATE OF active_lease_count ON image_generation_artifacts
WHEN NEW.active_lease_count!=(SELECT count(*) FROM image_generation_artifact_leases l WHERE l.artifact_id=NEW.artifact_id AND l.released_at IS NULL)
BEGIN SELECT RAISE(ABORT,'artifact active lease count differs from durable leases'); END;
CREATE TRIGGER image_generation_artifact_authorization_immutable BEFORE UPDATE OF authorization_digest,artifact_id,artifact_generation,job_id,job_generation,slot_id,slot_generation,consumer_purpose,consumer_route,principal_digest,created_at_unix_ms ON image_generation_artifact_authorization_facts BEGIN SELECT RAISE(ABORT,'artifact authorization identity is immutable'); END;
CREATE TRIGGER image_generation_artifact_authorization_delete_forbidden BEFORE DELETE ON image_generation_artifact_authorization_facts BEGIN SELECT RAISE(ABORT,'artifact authorization fact is durable'); END;
CREATE TRIGGER image_generation_artifact_authorization_revoke_guard BEFORE UPDATE OF revoked_at_unix_ms ON image_generation_artifact_authorization_facts
WHEN OLD.revoked_at_unix_ms IS NOT NULL OR NEW.revoked_at_unix_ms IS NULL OR NEW.revoked_at_unix_ms<OLD.created_at_unix_ms
BEGIN SELECT RAISE(ABORT,'artifact authorization revocation is not monotonic'); END;
CREATE TRIGGER image_generation_late_publication_identity_immutable BEFORE UPDATE OF publication_operation_id,artifact_id,artifact_generation,job_id,slot_id,expected_slot_version,component_set_digest,component_set_json,authorization_digest,output_authority_digest,output_authority_generation,destination_name,temporary_name,created_at_unix_ms,deadline_unix_ms ON image_generation_late_publication_leases BEGIN SELECT RAISE(ABORT,'late publication identity is immutable'); END;
CREATE TRIGGER image_generation_late_publication_delete_forbidden BEFORE DELETE ON image_generation_late_publication_leases BEGIN SELECT RAISE(ABORT,'late publication lease is durable'); END;
CREATE TRIGGER image_generation_late_publication_claim_guard BEFORE UPDATE OF worker_boot_id,claim_generation ON image_generation_late_publication_leases
WHEN OLD.state!='reserved' OR NEW.state!='reserved' OR NEW.worker_boot_id IS NULL OR NEW.claim_generation IS NULL OR NEW.claim_generation<=COALESCE(OLD.claim_generation,0) OR (OLD.claim_generation IS NOT NULL AND NEW.recovery_evidence_json IS NULL) OR CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)>=OLD.deadline_unix_ms
BEGIN SELECT RAISE(ABORT,'late publication claim lacks fresh fenced authority'); END;
CREATE TRIGGER image_generation_late_publication_evidence_immutable BEFORE UPDATE OF temporary_evidence_json,output_evidence_json,recovery_evidence_json ON image_generation_late_publication_leases
WHEN (OLD.temporary_evidence_json IS NOT NULL AND NEW.temporary_evidence_json!=OLD.temporary_evidence_json) OR (OLD.output_evidence_json IS NOT NULL AND NEW.output_evidence_json!=OLD.output_evidence_json) OR (OLD.recovery_evidence_json IS NOT NULL AND NEW.recovery_evidence_json!=OLD.recovery_evidence_json AND NOT (OLD.state='delete_authorized' AND NEW.state='aborted' AND json_valid(NEW.recovery_evidence_json) AND json_extract(NEW.recovery_evidence_json,'$.schema_version')=1 AND json_extract(NEW.recovery_evidence_json,'$.kind') IN ('temporary_deleted','exact_absence')))
BEGIN SELECT RAISE(ABORT,'late publication evidence is immutable'); END;
CREATE TRIGGER image_generation_late_publication_decision_immutable BEFORE UPDATE OF decided_at_unix_ms ON image_generation_late_publication_leases
WHEN NOT ((OLD.decided_at_unix_ms IS NULL AND NEW.decided_at_unix_ms IS NOT NULL) OR (OLD.state='security_blocked' AND NEW.state='delete_authorized' AND OLD.decided_at_unix_ms IS NOT NULL AND NEW.decided_at_unix_ms IS NULL))
BEGIN SELECT RAISE(ABORT,'late publication decision is immutable'); END;
CREATE TRIGGER image_generation_user_published_output_immutable BEFORE UPDATE ON image_generation_user_published_outputs BEGIN SELECT RAISE(ABORT,'published output evidence is immutable'); END;
CREATE TRIGGER image_generation_user_published_output_delete_forbidden BEFORE DELETE ON image_generation_user_published_outputs BEGIN SELECT RAISE(ABORT,'published output evidence is durable'); END;
CREATE TRIGGER image_generation_security_recovery_audit_identity_immutable BEFORE UPDATE OF recovery_operation_id,artifact_id,artifact_generation,job_id,slot_id,slot_generation,principal_digest,component_set_digest,component_identity_digest,publication_operation_id,publication_lease_version,output_identity_digest,disposition,created_at_unix_ms ON image_generation_artifact_security_recovery_audits BEGIN SELECT RAISE(ABORT,'security recovery audit identity is immutable'); END;
CREATE TRIGGER image_generation_security_recovery_audit_insert_guard BEFORE INSERT ON image_generation_artifact_security_recovery_audits
WHEN NOT EXISTS(SELECT 1 FROM image_generation_artifacts a JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id WHERE a.artifact_id=NEW.artifact_id AND a.generation=NEW.artifact_generation AND a.job_id=NEW.job_id AND a.slot_id=NEW.slot_id AND a.component_set_digest=NEW.component_set_digest AND (a.state='security_blocked' OR NEW.disposition IN ('complete_verified_late_publication','remove_verified_external_copy')) AND s.version=NEW.slot_generation)
 OR (NEW.publication_operation_id IS NULL AND NEW.disposition='complete_verified_late_publication')
 OR (NEW.publication_operation_id IS NOT NULL AND (NEW.disposition NOT IN ('complete_verified_late_publication','remove_verified_external_copy') OR NOT EXISTS(SELECT 1 FROM image_generation_late_publication_leases p WHERE p.publication_operation_id=NEW.publication_operation_id AND p.artifact_id=NEW.artifact_id AND p.artifact_generation=NEW.artifact_generation AND p.version=NEW.publication_lease_version AND p.state='security_blocked' AND p.output_evidence_json IS NOT NULL AND json_extract(p.output_evidence_json,'$.identity_digest')=NEW.output_identity_digest)))
BEGIN SELECT RAISE(ABORT,'security recovery audit lacks exact blocked authority'); END;
CREATE TRIGGER image_generation_security_recovery_audit_transition_guard BEFORE UPDATE OF state,outcome_digest,decided_at_unix_ms ON image_generation_artifact_security_recovery_audits WHEN OLD.state!='recorded' OR NEW.state NOT IN ('applied','denied','proof_failed','stale') OR NEW.outcome_digest IS NULL OR length(NEW.outcome_digest)!=64 OR NEW.outcome_digest GLOB '*[^0-9a-f]*' OR NEW.decided_at_unix_ms IS NULL BEGIN SELECT RAISE(ABORT,'security recovery audit outcome is immutable'); END;
CREATE TRIGGER image_generation_security_recovery_audit_delete_forbidden BEFORE DELETE ON image_generation_artifact_security_recovery_audits BEGIN SELECT RAISE(ABORT,'security recovery audit is durable'); END;
CREATE TRIGGER image_generation_late_publication_authorization_immutable BEFORE UPDATE OF authorization_digest,artifact_id,artifact_generation,job_id,slot_id,slot_generation,component_set_digest,output_authority_digest,output_authority_generation,destination_name,temporary_name,principal_digest,created_at_unix_ms ON image_generation_late_publication_authorization_facts BEGIN SELECT RAISE(ABORT,'late publication authorization identity is immutable'); END;
CREATE TRIGGER image_generation_late_publication_authorization_delete_forbidden BEFORE DELETE ON image_generation_late_publication_authorization_facts BEGIN SELECT RAISE(ABORT,'late publication authorization fact is durable'); END;
CREATE TRIGGER image_generation_late_publication_authorization_revoke_guard BEFORE UPDATE OF revoked_at_unix_ms ON image_generation_late_publication_authorization_facts WHEN OLD.revoked_at_unix_ms IS NOT NULL OR NEW.revoked_at_unix_ms IS NULL OR NEW.revoked_at_unix_ms<OLD.created_at_unix_ms BEGIN SELECT RAISE(ABORT,'late publication authorization revocation is not monotonic'); END;
CREATE TRIGGER image_generation_user_published_output_insert_guard BEFORE INSERT ON image_generation_user_published_outputs
WHEN NOT EXISTS(SELECT 1 FROM image_generation_late_publication_leases p WHERE p.publication_operation_id=NEW.publication_operation_id AND p.artifact_id=NEW.artifact_id AND p.artifact_generation=NEW.artifact_generation AND p.state IN ('copy_committed','security_blocked') AND p.output_authority_digest=NEW.output_authority_digest AND p.output_authority_generation=NEW.output_authority_generation AND p.destination_name=NEW.destination_name AND p.output_evidence_json=NEW.output_evidence_json)
BEGIN SELECT RAISE(ABORT,'published output fact lacks exact durable lease evidence'); END;
CREATE TRIGGER image_generation_owner_recovery_cleanup_intent_insert_guard BEFORE INSERT ON image_generation_artifact_cleanup_intents
WHEN NEW.reason='owner_recovery' AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_security_recovery_audits r JOIN image_generation_artifacts a ON a.artifact_id=r.artifact_id WHERE r.artifact_id=NEW.artifact_id AND r.disposition='resume_verified_cleanup' AND r.state='recorded' AND NEW.expected_artifact_generation=r.artifact_generation+1 AND a.generation=r.artifact_generation AND a.state='security_blocked')
BEGIN SELECT RAISE(ABORT,'owner recovery cleanup intent lacks recorded audit'); END;
CREATE TRIGGER image_generation_external_delete_authority_guard BEFORE UPDATE OF state ON image_generation_late_publication_leases
WHEN NEW.state='delete_authorized' AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_security_recovery_audits r WHERE r.publication_operation_id=OLD.publication_operation_id AND r.publication_lease_version=OLD.version AND r.artifact_id=OLD.artifact_id AND r.artifact_generation=OLD.artifact_generation AND r.output_identity_digest=json_extract(OLD.output_evidence_json,'$.identity_digest') AND r.disposition='remove_verified_external_copy' AND r.state='recorded')
BEGIN SELECT RAISE(ABORT,'external publication deletion lacks recorded authority'); END;
CREATE TRIGGER image_generation_external_delete_evidence_guard BEFORE UPDATE OF state,recovery_evidence_json ON image_generation_late_publication_leases
WHEN OLD.state='delete_authorized' AND (NEW.state!='aborted' OR json_valid(NEW.recovery_evidence_json)!=1 OR json_extract(NEW.recovery_evidence_json,'$.schema_version')!=1 OR json_extract(NEW.recovery_evidence_json,'$.kind') NOT IN ('temporary_deleted','exact_absence') OR (json_extract(NEW.recovery_evidence_json,'$.kind')='temporary_deleted' AND (length(json_extract(NEW.recovery_evidence_json,'$.identity_digest'))!=64 OR length(json_extract(NEW.recovery_evidence_json,'$.deletion_digest'))!=64 OR length(json_extract(NEW.recovery_evidence_json,'$.parent_sync_digest'))!=64)) OR (json_extract(NEW.recovery_evidence_json,'$.kind')='exact_absence' AND (length(json_extract(NEW.recovery_evidence_json,'$.absence_digest'))!=64 OR length(json_extract(NEW.recovery_evidence_json,'$.parent_identity_digest'))!=64)))
BEGIN SELECT RAISE(ABORT,'external publication deletion evidence is invalid'); END;
CREATE TRIGGER image_generation_artifact_transition_registry_sealed BEFORE INSERT ON image_generation_artifact_transitions BEGIN SELECT RAISE(ABORT,'image artifact transition registry is sealed'); END;
CREATE TRIGGER image_generation_artifact_transition_registry_update_sealed BEFORE UPDATE ON image_generation_artifact_transitions BEGIN SELECT RAISE(ABORT,'image artifact transition registry is sealed'); END;
CREATE TRIGGER image_generation_artifact_transition_registry_delete_sealed BEFORE DELETE ON image_generation_artifact_transitions BEGIN SELECT RAISE(ABORT,'image artifact transition registry is sealed'); END;
CREATE TRIGGER image_generation_component_transition_registry_sealed BEFORE INSERT ON image_generation_component_transitions BEGIN SELECT RAISE(ABORT,'image component transition registry is sealed'); END;
CREATE TRIGGER image_generation_component_transition_registry_update_sealed BEFORE UPDATE ON image_generation_component_transitions BEGIN SELECT RAISE(ABORT,'image component transition registry is sealed'); END;
CREATE TRIGGER image_generation_component_transition_registry_delete_sealed BEFORE DELETE ON image_generation_component_transitions BEGIN SELECT RAISE(ABORT,'image component transition registry is sealed'); END;
CREATE TRIGGER image_generation_cleanup_transition_registry_sealed BEFORE INSERT ON image_generation_cleanup_transitions BEGIN SELECT RAISE(ABORT,'image cleanup transition registry is sealed'); END;
CREATE TRIGGER image_generation_cleanup_transition_registry_update_sealed BEFORE UPDATE ON image_generation_cleanup_transitions BEGIN SELECT RAISE(ABORT,'image cleanup transition registry is sealed'); END;
CREATE TRIGGER image_generation_cleanup_transition_registry_delete_sealed BEFORE DELETE ON image_generation_cleanup_transitions BEGIN SELECT RAISE(ABORT,'image cleanup transition registry is sealed'); END;
CREATE TRIGGER image_generation_late_publication_transition_registry_sealed BEFORE INSERT ON image_generation_late_publication_transitions BEGIN SELECT RAISE(ABORT,'late publication transition registry is sealed'); END;
CREATE TRIGGER image_generation_late_publication_transition_registry_update_sealed BEFORE UPDATE ON image_generation_late_publication_transitions BEGIN SELECT RAISE(ABORT,'late publication transition registry is sealed'); END;
CREATE TRIGGER image_generation_late_publication_transition_registry_delete_sealed BEFORE DELETE ON image_generation_late_publication_transitions BEGIN SELECT RAISE(ABORT,'late publication transition registry is sealed'); END;

CREATE TABLE image_generation_job_transitions (from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_job_transitions VALUES
('created','validating'),('created','failed'),('created','cancelled'),
('validating','awaiting_authorization'),('validating','queued'),('validating','failed'),('validating','cancelled'),
('awaiting_authorization','queued'),('awaiting_authorization','failed'),('awaiting_authorization','cancelled'),
('queued','dispatching'),('queued','cancellation_requested'),('queued','failed'),('queued','cancelled'),
('dispatching','submission_unknown'),('dispatching','running'),('dispatching','cancellation_requested'),('dispatching','downloading'),('dispatching','partially_failed'),('dispatching','failed'),('dispatching','cancelled'),
('submission_unknown','running'),('submission_unknown','cancellation_requested'),('submission_unknown','downloading'),('submission_unknown','completed_after_cancel'),('submission_unknown','partially_failed'),('submission_unknown','failed'),
('running','cancellation_requested'),('running','downloading'),('running','partially_failed'),('running','failed'),
('cancellation_requested','cancelled'),('cancellation_requested','downloading'),('cancellation_requested','completed_after_cancel'),('cancellation_requested','partially_failed'),('cancellation_requested','failed'),
('downloading','validating_output'),('downloading','cancellation_requested'),('downloading','completed_after_cancel'),('downloading','partially_failed'),('downloading','failed'),
('validating_output','publishing'),('validating_output','cancellation_requested'),('validating_output','completed_after_cancel'),('validating_output','partially_failed'),('validating_output','failed'),
('publishing','completed'),('publishing','cancellation_requested'),('publishing','completed_after_cancel'),('publishing','partially_failed'),('publishing','failed');

CREATE TABLE image_generation_slot_transitions (from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_slot_transitions VALUES
('planned','queued'),('planned','failed'),('planned','cancelled'),('queued','dispatching'),('queued','failed'),('queued','cancelled'),
('dispatching','submission_unknown'),('dispatching','running'),('dispatching','downloading'),('dispatching','cancellation_requested'),('dispatching','failed'),('dispatching','cancelled'),
('submission_unknown','running'),('submission_unknown','downloading'),('submission_unknown','cancellation_requested'),('submission_unknown','failed'),('submission_unknown','cancelled'),
('running','downloading'),('running','cancellation_requested'),('running','failed'),
('cancellation_requested','cancelled'),('cancellation_requested','submission_unknown'),('cancellation_requested','downloading'),('cancellation_requested','failed'),
('downloading','validating'),('downloading','cancellation_requested'),('downloading','failed'),
('validating','ready_to_publish'),('validating','late_quarantined'),('validating','cancellation_requested'),('validating','failed'),
('ready_to_publish','published'),('ready_to_publish','late_quarantined'),('ready_to_publish','failed'),
('late_quarantined','published'),('late_quarantined','discarded');

CREATE TABLE image_generation_attempt_transitions (from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_attempt_transitions VALUES
('planned','preparing'),('planned','cancelled'),('planned','failed_not_submitted'),('preparing','prepared'),('preparing','cancelled'),('preparing','failed_not_submitted'),('prepared','dispatching'),('prepared','cancelled'),('prepared','failed_not_submitted'),
('dispatching','accepted'),('dispatching','submission_unknown'),('dispatching','rejected_not_accepted'),('dispatching','cancellation_requested'),('dispatching','failed_not_submitted'),
('accepted','running'),('accepted','downloading'),('accepted','cancellation_requested'),('accepted','response_adopted'),('accepted','failed_after_acceptance'),
('submission_unknown','reconciling'),('submission_unknown','cancellation_requested'),
('reconciling','accepted'),('reconciling','submission_unknown'),('reconciling','rejected_not_accepted'),('reconciling','downloading'),('reconciling','cancellation_requested'),('reconciling','failed_after_acceptance'),
('running','downloading'),('running','cancellation_requested'),('running','failed_after_acceptance'),
('downloading','response_adopted'),('downloading','completed_after_cancel'),('downloading','cancellation_requested'),('downloading','failed_after_acceptance'),
('cancellation_requested','cancelled'),('cancellation_requested','submission_unknown'),('cancellation_requested','reconciling'),('cancellation_requested','accepted'),('cancellation_requested','downloading'),('cancellation_requested','completed_after_cancel'),('cancellation_requested','failed_after_acceptance'),
('response_adopted','succeeded'),('response_adopted','completed_after_cancel'),('response_adopted','failed_after_acceptance');

CREATE TRIGGER image_generation_job_transition_guard BEFORE UPDATE OF state,version ON image_generation_jobs
WHEN NEW.version != OLD.version+1 OR (
 NOT EXISTS(SELECT 1 FROM image_generation_job_transitions WHERE from_state=OLD.state AND to_state=NEW.state)
 AND NOT (
   OLD.state IN ('dispatching','submission_unknown') AND NEW.state='queued' AND EXISTS(
     SELECT 1 FROM image_generation_slots s
     JOIN image_generation_attempt_activation_facts f ON f.job_id=s.job_id AND f.slot_id=s.slot_id AND f.activation_reason='authoritative_retry'
     JOIN image_generation_attempts prior ON prior.job_id=f.job_id AND prior.slot_id=f.slot_id AND prior.attempt_number=f.prior_attempt_number AND prior.state='rejected_not_accepted'
     JOIN external_journal_operations j ON j.operation_id=prior.external_operation_id AND j.state='rejected'
     JOIN image_generation_attempt_media_snapshots m ON m.job_id=f.job_id AND m.slot_id=f.slot_id AND m.attempt_number=f.attempt_number
     WHERE s.job_id=OLD.job_id AND s.state='queued' AND (EXISTS(SELECT 1 FROM image_generation_handoff_evidence e WHERE e.job_id=prior.job_id AND e.slot_id=prior.slot_id AND e.attempt_number=prior.attempt_number AND e.external_operation_id=j.operation_id AND e.outcome='definitively_rejected') OR EXISTS(SELECT 1 FROM image_generation_reconciliation_evidence e WHERE e.job_id=prior.job_id AND e.slot_id=prior.slot_id AND e.attempt_number=prior.attempt_number AND e.outcome='authoritative_nonacceptance'))
   )
 )
 AND NOT (
   OLD.terminal_event_version IS NULL
   AND NEW.terminal_event_version=NEW.version
   AND EXISTS(
     SELECT 1 FROM image_generation_terminal_events e
     WHERE e.job_id=OLD.job_id
       AND e.job_version=NEW.version
       AND e.terminal_state=NEW.state
   )
 )
)
BEGIN SELECT RAISE(ABORT,'forbidden image generation job transition'); END;
CREATE TRIGGER image_generation_slot_transition_guard BEFORE UPDATE OF state,version ON image_generation_slots
WHEN NEW.version != OLD.version+1 OR (
 (NEW.state != OLD.state AND NOT EXISTS(SELECT 1 FROM image_generation_slot_transitions WHERE from_state=OLD.state AND to_state=NEW.state)
  AND NOT (OLD.state IN ('dispatching','submission_unknown') AND NEW.state='queued' AND EXISTS(
    SELECT 1 FROM image_generation_attempt_activation_facts f
    JOIN image_generation_attempts prior ON prior.job_id=f.job_id AND prior.slot_id=f.slot_id AND prior.attempt_number=f.prior_attempt_number AND prior.state='rejected_not_accepted'
    JOIN external_journal_operations j ON j.operation_id=prior.external_operation_id AND j.state='rejected'
    JOIN image_generation_attempt_media_snapshots m ON m.job_id=f.job_id AND m.slot_id=f.slot_id AND m.attempt_number=f.attempt_number
    WHERE f.job_id=OLD.job_id AND f.slot_id=OLD.slot_id AND f.attempt_number=f.prior_attempt_number+1 AND (EXISTS(SELECT 1 FROM image_generation_handoff_evidence e WHERE e.job_id=prior.job_id AND e.slot_id=prior.slot_id AND e.attempt_number=prior.attempt_number AND e.external_operation_id=j.operation_id AND e.outcome='definitively_rejected') OR EXISTS(SELECT 1 FROM image_generation_reconciliation_evidence e WHERE e.job_id=prior.job_id AND e.slot_id=prior.slot_id AND e.attempt_number=prior.attempt_number AND e.outcome='authoritative_nonacceptance'))
  ))) OR
 (NEW.state = OLD.state AND NOT (OLD.state='validating' AND OLD.applied_cancellation_version IS NULL AND OLD.result_after_cancel=0 AND NEW.applied_cancellation_version IS NOT NULL AND NEW.result_after_cancel=1))
)
BEGIN SELECT RAISE(ABORT,'forbidden image generation slot transition'); END;
CREATE TRIGGER image_generation_attempt_transition_guard BEFORE UPDATE OF state,version ON image_generation_attempts
WHEN NEW.version != OLD.version+1 OR NOT EXISTS(SELECT 1 FROM image_generation_attempt_transitions WHERE from_state=OLD.state AND to_state=NEW.state)
BEGIN SELECT RAISE(ABORT,'forbidden image generation attempt transition'); END;
CREATE TRIGGER image_generation_attempt_retry_guard BEFORE UPDATE OF state ON image_generation_attempts
WHEN OLD.state='planned' AND NEW.state='preparing' AND NEW.attempt_number>1 AND NOT EXISTS(
 SELECT 1 FROM image_generation_attempts prior WHERE prior.job_id=NEW.job_id AND prior.slot_id=NEW.slot_id
 AND prior.attempt_number=NEW.attempt_number-1 AND prior.state IN ('failed_not_submitted','rejected_not_accepted'))
BEGIN SELECT RAISE(ABORT,'image generation retry lacks authoritative nonacceptance'); END;
CREATE TRIGGER image_generation_attempt_plan_bound_guard BEFORE INSERT ON image_generation_attempts
WHEN NEW.attempt_number > (SELECT max_attempt_count FROM image_generation_slots WHERE job_id=NEW.job_id AND slot_id=NEW.slot_id)
BEGIN SELECT RAISE(ABORT,'image generation attempt exceeds sealed plan'); END;
CREATE TRIGGER image_generation_slot_plan_bound_guard BEFORE INSERT ON image_generation_slots
WHEN NEW.slot_index >= (SELECT slot_count FROM image_generation_plans WHERE job_id=NEW.job_id)
BEGIN SELECT RAISE(ABORT,'image generation slot exceeds sealed plan'); END;
CREATE TRIGGER image_generation_response_adopted_guard AFTER UPDATE OF state ON image_generation_attempts
WHEN NEW.state='response_adopted' AND (
 NEW.applied_cancellation_version IS NOT NULL OR NEW.response_digest IS NULL OR NOT EXISTS(
  SELECT 1 FROM external_journal_operations j WHERE j.operation_id=NEW.external_operation_id
  AND j.state='succeeded' AND j.version=NEW.observed_journal_version)
 OR EXISTS(SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id))
BEGIN SELECT RAISE(ABORT,'response-adopted attempt lacks exact uncancelled journal evidence'); END;
CREATE TRIGGER image_generation_attempt_reconciliation_failure_guard BEFORE UPDATE OF state ON image_generation_attempts
WHEN OLD.state IN ('submission_unknown','reconciling') AND NEW.state IN ('rejected_not_accepted','failed_after_acceptance') AND NOT EXISTS(
 SELECT 1 FROM image_generation_reconciliation_evidence e WHERE e.job_id=NEW.job_id AND e.slot_id=NEW.slot_id AND e.attempt_number=NEW.attempt_number AND e.journal_version=NEW.observed_journal_version)
BEGIN SELECT RAISE(ABORT,'attempt failure lacks authoritative reconciliation evidence'); END;
CREATE TRIGGER image_generation_slot_reconciliation_failure_guard BEFORE UPDATE OF state ON image_generation_slots
WHEN OLD.state IN ('submission_unknown','cancellation_requested') AND NEW.state='failed' AND NOT EXISTS(
 SELECT 1 FROM image_generation_attempts a JOIN image_generation_reconciliation_evidence e ON e.job_id=a.job_id AND e.slot_id=a.slot_id AND e.attempt_number=a.attempt_number AND e.journal_version=a.observed_journal_version
 WHERE a.job_id=NEW.job_id AND a.slot_id=NEW.slot_id)
BEGIN SELECT RAISE(ABORT,'slot failure lacks authoritative reconciliation evidence'); END;
CREATE TRIGGER image_generation_job_reconciliation_failure_guard BEFORE UPDATE OF state ON image_generation_jobs
WHEN OLD.state='submission_unknown' AND NEW.state='failed' AND NOT EXISTS(
 SELECT 1 FROM image_generation_reconciliation_evidence e WHERE e.job_id=NEW.job_id)
BEGIN SELECT RAISE(ABORT,'job failure lacks authoritative reconciliation evidence'); END;
CREATE TRIGGER image_generation_failed_not_submitted_guard BEFORE UPDATE OF state ON image_generation_attempts
WHEN OLD.state='dispatching' AND NEW.state='failed_not_submitted' AND NEW.nonacceptance_evidence_digest IS NULL
BEGIN SELECT RAISE(ABORT,'dispatch failure lacks zero-handoff evidence'); END;
CREATE TRIGGER image_generation_job_cancellation_fact_guard BEFORE UPDATE OF state ON image_generation_jobs
WHEN NEW.state IN ('cancellation_requested','cancelled','completed_after_cancel') AND NOT EXISTS(
 SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id)
BEGIN SELECT RAISE(ABORT,'image generation cancellation projection lacks fact'); END;
CREATE TRIGGER image_generation_slot_cancellation_fact_guard BEFORE UPDATE OF state ON image_generation_slots
WHEN NEW.state IN ('cancellation_requested','cancelled','late_quarantined','discarded') AND NOT EXISTS(
 SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id AND c.cancellation_version=NEW.applied_cancellation_version)
BEGIN SELECT RAISE(ABORT,'image generation slot cancellation projection lacks fact'); END;
CREATE TRIGGER image_generation_job_transition_registry_sealed BEFORE INSERT ON image_generation_job_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_job_transition_registry_update_sealed BEFORE UPDATE ON image_generation_job_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_job_transition_registry_delete_sealed BEFORE DELETE ON image_generation_job_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_slot_transition_registry_sealed BEFORE INSERT ON image_generation_slot_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_slot_transition_registry_update_sealed BEFORE UPDATE ON image_generation_slot_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_slot_transition_registry_delete_sealed BEFORE DELETE ON image_generation_slot_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_attempt_transition_registry_sealed BEFORE INSERT ON image_generation_attempt_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_attempt_transition_registry_update_sealed BEFORE UPDATE ON image_generation_attempt_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_attempt_transition_registry_delete_sealed BEFORE DELETE ON image_generation_attempt_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;

CREATE TRIGGER image_generation_slot_cancellation_vector_insert BEFORE INSERT ON image_generation_slots
WHEN NEW.applied_cancellation_version IS NOT NULL AND NOT EXISTS(
  SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id AND c.cancellation_version=NEW.applied_cancellation_version)
BEGIN SELECT RAISE(ABORT,'image generation slot cites unknown cancellation'); END;
CREATE TRIGGER image_generation_slot_cancellation_vector_update BEFORE UPDATE ON image_generation_slots
WHEN NEW.applied_cancellation_version IS NOT NULL AND NOT EXISTS(
  SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id AND c.cancellation_version=NEW.applied_cancellation_version)
BEGIN SELECT RAISE(ABORT,'image generation slot cites unknown cancellation'); END;
CREATE TRIGGER image_generation_attempt_cancellation_vector_update BEFORE UPDATE ON image_generation_attempts
WHEN NEW.applied_cancellation_version IS NOT NULL AND NOT EXISTS(
  SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id AND c.cancellation_version=NEW.applied_cancellation_version)
BEGIN SELECT RAISE(ABORT,'image generation attempt cites unknown cancellation'); END;
CREATE TRIGGER image_generation_cancelled_attempt_fact_guard AFTER UPDATE OF state ON image_generation_attempts
WHEN NEW.state='completed_after_cancel' AND NOT EXISTS(
  SELECT 1 FROM image_generation_cancelled_result_facts f WHERE f.job_id=NEW.job_id AND f.slot_id=NEW.slot_id AND f.attempt_number=NEW.attempt_number AND f.cancellation_version=NEW.applied_cancellation_version)
BEGIN SELECT RAISE(ABORT,'completed-after-cancel attempt lacks exact fact'); END;
CREATE TRIGGER image_generation_succeeded_attempt_fact_guard AFTER UPDATE OF state ON image_generation_attempts
WHEN NEW.state='succeeded' AND (NEW.applied_cancellation_version IS NOT NULL OR NOT EXISTS(
  SELECT 1 FROM image_generation_publication_right_facts f WHERE f.job_id=NEW.job_id AND f.slot_id=NEW.slot_id AND f.attempt_number=NEW.attempt_number))
BEGIN SELECT RAISE(ABORT,'succeeded attempt lacks ordinary publication right'); END;
CREATE TRIGGER image_generation_cancelled_result_ordering_guard BEFORE INSERT ON image_generation_cancelled_result_facts
WHEN NOT EXISTS(
 SELECT 1 FROM image_generation_attempts a JOIN external_journal_operations j ON j.operation_id=a.external_operation_id
 WHERE a.job_id=NEW.job_id AND a.slot_id=NEW.slot_id AND a.attempt_number=NEW.attempt_number
 AND j.version=NEW.journal_terminal_version
 AND ((NEW.ordering='response_after_cancellation' AND j.state='completed_after_cancel') OR (NEW.ordering='response_adopted_before_cancellation' AND j.state='succeeded')))
BEGIN SELECT RAISE(ABORT,'cancelled-result ordering lacks journal evidence'); END;
CREATE TRIGGER image_generation_publication_right_guard BEFORE INSERT ON image_generation_publication_right_facts
WHEN EXISTS(SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id)
 OR NOT EXISTS(SELECT 1 FROM image_generation_attempts a JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id
   WHERE a.job_id=NEW.job_id AND a.slot_id=NEW.slot_id AND a.attempt_number=NEW.attempt_number
   AND a.state='response_adopted' AND a.applied_cancellation_version IS NULL AND s.state='ready_to_publish'
   AND s.version=NEW.slot_version AND s.applied_cancellation_version IS NULL AND s.result_after_cancel=0)
BEGIN SELECT RAISE(ABORT,'ordinary publication right lost its compare-and-set'); END;

CREATE TRIGGER image_generation_plans_immutable
BEFORE UPDATE ON image_generation_plans BEGIN
  SELECT RAISE(ABORT, 'image generation plans are immutable');
END;
CREATE TRIGGER image_generation_cancellations_immutable
BEFORE UPDATE ON image_generation_cancellation_facts BEGIN
  SELECT RAISE(ABORT, 'image generation cancellation facts are immutable');
END;
CREATE TRIGGER image_generation_cancelled_results_immutable
BEFORE UPDATE ON image_generation_cancelled_result_facts BEGIN
  SELECT RAISE(ABORT, 'image generation cancelled-result facts are immutable');
END;
CREATE TRIGGER image_generation_publication_rights_immutable
BEFORE UPDATE ON image_generation_publication_right_facts BEGIN
  SELECT RAISE(ABORT, 'image generation publication-right facts are immutable');
END;
