-- Immutable attribution captured when an inference request is dispatched.
-- NULL means the call was not dispatched as supervised host-goal work.
ALTER TABLE inference_requests ADD COLUMN goal_id TEXT;
ALTER TABLE inference_requests ADD COLUMN goal_attempt_generation INTEGER;

CREATE INDEX idx_ireq_goal_provenance
    ON inference_requests (goal_id, goal_attempt_generation);
