-- 0008_interrupt_questions.sql — multi-question interrupts (GOALS §3b).
--
-- The `question` tool raises one interrupt carrying an ARRAY of questions
-- (tool dispatch is sequential, so everything the agent needs has to ride
-- in a single call). `questions_json` holds a serialized
-- proto::InterruptQuestionSet; the legacy single-question `question_json`
-- column stays for the `jobs` needs-attention nudge and pre-§3b rows. A
-- row never populates both columns.

ALTER TABLE needs_attention ADD COLUMN questions_json TEXT;
