ALTER TABLE tool_call_events ADD COLUMN provider_item_id TEXT DEFAULT NULL;
ALTER TABLE tool_call_events ADD COLUMN provider_call_id TEXT DEFAULT NULL;
ALTER TABLE tool_call_events ADD COLUMN provider_call_id_source TEXT DEFAULT NULL;
ALTER TABLE tool_call_events ADD COLUMN wire_api TEXT DEFAULT NULL;
ALTER TABLE tool_call_events ADD COLUMN provider_family TEXT DEFAULT NULL;

UPDATE tool_call_events
   SET provider_item_id = NULL,
       provider_call_id = call_id,
       provider_call_id_source = 'legacy_synthesized_from_cockpit_call_id',
       wire_api = 'responses',
       provider_family = CASE
           WHEN provider = 'codex-oauth' THEN 'codex'
           WHEN provider IN ('grok', 'grok-oauth') THEN 'xai'
           WHEN provider = 'openai' THEN 'openai'
           ELSE 'unknown'
       END
 WHERE provider IN ('codex-oauth', 'grok', 'grok-oauth')
    OR (provider = 'openai' AND lower(model) LIKE 'gpt-5%');

UPDATE tool_call_events
   SET provider_call_id_source = 'unknown_legacy',
       wire_api = 'unknown',
       provider_family = 'unknown'
 WHERE provider_call_id_source IS NULL;
