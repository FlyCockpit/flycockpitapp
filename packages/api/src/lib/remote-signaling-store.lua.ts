import {
  REMOTE_SIGNALING_ATTEMPT_TTL_MS,
  REMOTE_SIGNALING_MAX_AGGREGATE_BYTES,
  REMOTE_SIGNALING_MAX_CANDIDATES_PER_ROLE,
  REMOTE_SIGNALING_MAX_EVENTS,
  REMOTE_SIGNALING_TRANSITION_ROWS,
  RemoteSignalingEventKind,
} from "@flycockpit/cockpit-protocol";

const roleId = { server: 1, client: 2, daemon: 3 } as const;
const LUA_TRANSITION_KEYS = REMOTE_SIGNALING_TRANSITION_ROWS.flatMap((row) =>
  (row.transport === "common" ? ["webrtc", "websocket_data"] : [row.transport]).map(
    (transport) =>
      `['${transport}:${RemoteSignalingEventKind[row.event as keyof typeof RemoteSignalingEventKind]}:${roleId[row.role as keyof typeof roleId]}']=true`,
  ),
).join(",");

/** Redis-Cluster-local atomic reducer. KEYS are metadata, events, idempotency. */
export const REMOTE_SIGNALING_COMMIT_LUA = String.raw`
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local exists = redis.call('EXISTS', KEYS[1])
if exists == 0 then return {'unavailable'} end
local expires = tonumber(redis.call('HGET', KEYS[1], 'expiresAtMs'))
if not expires or now_ms >= expires then
  redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
  return {'unavailable'}
end
local old = redis.call('HGET', KEYS[3], ARGV[1])
if old then
  local sep = string.find(old, '\n', 1, true)
  local binding = sep and string.find(old, '\n', sep + 1, true)
  if not binding or string.sub(old, binding + 1) ~= ARGV[2] then return {'conflict'} end
  if string.sub(old, sep + 1, binding - 1) ~= ARGV[7] then return {'unavailable'} end
  return {'replay', string.sub(old, 1, sep - 1)}
end
local count = tonumber(redis.call('HGET', KEYS[1], 'eventCount') or '0')
local total = tonumber(redis.call('HGET', KEYS[1], 'eventBytes') or '0')
local request_len = tonumber(ARGV[3])
if count >= ${REMOTE_SIGNALING_MAX_EVENTS} or total + request_len > ${REMOTE_SIGNALING_MAX_AGGREGATE_BYTES} then return {'limit'} end
local sequence = tonumber(redis.call('HGET', KEYS[1], 'sequence') or '0') + 1
local state = redis.call('HGET', KEYS[1], 'state')
if redis.call('HGET', KEYS[1], 'childAttemptId') ~= ARGV[15] then return {'unavailable'} end
if redis.call('HGET', KEYS[1], 'transportKind') ~= ARGV[8] then return {'unavailable'} end
if state == 'completed' or state == 'rejected' or state == 'cancelled' or state == 'superseded' then return {'invalid_transition'} end
local kind = tonumber(ARGV[4]); local role = tonumber(ARGV[5]); local next_state = state
local allowed = {${LUA_TRANSITION_KEYS}}
if not allowed[ARGV[8]..':'..tostring(kind)..':'..tostring(role)] then return {'invalid_transition'} end
local function mark(name)
  if redis.call('HEXISTS', KEYS[1], name) == 1 then return false end
  redis.call('HSET', KEYS[1], name, '1'); return true
end
if kind == 1 then return {'invalid_transition'}
elseif kind == 2 and state == 'created' and role == 3 and mark('daemonOffer') then redis.call('HSET',KEYS[1],'daemonOfferDigest',ARGV[16],'daemonOfferJti',ARGV[17]);next_state='daemon_offered'
elseif kind == 3 and state == 'daemon_offered' and role == 2 and redis.call('HGET',KEYS[1],'daemonOfferDigest')==ARGV[16] and redis.call('HGET',KEYS[1],'daemonOfferJti')==ARGV[17] and mark('admission') then next_state='admitted'
elseif kind == 4 and state == 'admitted' and role == 2 and mark('offer') then next_state='offered'
elseif kind == 5 and state == 'offered' and role == 3 and mark('answer') then next_state='answered'
elseif kind == 6 and (state == 'offered' or state == 'answered') then
  if role == 3 and state ~= 'answered' then return {'invalid_transition'} end
  local count_key = role == 2 and 'clientCandidates' or 'daemonCandidates'
  local complete_key = role == 2 and 'clientIceComplete' or 'daemonIceComplete'
  local candidates = tonumber(redis.call('HGET', KEYS[1], count_key) or '0')
  if candidates >= ${REMOTE_SIGNALING_MAX_CANDIDATES_PER_ROLE} or redis.call('HEXISTS', KEYS[1], complete_key) == 1 then return {'invalid_transition'} end
  redis.call('HSET', KEYS[1], count_key, candidates + 1)
elseif kind == 7 and (state == 'offered' or state == 'answered') then
  if role == 3 and state ~= 'answered' then return {'invalid_transition'} end
  if not mark(role == 2 and 'clientIceComplete' or 'daemonIceComplete') then return {'invalid_transition'} end
elseif kind == 8 and state == 'admitted' and role == 1 and mark('fallbackPair') then next_state='fallback_paired'
elseif kind == 9 and (state == 'fallback_paired' or state == 'fallback_noise_complete') and (role == 2 or role == 3) then
  if not mark(role == 2 and 'clientNoise' or 'daemonNoise') then return {'invalid_transition'} end
  if redis.call('HEXISTS', KEYS[1], 'clientNoise') == 1 and redis.call('HEXISTS', KEYS[1], 'daemonNoise') == 1 then next_state='fallback_noise_complete' end
elseif (kind == 10 or kind == 11) and (state == 'answered' or state == 'fallback_noise_complete') then
  if state == 'answered' and (redis.call('HEXISTS', KEYS[1], 'clientIceComplete') == 0 or redis.call('HEXISTS', KEYS[1], 'daemonIceComplete') == 0) then return {'invalid_transition'} end
  local proof_key = role == 2 and 'clientProof' or 'daemonProof'
  local peer_key = role == 2 and 'daemonProof' or 'clientProof'
  if redis.call('HEXISTS', KEYS[1], proof_key) == 1 then return {'invalid_transition'} end
  local peer_agreement = redis.call('HGET', KEYS[1], peer_key..'Agreement')
  if peer_agreement and peer_agreement ~= ARGV[9] then return {'invalid_transition'} end
  if peer_agreement and ARGV[14] == '' then return {'retry'} end
  redis.call('HSET', KEYS[1], proof_key, '1', proof_key..'Agreement', ARGV[9], proof_key..'Jti', ARGV[10], proof_key..'Payload', ARGV[13])
  if peer_agreement then redis.call('HSET', KEYS[1], 'finalProofSetDigest', ARGV[14]) end
elseif kind == 12 and (state == 'answered' or state == 'fallback_noise_complete') and (role == 2 or role == 3) then
  if redis.call('HEXISTS', KEYS[1], 'clientProof') == 0 or redis.call('HEXISTS', KEYS[1], 'daemonProof') == 0 then return {'invalid_transition'} end
  local peer_key = role == 2 and 'daemonProof' or 'clientProof'
  if redis.call('HGET', KEYS[1], peer_key..'Jti') ~= ARGV[11] or ARGV[12] == '' then return {'invalid_transition'} end
  if redis.call('HGET', KEYS[1], 'finalProofSetDigest') ~= ARGV[12] then return {'invalid_transition'} end
  if not mark(role == 2 and 'clientReady' or 'daemonReady') then return {'invalid_transition'} end
  if redis.call('HEXISTS', KEYS[1], 'clientReady') == 1 and redis.call('HEXISTS', KEYS[1], 'daemonReady') == 1 then next_state='completed' end
elseif kind == 13 and (role == 1 or role == 3) then next_state='rejected'
elseif kind == 14 then next_state='cancelled'
elseif kind == 15 and role == 1 then next_state='superseded'
else return {'invalid_transition'} end
redis.call('HSET', KEYS[1], 'state', next_state, 'sequence', sequence, 'eventCount', count + 1, 'eventBytes', total + request_len)
redis.call('XADD', KEYS[2], tostring(sequence)..'-0', 'request', ARGV[6], 'actor', ARGV[7], 'createdAtMs', tostring(now_ms))
redis.call('HSET', KEYS[3], ARGV[1], tostring(sequence)..'\n'..ARGV[7]..'\n'..ARGV[2])
redis.call('PEXPIREAT', KEYS[1], expires); redis.call('PEXPIREAT', KEYS[2], expires); redis.call('PEXPIREAT', KEYS[3], expires)
local route = redis.call('HGET', KEYS[1], 'attemptWakeRouteId')
redis.call('PUBLISH', 'flycockpit:remote-signaling:attempt-wake:'..route, cjson.encode({attemptWakeRouteId=route, latestSeq=tostring(sequence)}))
return {'committed', tostring(sequence), tostring(now_ms)}
`;

export const REMOTE_SIGNALING_CREATE_LUA = String.raw`
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local expires = now_ms + ${REMOTE_SIGNALING_ATTEMPT_TTL_MS}
local function unhex(value)
  return (string.gsub(value, '..', function(pair) return string.char(tonumber(pair, 16)) end))
end
local function be64(value)
  local bytes = {}
  for index = 8, 1, -1 do bytes[index] = string.char(value % 256); value = math.floor(value / 256) end
  return table.concat(bytes)
end
local discovery_seq = nil
local instance_route = nil
local instance_route_generation = nil
if ARGV[11] == '1' then
  instance_route = redis.call('HGET', KEYS[6], 'instanceWakeRouteId')
  instance_route_generation = redis.call('HGET', KEYS[6], 'instanceWakeRouteGeneration')
  local wake_expires = tonumber(redis.call('HGET', KEYS[6], 'expiresAtMs'))
  if not wake_expires or now_ms >= wake_expires then instance_route = nil; instance_route_generation = nil end
  local last_id = '0-0'
  if redis.call('EXISTS', KEYS[4]) == 1 then
    local info = redis.call('XINFO', 'STREAM', KEYS[4])
    for index = 1, #info, 2 do if info[index] == 'last-generated-id' then last_id = info[index + 1] end end
  end
  discovery_seq = tonumber(string.match(last_id, '^(%d+)')) + 1
end
if redis.call('EXISTS', KEYS[1]) == 1 then
  local old = redis.call('HGET', KEYS[3], ARGV[9])
  if not old then return {'conflict'} end
  local sep = string.find(old, '\n', 1, true)
  local binding = sep and string.find(old, '\n', sep + 1, true)
  if not binding or string.sub(old, binding + 1) ~= ARGV[10] then return {'conflict'} end
  if string.sub(old, sep + 1, binding - 1) ~= ARGV[8] then return {'unavailable'} end
  return {'replay', string.sub(old, 1, sep - 1)}
end
redis.call('HSET', KEYS[1], 'childAttemptId', ARGV[1], 'transportKind', ARGV[2], 'attemptWakeRouteId', ARGV[3],
 'participantA', ARGV[4], 'participantB', ARGV[5], 'createdAtMs', tostring(now_ms), 'expiresAtMs', tostring(expires),
 'state', 'created', 'sequence', '1', 'eventCount', '1', 'eventBytes', ARGV[6])
redis.call('XADD', KEYS[2], '1-0', 'request', ARGV[7], 'actor', ARGV[8], 'createdAtMs', tostring(now_ms))
redis.call('HSET', KEYS[3], ARGV[9], '1\n'..ARGV[8]..'\n'..ARGV[10])
redis.call('PEXPIREAT', KEYS[1], expires); redis.call('PEXPIREAT', KEYS[2], expires); redis.call('PEXPIREAT', KEYS[3], expires)
if discovery_seq then
  local entry_key = string.gsub(KEYS[4], ':discovery:', ':discovery-entry:', 1)..':'..tostring(discovery_seq)
  local entry = unhex(ARGV[12])..unhex(ARGV[14])..unhex(ARGV[3])..unhex(ARGV[13])..be64(expires)
  redis.call('XADD', KEYS[4], tostring(discovery_seq)..'-0', 'expiresAt', tostring(expires))
  redis.call('SET', entry_key, entry, 'PXAT', expires)
  if instance_route then redis.call('PUBLISH', 'flycockpit:remote-signaling:instance-wake:'..instance_route, cjson.encode({instanceWakeRouteId=instance_route, instanceWakeRouteGeneration=instance_route_generation, latestDiscoverySeq=tostring(discovery_seq)})) end
end
redis.call('PUBLISH', 'flycockpit:remote-signaling:attempt-wake:'..ARGV[3], cjson.encode({attemptWakeRouteId=ARGV[3], latestSeq='1'}))
return {'committed', '1', tostring(now_ms), ARGV[3], discovery_seq and tostring(discovery_seq) or '0'}
`;

/**
 * Mint a single-use admission ticket. Only `SHA-256(secret)` plus bindings are
 * stored; TTL is 30 s from Redis `TIME`. KEYS[1] is the ticket hash.
 * ARGV: secretSha256, originClass, childAttemptId(b64url), admissionProofSha256,
 * daemonInstanceId, accountId, deviceAttachmentId, deviceGeneration.
 */
export const REMOTE_SIGNALING_ISSUE_ADMISSION_TICKET_LUA = String.raw`
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local expires = now_ms + 30000
redis.call('HSET', KEYS[1], 'secretSha256', ARGV[1], 'originClass', ARGV[2], 'childAttemptId', ARGV[3],
 'admissionProofSha256', ARGV[4], 'daemonInstanceId', ARGV[5], 'accountId', ARGV[6],
 'deviceAttachmentId', ARGV[7], 'deviceGeneration', ARGV[8], 'expiresAtMs', tostring(expires))
redis.call('PEXPIREAT', KEYS[1], expires)
return tostring(expires)
`;

/**
 * Atomically consume the admission ticket and apply the client_admission_proof
 * (kind 3) transition. KEYS are metadata, events, idempotency, ticket. Ticket
 * mismatches return 'auth_failed' WITHOUT consuming the ticket; the ticket is
 * deleted only when every check (including the state transition) passes, so a
 * concurrent double-connect admits exactly one socket. The actor is built from
 * the ticket's device binding — never from client-declared bytes.
 * ARGV: eventId, bytesHex, requestLen, requestBuffer, childAttemptId(b64url),
 * daemonOfferDigest, daemonOfferJti, ticketSecretSha256, socketOriginClass,
 * requestPayloadSha256, transportKind.
 */
export const REMOTE_SIGNALING_COMMIT_ADMISSION_LUA = String.raw`
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
if redis.call('EXISTS', KEYS[1]) == 0 then return {'unavailable'} end
local expires = tonumber(redis.call('HGET', KEYS[1], 'expiresAtMs'))
if not expires or now_ms >= expires then
  redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
  return {'unavailable'}
end
-- Ticket authentication FIRST: only a fully-authenticated request may reach the
-- idempotency/replay path below. A wrong-secret / absent-ticket replay of a
-- previously committed proof must NEVER return 'replay' (which would grant a
-- second socket lease from one consumed ticket).
if redis.call('EXISTS', KEYS[4]) == 0 then return {'auth_failed'} end
local t_exp = tonumber(redis.call('HGET', KEYS[4], 'expiresAtMs'))
if not t_exp or now_ms >= t_exp then return {'auth_failed'} end
if redis.call('HGET', KEYS[4], 'secretSha256') ~= ARGV[8] then return {'auth_failed'} end
if redis.call('HGET', KEYS[4], 'originClass') ~= ARGV[9] then return {'auth_failed'} end
if redis.call('HGET', KEYS[4], 'childAttemptId') ~= ARGV[5] then return {'auth_failed'} end
if redis.call('HGET', KEYS[4], 'admissionProofSha256') ~= ARGV[10] then return {'auth_failed'} end
-- Idempotent replay (reachable only with a still-valid ticket; a successful
-- admission consumes the ticket, so a genuine cross-call replay lands on
-- 'auth_failed' above instead).
local old = redis.call('HGET', KEYS[3], ARGV[1])
if old then
  local sep = string.find(old, '\n', 1, true)
  local binding = sep and string.find(old, '\n', sep + 1, true)
  if not binding or string.sub(old, binding + 1) ~= ARGV[2] then return {'conflict'} end
  return {'replay', string.sub(old, 1, sep - 1), string.sub(old, sep + 1, binding - 1)}
end
if redis.call('HGET', KEYS[1], 'childAttemptId') ~= ARGV[5] then return {'unavailable'} end
if redis.call('HGET', KEYS[1], 'transportKind') ~= ARGV[11] then return {'unavailable'} end
local count = tonumber(redis.call('HGET', KEYS[1], 'eventCount') or '0')
local total = tonumber(redis.call('HGET', KEYS[1], 'eventBytes') or '0')
local request_len = tonumber(ARGV[3])
if count >= ${REMOTE_SIGNALING_MAX_EVENTS} or total + request_len > ${REMOTE_SIGNALING_MAX_AGGREGATE_BYTES} then return {'limit'} end
local state = redis.call('HGET', KEYS[1], 'state')
if state ~= 'daemon_offered' then return {'invalid_transition'} end
if redis.call('HGET', KEYS[1], 'daemonOfferDigest') ~= ARGV[6] or redis.call('HGET', KEYS[1], 'daemonOfferJti') ~= ARGV[7] then return {'invalid_transition'} end
if redis.call('HEXISTS', KEYS[1], 'admission') == 1 then return {'invalid_transition'} end
local deviceAttachmentId = redis.call('HGET', KEYS[4], 'deviceAttachmentId')
local deviceGeneration = redis.call('HGET', KEYS[4], 'deviceGeneration')
redis.call('DEL', KEYS[4])
redis.call('HSET', KEYS[1], 'admission', '1')
local actor = '{"role":"client","actor":"'..deviceAttachmentId..'","generation":"'..deviceGeneration..'"}'
local sequence = tonumber(redis.call('HGET', KEYS[1], 'sequence') or '0') + 1
redis.call('HSET', KEYS[1], 'state', 'admitted', 'sequence', sequence, 'eventCount', count + 1, 'eventBytes', total + request_len)
redis.call('XADD', KEYS[2], tostring(sequence)..'-0', 'request', ARGV[4], 'actor', actor, 'createdAtMs', tostring(now_ms))
redis.call('HSET', KEYS[3], ARGV[1], tostring(sequence)..'\n'..actor..'\n'..ARGV[2])
redis.call('PEXPIREAT', KEYS[1], expires); redis.call('PEXPIREAT', KEYS[2], expires); redis.call('PEXPIREAT', KEYS[3], expires)
local route = redis.call('HGET', KEYS[1], 'attemptWakeRouteId')
redis.call('PUBLISH', 'flycockpit:remote-signaling:attempt-wake:'..route, cjson.encode({attemptWakeRouteId=route, latestSeq=tostring(sequence)}))
return {'committed', tostring(sequence), actor}
`;

/**
 * Acquire one signal-socket lease for a device attachment. KEYS[1] is a sorted
 * set scored by expiry. Expired members are pruned, then the cap (ARGV[3]) is
 * enforced; re-acquiring an already-held member refreshes it.
 * ARGV: leaseId, ttlMs, cap.
 */
export const REMOTE_SIGNALING_SOCKET_LEASE_ACQUIRE_LUA = String.raw`
local now = redis.call('TIME')
local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', '('..tostring(now_ms))
local existing = redis.call('ZSCORE', KEYS[1], ARGV[1])
if not existing and redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then return {'conflict'} end
local expires = now_ms + tonumber(ARGV[2])
redis.call('ZADD', KEYS[1], expires, ARGV[1])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]))
return {'ok', tostring(expires)}
`;
