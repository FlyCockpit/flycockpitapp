use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// Current relay envelope version.
///
/// Additive changes such as new frame variants or new optional fields with
/// `#[serde(default)]` bump only this value; peers in the supported version
/// window must keep parsing known data and ignoring unknown additive fields.
/// Breaking changes such as removals, renames, or type changes bump
/// `RELAY_MIN_SUPPORTED_ENVELOPE_VERSION`.
pub const RELAY_ENVELOPE_VERSION: u32 = 2;
pub const RELAY_MIN_SUPPORTED_ENVELOPE_VERSION: u32 = 1;

pub fn is_relay_envelope_version_supported(version: u32) -> bool {
    (RELAY_MIN_SUPPORTED_ENVELOPE_VERSION..=RELAY_ENVELOPE_VERSION).contains(&version)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayGrantScope {
    Terminal,
    Agent,
    AgentReadonly,
    ProjectFiles,
    /// Image-generation management authority (foundation capability
    /// ordinal 15). Maps to `PrincipalScope::ImageGenerationAdmin` and, like
    /// its principal counterpart, confers no terminal/agent/project-file
    /// authority; it is only ever honored bound to an exact canonical project.
    ImageGenerationAdmin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayGrant {
    pub scope: RelayGrantScope,
    pub project_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayPrincipal {
    #[serde(deserialize_with = "non_empty_string")]
    pub user_id: String,
    pub grants: Vec<RelayGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_binding: Option<ClientActorBindingV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct ClientActorBindingV1 {
    #[serde(deserialize_with = "schema_version_one")]
    pub schema_version: u8,
    #[serde(deserialize_with = "canonical_nonnil_uuid")]
    pub device_id: uuid::Uuid,
    #[serde(with = "canonical_positive_u64")]
    pub device_generation: u64,
    #[serde(deserialize_with = "canonical_nonnil_uuid")]
    pub logical_attachment_id: uuid::Uuid,
}

fn schema_version_one<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
    let value = u8::deserialize(deserializer)?;
    if value != 1 {
        return Err(serde::de::Error::custom(
            "actor binding schemaVersion must be 1",
        ));
    }
    Ok(value)
}

fn canonical_nonnil_uuid<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<uuid::Uuid, D::Error> {
    let text = String::deserialize(deserializer)?;
    let value = uuid::Uuid::parse_str(&text).map_err(serde::de::Error::custom)?;
    if value.is_nil()
        || value.get_variant() != uuid::Variant::RFC4122
        || value.hyphenated().to_string() != text
    {
        return Err(serde::de::Error::custom(
            "UUID must be canonical lowercase and nonnil",
        ));
    }
    Ok(value)
}

mod canonical_positive_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty()
            || (text.len() > 1 && text.starts_with('0'))
            || !text.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(serde::de::Error::custom(
                "generation must be canonical decimal u64",
            ));
        }
        let value = text.parse::<u64>().map_err(serde::de::Error::custom)?;
        if value == 0 {
            return Err(serde::de::Error::custom("generation must be positive"));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientFrameOrigin {
    Client,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DaemonControlTarget {
    Control,
}

macro_rules! attention_event_type {
    ($($variant:ident => $wire:literal),+ $(,)?) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum AttentionEventType {
            $($variant,)+
            Unknown(String),
        }

        impl AttentionEventType {
            pub fn canonical_variants() -> impl Iterator<Item = Self> {
                [$(Self::$variant,)+].into_iter()
            }

            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $wire,)+
                    Self::Unknown(raw) => raw.as_str(),
                }
            }
        }

        impl Serialize for AttentionEventType {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for AttentionEventType {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                match value.as_str() {
                    $($wire => Ok(Self::$variant),)+
                    "" => Err(serde::de::Error::custom(
                        "expected non-empty attention event type",
                    )),
                    _ => Ok(Self::Unknown(value)),
                }
            }
        }
    };
}

attention_event_type! {
    ApprovalNeeded => "APPROVAL_NEEDED",
    QuestionRaised => "QUESTION_RAISED",
    TurnDone => "TURN_DONE",
    TurnError => "TURN_ERROR",
    ScheduleDone => "SCHEDULE_DONE",
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemCode {
    BadFrame,
    ChannelLimit,
    DaemonReplaced,
    ForcedDisconnect,
    InstanceOffline,
    RateLimited,
}

impl SystemCode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::BadFrame => "bad_frame",
            Self::ChannelLimit => "channel_limit",
            Self::DaemonReplaced => "daemon_replaced",
            Self::ForcedDisconnect => "forced_disconnect",
            Self::InstanceOffline => "instance_offline",
            Self::RateLimited => "rate_limited",
        }
    }
}

impl fmt::Display for SystemCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl PartialEq<&str> for SystemCode {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<SystemCode> for &str {
    fn eq(&self, other: &SystemCode) -> bool {
        *self == other.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientRelayFrame {
    #[serde(deserialize_with = "relay_envelope_version")]
    pub v: u32,
    #[serde(deserialize_with = "non_empty_string")]
    pub channel_id: String,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StampedClientRelayFrame {
    #[serde(deserialize_with = "relay_envelope_version")]
    pub v: u32,
    #[serde(deserialize_with = "non_empty_string")]
    pub channel_id: String,
    pub from: ClientFrameOrigin,
    pub principal: RelayPrincipal,
    pub payload: Value,
}

impl<'de> Deserialize<'de> for StampedClientRelayFrame {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            #[serde(deserialize_with = "relay_envelope_version")]
            v: u32,
            #[serde(deserialize_with = "non_empty_string")]
            channel_id: String,
            from: ClientFrameOrigin,
            principal: RelayPrincipal,
            payload: Value,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.v == 1 && wire.principal.actor_binding.is_some() {
            return Err(serde::de::Error::custom(
                "relay envelope v1 must be actorless",
            ));
        }
        Ok(Self {
            v: wire.v,
            channel_id: wire.channel_id,
            from: wire.from,
            principal: wire.principal,
            payload: wire.payload,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonClientRelayFrame {
    #[serde(deserialize_with = "relay_envelope_version")]
    pub v: u32,
    #[serde(deserialize_with = "non_empty_string")]
    pub channel_id: String,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonControlRelayFrame {
    #[serde(deserialize_with = "relay_envelope_version")]
    pub v: u32,
    pub to: DaemonControlTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum DaemonRelayFrame {
    Client(DaemonClientRelayFrame),
    Control(DaemonControlRelayFrame),
    Unknown { v: u32, kind: String },
}

impl<'de> Deserialize<'de> for DaemonRelayFrame {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("expected relay frame object"))?;
        let unknown_kind = object
            .get("type")
            .or_else(|| object.get("kind"))
            .map(|value| match value {
                Value::String(kind) if !kind.is_empty() => Ok(kind.clone()),
                _ => Err("expected non-empty daemon relay frame kind"),
            })
            .transpose()
            .map_err(serde::de::Error::custom)?;
        if let Some(kind) = unknown_kind {
            let v = serde_json::from_value::<RelayEnvelopeVersionProbe>(value)
                .map_err(serde::de::Error::custom)?
                .v;
            return Ok(Self::Unknown { v, kind });
        }
        if object.contains_key("to") {
            return serde_json::from_value::<DaemonControlRelayFrame>(value)
                .map(Self::Control)
                .map_err(serde::de::Error::custom);
        }
        if object.contains_key("channelId") {
            return serde_json::from_value::<DaemonClientRelayFrame>(value)
                .map(Self::Client)
                .map_err(serde::de::Error::custom);
        }
        Err(serde::de::Error::custom("unknown daemon relay frame shape"))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttentionNotificationPayload {
    #[serde(deserialize_with = "non_empty_string")]
    pub event_id: String,
    #[serde(deserialize_with = "non_empty_string")]
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
    pub event_type: AttentionEventType,
    #[serde(deserialize_with = "non_empty_string")]
    pub fixed_string_title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_string_body: Option<String>,
    #[serde(deserialize_with = "non_empty_string")]
    pub ts: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_principal: Option<AttentionTargetPrincipal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttentionTargetPrincipal {
    #[serde(deserialize_with = "non_empty_string")]
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPresenceRelayFrame {
    #[serde(deserialize_with = "relay_envelope_version")]
    pub v: u32,
    #[serde(rename = "type")]
    pub frame_type: UserPresenceFrameType,
    #[serde(deserialize_with = "non_empty_string")]
    pub client_id: String,
    pub visible: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserPresenceFrameType {
    Presence,
}

pub type UserRelayFrame = UserPresenceRelayFrame;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserNotificationRelayFrame {
    #[serde(deserialize_with = "relay_envelope_version")]
    pub v: u32,
    #[serde(rename = "type")]
    pub frame_type: UserNotificationFrameType,
    pub notification: RelayNotification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserNotificationFrameType {
    Notification,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayNotification {
    #[serde(deserialize_with = "non_empty_string")]
    pub id: String,
    #[serde(rename = "type")]
    pub notification_type: AttentionEventType,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(deserialize_with = "non_empty_string")]
    pub url: String,
    #[serde(deserialize_with = "non_empty_string")]
    pub instance_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ref: Option<String>,
    #[serde(deserialize_with = "non_empty_string")]
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemRelayFrame {
    #[serde(deserialize_with = "relay_envelope_version")]
    pub v: u32,
    #[serde(rename = "type")]
    pub frame_type: SystemFrameType,
    pub code: SystemCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SystemFrameType {
    System,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IncomingRelayFrame {
    Client(StampedClientRelayFrame),
    System(SystemRelayFrame),
    Unknown { v: u32, kind: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum RelayControlMessage {
    DisconnectInstance {
        #[serde(deserialize_with = "non_empty_string")]
        instance_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    DisconnectUser {
        #[serde(deserialize_with = "non_empty_string")]
        user_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        instance_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    NotifyUser {
        #[serde(deserialize_with = "non_empty_string")]
        user_id: String,
        notification: RelayNotification,
    },
    #[serde(other)]
    Unknown,
}

pub fn parse_incoming(value: &str) -> serde_json::Result<IncomingRelayFrame> {
    let parsed = serde_json::from_str::<Value>(value)?;
    if parsed
        .as_object()
        .is_some_and(|object| object.contains_key("type"))
    {
        let kind = serde_json::from_value::<RelayFrameKindProbe>(parsed.clone())?.kind;
        if kind == "system" {
            return serde_json::from_value::<SystemRelayFrame>(parsed)
                .map(IncomingRelayFrame::System);
        }
        let v = serde_json::from_value::<RelayEnvelopeVersionProbe>(parsed)?.v;
        return Ok(IncomingRelayFrame::Unknown { v, kind });
    }
    let v = serde_json::from_value::<RelayEnvelopeVersionProbe>(parsed.clone())?.v;
    if !is_relay_envelope_version_supported(v) {
        return Ok(IncomingRelayFrame::Unknown {
            v,
            kind: "client".to_string(),
        });
    }
    serde_json::from_value::<StampedClientRelayFrame>(parsed).map(IncomingRelayFrame::Client)
}

pub fn daemon_client_frame(channel_id: String, payload: Value) -> DaemonClientRelayFrame {
    DaemonClientRelayFrame {
        v: RELAY_ENVELOPE_VERSION,
        channel_id,
        payload,
    }
}

pub fn daemon_control_frame(event: impl Into<String>, payload: Value) -> DaemonControlRelayFrame {
    DaemonControlRelayFrame {
        v: RELAY_ENVELOPE_VERSION,
        to: DaemonControlTarget::Control,
        event: Some(event.into()),
        payload,
    }
}

fn non_empty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        Err(serde::de::Error::custom("expected non-empty string"))
    } else {
        Ok(value)
    }
}

fn relay_envelope_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = u32::deserialize(deserializer)?;
    if is_relay_envelope_version_supported(value) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "unsupported relay envelope version",
        ))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelayEnvelopeVersionProbe {
    #[serde(deserialize_with = "relay_envelope_version")]
    v: u32,
}

#[derive(Deserialize)]
struct RelayFrameKindProbe {
    #[serde(rename = "type", deserialize_with = "non_empty_string")]
    kind: String,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;

    use super::*;

    #[test]
    fn client_actor_binding_codec_is_strict_and_u64_complete() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../packages/relay-protocol/fixtures/client-actor-binding-v1.json"
        )))
        .unwrap();
        for vector in vectors["valid"].as_array().unwrap() {
            let value = vector["value"].clone();
            let binding: ClientActorBindingV1 = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(
                serde_json::to_value(binding).unwrap(),
                value,
                "{}",
                vector["name"]
            );
        }
        for vector in vectors["invalid"].as_array().unwrap() {
            assert!(
                serde_json::from_value::<ClientActorBindingV1>(vector["value"].clone()).is_err(),
                "{}",
                vector["name"]
            );
        }
    }
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use serde_json::{Map, json};

    #[test]
    fn parses_stamped_client_frame_from_canonical_shape() {
        let raw = r#"{
          "v": 1,
          "channelId": "ch-1",
          "from": "client",
          "principal": {
            "userId": "user-1",
            "grants": [{ "scope": "terminal", "projectRoot": null }]
          },
          "payload": { "kind": "req" }
        }"#;
        let frame = parse_incoming(raw).unwrap();
        match frame {
            IncomingRelayFrame::Client(frame) => {
                assert_eq!(frame.channel_id, "ch-1");
                assert_eq!(frame.principal.user_id, "user-1");
                assert_eq!(frame.principal.grants[0].scope, RelayGrantScope::Terminal);
                assert_eq!(frame.payload, json!({"kind": "req"}));
            }
            IncomingRelayFrame::System(_) => panic!("expected client frame"),
            IncomingRelayFrame::Unknown { .. } => panic!("expected client frame"),
        }
    }

    #[test]
    fn relay_grant_scope_image_generation_admin_roundtrips_snake_case() {
        // The unified image-admin scope is a wire-representable relay grant
        // scope that round-trips through the canonical snake_case string.
        assert_eq!(
            serde_json::to_string(&RelayGrantScope::ImageGenerationAdmin).unwrap(),
            "\"image_generation_admin\""
        );
        assert_eq!(
            serde_json::from_str::<RelayGrantScope>("\"image_generation_admin\"").unwrap(),
            RelayGrantScope::ImageGenerationAdmin
        );
        // A stamped client frame carrying the new scope parses through the real
        // production entry point.
        let raw = r#"{
          "v": 1,
          "channelId": "ch-1",
          "from": "client",
          "principal": {
            "userId": "user-1",
            "grants": [{ "scope": "image_generation_admin", "projectRoot": "/workspace/app" }]
          },
          "payload": { "kind": "req" }
        }"#;
        match parse_incoming(raw).unwrap() {
            IncomingRelayFrame::Client(frame) => {
                assert_eq!(
                    frame.principal.grants[0].scope,
                    RelayGrantScope::ImageGenerationAdmin
                );
            }
            _ => panic!("expected client frame"),
        }
    }

    #[test]
    fn serializes_daemon_frame_to_canonical_shape() {
        let frame = daemon_client_frame("ch-1".to_string(), json!({ "text": "world" }));
        let value = serde_json::to_value(frame).unwrap();
        assert_eq!(
            value,
            json!({ "v": 2, "channelId": "ch-1", "payload": { "text": "world" } })
        );
    }

    #[test]
    fn valid_fixtures_parse_and_roundtrip_canonically() {
        let root = fixture_root();
        for entry in fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy();
            let raw = fs::read_to_string(&path).unwrap();
            match name.as_ref() {
                "client-relay-frame.json" => assert_roundtrip::<ClientRelayFrame>(&raw),
                "stamped-client-relay-frame.json" | "stamped-client-relay-frame-v1.json" => {
                    assert_roundtrip::<StampedClientRelayFrame>(&raw)
                }
                "client-actor-binding-v1.json" => {
                    let _: serde_json::Value = serde_json::from_str(&raw).unwrap();
                }
                "daemon-client-relay-frame.json" => {
                    assert_roundtrip::<DaemonClientRelayFrame>(&raw)
                }
                "daemon-control-relay-frame.json" => {
                    assert_roundtrip::<DaemonControlRelayFrame>(&raw)
                }
                "user-presence-relay-frame.json" => {
                    assert_roundtrip::<UserPresenceRelayFrame>(&raw)
                }
                "user-notification-relay-frame.json" => {
                    assert_roundtrip::<UserNotificationRelayFrame>(&raw)
                }
                "system-relay-frame.json" => assert_roundtrip::<SystemRelayFrame>(&raw),
                "control-disconnect-instance.json"
                | "control-disconnect-user.json"
                | "control-notify-user.json" => assert_roundtrip::<RelayControlMessage>(&raw),
                other => panic!("unmapped fixture {other}"),
            }
        }
    }

    #[test]
    fn invalid_fixtures_are_rejected_by_every_schema() {
        for entry in fs::read_dir(fixture_root().join("invalid")).unwrap() {
            let path = entry.unwrap().path();
            let raw = fs::read_to_string(&path).unwrap();
            assert!(
                !parses_any_schema(&raw),
                "invalid fixture parsed successfully: {}",
                path.display()
            );
        }
    }

    #[test]
    fn forward_compat_frame_accepts_unknown_additive_field() {
        let raw = fs::read_to_string(
            fixture_root()
                .join("forward-compat")
                .join("client-relay-frame-additive-field.json"),
        )
        .unwrap();

        let frame = serde_json::from_str::<ClientRelayFrame>(&raw).unwrap();

        assert_eq!(frame.v, RELAY_MIN_SUPPORTED_ENVELOPE_VERSION);
        assert_eq!(frame.channel_id, "ch-forward");
        assert_eq!(frame.payload, json!({"kind": "req"}));
    }

    #[test]
    fn forward_compat_daemon_control_with_additive_channel_id_routes_to_control() {
        let raw = json!({
            "v": RELAY_ENVELOPE_VERSION,
            "to": "control",
            "channelId": "additive-channel",
            "event": "attention",
            "payload": { "kind": "notice" }
        });

        let frame = serde_json::from_value::<DaemonRelayFrame>(raw).unwrap();

        match frame {
            DaemonRelayFrame::Control(frame) => {
                assert_eq!(frame.event.as_deref(), Some("attention"));
                assert_eq!(frame.payload, json!({"kind": "notice"}));
            }
            DaemonRelayFrame::Client(_) => panic!("control frame routed as client frame"),
            DaemonRelayFrame::Unknown { .. } => panic!("control frame routed as unknown frame"),
        }
    }

    #[test]
    fn frame_kind_unknown_is_tolerated() {
        let raw = fs::read_to_string(
            fixture_root()
                .join("forward-compat")
                .join("unknown-frame-kind.json"),
        )
        .unwrap();

        let frame = parse_incoming(&raw).unwrap();

        assert_eq!(
            frame,
            IncomingRelayFrame::Unknown {
                v: RELAY_MIN_SUPPORTED_ENVELOPE_VERSION,
                kind: "mystery".to_string()
            }
        );
    }

    #[test]
    fn frame_kind_unknown_with_bad_version_still_rejected() {
        let raw = json!({
            "v": RELAY_ENVELOPE_VERSION + 1,
            "type": "mystery",
            "payload": {}
        })
        .to_string();

        assert!(parse_incoming(&raw).is_err());
    }

    #[test]
    fn daemon_unknown_frame_kind_takes_precedence_over_known_shape_fields() {
        let raw = json!({
            "v": RELAY_ENVELOPE_VERSION,
            "type": "future_daemon_frame",
            "channelId": "future-channel",
            "payload": {}
        });

        let frame = serde_json::from_value::<DaemonRelayFrame>(raw).unwrap();

        assert_eq!(
            frame,
            DaemonRelayFrame::Unknown {
                v: RELAY_ENVELOPE_VERSION,
                kind: "future_daemon_frame".to_string()
            }
        );
    }

    #[test]
    fn forward_compat_version_within_window_is_accepted() {
        let raw = json!({
            "v": RELAY_MIN_SUPPORTED_ENVELOPE_VERSION,
            "channelId": "ch-1",
            "payload": { "kind": "req" }
        });

        let frame = serde_json::from_value::<ClientRelayFrame>(raw).unwrap();

        assert_eq!(frame.v, RELAY_MIN_SUPPORTED_ENVELOPE_VERSION);
    }

    #[test]
    fn forward_compat_version_outside_window_is_rejected() {
        let raw = json!({
            "v": RELAY_ENVELOPE_VERSION + 1,
            "channelId": "ch-1",
            "payload": { "kind": "req" }
        });

        assert!(serde_json::from_value::<ClientRelayFrame>(raw).is_err());
    }

    #[test]
    fn attention_event_type_unknown_preserves_tag() {
        let event_type =
            serde_json::from_str::<AttentionEventType>(r#""NEW_ATTENTION_TYPE""#).unwrap();

        assert_eq!(
            event_type,
            AttentionEventType::Unknown("NEW_ATTENTION_TYPE".to_string())
        );
        assert_eq!(
            serde_json::to_string(&event_type).unwrap(),
            r#""NEW_ATTENTION_TYPE""#
        );
    }

    #[test]
    fn attention_event_type_matches_shared_fixture() {
        let fixture = attention_kind_fixture();
        let canonical = AttentionEventType::canonical_variants()
            .map(|event_type| event_type.as_str().to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(canonical, fixture);
        for event_type in fixture {
            let parsed = serde_json::from_value::<AttentionEventType>(json!(event_type)).unwrap();
            assert_eq!(parsed.as_str(), event_type);
            assert!(!matches!(parsed, AttentionEventType::Unknown(_)));
            assert_eq!(serde_json::to_value(parsed).unwrap(), json!(event_type));
        }
    }

    fn fixture_root() -> &'static Path {
        Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../packages/relay-protocol/fixtures"
        ))
    }

    fn attention_kind_fixture() -> BTreeSet<String> {
        let path = fixture_root().join("attention/attention-kinds.json");
        let kinds: Vec<String> = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        let unique = kinds.iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            unique.len(),
            kinds.len(),
            "attention fixture has duplicates"
        );
        unique
    }

    fn assert_roundtrip<T>(raw: &str)
    where
        T: DeserializeOwned + Serialize,
    {
        let original = serde_json::from_str::<Value>(raw).unwrap();
        let parsed = serde_json::from_str::<T>(raw).unwrap();
        let serialized = serde_json::to_value(parsed).unwrap();
        assert_eq!(canonical(original), canonical(serialized));
    }

    fn parses_any_schema(raw: &str) -> bool {
        let Ok(value) = serde_json::from_str::<Value>(raw) else {
            return false;
        };
        if value
            .as_object()
            .is_some_and(|object| object.contains_key("from") || object.contains_key("principal"))
        {
            return serde_json::from_value::<StampedClientRelayFrame>(value).is_ok();
        }
        serde_json::from_str::<ClientRelayFrame>(raw).is_ok()
            || serde_json::from_str::<StampedClientRelayFrame>(raw).is_ok()
            || serde_json::from_str::<DaemonRelayFrame>(raw).is_ok()
            || serde_json::from_str::<UserPresenceRelayFrame>(raw).is_ok()
            || serde_json::from_str::<UserNotificationRelayFrame>(raw).is_ok()
            || serde_json::from_str::<SystemRelayFrame>(raw).is_ok()
            || serde_json::from_str::<RelayControlMessage>(raw).is_ok()
            || serde_json::from_str::<AttentionNotificationPayload>(raw).is_ok()
    }

    fn canonical(value: Value) -> Value {
        match value {
            Value::Array(items) => Value::Array(items.into_iter().map(canonical).collect()),
            Value::Object(map) => {
                let mut sorted = Map::new();
                let mut keys = map.keys().cloned().collect::<Vec<_>>();
                keys.sort();
                for key in keys {
                    sorted.insert(key.clone(), canonical(map.get(&key).unwrap().clone()));
                }
                Value::Object(sorted)
            }
            other => other,
        }
    }
}
