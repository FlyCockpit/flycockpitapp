use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RELAY_ENVELOPE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayGrantScope {
    Terminal,
    Agent,
    AgentReadonly,
    ProjectFiles,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayGrant {
    pub scope: RelayGrantScope,
    #[serde(rename = "projectRoot")]
    pub project_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPrincipal {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(default)]
    pub grants: Vec<RelayGrant>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StampedClientRelayFrame {
    pub v: u32,
    #[serde(rename = "channelId")]
    pub channel_id: String,
    pub from: String,
    pub principal: RelayPrincipal,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonClientRelayFrame {
    pub v: u32,
    #[serde(rename = "channelId")]
    pub channel_id: String,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonControlRelayFrame {
    pub v: u32,
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemRelayFrame {
    pub v: u32,
    #[serde(rename = "type")]
    pub frame_type: String,
    pub code: String,
    #[serde(default, rename = "channelId", skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IncomingRelayFrame {
    Client(StampedClientRelayFrame),
    System(SystemRelayFrame),
}

pub fn parse_incoming(value: &str) -> serde_json::Result<IncomingRelayFrame> {
    if let Ok(system) = serde_json::from_str::<SystemRelayFrame>(value)
        && system.frame_type == "system"
    {
        return Ok(IncomingRelayFrame::System(system));
    }
    serde_json::from_str::<StampedClientRelayFrame>(value).map(IncomingRelayFrame::Client)
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
        to: "control".to_string(),
        event: Some(event.into()),
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        }
    }

    #[test]
    fn serializes_daemon_frame_to_canonical_shape() {
        let frame = daemon_client_frame("ch-1".to_string(), json!({ "text": "world" }));
        let value = serde_json::to_value(frame).unwrap();
        assert_eq!(
            value,
            json!({ "v": 1, "channelId": "ch-1", "payload": { "text": "world" } })
        );
    }
}
