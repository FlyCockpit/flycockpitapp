use super::*;
use serde::ser::SerializeMap;
use std::str::FromStr;

// ---- Events ----------------------------------------------------------------

const CLASS_TIMEOUT_TTFT: &str = "timeout_ttft";
const CLASS_TIMEOUT_IDLE: &str = "timeout_idle";
const CLASS_NETWORK: &str = "network";
const CLASS_HTTP_PREFIX: &str = "http_";
const CLASS_UTILITY_TIMEOUT: &str = "utility_timeout";
const CLASS_MISSING_TOOL_ENTITLEMENT: &str = "missing_tool_entitlement";
const CLASS_CLIENT_SIDE_TOOLS_UNSUPPORTED: &str = "client_side_tools_unsupported";
const CLASS_RESPONSES_TOOL_IDENTITY: &str = "responses_tool_identity";
const CLASS_PROVIDER_NOT_CONFIGURED: &str = "provider_not_configured";
const CLASS_PROVIDER_RATE_LIMIT: &str = "provider_rate_limit";
const CLASS_BILLING_OR_QUOTA_EXHAUSTED: &str = "billing_or_quota_exhausted";
const CLASS_UNRENDERABLE_WIRE_FIELD: &str = "unrenderable_wire_field";
const DEFAULT_MISSING_TOOL_FEATURE: &str = "client_side_tools";

/// Authoritative active-model state embedded in a completed selection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModelSelectionActiveState {
    pub selection: cockpit_config::config::providers::ActiveModelRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_selection: Option<cockpit_config::config::providers::ActiveModelRef>,
    pub diverged: bool,
    pub generation: u64,
}

/// Result of an optional request to save a selected session model as the
/// verified effective default for future sessions in the current configuration
/// context.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DefaultModelUpdateOutcome {
    NotRequested,
    /// Post-commit reload under the attach trust policy resolved exactly to
    /// `selection`. `unchanged` is true when no bytes were written because the
    /// effective default already matched.
    Verified {
        selection: cockpit_config::config::providers::ActiveModelRef,
        generation: u64,
        scope_label: String,
        #[serde(default)]
        unchanged: bool,
    },
}

/// Terminal result for `Request::SetDefaultModel` (config-only).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DefaultModelStandaloneOutcome {
    Applied {
        selection: Option<cockpit_config::config::providers::ActiveModelRef>,
        generation: u64,
        scope_label: String,
        #[serde(default)]
        unchanged: bool,
    },
    Rejected {
        user_message: String,
        diagnostic_code: String,
    },
}

/// Explicit terminal outcome for a client-correlated model selection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ModelSelectionOutcome {
    Applied {
        /// Boxed to keep the enum small: the applied payload carries two full
        /// model references plus the verified default, which would otherwise
        /// make every `Rejected` pay for the success case. `Box` is
        /// serde-transparent, so the wire shape is unchanged.
        active_state: Box<ModelSelectionActiveState>,
        default_update: DefaultModelUpdateOutcome,
    },
    Rejected {
        user_message: String,
        diagnostic_code: String,
    },
}

/// Durable terminal disposition for one or more accepted client submissions.
/// Once emitted, the correlated ids must never be replayed by a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserMessageTerminalDisposition {
    Removed,
    Cancelled,
    PreflightRejected,
}

impl From<cockpit_db::db::session_log::ClientSubmissionTerminalDisposition>
    for UserMessageTerminalDisposition
{
    fn from(disposition: cockpit_db::db::session_log::ClientSubmissionTerminalDisposition) -> Self {
        use cockpit_db::db::session_log::ClientSubmissionTerminalDisposition as Db;
        match disposition {
            Db::Removed => Self::Removed,
            Db::Cancelled => Self::Cancelled,
            Db::PreflightRejected => Self::PreflightRejected,
        }
    }
}

/// Durable per-assistant-message response performance snapshot carried on
/// the wire protocol. Persists durations (not wall-clock instants):
/// `ttft_ms` is time-to-first-token, `generation_ms` is the post-first-
/// visible-token duration, `displayed_tokens` is the shared-tokenizer count
/// of the displayed body, and `encoding` is the frozen tiktoken encoding
/// name. The snapshot is immutable: later tokenizer changes never recompute
/// history.
///
/// This is the wire form. The authority-free client layer validates it into
/// its canonical presentation snapshot; the engine classifier only produces
/// measurements. `encoding` is the stable shared-tokenizer encoding name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResponsePerformance {
    /// Time-to-first-token in milliseconds (dispatch → first non-whitespace
    /// presentation emission).
    pub ttft_ms: u64,
    /// Generation duration in milliseconds (first non-whitespace
    /// presentation emission → finish).
    pub generation_ms: u64,
    /// Token count of the final canonical displayed body as counted by the
    /// shared tokenizer.
    pub displayed_tokens: u64,
    /// The tiktoken encoding name used to count `displayed_tokens` (e.g.
    /// `"cl100k_base"`). Frozen at snapshot time.
    pub encoding: String,
}

/// Why a turn's inference failed.
///
/// The flat string produced by [`Self::as_str`] remains the stable display
/// text for every existing class. Serde carries data-bearing classes as
/// objects so the wire does not have to scrape values back out of prose.
///
/// Note `cancelled` is not a class: cancellation is recorded as a separate
/// dispatch status before an [`InferenceFailure`](Event::InferenceFailed)
/// exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferenceErrorClass {
    /// No first token within the configured TTFT ceiling.
    TimeoutTtft,
    /// Inter-token gap exceeded the configured idle ceiling.
    TimeoutIdle,
    /// Connection / transport failure with no HTTP status.
    Network,
    /// Non-retryable HTTP response, carrying the status code.
    Http(u16),
    /// A bounded utility-model request exceeded its call-site budget.
    UtilityTimeout,
    /// The provider requires an entitlement for client-side tools.
    MissingToolEntitlement { feature: String },
    /// Client-side tools cannot be used with this model.
    ClientSideToolsUnsupported,
    /// Responses tool-call identity normalization failed before dispatch.
    ResponsesToolIdentity,
    /// Provider credentials/configuration are absent.
    ProviderNotConfigured,
    /// Provider reported a rate or usage limit without a concrete HTTP class.
    ProviderRateLimit,
    /// Provider reported billing or account-quota exhaustion (an out-of-balance
    /// account or an exhausted resource package), as distinct from a transient
    /// throttle. Deliberately provider-neutral and data-free: it carries no
    /// provider body text, provider code, account identifier, balance, or
    /// limit. The observed HTTP status (often 429) is retained separately on
    /// core's diagnostic record, not on this semantic class.
    BillingOrQuotaExhausted,
    /// A message wire field had no renderer for an untrusted dispatch — a
    /// non-renderable media source (`Raw`/`FileId`/`Unknown`) on a route that
    /// must redact. The provider was never contacted; the dispatch fails
    /// closed at prep rather than passing an unscrubbable channel to the wire.
    UnrenderableWireField,
    /// A novel class preserved exactly at the string boundary.
    Other(String),
}

impl InferenceErrorClass {
    /// Stable string form used for display text and legacy flat values.
    pub fn as_str(&self) -> String {
        match self {
            Self::TimeoutTtft => CLASS_TIMEOUT_TTFT.to_string(),
            Self::TimeoutIdle => CLASS_TIMEOUT_IDLE.to_string(),
            Self::Network => CLASS_NETWORK.to_string(),
            Self::Http(status) => format!("{CLASS_HTTP_PREFIX}{status}"),
            Self::UtilityTimeout => CLASS_UTILITY_TIMEOUT.to_string(),
            Self::MissingToolEntitlement { .. } => CLASS_MISSING_TOOL_ENTITLEMENT.to_string(),
            Self::ClientSideToolsUnsupported => CLASS_CLIENT_SIDE_TOOLS_UNSUPPORTED.to_string(),
            Self::ResponsesToolIdentity => CLASS_RESPONSES_TOOL_IDENTITY.to_string(),
            Self::ProviderNotConfigured => CLASS_PROVIDER_NOT_CONFIGURED.to_string(),
            Self::ProviderRateLimit => CLASS_PROVIDER_RATE_LIMIT.to_string(),
            Self::BillingOrQuotaExhausted => CLASS_BILLING_OR_QUOTA_EXHAUSTED.to_string(),
            Self::UnrenderableWireField => CLASS_UNRENDERABLE_WIRE_FIELD.to_string(),
            Self::Other(value) => value.clone(),
        }
    }

    pub fn provider_status(&self) -> Option<u16> {
        match self {
            Self::Http(status) => Some(*status),
            _ => None,
        }
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::TimeoutTtft | Self::TimeoutIdle)
    }
}

impl fmt::Display for InferenceErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

impl FromStr for InferenceErrorClass {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let class = match value {
            CLASS_TIMEOUT_TTFT => Self::TimeoutTtft,
            CLASS_TIMEOUT_IDLE => Self::TimeoutIdle,
            CLASS_NETWORK => Self::Network,
            CLASS_UTILITY_TIMEOUT => Self::UtilityTimeout,
            CLASS_MISSING_TOOL_ENTITLEMENT => Self::MissingToolEntitlement {
                feature: DEFAULT_MISSING_TOOL_FEATURE.to_string(),
            },
            CLASS_CLIENT_SIDE_TOOLS_UNSUPPORTED => Self::ClientSideToolsUnsupported,
            CLASS_RESPONSES_TOOL_IDENTITY => Self::ResponsesToolIdentity,
            CLASS_PROVIDER_NOT_CONFIGURED => Self::ProviderNotConfigured,
            CLASS_PROVIDER_RATE_LIMIT => Self::ProviderRateLimit,
            CLASS_BILLING_OR_QUOTA_EXHAUSTED => Self::BillingOrQuotaExhausted,
            CLASS_UNRENDERABLE_WIRE_FIELD => Self::UnrenderableWireField,
            value => match value
                .strip_prefix(CLASS_HTTP_PREFIX)
                .and_then(|s| s.parse::<u16>().ok())
            {
                Some(status) if (100..=599).contains(&status) => Self::Http(status),
                _ => Self::Other(value.to_string()),
            },
        };
        Ok(class)
    }
}

impl Serialize for InferenceErrorClass {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Http(status) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("kind", "http")?;
                map.serialize_entry("status", status)?;
                map.end()
            }
            Self::MissingToolEntitlement { feature } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("kind", CLASS_MISSING_TOOL_ENTITLEMENT)?;
                map.serialize_entry("feature", feature)?;
                map.end()
            }
            _ => serializer.serialize_str(&self.as_str()),
        }
    }
}

impl<'de> Deserialize<'de> for InferenceErrorClass {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if let Some(class) = value.as_str() {
            return Ok(Self::from_str(class).expect("infallible class parse"));
        }
        let kind = value
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde::de::Error::missing_field("kind"))?;
        match kind {
            "http" => {
                #[derive(Deserialize)]
                struct Wire {
                    status: u16,
                }
                serde_json::from_value::<Wire>(value)
                    .map(|wire| Self::Http(wire.status))
                    .map_err(serde::de::Error::custom)
            }
            CLASS_MISSING_TOOL_ENTITLEMENT => {
                #[derive(Deserialize)]
                struct Wire {
                    feature: String,
                }
                serde_json::from_value::<Wire>(value)
                    .map(|wire| Self::MissingToolEntitlement {
                        feature: wire.feature,
                    })
                    .map_err(serde::de::Error::custom)
            }
            CLASS_TIMEOUT_TTFT => Ok(Self::TimeoutTtft),
            CLASS_TIMEOUT_IDLE => Ok(Self::TimeoutIdle),
            CLASS_NETWORK => Ok(Self::Network),
            CLASS_UTILITY_TIMEOUT => Ok(Self::UtilityTimeout),
            CLASS_CLIENT_SIDE_TOOLS_UNSUPPORTED => Ok(Self::ClientSideToolsUnsupported),
            CLASS_RESPONSES_TOOL_IDENTITY => Ok(Self::ResponsesToolIdentity),
            CLASS_PROVIDER_NOT_CONFIGURED => Ok(Self::ProviderNotConfigured),
            CLASS_PROVIDER_RATE_LIMIT => Ok(Self::ProviderRateLimit),
            CLASS_BILLING_OR_QUOTA_EXHAUSTED => Ok(Self::BillingOrQuotaExhausted),
            CLASS_UNRENDERABLE_WIRE_FIELD => Ok(Self::UnrenderableWireField),
            other => Ok(Self::Other(other.to_string())),
        }
    }
}

#[cfg(test)]
mod error_class_wire_tests {
    use super::*;

    #[test]
    fn error_class_wire_json_shape_is_pinned_for_every_variant() {
        let cases = [
            (InferenceErrorClass::TimeoutTtft, json!("timeout_ttft")),
            (InferenceErrorClass::TimeoutIdle, json!("timeout_idle")),
            (InferenceErrorClass::Network, json!("network")),
            (
                InferenceErrorClass::Http(502),
                json!({ "kind": "http", "status": 502 }),
            ),
            (
                InferenceErrorClass::UtilityTimeout,
                json!("utility_timeout"),
            ),
            (
                InferenceErrorClass::MissingToolEntitlement {
                    feature: "xai_multi_agent_tools_beta".to_string(),
                },
                json!({
                    "kind": "missing_tool_entitlement",
                    "feature": "xai_multi_agent_tools_beta"
                }),
            ),
            (
                InferenceErrorClass::ClientSideToolsUnsupported,
                json!("client_side_tools_unsupported"),
            ),
            (
                InferenceErrorClass::ResponsesToolIdentity,
                json!("responses_tool_identity"),
            ),
            (
                InferenceErrorClass::ProviderNotConfigured,
                json!("provider_not_configured"),
            ),
            (
                InferenceErrorClass::ProviderRateLimit,
                json!("provider_rate_limit"),
            ),
            (
                InferenceErrorClass::BillingOrQuotaExhausted,
                json!("billing_or_quota_exhausted"),
            ),
            (
                InferenceErrorClass::UnrenderableWireField,
                json!("unrenderable_wire_field"),
            ),
            (
                InferenceErrorClass::Other("future_error".to_string()),
                json!("future_error"),
            ),
        ];
        for (class, expected) in cases {
            assert_eq!(serde_json::to_value(&class).unwrap(), expected);
            assert_eq!(
                serde_json::from_value::<InferenceErrorClass>(expected).unwrap(),
                class
            );
        }
    }

    #[test]
    fn error_class_wire_unknown_value_deserializes_to_other() {
        let class: InferenceErrorClass = serde_json::from_value(json!("future_error")).unwrap();
        assert_eq!(
            class,
            InferenceErrorClass::Other("future_error".to_string())
        );
    }

    #[test]
    fn error_class_wire_missing_entitlement_feature_survives_the_wire() {
        let class = InferenceErrorClass::MissingToolEntitlement {
            feature: "xai_multi_agent_tools_beta".to_string(),
        };
        let json = serde_json::to_value(&class).unwrap();
        let parsed: InferenceErrorClass = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, class);
    }

    #[test]
    fn error_class_wire_inference_failed_event_round_trips() {
        let event = Event::InferenceFailed {
            session_id: Uuid::nil(),
            agent: "Build".to_string(),
            provider: "xai".to_string(),
            model: "grok".to_string(),
            error_class: InferenceErrorClass::MissingToolEntitlement {
                feature: "xai_multi_agent_tools_beta".to_string(),
            },
            detail: "missing entitlement".to_string(),
            auth_failure: None,
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(
            json["data"]["error_class"],
            json!({
                "kind": "missing_tool_entitlement",
                "feature": "xai_multi_agent_tools_beta"
            })
        );
        let parsed = serde_json::from_value::<Event>(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), json);
    }

    #[test]
    fn error_class_wire_backup_used_event_round_trips() {
        let event = Event::BackupUsed {
            session_id: Uuid::nil(),
            agent: "Build".to_string(),
            primary_model: "primary".to_string(),
            error_class: InferenceErrorClass::Http(500),
            backup_model: "backup".to_string(),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(
            json["data"]["error_class"],
            json!({ "kind": "http", "status": 500 })
        );
        let parsed = serde_json::from_value::<Event>(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), json);
    }

    #[test]
    fn error_class_wire_billing_or_quota_exhausted_round_trips() {
        let class = InferenceErrorClass::BillingOrQuotaExhausted;

        // Stable string surfaces: as_str, Display, and JSON are the exact wire
        // token, and the semantic class exposes no HTTP status (the observed
        // 429 lives on core's diagnostic record, not here).
        assert_eq!(class.as_str(), "billing_or_quota_exhausted");
        assert_eq!(class.to_string(), "billing_or_quota_exhausted");
        assert_eq!(class.provider_status(), None);

        // Serialize is the bare stable string, not an object.
        let json = serde_json::to_string(&class).unwrap();
        assert_eq!(json, "\"billing_or_quota_exhausted\"");

        // The stable string deserializes back to exactly the new variant
        // through the real serde path.
        let parsed: InferenceErrorClass = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, InferenceErrorClass::BillingOrQuotaExhausted);

        // FromStr resolves the token to the closed variant, not Other(_).
        assert_eq!(
            "billing_or_quota_exhausted"
                .parse::<InferenceErrorClass>()
                .unwrap(),
            InferenceErrorClass::BillingOrQuotaExhausted
        );

        // A bare 429 is NOT reclassified as billing/quota exhaustion at this
        // boundary: it deserializes to Http(429) and keeps its provider_status,
        // which the billing/quota class must never claim.
        let http_429: InferenceErrorClass =
            serde_json::from_value(json!({ "kind": "http", "status": 429 })).unwrap();
        assert_eq!(http_429, InferenceErrorClass::Http(429));
        assert_ne!(http_429, InferenceErrorClass::BillingOrQuotaExhausted);
        assert_eq!(http_429.provider_status(), Some(429));
    }

    #[test]
    fn error_class_wire_idle_reason_error_round_trips() {
        let reason = IdleReason::Error {
            class: InferenceErrorClass::ProviderRateLimit,
        };
        let json = serde_json::to_value(&reason).unwrap();
        assert_eq!(
            json,
            json!({ "kind": "error", "class": "provider_rate_limit" })
        );
        assert_eq!(serde_json::from_value::<IdleReason>(json).unwrap(), reason);
    }
}

/// Structured recovery classification for send-time credential and entitlement
/// failures. Rate limits, timeouts, and transport failures are intentionally
/// absent from this narrower taxonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFailureKind {
    CredentialsRejected { status: u16 },
    MissingEntitlement { feature: String },
    OAuthExpired { provider: String },
    ProviderNotConfigured,
    Other(String),
}

#[cfg(test)]
mod auth_failure_kind_forward_tests {
    use super::*;

    #[test]
    fn auth_failure_kind_forward_unknown_kind_deserializes_to_catch_all() {
        let kind: AuthFailureKind = serde_json::from_value(serde_json::json!({
            "kind": "future_auth_failure",
            "future": true
        }))
        .unwrap();
        assert_eq!(
            kind,
            AuthFailureKind::Other("future_auth_failure".to_string())
        );

        let serialized = serde_json::to_value(&kind).unwrap();
        assert_eq!(
            serialized,
            serde_json::json!({ "kind": "future_auth_failure" })
        );
        let parsed: AuthFailureKind = serde_json::from_value(serialized).unwrap();
        assert_eq!(parsed, kind);
    }

    #[test]
    fn auth_failure_kind_forward_inference_failed_parses_with_unknown_auth_failure() {
        let event: Event = serde_json::from_value(serde_json::json!({
            "event": "inference_failed",
            "data": {
                "session_id": "11111111-1111-4111-8111-111111111111",
                "agent": "Build",
                "provider": "future-provider",
                "model": "future-model",
                "error_class": "future_error",
                "detail": "details",
                "auth_failure": {
                    "kind": "future_auth_failure",
                    "future": true
                }
            }
        }))
        .unwrap();

        match event {
            Event::InferenceFailed { auth_failure, .. } => {
                assert_eq!(
                    auth_failure,
                    Some(AuthFailureKind::Other("future_auth_failure".to_string()))
                );
            }
            other => panic!("expected inference_failed event, got {other:?}"),
        }
    }

    #[test]
    fn auth_failure_kind_forward_malformed_known_kind_still_errors() {
        let error = serde_json::from_value::<AuthFailureKind>(serde_json::json!({
            "kind": "credentials_rejected",
            "status": "bad"
        }))
        .expect_err("malformed known auth failure must remain an error");
        assert!(
            error.to_string().contains("invalid type"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn auth_failure_kind_forward_known_kind_still_deserializes_with_fields() {
        let kind: AuthFailureKind = serde_json::from_value(serde_json::json!({
            "kind": "credentials_rejected",
            "status": 403
        }))
        .unwrap();
        assert_eq!(kind, AuthFailureKind::CredentialsRejected { status: 403 });
    }
}

impl Serialize for AuthFailureKind {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::CredentialsRejected { status } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("kind", "credentials_rejected")?;
                map.serialize_entry("status", status)?;
                map.end()
            }
            Self::MissingEntitlement { feature } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("kind", "missing_entitlement")?;
                map.serialize_entry("feature", feature)?;
                map.end()
            }
            Self::OAuthExpired { provider } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("kind", "oauth_expired")?;
                map.serialize_entry("provider", provider)?;
                map.end()
            }
            Self::ProviderNotConfigured => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("kind", "provider_not_configured")?;
                map.end()
            }
            Self::Other(kind) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("kind", kind)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for AuthFailureKind {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let kind = value
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde::de::Error::missing_field("kind"))?;
        match kind {
            "credentials_rejected" => {
                #[derive(Deserialize)]
                struct Wire {
                    status: u16,
                }
                serde_json::from_value::<Wire>(value)
                    .map(|wire| Self::CredentialsRejected {
                        status: wire.status,
                    })
                    .map_err(serde::de::Error::custom)
            }
            "missing_entitlement" => {
                #[derive(Deserialize)]
                struct Wire {
                    feature: String,
                }
                serde_json::from_value::<Wire>(value)
                    .map(|wire| Self::MissingEntitlement {
                        feature: wire.feature,
                    })
                    .map_err(serde::de::Error::custom)
            }
            "oauth_expired" => {
                #[derive(Deserialize)]
                struct Wire {
                    provider: String,
                }
                serde_json::from_value::<Wire>(value)
                    .map(|wire| Self::OAuthExpired {
                        provider: wire.provider,
                    })
                    .map_err(serde::de::Error::custom)
            }
            "provider_not_configured" => Ok(Self::ProviderNotConfigured),
            _ => Ok(Self::Other(kind.to_string())),
        }
    }
}

/// Unsolicited daemon → client notifications. The event stream is
/// fire-and-forget — clients do not ack individual events. A client
/// that misses events (e.g. dropped connection) re-`Attach`es and
/// receives a fresh history snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", content = "data")]
pub enum Event {
    EnvDriftWarning {
        baseline: EnvSnapshotMeta,
        candidate: EnvSnapshotMeta,
        diff: EnvDiffSummary,
        policy: EnvDriftPolicy,
    },

    /// Authoritative daemon-resolved config snapshot for one session. Carries
    /// the effective extended config plus a provider/model projection whose
    /// credential-bearing values have already been resolved daemon-side and
    /// redacted before crossing the wire.
    ConfigSnapshot {
        snapshot: Box<ConfigSnapshot>,
    },

    /// Authoritative pending user-message queue snapshot for one session.
    QueueUpdated {
        session_id: Uuid,
        queue: Vec<QueueItem>,
    },

    /// Current queue-edit foreground target for one session. Clients seed this
    /// from `Attached::foreground_target`; this event supplies live changes.
    ForegroundInputTarget {
        session_id: Uuid,
        target: QueueTarget,
    },

    /// Authoritative daemon-owned active model state for one session. The
    /// client renders this instead of assuming a requested switch succeeded.
    ActiveModelState {
        session_id: Uuid,
        selection: cockpit_config::config::providers::ActiveModelRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        default_selection: Option<cockpit_config::config::providers::ActiveModelRef>,
        diverged: bool,
        generation: u64,
    },

    /// Terminal outcome for one client-correlated active-model selection.
    ModelSelectionResult {
        session_id: Uuid,
        selection_id: Uuid,
        provider: String,
        model: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reasoning_effort: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        thinking_mode: Option<cockpit_config::config::providers::ThinkingMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt_cache_retention: Option<PromptCacheRetention>,
        outcome: ModelSelectionOutcome,
    },

    /// Terminal outcome for a local-owner-only config-only default update
    /// (`SetDefaultModel`). Never mutates the live session model.
    DefaultModelUpdateResult {
        session_id: Uuid,
        default_update_id: Uuid,
        outcome: DefaultModelStandaloneOutcome,
    },

    /// LOCAL image-generation control-plane `config_changed` replay event: a
    /// config mutation (endpoint/target create/update/delete/set_default)
    /// committed a new config generation. SECURITY: the carried
    /// [`ImageControlEventV1`](crate::image_control::ImageControlEventV1) holds
    /// only safe projections — never a raw credential, header, or workflow blob.
    ImageControlConfigChanged {
        event: crate::image_control::ImageControlEventV1,
    },

    /// Model inference started. TUI shows `Thinking…` until the first
    /// `AssistantTextDelta` arrives.
    ThinkingStarted {
        session_id: Uuid,
        agent: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        turn_id: Option<String>,
    },

    /// An inference call hit a network/transient failure and is being
    /// auto-retried. TUI shows a distinct, persistent `reconnecting —
    /// <provider>/<model> unreachable at <url> (attempt N)` status (daemon
    /// owns inference state — this is forwarded, not computed client-side);
    /// the headless `run` path logs a recurring attempt-numbered line.
    /// `attempt` is the 1-based retry number; `provider`/`model`/`url` name
    /// the unreachable target.
    Reconnecting {
        session_id: Uuid,
        agent: String,
        attempt: u32,
        provider: String,
        model: String,
        url: String,
    },

    /// A configured stream wait threshold elapsed. Without a backup model the
    /// daemon keeps waiting; with a backup model this warning precedes the
    /// timeout failure that engages fallback.
    InferenceWarning {
        session_id: Uuid,
        agent: String,
        provider: String,
        model: String,
        phase: String,
        waited_secs: u64,
    },

    /// One streaming chunk of assistant text.
    ///
    /// Legacy live path retained for fixtures/tests; production display uses
    /// [`Self::AssistantDisplayTextDelta`].
    AssistantTextDelta {
        session_id: Uuid,
        agent: String,
        delta: String,
    },

    /// One streaming chunk of model reasoning (thinking-mode models).
    /// TUI hides this by default but persists it so the user can
    /// expand the chain of thought later.
    ///
    /// Legacy live path; prefer [`Self::AssistantDisplayReasoningDelta`].
    ReasoningDelta {
        session_id: Uuid,
        agent: String,
        delta: String,
    },

    /// Classified visible assistant text delta (`attempt_id` is live-only).
    AssistantDisplayTextDelta {
        session_id: Uuid,
        agent: String,
        attempt_id: u64,
        delta: String,
    },

    /// Classified reasoning delta (`attempt_id` is live-only).
    AssistantDisplayReasoningDelta {
        session_id: Uuid,
        agent: String,
        attempt_id: u64,
        delta: String,
    },

    /// Display-only reset before a replacement attempt's first delta.
    AssistantDisplayAttemptReset {
        session_id: Uuid,
        agent: String,
        failed_attempt_id: u64,
        replacement_attempt_id: u64,
        reason: String,
    },

    /// Terminal live display complete for one attempt.
    AssistantDisplayComplete {
        session_id: Uuid,
        agent: String,
        attempt_id: u64,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presentation_text: Option<String>,
        #[serde(default)]
        reasoning: String,
        #[serde(default)]
        seq: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response_performance: Option<ResponsePerformance>,
    },

    /// Terminal live display error for a visible primary partial.
    AssistantDisplayError {
        session_id: Uuid,
        agent: String,
        attempt_id: u64,
        /// `"cancelled"` or `"failed"`.
        kind: String,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presentation_text: Option<String>,
    },

    /// Assistant turn complete — `text` is the full accumulated body with
    /// inline `<think>` blocks already stripped. `reasoning` is the
    /// finalized (channel + inline) reasoning the thinking chip renders;
    /// non-empty for a think-only turn with no body, so the chip survives
    /// across the wire. `seq` is the `session_events` row id of this message
    /// (the stable id a pin references — `pinned-messages`); `None` when the
    /// timeline write failed. UI/DB-only — never enters the model's context.
    /// Durable history transport — not live chip input.
    AssistantText {
        session_id: Uuid,
        agent: String,
        text: String,
        /// The exact final text shown to users when it differs from `text`
        /// (translation success). `None` for legacy/fallback/identical —
        /// consumers display `presentation_text.unwrap_or(text)`. Model
        /// context continues to use `text` only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presentation_text: Option<String>,
        #[serde(default)]
        reasoning: String,
        #[serde(default)]
        seq: Option<i64>,
        /// Optional durable response-performance snapshot. Absent for
        /// empty/think-only/no-visible-body/zero-duration responses and
        /// legacy rows.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response_performance: Option<ResponsePerformance>,
    },

    /// A user/injected message was recorded to the timeline. Carries the
    /// assigned `session_events` `seq` so the client can stamp it onto the
    /// already-pushed user history row (the stable id a pin references —
    /// `pinned-messages`). UI/DB-only — never enters the model's context.
    ///
    /// `preflight_cleaned` carries the request-preflight rewritten body
    /// (implementation note) when this turn was preflighted, so the
    /// client can show the cleaned text + `⚙ preflighted` chip and reveal the
    /// original typed input on click. `None` when preflight didn't run.
    UserMessageRecorded {
        session_id: Uuid,
        seq: i64,
        /// Client-generated ids folded into this durable user row. Ordinary
        /// local/system injections carry an empty list.
        client_submission_ids: Vec<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preflight_cleaned: Option<String>,
    },
    /// One or more daemon-queued user messages were drained and folded into a
    /// model request. Carries stable queue ids plus the persisted timeline seq
    /// when the session log write succeeded.
    QueuedUserMessagesFolded {
        session_id: Uuid,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_text: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tag_expansions: Vec<TagExpansionMeta>,
        queue_item_ids: Vec<Uuid>,
        target: QueueTarget,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seq: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preflight_cleaned: Option<String>,
    },
    /// Deferred session persistence failed before inference started, so the
    /// worker did not accept this exact message. Originating clients should
    /// retain the complete UUID/payload for a state-change retry.
    SessionPersistFailed {
        session_id: Uuid,
        /// Exact client submission rejected before it reached the driver.
        /// Clients must correlate by this id rather than transcript order
        /// because multiple optimistic submissions may be in flight.
        client_submission_id: Uuid,
        error: String,
    },

    /// The session driver's task ended unexpectedly while the worker was
    /// still serving. Terminal: clients should clear optimistic busy state
    /// and show the error because the worker will end this session.
    SessionDriverFailed {
        session_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        turn_id: Option<String>,
        error: String,
    },

    /// Request preflight is actually running for the just-submitted message
    /// (implementation note). Emitted at submit time, before the
    /// injection/preflight `tokio::join!`, only when preflight is enabled AND
    /// will run (not a `should_skip` no-op). The client marks the optimistic
    /// user row so its border slot shows the animated `Preflight…` indicator
    /// until the message resolves. UI-only — never enters the model's context.
    PreflightStarted {
        session_id: Uuid,
        client_submission_ids: Vec<Uuid>,
    },

    /// Accepted client submissions reached a durable terminal outcome without
    /// entering session history. Clients must retire the exact retained wire
    /// requests and remove only the correlated optimistic rows.
    UserMessagesTerminated {
        session_id: Uuid,
        client_submission_ids: Vec<Uuid>,
        disposition: UserMessageTerminalDisposition,
    },

    /// The just-submitted message was retracted before send because the
    /// prompt-injection guard blocked it (implementation note edge
    /// case). The client removes the optimistically-shown user row so the
    /// block/override UX stands alone. UI-only.
    UserMessageRetracted {
        session_id: Uuid,
        client_submission_ids: Vec<Uuid>,
    },

    /// A non-blocking system notice (warn chip) for the transcript.
    /// Used by the prompt-injection guard (GOALS §4i). UI-only: never
    /// enters the model's context.
    Notice {
        session_id: Uuid,
        text: String,
    },

    /// A daemon-global LSP warning/status notice. Used for language-server
    /// install failures that may be triggered from advisory write/edit
    /// diagnostics rather than a foreground settings request.
    LspNotice {
        text: String,
    },

    /// The receiver of this stream missed events and its view is incomplete.
    ///
    /// Re-attach with `since_seq = last_applied_seq` and apply the resulting
    /// [`Self::HistoryReplay`]. `session_id` is `None` when the loss happened
    /// on the daemon-global bus.
    EventStreamLagged {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<Uuid>,
        dropped: u64,
    },

    /// The utility-model skill auto-selector injected a skill onto this
    /// turn's wire message (`auto-injected-skill-transcript-
    /// visibility.md`). The client renders a distinct `/{name} · injected
    /// by agent` row ahead of the user's message. UI-only: never enters the
    /// model's context (the body is folded into the user message on the
    /// wire — wire-vs-user split, GOALS §14). One per injected skill.
    /// `reason` is the optional muted sub-line justification
    /// (implementation note); display-only and off-wire.
    SkillAutoInjected {
        session_id: Uuid,
        name: String,
        reason: Option<String>,
    },

    /// Tool dispatch started; args are post-repair.
    ToolStart {
        session_id: Uuid,
        agent: String,
        call_id: String,
        tool: String,
        args: Value,
    },

    /// UI-only progress tick for a running tool row.
    ToolProgress {
        session_id: Uuid,
        call_id: String,
        done: u64,
        total: u64,
        unit: String,
    },

    /// Tool finished cleanly. `output` is what the model sees on its
    /// next inference call.
    ToolEnd {
        session_id: Uuid,
        agent: String,
        call_id: String,
        tool: String,
        output: String,
        truncated: bool,
        /// `session_events.seq` for the corresponding persisted tool-call row.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seq: Option<i64>,
        /// Post-result hint text (`engine::bash_hints`, the user-side
        /// `data.hint.text`) when a rule fired on this `bash` call; `None`
        /// otherwise. UI-only (wire-vs-user split, GOALS §14). `#[serde(default)]`
        /// keeps the NDJSON wire backward-compatible with older peers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hint: Option<String>,
    },

    /// A resource-managed tool call is waiting for scheduler permits. UI-only:
    /// never enters model context.
    ResourceWait {
        session_id: Uuid,
        agent: String,
        request_id: Uuid,
        display_id: String,
        resources: HashMap<String, u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        queue_position: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command_label: Option<String>,
    },

    /// A resource-managed tool call acquired permits. UI-only.
    ResourceStart {
        session_id: Uuid,
        agent: String,
        request_id: Uuid,
        display_id: String,
        resources: HashMap<String, u32>,
        wait_ms: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command_label: Option<String>,
    },

    /// A resource-managed tool call released permits. UI-only.
    ResourceClear {
        session_id: Uuid,
        agent: String,
        request_id: Uuid,
        display_id: String,
        resources: HashMap<String, u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command_label: Option<String>,
    },

    /// Tool errored. The model sees this string as the tool result.
    /// `kind` distinguishes a bad call (the model's fault) from a bad
    /// outcome (the tool's fault) for the TUI's color treatment.
    ToolError {
        session_id: Uuid,
        agent: String,
        call_id: String,
        tool: String,
        error: String,
        kind: ToolFailKind,
        /// `session_events.seq` for the corresponding persisted tool-call row.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seq: Option<i64>,
    },

    /// An inference call failed terminally (TTFT / idle timeout, connection
    /// error, or non-retryable HTTP —
    /// implementation note). The TUI
    /// renders a RED inline error (same treatment as `ToolError`): the spinner
    /// stops and the user sees provider/model + the reason. UI-only: never
    /// enters the model's context (the recorded failure event is the data side).
    InferenceFailed {
        session_id: Uuid,
        agent: String,
        provider: String,
        model: String,
        error_class: InferenceErrorClass,
        detail: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_failure: Option<AuthFailureKind>,
    },

    /// A concrete provider/model inference completed successfully. TUI clients
    /// use this only to clear a prior process-local auth annotation.
    InferenceSucceeded {
        session_id: Uuid,
        provider: String,
        model: String,
    },

    /// The primary model failed a qualifying inference and the turn was
    /// answered by the configured backup model
    /// (implementation note). The TUI renders a
    /// DISPLAY-ONLY YELLOW banner. Wire-vs-user split (GOALS §14): never enters
    /// model context.
    BackupUsed {
        session_id: Uuid,
        agent: String,
        primary_model: String,
        error_class: InferenceErrorClass,
        backup_model: String,
    },

    /// `task` invoked an interactive subagent; primary handoff begins.
    SubagentSpawned {
        session_id: Uuid,
        parent: String,
        child: String,
        task_call_id: String,
        label: String,
        prompt: String,
        requested_cwd: Option<String>,
        resolved_cwd: Option<String>,
        #[serde(default)]
        model_trusted: bool,
        #[serde(default)]
        routing: serde_json::Value,
    },

    /// Later routing amend for a spawned subagent once the child model exists.
    SubagentRouting {
        session_id: Uuid,
        task_call_id: String,
        label: String,
        child: String,
        provider: String,
        model: String,
        #[serde(default)]
        model_trusted: bool,
        #[serde(default)]
        routing: serde_json::Value,
    },

    /// A subagent finished and emitted its report back to the parent.
    SubagentReport {
        session_id: Uuid,
        agent: String,
        task_call_id: String,
        label: String,
        report: String,
        #[serde(default)]
        failed: bool,
        #[serde(default)]
        model_trusted: bool,
        #[serde(default)]
        routing: serde_json::Value,
    },

    /// A noninteractive child event forwarded through the parent session
    /// stream with enough lineage for clients to build a delegation tree.
    NestedTurn {
        session_id: Uuid,
        task_call_id: String,
        label: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_task_call_id: Option<String>,
        inner: Box<Event>,
    },

    /// Provider-reported token usage for the round-trip that just
    /// finished. Emitted once per `model.complete` call; absent when
    /// the provider didn't include a usage chunk.
    Usage {
        session_id: Uuid,
        agent: String,
        input_tokens: u64,
        output_tokens: u64,
        cached_input_tokens: u64,
        /// Input tokens written into the prompt cache on a miss (Anthropic
        /// `cache_creation`). Carried so the TUI's cache hit-rate display
        /// (prompt `prompt-caching-strategy.md`) sees the full per-turn
        /// cache picture.
        #[serde(default)]
        cache_creation_input_tokens: u64,
    },

    /// A background builder paused with a question (GOALS §3b). Wire
    /// shape lands now; the dispatch logic that pauses turns ships
    /// in a later milestone.
    InterruptRaised {
        session_id: Uuid,
        interrupt_id: Uuid,
        agent: String,
        description: String,
        /// Legacy single-question payload (the `schedule` needs-attention
        /// nudge raises with neither field set). Kept for wire
        /// back-compat; new question-tool interrupts use `questions`.
        #[serde(default)]
        question: Option<InterruptQuestion>,
        /// Multi-question batch (GOALS §3b). Present when an agent's
        /// `question` tool raised the interrupt; drives the answering
        /// dialog. Mutually exclusive with `question` in practice.
        #[serde(default)]
        questions: Option<InterruptQuestionSet>,
        #[serde(default)]
        pending_count: usize,
        #[serde(default = "default_interrupt_raise_reason")]
        reason: super::InterruptRaiseReason,
    },

    InterruptQueueChanged {
        session_id: Uuid,
        active_interrupt_id: Option<Uuid>,
        pending_count: usize,
    },

    /// An outstanding interrupt was resolved — emitted to every client
    /// attached to the session (forward-compat for multi-client per
    /// GOALS §8e; v1 single-client receives it as a no-op echo).
    InterruptResolved {
        session_id: Uuid,
        interrupt_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decision: Option<super::InterruptDecision>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seq: Option<i64>,
    },

    /// Warm reattach replay of persisted timeline entries. `max_seq` is the
    /// highest session_events seq represented by this batch, including entries
    /// whose display shape does not carry its own seq field.
    HistoryReplay {
        session_id: Uuid,
        entries: Vec<super::HistoryEntry>,
        max_seq: i64,
    },

    /// The agent yielded control back to the human: the driver loop
    /// finished the current user message (and any folded queue) and is
    /// now awaiting input. Distinct from the mid-turn gaps where no
    /// model call is in flight (between tools, between inference
    /// rounds) — this fires only when the stack unwinds to the root and
    /// the queue is empty. The TUI keys its span-long "agent is
    /// working" indicator off the user-submit (rising) / this (falling)
    /// edges. Forward-compat: it means "no longer actively working," so
    /// a future agent that is *waiting* (agent-invoked timers/loops)
    /// emits it too.
    AgentIdle {
        session_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        turn_id: Option<String>,
        #[serde(default = "default_idle_reason")]
        reason: IdleReason,
    },

    /// A pending goal-completion verification round progressed. Clients show
    /// this while skeptic checks are still in flight; the normal goal-complete
    /// signal is emitted only after the goal reaches `complete`.
    GoalSupervisionProgress {
        session_id: Uuid,
        done: usize,
        total: usize,
    },

    /// The primary (root-frame) agent was swapped in place (`/plan` →
    /// `Plan`, `/build` → `Build`, `plan.md §4.6.d`). The client chrome's
    /// active-agent slot tracks `name`.
    PrimarySwapped {
        session_id: Uuid,
        name: String,
    },

    /// The active `llm_mode` was switched live (`/llm-mode`,
    /// implementation note). The client tracks `mode`
    /// so its `/llm-mode` toggle + cache-break warning resolve against the
    /// authoritative current value.
    LlmModeChanged {
        session_id: Uuid,
        mode: LlmMode,
    },

    /// The session ended (user requested, daemon shutting down,
    /// crash recovery couldn't restore it, …).
    SessionEnded {
        session_id: Uuid,
        reason: String,
    },

    /// An async job (loop / timer / background, GOALS §22) started.
    /// Drives the transient schedule strip. `kind` is `loop` / `timer` /
    /// `background`.
    ScheduleStarted {
        session_id: Uuid,
        job_id: String,
        label: String,
        kind: String,
    },
    /// A background job produced output (liveness tick for the strip).
    ScheduleProgress {
        session_id: Uuid,
        job_id: String,
    },
    /// A note from an ephemeral-fork loop iteration. Shown live in the
    /// transcript; the model sees it in main context only at loop end.
    ScheduleNote {
        session_id: Uuid,
        job_id: String,
        text: String,
    },
    /// An async job reached a terminal state (completed / failed /
    /// cancelled). Clears the strip entry + posts an inline marker; the
    /// model-facing result arrives separately as a late-arriving turn.
    ScheduleCompleted {
        session_id: Uuid,
        job_id: String,
        label: String,
        kind: String,
        failed: bool,
    },

    /// Live "% prunable" projection for the foreground agent (GOALS §1a).
    /// `prunable_tokens` is the wire-token drop `/prune` would achieve
    /// right now, computed by the same `dedup_plan` `/prune` executes.
    /// The TUI divides by the model's max context for the status line.
    ContextProjection {
        session_id: Uuid,
        prunable_tokens: u64,
        cache_cold: bool,
    },

    /// A `/prune` completed (manual or cache-aware auto). UI marker.
    /// `elided` is the **current** full set of `original_event_id`s whose
    /// tool-result body is now a wire-side elision marker; the TUI dims the
    /// matching scrollback tool-result bodies by `call_id`. Render-time
    /// view of live wire state, not a persisted transcript flag (§14).
    Pruned {
        session_id: Uuid,
        auto: bool,
        bodies: usize,
        tokens_saved: u64,
        #[serde(default)]
        elided: Vec<String>,
        /// Machine-readable auto-prune trigger reason. Present for automatic
        /// prunes and absent for manual `/prune`.
        #[serde(default)]
        trigger_reason: Option<String>,
        /// True when a warm prompt cache was broken by a ctx%-threshold
        /// auto-prune (implementation note); the client
        /// surfaces the shared cache-break warning.
        #[serde(default)]
        cache_break: bool,
    },

    /// A `/compact` handoff was assembled and applied in place.
    CompactReady {
        session_id: Uuid,
        new_session_id: Uuid,
        handoff: String,
        #[serde(default)]
        brief: String,
        #[serde(default)]
        source: String,
        #[serde(default)]
        trigger_ctx_pct: Option<f64>,
        #[serde(default)]
        tokens_before: u64,
        #[serde(default)]
        tokens_after: u64,
        #[serde(default)]
        turns_summarized: usize,
        #[serde(default)]
        tail_kept: usize,
        #[serde(default)]
        tail_trimmed: usize,
        seed_tool_count: usize,
        seed_tool_tokens: u64,
    },

    /// Sandboxing mode was set/toggled for the session (`/sandbox`). Broadcast
    /// to every attached client so they surface the resulting state.
    SandboxState {
        session_id: Uuid,
        mode: SandboxMode,
        enabled: bool,
        #[serde(default)]
        container_network_enabled: bool,
        container_availability: ContainerAvailability,
        /// Persisted `sandbox.defaultMode` after this call. Absent on older
        /// peers; `mode` remains the session's effective mode.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        persisted_intent: Option<SandboxMode>,
    },

    /// Sandbox-escalation availability changed for the session. Broadcast to
    /// every attached client and re-emitted on attach so reconnecting clients
    /// mirror the daemon-owned flag.
    SandboxEscalationState {
        session_id: Uuid,
        enabled: bool,
    },

    /// The shell sandbox cannot initialize for this session (`bash` hit the
    /// refuse path — Linux userns case; `implementation notes` §6.5). Broadcast
    /// **once per session** (the worker de-dupes) so attached clients raise a
    /// deterministic, persistent, user-facing indicator. `remedy` is the
    /// diagnosed reason; `fix_command` is the exact user-copyable host command
    /// when the diagnosis has one. The TUI renders it as a persistent
    /// below-input notice, cleared when a later `SandboxState { enabled: false }`
    /// arrives. Model-independent and never part of any inference request.
    SandboxUnavailable {
        session_id: Uuid,
        remedy: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fix_command: Option<String>,
    },

    /// Required command-line capabilities are unavailable for one or more
    /// tools granted to this session. Rendered as persistent startup chrome
    /// with a copyable install command when the remedy supplies one.
    CommandCapabilityUnavailable {
        session_id: Uuid,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fix_command: Option<String>,
    },

    /// Redaction sources were toggled for the session
    /// (`/toggle-redaction`). Broadcast to every attached client so they
    /// surface the resulting state (TUI: a toast). Session-only.
    RedactionState {
        session_id: Uuid,
        scan_environment: bool,
        scan_dotenv: bool,
        scan_ssh_keys: bool,
    },

    /// Request preflight was set/toggled for the session (`/preflight`,
    /// implementation note). Broadcast to every attached client so
    /// they surface the resulting state (TUI: a toast + the live `/preflight`
    /// description mirror). Session-only — reverts on restart.
    PreflightState {
        session_id: Uuid,
        enabled: bool,
    },

    /// Long prompt-cache retention intent changed for the session
    /// (`/longcache`). Session-only — reverts on restart.
    LongcacheState {
        session_id: Uuid,
        enabled: bool,
        supported: bool,
    },

    /// Command-approval mode changed for the session (`/quick`).
    ApprovalModeState {
        session_id: Uuid,
        mode: ApprovalMode,
    },

    /// Delegation recursion override changed for the session (`/quick`).
    DelegationRecursionState {
        session_id: Uuid,
        enabled: bool,
        default_depth: u32,
    },

    /// The session's model-comparison tandem (shadow) set changed
    /// (`/model-comparison`, implementation note).
    /// Broadcast to every attached client so they surface the resulting set
    /// (`models` = `provider/model` labels; empty = feature off) and, on a
    /// non-empty set, the one-line token-burn `warning` (warning only — no
    /// cap/meter). Session-only — reverts on restart.
    TandemState {
        session_id: Uuid,
        models: Vec<String>,
        #[serde(default)]
        warning: Option<String>,
    },

    /// The session's in-memory gitignore read-allowlist
    /// (implementation note) — the set of globs
    /// added via the approval flow's "Approve for this session" choice.
    /// Carries the **full current set** (replace, not delta) so the TUI's
    /// `@`-tag popup can union it with the persisted per-layer config and
    /// re-include session-approved gitignored entries. Broadcast on change
    /// (a new glob landed) and on attach (hydration), so a late/reconnecting
    /// client and any second concurrent client see prior approvals. Only the
    /// allow-set is ever broadcast — never the session reject-memory.
    /// Session-only — reverts on daemon restart. Never enters the model's
    /// context.
    GitignoreAllow {
        session_id: Uuid,
        allow: Vec<String>,
    },

    /// Caffeination (`/caffeinate`) turned on or off — including the
    /// daemon-decided `until-idle` auto-off. **Daemon-global**: carries no
    /// `session_id` and is broadcast to *every* connected client so the
    /// `☕` chrome glyph appears (and clears) on all of them in lockstep.
    /// `message` is `Some` for the originating client's toast; other
    /// clients use `active` to drive the glyph. `lid_close_guaranteed`
    /// lets a client word the lid-close caveat if it shows one.
    CaffeinateState {
        active: bool,
        lid_close_guaranteed: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },

    /// Remote relay connector state changed. **Daemon-global**: carries no
    /// session content and is broadcast to every connected client so status
    /// chrome can show connected/reconnecting/off without polling.
    #[cfg(feature = "remote")]
    ConnectorStatus {
        enabled: bool,
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_region: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_error: Option<String>,
    },

    TerminalOutput {
        terminal_id: Uuid,
        bytes: Vec<u8>,
    },

    TerminalClipboard {
        terminal_id: Uuid,
        text: String,
    },

    TerminalViewers {
        terminal_id: Uuid,
        count: usize,
    },

    TerminalClosed {
        terminal_id: Uuid,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
    },

    /// Content-free OSC 52 protocol violation for a hosted terminal generation.
    /// Emitted exactly once when the terminal-generation close oracle runs
    /// because a candidate exceeded `terminal::OSC52_MAX_SEQUENCE_BYTES`.
    /// Carries no payload, encoded text, or secret-bearing diagnostics.
    Osc52ProtocolViolation {
        terminal_id: Uuid,
        generation: u64,
    },

    /// The daemon began (or escalated) a graceful shutdown
    /// (`daemon-graceful-drain-shutdown.md`). **Daemon-global**: carries no
    /// `session_id` and is broadcast to *every* connected client so each
    /// TUI shows the drain notice and stops offering new input. `forced` is
    /// `false` when the drain just began (in-flight work is finishing) and
    /// `true` once the grace deadline was hit with work still outstanding,
    /// so a truncated turn isn't mistaken for a clean finish.
    DaemonDraining {
        forced: bool,
    },

    /// A session has durable paused work that needs a user's explicit resume
    /// or cancel decision.
    PausedWorkAvailable {
        session_id: Uuid,
        items: Vec<PausedWorkSummary>,
    },

    /// A write/edit implicit acquire in this session is blocked waiting on a
    /// lock held by another agent/session, or that wait just ended
    /// (implementation note). Per-session
    /// (`session_id`-scoped): the attached TUI shows a transient indicator
    /// — `` waiting for lock on `{path}` (held by `{holder_agent}`) `` —
    /// alongside the fixed chrome, like the `☕` caffeinate glyph, and
    /// clears it on `waiting == false` (lock acquired or wait cancelled).
    /// UI-only: never enters the model's context.
    WaitingForLock {
        session_id: Uuid,
        path: String,
        holder_agent: String,
        waiting: bool,
    },

    /// Daemon-owned host capability snapshot replaced after a successful
    /// refresh. **Daemon-global**: carries no `session_id`.
    HostCapabilitiesChanged {
        snapshot: crate::HostCapabilitySnapshot,
    },

    #[serde(other)]
    Unknown,
}
#[macro_export]
macro_rules! event_variants {
    ($with_variants:ident $(, $context:ident)*) => {
        $with_variants! { ($($context),*) [
            (Event::EnvDriftWarning { .. }, "env_drift_warning");
            (Event::ConfigSnapshot { .. }, "config_snapshot");
            (Event::QueueUpdated { .. }, "queue_updated");
            (Event::ForegroundInputTarget { .. }, "foreground_input_target");
            (Event::ActiveModelState { .. }, "active_model_state");
            (Event::ModelSelectionResult { .. }, "model_selection_result");
            (Event::DefaultModelUpdateResult { .. }, "default_model_update_result");
            (Event::ImageControlConfigChanged { .. }, "image_control_config_changed");
            (Event::ThinkingStarted { .. }, "thinking_started");
            (Event::Reconnecting { .. }, "reconnecting");
            (Event::InferenceWarning { .. }, "inference_warning");
            (Event::AssistantTextDelta { .. }, "assistant_text_delta");
            (Event::ReasoningDelta { .. }, "reasoning_delta");
            (Event::AssistantDisplayTextDelta { .. }, "assistant_display_text_delta");
            (Event::AssistantDisplayReasoningDelta { .. }, "assistant_display_reasoning_delta");
            (Event::AssistantDisplayAttemptReset { .. }, "assistant_display_attempt_reset");
            (Event::AssistantDisplayComplete { .. }, "assistant_display_complete");
            (Event::AssistantDisplayError { .. }, "assistant_display_error");
            (Event::AssistantText { .. }, "assistant_text");
            (Event::UserMessageRecorded { .. }, "user_message_recorded");
            (Event::QueuedUserMessagesFolded { .. }, "queued_user_messages_folded");
            (Event::SessionPersistFailed { .. }, "session_persist_failed");
            (Event::SessionDriverFailed { .. }, "session_driver_failed");
            (Event::PreflightStarted { .. }, "preflight_started");
            (Event::UserMessagesTerminated { .. }, "user_messages_terminated");
            (Event::UserMessageRetracted { .. }, "user_message_retracted");
            (Event::Notice { .. }, "notice");
            (Event::LspNotice { .. }, "lsp_notice");
            (Event::EventStreamLagged { .. }, "event_stream_lagged");
            (Event::SkillAutoInjected { .. }, "skill_auto_injected");
            (Event::ToolStart { .. }, "tool_start");
            (Event::ToolProgress { .. }, "tool_progress");
            (Event::ToolEnd { .. }, "tool_end");
            (Event::ResourceWait { .. }, "resource_wait");
            (Event::ResourceStart { .. }, "resource_start");
            (Event::ResourceClear { .. }, "resource_clear");
            (Event::ToolError { .. }, "tool_error");
            (Event::InferenceFailed { .. }, "inference_failed");
            (Event::InferenceSucceeded { .. }, "inference_succeeded");
            (Event::BackupUsed { .. }, "backup_used");
            (Event::SubagentSpawned { .. }, "subagent_spawned");
            (Event::SubagentRouting { .. }, "subagent_routing");
            (Event::SubagentReport { .. }, "subagent_report");
            (Event::NestedTurn { .. }, "nested_turn");
            (Event::Usage { .. }, "usage");
            (Event::InterruptRaised { .. }, "interrupt_raised");
            (Event::InterruptQueueChanged { .. }, "interrupt_queue_changed");
            (Event::InterruptResolved { .. }, "interrupt_resolved");
            (Event::HistoryReplay { .. }, "history_replay");
            (Event::AgentIdle { .. }, "agent_idle");
            (Event::GoalSupervisionProgress { .. }, "goal_supervision_progress");
            (Event::PrimarySwapped { .. }, "primary_swapped");
            (Event::LlmModeChanged { .. }, "llm_mode_changed");
            (Event::SessionEnded { .. }, "session_ended");
            (Event::ScheduleStarted { .. }, "schedule_started");
            (Event::ScheduleProgress { .. }, "schedule_progress");
            (Event::ScheduleNote { .. }, "schedule_note");
            (Event::ScheduleCompleted { .. }, "schedule_completed");
            (Event::ContextProjection { .. }, "context_projection");
            (Event::Pruned { .. }, "pruned");
            (Event::CompactReady { .. }, "compact_ready");
            (Event::SandboxState { .. }, "sandbox_state");
            (Event::SandboxEscalationState { .. }, "sandbox_escalation_state");
            (Event::SandboxUnavailable { .. }, "sandbox_unavailable");
            (Event::CommandCapabilityUnavailable { .. }, "command_capability_unavailable");
            (Event::RedactionState { .. }, "redaction_state");
            (Event::PreflightState { .. }, "preflight_state");
            (Event::LongcacheState { .. }, "longcache_state");
            (Event::ApprovalModeState { .. }, "approval_mode_state");
            (Event::DelegationRecursionState { .. }, "delegation_recursion_state");
            (Event::TandemState { .. }, "tandem_state");
            (Event::GitignoreAllow { .. }, "gitignore_allow");
            (Event::CaffeinateState { .. }, "caffeinate_state");
            #[cfg(feature = "remote")]
            (Event::ConnectorStatus { .. }, "connector_status");
            (Event::TerminalOutput { .. }, "terminal_output");
            (Event::TerminalClipboard { .. }, "terminal_clipboard");
            (Event::TerminalViewers { .. }, "terminal_viewers");
            (Event::TerminalClosed { .. }, "terminal_closed");
            (Event::Osc52ProtocolViolation { .. }, "osc52_protocol_violation");
            (Event::DaemonDraining { .. }, "daemon_draining");
            (Event::PausedWorkAvailable { .. }, "paused_work_available");
            (Event::WaitingForLock { .. }, "waiting_for_lock");
            (Event::HostCapabilitiesChanged { .. }, "host_capabilities_changed");
            (Event::Unknown, "__unknown");
        ] }
    };
}

impl Event {
    pub fn wire_tag(&self) -> &'static str {
        macro_rules! wire_tag {
            (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:expr);)+]) => {
                match self {
                    $($(#[$row_attr])* $pattern => $tag,)+
                }
            };
        }
        event_variants!(wire_tag)
    }
}

fn default_idle_reason() -> IdleReason {
    IdleReason::Completed
}

fn default_interrupt_raise_reason() -> super::InterruptRaiseReason {
    super::InterruptRaiseReason::Initial
}
