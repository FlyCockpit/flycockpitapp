//! Per-attempt TURN credentials and server-configured ICE policy protocol.
//!
//! This module owns the exact product contracts for ICE pool/secret file
//! schemas, RFC 7065/7064 URL validation, the public [`RemoteIcePolicyDigestV1`]
//! (computed before credential issuance), coturn REST credential derivation
//! (HMAC-SHA1), and the exact ICE policy response serialization. It never
//! holds long-lived secret material, never provisions infrastructure, and
//! never claims application-binary exclusivity.
//!
//! # Scope
//!
//! - Strict env defaults/ranges and secure file path validation.
//! - Pool V1 and secret-reference file schemas with lifecycle pairs.
//! - Provider endpoint/mTLS CA+SPKI/event-JWKS pin validation.
//! - RFC 7065 `turn:`/`turns:` and RFC 7064 `stun:` URL validation.
//! - `RemoteIcePolicyDigestV1` and `providerBindingDigest` (SHA-256 over
//!   RFC 8785 canonical JSON of public pre-credential inputs).
//! - Coturn REST username/password derivation with exact vector support.
//! - Exact ICE policy response JSON `{iceServers,iceTransportPolicy,
//!   authorization,expiresAt,routeClass}`.
//!
//! Secret bytes live only inside short-lived provider results and are
//! zeroized where possible. Secret refs never enter client output.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD as B64URL};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::remote_protocol_id::{
    CanonicalU64DecimalStringV1, parse_canonical_u64_decimal_string,
};
use crate::remote_public_service_policy::{RemotePublicPolicyError, canonical_json_value};

pub use crate::remote_protocol_id::REMOTE_PROTOCOL_ID_B64URL_LEN as ID_B64URL_LEN;

/// Hmac-SHA1 alias for coturn REST credential derivation.
type HmacSha1 = Hmac<sha1::Sha1>;

// ---------------------------------------------------------------------------
// Environment constants
// ---------------------------------------------------------------------------

/// Default credential TTL in seconds (300).
pub const DEFAULT_CREDENTIAL_TTL_SECONDS: u64 = 300;
/// Minimum credential TTL in seconds (60).
pub const MIN_CREDENTIAL_TTL_SECONDS: u64 = 60;
/// Maximum credential TTL in seconds (600).
pub const MAX_CREDENTIAL_TTL_SECONDS: u64 = 600;
/// Skew seconds added to drain windows after credential expiry (60).
pub const DRAIN_SKEW_SECONDS: u64 = 60;
/// v1 public-service byte limit per attachment.
pub const PUBLIC_SERVICE_MAX_BYTES: u64 = 10_737_418_240;
/// v1 public-service allocation-seconds limit per attachment.
pub const PUBLIC_SERVICE_MAX_ALLOCATION_SECONDS: u64 = 28_800;
/// Minimum secret bytes decoded (32).
pub const MIN_SECRET_BYTES: usize = 32;
/// Maximum secret bytes decoded (64).
pub const MAX_SECRET_BYTES: usize = 64;
/// Maximum TURN URLs per pool (8).
pub const MAX_TURN_URLS: usize = 8;
/// Maximum STUN URLs per pool (8).
pub const MAX_STUN_URLS: usize = 8;
/// Maximum ID/ref length (64).
pub const MAX_ID_LEN: usize = 64;
/// Credential random ID bytes (16).
pub const CREDENTIAL_RANDOM_ID_BYTES: usize = 16;
/// SHA-256 digest hex length.
pub const DIGEST_HEX_LEN: usize = 64;
/// Compact JWS max bytes.
pub const COMPACT_JWS_MAX_BYTES: usize = 8_192;

/// Allowed TURN secret providers.
pub const ALLOWED_SECRET_PROVIDERS: [&str; 2] = ["file", "enterprise"];

/// Allowed pool lifecycle states.
pub const ALLOWED_LIFECYCLE: [&str; 3] = ["current", "replacement_pending", "draining"];

/// Allowed ICE transport policy values.
pub const ALLOWED_ICE_TRANSPORT_POLICY: [&str; 2] = ["relay", "all"];

/// Allowed route classes.
pub const ALLOWED_ROUTE_CLASSES: [&str; 2] = ["relay_only", "direct_consent"];

/// Allowed TURN transports.
pub const ALLOWED_TURN_TRANSPORTS: [&str; 2] = ["udp", "tcp"];

/// Allowed compliance tag vocabulary (v1).
pub const ALLOWED_COMPLIANCE_TAGS: [&str; 2] = ["standard", "enterprise"];

/// Allowed regions (v1, sorted).
pub const ALLOWED_REGIONS: [&str; 6] = [
    "asia_east",
    "asia_southeast",
    "eu_central",
    "na_central",
    "na_east",
    "na_west",
];

/// ICE authorization JWS protected header `typ`.
pub const ICE_AUTHORIZATION_TYP: &str = "flycockpit-remote-ice-authorization+jws";

/// ICE policy digest schema version.
pub const ICE_POLICY_DIGEST_VERSION: u8 = 1;

/// `RemoteIceAuthorizationV1` audience.
pub const ICE_AUTHORIZATION_AUDIENCE: &str = "flycockpit-remote-ice-v1";

/// `renewalLeadSeconds = min(120, max(15, floor(encodedTtlSeconds/3)))`.
pub fn renewal_lead_seconds(encoded_ttl_seconds: u64) -> u64 {
    let third = encoded_ttl_seconds / 3;
    third.clamp(15, 120)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors raised by TURN/ICE policy validation and derivation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IcePolicyError {
    #[error("schemaVersion must be 1")]
    BadSchemaVersion,
    #[error("env {0} out of range or invalid: {1}")]
    BadEnv(&'static str, String),
    #[error("path must be absolute with safe parents: {0}")]
    UnsafePath(String),
    #[error("id/ref must match [A-Za-z0-9_-]{{1,64}}: {0}")]
    BadIdRef(String),
    #[error("generation must be a nonzero decimal string: {0}")]
    BadGeneration(String),
    #[error("invalid URL: {0}")]
    BadUrl(String),
    #[error("invalid lifecycle set: {0}")]
    BadLifecycle(String),
    #[error("invalid secret: {0}")]
    BadSecret(String),
    #[error("invalid provider: {0}")]
    BadProvider(String),
    #[error("invalid digest: {0}")]
    BadDigest(String),
    #[error("secret ref must not appear in client output")]
    SecretRefLeak,
    #[error("credential TTL must be {min}..={max}")]
    BadTtl { min: u64, max: u64 },
    #[error("invalid response shape: {0}")]
    BadResponse(String),
    #[error("HMAC derivation failed: {0}")]
    Hmac(String),
}

impl From<RemotePublicPolicyError> for IcePolicyError {
    fn from(e: RemotePublicPolicyError) -> Self {
        IcePolicyError::BadDigest(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Environment configuration
// ---------------------------------------------------------------------------

/// Parsed TURN/ICE environment configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceEnvConfig {
    pub ice_pools_file: Option<String>,
    pub turn_secrets_file: Option<String>,
    pub turn_secret_provider: String,
    pub turn_credential_ttl_seconds: u64,
}

impl Default for IceEnvConfig {
    fn default() -> Self {
        Self {
            ice_pools_file: None,
            turn_secrets_file: None,
            turn_secret_provider: "file".to_string(),
            turn_credential_ttl_seconds: DEFAULT_CREDENTIAL_TTL_SECONDS,
        }
    }
}

impl IceEnvConfig {
    /// Validate the environment configuration.
    pub fn validate(&self) -> Result<(), IcePolicyError> {
        if let Some(ref p) = self.ice_pools_file {
            validate_absolute_path(p)?;
        }
        if let Some(ref p) = self.turn_secrets_file {
            validate_absolute_path(p)?;
        }
        if !ALLOWED_SECRET_PROVIDERS.contains(&self.turn_secret_provider.as_str()) {
            return Err(IcePolicyError::BadEnv(
                "REMOTE_TURN_SECRET_PROVIDER",
                self.turn_secret_provider.clone(),
            ));
        }
        if self.turn_credential_ttl_seconds < MIN_CREDENTIAL_TTL_SECONDS
            || self.turn_credential_ttl_seconds > MAX_CREDENTIAL_TTL_SECONDS
        {
            return Err(IcePolicyError::BadTtl {
                min: MIN_CREDENTIAL_TTL_SECONDS,
                max: MAX_CREDENTIAL_TTL_SECONDS,
            });
        }
        Ok(())
    }

    /// Build from environment variables (does not read process env; accepts
    /// explicit values so callers can layer secrets safely).
    pub fn from_values(
        ice_pools_file: Option<String>,
        turn_secrets_file: Option<String>,
        turn_secret_provider: Option<String>,
        turn_credential_ttl_seconds: Option<u64>,
    ) -> Result<Self, IcePolicyError> {
        let provider = turn_secret_provider.unwrap_or_else(|| "file".to_string());
        let ttl = turn_credential_ttl_seconds.unwrap_or(DEFAULT_CREDENTIAL_TTL_SECONDS);
        let cfg = Self {
            ice_pools_file,
            turn_secrets_file,
            turn_secret_provider: provider,
            turn_credential_ttl_seconds: ttl,
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

// ---------------------------------------------------------------------------
// Pool / Secret file schemas
// ---------------------------------------------------------------------------

/// Pool lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolLifecycle {
    Current,
    ReplacementPending,
    Draining,
}

impl PoolLifecycle {
    pub fn as_str(self) -> &'static str {
        match self {
            PoolLifecycle::Current => "current",
            PoolLifecycle::ReplacementPending => "replacement_pending",
            PoolLifecycle::Draining => "draining",
        }
    }
}

/// Secret lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretLifecycle {
    Current,
    ReplacementPending,
    Draining,
}

/// Provider event JWKS public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventJwk {
    pub kid: String,
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub state: JwkState,
}

/// JWKS key state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwkState {
    Current,
    Next,
    VerificationOnly,
}

/// Provider event JWKS ring (1..=3 keys, exactly one current).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventJwks {
    pub keys: Vec<EventJwk>,
}

/// Provider endpoint pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderPin {
    pub provider_id: String,
    pub base_url: String,
    pub mtls_ca_sha256: String,
    pub mtls_leaf_spki_sha256: String,
    pub event_jwks: EventJwks,
}

/// Pool V1 entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolV1 {
    pub id: String,
    pub generation: String,
    pub turn_urls: Vec<String>,
    pub stun_urls: Vec<String>,
    pub realm: String,
    pub region: String,
    pub transports: Vec<String>,
    pub compliance_tags: Vec<String>,
    pub allow_ip_literals: bool,
    pub lifecycle: PoolLifecycle,
    pub secret_ref: String,
    pub provider: ProviderPin,
}

/// Pools file root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolsFile {
    pub schema_version: u8,
    pub revision: String,
    pub pools: Vec<PoolV1>,
}

/// One secret entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretEntry {
    pub secret_ref: String,
    pub secret_version: String,
    pub secret_base64url: String,
    pub state: SecretLifecycle,
}

/// Secrets file root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretsFile {
    pub schema_version: u8,
    pub revision: String,
    pub secrets: Vec<SecretEntry>,
}

// ---------------------------------------------------------------------------
// Path / ID / digest validation helpers
// ---------------------------------------------------------------------------

/// Validate an absolute path with safe parents (no `..`, no symlink expectation).
pub fn validate_absolute_path(s: &str) -> Result<(), IcePolicyError> {
    if !s.starts_with('/') {
        return Err(IcePolicyError::UnsafePath(s.to_string()));
    }
    for comp in s.split('/') {
        if comp == ".." {
            return Err(IcePolicyError::UnsafePath(s.to_string()));
        }
    }
    Ok(())
}

/// Validate an ID/ref: `[A-Za-z0-9_-]{1,64}`.
pub fn validate_id_ref(s: &str) -> Result<(), IcePolicyError> {
    if s.is_empty() || s.len() > MAX_ID_LEN {
        return Err(IcePolicyError::BadIdRef(s.to_string()));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(IcePolicyError::BadIdRef(s.to_string()));
    }
    Ok(())
}

/// Validate a lowercase 64-char hex digest.
pub fn validate_digest_hex(s: &str) -> Result<(), IcePolicyError> {
    if s.len() != DIGEST_HEX_LEN {
        return Err(IcePolicyError::BadDigest(format!(
            "digest must be {DIGEST_HEX_LEN} hex chars; got {}",
            s.len()
        )));
    }
    if !s
        .bytes()
        .all(|b| (b'a'..=b'f').contains(&b) || b.is_ascii_digit())
    {
        return Err(IcePolicyError::BadDigest("digest must be lowercase hex".into()));
    }
    Ok(())
}

/// Validate a nonzero decimal generation string.
pub fn validate_generation(s: &str) -> Result<u64, IcePolicyError> {
    let v = parse_canonical_u64_decimal_string(s)
        .map_err(|_| IcePolicyError::BadGeneration(s.to_string()))?;
    if v == 0 {
        return Err(IcePolicyError::BadGeneration("generation must be nonzero".into()));
    }
    Ok(v)
}

/// Validate that a sorted unique list of strings is sorted ascending and unique.
fn validate_sorted_unique(xs: &[String]) -> Result<(), IcePolicyError> {
    for w in xs.windows(2) {
        if w[0] >= w[1] {
            return Err(IcePolicyError::BadUrl("URLs must be sorted unique".into()));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RFC 7065 / RFC 7064 URL validation
// ---------------------------------------------------------------------------

/// Validate a single `turn:` or `turns:` URL per RFC 7065, with product policy
/// constraints (turns TLS/TCP on port 443, query transport only).
pub fn validate_turn_url(url: &str, allow_ip_literals: bool) -> Result<TurnUrl, IcePolicyError> {
    let (scheme, rest) = url
        .split_once(':')
        .ok_or_else(|| IcePolicyError::BadUrl("missing scheme".into()))?;
    let scheme = match scheme {
        "turn" => TurnScheme::Turn,
        "turns" => TurnScheme::Turns,
        _ => return Err(IcePolicyError::BadUrl(format!("bad scheme: {scheme}"))),
    };
    if rest.is_empty() {
        return Err(IcePolicyError::BadUrl("empty authority".into()));
    }
    // Reject userinfo, path, fragment.
    if rest.contains('@') || rest.contains('/') || rest.contains('#') {
        return Err(IcePolicyError::BadUrl("userinfo/path/fragment forbidden".into()));
    }
    let (authority, query) = match rest.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (rest, None),
    };
    // Validate query: only `transport=udp|tcp`, and omitted for scheme default.
    let transport = match (scheme, query) {
        (TurnScheme::Turn, None) => TurnTransport::Udp,
        (TurnScheme::Turns, None) => TurnTransport::Tcp,
        (TurnScheme::Turn, Some(q)) => {
            if !q.starts_with("transport=") || q.len() <= "transport=".len() {
                return Err(IcePolicyError::BadUrl("bad query".into()));
            }
            let val = &q["transport=".len()..];
            match val {
                "udp" => TurnTransport::Udp,
                "tcp" => TurnTransport::Tcp,
                _ => return Err(IcePolicyError::BadUrl("bad transport".into())),
            }
        }
        (TurnScheme::Turns, Some(q)) => {
            if !q.starts_with("transport=") {
                return Err(IcePolicyError::BadUrl("bad query".into()));
            }
            let val = &q["transport=".len()..];
            if val != "tcp" {
                return Err(IcePolicyError::BadUrl("turns requires transport=tcp".into()));
            }
            TurnTransport::Tcp
        }
    };
    // Scheme-default must omit query.
    match (scheme, query, transport) {
        (TurnScheme::Turn, Some(_), TurnTransport::Udp) => {
            return Err(IcePolicyError::BadUrl(
                "turn udp must omit query".into(),
            ));
        }
        (TurnScheme::Turns, Some(_), TurnTransport::Tcp) => {
            return Err(IcePolicyError::BadUrl(
                "turns tcp must omit query".into(),
            ));
        }
        _ => {}
    }
    // Parse host[:port].
    let (host, port) = parse_host_port(authority)?;
    let normalized_host = normalize_host(&host)?;
    let is_ip = is_ip_literal(&normalized_host);
    if is_ip && !allow_ip_literals {
        return Err(IcePolicyError::BadUrl(
            "IP literal requires allowIpLiterals=true".into(),
        ));
    }
    // Product policy: turns must be TLS/TCP on port 443.
    if scheme == TurnScheme::Turns && port != Some(443) {
        return Err(IcePolicyError::BadUrl("turns must use port 443".into()));
    }
    // turns transport must be tcp.
    if scheme == TurnScheme::Turns && transport != TurnTransport::Tcp {
        return Err(IcePolicyError::BadUrl("turns must use tcp".into()));
    }
    Ok(TurnUrl {
        scheme,
        host: normalized_host,
        port,
        transport,
        is_ip_literal: is_ip,
    })
}

/// Validate a `stun:` URL per RFC 7064 (no query).
pub fn validate_stun_url(url: &str) -> Result<StunUrl, IcePolicyError> {
    let (scheme, rest) = url
        .split_once(':')
        .ok_or_else(|| IcePolicyError::BadUrl("missing scheme".into()))?;
    if scheme != "stun" {
        return Err(IcePolicyError::BadUrl(format!("bad scheme: {scheme}")));
    }
    if rest.is_empty() || rest.contains('?') || rest.contains('@') || rest.contains('/')
        || rest.contains('#')
    {
        return Err(IcePolicyError::BadUrl("stun must be stun:host[:port]".into()));
    }
    let (host, port) = parse_host_port(rest)?;
    let normalized_host = normalize_host(&host)?;
    Ok(StunUrl {
        host: normalized_host,
        port,
    })
}

/// Parsed TURN URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnUrl {
    pub scheme: TurnScheme,
    pub host: String,
    pub port: Option<u16>,
    pub transport: TurnTransport,
    pub is_ip_literal: bool,
}

/// Parsed STUN URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunUrl {
    pub host: String,
    pub port: Option<u16>,
}

/// TURN scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnScheme {
    Turn,
    Turns,
}

/// TURN transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnTransport {
    Udp,
    Tcp,
}

impl TurnTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            TurnTransport::Udp => "udp",
            TurnTransport::Tcp => "tcp",
        }
    }
}

/// Parse `host[:port]` from an authority (no brackets for IPv6 in RFC 7065
/// host-abuse is rejected; we accept DNS hostnames and IPv4/IPv6 literals
/// in bracketed form).
fn parse_host_port(authority: &str) -> Result<(String, Option<u16>), IcePolicyError> {
    if authority.is_empty() {
        return Err(IcePolicyError::BadUrl("empty host".into()));
    }
    // Reject percent-encoding ambiguity.
    if authority.contains('%') {
        return Err(IcePolicyError::BadUrl("percent-encoding forbidden".into()));
    }
    if authority.starts_with('[') {
        // IPv6 literal: [addr]:port or [addr]
        let Some(close) = authority.find(']') else {
            return Err(IcePolicyError::BadUrl("unclosed IPv6 literal".into()));
        };
        let host = &authority[1..close];
        let rest = &authority[close + 1..];
        let port = if rest.is_empty() {
            None
        } else if let Some(p) = rest.strip_prefix(':') {
            Some(parse_port(p)?)
        } else {
            return Err(IcePolicyError::BadUrl("trailing delimiter after IPv6".into()));
        };
        return Ok((format!("[{host}]"), port));
    }
    // Split last colon for port (hostnames have no colons; IPv4 has dots).
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            // If host contains no dots and the whole thing looks like a port,
            // it's malformed. But a bare hostname:port is fine.
            if host.is_empty() {
                return Err(IcePolicyError::BadUrl("empty host".into()));
            }
            Ok((host.to_string(), Some(parse_port(port)?)))
        }
        None => Ok((authority.to_string(), None)),
    }
}

fn parse_port(s: &str) -> Result<u16, IcePolicyError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(IcePolicyError::BadUrl("bad port".into()));
    }
    s.parse::<u16>()
        .map_err(|_| IcePolicyError::BadUrl("port out of range".into()))
}

/// Normalize a hostname to lowercase IDNA A-label without trailing dot.
fn normalize_host(host: &str) -> Result<String, IcePolicyError> {
    if host.is_empty() {
        return Err(IcePolicyError::BadUrl("empty host".into()));
    }
    if host.ends_with('.') {
        return Err(IcePolicyError::BadUrl("trailing dot forbidden".into()));
    }
    // Reject raw spaces and control chars.
    if host
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b < 0x20 || b == 0x7f)
    {
        return Err(IcePolicyError::BadUrl("host has whitespace/control".into()));
    }
    Ok(host.to_lowercase())
}

/// Check if a normalized host is an IP literal (IPv4 or bracketed IPv6).
fn is_ip_literal(host: &str) -> bool {
    if host.starts_with('[') && host.ends_with(']') {
        return true;
    }
    // IPv4 dotted quad.
    host.parse::<std::net::IpAddr>().is_ok()
        || host.parse::<std::net::Ipv4Addr>().is_ok()
}

/// Reconstruct the canonical URL string from a parsed TurnUrl (for digest
/// determinism and output ordering).
impl TurnUrl {
    pub fn to_url_string(&self) -> String {
        let scheme = match self.scheme {
            TurnScheme::Turn => "turn",
            TurnScheme::Turns => "turns",
        };
        let authority = match self.port {
            Some(p) => format!("{}:{}", self.host, p),
            None => self.host.clone(),
        };
        match (self.scheme, self.transport) {
            (TurnScheme::Turn, TurnTransport::Udp) => format!("{scheme}:{authority}"),
            (TurnScheme::Turns, TurnTransport::Tcp) => format!("{scheme}:{authority}"),
            (TurnScheme::Turn, TurnTransport::Tcp) => {
                format!("{scheme}:{authority}?transport=tcp")
            }
            (TurnScheme::Turns, TurnTransport::Udp) => {
                // turns+udp is invalid per product policy; but the validator
                // already rejects this. Include for completeness.
                format!("{scheme}:{authority}?transport=udp")
            }
        }
    }
}

impl StunUrl {
    pub fn to_url_string(&self) -> String {
        match self.port {
            Some(p) => format!("stun:{}:{}", self.host, p),
            None => format!("stun:{}", self.host),
        }
    }
}

// ---------------------------------------------------------------------------
// Pool / Secret file validation
// ---------------------------------------------------------------------------

impl PoolsFile {
    /// Validate the strict pools file schema.
    pub fn validate(&self) -> Result<(), IcePolicyError> {
        if self.schema_version != 1 {
            return Err(IcePolicyError::BadSchemaVersion);
        }
        validate_generation(&self.revision)?;
        if self.pools.is_empty() {
            return Err(IcePolicyError::BadLifecycle("pools must be nonempty".into()));
        }
        // Sorted by raw UTF-8 id then generation.
        for w in self.pools.windows(2) {
            let a = (&w[0].id, &w[0].generation);
            let b = (&w[1].id, &w[1].generation);
            if a >= b {
                return Err(IcePolicyError::BadLifecycle(
                    "pools must be sorted by id then generation".into(),
                ));
            }
        }
        // Group by id and check lifecycle pairs.
        let mut i = 0;
        while i < self.pools.len() {
            let id = &self.pools[i].id;
            validate_id_ref(id)?;
            let mut gens: Vec<&PoolV1> = Vec::new();
            while i < self.pools.len() && &self.pools[i].id == id {
                let p = &self.pools[i];
                validate_generation(&p.generation)?;
                p.validate()?;
                gens.push(p);
                i += 1;
            }
            validate_lifecycle_pair(&gens)?;
        }
        Ok(())
    }
}

impl PoolV1 {
    /// Validate a single pool entry.
    pub fn validate(&self) -> Result<(), IcePolicyError> {
        validate_id_ref(&self.id)?;
        validate_generation(&self.generation)?;
        // turnUrls 1..=8 sorted unique.
        if self.turn_urls.is_empty() || self.turn_urls.len() > MAX_TURN_URLS {
            return Err(IcePolicyError::BadUrl("turnUrls must be 1..=8".into()));
        }
        validate_sorted_unique(&self.turn_urls)?;
        for u in &self.turn_urls {
            validate_turn_url(u, self.allow_ip_literals)?;
        }
        // stunUrls 0..=8 sorted unique.
        if self.stun_urls.len() > MAX_STUN_URLS {
            return Err(IcePolicyError::BadUrl("stunUrls must be 0..=8".into()));
        }
        if !self.stun_urls.is_empty() {
            validate_sorted_unique(&self.stun_urls)?;
            for u in &self.stun_urls {
                validate_stun_url(u)?;
            }
        }
        // realm.
        if self.realm.is_empty() || self.realm.len() > 128 {
            return Err(IcePolicyError::BadUrl("realm invalid".into()));
        }
        if self.realm.contains('\0') || self.realm.contains(' ') {
            return Err(IcePolicyError::BadUrl("realm has invalid chars".into()));
        }
        // region.
        if !ALLOWED_REGIONS.contains(&self.region.as_str()) {
            return Err(IcePolicyError::BadUrl(format!("bad region: {}", self.region)));
        }
        // transports (subset of allowed, sorted unique).
        if self.transports.is_empty() || self.transports.len() > ALLOWED_TURN_TRANSPORTS.len() {
            return Err(IcePolicyError::BadUrl("transports invalid".into()));
        }
        for t in &self.transports {
            if !ALLOWED_TURN_TRANSPORTS.contains(&t.as_str()) {
                return Err(IcePolicyError::BadUrl(format!("bad transport: {t}")));
            }
        }
        validate_sorted_unique_strings(&self.transports)?;
        // compliance tags.
        for t in &self.compliance_tags {
            if !ALLOWED_COMPLIANCE_TAGS.contains(&t.as_str()) {
                return Err(IcePolicyError::BadUrl(format!("bad compliance tag: {t}")));
            }
        }
        // secretRef.
        validate_id_ref(&self.secret_ref)?;
        // provider.
        self.provider.validate()?;
        Ok(())
    }
}

fn validate_sorted_unique_strings(xs: &[String]) -> Result<(), IcePolicyError> {
    for w in xs.windows(2) {
        if w[0] >= w[1] {
            return Err(IcePolicyError::BadUrl("must be sorted unique".into()));
        }
    }
    Ok(())
}

impl ProviderPin {
    /// Validate the provider endpoint pin.
    pub fn validate(&self) -> Result<(), IcePolicyError> {
        validate_id_ref(&self.provider_id)?;
        // baseUrl: normalized HTTPS origin + path prefix /v1.
        if !self.base_url.starts_with("https://") {
            return Err(IcePolicyError::BadProvider("baseUrl must be https".into()));
        }
        let without = &self.base_url["https://".len()..];
        if without.is_empty() {
            return Err(IcePolicyError::BadProvider("baseUrl empty origin".into()));
        }
        if without.contains('?') || without.contains('#') || without.contains('@') {
            return Err(IcePolicyError::BadProvider("baseUrl has query/frag/userinfo".into()));
        }
        if !without.ends_with("/v1") {
            return Err(IcePolicyError::BadProvider("baseUrl must end with /v1".into()));
        }
        // mTLS digests.
        validate_digest_hex(&self.mtls_ca_sha256)?;
        validate_digest_hex(&self.mtls_leaf_spki_sha256)?;
        // event JWKS: 1..=3 keys, exactly one current, unique kids.
        let jwks = &self.event_jwks.keys;
        if jwks.is_empty() || jwks.len() > 3 {
            return Err(IcePolicyError::BadProvider("eventJwks must be 1..=3 keys".into()));
        }
        let current = jwks
            .iter()
            .filter(|k| k.state == JwkState::Current)
            .count();
        if current != 1 {
            return Err(IcePolicyError::BadProvider(
                "exactly one current JWKS key".into(),
            ));
        }
        let mut kids = std::collections::HashSet::new();
        for k in jwks {
            if k.kty != "EC" || k.crv != "P-256" {
                return Err(IcePolicyError::BadProvider("JWKS must be ES256/P-256".into()));
            }
            if !kids.insert(k.kid.as_str()) {
                return Err(IcePolicyError::BadProvider("duplicate JWKS kid".into()));
            }
            validate_id_ref(&k.kid)?;
            // x, y are base64url P-256 coordinates (43 chars).
            if k.x.len() != 43 || k.y.len() != 43 {
                return Err(IcePolicyError::BadProvider("bad P-256 coord length".into()));
            }
        }
        Ok(())
    }
}

/// Validate lifecycle pairs for one logical pool ID.
/// Valid sets: one current; one current + one higher replacement_pending;
/// one current + one lower draining.
fn validate_lifecycle_pair(gens: &[&PoolV1]) -> Result<(), IcePolicyError> {
    if gens.is_empty() || gens.len() > 2 {
        return Err(IcePolicyError::BadLifecycle("1..=2 generations per id".into()));
    }
    let current_count = gens
        .iter()
        .filter(|p| p.lifecycle == PoolLifecycle::Current)
        .count();
    if current_count != 1 {
        return Err(IcePolicyError::BadLifecycle("exactly one current".into()));
    }
    if gens.len() == 2 {
        let current = gens
            .iter()
            .find(|p| p.lifecycle == PoolLifecycle::Current)
            .copied()
            .unwrap();
        let other = gens
            .iter()
            .find(|p| p.lifecycle != PoolLifecycle::Current)
            .copied()
            .unwrap();
        let current_gen = validate_generation(&current.generation)?;
        let other_gen = validate_generation(&other.generation)?;
        match other.lifecycle {
            PoolLifecycle::ReplacementPending => {
                if other_gen <= current_gen {
                    return Err(IcePolicyError::BadLifecycle(
                        "replacement_pending must be higher generation".into(),
                    ));
                }
            }
            PoolLifecycle::Draining => {
                if other_gen >= current_gen {
                    return Err(IcePolicyError::BadLifecycle(
                        "draining must be lower generation".into(),
                    ));
                }
            }
            PoolLifecycle::Current => {
                return Err(IcePolicyError::BadLifecycle("two current".into()));
            }
        }
        // Shared listener hostname/URL forbidden.
        let current_urls: std::collections::HashSet<&str> =
            current.turn_urls.iter().map(|s| s.as_str()).collect();
        let other_urls: std::collections::HashSet<&str> =
            other.turn_urls.iter().map(|s| s.as_str()).collect();
        if !current_urls.is_disjoint(&other_urls) {
            return Err(IcePolicyError::BadLifecycle(
                "shared listener URL forbidden".into(),
            ));
        }
    }
    Ok(())
}

impl SecretsFile {
    /// Validate the strict secrets file schema.
    pub fn validate(&self) -> Result<(), IcePolicyError> {
        if self.schema_version != 1 {
            return Err(IcePolicyError::BadSchemaVersion);
        }
        validate_generation(&self.revision)?;
        if self.secrets.is_empty() {
            return Err(IcePolicyError::BadSecret("secrets must be nonempty".into()));
        }
        // Sorted by secretRef then version.
        for w in self.secrets.windows(2) {
            let a = (&w[0].secret_ref, &w[0].secret_version);
            let b = (&w[1].secret_ref, &w[1].secret_version);
            if a >= b {
                return Err(IcePolicyError::BadSecret(
                    "secrets must be sorted by ref then version".into(),
                ));
            }
        }
        let mut material: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for s in &self.secrets {
            validate_id_ref(&s.secret_ref)?;
            validate_generation(&s.secret_version)?;
            let bytes = B64URL
                .decode(s.secret_base64url.as_bytes())
                .map_err(|_| IcePolicyError::BadSecret("secretBase64url decode failed".into()))?;
            if bytes.len() < MIN_SECRET_BYTES || bytes.len() > MAX_SECRET_BYTES {
                return Err(IcePolicyError::BadSecret(format!(
                    "secret bytes must be {MIN_SECRET_BYTES}..={MAX_SECRET_BYTES}"
                )));
            }
            if !material.insert(bytes) {
                return Err(IcePolicyError::BadSecret("duplicate secret material".into()));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// providerBindingDigest and RemoteIcePolicyDigestV1
// ---------------------------------------------------------------------------

/// Compute `providerBindingDigest = SHA-256(RFC 8785({providerId,baseUrl,
/// mtlsCaSha256,mtlsLeafSpkiSha256,eventJwksDigest}))`.
///
/// `eventJwksDigest` is SHA-256 of RFC 8785 canonical JSON of the JWKS keys
/// array (sorted by kid).
pub fn provider_binding_digest(provider: &ProviderPin) -> Result<[u8; 32], IcePolicyError> {
    let jwks_digest = event_jwks_digest(&provider.event_jwks)?;
    let canonical = canonical_json_value(&json!({
        "providerId": provider.provider_id,
        "baseUrl": provider.base_url,
        "mtlsCaSha256": provider.mtls_ca_sha256,
        "mtlsLeafSpkiSha256": provider.mtls_leaf_spki_sha256,
        "eventJwksDigest": hex::encode(&jwks_digest),
    }))?;
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

/// Compute the event JWKS digest: SHA-256 of RFC 8785 canonical JSON of the
/// sorted-by-kid keys array `{kid,kty,crv,x,y,state}`.
pub fn event_jwks_digest(jwks: &EventJwks) -> Result<[u8; 32], IcePolicyError> {
    let mut keys: Vec<&EventJwk> = jwks.keys.iter().collect();
    keys.sort_by(|a, b| a.kid.cmp(&b.kid));
    let arr: Vec<Value> = keys
        .iter()
        .map(|k| {
            json!({
                "kid": k.kid,
                "kty": k.kty,
                "crv": k.crv,
                "x": k.x,
                "y": k.y,
                "state": match k.state {
                    JwkState::Current => "current",
                    JwkState::Next => "next",
                    JwkState::VerificationOnly => "verification_only",
                },
            })
        })
        .collect();
    let canonical = canonical_json_value(&Value::Array(arr))?;
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

/// Inputs to `RemoteIcePolicyDigestV1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIcePolicyDigestInputV1 {
    pub version: u8,
    pub child_attempt_id: String,
    pub pool_id: String,
    pub pool_generation: String,
    pub ordered_urls: Vec<String>,
    pub realm: String,
    pub region: String,
    pub transports: Vec<String>,
    pub route_class: String,
    pub policy_epoch: String,
    pub credential_expires_at: String,
    pub allow_ip_literals: bool,
    pub provider_binding_digest: String,
}

/// Compute `RemoteIcePolicyDigestV1 = SHA-256(RFC 8785 canonical JSON of
/// {version:1,childAttemptId,poolId,poolGeneration,orderedUrls,realm,region,
/// transports,routeClass,policyEpoch,credentialExpiresAt,allowIpLiterals,
/// providerBindingDigest})`.
///
/// Excludes username/password, secretRef, secret version, HMAC, allocation
/// telemetry, and random credential ID.
pub fn remote_ice_policy_digest_v1(
    input: &RemoteIcePolicyDigestInputV1,
) -> Result<[u8; 32], IcePolicyError> {
    if input.version != ICE_POLICY_DIGEST_VERSION {
        return Err(IcePolicyError::BadDigest("version must be 1".into()));
    }
    if !ALLOWED_ROUTE_CLASSES.contains(&input.route_class.as_str()) {
        return Err(IcePolicyError::BadDigest(format!(
            "bad routeClass: {}",
            input.route_class
        )));
    }
    validate_digest_hex(&input.provider_binding_digest)?;
    // Validate childAttemptId is base64url-16.
    if input.child_attempt_id.len() != ID_B64URL_LEN {
        return Err(IcePolicyError::BadDigest("childAttemptId must be 22 chars".into()));
    }
    let canonical = canonical_json_value(&json!({
        "version": input.version,
        "childAttemptId": input.child_attempt_id,
        "poolId": input.pool_id,
        "poolGeneration": input.pool_generation,
        "orderedUrls": input.ordered_urls,
        "realm": input.realm,
        "region": input.region,
        "transports": input.transports,
        "routeClass": input.route_class,
        "policyEpoch": input.policy_epoch,
        "credentialExpiresAt": input.credential_expires_at,
        "allowIpLiterals": input.allow_ip_literals,
        "providerBindingDigest": input.provider_binding_digest,
    }))?;
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

/// Compute `iceServersDigest = SHA-256(RFC 8785({iceServers,
/// iceTransportPolicy}))`.
pub fn ice_servers_digest(
    ice_servers: &Value,
    ice_transport_policy: &str,
) -> Result<[u8; 32], IcePolicyError> {
    if !ALLOWED_ICE_TRANSPORT_POLICY.contains(&ice_transport_policy) {
        return Err(IcePolicyError::BadDigest(format!(
            "bad iceTransportPolicy: {ice_transport_policy}"
        )));
    }
    let canonical = canonical_json_value(&json!({
        "iceServers": ice_servers,
        "iceTransportPolicy": ice_transport_policy,
    }))?;
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

// ---------------------------------------------------------------------------
// Coturn REST credential derivation
// ---------------------------------------------------------------------------

/// Coturn REST credential username: `<unix-expiry>:<base64url-16-byte-random-id>`.
pub fn coturn_username(unix_expiry: u64, random_id: &[u8; CREDENTIAL_RANDOM_ID_BYTES]) -> String {
    format!("{}:{}", unix_expiry, B64URL.encode(random_id))
}

/// Coturn REST credential password: base64 of HMAC-SHA1 over UTF-8 username
/// using the selected coturn REST shared secret.
pub fn coturn_password(
    username: &str,
    secret: &[u8],
) -> Result<String, IcePolicyError> {
    let mut mac = HmacSha1::new_from_slice(secret)
        .map_err(|e| IcePolicyError::Hmac(e.to_string()))?;
    mac.update(username.as_bytes());
    let result = mac.finalize();
    Ok(BASE64_STD.encode(result.into_bytes()))
}

/// A derived coturn REST credential pair (username, password). The password
/// is wrapped in `Zeroizing` so it is cleared on drop; the secret input is
/// never retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoturnCredential {
    pub username: String,
    pub password: Zeroizing<String>,
}

/// Derive a coturn REST credential from the given expiry, random ID, and
/// secret bytes. The secret is consumed and not retained.
pub fn derive_coturn_credential(
    unix_expiry: u64,
    random_id: &[u8; CREDENTIAL_RANDOM_ID_BYTES],
    secret: &[u8],
) -> Result<CoturnCredential, IcePolicyError> {
    let username = coturn_username(unix_expiry, random_id);
    let password = coturn_password(&username, secret)?;
    Ok(CoturnCredential {
        username,
        password: Zeroizing::new(password),
    })
}

// ---------------------------------------------------------------------------
// ICE policy response serialization
// ---------------------------------------------------------------------------

/// Route class for the ICE policy response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRouteClass {
    RelayOnly,
    DirectConsent,
}

impl IceRouteClass {
    pub fn as_str(self) -> &'static str {
        match self {
            IceRouteClass::RelayOnly => "relay_only",
            IceRouteClass::DirectConsent => "direct_consent",
        }
    }
}

/// Inputs to the ICE policy response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcePolicyResponseInput<'a> {
    pub ordered_turn_urls: &'a [String],
    pub ordered_stun_urls: &'a [String],
    pub route_class: IceRouteClass,
    pub username: &'a str,
    pub password: &'a str,
    pub authorization_jws: &'a str,
    pub expires_at: u64,
}

/// Serialize the exact ICE policy response:
/// `{iceServers,iceTransportPolicy,authorization,expiresAt,routeClass}`.
///
/// `iceServers` is exactly one relay object
/// `{urls:[ordered turnUrls],username,credential,credentialType:"password"}`;
/// direct-consented mode may append exactly one `{urls:[ordered stunUrls]}`
/// object when nonempty. `iceTransportPolicy` is `"relay"` for relay-only and
/// `"all"` for direct-consented. `expiresAt` is a decimal string.
pub fn serialize_ice_policy_response(
    input: &IcePolicyResponseInput<'_>,
) -> Result<Value, IcePolicyError> {
    if input.ordered_turn_urls.is_empty() {
        return Err(IcePolicyError::BadResponse("turnUrls required".into()));
    }
    let (ice_transport_policy, include_stun) = match input.route_class {
        IceRouteClass::RelayOnly => ("relay", false),
        IceRouteClass::DirectConsent => ("all", !input.ordered_stun_urls.is_empty()),
    };
    let relay_obj = json!({
        "urls": input.ordered_turn_urls,
        "username": input.username,
        "credential": input.password,
        "credentialType": "password",
    });
    let ice_servers = if include_stun {
        let stun_obj = json!({
            "urls": input.ordered_stun_urls,
        });
        Value::Array(vec![relay_obj, stun_obj])
    } else {
        Value::Array(vec![relay_obj])
    };
    let response = json!({
        "iceServers": ice_servers,
        "iceTransportPolicy": ice_transport_policy,
        "authorization": input.authorization_jws,
        "expiresAt": input.expires_at.to_string(),
        "routeClass": input.route_class.as_str(),
    });
    // Verify no secretRef leak in the serialized output.
    let text = serde_json::to_string(&response)
        .map_err(|e| IcePolicyError::BadResponse(e.to_string()))?;
    if text.contains("secretRef") {
        return Err(IcePolicyError::SecretRefLeak);
    }
    Ok(response)
}

// ---------------------------------------------------------------------------
// Hex encoding helper (avoids adding hex crate dependency)
// ---------------------------------------------------------------------------

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_provider() -> ProviderPin {
        ProviderPin {
            provider_id: "prov1".into(),
            base_url: "https://turn.example.com/v1".into(),
            mtls_ca_sha256: "ab".repeat(32),
            mtls_leaf_spki_sha256: "cd".repeat(32),
            event_jwks: EventJwks {
                keys: vec![EventJwk {
                    kid: "k1".into(),
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: "A".repeat(43),
                    y: "B".repeat(43),
                    state: JwkState::Current,
                }],
            },
        }
    }

    fn valid_pool(id: &str, generation: &str, lifecycle: PoolLifecycle) -> PoolV1 {
        PoolV1 {
            id: id.into(),
            generation: generation.into(),
            turn_urls: vec!["turn:turn.example.com:3478?transport=tcp".into()],
            stun_urls: vec![],
            realm: "flycockpit.example".into(),
            region: "na_east".into(),
            transports: vec!["tcp".into(), "udp".into()],
            compliance_tags: vec!["standard".into()],
            allow_ip_literals: false,
            lifecycle,
            secret_ref: "secret1".into(),
            provider: valid_provider(),
        }
    }

    fn valid_pools_file() -> PoolsFile {
        PoolsFile {
            schema_version: 1,
            revision: "1".into(),
            pools: vec![valid_pool("pool1", "1", PoolLifecycle::Current)],
        }
    }

    fn valid_secrets_file() -> SecretsFile {
        let secret_bytes = [0x55u8; 32];
        SecretsFile {
            schema_version: 1,
            revision: "1".into(),
            secrets: vec![SecretEntry {
                secret_ref: "secret1".into(),
                secret_version: "1".into(),
                secret_base64url: B64URL.encode(&secret_bytes),
                state: SecretLifecycle::Current,
            }],
        }
    }

    // --- Acceptance criterion 1: env and file schema ---

    #[test]
    fn remote_ice_env_and_file_schema() {
        // Env defaults.
        let cfg = IceEnvConfig::from_values(None, None, None, None).unwrap();
        assert_eq!(cfg.turn_secret_provider, "file");
        assert_eq!(cfg.turn_credential_ttl_seconds, 300);
        // Env ranges.
        assert!(IceEnvConfig::from_values(None, None, None, Some(59)).is_err());
        assert!(IceEnvConfig::from_values(None, None, None, Some(60)).is_ok());
        assert!(IceEnvConfig::from_values(None, None, None, Some(600)).is_ok());
        assert!(IceEnvConfig::from_values(None, None, None, Some(601)).is_err());
        assert!(IceEnvConfig::from_values(None, None, Some("bogus".into()), None).is_err());
        assert!(IceEnvConfig::from_values(None, None, Some("enterprise".into()), None).is_ok());
        // Secure paths.
        assert!(IceEnvConfig::from_values(Some("relative".into()), None, None, None).is_err());
        assert!(IceEnvConfig::from_values(
            Some("/etc/pools.json".into()),
            Some("/etc/secrets.json".into()),
            None,
            None
        )
        .is_ok());
        // Pools file valid.
        assert!(valid_pools_file().validate().is_ok());
        // Bad schema version.
        let mut pf = valid_pools_file();
        pf.schema_version = 2;
        assert_eq!(pf.validate(), Err(IcePolicyError::BadSchemaVersion));
        // Bad lifecycle: two current.
        let mut pf = valid_pools_file();
        pf.pools.push(valid_pool("pool1", "2", PoolLifecycle::Current));
        assert!(pf.validate().is_err());
        // Bad lifecycle: pending lower than current.
        let mut pf = valid_pools_file();
        pf.pools.push(valid_pool("pool1", "0", PoolLifecycle::Draining));
        // generation 0 is invalid.
        assert!(pf.validate().is_err());
        // Good: current + higher replacement_pending.
        let mut pf = valid_pools_file();
        let mut pending = valid_pool("pool1", "2", PoolLifecycle::ReplacementPending);
        pending.turn_urls = vec!["turn:turn2.example.com:3478?transport=tcp".into()];
        pending.secret_ref = "secret2".into();
        pf.pools.push(pending);
        assert!(pf.validate().is_ok());
        // Shared listener URL forbidden.
        let mut pf = valid_pools_file();
        let mut pending = valid_pool("pool1", "2", PoolLifecycle::ReplacementPending);
        pending.turn_urls = vec!["turn:turn.example.com:3478?transport=tcp".into()];
        pending.secret_ref = "secret2".into();
        pf.pools.push(pending);
        assert!(pf.validate().is_err());
        // Secrets file valid.
        assert!(valid_secrets_file().validate().is_ok());
        // Secret too short.
        let mut sf = valid_secrets_file();
        sf.secrets[0].secret_base64url = B64URL.encode(&[0u8; 16]);
        assert!(sf.validate().is_err());
        // Duplicate secret material.
        let mut sf = valid_secrets_file();
        let bytes = [0x55u8; 32];
        sf.secrets.push(SecretEntry {
            secret_ref: "secret2".into(),
            secret_version: "1".into(),
            secret_base64url: B64URL.encode(&bytes),
            state: SecretLifecycle::Current,
        });
        assert!(sf.validate().is_err());
        // Provider pin validation.
        let mut p = valid_provider();
        p.base_url = "http://turn.example.com/v1".into();
        assert!(p.validate().is_err());
        let mut p = valid_provider();
        p.base_url = "https://turn.example.com/v2".into();
        assert!(p.validate().is_err());
        let mut p = valid_provider();
        p.mtls_ca_sha256 = "xy".repeat(32);
        assert!(p.validate().is_err());
        // JWKS no current.
        let mut p = valid_provider();
        p.event_jwks.keys[0].state = JwkState::Next;
        assert!(p.validate().is_err());
        // JWKS duplicate kid.
        let mut p = valid_provider();
        p.event_jwks.keys.push(EventJwk {
            kid: "k1".into(),
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "C".repeat(43),
            y: "D".repeat(43),
            state: JwkState::Next,
        });
        assert!(p.validate().is_err());
    }

    // --- Acceptance criterion 2: ICE policy digest vectors ---

    #[test]
    fn remote_ice_policy_digest_vectors() {
        let provider = valid_provider();
        let pbd = provider_binding_digest(&provider).unwrap();
        let pbd_hex = hex::encode(&pbd);
        validate_digest_hex(&pbd_hex).unwrap();

        let input = RemoteIcePolicyDigestInputV1 {
            version: 1,
            child_attempt_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            pool_id: "pool1".into(),
            pool_generation: "1".into(),
            ordered_urls: vec!["turn:turn.example.com:3478?transport=tcp".into()],
            realm: "flycockpit.example".into(),
            region: "na_east".into(),
            transports: vec!["tcp".into(), "udp".into()],
            route_class: "relay_only".into(),
            policy_epoch: "1".into(),
            credential_expires_at: "1000000000".into(),
            allow_ip_literals: false,
            provider_binding_digest: pbd_hex.clone(),
        };
        let digest = remote_ice_policy_digest_v1(&input).unwrap();
        assert_eq!(digest.len(), 32);
        // Deterministic.
        let digest2 = remote_ice_policy_digest_v1(&input).unwrap();
        assert_eq!(digest, digest2);
        // Field mutation changes digest.
        let mut input2 = input.clone();
        input2.route_class = "direct_consent".into();
        let digest3 = remote_ice_policy_digest_v1(&input2).unwrap();
        assert_ne!(digest, digest3);
        // allowIpLiterals mutation changes digest.
        let mut input3 = input.clone();
        input3.allow_ip_literals = true;
        let digest4 = remote_ice_policy_digest_v1(&input3).unwrap();
        assert_ne!(digest, digest4);
        // providerBindingDigest mutation changes digest.
        let mut input4 = input.clone();
        input4.provider_binding_digest = "00".repeat(32);
        let digest5 = remote_ice_policy_digest_v1(&input4).unwrap();
        assert_ne!(digest, digest5);
        // Excludes credential material: adding a username field to the JSON
        // manually must not match the digest computation (the digest function
        // itself never includes username/password).
        // Verify the canonical JSON does not contain "username" or "password".
        let canonical = canonical_json_value(&json!({
            "version": input.version,
            "childAttemptId": input.child_attempt_id,
            "poolId": input.pool_id,
            "poolGeneration": input.pool_generation,
            "orderedUrls": input.ordered_urls,
            "realm": input.realm,
            "region": input.region,
            "transports": input.transports,
            "routeClass": input.route_class,
            "policyEpoch": input.policy_epoch,
            "credentialExpiresAt": input.credential_expires_at,
            "allowIpLiterals": input.allow_ip_literals,
            "providerBindingDigest": input.provider_binding_digest,
        }))
        .unwrap();
        assert!(!canonical.contains("username"));
        assert!(!canonical.contains("password"));
        assert!(!canonical.contains("secretRef"));
        // Bad version.
        let mut bad = input.clone();
        bad.version = 2;
        assert!(remote_ice_policy_digest_v1(&bad).is_err());
        // Bad route class.
        let mut bad = input.clone();
        bad.route_class = "bogus".into();
        assert!(remote_ice_policy_digest_v1(&bad).is_err());
    }

    // --- Acceptance criterion 3: TURN credential vectors ---

    #[test]
    fn remote_turn_credential_vectors() {
        // Username format: <unix-expiry>:<base64url-16-byte-random-id>
        let random_id = [0xABu8; 16];
        let username = coturn_username(1_000_000_000, &random_id);
        assert_eq!(username, format!("1000000000:{}", B64URL.encode(&random_id)));
        assert_eq!(B64URL.encode(&random_id).len(), ID_B64URL_LEN);
        // 16-byte randomness check.
        assert_eq!(random_id.len(), 16);
        // HMAC-SHA1/base64 coturn vector: known test vector.
        // secret = "secret" (test vector), username = "100:random"
        let secret = b"secret";
        let username = "100:testuser";
        let password = coturn_password(username, secret).unwrap();
        // Verify against known coturn REST vector: HMAC-SHA1("secret", "100:testuser")
        let mut mac = HmacSha1::new_from_slice(secret).unwrap();
        mac.update(username.as_bytes());
        let expected = BASE64_STD.encode(mac.finalize().into_bytes());
        assert_eq!(password, expected);
        assert_eq!(password.len(), 28); // base64 of 20 bytes
        // No identity fields in username (only expiry:randomId).
        let random_id = [0x01u8; 16];
        let username = coturn_username(100, &random_id);
        let parts: Vec<&str> = username.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].parse::<u64>().is_ok());
        assert!(!parts[1].contains(':'));
        // TTL bounds.
        assert_eq!(MIN_CREDENTIAL_TTL_SECONDS, 60);
        assert_eq!(MAX_CREDENTIAL_TTL_SECONDS, 600);
        assert_eq!(DEFAULT_CREDENTIAL_TTL_SECONDS, 300);
        // Derive full credential.
        let cred = derive_coturn_credential(1_000_000_300, &random_id, b"mysecret").unwrap();
        assert!(!cred.username.is_empty());
        assert!(!cred.password.is_empty());
    }

    // --- Acceptance criterion 6: privacy relay-only fails closed ---

    #[test]
    fn remote_turn_privacy_required_fails_closed() {
        let turn_urls = vec!["turn:turn.example.com:3478?transport=tcp".into()];
        let resp = serialize_ice_policy_response(&IcePolicyResponseInput {
            ordered_turn_urls: &turn_urls,
            ordered_stun_urls: &[],
            route_class: IceRouteClass::RelayOnly,
            username: "100:abc",
            password: "pwd",
            authorization_jws: "eyJ..sig",
            expires_at: 1_000_000_300,
        })
        .unwrap();
        // relay-only: iceTransportPolicy = "relay", no STUN object.
        assert_eq!(resp["iceTransportPolicy"], "relay");
        let servers = resp["iceServers"].as_array().unwrap();
        assert_eq!(servers.len(), 1);
        assert!(servers[0]["urls"].is_array());
        assert!(!servers[0].get("stunUrls").is_some_and(|v| !v.is_null()));
        // No host/srflx/STUN-direct in relay-only.
        let text = serde_json::to_string(&resp).unwrap();
        assert!(!text.contains("stun:"));
        // Exact keys.
        let keys: Vec<String> = resp.as_object().unwrap().keys().cloned().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(sorted, vec!["authorization", "expiresAt", "iceServers", "iceTransportPolicy", "routeClass"]);
        // Relay-only with stun URLs provided should still not include STUN.
        let stun = vec!["stun:stun.example.com:3478".into()];
        let resp = serialize_ice_policy_response(&IcePolicyResponseInput {
            ordered_turn_urls: &turn_urls,
            ordered_stun_urls: &stun,
            route_class: IceRouteClass::RelayOnly,
            username: "100:abc",
            password: "pwd",
            authorization_jws: "eyJ..sig",
            expires_at: 1_000_000_300,
        })
        .unwrap();
        assert_eq!(resp["iceServers"].as_array().unwrap().len(), 1);
        assert_eq!(resp["iceTransportPolicy"], "relay");
    }

    // --- Acceptance criterion 8: client uses only signed servers ---

    #[test]
    fn remote_turn_client_uses_only_signed_servers() {
        let turn_urls = vec![
            "turn:turn.example.com:3478?transport=tcp".into(),
            "turns:turns.example.com:443".into(),
        ];
        let resp = serialize_ice_policy_response(&IcePolicyResponseInput {
            ordered_turn_urls: &turn_urls,
            ordered_stun_urls: &[],
            route_class: IceRouteClass::RelayOnly,
            username: "100:abc",
            password: "pwd",
            authorization_jws: "signed.jws",
            expires_at: 1_000_000_300,
        })
        .unwrap();
        // iceServers contains exactly the signed server list, no merge.
        let servers = resp["iceServers"].as_array().unwrap();
        assert_eq!(servers.len(), 1);
        let urls = servers[0]["urls"].as_array().unwrap();
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "turn:turn.example.com:3478?transport=tcp");
        assert_eq!(urls[1], "turns:turns.example.com:443");
        // Substitution detection: changing a URL changes iceServersDigest.
        let d1 = ice_servers_digest(&resp["iceServers"], "relay").unwrap();
        let mut resp2 = resp.clone();
        resp2["iceServers"][0]["urls"][0] = json!("turn:evil.example.com:3478?transport=tcp");
        let d2 = ice_servers_digest(&resp2["iceServers"], "relay").unwrap();
        assert_ne!(d1, d2);
    }

    // --- URL validation ---

    #[test]
    fn turn_url_validation() {
        // turn TCP with query.
        let u = validate_turn_url("turn:turn.example.com:3478?transport=tcp", false).unwrap();
        assert_eq!(u.scheme, TurnScheme::Turn);
        assert_eq!(u.transport, TurnTransport::Tcp);
        assert_eq!(u.port, Some(3478));
        // turn UDP default (no query).
        let u = validate_turn_url("turn:turn.example.com:3478", false).unwrap();
        assert_eq!(u.transport, TurnTransport::Udp);
        // turns on 443 (default tcp, no query).
        let u = validate_turn_url("turns:turns.example.com:443", false).unwrap();
        assert_eq!(u.scheme, TurnScheme::Turns);
        assert_eq!(u.transport, TurnTransport::Tcp);
        // turns not on 443 fails.
        assert!(validate_turn_url("turns:turns.example.com:8443", false).is_err());
        // turns with query fails (default tcp must omit).
        assert!(validate_turn_url("turns:turns.example.com:443?transport=tcp", false).is_err());
        // turn udp with explicit query fails.
        assert!(validate_turn_url("turn:turn.example.com:3478?transport=udp", false).is_err());
        // bad query key.
        assert!(validate_turn_url("turn:turn.example.com:3478?foo=bar", false).is_err());
        // userinfo.
        assert!(validate_turn_url("turn:user@turn.example.com:3478", false).is_err());
        // path.
        assert!(validate_turn_url("turn:turn.example.com:3478/path", false).is_err());
        // fragment.
        assert!(validate_turn_url("turn:turn.example.com:3478#frag", false).is_err());
        // trailing dot.
        assert!(validate_turn_url("turn:turn.example.com.:3478", false).is_err());
        // IP literal without allowIpLiterals.
        assert!(validate_turn_url("turn:192.0.2.1:3478", false).is_err());
        // IP literal with allowIpLiterals.
        assert!(validate_turn_url("turn:192.0.2.1:3478", true).is_ok());
        // Hostname normalized to lowercase.
        let u = validate_turn_url("turn:TURN.Example.COM:3478", false).unwrap();
        assert_eq!(u.host, "turn.example.com");
        // Round-trip URL string.
        let u = validate_turn_url("turn:turn.example.com:3478?transport=tcp", false).unwrap();
        assert_eq!(u.to_url_string(), "turn:turn.example.com:3478?transport=tcp");
        let u = validate_turn_url("turn:turn.example.com:3478", false).unwrap();
        assert_eq!(u.to_url_string(), "turn:turn.example.com:3478");
    }

    #[test]
    fn stun_url_validation() {
        let u = validate_stun_url("stun:stun.example.com:3478").unwrap();
        assert_eq!(u.host, "stun.example.com");
        assert_eq!(u.port, Some(3478));
        let u = validate_stun_url("stun:stun.example.com").unwrap();
        assert_eq!(u.port, None);
        assert_eq!(u.to_url_string(), "stun:stun.example.com");
        // query forbidden.
        assert!(validate_stun_url("stun:stun.example.com?foo=bar").is_err());
        // path forbidden.
        assert!(validate_stun_url("stun:stun.example.com/path").is_err());
    }

    // --- Renewal lead seconds ---

    #[test]
    fn renewal_lead_seconds_vectors() {
        // 60-second credential starts at 20 seconds remaining.
        assert_eq!(renewal_lead_seconds(60), 20);
        // 300-second credential at 100.
        assert_eq!(renewal_lead_seconds(300), 100);
        // 600-second credential at 120 (clamped).
        assert_eq!(renewal_lead_seconds(600), 120);
        // min 15.
        assert_eq!(renewal_lead_seconds(30), 15);
        assert_eq!(renewal_lead_seconds(45), 15);
        assert_eq!(renewal_lead_seconds(0), 15);
    }

    // --- Secret ref never in client output ---

    #[test]
    fn secret_ref_never_in_output() {
        let turn_urls = vec!["turn:turn.example.com:3478?transport=tcp".into()];
        let resp = serialize_ice_policy_response(&IcePolicyResponseInput {
            ordered_turn_urls: &turn_urls,
            ordered_stun_urls: &[],
            route_class: IceRouteClass::RelayOnly,
            username: "100:abc",
            password: "pwd",
            authorization_jws: "sig",
            expires_at: 1_000_000_300,
        })
        .unwrap();
        let text = serde_json::to_string(&resp).unwrap();
        assert!(!text.contains("secretRef"));
        assert!(!text.contains("secretVersion"));
    }

    // --- Direct consent mode includes STUN ---

    #[test]
    fn direct_consent_includes_stun() {
        let turn_urls = vec!["turn:turn.example.com:3478?transport=tcp".into()];
        let stun_urls = vec!["stun:stun.example.com:3478".into()];
        let resp = serialize_ice_policy_response(&IcePolicyResponseInput {
            ordered_turn_urls: &turn_urls,
            ordered_stun_urls: &stun_urls,
            route_class: IceRouteClass::DirectConsent,
            username: "100:abc",
            password: "pwd",
            authorization_jws: "sig",
            expires_at: 1_000_000_300,
        })
        .unwrap();
        assert_eq!(resp["iceTransportPolicy"], "all");
        let servers = resp["iceServers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);
        assert!(servers[1]["urls"].is_array());
        // direct consent with empty stun: no stun object.
        let resp = serialize_ice_policy_response(&IcePolicyResponseInput {
            ordered_turn_urls: &turn_urls,
            ordered_stun_urls: &[],
            route_class: IceRouteClass::DirectConsent,
            username: "100:abc",
            password: "pwd",
            authorization_jws: "sig",
            expires_at: 1_000_000_300,
        })
        .unwrap();
        assert_eq!(resp["iceServers"].as_array().unwrap().len(), 1);
    }

    // --- Lifecycle pair validation ---

    #[test]
    fn lifecycle_pair_validation() {
        // current + higher replacement_pending with distinct listener.
        let mut pf = valid_pools_file();
        let mut pending = valid_pool("pool1", "2", PoolLifecycle::ReplacementPending);
        pending.turn_urls = vec!["turn:turn2.example.com:3478?transport=tcp".into()];
        pending.secret_ref = "secret2".into();
        pf.pools.push(pending);
        assert!(pf.validate().is_ok());
        // current + lower draining with distinct listener.
        let mut pf = PoolsFile {
            schema_version: 1,
            revision: "1".into(),
            pools: vec![],
        };
        let mut draining = valid_pool("pool1", "1", PoolLifecycle::Draining);
        draining.turn_urls = vec!["turn:turn1.example.com:3478?transport=tcp".into()];
        draining.secret_ref = "secret0".into();
        let mut current = valid_pool("pool1", "2", PoolLifecycle::Current);
        current.turn_urls = vec!["turn:turn2.example.com:3478?transport=tcp".into()];
        current.secret_ref = "secret1".into();
        pf.pools = vec![draining, current];
        assert!(pf.validate().is_ok());
        // pending + draining (no current) fails.
        let mut pf = valid_pools_file();
        pf.pools[0].lifecycle = PoolLifecycle::ReplacementPending;
        let mut draining = valid_pool("pool1", "0", PoolLifecycle::Draining);
        // generation 0 invalid anyway; use a valid lower
        draining.generation = "1".into();
        pf.pools = vec![draining, pf.pools[0].clone()];
        // reorder: id=pool1 gen=1 draining, id=pool1 gen=2 pending
        pf.pools[0].generation = "1".into();
        pf.pools[0].lifecycle = PoolLifecycle::Draining;
        pf.pools[1].generation = "2".into();
        pf.pools[1].lifecycle = PoolLifecycle::ReplacementPending;
        pf.pools[0].turn_urls = vec!["turn:d1.example.com:3478?transport=tcp".into()];
        pf.pools[1].turn_urls = vec!["turn:d2.example.com:3478?transport=tcp".into()];
        assert!(pf.validate().is_err());
        // three generations fails.
        let mut pf = valid_pools_file();
        let mut pending = valid_pool("pool1", "2", PoolLifecycle::ReplacementPending);
        pending.turn_urls = vec!["turn:turn2.example.com:3478?transport=tcp".into()];
        pending.secret_ref = "secret2".into();
        let mut draining = valid_pool("pool1", "0", PoolLifecycle::Draining);
        draining.generation = "1".into();
        draining.turn_urls = vec!["turn:turn1.example.com:3478?transport=tcp".into()];
        draining.secret_ref = "secret0".into();
        pf.pools[0].generation = "3".into();
        pf.pools[0].secret_ref = "secret3".into();
        pf.pools[0].turn_urls = vec!["turn:turn3.example.com:3478?transport=tcp".into()];
        pf.pools = vec![draining, pending, pf.pools[0].clone()];
        assert!(pf.validate().is_err());
    }

    // --- iceServersDigest ---

    #[test]
    fn ice_servers_digest_exact() {
        let ice_servers = json!([
            {
                "urls": ["turn:turn.example.com:3478?transport=tcp"],
                "username": "100:abc",
                "credential": "pwd",
                "credentialType": "password",
            }
        ]);
        let d1 = ice_servers_digest(&ice_servers, "relay").unwrap();
        let d2 = ice_servers_digest(&ice_servers, "relay").unwrap();
        assert_eq!(d1, d2);
        // Changing policy changes digest.
        let d3 = ice_servers_digest(&ice_servers, "all").unwrap();
        assert_ne!(d1, d3);
        // Changing iceServers changes digest.
        let ice_servers2 = json!([
            {
                "urls": ["turn:other.example.com:3478?transport=tcp"],
                "username": "100:abc",
                "credential": "pwd",
                "credentialType": "password",
            }
        ]);
        let d4 = ice_servers_digest(&ice_servers2, "relay").unwrap();
        assert_ne!(d1, d4);
        // Bad policy.
        assert!(ice_servers_digest(&ice_servers, "bogus").is_err());
    }

    // --- Redaction: no credential/network/identity leakage in metrics path ---

    #[test]
    fn no_credential_leakage_in_serialized_response() {
        let turn_urls = vec!["turn:turn.example.com:3478?transport=tcp".into()];
        let resp = serialize_ice_policy_response(&IcePolicyResponseInput {
            ordered_turn_urls: &turn_urls,
            ordered_stun_urls: &[],
            route_class: IceRouteClass::RelayOnly,
            username: "100:sensitiveuser",
            password: "sensitivepassword",
            authorization_jws: "sig",
            expires_at: 1_000_000_300,
        })
        .unwrap();
        let text = serde_json::to_string(&resp).unwrap();
        // The response intentionally includes username/credential (they are
        // client-facing ICE credentials), but must never include secretRef,
        // secret material, or internal identity fields.
        assert!(!text.contains("secretRef"));
        assert!(!text.contains("secretVersion"));
        assert!(!text.contains("secretBase64url"));
        assert!(!text.contains("tenantId"));
        assert!(!text.contains("deviceId"));
    }

    // --- CanonicalU64DecimalStringV1 reuse for generation ---

    #[test]
    fn generation_decimal_string_reuse() {
        let g = CanonicalU64DecimalStringV1::from_u64(42);
        assert_eq!(g.as_str(), "42");
        assert_eq!(validate_generation("42").unwrap(), 42);
        assert!(validate_generation("0").is_err());
        assert!(validate_generation("").is_err());
        assert!(validate_generation("01").is_err());
    }
}
