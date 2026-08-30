//! Canonical typed identity for scoped sealed values.
//!
//! Everything in this module is *safe metadata*: it is the only sealed-value
//! information that may cross into a renderer, an export, a redaction origin,
//! or an untrusted model's context. No type here can carry a literal, a key,
//! an encoding, or an authorization result.

use std::fmt;
use std::path::Path;

use anyhow::{Result, bail};
use uuid::Uuid;

pub use cockpit_db::db::sealed_scope::SealedScopeKind;

/// Longest canonical name, in Unicode scalar values.
pub const MAX_SEALED_NAME_SCALARS: usize = 64;
/// Longest safe description, in Unicode scalar values.
pub const MAX_SEALED_DESCRIPTION_SCALARS: usize = 512;

/// A canonical, normalized sealed-value name.
///
/// Normalization is trim + case-fold, so `" Deploy_Token "` and
/// `"deploy_token"` are the same name and cannot both exist in one scope.
/// `:` is excluded because a name is embedded in the redaction origin, which
/// is `:`-delimited; a name that could inject a delimiter would let safe
/// metadata forge a different canonical identity.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealedName(String);

impl SealedName {
    /// Normalize and validate. This is the only constructor: an unnormalized
    /// name cannot exist anywhere in the tree.
    pub fn canonical(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        let folded = trimmed.to_lowercase();
        let scalars = folded.chars().count();
        if scalars == 0 {
            bail!("sealed value name must not be empty");
        }
        if scalars > MAX_SEALED_NAME_SCALARS {
            bail!("sealed value name must be at most {MAX_SEALED_NAME_SCALARS} characters");
        }
        if folded.chars().any(|c| c.is_control() || c == ':') {
            bail!("sealed value name must not contain control characters or ':'");
        }
        Ok(Self(folded))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SealedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedName({:?})", self.0)
    }
}

impl fmt::Display for SealedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A safe, human-authored description. Bounded and control-character free so
/// it can be rendered anywhere safe metadata is allowed.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SealedDescription(String);

impl SealedDescription {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.chars().count() > MAX_SEALED_DESCRIPTION_SCALARS {
            bail!(
                "sealed value description must be at most {MAX_SEALED_DESCRIPTION_SCALARS} characters"
            );
        }
        if trimmed.chars().any(|c| c.is_control() && c != '\n') {
            bail!("sealed value description must not contain control characters");
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SealedDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedDescription({:?})", self.0)
    }
}

/// The immutable identity of one sealed-value record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealedRecordId(Uuid);

impl SealedRecordId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    pub fn parse(raw: &str) -> Result<Self> {
        Ok(Self(Uuid::parse_str(raw)?))
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for SealedRecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A canonical project key. Project-scope uniqueness and every grant's project
/// targeting are expressed in this key, never in a raw filesystem path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealedProjectKey(String);

impl SealedProjectKey {
    /// Derive the canonical key from a project root, using the same project
    /// identity function the session layer uses. There is deliberately no
    /// second canonicalization rule for sealed values.
    pub fn canonical(project_root: &Path) -> Result<Self> {
        Ok(Self(crate::session::project_id_for(project_root)?))
    }

    /// Adopt an already-canonical key (for example `Session::project_id`).
    pub fn from_canonical(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SealedProjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether the canonical project is currently trusted.
///
/// A sealed value never resolves in an untrusted project. This is an input to
/// authorization rather than something the sealed layer re-derives, so there
/// is exactly one workspace-trust authority in the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedProjectTrust {
    Trusted,
    Untrusted,
}

impl SealedProjectTrust {
    pub fn is_trusted(self) -> bool {
        matches!(self, Self::Trusted)
    }
}

/// Which scope key a record lives under. Global records have no scope key:
/// their names are unique globally and their project reach is an explicit
/// Owner grant, never an implicit scope membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedScopeRef {
    Session(Uuid),
    Project(SealedProjectKey),
    Global,
}

impl SealedScopeRef {
    pub fn kind(&self) -> SealedScopeKind {
        match self {
            Self::Session(_) => SealedScopeKind::Session,
            Self::Project(_) => SealedScopeKind::Project,
            Self::Global => SealedScopeKind::Global,
        }
    }

    /// The stored `scope_key` column value.
    pub fn scope_key(&self) -> String {
        match self {
            Self::Session(id) => id.to_string(),
            Self::Project(key) => key.as_str().to_string(),
            Self::Global => String::new(),
        }
    }
}

/// The canonical typed identity carried by a persisted redaction entry.
///
/// This is what a historical-redaction inventory consumer sees. It contains no
/// grant, no action, and no authorization outcome — a value that was once
/// redacted stays redacted forever regardless of whether it is still usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRedactionIdentity {
    pub scope: SealedScopeKind,
    /// `None` for a session entry registered before the record layer existed,
    /// which is keyed by name alone.
    pub record_id: Option<SealedRecordId>,
    pub name: SealedName,
    /// `0` marks an unversioned legacy session entry.
    pub version: u32,
}

impl SealedRedactionIdentity {
    /// The canonical diagnostic origin *string* for `cockpit debug redact`
    /// display, derived FROM this typed identity. A scoped entry renders the
    /// full grammar; a legacy session entry (no record id) renders the
    /// pre-scoping `sealed:<name>` form. This is a display artifact only — it is
    /// NEVER parsed back to recover sealedness (classification is carried by the
    /// typed identity end-to-end).
    pub fn display_origin(&self) -> String {
        match self.record_id {
            Some(record_id) => {
                sealed_redaction_origin(self.scope, record_id, self.version, &self.name)
            }
            None => format!("{SEALED_ORIGIN_PREFIX}{}", self.name),
        }
    }
}

/// Redaction-origin prefix shared by every sealed entry, scoped or legacy.
pub const SEALED_ORIGIN_PREFIX: &str = "sealed:";
/// Version tag of the scoped origin grammar.
const SEALED_ORIGIN_GRAMMAR: &str = "1";

/// Render the canonical redaction origin for one record version.
///
/// Grammar: `sealed:1:<scope>:<record_id>:<version>:<name>`. The name is last
/// and unbounded-by-position, which is why `:` is banned from names.
pub fn sealed_redaction_origin(
    scope: SealedScopeKind,
    record_id: SealedRecordId,
    version: u32,
    name: &SealedName,
) -> String {
    format!(
        "{SEALED_ORIGIN_PREFIX}{SEALED_ORIGIN_GRAMMAR}:{}:{}:{}:{}",
        scope.as_str(),
        record_id,
        version,
        name
    )
}

/// The version-scoped, namespaced key that binds a scoped sealed redaction
/// entry (or the scoped side of a live grant) to the active-grant set.
///
/// The `version` is part of the key, so a grant pinned to version N never
/// activates a persisted entry sealed at a *different* version of the same
/// record. The `scoped:`/`legacy:` namespace prefix additionally prevents a
/// record-id key from ever colliding with a name key. Neither a record-id
/// (a UUID) nor a canonical name contains `@`, so the version suffix is
/// unambiguous.
pub(crate) fn sealed_scoped_active_key(record_id: &str, version: u32) -> String {
    format!("scoped:{record_id}@{version}")
}

/// The version-scoped, namespaced key for a legacy (pre-scoping) session entry
/// keyed by canonical name, or the legacy side of a live grant.
///
/// A legacy entry is always version `0`; a real grant is version `>= 1`. Binding
/// the version into the key means a scoped grant for a versioned record never
/// activates a legacy same-name entry of a *different* record — closing the
/// same-name cross-record leak. See [`sealed_scoped_active_key`].
pub(crate) fn sealed_legacy_active_key(name: &str, version: u32) -> String {
    format!("legacy:{name}@{version}")
}

/// Parse a redaction origin back into canonical typed identity.
///
/// Accepts both the scoped grammar and the pre-existing session grammar
/// (`sealed:<value_id>`), so a historical inventory covers entries written
/// before scoping existed.
pub fn parse_sealed_redaction_origin(origin: &str) -> Option<SealedRedactionIdentity> {
    let rest = origin.strip_prefix(SEALED_ORIGIN_PREFIX)?;
    let scoped = rest
        .strip_prefix(SEALED_ORIGIN_GRAMMAR)
        .and_then(|tail| tail.strip_prefix(':'));
    let Some(scoped) = scoped else {
        // Legacy session entry: the whole remainder is the value id.
        return Some(SealedRedactionIdentity {
            scope: SealedScopeKind::Session,
            record_id: None,
            name: SealedName::canonical(rest).ok()?,
            version: 0,
        });
    };
    let mut parts = scoped.splitn(4, ':');
    let scope = SealedScopeKind::parse(parts.next()?).ok()?;
    let record_id = SealedRecordId::parse(parts.next()?).ok()?;
    let version: u32 = parts.next()?.parse().ok()?;
    let name = SealedName::canonical(parts.next()?).ok()?;
    Some(SealedRedactionIdentity {
        scope,
        record_id: Some(record_id),
        name,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_trimmed_case_folded_and_bounded() {
        assert_eq!(
            SealedName::canonical("  Deploy_Token ").unwrap().as_str(),
            "deploy_token"
        );
        assert!(SealedName::canonical("   ").is_err());
        assert!(SealedName::canonical(&"a".repeat(65)).is_err());
        assert!(SealedName::canonical("has:colon").is_err());
        assert!(SealedName::canonical("has\u{7}bell").is_err());
        // Unicode scalars are counted, not bytes.
        assert!(SealedName::canonical(&"é".repeat(64)).is_ok());
    }

    #[test]
    fn scoped_origin_round_trips_and_legacy_origin_still_parses() {
        let id = SealedRecordId::generate();
        let name = SealedName::canonical("deploy_token").unwrap();
        let origin = sealed_redaction_origin(SealedScopeKind::Project, id, 7, &name);
        let parsed = parse_sealed_redaction_origin(&origin).unwrap();
        assert_eq!(parsed.scope, SealedScopeKind::Project);
        assert_eq!(parsed.record_id, Some(id));
        assert_eq!(parsed.version, 7);
        assert_eq!(parsed.name, name);

        let legacy = parse_sealed_redaction_origin("sealed:prod_token").unwrap();
        assert_eq!(legacy.scope, SealedScopeKind::Session);
        assert_eq!(legacy.record_id, None);
        assert_eq!(legacy.version, 0);
        assert_eq!(legacy.name.as_str(), "prod_token");

        assert!(parse_sealed_redaction_origin("$SOME_ENV").is_none());
    }
}
