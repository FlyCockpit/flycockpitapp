//! Canonical transport-neutral remote identity codecs. This module validates syntax only.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

pub const FCIP: [u8; 4] = *b"FCIP";
pub const FCEN: [u8; 4] = *b"FCEN";
pub const FCCE: [u8; 4] = *b"FCCE";
pub const FCPC: [u8; 4] = *b"FCPC";
pub const FCPP: [u8; 4] = *b"FCPP";
pub const FCCF: [u8; 4] = *b"FCCF";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid remote identity protocol value: {0}")]
pub struct Error(pub String);
type Result<T> = std::result::Result<T, Error>;
fn err<T>(s: impl Into<String>) -> Result<T> {
    Err(Error(s.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SubjectKind {
    Client = 1,
    Daemon = 2,
}
impl TryFrom<u8> for SubjectKind {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Client),
            2 => Ok(Self::Daemon),
            _ => err("unknown subject kind"),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CustodyClass {
    OriginProtected = 1,
    OsProtected = 2,
    HardwareOrExternal = 3,
}
impl TryFrom<u8> for CustodyClass {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::OriginProtected),
            2 => Ok(Self::OsProtected),
            3 => Ok(Self::HardwareOrExternal),
            _ => err("unknown custody class"),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PresenceMode {
    Unattended = 1,
    UnattendedAfterFirstUnlock = 2,
    UnattendedUnlockedDevice = 3,
    UserPresenceRequired = 4,
}
impl TryFrom<u8> for PresenceMode {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Unattended),
            2 => Ok(Self::UnattendedAfterFirstUnlock),
            3 => Ok(Self::UnattendedUnlockedDevice),
            4 => Ok(Self::UserPresenceRequired),
            _ => err("unknown presence mode"),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EnrollmentRole {
    ProposedSubject = 1,
    EnrolledCounterpart = 2,
    ControlPlaneAuthorizer = 3,
}
impl TryFrom<u8> for EnrollmentRole {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::ProposedSubject),
            2 => Ok(Self::EnrolledCounterpart),
            3 => Ok(Self::ControlPlaneAuthorizer),
            _ => err("unknown enrollment role"),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PossessionPurpose {
    EnrollProposed = 1,
    RenewCurrent = 2,
    RotateCurrent = 3,
    RotateProposed = 4,
    AttemptClient = 5,
    AttemptDaemon = 6,
    RevokeCurrent = 7,
}
impl TryFrom<u8> for PossessionPurpose {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::EnrollProposed),
            2 => Ok(Self::RenewCurrent),
            3 => Ok(Self::RotateCurrent),
            4 => Ok(Self::RotateProposed),
            5 => Ok(Self::AttemptClient),
            6 => Ok(Self::AttemptDaemon),
            7 => Ok(Self::RevokeCurrent),
            _ => err("unknown possession purpose"),
        }
    }
}

struct Writer(Vec<u8>);
impl Writer {
    fn new(magic: [u8; 4]) -> Self {
        let mut v = magic.to_vec();
        v.push(1);
        Self(v)
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b)
    }
    fn u8(&mut self, v: u8) {
        self.0.push(v)
    }
    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_be_bytes())
    }
    fn u64(&mut self, v: u64) {
        self.bytes(&v.to_be_bytes())
    }
    fn i64(&mut self, v: i64) {
        self.bytes(&v.to_be_bytes())
    }
    fn done(self, max: usize) -> Result<Vec<u8>> {
        if self.0.len() > max {
            err("wire value exceeds limit")
        } else {
            Ok(self.0)
        }
    }
}
struct Reader<'a> {
    b: &'a [u8],
    n: usize,
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8], magic: [u8; 4], max: usize) -> Result<Self> {
        if b.len() > max || b.len() < 5 || b[..4] != magic || b[4] != 1 {
            return err("wrong magic, version, or size");
        };
        Ok(Self { b, n: 5 })
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.n + N > self.b.len() {
            return err("truncated");
        };
        let x = self.b[self.n..self.n + N].try_into().expect("length");
        self.n += N;
        Ok(x)
    }
    fn slice(&mut self, n: usize) -> Result<Vec<u8>> {
        if self.n + n > self.b.len() {
            return err("truncated");
        };
        let x = self.b[self.n..self.n + n].to_vec();
        self.n += n;
        Ok(x)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take()?))
    }
    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(self.take()?))
    }
    fn finish(self) -> Result<()> {
        if self.n == self.b.len() {
            Ok(())
        } else {
            err("trailing bytes")
        }
    }
}
fn id(x: &[u8; 16]) -> Result<()> {
    if x.iter().all(|x| *x == 0) {
        err("zero identifier")
    } else {
        Ok(())
    }
}
const P256_N: [u8; 32] = [
    255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 188, 230, 250, 173,
    167, 23, 158, 132, 243, 185, 202, 194, 252, 99, 37, 81,
];
const P256_HALF_N: [u8; 32] = [
    127, 255, 255, 255, 128, 0, 0, 0, 127, 255, 255, 255, 255, 255, 255, 255, 222, 115, 125, 86,
    211, 139, 207, 66, 121, 220, 229, 97, 126, 49, 146, 168,
];
fn validate_low_s(signature: &[u8; 64]) -> Result<()> {
    let r: [u8; 32] = signature[..32]
        .try_into()
        .map_err(|_| Error("signature".into()))?;
    let s: [u8; 32] = signature[32..]
        .try_into()
        .map_err(|_| Error("signature".into()))?;
    if r.iter().all(|b| *b == 0) || s.iter().all(|b| *b == 0) || r >= P256_N || s > P256_HALF_N {
        return err("invalid or high-S P1363 signature");
    };
    Ok(())
}
fn validate_thumbprint(x: &[u8; 32], y: &[u8; 32], thumbprint: &[u8; 32]) -> Result<()> {
    let json = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        URL_SAFE_NO_PAD.encode(x),
        URL_SAFE_NO_PAD.encode(y)
    );
    if sha256(json.as_bytes()) != *thumbprint {
        return err("thumbprint mismatch");
    };
    Ok(())
}
fn put_account(w: &mut Writer, k: SubjectKind, a: &Option<[u8; 16]>) -> Result<()> {
    match (k, a) {
        (SubjectKind::Client, Some(x)) => {
            id(x)?;
            w.u8(1);
            w.bytes(x)
        }
        (SubjectKind::Daemon, None) => w.u8(0),
        (SubjectKind::Client, None) => return err("client account missing"),
        (SubjectKind::Daemon, Some(_)) => return err("daemon account present"),
    };
    Ok(())
}
fn get_account(r: &mut Reader<'_>, k: SubjectKind) -> Result<Option<[u8; 16]>> {
    match (r.u8()?, k) {
        (1, SubjectKind::Client) => Ok(Some(r.take()?)),
        (0, SubjectKind::Daemon) => Ok(None),
        (0, SubjectKind::Client) => err("client account missing"),
        (1, SubjectKind::Daemon) => err("daemon account present"),
        _ => err("invalid account presence"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub subject_kind: SubjectKind,
    pub subject_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub account_id: Option<[u8; 16]>,
    pub instance_id: [u8; 16],
    pub certificate_id: [u8; 16],
    pub generation: u64,
    pub p256_x: [u8; 32],
    pub p256_y: [u8; 32],
    pub thumbprint: [u8; 32],
    pub custody_class: CustodyClass,
    pub presence_mode: PresenceMode,
    pub issuer: String,
    pub service_version: u64,
    pub policy_epoch: u64,
    pub policy_digest: [u8; 32],
    pub authority_epoch: u64,
    pub issued_at: i64,
    pub expires_at: i64,
}
impl Proposal {
    pub fn encode(&self) -> Result<Vec<u8>> {
        for x in [
            &self.subject_id,
            &self.tenant_id,
            &self.instance_id,
            &self.certificate_id,
        ] {
            id(x)?
        }
        validate_thumbprint(&self.p256_x, &self.p256_y, &self.thumbprint)?;
        let o = normalized_origin(&self.issuer)?;
        let mut w = Writer::new(FCIP);
        w.u8(self.subject_kind as u8);
        w.bytes(&self.subject_id);
        w.bytes(&self.tenant_id);
        put_account(&mut w, self.subject_kind, &self.account_id)?;
        w.bytes(&self.instance_id);
        w.bytes(&self.certificate_id);
        w.u64(self.generation);
        w.bytes(&self.p256_x);
        w.bytes(&self.p256_y);
        w.bytes(&self.thumbprint);
        w.u8(self.custody_class as u8);
        w.u8(self.presence_mode as u8);
        w.u16(o.len() as u16);
        w.bytes(o);
        w.u64(self.service_version);
        w.u64(self.policy_epoch);
        w.bytes(&self.policy_digest);
        w.u64(self.authority_epoch);
        w.i64(self.issued_at);
        w.i64(self.expires_at);
        w.done(4096)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b, FCIP, 4096)?;
        let subject_kind = r.u8()?.try_into()?;
        let subject_id = r.take()?;
        let tenant_id = r.take()?;
        let account_id = get_account(&mut r, subject_kind)?;
        let instance_id = r.take()?;
        let certificate_id = r.take()?;
        let generation = r.u64()?;
        let p256_x = r.take()?;
        let p256_y = r.take()?;
        let thumbprint = r.take()?;
        let custody_class = r.u8()?.try_into()?;
        let presence_mode = r.u8()?.try_into()?;
        let n = r.u16()? as usize;
        let issuer = String::from_utf8(r.slice(n)?).map_err(|_| Error("issuer utf8".into()))?;
        let v = Self {
            subject_kind,
            subject_id,
            tenant_id,
            account_id,
            instance_id,
            certificate_id,
            generation,
            p256_x,
            p256_y,
            thumbprint,
            custody_class,
            presence_mode,
            issuer,
            service_version: r.u64()?,
            policy_epoch: r.u64()?,
            policy_digest: r.take()?,
            authority_epoch: r.u64()?,
            issued_at: r.i64()?,
            expires_at: r.i64()?,
        };
        r.finish()?;
        v.encode()?;
        Ok(v)
    }
}
fn normalized_origin(s: &str) -> Result<&[u8]> {
    let Some(authority) = s.strip_prefix("https://") else {
        return err("origin must use HTTPS");
    };
    if !(1..=255).contains(&s.len())
        || authority.is_empty()
        || authority
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_uppercase())
        || authority.contains(['/', '?', '#', '@'])
        || authority.ends_with(":443")
    {
        return err("origin must be a normalized HTTPS origin");
    }
    let host = authority.split_once(':').map_or(authority, |(host, port)| {
        if port.is_empty()
            || port.starts_with('0')
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().is_err()
        {
            ""
        } else {
            host
        }
    });
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return err("origin host is noncanonical");
    }
    Ok(s.as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentTranscript {
    pub enrollment_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub account_id: Option<[u8; 16]>,
    pub instance_id: [u8; 16],
    pub subject_kind: SubjectKind,
    pub subject_id: [u8; 16],
    pub generation: u64,
    pub p256_x: [u8; 32],
    pub p256_y: [u8; 32],
    pub thumbprint: [u8; 32],
    pub custody_class: CustodyClass,
    pub presence_mode: PresenceMode,
    pub public_origin: String,
    pub initiator_role: EnrollmentRole,
    pub confirmer_role: EnrollmentRole,
    pub initiator_nonce: [u8; 32],
    pub confirmer_nonce: [u8; 32],
    pub created_at: i64,
    pub expires_at: i64,
    pub service_version: u64,
    pub policy_epoch: u64,
    pub policy_digest: [u8; 32],
    pub authority_epoch: u64,
}
fn valid_roles(a: EnrollmentRole, b: EnrollmentRole) -> bool {
    a != b && (a == EnrollmentRole::ProposedSubject || b == EnrollmentRole::ProposedSubject)
}
impl EnrollmentTranscript {
    pub fn encode(&self) -> Result<Vec<u8>> {
        for value in [
            &self.enrollment_id,
            &self.tenant_id,
            &self.instance_id,
            &self.subject_id,
        ] {
            id(value)?;
        }
        if !valid_roles(self.initiator_role, self.confirmer_role) {
            return err("invalid enrollment role pair");
        }
        validate_thumbprint(&self.p256_x, &self.p256_y, &self.thumbprint)?;
        if !matches!(self.expires_at.checked_sub(self.created_at), Some(1..=300)) {
            return err("invalid transcript lifetime");
        }
        let origin = normalized_origin(&self.public_origin)?;
        let mut w = Writer::new(FCEN);
        w.bytes(&self.enrollment_id);
        w.bytes(&self.tenant_id);
        put_account(&mut w, self.subject_kind, &self.account_id)?;
        w.bytes(&self.instance_id);
        w.u8(self.subject_kind as u8);
        w.bytes(&self.subject_id);
        w.u64(self.generation);
        w.bytes(&self.p256_x);
        w.bytes(&self.p256_y);
        w.bytes(&self.thumbprint);
        w.u8(self.custody_class as u8);
        w.u8(self.presence_mode as u8);
        w.u16(origin.len() as u16);
        w.bytes(origin);
        w.u8(self.initiator_role as u8);
        w.u8(self.confirmer_role as u8);
        w.bytes(&self.initiator_nonce);
        w.bytes(&self.confirmer_nonce);
        w.i64(self.created_at);
        w.i64(self.expires_at);
        w.u64(self.service_version);
        w.u64(self.policy_epoch);
        w.bytes(&self.policy_digest);
        w.u64(self.authority_epoch);
        w.done(1024)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, FCEN, 1024)?;
        let enrollment_id = r.take()?;
        let tenant_id = r.take()?;
        let present = r.u8()?;
        if present > 1 {
            return err("invalid account presence");
        };
        let account_id = if present == 1 { Some(r.take()?) } else { None };
        let instance_id = r.take()?;
        let subject_kind = r.u8()?.try_into()?;
        match (subject_kind, account_id.is_some()) {
            (SubjectKind::Client, true) | (SubjectKind::Daemon, false) => {}
            (SubjectKind::Client, false) => return err("client account missing"),
            (SubjectKind::Daemon, true) => return err("daemon account present"),
        }
        let v = Self {
            enrollment_id,
            tenant_id,
            account_id,
            instance_id,
            subject_kind,
            subject_id: r.take()?,
            generation: r.u64()?,
            p256_x: r.take()?,
            p256_y: r.take()?,
            thumbprint: r.take()?,
            custody_class: r.u8()?.try_into()?,
            presence_mode: r.u8()?.try_into()?,
            public_origin: {
                let n = r.u16()? as usize;
                String::from_utf8(r.slice(n)?).map_err(|_| Error("origin utf8".into()))?
            },
            initiator_role: r.u8()?.try_into()?,
            confirmer_role: r.u8()?.try_into()?,
            initiator_nonce: r.take()?,
            confirmer_nonce: r.take()?,
            created_at: r.i64()?,
            expires_at: r.i64()?,
            service_version: r.u64()?,
            policy_epoch: r.u64()?,
            policy_digest: r.take()?,
            authority_epoch: r.u64()?,
        };
        r.finish()?;
        v.encode()?;
        Ok(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyEvidence {
    pub subject_kind: SubjectKind,
    pub subject_id: [u8; 16],
    pub generation: u64,
    pub custody_class: CustodyClass,
    pub presence_mode: PresenceMode,
    pub provider_evidence: Vec<u8>,
    pub evidence_digest: [u8; 32],
    pub observed_at: i64,
}
impl CustodyEvidence {
    pub fn encode(&self) -> Result<Vec<u8>> {
        id(&self.subject_id)?;
        if self.provider_evidence.len() > 65_000 {
            return err("provider evidence too long");
        };
        if sha256(&self.provider_evidence) != self.evidence_digest {
            return err("evidence digest mismatch");
        };
        let mut w = Writer::new(FCCE);
        w.u8(self.subject_kind as u8);
        w.bytes(&self.subject_id);
        w.u64(self.generation);
        w.u8(self.custody_class as u8);
        w.u8(self.presence_mode as u8);
        w.u16(self.provider_evidence.len() as u16);
        w.bytes(&self.provider_evidence);
        w.bytes(&self.evidence_digest);
        w.i64(self.observed_at);
        w.done(65_536)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b, FCCE, 65_536)?;
        let subject_kind = r.u8()?.try_into()?;
        let subject_id = r.take()?;
        let generation = r.u64()?;
        let custody_class = r.u8()?.try_into()?;
        let presence_mode = r.u8()?.try_into()?;
        let n = r.u16()? as usize;
        let v = Self {
            subject_kind,
            subject_id,
            generation,
            custody_class,
            presence_mode,
            provider_evidence: r.slice(n)?,
            evidence_digest: r.take()?,
            observed_at: r.i64()?,
        };
        r.finish()?;
        v.encode()?;
        Ok(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentConfirmation {
    pub role: EnrollmentRole,
    pub decision: u8,
    pub enrollment_id: [u8; 16],
    pub transcript_digest: [u8; 32],
    pub confirmation_nonce: [u8; 32],
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature_p1363: [u8; 64],
}
pub fn enrollment_confirmation_domain(role: EnrollmentRole) -> Vec<u8> {
    let r = match role {
        EnrollmentRole::ProposedSubject => "proposed-subject",
        EnrollmentRole::EnrolledCounterpart => "enrolled-counterpart",
        EnrollmentRole::ControlPlaneAuthorizer => "control-plane-authorizer",
    };
    format!("flycockpit.remote.enrollment-confirmation.{r}.v1\0").into_bytes()
}
impl EnrollmentConfirmation {
    pub fn encode(&self) -> Result<Vec<u8>> {
        id(&self.enrollment_id)?;
        validate_low_s(&self.signature_p1363)?;
        if !(1..=2).contains(&self.decision)
            || !matches!(self.expires_at.checked_sub(self.issued_at), Some(1..=60))
        {
            return err("confirmation decision or lifetime");
        };
        let mut w = Writer::new(FCCF);
        w.u8(self.role as u8);
        w.u8(self.decision);
        w.bytes(&self.enrollment_id);
        w.bytes(&self.transcript_digest);
        w.u8(1);
        w.bytes(&self.confirmation_nonce);
        w.i64(self.issued_at);
        w.i64(self.expires_at);
        w.bytes(&self.signature_p1363);
        let b = w.done(168)?;
        if b.len() != 168 {
            return err("confirmation length");
        };
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b, FCCF, 168)?;
        let role = r.u8()?.try_into()?;
        let decision = r.u8()?;
        let enrollment_id = r.take()?;
        let transcript_digest = r.take()?;
        if r.u8()? != 1 {
            return err("unknown SAS version");
        };
        let v = Self {
            role,
            decision,
            enrollment_id,
            transcript_digest,
            confirmation_nonce: r.take()?,
            issued_at: r.i64()?,
            expires_at: r.i64()?,
            signature_p1363: r.take()?,
        };
        r.finish()?;
        v.encode()?;
        Ok(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PossessionContext {
    pub purpose: PossessionPurpose,
    pub current_certificate_digest: Option<[u8; 32]>,
    pub proposed_identity_digest: Option<[u8; 32]>,
    pub enrollment_transcript_digest: Option<[u8; 32]>,
    pub attempt_request_digest: Option<[u8; 32]>,
    pub revocation_request_digest: Option<[u8; 32]>,
}
impl PossessionContext {
    fn expected(&self) -> [bool; 5] {
        use PossessionPurpose::*;
        match self.purpose {
            EnrollProposed => [false, true, true, false, false],
            RenewCurrent | RotateCurrent | RotateProposed => [true, true, false, false, false],
            AttemptClient | AttemptDaemon => [true, false, false, true, false],
            RevokeCurrent => [true, false, false, false, true],
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let xs = [
            self.current_certificate_digest,
            self.proposed_identity_digest,
            self.enrollment_transcript_digest,
            self.attempt_request_digest,
            self.revocation_request_digest,
        ];
        let mut w = Writer::new(FCPC);
        w.u8(self.purpose as u8);
        for (i, x) in xs.iter().enumerate() {
            if x.is_some() != self.expected()[i] {
                return err("purpose context mismatch");
            };
            w.u8(u8::from(x.is_some()));
            if let Some(x) = x {
                w.bytes(x)
            }
        }
        w.done(171)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b, FCPC, 171)?;
        let purpose = r.u8()?.try_into()?;
        let mut xs = [None; 5];
        for x in &mut xs {
            match r.u8()? {
                0 => {}
                1 => *x = Some(r.take()?),
                _ => return err("invalid presence"),
            }
        }
        r.finish()?;
        let v = Self {
            purpose,
            current_certificate_digest: xs[0],
            proposed_identity_digest: xs[1],
            enrollment_transcript_digest: xs[2],
            attempt_request_digest: xs[3],
            revocation_request_digest: xs[4],
        };
        v.encode()?;
        Ok(v)
    }
}
fn purpose_name(p: PossessionPurpose) -> &'static str {
    match p {
        PossessionPurpose::EnrollProposed => "enroll-proposed",
        PossessionPurpose::RenewCurrent => "renew-current",
        PossessionPurpose::RotateCurrent => "rotate-current",
        PossessionPurpose::RotateProposed => "rotate-proposed",
        PossessionPurpose::AttemptClient => "attempt-client",
        PossessionPurpose::AttemptDaemon => "attempt-daemon",
        PossessionPurpose::RevokeCurrent => "revoke-current",
    }
}
pub fn possession_challenge_domain(p: PossessionPurpose) -> Vec<u8> {
    format!(
        "flycockpit.remote.identity-possession-challenge.{}.v1\0",
        purpose_name(p)
    )
    .into_bytes()
}
pub fn possession_signature_domain(p: PossessionPurpose) -> Vec<u8> {
    format!(
        "flycockpit.remote.identity-possession-proof.{}.v1\0",
        purpose_name(p)
    )
    .into_bytes()
}
pub fn derive_possession_challenge(
    p: PossessionPurpose,
    status: &[u8; 32],
    request: &[u8; 16],
    context: &[u8],
) -> Result<[u8; 32]> {
    id(request)?;
    let context_digest = Sha256::digest(context);
    let mut h = Sha256::new();
    h.update(possession_challenge_domain(p));
    h.update(status);
    h.update(request);
    h.update(context_digest);
    Ok(h.finalize().into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PossessionProof {
    pub purpose: PossessionPurpose,
    pub subject_kind: SubjectKind,
    pub subject_id: [u8; 16],
    pub certificate_id: [u8; 16],
    pub generation: u64,
    pub request_id: [u8; 16],
    pub issuer_status_digest: [u8; 32],
    pub challenge: [u8; 32],
    pub transcript_digest: [u8; 32],
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature_p1363: [u8; 64],
}
impl PossessionProof {
    pub fn encode(&self) -> Result<Vec<u8>> {
        id(&self.subject_id)?;
        id(&self.certificate_id)?;
        id(&self.request_id)?;
        validate_low_s(&self.signature_p1363)?;
        if self.expires_at.checked_sub(self.issued_at) != Some(60) {
            return err("proof lifetime");
        };
        match (self.purpose, self.subject_kind) {
            (
                PossessionPurpose::AttemptClient | PossessionPurpose::RevokeCurrent,
                SubjectKind::Client,
            )
            | (PossessionPurpose::AttemptDaemon, SubjectKind::Daemon)
            | (
                PossessionPurpose::EnrollProposed
                | PossessionPurpose::RenewCurrent
                | PossessionPurpose::RotateCurrent
                | PossessionPurpose::RotateProposed,
                _,
            ) => {}
            _ => return err("purpose subject mismatch"),
        };
        let mut w = Writer::new(FCPP);
        w.u8(self.purpose as u8);
        w.u8(self.subject_kind as u8);
        w.bytes(&self.subject_id);
        w.bytes(&self.certificate_id);
        w.u64(self.generation);
        w.bytes(&self.request_id);
        w.bytes(&self.issuer_status_digest);
        w.bytes(&self.challenge);
        w.bytes(&self.transcript_digest);
        w.i64(self.issued_at);
        w.i64(self.expires_at);
        w.bytes(&self.signature_p1363);
        let b = w.done(239)?;
        if b.len() != 239 {
            return err("proof length");
        };
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b, FCPP, 239)?;
        let v = Self {
            purpose: r.u8()?.try_into()?,
            subject_kind: r.u8()?.try_into()?,
            subject_id: r.take()?,
            certificate_id: r.take()?,
            generation: r.u64()?,
            request_id: r.take()?,
            issuer_status_digest: r.take()?,
            challenge: r.take()?,
            transcript_digest: r.take()?,
            issued_at: r.i64()?,
            expires_at: r.i64()?,
            signature_p1363: r.take()?,
        };
        r.finish()?;
        v.encode()?;
        Ok(v)
    }
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCertificateJws {
    pub protected_header: serde_json::Value,
    pub payload: serde_json::Value,
    pub signature_p1363: [u8; 64],
    pub signing_input: Vec<u8>,
}
fn decode_canonical_b64url(text: &str) -> Result<Vec<u8>> {
    if text.is_empty() || text.contains('=') {
        return err("noncanonical base64url");
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Error("invalid base64url".into()))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != text {
        return err("noncanonical base64url");
    };
    Ok(bytes)
}
pub fn parse_remote_identity_certificate_jws(compact: &str) -> Result<ParsedCertificateJws> {
    if compact.len() > 4096 {
        return err("certificate exceeds limit");
    };
    let parts: Vec<_> = compact.split('.').collect();
    if parts.len() != 3 {
        return err("invalid compact JWS");
    };
    let header_bytes = decode_canonical_b64url(parts[0])?;
    let payload_bytes = decode_canonical_b64url(parts[1])?;
    let signature: [u8; 64] = decode_canonical_b64url(parts[2])?
        .try_into()
        .map_err(|_| Error("signature length".into()))?;
    validate_low_s(&signature)?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| Error("invalid header JSON".into()))?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| Error("invalid payload JSON".into()))?;
    if serde_json::to_vec(&header).map_err(|_| Error("header JSON".into()))? != header_bytes
        || serde_json::to_vec(&payload).map_err(|_| Error("payload JSON".into()))? != payload_bytes
    {
        return err("noncanonical JSON");
    };
    let h = header
        .as_object()
        .ok_or_else(|| Error("header object".into()))?;
    if h.len() != 3
        || h.get("alg").and_then(|v| v.as_str()) != Some("ES256")
        || h.get("typ").and_then(|v| v.as_str())
            != Some("flycockpit-remote-identity-certificate+jws")
        || h.get("kid").and_then(|v| v.as_str()).is_none()
    {
        return err("invalid protected header");
    };
    let p = payload
        .as_object()
        .ok_or_else(|| Error("payload object".into()))?;
    const KEYS: [&str; 17] = [
        "schemaVersion",
        "iss",
        "aud",
        "sub",
        "tenantId",
        "accountId",
        "instanceId",
        "subjectKind",
        "certificateId",
        "generation",
        "publicKey",
        "thumbprint",
        "custody",
        "presenceMode",
        "authorityEpoch",
        "iat",
        "exp",
    ];
    if p.len() != KEYS.len()
        || KEYS.iter().any(|k| !p.contains_key(*k))
        || p.get("schemaVersion").and_then(|v| v.as_u64()) != Some(1)
        || p.get("aud").and_then(|v| v.as_str()) != Some("flycockpit-remote-peer-v1")
    {
        return err("invalid certificate payload");
    };
    for key in ["sub", "tenantId", "instanceId", "certificateId"] {
        let value = p
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error(format!("invalid {key}")))?;
        crate::remote_protocol_id::decode_protocol_id_base64url(value)
            .map_err(|e| Error(e.to_string()))?;
    }
    let kind = SubjectKind::try_from(
        p.get("subjectKind")
            .and_then(|v| v.as_u64())
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| Error("invalid subjectKind".into()))?,
    )?;
    match (kind, p.get("accountId")) {
        (SubjectKind::Client, Some(serde_json::Value::String(value))) => {
            crate::remote_protocol_id::decode_protocol_id_base64url(value)
                .map_err(|e| Error(e.to_string()))?;
        }
        (SubjectKind::Daemon, Some(serde_json::Value::Null)) => {}
        _ => return err("invalid certificate account branch"),
    }
    for key in ["generation", "authorityEpoch", "iat", "exp"] {
        let value = p
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error(format!("invalid {key}")))?;
        crate::remote_protocol_id::parse_canonical_u64_decimal_string(value)
            .map_err(|e| Error(e.to_string()))?;
    }
    CustodyClass::try_from(
        p.get("custody")
            .and_then(|v| v.as_u64())
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| Error("invalid custody".into()))?,
    )?;
    PresenceMode::try_from(
        p.get("presenceMode")
            .and_then(|v| v.as_u64())
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| Error("invalid presenceMode".into()))?,
    )?;
    let key = p
        .get("publicKey")
        .and_then(|v| v.as_object())
        .ok_or_else(|| Error("invalid publicKey".into()))?;
    if key.len() != 4
        || key.get("kty").and_then(|v| v.as_str()) != Some("EC")
        || key.get("crv").and_then(|v| v.as_str()) != Some("P-256")
    {
        return err("invalid publicKey");
    };
    let x: [u8; 32] = decode_canonical_b64url(
        key.get("x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error("invalid x".into()))?,
    )?
    .try_into()
    .map_err(|_| Error("x length".into()))?;
    let y: [u8; 32] = decode_canonical_b64url(
        key.get("y")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error("invalid y".into()))?,
    )?
    .try_into()
    .map_err(|_| Error("y length".into()))?;
    let thumbprint: [u8; 32] = decode_canonical_b64url(
        p.get("thumbprint")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error("invalid thumbprint".into()))?,
    )?
    .try_into()
    .map_err(|_| Error("thumbprint length".into()))?;
    validate_thumbprint(&x, &y, &thumbprint)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]).into_bytes();
    Ok(ParsedCertificateJws {
        protected_header: header,
        payload,
        signature_p1363: signature,
        signing_input,
    })
}

pub fn possession_proof_signing_digest(
    unsigned_proof: &[u8],
    purpose: PossessionPurpose,
) -> Result<[u8; 32]> {
    if unsigned_proof.len() != 175
        || unsigned_proof.get(..4) != Some(FCPP.as_slice())
        || unsigned_proof.get(5) != Some(&(purpose as u8))
    {
        return err("invalid unsigned possession proof");
    }
    let mut h = Sha256::new();
    h.update(possession_signature_domain(purpose));
    h.update(unsigned_proof);
    Ok(h.finalize().into())
}
pub fn enrollment_confirmation_signing_digest(
    unsigned_confirmation: &[u8],
    role: EnrollmentRole,
) -> Result<[u8; 32]> {
    if unsigned_confirmation.len() != 104
        || unsigned_confirmation.get(..4) != Some(FCCF.as_slice())
        || unsigned_confirmation.get(5) != Some(&(role as u8))
    {
        return err("invalid unsigned enrollment confirmation");
    }
    let mut h = Sha256::new();
    h.update(enrollment_confirmation_domain(role));
    h.update(unsigned_confirmation);
    Ok(h.finalize().into())
}
