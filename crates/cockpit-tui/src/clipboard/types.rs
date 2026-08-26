//! Shared types for trusted ordered clipboard delivery.

/// Delivery route evaluated by the routing service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Route {
    Native,
    Osc52,
    Executable,
}

/// Final confidence for a copy attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// A native adapter or executable reported success, or OSC52 was
    /// explicitly acknowledged by a tested terminal capability.
    Confirmed,
    /// OSC52 was emitted without acknowledgement (and no later route confirmed).
    Unverified,
    /// No route delivered content.
    Failed,
}

/// Representation carried by a request or delivered by a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Representation {
    Plain,
    Rich,
    None,
}

/// Policy for rich-text requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RichPolicy {
    /// Plain text only — every eligible route may run.
    Plain,
    /// Rich only via native; never downgrade.
    StrictRich,
    /// Prefer rich via native; on failure record one RichToPlain downgrade
    /// and run the ordinary plain chain.
    AllowPlainDowngrade,
}

/// Explicit post-success representation downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Downgrade {
    RichToPlain,
}

/// OSC52 transport form. Exactly one frame is emitted per attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OscTransport {
    /// Raw `ESC ] 52 ; c ; payload BEL`.
    Direct,
    /// Single DCS-wrapped frame for tmux passthrough.
    TmuxPassthrough,
}

/// Per-attempt outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    Confirmed,
    Unverified,
    Failed,
    Skipped,
}

/// Why a route was not attempted or could not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    NotSameHostLocalDesktop,
    UntrustedRemote,
    SshSession,
    WslOrContainer,
    HostBridge,
    NoHeldAuthenticatedConnection,
    UnsupportedBackend,
    PlainOnlyRoute,
    OverSizeLimit,
    EmptyPayload,
    Cancelled,
    MissingCandidate,
    IneligibleExecutable,
    X11Unsupported,
    LinuxNativeCannotConsumeHeldStream,
    OscNotAdvertised,
    /// No attached-client clipboard route exists in this architecture.
    NoAttachedClientRoute,
}

/// Content-free error classification for attempt records and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeErrorKind {
    BackendUnavailable,
    WriteFailed,
    Timeout,
    Cancelled,
    TooLarge,
    Empty,
    SpawnFailed,
    ExitFailure,
    OutputCapExceeded,
    Unsupported,
    Ineligible,
}

/// Eligibility decision for one route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eligibility {
    Eligible,
    Skipped(SkipReason),
}

/// One ordered attempt record returned by the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptRecord {
    pub route: Route,
    pub eligibility: Eligibility,
    pub representation: Representation,
    pub outcome: AttemptOutcome,
    pub safe_error_kind: Option<SafeErrorKind>,
}

/// Full delivery result for recovery/feedback consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryResult {
    pub attempts: Vec<AttemptRecord>,
    pub requested_representation: Representation,
    pub delivered_representation: Representation,
    pub downgrade: Option<Downgrade>,
    pub confidence: Confidence,
}

impl DeliveryResult {
    /// True when any route confirmed or OSC52 was emitted (Unverified).
    pub fn delivered(&self) -> bool {
        !matches!(self.confidence, Confidence::Failed)
    }

    pub fn is_confirmed(&self) -> bool {
        matches!(self.confidence, Confidence::Confirmed)
    }

    pub fn is_unverified(&self) -> bool {
        matches!(self.confidence, Confidence::Unverified)
    }

    /// Map a hard failure into a content-free caller error.
    pub fn failure_error(&self) -> CopyError {
        if self.attempts.is_empty() {
            return CopyError::Empty;
        }
        if let Some(kind) = self.attempts.iter().find_map(|a| {
            a.safe_error_kind
                .filter(|_| a.outcome == AttemptOutcome::Failed)
        }) {
            return CopyError::from_safe(kind);
        }
        if self
            .attempts
            .iter()
            .all(|a| matches!(a.outcome, AttemptOutcome::Skipped))
        {
            return CopyError::NoEligibleRoute;
        }
        CopyError::Failed
    }
}

/// Pre-route or adapter-visible error surface for callers that still use
/// `Result`-style feedback. Never carries clipboard plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyError {
    Empty,
    TooLarge { max: usize },
    NoEligibleRoute,
    Failed,
    Backend,
    Timeout,
    Cancelled,
    Unsupported,
}

impl CopyError {
    fn from_safe(kind: SafeErrorKind) -> Self {
        match kind {
            SafeErrorKind::TooLarge => Self::TooLarge {
                max: cockpit_proto::terminal::OSC52_MAX_SEQUENCE_BYTES,
            },
            SafeErrorKind::Empty => Self::Empty,
            SafeErrorKind::Timeout => Self::Timeout,
            SafeErrorKind::Cancelled => Self::Cancelled,
            SafeErrorKind::Unsupported => Self::Unsupported,
            SafeErrorKind::BackendUnavailable
            | SafeErrorKind::WriteFailed
            | SafeErrorKind::SpawnFailed
            | SafeErrorKind::ExitFailure
            | SafeErrorKind::OutputCapExceeded
            | SafeErrorKind::Ineligible => Self::Backend,
        }
    }
}

impl std::fmt::Display for CopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "nothing to copy"),
            Self::TooLarge { max } => write!(
                f,
                "selection too large for clipboard delivery (max {max} sequence bytes)"
            ),
            Self::NoEligibleRoute => write!(f, "no eligible clipboard route"),
            Self::Failed => write!(f, "clipboard delivery failed"),
            Self::Backend => write!(f, "clipboard backend error"),
            Self::Timeout => write!(f, "clipboard backend timed out"),
            Self::Cancelled => write!(f, "clipboard delivery cancelled"),
            Self::Unsupported => write!(f, "clipboard operation unsupported"),
        }
    }
}

impl std::error::Error for CopyError {}

/// Copy request evaluated by the routing service.
#[derive(Debug, Clone)]
pub struct CopyRequest {
    pub plain: String,
    pub html: Option<String>,
    pub policy: RichPolicy,
    /// When true, after a primary route succeeds, run `tmux load-buffer`
    /// as an explicit mirror (never upgrades confidence).
    pub mirror_tmux_buffer: bool,
    /// Generation token; a newer generation cancels late fallback/mirrors.
    pub generation: u64,
}

impl CopyRequest {
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            plain: text.into(),
            html: None,
            policy: RichPolicy::Plain,
            mirror_tmux_buffer: false,
            generation: 0,
        }
    }

    pub fn rich(plain: impl Into<String>, html: impl Into<String>, policy: RichPolicy) -> Self {
        Self {
            plain: plain.into(),
            html: Some(html.into()),
            policy,
            mirror_tmux_buffer: false,
            generation: 0,
        }
    }
}

/// Session context that drives route eligibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    pub same_host_local_desktop: bool,
    pub ssh: bool,
    pub tmux: bool,
    pub trusted_remote_terminal: bool,
    pub untrusted_remote: bool,
    pub wsl_or_container: bool,
    pub host_bridge: bool,
    /// Terminal advertises OSC52 (same-host terminal path).
    pub osc52_advertised: bool,
    /// Separately tested capability: terminal acknowledges OSC52.
    pub osc52_acknowledged_capability: bool,
    /// Trusted tmux/terminal advertises DCS passthrough.
    pub osc52_tmux_passthrough: bool,
    pub platform: PlatformKind,
}

impl SessionContext {
    /// Probe production environment. Conservative: untrusted remote and
    /// host-bridge markers force desktop routes off.
    pub fn detect() -> Self {
        let ssh = cockpit_host::sysinfo::is_ssh();
        let tmux = std::env::var_os("TMUX").is_some();
        let wsl_or_container = detect_wsl_or_container();
        let host_bridge = detect_host_bridge();
        let untrusted_remote = ssh && wsl_or_container;
        // Authenticated SSH/tmux sessions are trusted for OSC52; plain local
        // terminals advertise OSC52 by default (terminals that ignore it
        // simply leave the chain at Unverified).
        let trusted_remote_terminal = ssh && !untrusted_remote;
        let same_host_local_desktop = !ssh && !wsl_or_container && !host_bridge;
        Self {
            same_host_local_desktop,
            ssh,
            tmux,
            trusted_remote_terminal,
            untrusted_remote,
            wsl_or_container,
            host_bridge,
            osc52_advertised: true,
            osc52_acknowledged_capability: false,
            osc52_tmux_passthrough: tmux,
            platform: PlatformKind::current(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformKind {
    Linux,
    MacOs,
    Windows,
    Other,
}

impl PlatformKind {
    pub fn current() -> Self {
        match std::env::consts::OS {
            "linux" => Self::Linux,
            "macos" => Self::MacOs,
            "windows" => Self::Windows,
            _ => Self::Other,
        }
    }
}

fn detect_wsl_or_container() -> bool {
    if std::env::var_os("WSL_DISTRO_NAME").is_some()
        || std::env::var_os("WSL_INTEROP").is_some()
        || std::env::var_os("WSLENV").is_some()
    {
        return true;
    }
    // Container markers — presence alone is enough to skip desktop routes.
    if std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
    {
        return true;
    }
    if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup")
        && (cgroup.contains("docker")
            || cgroup.contains("containerd")
            || cgroup.contains("kubepods"))
    {
        return true;
    }
    false
}

fn detect_host_bridge() -> bool {
    // WSLg host-mounted display bridge and similar remote desktop paths.
    if std::path::Path::new("/mnt/wslg").exists() {
        return true;
    }
    if let Ok(display) = std::env::var("DISPLAY") {
        // Hostname/TCP/localhost displays are never local held-socket paths.
        if display.contains(':') {
            let host = display.split(':').next().unwrap_or("");
            if !host.is_empty()
                && (host.eq_ignore_ascii_case("localhost")
                    || host == "127.0.0.1"
                    || host.contains('.'))
            {
                return true;
            }
        }
    }
    false
}
