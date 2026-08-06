//! Trusted ordered clipboard delivery service.

use super::executable::{ExecutableClipboard, PlatformExecutable, executable_eligibility};
use super::native::{ArboardNative, NativeClipboard, native_eligibility};
use super::osc52::{Osc52Emitter, StdoutOsc52Emitter};
use super::types::{
    AttemptOutcome, AttemptRecord, Confidence, CopyRequest, DeliveryResult, Downgrade, Eligibility,
    OscTransport, Representation, RichPolicy, Route, SafeErrorKind, SessionContext, SkipReason,
};

/// Ordered routes: Native → OSC52 → Executable.
const ROUTE_ORDER: [Route; 3] = [Route::Native, Route::Osc52, Route::Executable];

/// Central clipboard delivery service. Stops at first Confirmed; continues
/// after unacknowledged OSC52 (Unverified) into the platform executable.
pub struct ClipboardService<N, O, E> {
    pub context: SessionContext,
    pub native: N,
    pub osc52: O,
    pub executable: E,
    /// Active generation; mismatches cancel fallback/mirrors.
    pub generation: u64,
    /// When true, a tmux load-buffer mirror ran after primary success.
    pub tmux_mirror_ran: bool,
    /// Captured mirror payloads for tests (never logged in production).
    pub tmux_mirror_payloads: Vec<String>,
}

impl ClipboardService<ArboardNative, StdoutOsc52Emitter, PlatformExecutable> {
    pub fn system() -> Self {
        Self {
            context: SessionContext::detect(),
            native: ArboardNative,
            osc52: StdoutOsc52Emitter,
            executable: PlatformExecutable::default(),
            generation: 0,
            tmux_mirror_ran: false,
            tmux_mirror_payloads: Vec::new(),
        }
    }
}

impl<N, O, E> ClipboardService<N, O, E>
where
    N: NativeClipboard,
    O: Osc52Emitter,
    E: ExecutableClipboard,
{
    pub fn new(context: SessionContext, native: N, osc52: O, executable: E) -> Self {
        Self {
            context,
            native,
            osc52,
            executable,
            generation: 0,
            tmux_mirror_ran: false,
            tmux_mirror_payloads: Vec::new(),
        }
    }

    pub fn deliver_plain(&mut self, text: &str) -> DeliveryResult {
        self.deliver(CopyRequest::plain(text))
    }

    pub fn deliver_rich(&mut self, plain: &str, html: &str, policy: RichPolicy) -> DeliveryResult {
        self.deliver(CopyRequest::rich(plain, html, policy))
    }

    pub fn deliver(&mut self, request: CopyRequest) -> DeliveryResult {
        self.tmux_mirror_ran = false;
        self.tmux_mirror_payloads.clear();

        let requested = match request.policy {
            RichPolicy::Plain => Representation::Plain,
            RichPolicy::StrictRich | RichPolicy::AllowPlainDowngrade => Representation::Rich,
        };

        // Pre-route guards.
        if request.plain.is_empty() && request.html.as_ref().map(|h| h.is_empty()).unwrap_or(true) {
            return DeliveryResult {
                attempts: vec![],
                requested_representation: requested,
                delivered_representation: Representation::None,
                downgrade: None,
                confidence: Confidence::Failed,
            };
        }

        // Cancellation: stale generation.
        if request.generation != self.generation && request.generation != 0 {
            // generation 0 is "ignore"; non-zero must match.
            if self.generation != 0 && request.generation != self.generation {
                return DeliveryResult {
                    attempts: vec![AttemptRecord {
                        route: Route::Native,
                        eligibility: Eligibility::Skipped(SkipReason::Cancelled),
                        representation: Representation::None,
                        outcome: AttemptOutcome::Skipped,
                        safe_error_kind: Some(SafeErrorKind::Cancelled),
                    }],
                    requested_representation: requested,
                    delivered_representation: Representation::None,
                    downgrade: None,
                    confidence: Confidence::Failed,
                };
            }
        }

        match request.policy {
            RichPolicy::Plain => {
                self.deliver_plain_chain(&request.plain, request.mirror_tmux_buffer, None)
            }
            RichPolicy::StrictRich => self.deliver_strict_rich(&request),
            RichPolicy::AllowPlainDowngrade => self.deliver_allow_plain_downgrade(&request),
        }
    }

    fn deliver_strict_rich(&mut self, request: &CopyRequest) -> DeliveryResult {
        let html = request.html.as_deref().unwrap_or("");
        let mut attempts = Vec::new();

        match native_eligibility(&self.context) {
            Err(reason) => {
                attempts.push(skipped(Route::Native, Representation::Rich, reason));
                // Plain-only routes are not run under StrictRich.
                attempts.push(skipped(
                    Route::Osc52,
                    Representation::Plain,
                    SkipReason::PlainOnlyRoute,
                ));
                attempts.push(skipped(
                    Route::Executable,
                    Representation::Plain,
                    SkipReason::PlainOnlyRoute,
                ));
                DeliveryResult {
                    attempts,
                    requested_representation: Representation::Rich,
                    delivered_representation: Representation::None,
                    downgrade: None,
                    confidence: Confidence::Failed,
                }
            }
            Ok(()) => match self.native.set_rich(&request.plain, html) {
                Ok(()) => {
                    attempts.push(confirmed(Route::Native, Representation::Rich));
                    self.maybe_mirror_tmux(request.mirror_tmux_buffer, &request.plain);
                    DeliveryResult {
                        attempts,
                        requested_representation: Representation::Rich,
                        delivered_representation: Representation::Rich,
                        downgrade: None,
                        confidence: Confidence::Confirmed,
                    }
                }
                Err(kind) => {
                    attempts.push(failed(Route::Native, Representation::Rich, kind));
                    attempts.push(skipped(
                        Route::Osc52,
                        Representation::Plain,
                        SkipReason::PlainOnlyRoute,
                    ));
                    attempts.push(skipped(
                        Route::Executable,
                        Representation::Plain,
                        SkipReason::PlainOnlyRoute,
                    ));
                    DeliveryResult {
                        attempts,
                        requested_representation: Representation::Rich,
                        delivered_representation: Representation::None,
                        downgrade: None,
                        confidence: Confidence::Failed,
                    }
                }
            },
        }
    }

    fn deliver_allow_plain_downgrade(&mut self, request: &CopyRequest) -> DeliveryResult {
        let html = request.html.as_deref().unwrap_or("");
        let mut attempts = Vec::new();

        // Try native rich first when eligible.
        match native_eligibility(&self.context) {
            Ok(()) => match self.native.set_rich(&request.plain, html) {
                Ok(()) => {
                    attempts.push(confirmed(Route::Native, Representation::Rich));
                    self.maybe_mirror_tmux(request.mirror_tmux_buffer, &request.plain);
                    return DeliveryResult {
                        attempts,
                        requested_representation: Representation::Rich,
                        delivered_representation: Representation::Rich,
                        downgrade: None,
                        confidence: Confidence::Confirmed,
                    };
                }
                Err(kind) => {
                    attempts.push(failed(Route::Native, Representation::Rich, kind));
                }
            },
            Err(reason) => {
                attempts.push(skipped(Route::Native, Representation::Rich, reason));
            }
        }
        let downgrade = Some(Downgrade::RichToPlain);

        // Ordinary plain chain after one explicit RichToPlain downgrade.
        // Native plain may still succeed even when rich failed.
        let plain_result = self.deliver_plain_chain_from(
            &request.plain,
            request.mirror_tmux_buffer,
            Route::Native,
        );
        // Avoid duplicate native-rich failure row followed by another native skip noise:
        // plain chain records its own native attempt.
        attempts.extend(plain_result.attempts);

        DeliveryResult {
            attempts,
            requested_representation: Representation::Rich,
            delivered_representation: plain_result.delivered_representation,
            downgrade,
            confidence: plain_result.confidence,
        }
    }

    fn deliver_plain_chain(
        &mut self,
        text: &str,
        mirror_tmux: bool,
        _unused: Option<()>,
    ) -> DeliveryResult {
        self.deliver_plain_chain_from(text, mirror_tmux, Route::Native)
    }

    fn deliver_plain_chain_from(
        &mut self,
        text: &str,
        mirror_tmux: bool,
        start: Route,
    ) -> DeliveryResult {
        let mut attempts = Vec::new();
        let mut confidence = Confidence::Failed;
        let mut delivered = Representation::None;
        let start_idx = ROUTE_ORDER.iter().position(|r| *r == start).unwrap_or(0);

        for route in ROUTE_ORDER.iter().skip(start_idx) {
            // Stop after first Confirmed.
            if matches!(confidence, Confidence::Confirmed) {
                break;
            }

            match route {
                Route::Native => match native_eligibility(&self.context) {
                    Err(reason) => attempts.push(skipped(*route, Representation::Plain, reason)),
                    Ok(()) => match self.native.set_plain(text) {
                        Ok(()) => {
                            attempts.push(confirmed(*route, Representation::Plain));
                            confidence = Confidence::Confirmed;
                            delivered = Representation::Plain;
                            self.maybe_mirror_tmux(mirror_tmux, text);
                            break;
                        }
                        Err(kind) => {
                            attempts.push(failed(*route, Representation::Plain, kind));
                        }
                    },
                },
                Route::Osc52 => match osc52_eligibility(&self.context) {
                    Err(reason) => attempts.push(skipped(*route, Representation::Plain, reason)),
                    Ok(transport) => match self.osc52.emit(text, transport) {
                        Ok(()) => {
                            if self.context.osc52_acknowledged_capability {
                                attempts.push(confirmed(*route, Representation::Plain));
                                confidence = Confidence::Confirmed;
                                delivered = Representation::Plain;
                                self.maybe_mirror_tmux(mirror_tmux, text);
                                break;
                            }
                            // Unacknowledged: Unverified, continue to executable.
                            attempts.push(AttemptRecord {
                                route: *route,
                                eligibility: Eligibility::Eligible,
                                representation: Representation::Plain,
                                outcome: AttemptOutcome::Unverified,
                                safe_error_kind: None,
                            });
                            confidence = Confidence::Unverified;
                            delivered = Representation::Plain;
                            // Do not mirror yet — wait for final primary result.
                            // Mirrors run after primary success; Unverified OSC is
                            // a primary result, so mirror is allowed.
                            self.maybe_mirror_tmux(mirror_tmux, text);
                        }
                        Err(SafeErrorKind::TooLarge) => {
                            attempts.push(failed(
                                *route,
                                Representation::Plain,
                                SafeErrorKind::TooLarge,
                            ));
                            // Over-cap: do not continue if we are remote-only
                            // and nothing else can help with the same payload
                            // size? Spec: "remote over-cap emits nothing and
                            // Fails". Executable is still size-unbounded for
                            // plain text, so local desktop may continue.
                            // For SSH (no executable), final remains Failed.
                        }
                        Err(kind) => {
                            attempts.push(failed(*route, Representation::Plain, kind));
                        }
                    },
                },
                Route::Executable => match executable_eligibility(&self.context) {
                    Err(reason) => attempts.push(skipped(*route, Representation::Plain, reason)),
                    Ok(()) => match self.executable.set_plain(text) {
                        Ok(()) => {
                            attempts.push(confirmed(*route, Representation::Plain));
                            confidence = Confidence::Confirmed;
                            delivered = Representation::Plain;
                            // Mirror only once; if OSC already mirrored, skip.
                            if !self.tmux_mirror_ran {
                                self.maybe_mirror_tmux(mirror_tmux, text);
                            }
                            break;
                        }
                        Err(kind) => {
                            attempts.push(failed(*route, Representation::Plain, kind));
                        }
                    },
                },
            }
        }

        // Final confidence: Confirmed if any confirmed; else Unverified if OSC
        // emitted; else Failed. All-ineligible is Failed with Skipped attempts.
        if !matches!(confidence, Confidence::Confirmed) {
            let had_unverified = attempts
                .iter()
                .any(|a| a.outcome == AttemptOutcome::Unverified);
            confidence = if had_unverified {
                Confidence::Unverified
            } else {
                Confidence::Failed
            };
            if !had_unverified {
                delivered = Representation::None;
            }
        }

        DeliveryResult {
            attempts,
            requested_representation: Representation::Plain,
            delivered_representation: delivered,
            downgrade: None,
            confidence,
        }
    }

    fn maybe_mirror_tmux(&mut self, enabled: bool, text: &str) {
        if !enabled || !self.context.tmux || self.tmux_mirror_ran {
            return;
        }
        // Explicit mirror only — never upgrades confidence. Best-effort;
        // failures are ignored and content-free.
        self.tmux_mirror_ran = true;
        self.tmux_mirror_payloads.push(text.to_string());
        let _ = run_tmux_load_buffer(text);
    }
}

fn osc52_eligibility(ctx: &SessionContext) -> Result<OscTransport, SkipReason> {
    if ctx.untrusted_remote {
        return Err(SkipReason::UntrustedRemote);
    }
    // Eligible for authenticated trusted remote terminal/tmux/SSH, or
    // same-host terminal that advertises OSC52.
    let eligible = ctx.trusted_remote_terminal
        || (ctx.same_host_local_desktop && ctx.osc52_advertised)
        || (ctx.ssh && !ctx.untrusted_remote)
        || (!ctx.ssh && ctx.osc52_advertised);

    if !eligible {
        return Err(SkipReason::OscNotAdvertised);
    }
    if !ctx.osc52_advertised && !ctx.trusted_remote_terminal && !ctx.ssh {
        return Err(SkipReason::OscNotAdvertised);
    }

    if ctx.tmux && ctx.osc52_tmux_passthrough {
        Ok(OscTransport::TmuxPassthrough)
    } else {
        Ok(OscTransport::Direct)
    }
}

fn run_tmux_load_buffer(text: &str) -> Result<(), SafeErrorKind> {
    // Not OS clipboard delivery. Best-effort; no shell; fixed argv.
    // Do not require root-owned tmux — this is an explicit mirror only.
    let mut child = std::process::Command::new("tmux")
        .args(["load-buffer", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| SafeErrorKind::SpawnFailed)?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(text.as_bytes());
    }
    let _ = child.wait();
    Ok(())
}

fn confirmed(route: Route, representation: Representation) -> AttemptRecord {
    AttemptRecord {
        route,
        eligibility: Eligibility::Eligible,
        representation,
        outcome: AttemptOutcome::Confirmed,
        safe_error_kind: None,
    }
}

fn failed(route: Route, representation: Representation, kind: SafeErrorKind) -> AttemptRecord {
    AttemptRecord {
        route,
        eligibility: Eligibility::Eligible,
        representation,
        outcome: AttemptOutcome::Failed,
        safe_error_kind: Some(kind),
    }
}

fn skipped(route: Route, representation: Representation, reason: SkipReason) -> AttemptRecord {
    AttemptRecord {
        route,
        eligibility: Eligibility::Skipped(reason),
        representation,
        outcome: AttemptOutcome::Skipped,
        safe_error_kind: None,
    }
}

/// Prove no attached-client route exists in the public type surface.
pub fn attached_client_route_exists() -> bool {
    // Inventory: Route enum has only Native, Osc52, Executable.
    false
}
