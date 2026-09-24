use super::*;
use cockpit_config::providers::AuthKind;

#[cfg(test)]
mod tests {
    #[tokio::test(flavor = "current_thread")]
    async fn coverage_phases_complete_before_the_first_correct_paint() {
        let namespace = tempfile::tempdir().expect("isolated startup trace root");
        let workspace = namespace.path().join("workspace");
        let runtime = namespace.path().join("runtime");
        std::fs::create_dir_all(&workspace).expect("workspace fixture");
        std::fs::create_dir_all(&runtime).expect("runtime fixture");
        let trace = crate::tui::app::startup_first_paint_tests::run_startup_trace_case(
            &workspace, &runtime, false, true,
        )
        .await;

        let mut cursor = 0usize;
        // The first paint waits for the daemon's onboarding (and workspace)
        // answer, so the daemon's coverage phases precede it.
        for event in [
            "coverage-phase-start",
            "coverage-phase-complete",
            "daemon-ready",
            "first-model-request",
            "first-paint",
        ] {
            let relative = trace[cursor..]
                .find(event)
                .unwrap_or_else(|| panic!("missing `{event}` in startup trace: {trace}"));
            cursor += relative + event.len();
        }
        assert!(trace.contains("scope_class=\"daemon_global\""));
        assert!(trace.contains("correlation=\"opaque-test-correlation\""));
        for forbidden in ["candidate", "matcher", "fingerprint", "source_inventory"] {
            assert!(!trace.contains(forbidden), "trace exposed {forbidden}");
        }
    }
}

fn onboarding_ready_construction_retry_required(error: &cockpit_proto::ErrorPayload) -> bool {
    error.code == cockpit_proto::ErrorCode::Internal
        && error.message.contains("retry ready construction")
}

/// How long the pre-screen startup may run silently before it prints its one
/// "Starting cockpit…" line on the normal terminal.
pub(super) const STARTING_NOTICE_DELAY: std::time::Duration = std::time::Duration::from_millis(300);

/// Upper bound for deciding the first screen before paint. Generous: it
/// covers a cold daemon spawn (the lifecycle request budget) plus the
/// onboarding and workspace reads. Past it the TUI opens anyway.
pub(super) const FIRST_SCREEN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(90);

/// The one-line pre-screen notice. Production writes to the normal terminal
/// (before the alternate screen exists); tests record the calls.
pub(super) trait StartupNotice {
    fn show(&mut self);
    fn clear(&mut self);
}

/// `Starting cockpit…` on the normal terminal, erased again before the
/// alternate screen is entered so it never lingers in scrollback.
pub(super) struct TerminalStartupNotice;

pub(super) const STARTING_NOTICE_TEXT: &str = "Starting cockpit…";

impl StartupNotice for TerminalStartupNotice {
    fn show(&mut self) {
        use std::io::Write as _;
        let mut out = std::io::stdout();
        let _ = write!(out, "{STARTING_NOTICE_TEXT}");
        let _ = out.flush();
    }

    fn clear(&mut self) {
        use std::io::Write as _;
        let mut out = std::io::stdout();
        let _ = write!(out, "\r\x1b[2K");
        let _ = out.flush();
    }
}

/// Upper bound for one onboarding authority operation to reach a serving
/// daemon across a handoff: a worker roll after a config write, or the
/// daemon-owned ready construction after the secure-store choice commits
/// (redaction source capture plus journal recovery, seconds on a large
/// checkout). Generous by design: a locked owner reports its own progress in
/// every hello (`ready_construction`), so this only bounds a daemon that has
/// stopped making progress; it is not a transport-luck retry budget.
pub(super) const ONBOARDING_HANDOFF_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(180);
const ONBOARDING_HANDOFF_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// `{error:#}`: the whole cause chain (e.g. the ENOENT behind "connecting to
/// …/cockpit.sock"), never just the outermost context.
fn error_chain(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

/// A daemon rejection that is resolved by re-sending the same request once
/// the handoff completes: the documented `RetryLater` code (a locked owner
/// refusing a mutation while its ready construction runs), or the client's
/// pre-request hello timeout, which evaluated no daemon operation at all.
fn onboarding_request_retryable(error: &cockpit_proto::ErrorPayload) -> bool {
    error.code == cockpit_proto::ErrorCode::RetryLater
        || error.message.contains("daemon hello timed out")
}

/// What an in-flight secure-store submission is waiting on, for the screen's
/// progress line. Written by the async operation, read at render time.
#[derive(Clone, Debug, Default)]
pub(crate) struct OnboardingHandoffProgress {
    phase: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OnboardingHandoffPhase {
    /// The secure-store choice is being applied.
    Submitting,
    /// The choice committed; the daemon is building its ready services.
    PreparingServices,
    /// The daemon connection dropped; re-attaching or confirming the outcome.
    Reconnecting,
}

impl OnboardingHandoffProgress {
    pub(crate) fn set(&self, phase: OnboardingHandoffPhase) {
        self.phase
            .store(phase as u8, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn get(&self) -> OnboardingHandoffPhase {
        match self.phase.load(std::sync::atomic::Ordering::Acquire) {
            1 => OnboardingHandoffPhase::PreparingServices,
            2 => OnboardingHandoffPhase::Reconnecting,
            _ => OnboardingHandoffPhase::Submitting,
        }
    }
}

/// Whether the daemon behind a connection is serving ready services or is a
/// locked first-run owner, and then in which ready-construction phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OnboardingDaemonPhase {
    Ready,
    Locked(cockpit_proto::LockedReadyConstruction),
}

pub(super) async fn onboarding_daemon_phase(
    client: &cockpit_client::DaemonClient,
) -> Result<OnboardingDaemonPhase, String> {
    match client
        .request(cockpit_proto::Request::DaemonStatus)
        .await
        .map_err(|error| error_chain(&error))?
    {
        Ok(cockpit_proto::Response::DaemonStatus { .. }) => Ok(OnboardingDaemonPhase::Ready),
        Ok(cockpit_proto::Response::LockedBootstrapHello(hello)) => {
            Ok(OnboardingDaemonPhase::Locked(hello.ready_construction))
        }
        Ok(other) => Err(format!("unexpected daemon status response: {other:?}")),
        Err(error) => Err(error.to_string()),
    }
}

/// Resolve the daemon endpoint for an onboarding authority operation. The
/// startup machine's resolved lifecycle endpoint is used when present;
/// otherwise the app's lifecycle client resolves it — the same funnel the
/// settings surfaces use. An onboarding request is never silently dropped
/// because the startup machine has not pinned its selection yet.
async fn onboarding_authority_endpoint(
    lifecycle: &cockpit_client::LifecycleClient,
    selected_endpoint: Option<&cockpit_client::ClientEndpoint>,
) -> Result<cockpit_client::ClientEndpoint, String> {
    match selected_endpoint {
        Some(endpoint) => Ok(endpoint.clone()),
        None => lifecycle
            .resolve_default()
            .await
            .map(|resolved| resolved.endpoint)
            .map_err(|error| error.to_string()),
    }
}

/// Reconnect a transition after a config write hands ownership to a new
/// daemon worker. The request ID is deliberately preserved: a response lost
/// during the handoff must replay the same daemon operation, never advance a
/// second revision.
async fn apply_onboarding_transition_after_handoff(
    lifecycle: &cockpit_client::LifecycleClient,
    selected_endpoint: Option<&cockpit_client::ClientEndpoint>,
    request: cockpit_proto::ApplyOnboardingTransition,
) -> Result<
    (
        cockpit_proto::OnboardingTransitionResult,
        cockpit_client::DaemonClient,
    ),
    String,
> {
    match onboarding_request_after_handoff(
        lifecycle,
        selected_endpoint,
        cockpit_proto::Request::ApplyOnboardingTransition(request),
    )
    .await?
    {
        (cockpit_proto::Response::OnboardingTransition(result), client) => Ok((result, client)),
        (other, _) => Err(format!("unexpected onboarding response: {other:?}")),
    }
}

/// The single onboarding request funnel across a daemon handoff. Transport
/// failures (no socket yet, a hello that has not been answered, a connection
/// closed by a retiring owner) and self-resolving refusals are retried until
/// [`ONBOARDING_HANDOFF_DEADLINE`]; any other daemon rejection returns at
/// once. The request is re-sent unchanged, so its client operation id makes a
/// replay after a lost response idempotent.
async fn onboarding_request_after_handoff(
    lifecycle: &cockpit_client::LifecycleClient,
    selected_endpoint: Option<&cockpit_client::ClientEndpoint>,
    request: cockpit_proto::Request,
) -> Result<(cockpit_proto::Response, cockpit_client::DaemonClient), String> {
    let deadline = tokio::time::Instant::now() + ONBOARDING_HANDOFF_DEADLINE;
    let mut last_transient;
    loop {
        match onboarding_authority_endpoint(lifecycle, selected_endpoint).await {
            Err(error) => last_transient = error,
            Ok(endpoint) => match cockpit_client::DaemonClient::connect_endpoint(&endpoint).await {
                Err(error) => last_transient = error_chain(&error),
                Ok(client) => match client.request(request.clone()).await {
                    Ok(Ok(response)) => return Ok((response, client)),
                    Ok(Err(error)) if onboarding_request_retryable(&error) => {
                        last_transient = error.to_string();
                    }
                    Ok(Err(error)) => return Err(error.to_string()),
                    Err(error) => last_transient = error_chain(&error),
                },
            },
        }
        if tokio::time::Instant::now() + ONBOARDING_HANDOFF_POLL >= deadline {
            return Err(format!(
                "the Cockpit daemon did not become available within {}s: {last_transient}",
                ONBOARDING_HANDOFF_DEADLINE.as_secs()
            ));
        }
        tokio::time::sleep(ONBOARDING_HANDOFF_POLL).await;
    }
}

async fn fetch_onboarding_provider_models(
    client: &cockpit_client::DaemonClient,
    project_root: &str,
    provider_id: &str,
) -> Result<(crate::tui::onboarding::VerifyOutcome, u64), String> {
    use cockpit_proto::{ProviderModelFetchOutcome, Request, Response};
    let response = client
        .request(Request::FetchProviderModels {
            project_root: project_root.to_string(),
            provider_id: Some(provider_id.to_string()),
            model_id: None,
            deep: false,
            on_unlisted: Some(cockpit_config::config::providers::OnUnlistedModelsFetch::Keep),
            allow_fallback: false,
        })
        .await
        .map_err(|error| error_chain(&error))?
        .map_err(|error| error.to_string())?;
    let Response::ProviderModelsFetched {
        mut results,
        config_generation,
        ..
    } = response
    else {
        return Err("daemon returned the wrong provider verification response".into());
    };
    let result = results
        .pop()
        .ok_or_else(|| "daemon returned no provider verification result".to_string())?;
    if let Some(verification) = result.verification {
        let outcome = match verification {
            cockpit_proto::ProviderModelVerification::NoEndpoint => {
                crate::tui::onboarding::VerifyOutcome::NoEndpoint
            }
            cockpit_proto::ProviderModelVerification::Unauthorized { status } => {
                crate::tui::onboarding::VerifyOutcome::Unauthorized(status)
            }
            cockpit_proto::ProviderModelVerification::NotFound => {
                crate::tui::onboarding::VerifyOutcome::NotFound
            }
            cockpit_proto::ProviderModelVerification::HttpStatus { status, snippet } => {
                crate::tui::onboarding::VerifyOutcome::HttpStatus { status, snippet }
            }
            cockpit_proto::ProviderModelVerification::Network { message } => {
                crate::tui::onboarding::VerifyOutcome::Network(message)
            }
            cockpit_proto::ProviderModelVerification::Parse { message } => {
                crate::tui::onboarding::VerifyOutcome::Parse(message)
            }
        };
        return Ok((outcome, config_generation));
    }
    let outcome = match result.outcome {
        ProviderModelFetchOutcome::Models { models, .. }
        | ProviderModelFetchOutcome::FallbackAvailable { models, .. } => {
            crate::tui::onboarding::VerifyOutcome::Models(
                models.into_iter().map(|model| model.id).collect(),
            )
        }
        ProviderModelFetchOutcome::Unsupported => crate::tui::onboarding::VerifyOutcome::NoEndpoint,
        ProviderModelFetchOutcome::UnlistedModelsPreview { .. } => {
            crate::tui::onboarding::VerifyOutcome::Parse(
                "the fetched catalog requires an unlisted-model decision".into(),
            )
        }
        ProviderModelFetchOutcome::Error { .. } => {
            return Err("daemon omitted provider verification categorization".into());
        }
    };
    Ok((outcome, config_generation))
}

/// Outcome of waiting for ready services.
enum OnboardingReadyWait {
    Ready(cockpit_client::DaemonClient),
    /// A locked owner reports that construction failed; the client is a
    /// connection to that locked owner (the only place a retry is valid).
    ConstructionFailed(cockpit_client::DaemonClient),
}

/// Wait on the daemon's explicit readiness signal: a locked owner answers
/// every hello with its `ready_construction` phase while it builds ready
/// services, and ready services answer status as a ready daemon. A locked
/// connection is closed when ready services take ownership; that, a hello
/// not yet answered, or a missing socket is a transient reconnect, bounded by
/// [`ONBOARDING_HANDOFF_DEADLINE`] rather than a fixed attempt count.
async fn wait_for_ready_onboarding_daemon(
    lifecycle: &cockpit_client::LifecycleClient,
    selected_endpoint: Option<&cockpit_client::ClientEndpoint>,
    progress: &OnboardingHandoffProgress,
) -> Result<OnboardingReadyWait, String> {
    let deadline = tokio::time::Instant::now() + ONBOARDING_HANDOFF_DEADLINE;
    let mut held: Option<cockpit_client::DaemonClient> = None;
    let mut last_transient = String::from("the daemon has not answered yet");
    loop {
        if held.is_none() {
            match onboarding_authority_endpoint(lifecycle, selected_endpoint).await {
                Err(error) => last_transient = error,
                Ok(endpoint) => {
                    match cockpit_client::DaemonClient::connect_endpoint(&endpoint).await {
                        Ok(client) => held = Some(client),
                        Err(error) => last_transient = error_chain(&error),
                    }
                }
            }
        }
        if let Some(client) = held.as_ref() {
            match onboarding_daemon_phase(client).await {
                Ok(OnboardingDaemonPhase::Ready) => {
                    let client = held.take().expect("held ready client");
                    return Ok(OnboardingReadyWait::Ready(client));
                }
                Ok(OnboardingDaemonPhase::Locked(
                    cockpit_proto::LockedReadyConstruction::Constructing,
                )) => progress.set(OnboardingHandoffPhase::PreparingServices),
                Ok(OnboardingDaemonPhase::Locked(
                    cockpit_proto::LockedReadyConstruction::Failed,
                )) => {
                    let client = held.take().expect("held locked client");
                    return Ok(OnboardingReadyWait::ConstructionFailed(client));
                }
                Ok(OnboardingDaemonPhase::Locked(
                    cockpit_proto::LockedReadyConstruction::AwaitingSecureStore,
                )) => {
                    return Err(
                        "the Cockpit daemon has no committed secure store; choose it again".into(),
                    );
                }
                Err(error) => {
                    held = None;
                    last_transient = error;
                    progress.set(OnboardingHandoffPhase::Reconnecting);
                }
            }
        }
        if tokio::time::Instant::now() + ONBOARDING_HANDOFF_POLL >= deadline {
            return Err(format!(
                "Cockpit did not finish preparing its services within {}s: {last_transient}",
                ONBOARDING_HANDOFF_DEADLINE.as_secs()
            ));
        }
        tokio::time::sleep(ONBOARDING_HANDOFF_POLL).await;
    }
}

/// Wait until the daemon serves ready services and return a retained ready
/// connection. A construction the locked owner reports as failed is retried
/// at most once per call, and only through that locked owner: a ready daemon
/// never receives `retry_onboarding_ready_construction`.
async fn await_onboarding_ready_services(
    lifecycle: &cockpit_client::LifecycleClient,
    selected_endpoint: Option<&cockpit_client::ClientEndpoint>,
    progress: &OnboardingHandoffProgress,
) -> Result<cockpit_client::DaemonClient, String> {
    let mut retried = false;
    loop {
        match wait_for_ready_onboarding_daemon(lifecycle, selected_endpoint, progress).await? {
            OnboardingReadyWait::Ready(client) => return Ok(client),
            OnboardingReadyWait::ConstructionFailed(_) if retried => {
                return Err(
                    "Cockpit could not finish preparing its services after the secure store was set up; see daemon.log".into(),
                );
            }
            OnboardingReadyWait::ConstructionFailed(locked) => {
                retried = true;
                progress.set(OnboardingHandoffPhase::PreparingServices);
                match locked
                    .retry_onboarding_ready_construction()
                    .await
                    .map_err(|error| error_chain(&error))?
                {
                    Ok(_) => {}
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
    }
}

/// The authoritative snapshot from a ready daemon. A ready daemon clears a
/// stale `failed` checkpoint when it boots, so one that still reports it is a
/// daemon-side fault: surfaced, never answered with a retry (the retry is a
/// locked-owner operation and would only loop).
async fn ready_onboarding_snapshot(
    client: &cockpit_client::DaemonClient,
) -> Result<Option<cockpit_proto::OnboardingBootstrapSnapshot>, String> {
    let snapshot = match client
        .request(cockpit_proto::Request::GetOnboardingBootstrapSnapshot)
        .await
        .map_err(|error| error_chain(&error))?
    {
        Ok(cockpit_proto::Response::OnboardingBootstrapSnapshot(snapshot)) => snapshot,
        Ok(other) => return Err(format!("unexpected onboarding response: {other:?}")),
        Err(error) => return Err(error.to_string()),
    };
    if snapshot.as_ref().is_some_and(|snapshot| {
        snapshot.bootstrap_state == cockpit_proto::OnboardingBootstrapState::Failed
    }) {
        return Err(
            "the ready daemon still reports a failed setup checkpoint; run `cockpit daemon restart`"
                .into(),
        );
    }
    Ok(snapshot)
}

/// Resolve a `failed` ready-construction checkpoint observed on `client`.
/// Phase-aware: a locked owner that reports `failed` gets the retry and is
/// waited on; a ready daemon is never asked to retry (its answer is simply
/// the authoritative snapshot).
pub(super) async fn resolve_failed_ready_construction(
    lifecycle: &cockpit_client::LifecycleClient,
    selected_endpoint: Option<&cockpit_client::ClientEndpoint>,
    client: cockpit_client::DaemonClient,
) -> Result<
    (
        Option<cockpit_proto::OnboardingBootstrapSnapshot>,
        cockpit_client::DaemonClient,
    ),
    String,
> {
    let client = match onboarding_daemon_phase(&client).await? {
        OnboardingDaemonPhase::Ready => client,
        OnboardingDaemonPhase::Locked(_) => {
            drop(client);
            await_onboarding_ready_services(
                lifecycle,
                selected_endpoint,
                &OnboardingHandoffProgress::default(),
            )
            .await?
        }
    };
    let snapshot = ready_onboarding_snapshot(&client).await?;
    Ok((snapshot, client))
}

/// Reconcile a secure-store submission whose response was lost from the
/// daemon's durable receipt for the exact client operation id. The intent is
/// never re-sent: a committed receipt is the outcome.
async fn committed_secure_intent_receipt(
    lifecycle: &cockpit_client::LifecycleClient,
    selected_endpoint: Option<&cockpit_client::ClientEndpoint>,
    query: cockpit_proto::OnboardingReceiptQuery,
) -> Result<Option<cockpit_proto::OnboardingTransitionReceipt>, String> {
    match onboarding_request_after_handoff(
        lifecycle,
        selected_endpoint,
        cockpit_proto::Request::GetOnboardingTransitionReceipt(query),
    )
    .await?
    {
        (cockpit_proto::Response::OnboardingTransitionReceipt(receipt), _) => Ok(receipt
            .filter(|receipt| receipt.status == cockpit_proto::OnboardingReceiptStatus::Committed)),
        (other, _) => Err(format!("unexpected onboarding receipt response: {other:?}")),
    }
}

async fn onboarding_snapshot_after_secure_intent(
    lifecycle: &cockpit_client::LifecycleClient,
    selected_endpoint: Option<&cockpit_client::ClientEndpoint>,
    request: cockpit_proto::ApplyOnboardingSecureIntent,
    progress: OnboardingHandoffProgress,
) -> Result<
    (
        Option<cockpit_proto::OnboardingBootstrapSnapshot>,
        Option<cockpit_proto::OnboardingTransitionReceipt>,
        cockpit_client::DaemonClient,
    ),
    String,
> {
    progress.set(OnboardingHandoffPhase::Submitting);
    let endpoint = onboarding_authority_endpoint(lifecycle, selected_endpoint).await?;
    let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
        .await
        .map_err(|error| error_chain(&error))?;
    let receipt_query = cockpit_proto::OnboardingReceiptQuery {
        run_id: request.run_id,
        attempt_id: request.attempt_id,
        client_operation_id: request.client_operation_id.clone(),
    };
    let committed = match client
        .apply_onboarding_secure_intent(&endpoint, request)
        .await
    {
        Ok(Ok(result)) => Some(result.receipt),
        // The vault committed but construction could not start; the
        // readiness wait below sees the locked owner's `failed` phase and
        // retries it there.
        Ok(Err(error)) if onboarding_ready_construction_retry_required(&error) => None,
        Ok(Err(error)) => return Err(error.to_string()),
        // The frame may have been delivered and committed before the
        // transport failed: the outcome is uncertain, so it is reconciled
        // from the durable receipt, never by sending a second intent.
        Err(error) => {
            progress.set(OnboardingHandoffPhase::Reconnecting);
            match committed_secure_intent_receipt(
                lifecycle,
                selected_endpoint,
                receipt_query.clone(),
            )
            .await?
            {
                Some(receipt) => Some(receipt),
                None => return Err(error_chain(&error)),
            }
        }
    };
    drop(client);
    progress.set(OnboardingHandoffPhase::PreparingServices);
    let ready_client =
        await_onboarding_ready_services(lifecycle, selected_endpoint, &progress).await?;
    let receipt = match committed {
        Some(receipt) => receipt,
        None => match ready_client
            .request(cockpit_proto::Request::GetOnboardingTransitionReceipt(
                receipt_query,
            ))
            .await
            .map_err(|error| error_chain(&error))?
        {
            Ok(cockpit_proto::Response::OnboardingTransitionReceipt(Some(receipt))) => receipt,
            Ok(cockpit_proto::Response::OnboardingTransitionReceipt(None)) => {
                return Err("secure onboarding receipt is unavailable".to_string());
            }
            Ok(other) => {
                return Err(format!("unexpected onboarding receipt response: {other:?}"));
            }
            Err(error) => return Err(error.to_string()),
        },
    };
    let snapshot = ready_onboarding_snapshot(&ready_client).await?;
    Ok((snapshot, Some(receipt), ready_client))
}

impl App {
    pub(super) fn mark_startup_trace_milestone(&mut self, event: &'static str) -> bool {
        self.startup_background.trace_milestones.insert(event)
    }

    pub(super) fn start_startup_lifecycle_resolution(&mut self) {
        let generation = self.startup_background.generation;
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::Internal("startup.lifecycle"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("startup.lifecycle"),
            ),
            async move {
                let result = lifecycle.resolve_default().await.map(Into::into);
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupLifecycleResolved {
                        generation,
                        result,
                    },
                )
            },
        );
    }

    pub fn configure_onboarding_launch(&mut self, skip: bool, force: bool) {
        self.configure_onboarding_launch_with_setup_wizard(skip, force, None, None);
    }

    pub fn configure_onboarding_launch_with_setup_wizard(
        &mut self,
        skip: bool,
        force: bool,
        setup_wizard: Option<String>,
        provider_add_template: Option<String>,
    ) {
        self.onboarding_skip = skip;
        self.onboarding_force = force;
        self.pending_setup_wizard = setup_wizard;
        self.pending_provider_add_template = provider_add_template;
        if skip {
            self.onboarding_snapshot = None;
            self.onboarding_shell = None;
            self.dialog = crate::tui::settings::Dialog::None;
        }
    }

    /// After a committed authored-agent apply, the daemon publishes sidecar
    /// config and bumps the inventory generation. Keep the held snapshot in
    /// sync so onboarding settlement fences match the authority.
    pub(super) fn sync_config_generation_after_authored_agent_apply(&mut self, generation: u64) {
        self.config_snapshot.generation = self.config_snapshot.generation.max(generation);
        self.config_snapshot
            .providers
            .set_resolution_generation(self.config_snapshot.generation);
    }

    fn onboarding_agent_operation_id_for_attempt(attempt_id: uuid::Uuid) -> String {
        format!("onboarding-agent-{attempt_id}")
    }

    fn require_onboarding_snapshot_for_named_route(&mut self, wizard_id: &str) -> bool {
        if self.onboarding_snapshot.is_some() {
            return true;
        }
        self.pending_setup_wizard = Some(wizard_id.to_string());
        self.start_onboarding_bootstrap_fetch();
        false
    }

    fn snapshot_matches_named_wizard_stage(
        wizard_id: &str,
        stage: cockpit_proto::OnboardingStage,
    ) -> bool {
        if cockpit_core::wizard::named_setup_wizard_allows_complete_stage(wizard_id)
            && stage == cockpit_proto::OnboardingStage::Complete
        {
            return true;
        }
        cockpit_core::wizard::named_setup_wizard_authoritative_stage(wizard_id)
            .map(|required| stage == required)
            .unwrap_or(false)
    }

    fn focus_named_setup_wizard(&mut self, wizard_id: &str) -> bool {
        let snapshot = self
            .onboarding_snapshot
            .clone()
            .expect("named setup wizard routes require an authoritative onboarding snapshot");
        if !Self::snapshot_matches_named_wizard_stage(wizard_id, snapshot.stage) {
            if snapshot.stage == cockpit_proto::OnboardingStage::Complete {
                self.push_plain(format!(
                    "`{wizard_id}` requires an active onboarding run at its authoritative stage."
                ));
                return false;
            }
            self.reopen_onboarding_shell(&snapshot);
            return false;
        }
        true
    }

    fn maybe_open_pending_setup_wizard(&mut self) {
        if !self.startup_background.workspace_ready {
            return;
        }
        if let Some(wizard) = self.pending_setup_wizard.take() {
            let template = self.pending_provider_add_template.take();
            self.open_onboarding_setup(Some(&wizard));
            if wizard == cockpit_core::wizard::PROVIDER_WIZARD_ID {
                self.maybe_seed_pending_provider_template(template);
            }
        }
    }

    fn maybe_seed_pending_provider_template(&mut self, template: Option<String>) {
        let Some(template_id) = template else {
            return;
        };
        let template = cockpit_core::providers::template_by_id(&template_id).or_else(|| {
            self.push_plain(format!(
                "Unknown provider template `{template_id}`; pick one from the catalog."
            ));
            None
        });
        if template.is_none() {
            return;
        }
        let template = template.unwrap();
        if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.present_authenticate(template);
        }
    }

    /// Route `/setup` and equivalent interactive onboarding entrypoints through
    /// the full-screen shell instead of the legacy settings-modal wizards.
    pub(super) fn open_onboarding_setup(&mut self, wizard_id: Option<&str>) {
        if self.onboarding_skip {
            self.push_plain("Onboarding is skipped for this launch (`--skip-setup`).");
            return;
        }
        self.onboarding_dismissed = false;
        self.onboarding_force = wizard_id.is_none();
        match wizard_id {
            None => {
                if self.onboarding_shell.is_none() {
                    if let Some(snapshot) = self.onboarding_snapshot.clone() {
                        self.reopen_onboarding_shell(&snapshot);
                    } else {
                        self.start_onboarding_bootstrap_fetch();
                    }
                }
            }
            Some(cockpit_core::wizard::PROVIDER_WIZARD_ID) => {
                if !self.require_onboarding_snapshot_for_named_route(
                    cockpit_core::wizard::PROVIDER_WIZARD_ID,
                ) {
                    return;
                }
                if self.onboarding_snapshot.as_ref().is_some_and(|snapshot| {
                    snapshot.stage == cockpit_proto::OnboardingStage::Complete
                }) {
                    let snapshot = self.onboarding_snapshot.clone().expect(
                        "named provider route requires an authoritative onboarding snapshot",
                    );
                    if self.onboarding_shell.is_none() {
                        self.onboarding_shell =
                            Some(Box::new(crate::tui::onboarding::OnboardingShell::new(
                                &snapshot,
                                crate::tui::onboarding::reduced_motion_enabled(),
                            )));
                        if let Some(shell) = self.onboarding_shell.as_mut() {
                            shell.present_completion("Cockpit is ready.".to_string());
                            shell.begin_completion_provider_detour(None);
                        }
                    } else if let Some(shell) = self.onboarding_shell.as_mut() {
                        shell.begin_completion_provider_detour(None);
                    }
                } else if self
                    .onboarding_shell
                    .as_ref()
                    .is_some_and(|shell| shell.stage() == cockpit_proto::OnboardingStage::Complete)
                {
                    self.refresh_bootstrap_config_snapshot();
                    if let Some(shell) = self.onboarding_shell.as_mut() {
                        shell.return_to_completion();
                    }
                } else {
                    let snapshot = self.onboarding_snapshot.clone().expect(
                        "named provider route requires an authoritative onboarding snapshot",
                    );
                    self.reopen_onboarding_shell(&snapshot);
                }
            }
            Some(cockpit_core::wizard::SECURITY_WIZARD_ID) => {
                if !self.require_onboarding_snapshot_for_named_route(
                    cockpit_core::wizard::SECURITY_WIZARD_ID,
                ) {
                    return;
                }
                if !self.focus_named_setup_wizard(cockpit_core::wizard::SECURITY_WIZARD_ID) {
                    return;
                }
                self.mount_named_setup_wizard_in_onboarding_shell(
                    cockpit_core::wizard::SECURITY_WIZARD_ID,
                    None,
                );
            }
            Some(cockpit_core::wizard::MODEL_WIZARD_ID) => {
                if !self.require_onboarding_snapshot_for_named_route(
                    cockpit_core::wizard::MODEL_WIZARD_ID,
                ) {
                    return;
                }
                if !self.focus_named_setup_wizard(cockpit_core::wizard::MODEL_WIZARD_ID) {
                    return;
                }
                self.mount_named_setup_wizard_in_onboarding_shell(
                    cockpit_core::wizard::MODEL_WIZARD_ID,
                    None,
                );
            }
            Some(other) => {
                self.push_plain(format!(
                    "Unknown setup wizard `{other}`; run `/setup` to list named wizards."
                ));
            }
        }
    }

    fn mount_named_setup_wizard_in_onboarding_shell(
        &mut self,
        wizard_id: &str,
        preselected_model: Option<(&str, &str)>,
    ) {
        let snapshot = self
            .onboarding_snapshot
            .clone()
            .expect("named setup wizard routes require an authoritative onboarding snapshot");
        if self.onboarding_shell.is_none() {
            self.onboarding_shell = Some(Box::new(crate::tui::onboarding::OnboardingShell::new(
                &snapshot,
                crate::tui::onboarding::reduced_motion_enabled(),
            )));
        }
        match Dialog::shell_setup_wizard_engine(wizard_id, preselected_model, None) {
            Ok(dialog) => {
                self.dialog = dialog;
                if let Some(shell) = self.onboarding_shell.as_mut() {
                    shell.present_embedded_settings();
                }
            }
            Err(error) => self.show_toast(error, super::ToastKind::Error),
        }
    }

    pub(super) fn start_onboarding_bootstrap_fetch(&mut self) {
        let generation = self.startup_background.generation;
        let force = self.onboarding_force;
        let skip = self.onboarding_skip;
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let request_id = uuid::Uuid::new_v4().to_string();
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.bootstrap"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.bootstrap"),
            ),
            async move {
                let bootstrap_request_id = request_id.clone();
                let endpoint =
                    match onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref())
                        .await
                    {
                        Ok(endpoint) => endpoint,
                        Err(error) => {
                            return Ok(
                                crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                                    generation,
                                    error,
                                },
                            );
                        }
                    };
                let client = match cockpit_client::DaemonClient::connect_endpoint(&endpoint).await {
                    Ok(client) => client,
                    Err(error) => {
                        return Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                            generation,
                            error: error_chain(&error),
                        });
                    }
                };
                let current = match client
                    .request(cockpit_proto::Request::GetOnboardingBootstrapSnapshot)
                    .await
                {
                    Ok(Ok(cockpit_proto::Response::OnboardingBootstrapSnapshot(snapshot))) => snapshot,
                    Ok(Ok(other)) => {
                        return Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                            generation,
                            error: format!("unexpected onboarding response: {other:?}"),
                        });
                    }
                    Ok(Err(error)) => {
                        return Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                            generation,
                            error: error.to_string(),
                        });
                    }
                    Err(error) => {
                        return Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                            generation,
                            error: error_chain(&error),
                        });
                    }
                };
                if current.as_ref().is_some_and(|snapshot| {
                    snapshot.bootstrap_state == cockpit_proto::OnboardingBootstrapState::Failed
                }) {
                    return match resolve_failed_ready_construction(
                        &lifecycle,
                        selected_endpoint.as_ref(),
                        client,
                    )
                    .await
                    {
                        Ok((snapshot, lifetime_client)) => Ok(
                            crate::tui::async_action::AsyncActionPayload::StartupOnboardingBootstrap {
                                generation,
                                request_id,
                                receipt: None,
                                lifetime_client: Some(lifetime_client),
                                snapshot,
                            },
                        ),
                        Err(error) => Ok(
                            crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                                generation,
                                error,
                            },
                        ),
                    };
                }
                if current.as_ref().is_some_and(|snapshot| {
                    !force && snapshot.stage == cockpit_proto::OnboardingStage::Complete
                }) || skip
                {
                    return Ok(
                        crate::tui::async_action::AsyncActionPayload::StartupOnboardingBootstrap {
                            generation,
                            request_id,
                            receipt: None,
                            lifetime_client: Some(client),
                            snapshot: current,
                        },
                    );
                }
                let request = cockpit_proto::BeginOrReopenOnboarding {
                    expected_revision: current.as_ref().map(|snapshot| snapshot.revision),
                    client_operation_id: bootstrap_request_id,
                    reentry: force || current.is_some(),
                };
                match client.request(cockpit_proto::Request::BeginOrReopenOnboarding(request)).await {
                    Ok(Ok(cockpit_proto::Response::OnboardingTransition(result))) => Ok(
                            crate::tui::async_action::AsyncActionPayload::StartupOnboardingBootstrap {
                                generation,
                                request_id,
                                receipt: Some(result.receipt),
                                lifetime_client: Some(client),
                                snapshot: Some(result.snapshot),
                        },
                    ),
                    Ok(Ok(other)) => Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                        generation,
                        error: format!("unexpected onboarding response: {other:?}"),
                    }),
                    Ok(Err(error)) => Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                        generation,
                        error: error.to_string(),
                    }),
                    Err(error) => Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                        generation,
                        error: error_chain(&error),
                    }),
                }
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
    }

    pub(super) fn apply_onboarding_bootstrap_snapshot(
        &mut self,
        snapshot: Option<cockpit_proto::OnboardingBootstrapSnapshot>,
    ) {
        // A bootstrap projection is global authority only, so it is recorded
        // and presented immediately: the ordered onboarding screens
        // (Welcome/Profile/SecureStore) deliberately run while the daemon is
        // still locked and no vault exists, before any workspace trust has
        // been decided. The workspace ride-along below still resolves the
        // project root and its daemon-owned trust decision — the
        // session-attach reducer and every project-touching path stay fenced
        // behind `workspace_ready` until that lands, so an eager attach can
        // never read a project config under the safe shell's `.` placeholder.
        //
        // The ride-along is deferred while an onboarding run is still open:
        // a bootstrap-locked daemon denies `GetWorkspaceTrust`, so resolving
        // during the wizard can only produce the red "could not be resolved"
        // toast of #426 on every cold launch. The deferral re-arms itself
        // here the moment the authoritative snapshot reaches `Complete`
        // (the vault exists by then, the daemon is ready, and the trust
        // modal can actually be answered), so no path stays unfenced.
        let onboarding_resolvable = snapshot
            .as_ref()
            .is_none_or(|current| current.stage == cockpit_proto::OnboardingStage::Complete);
        if !self.startup_background.workspace_ready && onboarding_resolvable {
            self.start_workspace_resolution(snapshot.clone());
        }
        if let Some(incoming) = snapshot.as_ref()
            && let Some(recorded) = self.onboarding_snapshot.as_ref()
            && incoming.run_id == recorded.run_id
            && incoming.attempt_id == recorded.attempt_id
            && incoming.revision < recorded.revision
        {
            // The workspace ride-along carries the projection the first
            // fetch observed; by the time it lands, transitions may have
            // advanced the same run past it. Authority application is
            // monotonic: a same-run stale projection never regresses the
            // recorded one.
            return;
        }
        if snapshot.as_ref().is_some_and(|current| {
            current.bootstrap_state == cockpit_proto::OnboardingBootstrapState::Failed
        }) {
            self.onboarding_snapshot = snapshot;
            self.start_onboarding_ready_construction_retry();
            return;
        }
        if let (Some(incoming), Some(recorded)) =
            (snapshot.as_ref(), self.onboarding_snapshot.as_ref())
            && incoming.attempt_id != recorded.attempt_id
        {
            self.onboarding_agent_operation_id = None;
            self.pending_startup_agent_authoring_receipt = None;
        }
        self.onboarding_snapshot = snapshot;
        if let Some(snapshot) = self.onboarding_snapshot.clone() {
            self.sync_onboarding_shell(&snapshot);
        } else {
            self.onboarding_shell = None;
        }
        if self
            .onboarding_shell
            .as_ref()
            .is_some_and(|shell| shell.secure_store_capabilities_probing())
        {
            self.start_onboarding_capability_probe_wait();
        }
        self.maybe_open_pending_setup_wizard();
    }

    /// The locked daemon answers onboarding before its host probes settle,
    /// and a locked connection carries no push events. While the mounted
    /// secure-store screen shows the probing placeholder, re-read the
    /// authoritative bootstrap snapshot on one connection until the settled
    /// capability snapshot (generation > 0) lands, then apply it through the
    /// ordinary snapshot path. Read-only and deduplicated; the daemon settles
    /// its probes (fail-closed on timeout) well within the poll budget.
    fn start_onboarding_capability_probe_wait(&mut self) {
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);
        const POLL_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);
        if self.onboarding_skip || self.onboarding_dismissed {
            return;
        }
        // Poll the same onboarding authority every other onboarding read
        // uses: the startup-selected daemon when startup resolved one, else
        // the default owner (a launch that fetched the bootstrap without a
        // startup selection, e.g. `/setup` or a reopened shell, was served
        // by exactly that owner). Returning early here would strand the
        // screen on its probing rows forever, since a locked connection
        // carries no push events.
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::Refresh("onboarding.capabilities"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.capabilities"),
            ),
            async move {
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                    .await
                    .map_err(|error| error_chain(&error))?;
                let budget = tokio::time::Instant::now() + POLL_BUDGET;
                loop {
                    tokio::time::sleep(POLL_INTERVAL).await;
                    let current = match client
                        .request(cockpit_proto::Request::GetOnboardingBootstrapSnapshot)
                        .await
                        .map_err(|error| error_chain(&error))?
                    {
                        Ok(cockpit_proto::Response::OnboardingBootstrapSnapshot(snapshot)) => {
                            snapshot
                        }
                        Ok(other) => {
                            return Err(format!("unexpected onboarding response: {other:?}"));
                        }
                        Err(error) => return Err(error.to_string()),
                    };
                    let settled = current.as_ref().is_none_or(|snapshot| {
                        snapshot.stage != cockpit_proto::OnboardingStage::SecureStore
                            || snapshot.host_capabilities.generation > 0
                            || !snapshot.host_capabilities.features.is_empty()
                    });
                    if settled || tokio::time::Instant::now() >= budget {
                        return Ok(
                            crate::tui::async_action::AsyncActionPayload::OnboardingBootstrap(
                                current, client,
                            ),
                        );
                    }
                }
            },
        );
    }

    /// Activate, update, or retire the full-screen onboarding shell so it
    /// always mirrors the authoritative daemon snapshot. This is the single
    /// onboarding entry/exit point: fresh launch, resume, deferred resume,
    /// and post-transition refreshes all flow through here.
    ///
    /// A user-dismissed shell never reopens from a snapshot alone: Cancel,
    /// close, and late authority results stay inert for occupancy while
    /// still updating the stored snapshot (committed daemon progress is
    /// never lost). Explicit re-entry (the no-provider send guard, or a
    /// fresh launch) clears the dismissal.
    ///
    /// A deferred run (`limited_mode`) does not auto-open the shell: defer
    /// means "limited mode now"; the shell reopens through the no-provider
    /// send guard or an explicit re-entry. A snapshot that commits the
    /// deferral closes a currently open shell.
    pub(super) fn sync_onboarding_shell(
        &mut self,
        snapshot: &cockpit_proto::OnboardingBootstrapSnapshot,
    ) {
        if self.onboarding_skip {
            self.onboarding_shell = None;
            return;
        }
        if self.onboarding_dismissed {
            // The user closed the shell; a snapshot alone must not reopen
            // it (an in-flight transition result arriving after Cancel
            // stays inert for occupancy).
            return;
        }
        if snapshot.stage == cockpit_proto::OnboardingStage::Complete {
            // A completed run presents no onboarding surface to a fresh
            // launch. A shell that is still open just committed its own
            // terminal transition: present the completion screen from the
            // summary recorded when the lifetime stage settled. "Add
            // another provider" is a local detour on top of that screen;
            // `note_authoritative_complete` treats detour occupancy like
            // dismissal occupancy and never unmounts it for an authority
            // refresh.
            if let Some(shell) = self.onboarding_shell.as_mut() {
                if shell.note_authoritative_complete(snapshot) {
                    self.dialog = crate::tui::settings::Dialog::None;
                }
            } else {
                self.onboarding_shell = None;
                self.dialog = crate::tui::settings::Dialog::None;
            }
            return;
        }
        if snapshot.limited_mode {
            // Deferred limited mode: the ordinary composer is the surface,
            // guarded by the existing no-provider send rule.
            self.onboarding_shell = None;
            self.dialog = crate::tui::settings::Dialog::None;
            return;
        }
        let remount_engine = if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.sync_snapshot(snapshot)
        } else {
            self.onboarding_shell = Some(Box::new(crate::tui::onboarding::OnboardingShell::new(
                snapshot,
                crate::tui::onboarding::reduced_motion_enabled(),
            )));
            true
        };
        if remount_engine {
            self.mount_onboarding_engine(snapshot.stage);
        }
    }

    /// User-initiated reopen (the no-provider send guard): present the
    /// authoritative stage through the shell even in deferred limited mode.
    /// Explicit re-entry clears the dismissal fence.
    pub(super) fn reopen_onboarding_shell(
        &mut self,
        snapshot: &cockpit_proto::OnboardingBootstrapSnapshot,
    ) {
        if self.onboarding_skip || snapshot.stage == cockpit_proto::OnboardingStage::Complete {
            return;
        }
        self.onboarding_dismissed = false;
        if self.onboarding_shell.is_none() {
            self.onboarding_shell = Some(Box::new(crate::tui::onboarding::OnboardingShell::new(
                snapshot,
                crate::tui::onboarding::reduced_motion_enabled(),
            )));
            self.mount_onboarding_engine(snapshot.stage);
        }
    }

    /// Read-only refresh of the authoritative bootstrap snapshot. Used by
    /// the daemon-global `OnboardingBootstrap` broadcast so concurrent
    /// clients follow authority changes; unlike the initial fetch it never
    /// begins or reopens a run (a reopen would supersede the active
    /// attempt and invalidate in-flight transition revisions).
    pub(super) fn refresh_onboarding_bootstrap_snapshot(&mut self) {
        if self.onboarding_skip {
            return;
        }
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.bootstrap_refresh"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.bootstrap_refresh"),
            ),
            async move {
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                    .await
                    .map_err(|error| error_chain(&error))?;
                let current = match client
                    .request(cockpit_proto::Request::GetOnboardingBootstrapSnapshot)
                    .await
                    .map_err(|error| error_chain(&error))?
                {
                    Ok(cockpit_proto::Response::OnboardingBootstrapSnapshot(snapshot)) => snapshot,
                    Ok(other) => return Err(format!("unexpected onboarding response: {other:?}")),
                    Err(error) => return Err(error.to_string()),
                };
                if current.as_ref().is_some_and(|snapshot| {
                    snapshot.bootstrap_state == cockpit_proto::OnboardingBootstrapState::Failed
                }) {
                    return resolve_failed_ready_construction(
                        &lifecycle,
                        selected_endpoint.as_ref(),
                        client,
                    )
                    .await
                    .map(|(snapshot, client)| {
                        crate::tui::async_action::AsyncActionPayload::OnboardingBootstrap(
                            snapshot, client,
                        )
                    });
                }
                Ok(
                    crate::tui::async_action::AsyncActionPayload::OnboardingBootstrap(
                        current, client,
                    ),
                )
            },
        );
    }

    /// Mount the settings-dialog engine for wizard stages. The engine stays
    /// in `App.dialog` so every daemon-effect, OAuth, paste, and pointer
    /// accessor keeps flowing through the ordinary `Dialog` dispatch; the
    /// shell only records the pairing via `present_engine`.
    fn mount_onboarding_engine(&mut self, stage: cockpit_proto::OnboardingStage) {
        use cockpit_proto::OnboardingStage;
        match stage {
            OnboardingStage::Welcome | OnboardingStage::Profile | OnboardingStage::SecureStore => {
                self.dialog = crate::tui::settings::Dialog::None;
            }
            OnboardingStage::Provider => {
                self.dialog = crate::tui::settings::Dialog::None;
                if let Some(shell) = self.onboarding_shell.as_mut() {
                    shell.present_provider_search(Some(
                        "Pick a provider and sign in; setup resumes here.".to_string(),
                    ));
                }
            }
            OnboardingStage::Model => {
                // Seed the model wizard with the committed provider's first
                // catalog model when one exists; manual entry stays available
                // when it does not.
                let preselected = self
                    .config_snapshot
                    .providers
                    .providers
                    .iter()
                    .next()
                    .and_then(|(provider_id, entry)| {
                        entry
                            .models
                            .first()
                            .map(|model| (provider_id.clone(), model.id.clone()))
                    });
                let preselected = preselected.as_ref().map(|(p, m)| (p.as_str(), m.as_str()));
                self.dialog = crate::tui::settings::Dialog::None;
                if let Some(shell) = self.onboarding_shell.as_mut() {
                    shell.present_model(&self.config_snapshot.providers, preselected);
                }
            }
            OnboardingStage::Agent => {
                self.dialog = crate::tui::settings::Dialog::None;
                self.mount_onboarding_agent_authoring();
            }
            OnboardingStage::Lifetime => {
                self.dialog = crate::tui::settings::Dialog::None;
            }
            OnboardingStage::Complete => {}
        }
    }

    fn start_workspace_resolution(
        &mut self,
        snapshot: Option<cockpit_proto::OnboardingBootstrapSnapshot>,
    ) {
        let generation = self.startup_background.generation;
        let requested_project = self.launch.cwd.clone();
        let endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let failure_snapshot = snapshot.clone();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("startup.workspace"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("startup.workspace"),
            ),
            async move {
                let result: Result<StartupWorkspaceCompletion, String> = async move {
                    let opened = if requested_project == std::path::Path::new(".") {
                        std::env::current_dir()
                            .map_err(|error| format!("resolving workspace: {error}"))?
                    } else {
                        requested_project
                    };
                    let root = cockpit_config::trust::resolve_trust_root(&opened)
                        .map_err(|error| format!("resolving workspace trust root: {error}"))?;
                    let project_root = root.root.to_string_lossy().into_owned();
                    let endpoint = endpoint
                        .ok_or_else(|| "selected startup daemon is unavailable".to_string())?;
                    let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                        .await
                        .map_err(|error| error_chain(&error))?;
                    let response = client
                        .request(cockpit_proto::Request::GetWorkspaceTrust { project_root })
                        .await
                        .map_err(|error| error_chain(&error))?;
                    let (mode, config_generation) = match response {
                        Ok(cockpit_proto::Response::WorkspaceTrust {
                            mode,
                            config_generation,
                        }) => (mode, config_generation),
                        Ok(other) => {
                            return Err(format!("unexpected workspace trust response: {other:?}"));
                        }
                        Err(error) => return Err(error.to_string()),
                    };
                    Ok(StartupWorkspaceCompletion {
                        generation,
                        opened,
                        root,
                        mode,
                        config_generation,
                        snapshot,
                    })
                }
                .await;
                Ok(match result {
                    Ok(completion) => {
                        crate::tui::async_action::AsyncActionPayload::StartupWorkspace(completion)
                    }
                    Err(error) => {
                        crate::tui::async_action::AsyncActionPayload::StartupWorkspaceFailed {
                            generation,
                            snapshot: failure_snapshot,
                            error,
                        }
                    }
                })
            },
        );
    }

    pub(super) fn apply_startup_workspace_completion(
        &mut self,
        completion: StartupWorkspaceCompletion,
    ) {
        if completion.generation != self.startup_background.generation || self.exit_requested {
            return;
        }
        self.startup_background.retry = None;
        let mode = match completion.mode {
            Some(cockpit_proto::WorkspaceTrustMode::Trust) => {
                cockpit_config::WorkspaceTrustMode::Trust
            }
            Some(cockpit_proto::WorkspaceTrustMode::IgnoreConfig) => {
                cockpit_config::WorkspaceTrustMode::IgnoreConfig
            }
            None => {
                // An unset daemon decision is not an accepted IgnoreConfig
                // choice. Install the restrictive runtime policy while the
                // modal is open, but do not expose config, onboarding, or a
                // session until the correlated SetWorkspaceTrust receipt.
                cockpit_config::trust::set_runtime_policy(
                    completion.root.clone(),
                    cockpit_config::WorkspaceTrustMode::IgnoreConfig,
                );
                self.launch.cwd = completion.opened;
                self.config_snapshot.generation = self
                    .config_snapshot
                    .generation
                    .max(completion.config_generation);
                self.config_snapshot
                    .providers
                    .set_resolution_generation(self.config_snapshot.generation);
                self.startup_pending_trust = Some(StartupPendingTrust {
                    generation: completion.generation,
                    snapshot: completion.snapshot,
                });
                self.dialog = crate::tui::settings::Dialog::open_workspace_trust(completion.root);
                return;
            }
            Some(cockpit_proto::WorkspaceTrustMode::Untrusted) => {
                if self.mark_startup_trace_milestone("trust-error") {
                    tracing::warn!(target: cockpit_core::startup::TARGET, event = "trust-error", "startup");
                }
                self.push_plain("workspace is untrusted and cannot be opened".to_string());
                self.exit_requested = true;
                return;
            }
        };
        cockpit_config::trust::set_runtime_policy(completion.root, mode);
        self.launch.cwd = completion.opened;
        self.config_snapshot.generation = self
            .config_snapshot
            .generation
            .max(completion.config_generation);
        self.config_snapshot
            .providers
            .set_resolution_generation(self.config_snapshot.generation);
        if self.startup_debug_last_message {
            cockpit_core::engine::model::enable_debug_last_message(
                self.launch.cwd.join(".lastmessage"),
            );
        }
        self.startup_background.workspace_ready = true;
        if self.mark_startup_trace_milestone("trust-ready") {
            tracing::info!(target: cockpit_core::startup::TARGET, event = "trust-ready", "startup");
        }
        self.apply_onboarding_bootstrap_snapshot(completion.snapshot);
        self.start_post_trust_cleanup();
    }

    pub(super) fn start_post_trust_cleanup(&mut self) {
        let exports_dir = self.launch.cwd.join(".cockpit").join("exports");
        self.schedule_startup_export_recovery(async move {
            crate::tui::app::export_actions::recover_deferred_export_cleanup(&exports_dir).await;
        });

        // These projections used to be queued with startup construction. They
        // are retained, but are intentionally downstream of the accepted
        // workspace trust fence because they inspect the opened project.
        crate::tui::async_action::spawn_blocking_action_task(cockpit_core::tokens::warm_cl100k);

        let cwd = self.launch.cwd.clone();
        let active_model = self.launch.active_model.clone();
        let endpoint = self.attached_daemon_endpoint();
        let providers = self.config_snapshot.providers.clone();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::Internal("startup.guidance.estimate"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("startup.guidance.estimate"),
            ),
            async move {
                let (provider, model) = match &active_model {
                    Some((provider, model)) => (Some(provider.clone()), Some(model.clone())),
                    None => (None, None),
                };
                let estimate = agent_runner::fetch_guidance_estimate_with_endpoint(
                    &cwd, providers, provider, model, endpoint,
                )
                .await;
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupGuidanceEstimate {
                        cwd,
                        active_model,
                        estimate,
                    },
                )
            },
        );

        let dependency_cwd = self.launch.cwd.clone();
        let sandbox_enabled = !self.no_sandbox;
        self.async_actions.start_blocking(
            crate::tui::async_action::AsyncActionKind::Internal("startup.dependencies"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("startup.dependencies"),
            ),
            move || {
                cockpit_core::diagnostics::dependency_projection_with_deadline_and_publish_for_run(
                    dependency_cwd,
                    std::time::Duration::from_secs(2),
                    sandbox_enabled,
                )
                .map(crate::tui::async_action::AsyncActionPayload::StartupDependencyProjection)
                .map_err(|error| error.to_string())
            },
        );

        let lifecycle = self.lifecycle.clone();
        let cwd = self.launch.cwd.clone();
        let repo_status = Arc::clone(&self.repo_status);
        let _git_refresh = super::spawn_git_refresh(cwd.clone(), lifecycle.clone(), repo_status);
        let worktree_root = Arc::clone(&self.worktree_root);
        let _worktree_resolve = super::spawn_worktree_root_resolve(cwd, lifecycle, worktree_root);

        #[cfg(feature = "remote")]
        self.start_startup_disclosures_fetch();
    }

    pub(super) fn schedule_startup_export_recovery<F>(&mut self, work: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let generation = self.startup_background.generation;
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::Internal("startup.export_recovery"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("startup.export_recovery"),
            ),
            async move {
                work.await;
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupExportRecovery {
                        generation,
                    },
                )
            },
        );
    }
}

#[derive(Debug)]
pub(crate) struct StartupWorkspaceCompletion {
    pub(crate) generation: u64,
    pub(crate) opened: std::path::PathBuf,
    pub(crate) root: cockpit_config::trust::TrustRoot,
    pub(crate) mode: Option<cockpit_proto::WorkspaceTrustMode>,
    pub(crate) config_generation: u64,
    pub(crate) snapshot: Option<cockpit_proto::OnboardingBootstrapSnapshot>,
}

#[derive(Debug)]
pub(crate) struct StartupPendingTrust {
    pub(crate) generation: u64,
    pub(crate) snapshot: Option<cockpit_proto::OnboardingBootstrapSnapshot>,
}

#[derive(Debug)]
pub(crate) struct StartupOnboardingCompletion {
    pub(crate) lifetime_client: Option<cockpit_client::DaemonClient>,
    pub(crate) generation: u64,
    pub(crate) run_id: uuid::Uuid,
    pub(crate) attempt_id: uuid::Uuid,
    pub(crate) expected_revision: u64,
    pub(crate) request_id: String,
    pub(crate) receipt: Option<cockpit_proto::OnboardingTransitionReceipt>,
    pub(crate) snapshot: Option<cockpit_proto::OnboardingBootstrapSnapshot>,
}

impl App {
    fn start_onboarding_ready_construction_retry(&mut self) {
        let generation = self.startup_background.generation;
        let Some(current) = self.onboarding_snapshot.as_ref() else {
            return;
        };
        let (run_id, attempt_id, expected_revision) =
            (current.run_id, current.attempt_id, current.revision);
        let request_id = uuid::Uuid::new_v4().to_string();
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.ready_retry"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.ready_retry"),
            ),
            async move {
                async {
                    let (_, client) = onboarding_request_after_handoff(
                        &lifecycle,
                        selected_endpoint.as_ref(),
                        cockpit_proto::Request::DaemonStatus,
                    )
                    .await?;
                    resolve_failed_ready_construction(
                        &lifecycle,
                        selected_endpoint.as_ref(),
                        client,
                    )
                    .await
                }
                .await
                .map(|(snapshot, lifetime_client)| {
                    crate::tui::async_action::AsyncActionPayload::StartupOnboardingTransition(
                        StartupOnboardingCompletion {
                            lifetime_client: Some(lifetime_client),
                            generation,
                            run_id,
                            attempt_id,
                            expected_revision,
                            request_id,
                            receipt: None,
                            snapshot,
                        },
                    )
                })
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
    }

    fn request_onboarding_transition(
        &mut self,
        transition: cockpit_proto::OnboardingTransitionKind,
        settlement: Option<cockpit_proto::OnboardingStageSettlement>,
    ) {
        let Some(snapshot) = self.onboarding_snapshot.clone() else {
            self.show_toast(
                "Onboarding checkpoint is unavailable",
                super::ToastKind::Error,
            );
            return;
        };
        let generation = self.startup_background.generation;
        let run_id = snapshot.run_id;
        let attempt_id = snapshot.attempt_id;
        let expected_revision = snapshot.revision;
        let request_id = uuid::Uuid::new_v4().to_string();
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        // Latch the in-flight transition on the shell so a duplicate stage
        // completion cannot request a second advance before the
        // authoritative revision lands. The latch belongs to the settled
        // stage, not to the transport: it is taken whenever the authority
        // checkpoint exists, and the action below resolves the daemon
        // through the pinned startup endpoint or the app's lifecycle funnel.
        if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.latch_transition(snapshot.revision, transition);
        }
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.transition"),
            // A superseding user intent owns the slot: Replace aborts the
            // in-flight transition RPC before the new one starts, so a
            // Back chosen while an Advance is in flight is never silently
            // dropped by dedupe. The daemon's revision CAS is the final
            // arbiter; losers reconcile through the error-path refresh.
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new("onboarding.transition"),
            ),
            async move {
                let request = cockpit_proto::ApplyOnboardingTransition {
                    run_id: snapshot.run_id,
                    attempt_id: snapshot.attempt_id,
                    expected_revision: snapshot.revision,
                    client_operation_id: request_id.clone(),
                    transition,
                    settlement,
                };
                let (result, client) = apply_onboarding_transition_after_handoff(
                    &lifecycle,
                    selected_endpoint.as_ref(),
                    request,
                )
                .await?;
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupOnboardingTransition(
                        StartupOnboardingCompletion {
                            lifetime_client: Some(client),
                            generation,
                            run_id,
                            attempt_id,
                            expected_revision,
                            request_id,
                            receipt: Some(result.receipt),
                            snapshot: Some(result.snapshot),
                        },
                    ),
                )
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
    }

    /// Map a shell intent onto its daemon operation. The shell never writes
    /// config, credential, or onboarding state itself.
    pub(super) fn apply_onboarding_shell_action(
        &mut self,
        action: Option<crate::tui::onboarding::OnboardingShellAction>,
    ) {
        use crate::tui::onboarding::OnboardingShellAction;
        match action {
            None => {}
            Some(OnboardingShellAction::Transition(kind, settlement)) => {
                // A duplicate of the already in-flight intent is dropped:
                // repeated completions (poller + user key) must not abort
                // and resend the same RPC. A *different* kind supersedes
                // the slot — `request_onboarding_transition` replaces the
                // in-flight action.
                let already_in_flight = self
                    .onboarding_shell
                    .as_ref()
                    .is_some_and(|shell| shell.pending_transition_kind() == Some(kind));
                if already_in_flight {
                    tracing::warn!(
                        ?kind,
                        "onboarding transition intent rejected: matching transition is already pending"
                    );
                    // Visible, not silent: the user's key was received while
                    // the previous transition is still settling (#425).
                    self.show_toast("Still applying the previous step…", super::ToastKind::Info);
                    return;
                }
                self.request_onboarding_transition(kind, settlement);
            }
            Some(OnboardingShellAction::SecureIntent(submission)) => {
                self.apply_onboarding_secure_intent(submission);
            }
            Some(OnboardingShellAction::ApplyProfile(name)) => {
                if self
                    .onboarding_shell
                    .as_ref()
                    .is_some_and(|shell| shell.transition_pending())
                {
                    self.show_toast("Still applying the previous step…", super::ToastKind::Info);
                    return;
                }
                self.apply_onboarding_profile(name);
            }
            Some(OnboardingShellAction::ApplyLifetime(background_agents)) => {
                if self
                    .onboarding_shell
                    .as_ref()
                    .is_some_and(|shell| shell.transition_pending())
                {
                    self.show_toast("Still applying the previous step…", super::ToastKind::Info);
                    return;
                }
                self.apply_onboarding_lifetime(background_agents);
            }
            Some(OnboardingShellAction::ApplyModel(submission)) => {
                if self
                    .onboarding_shell
                    .as_ref()
                    .is_some_and(|shell| shell.transition_pending())
                {
                    self.show_toast("Still applying the previous step…", super::ToastKind::Info);
                    return;
                }
                self.apply_onboarding_model(submission);
            }
            Some(OnboardingShellAction::SelectTemplate(template)) => {
                if matches!(template.auth, AuthKind::None) {
                    let submission = crate::tui::onboarding::AuthSubmission::NoCredential {
                        provider_id: template.id.to_string(),
                        base_url: template.url.to_string(),
                    };
                    if let Some(shell) = self.onboarding_shell.as_mut() {
                        shell.present_verify(template.id.to_string());
                    }
                    self.start_onboarding_provider_authentication(template, submission);
                } else if let Some(shell) = self.onboarding_shell.as_mut() {
                    shell.present_authenticate(template);
                }
            }
            Some(OnboardingShellAction::AuthenticateProvider {
                template,
                submission,
            }) => {
                let provider_id = submission.provider_id().to_string();
                if let Some(shell) = self.onboarding_shell.as_mut() {
                    shell.present_verify(provider_id);
                }
                self.start_onboarding_provider_authentication(template, submission);
            }
            Some(OnboardingShellAction::OAuth(action)) => {
                self.dispatch_oauth_action(action);
            }
            Some(OnboardingShellAction::RetryProviderVerification { provider_id }) => {
                self.start_onboarding_provider_verification(provider_id);
            }
            Some(OnboardingShellAction::FinishProvider {
                settlement,
                add_another,
            }) => {
                if add_another {
                    if let Some(shell) = self.onboarding_shell.as_mut() {
                        shell.present_provider_search(Some(
                            "Provider connected. Add another, or finish from Verify.".into(),
                        ));
                    }
                } else if self
                    .onboarding_shell
                    .as_ref()
                    .is_some_and(|shell| shell.completion_detour_active())
                {
                    self.refresh_bootstrap_config_snapshot();
                    let summary = self.onboarding_completion_summary();
                    if let Some(shell) = self.onboarding_shell.as_mut() {
                        shell.note_completion_summary(summary);
                        shell.return_to_completion();
                    }
                    self.dialog = crate::tui::settings::Dialog::None;
                } else {
                    self.refresh_bootstrap_config_snapshot();
                    self.request_onboarding_transition(
                        cockpit_proto::OnboardingTransitionKind::Advance,
                        Some(settlement),
                    );
                }
            }
            Some(OnboardingShellAction::ReturnToCompletion) => {
                // Shell-local: leave the completion screen's "add another
                // provider" detour. The detour engine's in-flight provider
                // authority work (if any) is not discardable — the escape
                // menu offering this choice is suppressed while any is
                // pending.
                if let Some(shell) = self.onboarding_shell.as_mut() {
                    shell.return_to_completion();
                }
                self.dialog = crate::tui::settings::Dialog::None;
            }
            Some(OnboardingShellAction::Close) => {
                // Cancel/exit preserves committed daemon progress and drops
                // only the local engine state; a later reopen resumes from
                // the authoritative snapshot. The dismissal fence keeps
                // late authority results (an in-flight transition, a
                // concurrent client's broadcast) from reopening the shell;
                // only explicit re-entry clears it.
                self.onboarding_dismissed = true;
                self.onboarding_shell = None;
                self.dialog = crate::tui::settings::Dialog::None;
            }
            Some(OnboardingShellAction::AgentAuthoring(action)) => {
                self.dispatch_onboarding_agent_authoring(action);
            }
        }
    }

    pub(super) fn start_onboarding_provider_authentication(
        &mut self,
        template: &'static cockpit_core::providers::ProviderTemplate,
        submission: crate::tui::onboarding::AuthSubmission,
    ) {
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let project_root = self.launch.cwd.display().to_string();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.provider.verify"),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new("onboarding.provider.verify"),
            ),
            async move {
                use cockpit_proto::{
                    ProviderMutationBatch, ProviderMutationUpsert, Request, Response,
                };
                let (provider_id, base_url, mut headers, header_secrets) = match submission {
                    crate::tui::onboarding::AuthSubmission::ApiKey {
                        provider_id,
                        base_url,
                        key,
                    } => {
                        let mut headers =
                            cockpit_core::providers::headers_for_pasted_key(template, key.as_str());
                        let key_header = template.api_key.map(|meta| meta.header_name);
                        let secrets = headers
                            .iter_mut()
                            .map(|header| {
                                if key_header
                                    .is_some_and(|name| name.eq_ignore_ascii_case(&header.name))
                                {
                                    Some(cockpit_proto::ProviderSecretValue::new(std::mem::take(
                                        &mut header.value,
                                    )))
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>();
                        (provider_id, base_url, headers, secrets)
                    }
                    crate::tui::onboarding::AuthSubmission::Environment {
                        provider_id,
                        base_url,
                        variable,
                    } => {
                        let headers = cockpit_core::providers::headers_for_pasted_key(template, "");
                        let key_header = template.api_key.map(|meta| meta.header_name);
                        let secrets = headers
                            .iter()
                            .map(|header| {
                                key_header
                                    .is_some_and(|name| name.eq_ignore_ascii_case(&header.name))
                                    .then(|| {
                                        cockpit_proto::ProviderSecretValue::detected_environment(
                                            template.id.to_string(),
                                            variable.clone(),
                                        )
                                    })
                            })
                            .collect::<Vec<_>>();
                        (provider_id, base_url, headers, secrets)
                    }
                    crate::tui::onboarding::AuthSubmission::OAuth {
                        provider_id,
                        base_url,
                    }
                    | crate::tui::onboarding::AuthSubmission::NoCredential {
                        provider_id,
                        base_url,
                    } => (provider_id, base_url, Vec::new(), Vec::new()),
                };
                let url = if base_url.is_empty() {
                    template.url.to_string()
                } else {
                    base_url
                };
                let entry = cockpit_core::wizard::provider_entry_for_template(
                    template,
                    url,
                    std::mem::take(&mut headers),
                );
                let mutation = ProviderMutationBatch {
                    upserts: vec![ProviderMutationUpsert {
                        provider_id: provider_id.clone(),
                        entry,
                        header_secrets,
                    }],
                    deletes: Vec::new(),
                    metadata: None,
                };
                let mutation_intent_hash = mutation
                    .sanitized_intent_hash()
                    .map_err(|error| error.to_string())?;
                let snapshot_session_id = uuid::Uuid::new_v4().to_string();
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                    .await
                    .map_err(|error| error_chain(&error))?;
                let snapshot = client
                    .request(Request::GetProviderCatalogSnapshot {
                        project_root: project_root.clone(),
                        provider_id: None,
                        snapshot_session_id: snapshot_session_id.clone(),
                    })
                    .await
                    .map_err(|error| error_chain(&error))?
                    .map_err(|error| error.to_string())?;
                let Response::ProviderCatalogSnapshot {
                    layer_id,
                    base_revision,
                    ..
                } = snapshot
                else {
                    return Err("daemon returned the wrong provider snapshot response".to_string());
                };
                let client_operation_id = uuid::Uuid::new_v4().to_string();
                let committed = client
                    .request(Request::ApplyProviderMutation {
                        snapshot_session_id,
                        layer_id,
                        expected_revision: base_revision,
                        client_operation_id: client_operation_id.clone(),
                        mutation_intent_hash: mutation_intent_hash.clone(),
                        mutation,
                    })
                    .await
                    .map_err(|error| error_chain(&error))?
                    .map_err(|error| error.to_string())?;
                let Response::ProviderMutationCommitted {
                    config_generation, ..
                } = committed
                else {
                    return Err("daemon returned the wrong provider mutation response".to_string());
                };
                let outcome =
                    match fetch_onboarding_provider_models(&client, &project_root, &provider_id)
                        .await
                    {
                        Ok((outcome, _)) => Ok(outcome),
                        Err(error) => Err(error),
                    };
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupProviderVerification(
                        crate::tui::onboarding::ProviderVerificationCompletion {
                            provider_id,
                            outcome,
                            settlement: Some(crate::tui::onboarding::ProviderSettlementEvidence {
                                operation_id: client_operation_id,
                                mutation_intent_hash,
                                mutation_config_generation: config_generation,
                                // The Provider advance is authorized by this
                                // terminal mutation receipt, not by a later
                                // catalog read or a replacement worker.
                                config_generation,
                            }),
                        },
                    ),
                )
            },
        );
    }

    fn start_onboarding_provider_verification(&mut self, provider_id: String) {
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let project_root = self.launch.cwd.display().to_string();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.provider.verify"),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new("onboarding.provider.verify"),
            ),
            async move {
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                    .await
                    .map_err(|error| error_chain(&error))?;
                let outcome =
                    match fetch_onboarding_provider_models(&client, &project_root, &provider_id)
                        .await
                    {
                        Ok((outcome, _)) => Ok(outcome),
                        Err(error) => Err(error),
                    };
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupProviderVerification(
                        crate::tui::onboarding::ProviderVerificationCompletion {
                            provider_id,
                            outcome,
                            settlement: None,
                        },
                    ),
                )
            },
        );
    }

    fn mount_onboarding_agent_authoring(&mut self) {
        let Some(snapshot) = self.onboarding_snapshot.clone() else {
            return;
        };
        if self.onboarding_shell.is_none() {
            self.onboarding_shell = Some(Box::new(crate::tui::onboarding::OnboardingShell::new(
                &snapshot,
                crate::tui::onboarding::reduced_motion_enabled(),
            )));
        }
        let operation_id = self
            .onboarding_agent_operation_id
            .get_or_insert_with(|| {
                Self::onboarding_agent_operation_id_for_attempt(snapshot.attempt_id)
            })
            .clone();
        if self
            .onboarding_shell
            .as_ref()
            .is_some_and(|shell| shell.screen_is_agent_authoring())
        {
            return;
        }
        self.request_agent_authoring_receipt(operation_id.clone());
        self.request_agent_authoring_projection(operation_id);
    }

    fn request_agent_authoring_receipt(&mut self, client_operation_id: String) {
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let request_id = uuid::Uuid::new_v4().to_string();
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("agent_authoring.receipt"),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new("agent_authoring.receipt"),
            ),
            async move {
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                    .await
                    .map_err(|error| error_chain(&error))?;
                let response = client
                    .request(cockpit_proto::Request::GetAuthoredAgentPackageReceipt(
                        cockpit_proto::AuthoredAgentPackageReceiptQuery {
                            client_operation_id,
                        },
                    ))
                    .await
                    .map_err(|error| error_chain(&error))?;
                match response {
                    Ok(cockpit_proto::Response::AuthoredAgentPackageReceipt(Some(receipt))) => {
                        Ok(crate::tui::async_action::AsyncActionPayload::StartupAgentAuthoringReceipt {
                            request_id,
                            receipt,
                        })
                    }
                    Ok(cockpit_proto::Response::AuthoredAgentPackageReceipt(None)) => {
                        Ok(crate::tui::async_action::AsyncActionPayload::StartupAgentAuthoringReceiptMiss {
                            request_id,
                        })
                    }
                    Ok(other) => Err(format!("unexpected agent authoring receipt: {other:?}")),
                    Err(error) => Err(error.to_string()),
                }
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
    }

    fn request_agent_authoring_projection(&mut self, client_operation_id: String) {
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let request_id = uuid::Uuid::new_v4().to_string();
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("agent_authoring.projection"),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new("agent_authoring.projection"),
            ),
            async move {
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                    .await
                    .map_err(|error| error_chain(&error))?;
                let response = client
                    .request(cockpit_proto::Request::GetAgentAuthoringProjection)
                    .await
                    .map_err(|error| error_chain(&error))?;
                match response {
                    Ok(cockpit_proto::Response::AgentAuthoringProjection(projection)) => {
                        Ok(crate::tui::async_action::AsyncActionPayload::StartupAgentAuthoringProjection {
                            client_operation_id,
                            request_id,
                            projection,
                        })
                    }
                    Ok(other) => Err(format!("unexpected agent authoring projection: {other:?}")),
                    Err(error) => Err(error.to_string()),
                }
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
    }

    fn dispatch_onboarding_agent_authoring(
        &mut self,
        action: crate::tui::onboarding::agent::AgentAuthoringShellAction,
    ) {
        use crate::tui::onboarding::agent::AgentAuthoringAction;
        let Some(snapshot) = self.onboarding_snapshot.clone() else {
            self.show_toast(
                "Onboarding checkpoint is unavailable",
                super::ToastKind::Error,
            );
            return;
        };
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let request_id = uuid::Uuid::new_v4().to_string();
        let pending_request_id = request_id.clone();
        let operation_id = self
            .onboarding_agent_operation_id
            .get_or_insert_with(|| {
                Self::onboarding_agent_operation_id_for_attempt(snapshot.attempt_id)
            })
            .clone();
        let (validate_only, package, replace_key, rpc_operation_id) = match action {
            AgentAuthoringAction::PreviewPackage(package) => (
                true,
                package,
                "agent_authoring.preview",
                format!("{operation_id}-preview"),
            ),
            AgentAuthoringAction::ApplyPackage {
                client_operation_id,
                package,
            } => (false, package, "agent_authoring.apply", client_operation_id),
            AgentAuthoringAction::RefreshProjection => {
                self.request_agent_authoring_projection(operation_id);
                return;
            }
        };
        let correlation = cockpit_proto::AuthoredAgentOnboardingCorrelation {
            run_id: snapshot.run_id,
            attempt_id: snapshot.attempt_id,
            stage_revision: snapshot.revision,
        };
        let request = cockpit_proto::ApplyAuthoredAgentPackageRequest {
            client_operation_id: rpc_operation_id,
            expected_policy_revision: package.policy_revision.clone(),
            package,
            onboarding: Some(correlation),
            validate_only,
        };
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc(replace_key),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new(replace_key),
            ),
            async move {
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                    .await
                    .map_err(|error| error_chain(&error))?;
                let response = client
                    .request(cockpit_proto::Request::ApplyAuthoredAgentPackage(request))
                    .await
                    .map_err(|error| error_chain(&error))?;
                match response {
                    Ok(cockpit_proto::Response::AuthoredAgentPackage(outcome)) => {
                        Ok(crate::tui::async_action::AsyncActionPayload::StartupAgentAuthoringOutcome {
                            request_id,
                            outcome: Ok(outcome),
                        })
                    }
                    Ok(other) => Err(format!("unexpected agent authoring response: {other:?}")),
                    Err(error) => Err(error.to_string()),
                }
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
    }

    fn apply_onboarding_secure_intent(
        &mut self,
        submission: crate::tui::onboarding::SecureStoreSubmission,
    ) {
        let Some(snapshot) = self.onboarding_snapshot.clone() else {
            self.show_toast(
                "Onboarding checkpoint is unavailable",
                super::ToastKind::Error,
            );
            return;
        };
        let request = cockpit_proto::ApplyOnboardingSecureIntent {
            run_id: snapshot.run_id,
            attempt_id: snapshot.attempt_id,
            expected_revision: snapshot.revision,
            client_operation_id: uuid::Uuid::new_v4().to_string(),
            placement: submission.placement,
            passphrase: submission.passphrase,
        };
        let generation = self.startup_background.generation;
        let run_id = snapshot.run_id;
        let attempt_id = snapshot.attempt_id;
        let expected_revision = snapshot.revision;
        let request_id = request.client_operation_id.clone();
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let pending_request_id = request_id.clone();
        let progress = OnboardingHandoffProgress::default();
        let task_progress = progress.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.secure_intent"),
            // One secure-store submission at a time. Once sent, its outcome
            // is decided by the daemon (the vault may already be committed),
            // so it is never aborted or superseded: a repeated choice while
            // one is in flight is dropped here, and the in-flight one
            // reconciles a lost response from its committed receipt.
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.secure_intent"),
            ),
            async move {
                onboarding_snapshot_after_secure_intent(
                    &lifecycle,
                    selected_endpoint.as_ref(),
                    request,
                    task_progress,
                )
                .await
                .map(|(snapshot, receipt, lifetime_client)| {
                    crate::tui::async_action::AsyncActionPayload::StartupOnboardingTransition(
                        StartupOnboardingCompletion {
                            lifetime_client: Some(lifetime_client),
                            generation,
                            run_id,
                            attempt_id,
                            expected_revision,
                            request_id,
                            receipt,
                            snapshot,
                        },
                    )
                })
            },
        );
        match started {
            crate::tui::async_action::AsyncActionStart::Started(id) => {
                self.pending_startup_onboarding_operations
                    .insert(id, pending_request_id);
                self.onboarding_secure_intent_progress = Some((Instant::now(), progress));
            }
            crate::tui::async_action::AsyncActionStart::Existing(_) => {
                self.show_toast("Still securing your secrets…", super::ToastKind::Info);
            }
        }
    }

    /// Mirror the in-flight secure-store submission onto the screen's
    /// progress line. Called before each render; the pending action keeps
    /// the animation tick running, so the elapsed time advances on its own.
    pub(super) fn sync_onboarding_secure_intent_progress(&mut self) {
        let text = self
            .onboarding_secure_intent_progress
            .as_ref()
            .map(|(started, progress)| {
                let elapsed = started.elapsed().as_secs();
                match progress.get() {
                    OnboardingHandoffPhase::Submitting => "Securing your secrets…".to_string(),
                    OnboardingHandoffPhase::PreparingServices => {
                        format!("Secure store ready. Preparing Cockpit services… ({elapsed}s)")
                    }
                    OnboardingHandoffPhase::Reconnecting => {
                        format!("Reconnecting to the Cockpit daemon… ({elapsed}s)")
                    }
                }
            });
        if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.set_secure_store_progress(text);
        }
    }

    fn apply_onboarding_profile(&mut self, name: String) {
        let Some(snapshot) = self.onboarding_snapshot.clone() else {
            self.show_toast(
                "Onboarding checkpoint is unavailable",
                super::ToastKind::Error,
            );
            return;
        };
        let generation = self.startup_background.generation;
        let run_id = snapshot.run_id;
        let attempt_id = snapshot.attempt_id;
        let expected_revision = snapshot.revision;
        let request_id = uuid::Uuid::new_v4().to_string();
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.latch_transition(
                snapshot.revision,
                cockpit_proto::OnboardingTransitionKind::Advance,
            );
        }
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.profile"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.profile"),
            ),
            async move {
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                    .await
                    .map_err(|error| error_chain(&error))?;
                let response = client
                    .request(cockpit_proto::Request::ApplyOnboardingProfile(
                        cockpit_proto::ApplyOnboardingProfile {
                            client_operation_id: uuid::Uuid::new_v4().to_string(),
                            display_name: name,
                        },
                    ))
                    .await
                    .map_err(|error| error_chain(&error))?;
                match response {
                    Ok(cockpit_proto::Response::SetupWizardApplied { .. }) => {}
                    Ok(other) => return Err(format!("unexpected profile response: {other:?}")),
                    Err(error) => return Err(error.to_string()),
                }
                let transition = cockpit_proto::ApplyOnboardingTransition {
                    run_id,
                    attempt_id,
                    expected_revision,
                    client_operation_id: request_id.clone(),
                    transition: cockpit_proto::OnboardingTransitionKind::Advance,
                    settlement: None,
                };
                let (result, lifetime_client) = apply_onboarding_transition_after_handoff(
                    &lifecycle,
                    selected_endpoint.as_ref(),
                    transition,
                )
                .await?;
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupOnboardingTransition(
                        StartupOnboardingCompletion {
                            lifetime_client: Some(lifetime_client),
                            generation,
                            run_id,
                            attempt_id,
                            expected_revision,
                            request_id,
                            receipt: Some(result.receipt),
                            snapshot: Some(result.snapshot),
                        },
                    ),
                )
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
    }

    fn apply_onboarding_model(
        &mut self,
        submission: cockpit_core::wizard::OnboardingModelSubmission,
    ) {
        let Some(snapshot) = self.onboarding_snapshot.clone() else {
            self.show_toast(
                "Onboarding checkpoint is unavailable",
                super::ToastKind::Error,
            );
            return;
        };
        let project_root = match cockpit_config::config::dirs::global_config_dir() {
            Ok(root) => root,
            Err(error) => {
                self.show_toast(
                    format!("Could not resolve global Cockpit config: {error}"),
                    super::ToastKind::Error,
                );
                return;
            }
        };
        let descriptor = cockpit_core::wizard::onboarding_model_descriptor_for_cwd(
            &project_root,
            Some((&submission.provider_id, &submission.model_id)),
        );
        let answers_json = match cockpit_core::wizard::onboarding_model_client_answers_json(
            descriptor,
            &submission,
        ) {
            Ok(answers) => answers,
            Err(error) => {
                self.show_toast(
                    format!("Could not prepare model settings: {error}"),
                    super::ToastKind::Error,
                );
                return;
            }
        };
        let project_root = project_root.display().to_string();
        let generation = self.startup_background.generation;
        let run_id = snapshot.run_id;
        let attempt_id = snapshot.attempt_id;
        let expected_revision = snapshot.revision;
        let request_id = uuid::Uuid::new_v4().to_string();
        let apply_operation_id = uuid::Uuid::new_v4().to_string();
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.latch_transition(
                snapshot.revision,
                cockpit_proto::OnboardingTransitionKind::Advance,
            );
        }
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.model"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.model"),
            ),
            async move {
                let (response, _lifetime_client) = onboarding_request_after_handoff(
                    &lifecycle,
                    selected_endpoint.as_ref(),
                    cockpit_proto::Request::ApplySetupWizard {
                        client_operation_id: apply_operation_id.clone(),
                        project_root,
                        wizard_id: cockpit_core::wizard::MODEL_SETUP_WIZARD_ID.to_string(),
                        answers_json,
                    },
                )
                .await?;
                let config_generation = match response {
                    cockpit_proto::Response::SetupWizardApplied {
                        wizard_id,
                        config_generation,
                        ..
                    } if wizard_id == cockpit_core::wizard::MODEL_SETUP_WIZARD_ID => {
                        config_generation
                    }
                    other => return Err(format!("unexpected model response: {other:?}")),
                };
                let settlement = cockpit_proto::OnboardingStageSettlement {
                    run_id,
                    attempt_id,
                    stage_revision: expected_revision,
                    settlement_operation_id: apply_operation_id,
                    provider_id: None,
                    mutation_intent_hash: None,
                    provider_mutation_config_generation: None,
                    wizard_id: Some(cockpit_core::wizard::MODEL_SETUP_WIZARD_ID.to_string()),
                    config_generation,
                };
                let transition = cockpit_proto::ApplyOnboardingTransition {
                    run_id,
                    attempt_id,
                    expected_revision,
                    client_operation_id: request_id.clone(),
                    transition: cockpit_proto::OnboardingTransitionKind::Advance,
                    settlement: Some(settlement),
                };
                let (result, lifetime_client) = apply_onboarding_transition_after_handoff(
                    &lifecycle,
                    selected_endpoint.as_ref(),
                    transition,
                )
                .await?;
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupOnboardingTransition(
                        StartupOnboardingCompletion {
                            lifetime_client: Some(lifetime_client),
                            generation,
                            run_id,
                            attempt_id,
                            expected_revision,
                            request_id,
                            receipt: Some(result.receipt),
                            snapshot: Some(result.snapshot),
                        },
                    ),
                )
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
    }

    fn apply_onboarding_lifetime(&mut self, background_agents: bool) {
        let Some(snapshot) = self.onboarding_snapshot.clone() else {
            self.show_toast(
                "Onboarding checkpoint is unavailable",
                super::ToastKind::Error,
            );
            return;
        };
        let answers_json = match cockpit_core::wizard::onboarding_lifetime_client_answers_json(
            background_agents,
        ) {
            Ok(answers) => answers,
            Err(error) => {
                self.show_toast(
                    format!("Could not prepare lifetime choice: {error}"),
                    super::ToastKind::Error,
                );
                return;
            }
        };
        let project_root = match cockpit_config::config::dirs::global_config_dir() {
            Ok(root) => root.display().to_string(),
            Err(error) => {
                self.show_toast(
                    format!("Could not resolve global Cockpit config: {error}"),
                    super::ToastKind::Error,
                );
                return;
            }
        };
        let generation = self.startup_background.generation;
        let run_id = snapshot.run_id;
        let attempt_id = snapshot.attempt_id;
        let expected_revision = snapshot.revision;
        let request_id = uuid::Uuid::new_v4().to_string();
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        // Latch only. Every client-side adoption of the choice — the
        // bootstrap config re-read (lifetime preference, default intent,
        // default model), the completion summary, and the held-draft
        // release — waits for the correlated completion in
        // `finish_onboarding_lifetime_settlement`, because the wizard
        // apply can still fail until its receipt lands (#426).
        if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.latch_transition(
                snapshot.revision,
                cockpit_proto::OnboardingTransitionKind::Advance,
            );
        }
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.lifetime"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.lifetime"),
            ),
            async move {
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                    .await
                    .map_err(|error| error_chain(&error))?;
                let response = client
                    .request(cockpit_proto::Request::ApplySetupWizard {
                        client_operation_id: uuid::Uuid::new_v4().to_string(),
                        project_root,
                        wizard_id: cockpit_core::wizard::LIFETIME_SETUP_WIZARD_ID.to_string(),
                        answers_json,
                    })
                    .await
                    .map_err(|error| error_chain(&error))?;
                match response {
                    Ok(cockpit_proto::Response::SetupWizardApplied { .. }) => {}
                    Ok(other) => return Err(format!("unexpected lifetime response: {other:?}")),
                    Err(error) => return Err(error.to_string()),
                }
                let transition = cockpit_proto::ApplyOnboardingTransition {
                    run_id,
                    attempt_id,
                    expected_revision,
                    client_operation_id: request_id.clone(),
                    transition: cockpit_proto::OnboardingTransitionKind::Advance,
                    settlement: None,
                };
                let (result, lifetime_client) = apply_onboarding_transition_after_handoff(
                    &lifecycle,
                    selected_endpoint.as_ref(),
                    transition,
                )
                .await?;
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupOnboardingTransition(
                        StartupOnboardingCompletion {
                            lifetime_client: Some(lifetime_client),
                            generation,
                            run_id,
                            attempt_id,
                            expected_revision,
                            request_id,
                            receipt: Some(result.receipt),
                            snapshot: Some(result.snapshot),
                        },
                    ),
                )
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
    }

    /// Adopt the committed lifetime settlement on the correlated
    /// `onboarding.lifetime` completion. The wizard apply has written the
    /// global config by then, so the bootstrap re-read (the sanctioned
    /// detached first-run resolution) picks up the recorded
    /// `background_agents` choice — resetting this process's lifetime
    /// preference and default owner intent — plus the effective default
    /// model and TUI chrome. The completion summary is recorded from that
    /// authoritative view before the `Complete` revision presents it, and
    /// a draft held behind model selection is released only now that the
    /// choice is durable. Same post-commit order the pre-native
    /// `service_onboarding_shell` poll arm used (#426).
    pub(super) fn finish_onboarding_lifetime_settlement(&mut self) {
        self.refresh_bootstrap_config_snapshot();
        let configured_model = self.config_snapshot.providers.active_model.clone();
        let summary = self.onboarding_completion_summary();
        if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.note_completion_summary(summary);
        }
        if self.submit_after_model_selection {
            match configured_model {
                Some(active) => {
                    if self.notify_active_model_selected(
                        active,
                        false,
                        cockpit_proto::ActiveModelSwitchTrigger::Picker,
                    ) {
                        self.submit_after_model_selection = false;
                        let _ = self.submit_input();
                    }
                }
                None => {
                    self.submit_after_model_selection = false;
                    self.push_plain(
                        "Your draft is still here; choose a model before sending.".to_string(),
                    );
                }
            }
        }
    }

    /// Service snapshot-driven onboarding stage work each wake. Native
    /// provider intents are applied inline by their reducers.
    pub(super) fn service_onboarding_shell(&mut self) -> bool {
        let Some(snapshot) = self.onboarding_snapshot.clone() else {
            return false;
        };
        let Some(shell) = self.onboarding_shell.as_mut() else {
            return false;
        };
        if shell.transition_pending() {
            tracing::warn!(stage = ?shell.stage(), pending_kind = ?shell.pending_transition_kind(), revision = snapshot.revision, "onboarding shell service rejected: transition is pending");
            return false;
        }
        match shell.stage() {
            cockpit_proto::OnboardingStage::Complete => false,
            cockpit_proto::OnboardingStage::Welcome
            | cockpit_proto::OnboardingStage::Profile
            | cockpit_proto::OnboardingStage::SecureStore => false,
            cockpit_proto::OnboardingStage::Provider => false,
            cockpit_proto::OnboardingStage::Model => false,
            cockpit_proto::OnboardingStage::Agent => {
                let (agent_action, settlement) = {
                    let Some(shell) = self.onboarding_shell.as_mut() else {
                        return false;
                    };
                    let action = shell.take_agent_authoring_action();
                    let settlement = shell.agent_authoring_settlement(
                        snapshot.run_id,
                        snapshot.attempt_id,
                        snapshot.revision,
                        self.config_snapshot.generation,
                    );
                    (action, settlement)
                };
                if let Some(action) = agent_action {
                    self.dispatch_onboarding_agent_authoring(action);
                }
                let Some(settlement) = settlement else {
                    return false;
                };
                self.refresh_bootstrap_config_snapshot();
                self.request_onboarding_transition(
                    cockpit_proto::OnboardingTransitionKind::Advance,
                    Some(settlement),
                );
                true
            }
            cockpit_proto::OnboardingStage::Lifetime => false,
        }
    }

    /// Route a key through the full-screen onboarding shell. Returns
    /// `false` (consume): while onboarding, no other surface sees keys.
    pub(super) fn handle_onboarding_shell_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        self.dialog.bind_lifecycle(self.lifecycle.clone());
        let action = match self.onboarding_shell.as_mut() {
            Some(shell) => shell.handle_key(key, &mut self.dialog),
            None => None,
        };
        // The engine may have queued OAuth or effect requests with the key.
        self.drain_oauth_actions();
        self.apply_onboarding_shell_action(action);
        false
    }

    fn onboarding_completion_summary(&self) -> String {
        let configured_model = &self.config_snapshot.providers.active_model;
        let summary = configured_model
            .as_ref()
            .map(|active| {
                format!(
                    "Configured {}/{} as the default model for future sessions.",
                    active.provider, active.model
                )
            })
            .unwrap_or_else(|| {
                "Model configuration finished; no default model was selected.".to_string()
            });
        let sandbox = self
            .host_capabilities
            .feature("sandbox.host")
            .map(|row| format!("Sandbox: {:?} ({})", row.state, row.reason))
            .unwrap_or_else(|| "Sandbox: capability check pending".to_string());
        let missing_dependencies = self
            .host_capabilities
            .dependencies
            .iter()
            .filter(|row| {
                !matches!(
                    row.state,
                    cockpit_proto::CatalogDependencyState::Available
                        | cockpit_proto::CatalogDependencyState::NotApplicable
                )
            })
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>();
        let dependencies = if missing_dependencies.is_empty() {
            "Dependencies: ready".to_string()
        } else {
            format!(
                "Dependencies needing attention: {}",
                missing_dependencies.join(", ")
            )
        };
        let platform_warning = onboarding_platform_warning();
        format!(
            "{summary} {sandbox}. {dependencies}.{platform_warning} Add another provider any time with /provider add. Suggested first prompt: ‘Help me understand this codebase.’"
        )
    }

    pub(super) fn apply_startup_guidance_estimate(
        &mut self,
        cwd: PathBuf,
        active_model: Option<(String, String)>,
        estimate: agent_runner::GuidanceEstimate,
    ) {
        if cwd == self.launch.cwd && active_model == self.launch.active_model {
            self.guidance_estimate = Some(estimate);
        }
    }

    pub(super) fn start_startup_background_tasks(&mut self) {
        self.start_startup_background_tasks_with_policy(async {
            cockpit_config::extended::load_global_daemon_lifetime_policy()
                .map_err(|error| error.to_string())
        });
    }

    pub(super) fn start_startup_background_tasks_with_policy<F>(&mut self, policy: F)
    where
        F: std::future::Future<Output = Result<bool, String>> + Send + 'static,
    {
        if !self.first_paint_completed {
            return;
        }
        self.begin_startup_background_tasks(policy);
    }

    /// Start the startup authority chain (lifetime policy, lifecycle,
    /// onboarding bootstrap, workspace). Idempotent. Production starts it
    /// before the first frame ([`Self::settle_first_screen_before_paint`]);
    /// the post-paint hook remains the fallback for a shell that did not.
    fn begin_startup_background_tasks<F>(&mut self, policy: F)
    where
        F: std::future::Future<Output = Result<bool, String>> + Send + 'static,
    {
        if self.startup_background.started {
            return;
        }
        self.startup_background.started = true;
        let generation = self.startup_background.generation;
        // The daemon's update notice lives in its process. Run the check here
        // as well so this interactive process can render the result. Channel
        // resolution reads installation config, so it stays off the draw
        // path; it is detached from the action tracker because its result is
        // published through the updater's notice slot, not an action payload.
        crate::tui::async_action::spawn_action_task(async move {
            if let Ok(channel) = cockpit_core::updater::effective_update_channel()
                && cockpit_core::updater::update_checks_enabled(channel)
            {
                let _ = cockpit_core::updater::run_startup_check(channel).await;
            }
        });
        // The first authority operation is isolated in the action runner so
        // an exit before the worker begins has no configuration I/O.  It
        // reads only `daemon.background_agents`; project configuration is not
        // available until the daemon has returned onboarding and trust.
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::Blocking("startup.lifetime-policy"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("startup.lifetime-policy"),
            ),
            async move {
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupLifetimePolicy {
                        generation,
                        result: policy.await,
                    },
                )
            },
        );
    }

    /// Whether the startup chain has settled what the first frame shows:
    /// the onboarding shell (or a startup modal) is mounted, or the chain
    /// has no step left in flight (the chat UI, a limited-mode run, or a
    /// visible startup failure with its retry).
    pub(super) fn first_screen_settled(&self) -> bool {
        use crate::tui::async_action::AsyncActionKind;
        const STARTUP_CHAIN: [AsyncActionKind; 5] = [
            AsyncActionKind::Blocking("startup.lifetime-policy"),
            AsyncActionKind::Internal("startup.lifecycle"),
            AsyncActionKind::DaemonRpc("onboarding.bootstrap"),
            AsyncActionKind::DaemonRpc("onboarding.ready_retry"),
            AsyncActionKind::DaemonRpc("startup.workspace"),
        ];
        self.exit_requested
            || self.onboarding_shell.is_some()
            || self.startup_modal_on_top().is_some()
            || !STARTUP_CHAIN
                .iter()
                .any(|kind| self.async_actions.has_pending_kind(kind))
    }

    /// Decide the first screen before the terminal enters the alternate
    /// screen: run the startup chain (lifetime policy, daemon lifecycle —
    /// spawning the daemon if needed —, the onboarding bootstrap, and for an
    /// onboarded home the workspace decision) through the ordinary reducers
    /// until [`Self::first_screen_settled`]. The first frame is then
    /// onboarding or chat, never one replaced by the other.
    ///
    /// Nothing is drawn meanwhile. If settling takes longer than
    /// [`STARTING_NOTICE_DELAY`], `notice` shows one plain line on the normal
    /// terminal and clears it before the caller enters the alternate screen.
    /// Bounded by [`FIRST_SCREEN_DEADLINE`]: past it the TUI opens anyway and
    /// the chain continues behind the first frame, as a failure fallback.
    pub(super) async fn settle_first_screen_before_paint<F>(
        &mut self,
        policy: F,
        notice: &mut dyn StartupNotice,
    ) where
        F: std::future::Future<Output = Result<bool, String>> + Send + 'static,
    {
        let started = tokio::time::Instant::now();
        let notice_at = started + STARTING_NOTICE_DELAY;
        let deadline = started + FIRST_SCREEN_DEADLINE;
        let notify = self.async_actions.notifier();
        self.begin_startup_background_tasks(policy);
        let mut shown = false;
        loop {
            self.drain_async_actions();
            if self.first_screen_settled() {
                break;
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                tracing::warn!(
                    target: cockpit_core::startup::TARGET,
                    event = "first-screen-deadline",
                    deadline_s = FIRST_SCREEN_DEADLINE.as_secs(),
                    "startup"
                );
                break;
            }
            if !shown && now >= notice_at {
                notice.show();
                shown = true;
            }
            let wake = if shown { deadline } else { notice_at };
            tokio::select! {
                () = notify.notified() => {}
                () = tokio::time::sleep_until(wake) => {}
            }
        }
        if shown {
            notice.clear();
        }
    }

    /// True while the post-paint startup machine has not yet accepted a workspace.
    /// Composer input stays live, but runner/session effects and project I/O must
    /// remain blocked until this clears.
    pub(super) fn blocks_startup_workspace_effects(&self) -> bool {
        (self.first_paint_completed || self.startup_background.started)
            && !self.startup_background.workspace_ready
    }

    /// Gate runner attach, slash/`!` dispatch, scratchpad/notes RPC,
    /// `@`-autocomplete project walks, and other project-touching paths behind
    /// the accepted-workspace fence. Returns `false` when blocked.
    pub(super) fn guard_startup_workspace_effects(&mut self) -> bool {
        if !self.blocks_startup_workspace_effects() {
            return true;
        }
        self.show_toast(
            "Command unavailable until startup accepts the workspace",
            ToastKind::Info,
        );
        self.retry_startup_background();
        false
    }

    pub(super) fn retry_startup_background(&mut self) {
        let Some(retry) = self.startup_background.retry.take() else {
            return;
        };
        match retry {
            StartupRetry::LifetimePolicy => {
                self.startup_background.started = false;
                self.start_startup_background_tasks();
            }
            StartupRetry::Lifecycle => self.start_startup_lifecycle_resolution(),
            StartupRetry::Onboarding => self.start_onboarding_bootstrap_fetch(),
            StartupRetry::Workspace(snapshot) => self.start_workspace_resolution(snapshot),
            StartupRetry::NamedAssistant => {
                if let Some(name) = self.startup_assistant_name.clone() {
                    self.start_named_assistant_resolution(name);
                }
            }
        }
    }

    #[cfg(feature = "remote")]
    pub(super) fn start_startup_disclosures_fetch(&mut self) {
        self.startup_disclosures_generation = self.startup_disclosures_generation.wrapping_add(1);
        let request_generation = self.startup_disclosures_generation;
        let disclosure_root = self.launch.cwd.to_string_lossy().into_owned();
        let disclosure_endpoint = self.attached_daemon_endpoint();
        let launch_session_id = self.launch.session_id;
        let (session_id, attachment_epoch) = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .filter(|runner| runner.has_attached_client())
            .map(|runner| (Some(runner.session_id()), Some(runner.attachment_epoch())))
            .unwrap_or((None, None));
        let request_socket = self.startup_background.daemon_socket.clone();
        self.async_actions.start_blocking(
            AsyncActionKind::Internal("startup.remote_disclosures"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("startup.remote_disclosures")),
            move || {
                let request = cockpit_proto::Request::GetStartupDisclosures {
                    project_root: disclosure_root.clone(),
                };
                let endpoint = disclosure_endpoint.ok_or_else(|| {
                    "daemon endpoint unavailable for startup disclosures".to_string()
                })?;
                let response = agent_runner::daemon_request_at_blocking(&endpoint, request)?;
                match response {
                    cockpit_proto::Response::StartupDisclosures {
                        org_sync,
                        connector,
                        ..
                    } => Ok(AsyncActionPayload::RemoteDisclosures {
                        project_root: disclosure_root,
                        request_generation,
                        socket: request_socket,
                        launch_session_id,
                        session_id,
                        attachment_epoch,
                        org: org_sync,
                        connector,
                    }),
                    other => Err(format!(
                        "unexpected startup disclosures response: {other:?}"
                    )),
                }
            },
        );
    }

    pub(super) fn geometry(&self) -> PaneGeometry {
        let dialog = if self.dialog.is_active() {
            settings::DIALOG_HEIGHT
        } else if self.overlay.dialog_height() > 0 {
            self.overlay.dialog_height()
        } else {
            0
        };
        // The answering dialog (GOALS §3b) is a compact, bottom-anchored
        // overlay sized to its content (capped), not a fullscreen modal.
        let compact = self
            .question_dialog
            .as_ref()
            .map(|d| d.desired_height())
            .unwrap_or_else(|| 0);
        PaneGeometry::compute(
            self.input_height(),
            self.queue_lines(),
            self.suggestion_box_lines(),
            self.total_history_lines(),
            dialog,
            compact,
        )
    }

    /// Full text of the persistent sandbox-down notice (§6.5), or `None` when
    /// the sandbox is fine. Combines the diagnosed remedy (incl. the `sudo
    /// sysctl …=0` command when present) with the deterministic `/sandbox off`
    /// instruction the user must act on. Pure UI chrome — never enters history
    /// or any inference request.
    pub(super) fn sandbox_down_notice_text(&self) -> Option<String> {
        self.sandbox_down_notice.as_ref().map(|notice| {
            if let Some(banner) = crate::tui::capability_gate::sandbox_intent_effective_banner(
                self.sandbox_intent,
                self.sandbox_mode,
                &self.host_capabilities,
            ) {
                return banner;
            }
            let intent = if self.sandbox_intent != self.sandbox_mode {
                Some(self.sandbox_intent)
            } else {
                None
            };
            super::sandbox_down_notice_text_with_intent(
                &notice.remedy,
                notice.fix_command.as_deref(),
                notice.fix_command.is_some(),
                intent,
            )
        })
    }

    pub(super) fn command_capability_notice_text(&self) -> Option<String> {
        self.command_capability_notice.as_ref().map(|notice| {
            command_capability_notice_text(
                &notice.text,
                notice.fix_command.as_deref(),
                notice.fix_command.is_some(),
            )
        })
    }

    pub(super) fn persistent_notice_fix_command(&self) -> Option<&str> {
        self.sandbox_down_notice
            .as_ref()
            .and_then(|notice| notice.fix_command.as_deref())
            .or_else(|| {
                self.command_capability_notice
                    .as_ref()
                    .and_then(|notice| notice.fix_command.as_deref())
            })
    }

    #[cfg(test)]
    pub(super) fn persistent_notice_text(&self) -> Option<String> {
        // Sandbox recovery is safety-critical, so it keeps the shared notice
        // row while active. Command-capability startup notices are next; the
        // auth notice remains queued until higher-priority remedies clear.
        self.sandbox_down_notice_text()
            .or_else(|| self.command_capability_notice_text())
            .or_else(|| {
                self.auth_failure_notice
                    .as_ref()
                    .map(|notice| crate::tui::auth_failure::notice_text(notice, true))
            })
    }
}

#[cfg(windows)]
fn onboarding_platform_warning() -> &'static str {
    " Windows: bash will run unsandboxed; bubblewrap is unavailable."
}

#[cfg(not(windows))]
fn onboarding_platform_warning() -> &'static str {
    ""
}
