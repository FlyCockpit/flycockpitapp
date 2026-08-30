use super::*;

const OAUTH_BEGIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const OAUTH_COMPLETE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);
const OAUTH_CANCEL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const OAUTH_HOST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const OAUTH_SETTLEMENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

fn valid_settlement_request_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

async fn oauth_settlement(
    client: &cockpit_client::DaemonClient,
    client_operation_id: String,
) -> anyhow::Result<Result<cockpit_proto::Response, cockpit_proto::ErrorPayload>> {
    const ATTEMPTS: usize = 3;
    for attempt in 0..ATTEMPTS {
        let response = tokio::time::timeout(
            OAUTH_SETTLEMENT_TIMEOUT,
            client.request(cockpit_proto::Request::GetLocalOperationSettlement {
                client_operation_id: client_operation_id.clone(),
            }),
        )
        .await;
        if let Ok(result) = response {
            if !matches!(
                result,
                Ok(Ok(cockpit_proto::Response::LocalOperationSettlement {
                    pending: true,
                    ..
                }))
            ) || attempt + 1 == ATTEMPTS
            {
                return result;
            }
        } else if attempt + 1 == ATTEMPTS {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Err(anyhow::anyhow!(
        "OAuth settlement query timed out; the exact operation remains unsettled and must be retried"
    ))
}

fn oauth_settlement_unknown(
    error: impl std::fmt::Display,
) -> crate::tui::async_action::OAuthAsyncResult {
    crate::tui::async_action::OAuthAsyncResult::SettlementUnknown(error.to_string())
}

fn oauth_payload(
    client_flow_id: crate::tui::settings::pointer_actions::OAuthFlowId,
    operation_id: crate::tui::settings::shell::PointerOperationId,
    result: Result<crate::tui::async_action::OAuthAsyncResult, String>,
) -> AsyncActionPayload {
    AsyncActionPayload::OAuth {
        client_flow_id,
        operation_id,
        result: result.unwrap_or_else(crate::tui::async_action::OAuthAsyncResult::Failed),
    }
}

fn oauth_operation_id(
    client_flow_id: crate::tui::settings::pointer_actions::OAuthFlowId,
    kind: &str,
) -> String {
    // UI pointer-operation IDs change when a user retries. The durable daemon
    // key deliberately does not: an ambiguous operation must be queried or
    // replayed with the exact same idempotency identity.
    format!("tui-oauth-{}-{kind}", client_flow_id.0)
}

fn oauth_begin_operation_id(
    client_flow_id: crate::tui::settings::pointer_actions::OAuthFlowId,
) -> String {
    format!("tui-oauth-{}-begin", client_flow_id.0)
}

async fn begin_provider_oauth(
    lifecycle: cockpit_client::LifecycleClient,
    provider_id: &str,
    client_operation_id: String,
) -> Result<crate::tui::async_action::OAuthAsyncResult, String> {
    let expected_hash = oauth_request_hash(&("begin_provider_oauth", provider_id))?;
    let client = crate::tui::settings::settings_daemon_client(&lifecycle)
        .await
        .map_err(|e| e.to_string())?;
    let response = tokio::time::timeout(
        OAUTH_BEGIN_TIMEOUT,
        client.request(cockpit_proto::Request::BeginProviderOAuth {
            client_operation_id: client_operation_id.clone(),
            provider_id: provider_id.to_string(),
        }),
    )
    .await;
    let response = match response {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_)) | Err(_) => Ok(
            match oauth_settlement(&client, client_operation_id.clone()).await {
                Ok(response @ Ok(_)) => response,
                Ok(Err(error)) => return Ok(oauth_settlement_unknown(error)),
                Err(error) => return Ok(oauth_settlement_unknown(error)),
            },
        ),
    };
    match response.map_err(|e: anyhow::Error| e.to_string())? {
        Ok(cockpit_proto::Response::LocalOperationSettlement {
            client_operation_id: settlement_operation_id,
            operation_kind,
            request_hash: settlement_hash,
            pending: false,
            response: Some(response),
            ..
        }) if settlement_operation_id == client_operation_id
            && operation_kind == "begin_provider_oauth"
            && valid_settlement_request_hash(&settlement_hash) =>
        {
            match *response {
                cockpit_proto::Response::ProviderOAuthStarted {
                    client_operation_id: receipt_operation_id,
                    request_hash,
                    flow_id,
                    authorize_url,
                    user_code,
                } if receipt_operation_id == client_operation_id
                    && request_hash == expected_hash =>
                {
                    Ok(crate::tui::async_action::OAuthAsyncResult::Began {
                        flow_id,
                        authorize_url,
                        user_code,
                    })
                }
                other => Ok(oauth_settlement_unknown(format!(
                    "OAuth begin receipt was malformed or unbound: {other:?}"
                ))),
            }
        }
        Ok(cockpit_proto::Response::LocalOperationSettlement {
            client_operation_id: settlement_operation_id,
            operation_kind,
            request_hash: settlement_hash,
            pending: false,
            response: None,
            terminal_error: Some(error),
            ..
        }) if settlement_operation_id == client_operation_id
            && operation_kind == "begin_provider_oauth"
            && valid_settlement_request_hash(&settlement_hash) =>
        {
            Ok(crate::tui::async_action::OAuthAsyncResult::AuthoritativeFailure(error.to_string()))
        }
        Ok(cockpit_proto::Response::ProviderOAuthStarted {
            client_operation_id: receipt_operation_id,
            request_hash,
            flow_id,
            authorize_url,
            user_code,
        }) if receipt_operation_id == client_operation_id && request_hash == expected_hash => {
            Ok(crate::tui::async_action::OAuthAsyncResult::Began {
                flow_id,
                authorize_url,
                user_code,
            })
        }
        Ok(cockpit_proto::Response::LocalOperationSettlement {
            client_operation_id: settlement_operation_id,
            operation_kind,
            request_hash: settlement_hash,
            pending: true,
            ..
        }) if settlement_operation_id == client_operation_id
            && operation_kind == "begin_provider_oauth"
            && valid_settlement_request_hash(&settlement_hash) =>
        {
            Ok(oauth_settlement_unknown(
                "OAuth begin is still pending; retrying must use the same operation",
            ))
        }
        Ok(other) => Ok(oauth_settlement_unknown(format!(
            "provider OAuth begin response was malformed or unbound: {other:?}"
        ))),
        Err(error) => Ok(oauth_settlement_unknown(error)),
    }
}

async fn complete_provider_oauth(
    lifecycle: cockpit_client::LifecycleClient,
    client_operation_id: String,
    flow_id: String,
    input: Option<zeroize::Zeroizing<String>>,
) -> Result<crate::tui::async_action::OAuthAsyncResult, String> {
    let client = crate::tui::settings::settings_daemon_client(&lifecycle)
        .await
        .map_err(|e| e.to_string())?;
    let expected_hash = oauth_request_hash(&(
        "complete_provider_oauth_receipt_v2",
        &client_operation_id,
        &flow_id,
    ))?;
    let request = cockpit_proto::Request::CompleteProviderOAuth {
        client_operation_id: client_operation_id.clone(),
        flow_id: flow_id.clone(),
        input: input
            .map(|mut value| cockpit_proto::SensitiveWirePayload::new(std::mem::take(&mut *value))),
    };
    let response = tokio::time::timeout(OAUTH_COMPLETE_TIMEOUT, client.request(request)).await;
    let response = match response {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_)) | Err(_) => Ok(
            match oauth_settlement(&client, client_operation_id.clone()).await {
                Ok(response @ Ok(_)) => response,
                Ok(Err(error)) => return Ok(oauth_settlement_unknown(error)),
                Err(error) => return Ok(oauth_settlement_unknown(error)),
            },
        ),
    };
    match response.map_err(|e: anyhow::Error| e.to_string())? {
        Ok(cockpit_proto::Response::LocalOperationSettlement {
            client_operation_id: settlement_operation_id,
            operation_kind,
            request_hash: settlement_hash,
            pending: false,
            response: Some(response),
            ..
        }) if settlement_operation_id == client_operation_id
            && operation_kind == "complete_provider_oauth"
            && valid_settlement_request_hash(&settlement_hash) =>
        {
            match *response {
                cockpit_proto::Response::ProviderOAuthCompleted {
                    client_operation_id: receipt_operation_id,
                    request_hash,
                    flow_id: receipt_flow_id,
                    logged_in,
                    ..
                } if receipt_operation_id == client_operation_id
                    && request_hash == expected_hash
                    && receipt_flow_id == flow_id =>
                {
                    Ok(crate::tui::async_action::OAuthAsyncResult::Completed { logged_in })
                }
                other => Ok(oauth_settlement_unknown(format!(
                    "OAuth completion receipt was malformed or unbound: {other:?}"
                ))),
            }
        }
        Ok(cockpit_proto::Response::LocalOperationSettlement {
            client_operation_id: settlement_operation_id,
            operation_kind,
            request_hash: settlement_hash,
            pending: false,
            response: None,
            terminal_error: Some(error),
            ..
        }) if settlement_operation_id == client_operation_id
            && operation_kind == "complete_provider_oauth"
            && valid_settlement_request_hash(&settlement_hash) =>
        {
            Ok(crate::tui::async_action::OAuthAsyncResult::AuthoritativeFailure(error.to_string()))
        }
        Ok(cockpit_proto::Response::ProviderOAuthCompleted {
            client_operation_id: receipt_operation_id,
            request_hash,
            flow_id: receipt_flow_id,
            logged_in,
            ..
        }) if receipt_operation_id == client_operation_id
            && request_hash == expected_hash
            && receipt_flow_id == flow_id =>
        {
            Ok(crate::tui::async_action::OAuthAsyncResult::Completed { logged_in })
        }
        Ok(cockpit_proto::Response::LocalOperationSettlement {
            client_operation_id: settlement_operation_id,
            operation_kind,
            request_hash: settlement_hash,
            pending: true,
            ..
        }) if settlement_operation_id == client_operation_id
            && operation_kind == "complete_provider_oauth"
            && valid_settlement_request_hash(&settlement_hash) =>
        {
            Ok(oauth_settlement_unknown(
                "OAuth completion is still pending; retrying must use the same operation",
            ))
        }
        Ok(other) => Ok(oauth_settlement_unknown(format!(
            "provider OAuth completion response was malformed or unbound: {other:?}"
        ))),
        Err(error) => Ok(oauth_settlement_unknown(error)),
    }
}

async fn cancel_provider_oauth(
    lifecycle: cockpit_client::LifecycleClient,
    client_operation_id: String,
    begin_client_operation_id: String,
    flow_id: Option<String>,
) -> Result<crate::tui::async_action::OAuthAsyncResult, String> {
    let expected_hash = oauth_request_hash(&(
        "cancel_provider_oauth",
        &begin_client_operation_id,
        &flow_id,
    ))?;
    let client = crate::tui::settings::settings_daemon_client(&lifecycle)
        .await
        .map_err(|e| e.to_string())?;
    let response = tokio::time::timeout(
        OAUTH_CANCEL_TIMEOUT,
        client.request(cockpit_proto::Request::CancelProviderOAuth {
            client_operation_id: client_operation_id.clone(),
            begin_client_operation_id: begin_client_operation_id.clone(),
            flow_id: flow_id.clone(),
        }),
    )
    .await;
    let response = match response {
        Ok(Ok(response)) => response,
        Ok(Err(_)) | Err(_) => match oauth_settlement(&client, client_operation_id.clone()).await {
            Ok(response @ Ok(_)) => response,
            Ok(Err(error)) => return Ok(oauth_settlement_unknown(error)),
            Err(error) => return Ok(oauth_settlement_unknown(error)),
        },
    };
    match response {
        Ok(cockpit_proto::Response::LocalOperationSettlement {
            client_operation_id: settlement_operation_id,
            operation_kind,
            request_hash: settlement_hash,
            pending: false,
            response: Some(response),
            ..
        }) if settlement_operation_id == client_operation_id
            && operation_kind == "cancel_provider_oauth"
            && settlement_hash == expected_hash =>
        {
            match *response {
                cockpit_proto::Response::ProviderOAuthCancelled {
                    client_operation_id: receipt_operation_id,
                    request_hash,
                    flow_id: receipt_flow_id,
                    cancelled: true,
                } if receipt_operation_id == client_operation_id
                    && request_hash == expected_hash
                    && (flow_id.is_none() || receipt_flow_id == flow_id) =>
                {
                    Ok(crate::tui::async_action::OAuthAsyncResult::Cancelled)
                }
                cockpit_proto::Response::ProviderOAuthCancelled {
                    client_operation_id: receipt_operation_id,
                    request_hash,
                    flow_id: receipt_flow_id,
                    cancelled: false,
                } if receipt_operation_id == client_operation_id
                    && request_hash == expected_hash
                    && (flow_id.is_none() || receipt_flow_id == flow_id) =>
                {
                    Ok(crate::tui::async_action::OAuthAsyncResult::AlreadyTerminal)
                }
                other => Ok(oauth_settlement_unknown(format!(
                    "OAuth cancellation receipt was malformed or unbound: {other:?}"
                ))),
            }
        }
        Ok(cockpit_proto::Response::LocalOperationSettlement {
            client_operation_id: settlement_operation_id,
            operation_kind,
            request_hash: settlement_hash,
            pending: false,
            response: None,
            terminal_error: Some(error),
            ..
        }) if settlement_operation_id == client_operation_id
            && operation_kind == "cancel_provider_oauth"
            && settlement_hash == expected_hash =>
        {
            Ok(crate::tui::async_action::OAuthAsyncResult::AuthoritativeFailure(error.to_string()))
        }
        Ok(cockpit_proto::Response::ProviderOAuthCancelled {
            client_operation_id: receipt_operation_id,
            request_hash,
            flow_id: receipt_flow_id,
            cancelled: true,
        }) if receipt_operation_id == client_operation_id
            && request_hash == expected_hash
            && (flow_id.is_none() || receipt_flow_id == flow_id) =>
        {
            Ok(crate::tui::async_action::OAuthAsyncResult::Cancelled)
        }
        Ok(cockpit_proto::Response::ProviderOAuthCancelled {
            client_operation_id: receipt_operation_id,
            request_hash,
            flow_id: receipt_flow_id,
            cancelled: false,
        }) if receipt_operation_id == client_operation_id
            && request_hash == expected_hash
            && (flow_id.is_none() || receipt_flow_id == flow_id) =>
        {
            Ok(crate::tui::async_action::OAuthAsyncResult::AlreadyTerminal)
        }
        Ok(cockpit_proto::Response::LocalOperationSettlement {
            client_operation_id: settlement_operation_id,
            operation_kind,
            request_hash: settlement_hash,
            pending: true,
            ..
        }) if settlement_operation_id == client_operation_id
            && operation_kind == "cancel_provider_oauth"
            && settlement_hash == expected_hash =>
        {
            Ok(oauth_settlement_unknown(
                "OAuth cancellation is still pending; retrying must use the same operation",
            ))
        }
        Ok(other) => Ok(oauth_settlement_unknown(format!(
            "provider OAuth cancel response was malformed or unbound: {other:?}"
        ))),
        Err(error) => Ok(oauth_settlement_unknown(error)),
    }
}

fn oauth_request_hash<T: serde::Serialize>(value: &T) -> Result<String, String> {
    use sha2::{Digest as _, Sha256};

    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|e| e.to_string())?);
    Ok(Sha256::digest(bytes.as_slice())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StartupDisclosureIdentity<'a> {
    project_root: &'a str,
    generation: u64,
    socket: Option<&'a std::path::Path>,
    launch_session_id: Option<uuid::Uuid>,
    attachment: Option<(uuid::Uuid, u64)>,
}

fn startup_disclosure_completion_is_current(
    current: StartupDisclosureIdentity<'_>,
    completed: StartupDisclosureIdentity<'_>,
) -> bool {
    current == completed
}

fn reconnectable_session_switch_error(error: &str) -> bool {
    error.contains("connection closed")
        || error.contains("broken pipe")
        || error.contains("connection reset")
}

fn floor_char_boundary(text: &str, requested: usize) -> usize {
    let mut offset = requested.min(text.len());
    while !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

impl App {
    pub(super) fn cancel_paste_probes_matching(
        &mut self,
        mut predicate: impl FnMut(&PendingPasteProbe) -> bool,
    ) {
        let cancelled = self
            .pending_paste_probes
            .iter()
            .filter_map(|(id, probe)| predicate(probe).then_some((*id, probe.async_action_id)))
            .collect::<Vec<_>>();
        for (id, action_id) in cancelled {
            if let Some(action_id) = action_id {
                self.async_actions.abort_id(action_id);
            }
            self.pending_paste_probes.remove(&id);
            crate::tui::input_source::acknowledge_native_paste(
                id,
                crate::tui::structured_paste::DedupResult::Busy,
            );
        }
    }

    pub(super) fn expire_pending_paste_probes(&mut self) -> bool {
        let expired = self
            .pending_paste_probes
            .iter()
            .filter_map(|(id, probe)| {
                (probe.deadline <= self.event_loop_monotonic_now).then_some((
                    *id,
                    probe.request.paste_generation,
                    probe.source_draft_generation,
                    probe.async_action_id,
                ))
            })
            .collect::<Vec<_>>();
        for (id, generation, draft_generation, action_id) in &expired {
            if let Some(action_id) = action_id {
                self.async_actions.abort_id(*action_id);
            }
            self.settle_paste_probe(*id, *generation, *draft_generation, 0, None, true);
        }
        !expired.is_empty()
    }

    pub(super) fn drain_async_actions(&mut self) -> bool {
        self.start_pending_image_ingress_discards();
        self.start_pending_goal_settings_effect();
        self.start_pending_tools_effect();
        self.start_pending_settings_daemon_effects();
        self.start_pending_settings_blocking_effects();
        // Cancellation is a terminal runner outcome; most kinds intentionally
        // skip UI mutation. Session switch/resume must still settle provisional
        // buffers, order, and the cleared-view failure contract.
        let cancelled = self.async_actions.drain_cancelled();
        self.tombstone_cancelled_mouse_copies(&cancelled);
        let mcp_local_cancellations = cancelled
            .iter()
            .filter(|result| matches!(result.kind, AsyncActionKind::DaemonRpc("mcp.local")))
            .map(|result| result.id)
            .collect::<Vec<_>>();
        let settings_blocking_cancellations = cancelled
            .iter()
            .filter(|result| {
                matches!(
                    result.kind,
                    AsyncActionKind::Blocking("settings.blocking-effect" | "settings.path-suggest")
                )
            })
            .map(|result| AsyncActionResult {
                id: result.id,
                kind: result.kind.clone(),
                presentation_stale: result.presentation_stale,
                payload: Err("operation cancelled".into()),
            })
            .collect::<Vec<_>>();
        let session_switch_cancellations = cancelled
            .into_iter()
            .filter(|result| {
                matches!(
                    result.kind,
                    AsyncActionKind::Internal("session.switch" | "session.resume")
                )
            })
            .collect::<Vec<_>>();
        let mut results = self.async_actions.expire_blocking(
            self.async_action_clock_origin + self.event_loop_monotonic_now,
            std::time::Duration::from_secs(30),
        );
        results.extend(self.async_actions.drain_completed());
        let changed = !results.is_empty()
            || !session_switch_cancellations.is_empty()
            || !settings_blocking_cancellations.is_empty()
            || !mcp_local_cancellations.is_empty();
        let oauth_completed = results.iter().any(|result| {
            matches!(
                result.kind,
                AsyncActionKind::Internal("oauth.codex.poll" | "oauth.grok.complete")
            )
        });
        for result in session_switch_cancellations {
            self.apply_async_action_result(result);
        }
        for result in settings_blocking_cancellations {
            self.apply_async_action_result(result);
        }
        for action_id in mcp_local_cancellations {
            self.apply_mcp_local_cancellation(action_id);
        }
        for result in results {
            self.apply_async_action_result(result);
        }
        // Applying a correlated OAuth completion may enqueue its next typed
        // effect (begin -> host presentation -> poll). Adopt it in this same
        // event-loop turn; never require an unrelated keypress to advance or
        // install the state machine.
        self.drain_oauth_actions();
        // OAuth completion writes credentials asynchronously while its dialog
        // remains open. Fingerprint reconciliation is deliberately performed
        // after applying the result; failed/cancelled flows leave the stored
        // fingerprint unchanged and therefore retain the annotation.
        if oauth_completed {
            self.clear_changed_provider_auth_failures();
        }
        changed
    }

    fn start_pending_image_ingress_discards(&mut self) {
        let mut retained = self
            .composer
            .image_ingress_drafts()
            .into_iter()
            .map(|draft| draft.admission_id)
            .collect::<std::collections::HashSet<_>>();
        for fence in self.submission_fences.values() {
            let possibly_sent =
                fence.lifecycle == crate::tui::structured_paste::FenceLifecycle::PossiblySent;
            if possibly_sent {
                for draft in &fence.retained_drafts {
                    self.image_ingress_draft_discards
                        .remove(&draft.admission_id);
                }
            } else {
                retained.extend(fence.retained_drafts.iter().map(|draft| draft.admission_id));
            }
            for slot in &fence.slots {
                if let crate::tui::structured_paste::PasteSlotState::Ready {
                    image:
                        Some(crate::tui::structured_paste::PasteImageAdmission::Handle {
                            draft, ..
                        }),
                    ..
                } = slot
                {
                    if possibly_sent && fence.model.supports_images {
                        self.image_ingress_draft_discards
                            .remove(&draft.admission_id);
                    } else if !possibly_sent {
                        retained.insert(draft.admission_id);
                    }
                }
            }
        }
        let pending = self
            .image_ingress_draft_discards
            .iter_mut()
            .filter_map(|(_, (draft, in_flight))| {
                (!*in_flight && !retained.contains(&draft.admission_id)).then(|| {
                    *in_flight = true;
                    draft.clone()
                })
            })
            .collect::<Vec<_>>();
        for draft in pending {
            let request = cockpit_proto::Request::DiscardImageIngressDraft {
                session_id: draft.session_id,
                admission_id: draft.admission_id,
                local_operation_id: draft.local_operation_id,
            };
            let lifecycle = self.lifecycle.clone();
            self.async_actions.start(
                AsyncActionKind::DaemonRpc("paste.image_ingress_discard"),
                AsyncActionPolicy::AllowConcurrent,
                async move {
                    let response = async {
                        let client = crate::tui::settings::settings_daemon_client(&lifecycle)
                            .await
                            .map_err(|error| error.to_string())?;
                        client
                            .request(request)
                            .await
                            .map_err(|error| error.to_string())?
                            .map_err(|error| error.to_string())
                    }
                    .await;
                    Ok(AsyncActionPayload::ImageIngressDraftDiscard(
                        super::ImageIngressDraftDiscardCompletion { draft, response },
                    ))
                },
            );
        }
    }

    fn start_pending_goal_settings_effect(&mut self) {
        let effect = match &mut self.overlay {
            Overlay::GoalSettings(pane) => pane.take_effect(),
            _ => None,
        };
        let Some(effect) = effect else {
            return;
        };
        let operation_id = effect.operation_id;
        let agent_name = effect.agent_name;
        let project_root = effect.project_root;
        let expected_revision = effect.expected_revision;
        let request = effect.request;
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start(
            AsyncActionKind::DaemonRpc("goal-settings.effect"),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let response = async {
                    let client = crate::tui::settings::settings_daemon_client(&lifecycle)
                        .await
                        .map_err(|error| error.to_string())?;
                    client
                        .request(request)
                        .await
                        .map_err(|error| error.to_string())?
                        .map_err(|error| error.to_string())
                }
                .await;
                Ok(AsyncActionPayload::GoalSettings(
                    crate::tui::goal_settings_pane::GoalSettingsCompletion {
                        operation_id,
                        agent_name,
                        project_root,
                        expected_revision,
                        response,
                    },
                ))
            },
        );
    }

    fn start_pending_tools_effect(&mut self) {
        let effect = match &mut self.overlay {
            Overlay::Tools(pane) => pane.take_effect(),
            _ => None,
        };
        let Some(effect) = effect else {
            return;
        };
        let operation_id = effect.operation_id;
        let agent_name = effect.agent_name;
        let project_root = effect.project_root;
        let expected_revision = effect.expected_revision;
        let request = effect.request;
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start(
            AsyncActionKind::DaemonRpc("tools.effect"),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let response = async {
                    let client = crate::tui::settings::settings_daemon_client(&lifecycle)
                        .await
                        .map_err(|error| error.to_string())?;
                    client
                        .request(request)
                        .await
                        .map_err(|error| error.to_string())?
                        .map_err(|error| error.to_string())
                }
                .await;
                Ok(AsyncActionPayload::Tools(
                    crate::tui::tools_pane::ToolsCompletion {
                        operation_id,
                        agent_name,
                        project_root,
                        expected_revision,
                        response,
                    },
                ))
            },
        );
    }

    fn start_pending_settings_daemon_effects(&mut self) {
        self.dialog.bind_lifecycle(self.lifecycle.clone());
        while let Some(effect) = self.dialog.take_settings_daemon_effect() {
            let dialog_id = effect.dialog_id;
            let operation_id = effect.operation_id;
            let target = effect.target;
            let work = effect.work;
            let lifecycle = self.lifecycle.clone();
            let attached = self
                .agent_runner
                .as_ref()
                .and_then(|runner| runner.as_ref().ok())
                .map(|runner| runner.attached_request_binding());
            self.async_actions.start(
                AsyncActionKind::DaemonRpc("settings.effect"),
                AsyncActionPolicy::AllowConcurrent,
                async move {
                    let outcome = match work {
                        crate::tui::settings::SettingsDaemonEffectWork::AttachedRequest(
                            request,
                        ) => match attached {
                            Some(binding) => {
                                let response = binding.request(request).await;
                                Ok(crate::tui::settings::SettingsDaemonWorkOutcome {
                                    response,
                                    authoritative_rejection: false,
                                    committed_refresh_needed: None,
                                })
                            }
                            None => Err("session attachment required".into()),
                        },
                        work => {
                            crate::tui::settings::execute_settings_daemon_work(work, lifecycle)
                                .await
                        }
                    };
                    let (response, authoritative_rejection, committed_refresh_needed) =
                        match outcome {
                            Ok(outcome) => (
                                outcome.response,
                                outcome.authoritative_rejection,
                                outcome.committed_refresh_needed,
                            ),
                            Err(error) => (Err(error), false, None),
                        };
                    Ok(AsyncActionPayload::SettingsDaemon(
                        crate::tui::settings::SettingsDaemonEffectCompletion {
                            dialog_id,
                            operation_id,
                            target,
                            response,
                            authoritative_rejection,
                            committed_refresh_needed,
                        },
                    ))
                },
            );
        }
    }

    fn start_pending_settings_blocking_effects(&mut self) {
        while let Some(effect) = self.dialog.take_settings_blocking_effect() {
            let dialog_id = effect.dialog_id;
            let operation_id = effect.operation_id;
            let target = effect.target;
            let work = effect.work;
            let action_label = work.action_label();
            let metadata = crate::tui::settings::SettingsBlockingEffectMetadata {
                dialog_id,
                operation_id,
                target: target.clone(),
            };
            let action_id = self
                .async_actions
                .start_blocking(
                    AsyncActionKind::Blocking(action_label),
                    AsyncActionPolicy::AllowConcurrent,
                    move || {
                        let outcome = crate::tui::settings::execute_settings_blocking_work(work);
                        Ok(AsyncActionPayload::SettingsBlocking(
                            crate::tui::settings::SettingsBlockingEffectCompletion {
                                dialog_id,
                                operation_id,
                                target,
                                outcome,
                            },
                        ))
                    },
                )
                .id();
            self.settings_blocking_actions.insert(action_id, metadata);
        }
    }

    pub(super) fn start_sessions_mutation_action(
        &mut self,
        effect: crate::tui::sessions_pane::SessionsMutationEffect,
    ) {
        let pane_id = effect.pane_id;
        let operation_id = effect.operation_id;
        let target = effect.target;
        let request = effect.request;
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start(
            AsyncActionKind::DaemonRpc("sessions.mutation"),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let response = async {
                    let client = crate::tui::settings::settings_daemon_client(&lifecycle)
                        .await
                        .map_err(|error| error.to_string())?;
                    client
                        .request(request)
                        .await
                        .map_err(|error| error.to_string())?
                        .map_err(|error| error.to_string())
                }
                .await;
                Ok(AsyncActionPayload::SessionsMutation(
                    crate::tui::sessions_pane::SessionsMutationCompletion {
                        pane_id,
                        operation_id,
                        target,
                        response,
                    },
                ))
            },
        );
    }

    pub(super) fn apply_async_action_result(&mut self, result: AsyncActionResult) {
        if result.presentation_stale && !stale_completion_requires_reducer(&result.kind) {
            // The runner has consumed the terminal completion and released its
            // process authority. Nothing in these handlers owns additional
            // correlated state; running them would only publish output into a
            // replacement view. Mouse copy is the one presentation-only host
            // action with a local gesture record to retire.
            if matches!(result.kind, AsyncActionKind::Blocking("mouse.copy")) {
                self.pending_mouse_copies.remove(&result.id);
            }
            return;
        }
        // Provisional `/new` owns a cleared view. Only the switch/resume
        // settlement path and outgoing delivery-receipt fence bookkeeping may
        // run; every other completion is presentation noise from the discarded
        // transcript (including Blocking timeouts that bypass view-generation).
        if (result.presentation_stale || self.provisional_new_session)
            && result.kind.authority() == crate::tui::async_action::AsyncActionAuthority::ReadOnly
            && !matches!(
                result.kind,
                AsyncActionKind::Internal(
                    "session.switch" | "session.resume" | "runner.attach" | "btw.runner.attach"
                ) | AsyncActionKind::Blocking("paste.delivery_receipt")
                    | AsyncActionKind::DaemonRpc("sealed.effect" | "mcp.local")
            )
        {
            return;
        }
        match result.kind {
            AsyncActionKind::Internal("runner.attach") => {
                self.apply_runner_attach_result(result.id, result.payload);
            }
            AsyncActionKind::Internal("btw.runner.attach") => {
                self.apply_btw_runner_attach(result.id, result.payload);
            }
            AsyncActionKind::DaemonRpc("settings.effect") => {
                if let Ok(AsyncActionPayload::SettingsDaemon(completion)) = result.payload {
                    self.dialog.apply_settings_daemon_completion(completion);
                }
            }
            AsyncActionKind::Blocking("settings.blocking-effect" | "settings.path-suggest") => {
                let metadata = self.settings_blocking_actions.remove(&result.id);
                let completion = match result.payload {
                    Ok(AsyncActionPayload::SettingsBlocking(completion)) => Some(completion),
                    Err(error) => metadata.map(|metadata| {
                        crate::tui::settings::SettingsBlockingEffectCompletion {
                            dialog_id: metadata.dialog_id,
                            operation_id: metadata.operation_id,
                            target: metadata.target,
                            outcome: Err(error),
                        }
                    }),
                    Ok(_) => metadata.map(|metadata| {
                        crate::tui::settings::SettingsBlockingEffectCompletion {
                            dialog_id: metadata.dialog_id,
                            operation_id: metadata.operation_id,
                            target: metadata.target,
                            outcome: Err("unexpected settings blocking result".into()),
                        }
                    }),
                };
                if let Some(completion) = completion {
                    self.dialog.apply_settings_blocking_completion(completion);
                }
            }
            AsyncActionKind::DaemonRpc("sessions.mutation") => {
                let mut reload = false;
                if let Ok(AsyncActionPayload::SessionsMutation(completion)) = result.payload
                    && let Overlay::Sessions(pane) = &mut self.overlay
                {
                    reload = pane.apply_mutation_completion(completion);
                }
                if reload {
                    self.start_sessions_list_action();
                }
            }
            AsyncActionKind::DaemonRpc("goal-settings.effect") => {
                let outcome = match result.payload {
                    Ok(AsyncActionPayload::GoalSettings(completion)) => match &mut self.overlay {
                        Overlay::GoalSettings(pane) => pane.apply_completion(completion),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(outcome) = outcome {
                    self.handle_goal_settings_outcome(outcome);
                }
            }
            AsyncActionKind::DaemonRpc("tools.effect") => {
                let outcome = match result.payload {
                    Ok(AsyncActionPayload::Tools(completion)) => match &mut self.overlay {
                        Overlay::Tools(pane) => pane.apply_completion(completion),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(outcome) = outcome {
                    self.handle_tools_outcome(outcome);
                }
            }
            AsyncActionKind::DaemonRpc("workspace-trust.effect") => {
                if let Ok(AsyncActionPayload::WorkspaceTrust(completion)) = result.payload {
                    self.apply_workspace_trust_completion(completion);
                }
            }
            AsyncActionKind::DaemonRpc("sealed.effect") => {
                if let Ok(AsyncActionPayload::Sealed(completion)) = result.payload {
                    self.apply_sealed_completion(completion);
                }
            }
            AsyncActionKind::DaemonRpc("mcp.local") => {
                if let Ok(AsyncActionPayload::McpLocal(completion)) = result.payload {
                    self.apply_mcp_local_completion(result.id, completion);
                } else {
                    self.apply_mcp_local_cancellation(result.id);
                }
            }
            AsyncActionKind::DaemonRpc("paste.image_ingress_discard") => {
                if let Ok(AsyncActionPayload::ImageIngressDraftDiscard(completion)) = result.payload
                {
                    let terminal = matches!(
                        &completion.response,
                        Ok(cockpit_proto::Response::LocalMediaMutation(receipt))
                            if receipt.schema_version == 1
                                && receipt.kind == "localMediaMutationReceipt"
                                && receipt.local_operation_id
                                    == completion.draft.local_operation_id
                                && receipt.action == "discard"
                                && receipt.subject_id == completion.draft.attachment_id
                                && receipt.discard_result.is_some()
                    );
                    if terminal {
                        self.image_ingress_draft_discards
                            .remove(&completion.draft.admission_id);
                    } else if let Some((owned, in_flight)) = self
                        .image_ingress_draft_discards
                        .get_mut(&completion.draft.admission_id)
                        && *owned == completion.draft
                    {
                        *in_flight = false;
                    }
                }
            }
            AsyncActionKind::DaemonRpc("btw.resolve-interrupt") => match result.payload {
                Ok(AsyncActionPayload::Unit) => {}
                Ok(_) => self.push_plain("question: unexpected daemon response".to_string()),
                Err(error) => self.push_plain(format!("question: {error}")),
            },
            AsyncActionKind::DaemonRpc("sessions.list") => {
                let mut live_ids = None;
                let mut preview_request = None;
                if let Overlay::Sessions(pane) = &mut self.overlay {
                    let payload = match result.payload {
                        Ok(AsyncActionPayload::Sessions(sessions)) => Ok(sessions),
                        Ok(_) => Err("unexpected daemon response".to_string()),
                        Err(e) => Err(e),
                    };
                    let ids = pane.apply_sessions_result(payload);
                    if !ids.is_empty() {
                        live_ids = Some(ids);
                    }
                    if pane.is_preview_enabled()
                        && let Some(crate::tui::sessions_pane::SessionsOutcome::LoadPreview {
                            session_id,
                            before_seq,
                        }) = pane.ensure_preview_for_selection()
                    {
                        preview_request = Some((session_id, before_seq));
                    }
                }
                if let Some(ids) = live_ids {
                    self.start_sessions_live_status_action(ids);
                }
                if let Some((session_id, before_seq)) = preview_request {
                    self.start_sessions_preview_action(session_id, before_seq);
                }
            }
            AsyncActionKind::DaemonRpc("sessions.live") => {
                if let Overlay::Sessions(pane) = &mut self.overlay
                    && let Ok(AsyncActionPayload::SessionLiveStatus(live)) = result.payload
                {
                    pane.apply_live_status(live);
                }
            }
            AsyncActionKind::DaemonRpc("sessions.preview") => {
                if let Overlay::Sessions(pane) = &mut self.overlay {
                    match result.payload {
                        Ok(AsyncActionPayload::SessionMessages {
                            session_id,
                            before_seq,
                            messages,
                            has_more,
                        }) => pane.apply_preview_result(
                            session_id,
                            before_seq,
                            Ok((messages, has_more)),
                        ),
                        Err(error) => {
                            if let Some((session_id, before_seq)) = pane.take_preview_load() {
                                pane.apply_preview_result(session_id, before_seq, Err(error));
                            }
                        }
                        Ok(_) => {}
                    }
                }
            }
            AsyncActionKind::DaemonRpc("sessions.inbox") => {
                if let Overlay::Sessions(pane) = &mut self.overlay {
                    match result.payload {
                        Ok(AsyncActionPayload::AssistantInbox {
                            main_session_id,
                            items,
                        }) => pane.apply_inbox_result(main_session_id, Ok(items)),
                        Err(error) => {
                            if let Some(main_session_id) = pane.selected_session_id_for_action() {
                                pane.apply_inbox_result(main_session_id, Err(error));
                            }
                        }
                        Ok(_) => {}
                    }
                }
            }
            AsyncActionKind::DaemonRpc("skills.list") => {
                if let Ok(AsyncActionPayload::Skills(result)) = result.payload {
                    let owns_result = matches!(
                        &self.overlay,
                        Overlay::Skills(pane) if pane.owns_fetch_generation(result.generation)
                    );
                    if !owns_result {
                        return;
                    }
                    if let Overlay::Skills(pane) = &mut self.overlay {
                        pane.apply_fetch_result(result);
                    }
                }
            }
            AsyncActionKind::DaemonRpc("inventory.bundle") => match result.payload {
                Ok(AsyncActionPayload::InventoryBundle(response)) => {
                    self.apply_inventory_bundle_response(response);
                }
                Err(error) => {
                    if let Some(ticket) = self.inventory.in_flight.clone() {
                        self.inventory.apply_failure(&ticket, error);
                    }
                }
                _ => {}
            },
            AsyncActionKind::DaemonRpc("session_setup.snapshot") => match result.payload {
                Ok(AsyncActionPayload::SessionSetupSnapshot(response)) => {
                    self.apply_session_setup_snapshot_response(response);
                }
                Err(error) => {
                    self.apply_session_setup_snapshot_error(error);
                }
                _ => {}
            },
            AsyncActionKind::DaemonRpc("session_setup.add_mcp")
            | AsyncActionKind::DaemonRpc("session_setup.add_mcp_agent") => match result.payload {
                Ok(AsyncActionPayload::SessionSetupSnapshot(response)) => {
                    self.apply_session_setup_snapshot_response(response);
                }
                Err(error) => {
                    self.apply_session_setup_add_mcp_error(error);
                }
                _ => {}
            },
            AsyncActionKind::DaemonRpc("agent_tree.snapshot") => match result.payload {
                Ok(AsyncActionPayload::AgentTreeSnapshot { tree, attention }) => {
                    self.apply_agent_tree_snapshot(*tree, *attention);
                }
                Err(error) => {
                    self.apply_agent_tree_error(error);
                }
                _ => {}
            },
            AsyncActionKind::DaemonRpc("agent_tree.resolve") => match result.payload {
                Ok(AsyncActionPayload::AgentTreeResolved) => {
                    self.request_agent_tree_refresh();
                }
                _ => {}
            },
            AsyncActionKind::DaemonRpc("agent_tree.effective_settings") => match result.payload {
                Ok(AsyncActionPayload::AgentEffectiveSettings(response)) => {
                    self.apply_agent_effective_settings(response);
                }
                Err(error) => {
                    self.apply_agent_effective_settings_error(error);
                }
                _ => {}
            },
            AsyncActionKind::DaemonRpc("agent_tree.apply_override") => match result.payload {
                Ok(AsyncActionPayload::AgentSessionOverrideOutcome(response)) => {
                    self.apply_agent_session_override_outcome(response);
                }
                Err(error) => {
                    self.set_agent_override_error(error);
                }
                _ => {}
            },
            AsyncActionKind::DaemonRpc("agent_tree.override_model_choices") => {
                // Supplementary to the effective settings: on success populate the
                // Model section; a failure leaves it empty (no error surfaced).
                if let Ok(AsyncActionPayload::SessionSetupSnapshot(response)) = result.payload {
                    self.apply_agent_override_model_choices(response);
                }
            }
            AsyncActionKind::DaemonRpc("guidance.estimate") => {
                if let Ok(AsyncActionPayload::GuidanceEstimate(estimate)) = result.payload {
                    self.guidance_estimate = Some(estimate);
                }
            }
            AsyncActionKind::Internal("startup.guidance.estimate") => {
                if let Ok(AsyncActionPayload::StartupGuidanceEstimate {
                    cwd,
                    active_model,
                    estimate,
                }) = result.payload
                {
                    self.apply_startup_guidance_estimate(cwd, active_model, estimate);
                }
            }
            AsyncActionKind::DaemonRpc("paste.image_path_admission") => {
                let presentation_stale = result.presentation_stale;
                let action_id = result.id;
                match result.payload {
                    Ok(AsyncActionPayload::ImagePathProbe {
                        request_id,
                        request_generation,
                        terminal_generation,
                        original: _,
                        source_draft_generation,
                        cursor,
                        admission: Some(admission),
                    }) if terminal_generation == self.terminal_input_generation => {
                        self.settle_paste_probe(
                            request_id,
                            request_generation,
                            source_draft_generation,
                            cursor,
                            Some(admission),
                            false,
                        );
                    }
                    Ok(AsyncActionPayload::ImagePathProbe {
                        request_id,
                        request_generation,
                        terminal_generation,
                        original: _,
                        source_draft_generation,
                        cursor: _,
                        admission: None,
                    }) if terminal_generation == self.terminal_input_generation => {
                        self.settle_paste_probe(
                            request_id,
                            request_generation,
                            source_draft_generation,
                            0,
                            None,
                            true,
                        );
                    }
                    Err(_) => {
                        if let Some((request_id, request_generation, source_draft_generation)) =
                            self.pending_paste_probes
                                .iter()
                                .find_map(|(request_id, probe)| {
                                    (probe.async_action_id == Some(action_id)).then_some((
                                        *request_id,
                                        probe.request.paste_generation,
                                        probe.source_draft_generation,
                                    ))
                                })
                        {
                            self.settle_paste_probe(
                                request_id,
                                request_generation,
                                source_draft_generation,
                                0,
                                None,
                                !presentation_stale,
                            );
                        }
                        if presentation_stale {
                            return;
                        }
                        let caps = self.refresh_host_capabilities();
                        let media =
                            caps.feature(cockpit_core::host_capabilities::FEATURE_MEDIA_DECODE);
                        if media.is_none_or(|row| !row.state.is_available()) {
                            self.show_toast(
                                crate::tui::capability_gate::media_decode_instruct(&caps).display(),
                                ToastKind::Error,
                            );
                        } else {
                            self.show_toast("Paste unavailable", ToastKind::Error);
                        }
                    }
                    Ok(_) => {}
                }
            }
            AsyncActionKind::Internal("paste.native_image") => match result.payload {
                Ok(AsyncActionPayload::NativeImagePaste {
                    request_id,
                    request_generation,
                    terminal_generation,
                    source_draft_generation,
                    cursor,
                    admission: Some(admission),
                }) if terminal_generation == self.terminal_input_generation => {
                    self.terminal_paste_classifier.resolve_shortcut_intent();
                    self.settle_paste_probe(
                        request_id,
                        request_generation,
                        source_draft_generation,
                        cursor,
                        Some(admission),
                        false,
                    );
                }
                // The classifier owns the 250 ms timeout notice. A missing
                // bitmap can still be followed by authoritative bracketed
                // text, so the speculative native probe remains silent.
                Ok(AsyncActionPayload::NativeImagePaste {
                    request_id,
                    request_generation,
                    terminal_generation,
                    source_draft_generation,
                    admission: None,
                    ..
                }) if terminal_generation == self.terminal_input_generation => {
                    self.settle_paste_probe(
                        request_id,
                        request_generation,
                        source_draft_generation,
                        0,
                        None,
                        false,
                    );
                }
                Err(_) => {}
                Ok(_) => {}
            },
            AsyncActionKind::Blocking("paste.delivery_receipt") => {
                if let Ok(AsyncActionPayload::ClientSubmissionReceipt {
                    client_submission_id,
                    result,
                }) = result.payload
                {
                    match result {
                        Ok(cockpit_proto::ClientSubmissionReceiptStatus::Pending) | Err(_) => {
                            if let Some(record) = self
                                .delivery_unconfirmed_records
                                .get_mut(&client_submission_id)
                            {
                                record.probe_in_flight = false;
                                record.next_probe_at = self.event_loop_monotonic_now
                                    + std::time::Duration::from_millis(250);
                                if record.next_probe_at >= record.probe_deadline {
                                    record.probe_exhausted = true;
                                }
                            }
                        }
                        Ok(status) => {
                            let (outcome, wire_fingerprint) = match status {
                                cockpit_proto::ClientSubmissionReceiptStatus::Accepted {
                                    wire_fingerprint,
                                    ..
                                } => ("accepted".to_string(), wire_fingerprint),
                                cockpit_proto::ClientSubmissionReceiptStatus::Terminal {
                                    disposition,
                                    wire_fingerprint,
                                } => (disposition, wire_fingerprint),
                                cockpit_proto::ClientSubmissionReceiptStatus::Pending => {
                                    unreachable!()
                                }
                            };
                            if let Some(record) = self
                                .delivery_unconfirmed_records
                                .remove(&client_submission_id)
                            {
                                self.submission_fences.remove(&client_submission_id);
                                if !self.provisional_new_session {
                                    let wire_fingerprint = if wire_fingerprint.is_empty() {
                                        "unavailable"
                                    } else {
                                        &wire_fingerprint
                                    };
                                    self.push_plain(format!(
                                    "Delivery {outcome} for message {} in session {} (daemon wire {}).",
                                    record.client_submission_id,
                                    record.session_id,
                                    wire_fingerprint
                                ));
                                }
                            }
                        }
                    }
                }
            }
            AsyncActionKind::Internal("startup.dependencies") => {
                if let Ok(AsyncActionPayload::StartupDependencyProjection(projection)) =
                    result.payload
                    && let Some(summary) =
                        cockpit_core::external_runtime::startup_dependency_policy(&projection)
                            .summary
                {
                    self.show_toast(format!("Dependency warning: {summary}"), ToastKind::Warning);
                }
            }
            AsyncActionKind::Internal(label @ ("session.switch" | "session.resume")) => {
                match result.payload {
                    Ok(AsyncActionPayload::SessionSwitched(outcome)) => {
                        if label == "session.switch"
                            && !matches!(outcome.target, agent_runner::SessionTarget::New)
                        {
                            self.history.push(HistoryEntry::CommandError {
                                line: "/new: session switch returned the wrong target; view remains cleared"
                                    .to_string(),
                            });
                            self.fail_pending_session_switch_submissions();
                            self.abandon_provisional_new_session();
                        } else {
                            if label == "session.switch" {
                                self.commit_new_session_switch_outcome(*outcome);
                            } else {
                                self.apply_session_switch_outcome(*outcome);
                            }
                            self.flush_pending_session_switch_submissions();
                        }
                    }
                    Ok(_) => {
                        if label == "session.switch" {
                            self.history.push(HistoryEntry::CommandError {
                                line: "/new: session switch returned an unexpected response; view remains cleared"
                                    .to_string(),
                            });
                            self.fail_pending_session_switch_submissions();
                            self.abandon_provisional_new_session();
                        } else {
                            self.history.push(HistoryEntry::CommandError {
                                line: "/resume: session switch returned an unexpected response"
                                    .to_string(),
                            });
                            self.fail_pending_session_switch_submissions();
                        }
                    }
                    Err(error) => {
                        let command = if label == "session.resume" {
                            "/resume"
                        } else {
                            "/new"
                        };
                        if reconnectable_session_switch_error(&error)
                            && matches!(self.agent_runner, Some(Ok(_)))
                        {
                            self.history.push(HistoryEntry::CommandError {
                                line: format!("{command}: daemon connection lost; reconnecting"),
                            });
                        } else {
                            // Replacement Attach installs its new client only
                            // after success. A rejected switch therefore leaves
                            // the current attachment and its view retryable.
                            self.history.push(HistoryEntry::CommandError {
                                line: format!("{command}: {error}"),
                            });
                        }
                        self.fail_pending_session_switch_submissions();
                        if label == "session.switch" {
                            self.abandon_provisional_new_session();
                        }
                    }
                }
                if label == "session.switch"
                    && let Some((sequence, _)) = self.pending_session_switch_order.take()
                {
                    self.pending_session_switch_reconcile_started_at = None;
                    let _ = self.submission_order.complete(sequence);
                    self.dispatch_next_ready_paste_fence();
                }
            }
            AsyncActionKind::Internal("session.fork") => match result.payload {
                Ok(AsyncActionPayload::ForkSessionSwitched {
                    outcome,
                    fork_short_id,
                    seed_composer,
                }) => {
                    self.apply_session_switch_outcome_without_resume_chrome(*outcome);
                    self.flush_pending_session_switch_submissions();
                    self.push_plain(format!("/fork: switched to fork {fork_short_id}."));
                    if let Some(seed) = seed_composer {
                        self.replace_composer_buffer(seed);
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                }
                Ok(_) => {
                    self.history.push(HistoryEntry::CommandError {
                        line: "/fork: session switch returned an unexpected response".to_string(),
                    });
                    self.fail_pending_session_switch_submissions();
                }
                Err(error) => {
                    if reconnectable_session_switch_error(&error)
                        && matches!(self.agent_runner, Some(Ok(_)))
                    {
                        self.history.push(HistoryEntry::CommandError {
                            line: "/fork: daemon connection lost; reconnecting".to_string(),
                        });
                    } else {
                        // The unattached fork is discarded by the switch task;
                        // the current session client was never replaced.
                        self.history.push(HistoryEntry::CommandError {
                            line: format!("/fork: could not attach to fork: {error}"),
                        });
                    }
                    self.fail_pending_session_switch_submissions();
                }
            },
            AsyncActionKind::Internal("session.side") => match result.payload {
                Ok(AsyncActionPayload::SideSessionSwitched {
                    outcome,
                    side_short_id,
                }) => {
                    self.apply_session_switch_outcome_preserving_history(*outcome, false);
                    self.flush_pending_session_switch_submissions();
                    self.push_plain(Self::side_entry_banner(&side_short_id));
                }
                Ok(_) => {
                    self.agent_runner = Some(Err("side switch returned unexpected payload".into()));
                    self.fail_pending_session_switch_submissions();
                }
                Err(error) => {
                    if let Some(side) = self.side_conversation.take() {
                        let discard_endpoint = side.endpoint.clone();
                        let discard_session_id = side.side_session_id;
                        self.restore_side_snapshot(side);
                        self.async_actions.start_blocking(
                            AsyncActionKind::DaemonRpc("side.discard"),
                            AsyncActionPolicy::AllowConcurrent,
                            move || {
                                agent_runner::discard_session_blocking(
                                    &discard_endpoint,
                                    discard_session_id,
                                )
                                .map(|_| AsyncActionPayload::Unit)
                            },
                        );
                    }
                    if reconnectable_session_switch_error(&error)
                        && matches!(self.agent_runner, Some(Ok(_)))
                    {
                        self.history.push(HistoryEntry::CommandError {
                            line: "/side: daemon connection lost; reconnecting".to_string(),
                        });
                    } else {
                        self.history.push(HistoryEntry::CommandError {
                            line: format!("/side: could not enter side conversation: {error}"),
                        });
                    }
                    self.fail_pending_session_switch_submissions();
                }
            },
            AsyncActionKind::Internal("session.side.return") => match result.payload {
                Ok(AsyncActionPayload::SideSessionReturned(outcome)) => {
                    self.complete_side_conversation_return(*outcome);
                }
                Ok(_) => {
                    self.history.push(HistoryEntry::CommandError {
                        line: "/side: return produced an unexpected response; still in side conversation"
                            .to_string(),
                    });
                    self.fail_pending_session_switch_submissions();
                }
                Err(error) => {
                    let line = if reconnectable_session_switch_error(&error) {
                        "/side: daemon connection lost; reconnecting — still in side conversation"
                            .to_string()
                    } else {
                        format!(
                            "/side: could not return to main session: {error}; still in side conversation — retry `/side end`"
                        )
                    };
                    self.history.push(HistoryEntry::CommandError { line });
                    self.fail_pending_session_switch_submissions();
                }
            },
            AsyncActionKind::Refresh("container.availability") => {
                if let Ok(AsyncActionPayload::ContainerAvailability(availability)) = result.payload
                {
                    self.container_availability = availability;
                }
            }
            #[cfg(feature = "remote")]
            AsyncActionKind::Internal("startup.remote_disclosures") => match result.payload {
                Ok(AsyncActionPayload::RemoteDisclosures {
                    project_root,
                    request_generation,
                    socket,
                    launch_session_id,
                    session_id,
                    attachment_epoch,
                    org,
                    connector,
                }) => {
                    let current_attachment = self
                        .agent_runner
                        .as_ref()
                        .and_then(|runner| runner.as_ref().ok())
                        .filter(|runner| runner.has_attached_client())
                        .map(|runner| (runner.session_id(), runner.attachment_epoch()));
                    if startup_disclosure_completion_is_current(
                        StartupDisclosureIdentity {
                            project_root: &self.launch.cwd.to_string_lossy(),
                            generation: self.startup_disclosures_generation,
                            socket: self.startup_background.daemon_socket.as_deref(),
                            launch_session_id: self.launch.session_id,
                            attachment: current_attachment,
                        },
                        StartupDisclosureIdentity {
                            project_root: &project_root,
                            generation: request_generation,
                            socket: socket.as_deref(),
                            launch_session_id,
                            attachment: session_id.zip(attachment_epoch),
                        },
                    ) {
                        self.startup_disclosures_ready = true;
                        self.org_sync_disclosure = org;
                        self.connector_disclosure = connector;
                    }
                }
                Ok(_) => {}
                Err(error) => self.show_toast(
                    format!("Startup disclosures Unavailable — {error}; Retry"),
                    ToastKind::Warning,
                ),
            },
            AsyncActionKind::DaemonRpc("assistant.resolve") => match result.payload {
                Ok(AsyncActionPayload::AssistantSessionResolved {
                    session_id,
                    source_session_id,
                    startup_notice,
                    promoted_from_ephemeral,
                }) => {
                    if self.launch.session_id == source_session_id {
                        if let Some(notice) = startup_notice {
                            // A lifecycle warning is independent of the
                            // ownership transition below. Keep it in the
                            // transcript so the required promotion toast
                            // cannot overwrite it.
                            self.push_plain(notice);
                        }
                        if promoted_from_ephemeral {
                            self.show_toast(
                                cockpit_core::daemon::client::ASSISTANT_PERSISTENCE_NOTICE,
                                ToastKind::Info,
                            );
                            // The prior runner was attached to the ephemeral
                            // owner that just exited. Reattach directly to the
                            // resolved persistent owner instead of asking that
                            // dead transport to perform an in-process switch.
                            self.agent_runner.take();
                            self.launch.session_id = Some(session_id);
                            self.start_runner_attach(
                                true,
                                RunnerAttachContinuation::RetryRetainedSubmissions,
                            );
                            return;
                        }
                        self.resume_session(session_id);
                    }
                }
                Ok(_) => self.push_plain("/assistant: unexpected daemon response".to_string()),
                Err(error) => self.push_plain(format!("/assistant: Unavailable — {error}; Retry")),
            },
            AsyncActionKind::Refresh("stats.rollup") => {
                if let Overlay::Stats(pane) = &mut self.overlay
                    && let Ok(AsyncActionPayload::StatsRollup(result)) = result.payload
                {
                    pane.apply_fetch_result(result);
                }
            }
            AsyncActionKind::DaemonRpc("git.diff") => {
                if let Overlay::Diff(pane) = &mut self.overlay
                    && let Ok(AsyncActionPayload::GitDiff(result)) = result.payload
                {
                    pane.apply_fetch_result(result);
                }
            }
            AsyncActionKind::DaemonRpc("git.review_sources") => {
                if let Overlay::Multireview(dialog) = &mut self.overlay
                    && let Ok(AsyncActionPayload::GitReviewSources(completion)) = result.payload
                {
                    dialog.apply_git_sources(completion);
                    if let Some(kickoff) = dialog.take_done() {
                        self.overlay = Overlay::None;
                        self.start_multireview(kickoff.prompt);
                    }
                }
            }
            AsyncActionKind::Internal("subagent.history") => {
                if let Ok(AsyncActionPayload::SubagentHistory {
                    session_id,
                    task_call_id,
                    label,
                    history,
                    has_more,
                    oldest_seq,
                }) = result.payload
                {
                    self.apply_subagent_history_result(
                        session_id,
                        &task_call_id,
                        &label,
                        history,
                        has_more,
                        oldest_seq,
                    );
                }
            }
            AsyncActionKind::Refresh("provider.usage") => {
                if let Overlay::Usage(pane) = &mut self.overlay {
                    match result.payload {
                        Ok(AsyncActionPayload::ProviderUsage {
                            pane_generation,
                            result,
                        }) if pane_generation == pane.generation() => pane.apply_result(result),
                        Ok(AsyncActionPayload::ProviderUsage { .. }) => {}
                        Ok(_) => pane.apply_result(Err("unexpected usage response".to_string())),
                        Err(e) => pane.apply_result(Err(e)),
                    }
                }
            }
            AsyncActionKind::Internal("paste.token_count") => match result.payload {
                Ok(AsyncActionPayload::PasteTokenCount { block_id, tokens }) => {
                    self.apply_paste_token_count(block_id, tokens);
                }
                Ok(_) => {
                    tracing::debug!("paste token count returned unexpected payload");
                }
                Err(e) => {
                    tracing::debug!(error = %e, "paste token count failed");
                }
            },
            AsyncActionKind::Refresh("pins.state") => match result.payload {
                Ok(AsyncActionPayload::PinState {
                    session_id,
                    count,
                    pinned_seqs,
                }) => {
                    self.apply_pin_state(session_id, count, pinned_seqs);
                }
                Ok(AsyncActionPayload::PinStateRefreshFailed { session_id, error }) => {
                    tracing::debug!(error = %error, "pin state refresh failed");
                    self.note_pin_state_refresh_failed(session_id);
                }
                Ok(_) => {
                    tracing::debug!("pin state refresh returned unexpected payload");
                }
                Err(e) => {
                    // Reached only on infra-level failure (task cancellation),
                    // not on an RPC error — those now arrive as
                    // `PinStateRefreshFailed`. No session identity is available,
                    // so we only log. A cancellation always has a replacement
                    // refresh in flight (`Replace` policy) that re-stamps; a raw
                    // task panic (abnormal — `load_pin_state` returns `Result`)
                    // would leave the eager stamp set until the next session
                    // switch clears it.
                    tracing::debug!(error = %e, "pin state refresh action failed");
                }
            },
            AsyncActionKind::Internal("pins.toggle") => match result.payload {
                Ok(AsyncActionPayload::PinToggle {
                    session_id,
                    seq,
                    now_pinned,
                    count,
                    pinned_seqs,
                }) => {
                    self.apply_pin_toggle(session_id, seq, now_pinned, count, pinned_seqs);
                }
                Ok(_) => self.pin_toast("pin: unexpected response".to_string()),
                Err(e) => self.pin_toast(format!("pin: {e}")),
            },
            AsyncActionKind::Internal("pins.review") => match result.payload {
                Ok(AsyncActionPayload::PinsReview { session_id, pins }) => {
                    self.apply_pins_review(session_id, pins);
                }
                Ok(_) => self.push_plain("/pins: unexpected response".to_string()),
                Err(e) => self.push_plain(format!("/pins: {e}")),
            },
            AsyncActionKind::Internal("pins.pin") => match result.payload {
                Ok(AsyncActionPayload::PinMessage {
                    session_id,
                    seq: _,
                    inserted,
                    count,
                    pinned_seqs,
                }) => {
                    self.apply_pin_message(session_id, inserted, count, pinned_seqs);
                }
                Ok(_) => self.pin_toast("pin: unexpected response".to_string()),
                Err(e) => self.pin_toast(format!("pin: {e}")),
            },
            AsyncActionKind::Internal("pins.unpin") => match result.payload {
                Ok(AsyncActionPayload::PinUnpin {
                    session_id,
                    seq,
                    count,
                    pinned_seqs,
                }) => {
                    self.apply_pin_unpin(session_id, seq, count, pinned_seqs);
                }
                Ok(_) => self.pin_toast("unpin: unexpected response".to_string()),
                Err(e) => self.pin_toast(format!("unpin: {e}")),
            },
            AsyncActionKind::DaemonRpc("resources.snapshot") => {
                if let Overlay::Resources(pane) = &mut self.overlay {
                    let payload = match result.payload {
                        Ok(AsyncActionPayload::ResourceSnapshot {
                            pane_generation,
                            result,
                        }) if pane_generation == pane.generation() => result,
                        Ok(AsyncActionPayload::ResourceSnapshot { .. }) => return,
                        Ok(_) => Err("unexpected daemon response".to_string()),
                        Err(e) => Err(e),
                    };
                    pane.apply_snapshot_result(payload);
                }
            }
            AsyncActionKind::DaemonRpc("resources.promote") => match result.payload {
                Ok(AsyncActionPayload::PromoteResource {
                    pane_generation,
                    status,
                    message,
                    snapshot,
                }) => {
                    if let Overlay::Resources(pane) = &mut self.overlay
                        && pane_generation == Some(pane.generation())
                    {
                        pane.apply_snapshot_result(Ok(snapshot));
                    }
                    let kind = match status {
                        cockpit_proto::ResourcePromoteStatus::Promoted => ToastKind::Success,
                        cockpit_proto::ResourcePromoteStatus::NotQueued
                        | cockpit_proto::ResourcePromoteStatus::NotFound => ToastKind::Info,
                        cockpit_proto::ResourcePromoteStatus::Disabled => ToastKind::Warning,
                    };
                    self.show_toast(message, kind);
                }
                Ok(_) => {
                    self.show_toast("/resources: unexpected daemon response", ToastKind::Error)
                }
                Err(e) => self.show_toast(format!("/resources: {e}"), ToastKind::Error),
            },
            AsyncActionKind::NotesProjection {
                instance_id,
                generation,
            } => {
                let next = if let Overlay::Notes(pane) = &mut self.overlay {
                    match result.payload {
                        Ok(AsyncActionPayload::NotesRpc(result)) => {
                            pane.apply_rpc_result(Ok(result))
                        }
                        Ok(_) => pane.apply_transport_error(
                            instance_id,
                            generation,
                            "notes db returned an unexpected response".to_string(),
                        ),
                        Err(error) => pane.apply_transport_error(instance_id, generation, error),
                    }
                } else {
                    None
                };
                debug_assert!(next.is_none(), "notes actions are app-lane owned");
            }
            AsyncActionKind::Internal("leaks.rpc") => {
                if let Overlay::Leaks(pane) = &mut self.overlay {
                    let payload = match result.payload {
                        Ok(AsyncActionPayload::LeaksRpc(result)) => Ok(result),
                        Ok(_) => Err("leaks daemon returned an unexpected response".to_string()),
                        Err(e) => Err(e),
                    };
                    pane.apply_rpc_result(payload);
                }
            }
            AsyncActionKind::DaemonRpc(
                "goal.create" | "goal.disposition" | "goal.set" | "goal.clear",
            ) => match result.payload {
                Ok(AsyncActionPayload::Text(message)) => self.push_plain(message),
                Ok(_) => self.push_plain("/goal: unexpected daemon response".to_string()),
                Err(error) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/goal: {error}"),
                }),
            },
            AsyncActionKind::Blocking("curator.command") => match result.payload {
                Ok(AsyncActionPayload::Text(message)) => self.push_plain(message),
                Ok(_) => self.push_plain("/curator: unexpected async response".to_string()),
                Err(e) => self.push_plain(format!("/curator: {e}")),
            },
            AsyncActionKind::Blocking("export.transcript") => match result.payload {
                Ok(AsyncActionPayload::Text(message)) => self.push_plain(message),
                Ok(_) => self.push_plain("/export: unexpected async response".to_string()),
                Err(e) => self.push_plain(e),
            },
            AsyncActionKind::Blocking("export.debug") => match result.payload {
                Ok(AsyncActionPayload::Text(message)) => self.push_plain(message),
                Ok(_) => self.push_plain("/export debug: unexpected async response".to_string()),
                Err(e) => self.push_plain(e),
            },
            AsyncActionKind::Blocking("doctor.snapshot") => match result.payload {
                Ok(AsyncActionPayload::DoctorSnapshot(rendered)) => self.push_plain(rendered),
                Ok(_) => self.push_plain("/doctor: unexpected async response".to_string()),
                Err(error) => self.push_plain(error),
            },
            AsyncActionKind::Blocking("autocomplete.files") => match result.payload {
                Ok(AsyncActionPayload::FileSuggestions { query, suggestions })
                    if self.composer.at_query() == Some(query.as_str()) =>
                {
                    self.at_suggestions_loading = false;
                    self.at_suggestions_loaded_query = Some(query.clone());
                    self.at_suggestions_error = None;
                    *self.at_cache.borrow_mut() = Some((query, suggestions));
                }
                Err(error) => {
                    self.at_suggestions_loading = false;
                    self.at_suggestions_loaded_query = self.composer.at_query().map(str::to_string);
                    self.at_suggestions_error = Some(error);
                }
                _ => {}
            },
            AsyncActionKind::Blocking("queue.edit") => {
                let outcome = match result.payload {
                    Ok(AsyncActionPayload::DaemonResponse(response)) => {
                        self.remove_editable_queued_messages_with(|| Ok(*response))
                    }
                    _ => input::QueueEditOutcome::TransportError,
                };
                self.apply_queue_edit_outcome(outcome);
            }
            AsyncActionKind::DaemonRpc("queue.control") => match result.payload {
                Ok(AsyncActionPayload::DaemonResponse(response)) => {
                    self.apply_queue_control_response(*response);
                }
                Err(error) => {
                    self.show_toast(
                        format!("queue control failed: {error}"),
                        super::ToastKind::Info,
                    );
                }
                _ => {}
            },
            AsyncActionKind::DaemonRpc(
                "queue.edit.reservation" | "queue.edit.commit" | "queue.edit.release",
            ) => match result.payload {
                Ok(AsyncActionPayload::DaemonResponse(response)) => {
                    self.apply_queue_control_response(*response);
                }
                Err(error) => {
                    self.fail_pending_queue_edit(&error);
                }
                _ => {}
            },
            AsyncActionKind::Blocking("btw.teardown") => match result.payload {
                Ok(AsyncActionPayload::BtwTransition {
                    created,
                    ended,
                    question,
                    error,
                }) => {
                    if ended {
                        self.close_btw_pane();
                    }
                    if let Some(info) = created {
                        self.open_btw_pane_from_info(info, true);
                    }
                    if let Some(error) = error {
                        self.push_plain(format!("/btw: {error}"));
                    } else if let Some(pane) = self.btw_pane.as_mut() {
                        pane.focused = true;
                        if let Some(question) = question
                            && let Err(error) = pane.send_text(question)
                        {
                            pane.history.push(HistoryEntry::InferenceError {
                                summary: error.clone(),
                                detail: error,
                                expanded: false,
                            });
                        }
                    } else if !ended {
                        self.push_plain("/btw: no live fork".to_string());
                    }
                }
                Ok(_) => self.push_plain("/btw: unexpected async response".to_string()),
                Err(error) => self.push_plain(format!("/btw: {error}")),
            },
            AsyncActionKind::DaemonRpc("rename") => match result.payload {
                Ok(AsyncActionPayload::Text(title)) => {
                    self.push_plain(format!("Renamed session to `{title}`"));
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/rename: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/rename: {e}"),
                }),
            },
            AsyncActionKind::Internal("rename.auto") => match result.payload {
                Ok(AsyncActionPayload::Text(title)) => {
                    self.push_plain(format!("Renamed session to `{title}`"));
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/rename: unexpected title result".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/rename: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("sealed") => match result.payload {
                Ok(AsyncActionPayload::Text(message)) => self.push_plain(message),
                Ok(_) => self.push_plain("/sealed: unexpected daemon response".to_string()),
                Err(e) => self.push_plain(format!("/sealed: {e}")),
            },
            AsyncActionKind::DaemonRpc(
                "leaks-list" | "leaks-rotate" | "leaks-delete" | "leaks",
            ) => match result.payload {
                Ok(AsyncActionPayload::Text(message)) => self.push_plain(message),
                Ok(_) => self.push_plain("/leaks: unexpected daemon response".to_string()),
                Err(e) => self.push_plain(format!("/leaks: {e}")),
            },
            AsyncActionKind::DaemonRpc("note") => match result.payload {
                Ok(AsyncActionPayload::NoteRecorded { text }) => {
                    self.history.push(HistoryEntry::UserNote {
                        text,
                        timestamp: chrono::Local::now(),
                    });
                    self.pin_chat_to_tail();
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/note: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/note: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("history.page") => match result.payload {
                Ok(AsyncActionPayload::HistoryPage {
                    request_id,
                    session_id,
                    entries,
                    has_more,
                    oldest_seq,
                }) => {
                    self.apply_older_history_page_result(
                        request_id, session_id, entries, has_more, oldest_seq,
                    );
                }
                Ok(AsyncActionPayload::HistoryPageError {
                    request_id,
                    session_id,
                    message: _,
                }) => self.apply_older_history_page_error(request_id, session_id),
                Ok(_) => {}
                Err(_) => {}
            },
            AsyncActionKind::DaemonRpc("subagent.history.page") => match result.payload {
                Ok(AsyncActionPayload::SubagentHistoryPage {
                    request_id,
                    session_id,
                    task_call_id,
                    label,
                    entries,
                    has_more,
                    oldest_seq,
                }) => {
                    self.apply_subagent_history_page_result(
                        request_id,
                        session_id,
                        (&task_call_id, &label),
                        entries,
                        has_more,
                        oldest_seq,
                    );
                }
                Ok(AsyncActionPayload::SubagentHistoryPageError {
                    request_id,
                    session_id,
                    task_call_id,
                    label,
                    message: _,
                }) => self.apply_subagent_history_page_error(
                    request_id,
                    session_id,
                    &task_call_id,
                    &label,
                ),
                Ok(_) => {}
                Err(_) => {}
            },
            AsyncActionKind::DaemonRpc("fork.create") => match result.payload {
                Ok(AsyncActionPayload::ForkCreated {
                    parent_session_id,
                    endpoint,
                    socket,
                    session_id,
                    short_id,
                    fork_point_seq,
                    seed_composer,
                    ..
                }) => {
                    self.apply_fork_created(
                        parent_session_id,
                        endpoint,
                        socket,
                        session_id,
                        short_id,
                        fork_point_seq,
                        seed_composer,
                    );
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/fork: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/fork: could not fork: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("side.start") => match result.payload {
                Ok(AsyncActionPayload::ForkCreated {
                    parent_session_id,
                    endpoint,
                    socket,
                    session_id,
                    short_id,
                    ..
                }) => {
                    self.apply_side_created(
                        parent_session_id,
                        endpoint,
                        socket,
                        session_id,
                        short_id,
                    );
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/side: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/side: could not fork: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("side.discard") => {
                if let Err(e) = result.payload {
                    tracing::warn!(error = %e, "discarding ephemeral side session failed; boot sweep will reclaim it");
                }
            }
            AsyncActionKind::Blocking("local.command") => match result.payload {
                Ok(AsyncActionPayload::LocalCommand {
                    label,
                    raw_output,
                    failed,
                    git_args,
                }) => {
                    self.apply_local_command_result(label, raw_output, failed, git_args);
                }
                Ok(_) => self.push_plain("local command: unexpected async response".to_string()),
                Err(e) => self.push_plain(format!("local command: {e}")),
            },
            AsyncActionKind::Blocking("mouse.copy") => {
                self.apply_mouse_copy_action_result(result);
            }
            AsyncActionKind::Blocking("copy.file") => match result.payload {
                Ok(AsyncActionPayload::CopyToFile {
                    path,
                    bytes_written,
                    durability_confirmed: true,
                }) => {
                    self.show_toast(
                        format!("Wrote {bytes_written} bytes to {}", path.display()),
                        ToastKind::Success,
                    );
                }
                Ok(AsyncActionPayload::CopyToFile {
                    path,
                    bytes_written,
                    durability_confirmed: false,
                }) => {
                    // The file is genuinely on disk — this is not a failed
                    // copy — but the directory-fsync durability barrier did
                    // not confirm, so it is not an ordinary success either.
                    self.show_toast(
                        format!(
                            "Wrote {bytes_written} bytes to {} (durability unconfirmed — a crash before the next fsync could lose the directory entry; verify the file)",
                            path.display()
                        ),
                        ToastKind::Warning,
                    );
                }
                Ok(_) => self.show_toast(
                    "copy file: unexpected async response".to_string(),
                    ToastKind::Error,
                ),
                Err(e) => self.show_toast(format!("copy file: {e}"), ToastKind::Error),
            },
            #[cfg(test)]
            AsyncActionKind::Refresh("display.daemon.probe") => match result.payload {
                Ok(AsyncActionPayload::DaemonProbe { cwd, status }) => {
                    self.apply_display_daemon_probe_result(cwd, status);
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "display daemon probe failed");
                }
            },
            AsyncActionKind::Internal("oauth.acknowledge") => {
                if let Ok(AsyncActionPayload::OAuth {
                    client_flow_id,
                    operation_id,
                    result,
                }) = result.payload
                {
                    let Some(provider) = self.dialog.oauth_provider() else {
                        return;
                    };
                    let outcome = match result {
                        crate::tui::async_action::OAuthAsyncResult::Acknowledged => Ok(()),
                        crate::tui::async_action::OAuthAsyncResult::Failed(error)
                        | crate::tui::async_action::OAuthAsyncResult::AuthoritativeFailure(error) => {
                            Err(error)
                        }
                        crate::tui::async_action::OAuthAsyncResult::SettlementUnknown(error) => {
                            self.dialog.apply_oauth_acknowledgement_settlement_unknown(
                                provider,
                                client_flow_id,
                                operation_id,
                                error,
                            );
                            return;
                        }
                        _ => Err("unexpected OAuth acknowledgement result".into()),
                    };
                    self.dialog.apply_oauth_acknowledgement(
                        provider,
                        client_flow_id,
                        operation_id,
                        outcome,
                    );
                }
            }
            AsyncActionKind::Internal("oauth.codex.begin") => {
                let (client_flow_id, operation_id, payload) = match result.payload {
                    Ok(AsyncActionPayload::OAuth {
                        client_flow_id,
                        operation_id,
                        result:
                            crate::tui::async_action::OAuthAsyncResult::Began {
                                flow_id,
                                authorize_url,
                                user_code,
                            },
                    }) => (
                        client_flow_id,
                        operation_id,
                        Ok(settings::OAuthPublicBegin {
                            flow_id,
                            authorize_url,
                            user_code,
                        }),
                    ),
                    Ok(AsyncActionPayload::OAuth {
                        client_flow_id,
                        operation_id,
                        result:
                            crate::tui::async_action::OAuthAsyncResult::Failed(error)
                            | crate::tui::async_action::OAuthAsyncResult::AuthoritativeFailure(error),
                    }) => (client_flow_id, operation_id, Err(error)),
                    Ok(AsyncActionPayload::OAuth {
                        client_flow_id,
                        operation_id,
                        result: crate::tui::async_action::OAuthAsyncResult::SettlementUnknown(error),
                    }) => {
                        self.dialog.apply_oauth_settlement_unknown(
                            OAuthProvider::Codex,
                            client_flow_id,
                            operation_id,
                            error,
                        );
                        return;
                    }
                    _ => return,
                };
                self.dialog.apply_oauth_begin(
                    OAuthProvider::Codex,
                    client_flow_id,
                    operation_id,
                    OAuthBeginResult::Public(payload),
                );
            }
            AsyncActionKind::Internal("oauth.codex.poll") => {
                let (client_flow_id, operation_id, payload) = match result.payload {
                    Ok(AsyncActionPayload::OAuth {
                        client_flow_id,
                        operation_id,
                        result: crate::tui::async_action::OAuthAsyncResult::Completed { logged_in },
                    }) => (client_flow_id, operation_id, Ok(logged_in)),
                    Ok(AsyncActionPayload::OAuth {
                        client_flow_id,
                        operation_id,
                        result:
                            crate::tui::async_action::OAuthAsyncResult::Failed(error)
                            | crate::tui::async_action::OAuthAsyncResult::AuthoritativeFailure(error),
                    }) => (client_flow_id, operation_id, Err(error)),
                    Ok(AsyncActionPayload::OAuth {
                        client_flow_id,
                        operation_id,
                        result: crate::tui::async_action::OAuthAsyncResult::SettlementUnknown(error),
                    }) => {
                        self.dialog.apply_oauth_settlement_unknown(
                            OAuthProvider::Codex,
                            client_flow_id,
                            operation_id,
                            error,
                        );
                        return;
                    }
                    _ => return,
                };
                self.dialog.apply_oauth_complete(
                    OAuthProvider::Codex,
                    client_flow_id,
                    operation_id,
                    payload,
                );
            }
            AsyncActionKind::Internal("oauth.grok.begin") => {
                let (client_flow_id, operation_id, payload) = match result.payload {
                    Ok(AsyncActionPayload::OAuth {
                        client_flow_id,
                        operation_id,
                        result:
                            crate::tui::async_action::OAuthAsyncResult::Began {
                                flow_id,
                                authorize_url,
                                user_code,
                            },
                    }) => (
                        client_flow_id,
                        operation_id,
                        Ok(settings::OAuthPublicBegin {
                            flow_id,
                            authorize_url,
                            user_code,
                        }),
                    ),
                    Ok(AsyncActionPayload::OAuth {
                        client_flow_id,
                        operation_id,
                        result:
                            crate::tui::async_action::OAuthAsyncResult::Failed(error)
                            | crate::tui::async_action::OAuthAsyncResult::AuthoritativeFailure(error),
                    }) => (client_flow_id, operation_id, Err(error)),
                    Ok(AsyncActionPayload::OAuth {
                        client_flow_id,
                        operation_id,
                        result: crate::tui::async_action::OAuthAsyncResult::SettlementUnknown(error),
                    }) => {
                        self.dialog.apply_oauth_settlement_unknown(
                            OAuthProvider::Grok,
                            client_flow_id,
                            operation_id,
                            error,
                        );
                        return;
                    }
                    _ => return,
                };
                self.dialog.apply_oauth_begin(
                    OAuthProvider::Grok,
                    client_flow_id,
                    operation_id,
                    OAuthBeginResult::Public(payload),
                );
            }
            AsyncActionKind::Internal("oauth.grok.complete") => {
                let (client_flow_id, operation_id, payload) = match result.payload {
                    Ok(AsyncActionPayload::OAuth {
                        client_flow_id,
                        operation_id,
                        result: crate::tui::async_action::OAuthAsyncResult::Completed { logged_in },
                    }) => (client_flow_id, operation_id, Ok(logged_in)),
                    Ok(AsyncActionPayload::OAuth {
                        client_flow_id,
                        operation_id,
                        result:
                            crate::tui::async_action::OAuthAsyncResult::Failed(error)
                            | crate::tui::async_action::OAuthAsyncResult::AuthoritativeFailure(error),
                    }) => (client_flow_id, operation_id, Err(error)),
                    Ok(AsyncActionPayload::OAuth {
                        client_flow_id,
                        operation_id,
                        result: crate::tui::async_action::OAuthAsyncResult::SettlementUnknown(error),
                    }) => {
                        self.dialog.apply_oauth_settlement_unknown(
                            OAuthProvider::Grok,
                            client_flow_id,
                            operation_id,
                            error,
                        );
                        return;
                    }
                    _ => return,
                };
                self.dialog.apply_oauth_complete(
                    OAuthProvider::Grok,
                    client_flow_id,
                    operation_id,
                    payload,
                );
            }
            AsyncActionKind::Internal("oauth.host.present") => {
                if let Ok(AsyncActionPayload::OAuth {
                    client_flow_id,
                    operation_id,
                    result,
                }) = result.payload
                    && let Some(provider) = self.dialog.oauth_provider()
                {
                    let outcome = match result {
                        crate::tui::async_action::OAuthAsyncResult::Presented(payload) => {
                            Ok(payload)
                        }
                        crate::tui::async_action::OAuthAsyncResult::Failed(error)
                        | crate::tui::async_action::OAuthAsyncResult::AuthoritativeFailure(error) => {
                            Err(error)
                        }
                        crate::tui::async_action::OAuthAsyncResult::SettlementUnknown(error) => {
                            self.dialog.apply_oauth_settlement_unknown(
                                provider,
                                client_flow_id,
                                operation_id,
                                error,
                            );
                            return;
                        }
                        _ => Err("unexpected OAuth host result".into()),
                    };
                    self.dialog.apply_oauth_present(
                        provider,
                        client_flow_id,
                        operation_id,
                        outcome,
                    );
                }
            }
            AsyncActionKind::Internal("oauth.cancel") => {
                if let Ok(AsyncActionPayload::OAuth {
                    client_flow_id,
                    operation_id,
                    result,
                }) = result.payload
                    && let Some(provider) = self.dialog.oauth_provider()
                {
                    if let crate::tui::async_action::OAuthAsyncResult::AuthoritativeFailure(error) =
                        result
                    {
                        self.dialog.apply_oauth_cancel_authoritative_failure(
                            provider,
                            client_flow_id,
                            operation_id,
                            error,
                        );
                        return;
                    }
                    let outcome = match result {
                        crate::tui::async_action::OAuthAsyncResult::Cancelled => Ok(true),
                        crate::tui::async_action::OAuthAsyncResult::AlreadyTerminal => Ok(false),
                        crate::tui::async_action::OAuthAsyncResult::Failed(error) => Err(error),
                        _ => Err("unexpected OAuth cancellation result".into()),
                    };
                    self.dialog
                        .apply_oauth_cancel(provider, client_flow_id, operation_id, outcome);
                }
            }
            _ => self.completed_async_actions.push(result),
        }
    }

    fn settle_paste_probe(
        &mut self,
        request_id: uuid::Uuid,
        request_generation: u64,
        source_draft_generation: u64,
        cursor: usize,
        admission: Option<crate::tui::async_action::DaemonImagePathAdmission>,
        report_unavailable: bool,
    ) {
        if let Some(admission) = admission.as_ref() {
            let draft = crate::tui::composer::ImageIngressDraftAuthority {
                session_id: admission.session_id,
                admission_id: admission.admission_id,
                attachment_id: admission.image_ref.attachment_id,
                local_operation_id: admission.discard_operation_id,
            };
            self.image_ingress_draft_discards
                .entry(draft.admission_id)
                .or_insert((draft, false));
        }
        let Some(probe) = self.pending_paste_probes.remove(&request_id) else {
            return;
        };
        if probe.request.paste_generation != request_generation
            || probe.source_draft_generation != source_draft_generation
        {
            return;
        }
        let commit = self.paste_correlations.commit(
            request_id,
            request_generation,
            probe.request.host,
            self.event_loop_monotonic_now,
        );
        crate::tui::input_source::acknowledge_native_paste(request_id, commit);
        let Some(fence_id) = probe.owner_fence else {
            if source_draft_generation != self.draft_generation {
                return;
            }
            if let Some(admission) = admission {
                self.composer.set_cursor(cursor);
                self.insert_image_handle_block(admission);
            } else if report_unavailable {
                self.show_toast("Paste unavailable", ToastKind::Error);
            }
            return;
        };
        if admission.is_none() && report_unavailable {
            self.show_toast("Paste unavailable", ToastKind::Error);
        }
        let ready = if let Some(fence) = self.submission_fences.get_mut(&fence_id) {
            let result = admission.map(|admission| {
                (
                    "[image]".to_string(),
                    String::new(),
                    Some(crate::tui::structured_paste::PasteImageAdmission::Handle {
                        draft: crate::tui::composer::ImageIngressDraftAuthority {
                            session_id: admission.session_id,
                            admission_id: admission.admission_id,
                            attachment_id: admission.image_ref.attachment_id,
                            local_operation_id: admission.discard_operation_id,
                        },
                        image_ref: admission.image_ref,
                        normalized_byte_length: admission.normalized_byte_length,
                        sha256: admission.sha256,
                    }),
                )
            });
            let _ = fence.settle_slot(
                request_id,
                request_generation,
                source_draft_generation,
                result,
            );
            fence.lifecycle == crate::tui::structured_paste::FenceLifecycle::Ready
        } else {
            false
        };
        if ready {
            self.dispatch_ready_paste_fence(fence_id);
        }
    }

    fn dispatch_ready_paste_fence(&mut self, fence_id: uuid::Uuid) {
        if !matches!(
            self.submission_order.front(),
            Some((_, crate::tui::structured_paste::OrderedIntent::Fence(id))) if id == fence_id
        ) {
            return;
        }
        if self
            .deferred_fence_dispatches
            .get(&fence_id)
            .is_some_and(|dispatch| dispatch.waiting_model_selection.is_some())
        {
            return;
        }
        if !self.submission_fences.contains_key(&fence_id) {
            return;
        }
        let Some(mut deferred) = self.deferred_fence_dispatches.remove(&fence_id) else {
            return;
        };
        let Some(fence) = self.submission_fences.get_mut(&fence_id) else {
            return;
        };
        let mut resolved_images = Vec::new();
        for slot in &fence.slots {
            if let crate::tui::structured_paste::PasteSlotState::Ready {
                original_offset,
                image: Some(image),
                ..
            } = slot
            {
                resolved_images.push((*original_offset, image.clone()));
            }
        }
        resolved_images.sort_by_key(|(offset, _)| *offset);
        let positional_wire = deferred.submission.text == fence.captured_composer;
        let positional_display = deferred.display == fence.captured_composer;
        if !fence.model.supports_images {
            let first_note_number = deferred.submission.text.matches("[Pasted image #").count()
                + deferred.submission.images.len()
                + 1;
            let notes = resolved_images
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    format!(
                        "[Pasted image #{}: not sent — current model has no image support]",
                        first_note_number + index
                    )
                })
                .collect::<Vec<_>>();
            if positional_wire {
                for ((offset, _), note) in resolved_images.iter().zip(&notes).rev() {
                    let offset = floor_char_boundary(&deferred.submission.text, *offset);
                    deferred.submission.text.insert_str(offset, note);
                }
            } else {
                for note in &notes {
                    deferred.submission.text.push_str(note);
                }
            }
            if positional_display {
                for (offset, _) in resolved_images.iter().rev() {
                    let offset = floor_char_boundary(&deferred.display, *offset);
                    deferred.display.insert_str(offset, "[image]");
                }
            } else {
                for _ in &resolved_images {
                    deferred.display.push_str("[image]");
                }
            }
            resolved_images.clear();
        }
        if positional_wire {
            let original_wire = deferred.submission.text.clone();
            for (inserted, (offset, image)) in resolved_images.iter().enumerate() {
                let offset = floor_char_boundary(&original_wire, *offset);
                let existing_before = original_wire[..offset]
                    .matches(cockpit_proto::IMAGE_PART_SENTINEL)
                    .count();
                deferred.submission.images.insert(
                    existing_before + inserted,
                    match image {
                        crate::tui::structured_paste::PasteImageAdmission::Bytes(bytes) => {
                            cockpit_client::image_upload::SubmissionImage::png(bytes.clone())
                        }
                        crate::tui::structured_paste::PasteImageAdmission::Handle {
                            image_ref,
                            ..
                        } => cockpit_client::image_upload::SubmissionImage::retained(
                            image_ref.clone(),
                        ),
                    },
                );
            }
            for (offset, _) in resolved_images.iter().rev() {
                let offset = floor_char_boundary(&deferred.submission.text, *offset);
                deferred
                    .submission
                    .text
                    .insert_str(offset, cockpit_proto::IMAGE_PART_SENTINEL);
            }
        } else {
            for (_, image) in &resolved_images {
                deferred
                    .submission
                    .text
                    .push_str(cockpit_proto::IMAGE_PART_SENTINEL);
                deferred.submission.images.push(match image {
                    crate::tui::structured_paste::PasteImageAdmission::Bytes(bytes) => {
                        cockpit_client::image_upload::SubmissionImage::png(bytes.clone())
                    }
                    crate::tui::structured_paste::PasteImageAdmission::Handle {
                        image_ref, ..
                    } => cockpit_client::image_upload::SubmissionImage::retained(image_ref.clone()),
                });
            }
        }
        if positional_display {
            for (offset, _) in resolved_images.iter().rev() {
                let offset = floor_char_boundary(&deferred.display, *offset);
                deferred.display.insert_str(offset, "[image]");
            }
        } else {
            for _ in &resolved_images {
                deferred.display.push_str("[image]");
            }
        }
        if deferred.submission.text.trim().is_empty() && deferred.submission.images.is_empty() {
            fence.lifecycle = crate::tui::structured_paste::FenceLifecycle::NoPayload;
            let sequence = fence.fence_sequence;
            self.submission_fences.remove(&fence_id);
            let _ = self.submission_order.complete(sequence);
            self.dispatch_next_ready_paste_fence();
            return;
        }
        if let Err(message) =
            super::input::validate_pasted_images_for_submit(&deferred.submission.images)
        {
            let sequence = fence.fence_sequence;
            self.submission_fences.remove(&fence_id);
            let _ = self.submission_order.complete(sequence);
            self.show_toast(message, ToastKind::Error);
            self.dispatch_next_ready_paste_fence();
            return;
        }
        let sequence = fence.fence_sequence;
        let was_busy = self.busy;
        if was_busy && self.has_pending_session_switch_action() {
            let item = super::input::optimistic_queue_item_with_id(
                fence_id,
                deferred.submission.text.clone(),
                Some(deferred.display),
            );
            self.queue.push(item.clone());
            self.queue_pending_session_switch_submission_with_optimistic_state(
                deferred.submission,
                "engine",
                false,
                OptimisticSubmissionState {
                    id: fence_id,
                    tag_entries: 0,
                    history: Vec::new(),
                    queue_item: Some(item),
                },
            );
            let _ = self.submission_order.complete(sequence);
            self.dispatch_next_ready_paste_fence();
            return;
        }
        if was_busy {
            self.queue.push(super::input::optimistic_queue_item_with_id(
                fence_id,
                deferred.submission.text.clone(),
                Some(deferred.display.clone()),
            ));
        } else {
            self.begin_working_span();
            self.prompt_history.push(deferred.display.clone());
            self.prompt_history_cursor = 0;
            self.staged_draft = None;
        }
        let optimistic_history_start = self.history.len();
        let assembled_wire_digest =
            crate::tui::structured_paste::user_submission_wire_digest(&deferred.submission);
        let outcome = self.dispatch_optimistic_user_submission_with_id(
            fence_id,
            deferred.display,
            deferred.submission,
            "engine",
            !was_busy,
            &deferred.tag_expansions,
        );
        if outcome == DispatchOutcome::Sent
            && let Some(fence) = self.submission_fences.get_mut(&fence_id)
        {
            fence.assembled_wire_digest = Some(assembled_wire_digest);
            fence.lifecycle = crate::tui::structured_paste::FenceLifecycle::PossiblySent;
        }
        if was_busy {
            self.history
                .retain_terminal_notices_since(optimistic_history_start);
            if outcome != DispatchOutcome::Sent {
                self.queue.retain(|item| item.id != fence_id);
            }
        }
        let _ = self.submission_order.complete(sequence);
        self.dispatch_next_ready_paste_fence();
    }

    pub(super) fn dispatch_next_ready_paste_fence(&mut self) {
        let Some((_, crate::tui::structured_paste::OrderedIntent::Fence(id))) =
            self.submission_order.front()
        else {
            return;
        };
        if self.submission_fences.get(&id).is_some_and(|fence| {
            fence.lifecycle == crate::tui::structured_paste::FenceLifecycle::Ready
        }) {
            self.dispatch_ready_paste_fence(id);
        }
    }

    pub(super) fn drain_oauth_actions(&mut self) {
        while let Some(action) = self.dialog.take_oauth_action() {
            let provider = action.provider;
            let client_flow_id = action.client_flow_id;
            let operation_id = action.operation_id;
            let lifecycle = self.lifecycle.clone();
            match (action.provider, action.op) {
                (provider, OAuthFlowOp::Acknowledge) => {
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.acknowledge"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.acknowledge")),
                        async move {
                            let outcome = async {
                                let provider_id = match provider {
                                    OAuthProvider::Grok => {
                                        cockpit_core::auth::subscription_ack::GROK_OAUTH_PROVIDER
                                    }
                                    OAuthProvider::Codex => {
                                        cockpit_core::auth::subscription_ack::CODEX_OAUTH_PROVIDER
                                    }
                                };
                                let client = crate::tui::settings::settings_daemon_client(&lifecycle)
                                    .await
                                    .map_err(|e| e.to_string())?;
                                // Retrying acknowledgement for the same visible
                                // OAuth pane reuses the exact daemon operation.
                                let client_operation_id =
                                    client_flow_id.subscription_ack_operation_id();
                                let expected_hash =
                                    oauth_request_hash(&("put_subscription_ack", provider_id))?;
                                let request = cockpit_proto::Request::PutSubscriptionAck {
                                    client_operation_id: client_operation_id.clone(),
                                    provider_id: provider_id.to_string(),
                                };
                                let direct = tokio::time::timeout(
                                    std::time::Duration::from_secs(10),
                                    client.request(request),
                                )
                                .await;
                                let response = match direct {
                                    Ok(Ok(Ok(response))) => response,
                                    // A generic request error is not a typed
                                    // terminal receipt: the acknowledgement
                                    // may have committed before the transport
                                    // carried that error. Resolve every such
                                    // result through the durable settlement
                                    // journal before releasing TUI authority.
                                    Ok(Ok(Err(_))) | Ok(Err(_)) | Err(_) => {
                                        let settlement = match tokio::time::timeout(
                                            std::time::Duration::from_secs(10),
                                            client.request(cockpit_proto::Request::GetLocalOperationSettlement {
                                                client_operation_id: client_operation_id.clone(),
                                            }),
                                        )
                                        .await {
                                            Ok(Ok(Ok(response))) => response,
                                            Ok(Ok(Err(error))) => return Ok(oauth_settlement_unknown(error)),
                                            Ok(Err(error)) => return Ok(oauth_settlement_unknown(error)),
                                            Err(_) => return Ok(oauth_settlement_unknown(
                                                "acknowledgement settlement query timed out; retry to query the same durable operation",
                                            )),
                                        };
                                        match settlement {
                                            cockpit_proto::Response::LocalOperationSettlement {
                                                client_operation_id: returned_id,
                                                operation_kind,
                                                request_hash,
                                                pending: false,
                                                response: Some(response),
                                                terminal_error: None,
                                                terminal_cancelled: false,
                                            } if returned_id == client_operation_id
                                                && operation_kind == "put_subscription_ack"
                                                && request_hash == expected_hash => *response,
                                            cockpit_proto::Response::LocalOperationSettlement {
                                                client_operation_id: returned_id,
                                                operation_kind,
                                                request_hash,
                                                pending: false,
                                                terminal_error: Some(error),
                                                ..
                                            } if returned_id == client_operation_id
                                                && operation_kind == "put_subscription_ack"
                                                && request_hash == expected_hash => {
                                                return Ok(crate::tui::async_action::OAuthAsyncResult::AuthoritativeFailure(
                                                    format!("acknowledgement was authoritatively rejected: {error}"),
                                                ));
                                            }
                                            other => return Ok(oauth_settlement_unknown(format!(
                                                "acknowledgement settlement remains unknown or unbound; retry the same operation: {other:?}"
                                            ))),
                                        }
                                    }
                                };
                                match response {
                                    cockpit_proto::Response::SubscriptionAckCommitted {
                                        client_operation_id: returned_id,
                                        provider_id: returned_provider,
                                        request_hash,
                                        consumed_vault_generation,
                                        result_vault_generation,
                                        changed,
                                    } if returned_id == client_operation_id
                                        && returned_provider == provider_id
                                        && request_hash == expected_hash
                                        && result_vault_generation > 0
                                        && if changed { result_vault_generation > consumed_vault_generation } else { result_vault_generation == consumed_vault_generation } => {
                                        Ok(crate::tui::async_action::OAuthAsyncResult::Acknowledged)
                                    }
                                    other => Ok(oauth_settlement_unknown(format!(
                                        "acknowledgement receipt was malformed or unbound: {other:?}"
                                    ))),
                                }
                            }
                            .await;
                            Ok(oauth_payload(client_flow_id, operation_id, outcome))
                        },
                    );
                }
                (OAuthProvider::Codex, OAuthFlowOp::Begin) => {
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.codex.begin"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.codex")),
                        async move {
                            Ok(oauth_payload(
                                client_flow_id,
                                operation_id,
                                begin_provider_oauth(
                                    lifecycle,
                                    "codex-oauth",
                                    oauth_begin_operation_id(client_flow_id),
                                )
                                .await,
                            ))
                        },
                    );
                }
                (OAuthProvider::Codex, OAuthFlowOp::Poll { flow_id }) => {
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.codex.poll"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.codex")),
                        async move {
                            Ok(oauth_payload(
                                client_flow_id,
                                operation_id,
                                complete_provider_oauth(
                                    lifecycle,
                                    oauth_operation_id(client_flow_id, "complete"),
                                    flow_id,
                                    None,
                                )
                                .await,
                            ))
                        },
                    );
                }
                (OAuthProvider::Grok, OAuthFlowOp::Begin) => {
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.grok.begin"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.grok")),
                        async move {
                            Ok(oauth_payload(
                                client_flow_id,
                                operation_id,
                                begin_provider_oauth(
                                    lifecycle,
                                    "grok-oauth",
                                    oauth_begin_operation_id(client_flow_id),
                                )
                                .await,
                            ))
                        },
                    );
                }
                (OAuthProvider::Grok, OAuthFlowOp::Complete { flow_id, input }) => {
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.grok.complete"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.grok")),
                        async move {
                            Ok(oauth_payload(
                                client_flow_id,
                                operation_id,
                                complete_provider_oauth(
                                    lifecycle,
                                    oauth_operation_id(client_flow_id, "complete"),
                                    flow_id,
                                    Some(input),
                                )
                                .await,
                            ))
                        },
                    );
                }
                (
                    _,
                    OAuthFlowOp::Present {
                        authorize_url,
                        user_code,
                        open_browser,
                        advance_flow,
                    },
                ) => {
                    let key = match provider {
                        OAuthProvider::Codex => "oauth.codex",
                        OAuthProvider::Grok => "oauth.grok",
                    };
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.host.present"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new(key)),
                        async move {
                            let worker = tokio::task::spawn_blocking(move || {
                                settings::providers::present_oauth_on_blocking_worker(
                                    authorize_url,
                                    user_code,
                                    open_browser,
                                    advance_flow,
                                )
                            });
                            let result = match tokio::time::timeout(OAUTH_HOST_TIMEOUT, worker)
                                .await
                            {
                                Ok(Ok(result)) => result
                                    .map(crate::tui::async_action::OAuthAsyncResult::Presented),
                                Ok(Err(error)) => Err(format!("OAuth host worker failed: {error}")),
                                Err(_) => Err("OAuth browser/clipboard operation timed out".into()),
                            };
                            Ok(oauth_payload(client_flow_id, operation_id, result))
                        },
                    );
                }
                (_, OAuthFlowOp::Cancel { flow_id }) => {
                    let key = match provider {
                        OAuthProvider::Codex => AsyncActionKey::new("oauth.codex"),
                        OAuthProvider::Grok => AsyncActionKey::new("oauth.grok"),
                    };
                    self.async_actions.abort_key(&key);
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.cancel"),
                        AsyncActionPolicy::Replace(key),
                        async move {
                            Ok(oauth_payload(
                                client_flow_id,
                                operation_id,
                                cancel_provider_oauth(
                                    lifecycle,
                                    oauth_operation_id(client_flow_id, "cancel"),
                                    oauth_begin_operation_id(client_flow_id),
                                    flow_id,
                                )
                                .await,
                            ))
                        },
                    );
                }
                (OAuthProvider::Codex, OAuthFlowOp::Complete { .. })
                | (OAuthProvider::Grok, OAuthFlowOp::Poll { .. }) => {}
            }
        }
    }

    pub(super) fn start_resources_snapshot_action(&mut self) {
        let Overlay::Resources(pane) = &self.overlay else {
            return;
        };
        let pane_generation = pane.generation();
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start_serialized(
            AsyncActionKind::DaemonRpc("resources.snapshot"),
            AsyncActionKey::new("resources.projection"),
            async move {
                let result = tokio::task::spawn_blocking(move || {
                    match crate::tui::agent_runner::resource_snapshot_blocking(lifecycle)? {
                        cockpit_proto::Response::ResourceSnapshot { snapshot } => Ok(snapshot),
                        other => Err(format!("unexpected resource_snapshot response: {other:?}")),
                    }
                })
                .await
                .map_err(|error| format!("resources.snapshot worker failed: {error}"))
                .and_then(|result| result);
                Ok(AsyncActionPayload::ResourceSnapshot {
                    pane_generation,
                    result,
                })
            },
        );
    }

    pub(super) fn start_resource_promote_action(&mut self, request_id: uuid::Uuid) {
        let session_id = self.current_session_id();
        let request = crate::tui::agent_runner::promote_resource_request(request_id, session_id);
        self.start_resource_promote_request_action(request);
    }

    pub(super) fn start_resource_promote_token_action(&mut self, request_id: String) {
        let session_id = self.current_session_id();
        let request =
            crate::tui::agent_runner::promote_resource_token_request(request_id, session_id);
        self.start_resource_promote_request_action(request);
    }

    fn start_resource_promote_request_action(&mut self, request: cockpit_proto::Request) {
        let pane_generation = match &self.overlay {
            Overlay::Resources(pane) => Some(pane.generation()),
            _ => None,
        };
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start_serialized(
            AsyncActionKind::DaemonRpc("resources.promote"),
            AsyncActionKey::new("resources.projection"),
            async move {
                tokio::task::spawn_blocking(move || {
                    match crate::tui::agent_runner::promote_resource_blocking(lifecycle, request)? {
                        cockpit_proto::Response::PromoteResourceResult {
                            status,
                            message,
                            snapshot,
                        } => Ok(AsyncActionPayload::PromoteResource {
                            pane_generation,
                            status,
                            message,
                            snapshot,
                        }),
                        other => Err(format!("unexpected promote_resource response: {other:?}")),
                    }
                })
                .await
                .map_err(|error| format!("resources.promote worker failed: {error}"))?
            },
        );
    }

    pub(super) fn start_resources_outcome(
        &mut self,
        outcome: crate::tui::resources_pane::ResourcesOutcome,
    ) {
        match outcome {
            crate::tui::resources_pane::ResourcesOutcome::Close => self.overlay = Overlay::None,
            crate::tui::resources_pane::ResourcesOutcome::Refresh => {
                self.start_resources_snapshot_action();
            }
            crate::tui::resources_pane::ResourcesOutcome::Promote(request_id) => {
                self.start_resource_promote_action(request_id);
            }
        }
    }

    pub(super) fn sessions_daemon_socket(&self) -> Option<&Path> {
        self.agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok().map(|runner| runner.socket.as_path()))
            .or(self.startup_background.daemon_socket.as_deref())
    }

    /// The daemon-resolved git worktree root for the launch cwd, if the
    /// background resolver (`spawn_worktree_root_resolve`) has populated it.
    /// `None` when the cwd is not in a repo or has not been resolved yet.
    /// Panes read this instead of shelling out to git themselves.
    pub(super) fn resolved_worktree_root(&self) -> Option<std::path::PathBuf> {
        self.worktree_root
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().cloned())
    }

    pub(super) fn sessions_daemon_endpoint(&self) -> Option<cockpit_client::ClientEndpoint> {
        self.attached_daemon_endpoint()
    }

    pub(super) fn start_sessions_list_action(&mut self) {
        let Overlay::Sessions(pane) = &self.overlay else {
            return;
        };
        let (project_id, parent) = pane.root_request();
        let endpoint = self.sessions_daemon_endpoint();
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("sessions.list"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("sessions.list")),
            move || {
                let endpoint = endpoint
                    .ok_or_else(|| "daemon endpoint unavailable for sessions.list".to_string())?;
                crate::tui::agent_runner::list_sessions_blocking(&endpoint, project_id, parent)
                    .map(AsyncActionPayload::Sessions)
            },
        );
    }

    pub(super) fn start_sessions_live_status_action(&mut self, ids: Vec<uuid::Uuid>) {
        let endpoint = self.sessions_daemon_endpoint();
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("sessions.live"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("sessions.live")),
            move || {
                let endpoint = endpoint
                    .ok_or_else(|| "daemon endpoint unavailable for sessions.live".to_string())?;
                Ok(AsyncActionPayload::SessionLiveStatus(
                    crate::tui::agent_runner::session_live_status_blocking(&endpoint, ids),
                ))
            },
        );
    }

    pub(super) fn start_sessions_preview_action(
        &mut self,
        session_id: uuid::Uuid,
        before_seq: Option<i64>,
    ) {
        let endpoint = self.sessions_daemon_endpoint();
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("sessions.preview"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("sessions.preview")),
            move || {
                let endpoint = endpoint.ok_or_else(|| {
                    "daemon endpoint unavailable for sessions.preview".to_string()
                })?;
                let (messages, has_more) =
                    crate::tui::agent_runner::read_session_messages_blocking(
                        &endpoint, session_id, before_seq, 50,
                    )?;
                Ok(AsyncActionPayload::SessionMessages {
                    session_id,
                    before_seq,
                    messages,
                    has_more,
                })
            },
        );
    }

    pub(super) fn start_sessions_inbox_action(&mut self, main_session_id: uuid::Uuid) {
        let endpoint = self.sessions_daemon_endpoint();
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("sessions.inbox"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("sessions.inbox")),
            move || {
                let endpoint = endpoint
                    .ok_or_else(|| "daemon endpoint unavailable for sessions.inbox".to_string())?;
                let items = crate::tui::agent_runner::read_assistant_inbox_blocking(
                    &endpoint,
                    main_session_id,
                )?;
                Ok(AsyncActionPayload::AssistantInbox {
                    main_session_id,
                    items,
                })
            },
        );
    }

    pub(super) fn start_provider_usage_action(&mut self, args: String) {
        let filter = args.split_whitespace().next().map(str::to_string);
        let cwd = self.launch.cwd.clone();
        let lifecycle = self.lifecycle.clone();
        self.overlay = Overlay::Usage(crate::tui::usage_pane::UsagePane::loading());
        let pane_generation = match &self.overlay {
            Overlay::Usage(pane) => pane.generation(),
            _ => unreachable!(),
        };
        self.async_actions.start(
            AsyncActionKind::Refresh("provider.usage"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("provider.usage")),
            async move {
                let result = async {
                    let client = crate::tui::settings::settings_daemon_client(&lifecycle)
                        .await
                        .map_err(|e| e.to_string())?;
                    match client
                        .request(cockpit_proto::Request::GetProviderUsageSnapshot {
                            project_root: cwd.display().to_string(),
                            provider_id: filter,
                        })
                        .await
                        .map_err(|e| e.to_string())?
                    {
                        Ok(cockpit_proto::Response::ProviderUsageSnapshot { snapshots }) => {
                            Ok(snapshots)
                        }
                        Ok(other) => Err(format!(
                            "unexpected provider usage daemon response: {other:?}"
                        )),
                        Err(error) => Err(error.to_string()),
                    }
                }
                .await;
                Ok(AsyncActionPayload::ProviderUsage {
                    pane_generation,
                    result,
                })
            },
        );
    }

    pub(super) fn start_stats_rollup_action(
        &mut self,
        key: crate::tui::stats_pane::StatsPaneFetchKey,
    ) {
        let endpoint = self.attached_daemon_endpoint();
        self.async_actions.start_blocking(
            AsyncActionKind::Refresh("stats.rollup"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("stats.rollup")),
            move || {
                Ok(AsyncActionPayload::StatsRollup(
                    crate::tui::stats_pane::fetch_stats_rollup(endpoint.as_ref(), key),
                ))
            },
        );
    }

    pub(super) fn start_git_diff_action(
        &mut self,
        operation_id: uuid::Uuid,
        source: crate::tui::diff_pane::DiffSource,
    ) {
        let (project_root, source_wire) = match &self.overlay {
            Overlay::Diff(pane) => (
                pane.project_root().display().to_string(),
                match source {
                    crate::tui::diff_pane::DiffSource::Worktree => {
                        cockpit_proto::GitReadSource::Worktree
                    }
                    crate::tui::diff_pane::DiffSource::Staged => {
                        cockpit_proto::GitReadSource::Staged
                    }
                    crate::tui::diff_pane::DiffSource::Last => return,
                },
            ),
            _ => return,
        };
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start(
            AsyncActionKind::DaemonRpc("git.diff"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("git.diff")),
            async move {
                let result = async {
                    let client = crate::tui::settings::settings_daemon_client(&lifecycle)
                        .await
                        .map_err(|error| error.to_string())?;
                    match client
                        .request(cockpit_proto::Request::GitDiff {
                            project_root,
                            source: source_wire.clone(),
                        })
                        .await
                        .map_err(|error| format!("daemon request: {error}"))?
                    {
                        Ok(cockpit_proto::Response::GitDiff {
                            source: returned_source,
                            diff,
                            truncated,
                        }) if returned_source == source_wire => {
                            if truncated {
                                Err("git diff exceeded the daemon response limit".to_string())
                            } else {
                                Ok(diff)
                            }
                        }
                        Ok(other) => Err(format!("unexpected git_diff response: {other:?}")),
                        Err(error) => Err(error.message),
                    }
                }
                .await;
                Ok(AsyncActionPayload::GitDiff(
                    crate::tui::diff_pane::DiffPaneFetchResult {
                        operation_id,
                        source,
                        result,
                    },
                ))
            },
        );
    }

    pub(super) fn start_git_review_sources_action(
        &mut self,
        operation_id: uuid::Uuid,
        sources: Vec<cockpit_proto::GitReadSource>,
    ) {
        let project_root = match &self.overlay {
            Overlay::Multireview(dialog) => dialog.project_root().display().to_string(),
            _ => return,
        };
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start(
            AsyncActionKind::DaemonRpc("git.review_sources"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("git.review_sources")),
            async move {
                let result = async {
                    let client = crate::tui::settings::settings_daemon_client(&lifecycle)
                        .await
                        .map_err(|error| error.to_string())?;
                    match client
                        .request(cockpit_proto::Request::GitReviewSources {
                            project_root,
                            sources,
                        })
                        .await
                        .map_err(|error| format!("daemon request: {error}"))?
                    {
                        Ok(cockpit_proto::Response::GitReviewSources { sources }) => Ok(sources),
                        Ok(other) => {
                            Err(format!("unexpected git_review_sources response: {other:?}"))
                        }
                        Err(error) => Err(error.message),
                    }
                }
                .await;
                Ok(AsyncActionPayload::GitReviewSources(
                    crate::tui::multireview_dialog::GitReviewSourcesCompletion {
                        operation_id,
                        result,
                    },
                ))
            },
        );
    }

    pub(super) fn sync_repo_status(&mut self) -> bool {
        if let Ok(guard) = self.repo_status.lock()
            && self.launch.repo_status != *guard
        {
            self.launch.repo_status = guard.clone();
            return true;
        }
        false
    }
}

fn stale_completion_requires_reducer(kind: &AsyncActionKind) -> bool {
    matches!(
        kind,
        AsyncActionKind::Blocking(
            "btw.teardown" | "paste.delivery_receipt" | "queue.edit" | "settings.blocking-effect"
        ) | AsyncActionKind::DaemonRpc(
            "assistant.resolve"
                | "btw.resolve-interrupt"
                | "fork.create"
                | "goal-settings.effect"
                | "mcp.local"
                | "paste.image_path_admission"
                | "queue.control"
                | "queue.edit.commit"
                | "queue.edit.release"
                | "queue.edit.reservation"
                | "resources.promote"
                | "sealed.effect"
                | "sessions.mutation"
                | "settings.effect"
                | "side.discard"
                | "side.start"
                | "subagent.steer"
                | "tools.effect"
                | "workspace-trust.effect"
        ) | AsyncActionKind::NotesProjection { .. }
            | AsyncActionKind::Internal(
                "btw.runner.attach"
                    | "leaks.rpc"
                    | "oauth.acknowledge"
                    | "oauth.cancel"
                    | "oauth.codex.begin"
                    | "oauth.codex.poll"
                    | "oauth.grok.begin"
                    | "oauth.grok.complete"
                    | "pins.pin"
                    | "pins.toggle"
                    | "pins.unpin"
                    | "runner.attach"
                    | "session.fork"
                    | "session.resume"
                    | "session.side"
                    | "session.side.return"
                    | "session.switch"
            )
    )
}

#[cfg(test)]
mod startup_disclosure_generation_tests {
    use super::{StartupDisclosureIdentity, startup_disclosure_completion_is_current};
    use std::path::Path;
    use uuid::Uuid;

    #[test]
    fn stale_or_detached_disclosure_completions_are_rejected_for_same_project() {
        fn identity<'a>(
            project_root: &'a str,
            generation: u64,
            socket: Option<&'a Path>,
            launch_session_id: Option<Uuid>,
            attachment: Option<(Uuid, u64)>,
        ) -> StartupDisclosureIdentity<'a> {
            StartupDisclosureIdentity {
                project_root,
                generation,
                socket,
                launch_session_id,
                attachment,
            }
        }

        let session = Uuid::new_v4();
        let current = Some((session, 4));
        let socket = Some(Path::new("/tmp/cockpit.sock"));
        let completed = identity("/repo", 8, socket, Some(session), current);
        assert!(startup_disclosure_completion_is_current(
            completed, completed
        ));
        assert!(!startup_disclosure_completion_is_current(
            identity("/repo", 9, socket, Some(session), current),
            completed,
        ));
        assert!(!startup_disclosure_completion_is_current(
            identity("/repo", 8, socket, Some(session), None),
            completed,
        ));
        assert!(!startup_disclosure_completion_is_current(
            identity("/repo", 8, socket, Some(session), Some((session, 5))),
            completed,
        ));
        assert!(!startup_disclosure_completion_is_current(
            identity(
                "/repo",
                8,
                Some(Path::new("/tmp/replacement.sock")),
                Some(session),
                current,
            ),
            completed,
        ));
        assert!(!startup_disclosure_completion_is_current(
            identity("/repo", 8, socket, None, current),
            completed,
        ));
    }
}

#[cfg(test)]
mod oauth_settlement_source_tests {
    #[test]
    fn oauth_fallbacks_are_bounded_and_already_terminal_is_not_called_cancelled() {
        let source = include_str!("async_actions.rs");
        assert!(source.contains("OAUTH_SETTLEMENT_TIMEOUT"));
        assert!(source.contains("oauth_settlement(&client"));
        assert!(source.contains("OAuthAsyncResult::AlreadyTerminal"));
        assert!(source.contains("OAuthAsyncResult::AlreadyTerminal => Ok(false)"));
        assert!(source.contains("result: Result<bool, String>"));
        assert!(source.contains("operation_kind == \"cancel_provider_oauth\""));
        assert!(source.contains("Ok(Ok("));
        assert!(source.contains("receipt was malformed or unbound"));
        assert!(source.contains("request_hash == expected_hash"));
        assert!(source.contains("acknowledgement settlement remains unknown or unbound"));
    }
}
