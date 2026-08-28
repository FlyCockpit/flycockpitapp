//! jsonrpsee inbound method dispatch for the ACP v1 peer.
//!
//! Cockpit's parser gates each frame and retains raw `params`; the admitted
//! request is then routed through jsonrpsee's raw-request dispatch API. The
//! production transport deliberately has no session ingress owner yet, so its
//! session methods fail closed. Tests can inject a recording owner to exercise
//! the DTO-to-bridge conversion seam without pretending that a daemon API
//! exists.

use std::sync::{Arc, Mutex};

use jsonrpsee::RpcModule;
use jsonrpsee_types::{ErrorObjectOwned, Params};

use super::AcpTransportCounters;
use super::classify::InboundRequest;
use super::dto::{SessionAdmissionDto, decode_session_load, decode_session_new, initialize_result};
use super::raw_json::parse_frame;

/// If this fails to type-check, return the transport-selection prompt.
const JSONRPSEE_RAW_PARAMS_API: fn(&Params<'_>) -> Option<&str> = Params::as_str;

const INBOUND_METHODS: &[&str] = &[
    "initialize",
    "session/new",
    "session/load",
    "session/cancel",
    "session/prompt",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionIngressError {
    Unavailable,
}

impl SessionIngressError {
    fn message(self) -> &'static str {
        match self {
            Self::Unavailable => "ACP session adaptation is unavailable",
        }
    }
}

/// The deliberately narrow downstream boundary. No production implementation
/// is supplied until editor-session adaptation and its daemon API are owned.
pub trait SessionIngress: Send {
    fn is_available(&self) -> bool;

    fn admit(
        &mut self,
        admission: SessionAdmissionDto,
        counters: &mut AcpTransportCounters,
    ) -> Result<serde_json::Value, SessionIngressError>;

    fn cancel(
        &mut self,
        raw_params: &str,
        counters: &mut AcpTransportCounters,
    ) -> Result<serde_json::Value, SessionIngressError>;

    fn prompt(
        &mut self,
        raw_params: &str,
        counters: &mut AcpTransportCounters,
    ) -> Result<serde_json::Value, SessionIngressError>;
}

/// The only production owner until the out-of-scope daemon adaptation lands.
#[derive(Debug, Default)]
pub struct UnavailableSessionIngress;

impl SessionIngress for UnavailableSessionIngress {
    fn is_available(&self) -> bool {
        false
    }

    fn admit(
        &mut self,
        _admission: SessionAdmissionDto,
        _counters: &mut AcpTransportCounters,
    ) -> Result<serde_json::Value, SessionIngressError> {
        Err(SessionIngressError::Unavailable)
    }

    fn cancel(
        &mut self,
        _raw_params: &str,
        _counters: &mut AcpTransportCounters,
    ) -> Result<serde_json::Value, SessionIngressError> {
        Err(SessionIngressError::Unavailable)
    }

    fn prompt(
        &mut self,
        _raw_params: &str,
        _counters: &mut AcpTransportCounters,
    ) -> Result<serde_json::Value, SessionIngressError> {
        Err(SessionIngressError::Unavailable)
    }
}

pub struct DispatchContext<I: SessionIngress> {
    counters: Mutex<AcpTransportCounters>,
    session_ingress: Arc<Mutex<I>>,
    raw_params: Option<String>,
}

pub fn build_rpc_module() -> RpcModule<DispatchContext<UnavailableSessionIngress>> {
    build_rpc_module_with_ingress(Arc::new(Mutex::new(UnavailableSessionIngress)))
}

pub fn build_rpc_module_with_ingress<I: SessionIngress + 'static>(
    session_ingress: Arc<Mutex<I>>,
) -> RpcModule<DispatchContext<I>> {
    build_rpc_module_from_arc(Arc::new(DispatchContext {
        counters: Mutex::new(AcpTransportCounters::default()),
        session_ingress,
        raw_params: None,
    }))
}

fn build_rpc_module_from_arc<I: SessionIngress + 'static>(
    context: Arc<DispatchContext<I>>,
) -> RpcModule<DispatchContext<I>> {
    let mut module = RpcModule::from_arc(context);
    module
        .register_method("initialize", |params, _, _| {
            let _ = JSONRPSEE_RAW_PARAMS_API(&params);
            Ok::<_, ErrorObjectOwned>(initialize_result())
        })
        .expect("initialize is unique");
    module
        .register_method("session/new", |params, context, _| {
            let raw = required_raw_params(&params, context)?;
            ensure_session_ingress_available(context)?;
            let parsed = parse_frame(&raw).map_err(|err| invalid_params(err.to_string()))?;
            let mut counters = context.counters.lock().expect("dispatch counters");
            let dto = decode_session_new(&raw, &parsed.root, &mut counters)
                .map_err(|err| invalid_params(err.to_string()))?;
            context
                .session_ingress
                .lock()
                .expect("session ingress")
                .admit(SessionAdmissionDto::New(dto), &mut counters)
                .map_err(ingress_error)
        })
        .expect("session/new is unique");
    module
        .register_method("session/load", |params, context, _| {
            let raw = required_raw_params(&params, context)?;
            ensure_session_ingress_available(context)?;
            let parsed = parse_frame(&raw).map_err(|err| invalid_params(err.to_string()))?;
            let mut counters = context.counters.lock().expect("dispatch counters");
            let dto = decode_session_load(&raw, &parsed.root, &mut counters)
                .map_err(|err| invalid_params(err.to_string()))?;
            context
                .session_ingress
                .lock()
                .expect("session ingress")
                .admit(SessionAdmissionDto::Load(dto), &mut counters)
                .map_err(ingress_error)
        })
        .expect("session/load is unique");
    module
        .register_method("session/cancel", |params, context, _| {
            let raw = required_raw_params(&params, context)?;
            ensure_session_ingress_available(context)?;
            let mut counters = context.counters.lock().expect("dispatch counters");
            context
                .session_ingress
                .lock()
                .expect("session ingress")
                .cancel(&raw, &mut counters)
                .map_err(ingress_error)
        })
        .expect("session/cancel is unique");
    module
        .register_method("session/prompt", |params, context, _| {
            let raw = required_raw_params(&params, context)?;
            ensure_session_ingress_available(context)?;
            let mut counters = context.counters.lock().expect("dispatch counters");
            context
                .session_ingress
                .lock()
                .expect("session ingress")
                .prompt(&raw, &mut counters)
                .map_err(ingress_error)
        })
        .expect("session/prompt is unique");
    module
}

fn required_raw_params<I: SessionIngress>(
    params: &Params<'_>,
    context: &DispatchContext<I>,
) -> Result<String, ErrorObjectOwned> {
    context
        .raw_params
        .clone()
        .or_else(|| JSONRPSEE_RAW_PARAMS_API(params).map(str::to_string))
        .ok_or_else(|| invalid_params("params required"))
}

fn invalid_params(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, message.into(), None::<()>)
}

fn ensure_session_ingress_available<I: SessionIngress>(
    context: &DispatchContext<I>,
) -> Result<(), ErrorObjectOwned> {
    if context
        .session_ingress
        .lock()
        .expect("session ingress")
        .is_available()
    {
        Ok(())
    } else {
        Err(ingress_error(SessionIngressError::Unavailable))
    }
}

fn ingress_error(error: SessionIngressError) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32601, error.message(), None::<()>)
}

pub fn registered_method_names() -> Vec<&'static str> {
    INBOUND_METHODS.to_vec()
}

pub fn is_session_method(method: &str) -> bool {
    matches!(
        method,
        "session/new" | "session/load" | "session/cancel" | "session/prompt"
    )
}

/// `session/new`, `session/load`, and `session/prompt` are JSON-RPC requests.
/// A notification with those method names is not an admission or prompt path.
pub fn is_request_only_session_method(method: &str) -> bool {
    matches!(method, "session/new" | "session/load" | "session/prompt")
}

pub fn elicitation_is_rejected(method: &str) -> bool {
    matches!(
        method,
        "elicitation/create" | "elicitation/complete" | "elicitation.form"
    )
}

pub enum DispatchResult {
    Response(String),
    NotificationHandled,
    NoResponse,
}

pub fn dispatch_request<I: SessionIngress + 'static>(
    request: &InboundRequest,
    session_ingress: Arc<Mutex<I>>,
    counters: &mut AcpTransportCounters,
) -> DispatchResult {
    let context = Arc::new(DispatchContext {
        counters: Mutex::new(AcpTransportCounters::default()),
        session_ingress,
        raw_params: request.raw_params.clone(),
    });
    let module = build_rpc_module_from_arc(Arc::clone(&context));
    let response = futures::executor::block_on(module.raw_json_request(&request.raw, 1));
    let Ok((response, _notifications)) = response else {
        return DispatchResult::NoResponse;
    };
    let dispatch_counters = context.counters.lock().expect("dispatch counters").clone();
    counters.daemon_mutations += dispatch_counters.daemon_mutations;
    counters.bridge_conversions += dispatch_counters.bridge_conversions;
    counters.catalog_mutations += dispatch_counters.catalog_mutations;
    counters.dto_produced += dispatch_counters.dto_produced;
    counters.schema_decode_attempts += dispatch_counters.schema_decode_attempts;
    DispatchResult::Response(response)
}

/// Notifications are not rewritten into jsonrpsee requests. Admission
/// (`session/new`, `session/load`) and `session/prompt` are request-only.
pub fn dispatch_notification<I: SessionIngress + 'static>(
    method: &str,
    raw: &str,
    session_ingress: Arc<Mutex<I>>,
    counters: &mut AcpTransportCounters,
) -> DispatchResult {
    if method == "$/cancel_request" {
        return DispatchResult::NotificationHandled;
    }
    if is_request_only_session_method(method) {
        return DispatchResult::NoResponse;
    }
    if method != "session/cancel" {
        return DispatchResult::NoResponse;
    }
    let Ok(parsed) = parse_frame(raw) else {
        return DispatchResult::NoResponse;
    };
    let Some(raw_params) = parsed.root.member("params").map(|node| node.raw(raw)) else {
        return DispatchResult::NoResponse;
    };
    let mut local_counters = AcpTransportCounters::default();
    let mut ingress = session_ingress.lock().expect("session ingress");
    if !ingress.is_available() {
        return DispatchResult::NoResponse;
    }
    let result = ingress.cancel(raw_params, &mut local_counters);
    counters.daemon_mutations += local_counters.daemon_mutations;
    counters.bridge_conversions += local_counters.bridge_conversions;
    counters.catalog_mutations += local_counters.catalog_mutations;
    counters.dto_produced += local_counters.dto_produced;
    counters.schema_decode_attempts += local_counters.schema_decode_attempts;
    match result {
        Ok(_) => DispatchResult::NotificationHandled,
        Err(_) => DispatchResult::NoResponse,
    }
}
