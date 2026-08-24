//! Remote-only daemon ingress and dispatch authority.
//!
//! This module is compiled only for the opt-in `remote` profile. Keeping the
//! authenticated operation identity here prevents the local server surface
//! from growing a transport-derived authority type.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoteOperationContext {
    pub(super) request_id: Uuid,
    pub(super) logical_attachment_id: Uuid,
    pub(super) operation_id: Uuid,
    pub(super) authenticated_device_id: Uuid,
    pub(super) authenticated_device_generation: u64,
}

fn denied() -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Authorization,
        message: "remote operations require a valid server-authenticated actor binding and operation identity"
            .to_string(),
    }
}

pub(super) fn admit(
    principal: &ClientPrincipal,
    request_id: Uuid,
    operation: Option<proto::RemoteOperationIdentityV1>,
    request: &Request,
) -> std::result::Result<Option<RemoteOperationContext>, ErrorPayload> {
    if principal.is_owner() {
        return Ok(None);
    }
    let class = request.remote_operation_class().map_err(|_| denied())?;
    if class == proto::RemoteOperationClass::ReadOnly && operation.is_none() {
        return Ok(None);
    }
    let ClientPrincipal::Remote(remote) = principal else {
        unreachable!("owner principal returned above")
    };
    if remote.actor_binding.is_none() {
        return Ok(None);
    }
    let (Some(actor), Some(operation)) = (remote.actor_binding.as_ref(), operation) else {
        return Err(denied());
    };
    let operation_valid = operation.schema_version == 1
        && !operation.logical_attachment_id.is_nil()
        && operation.logical_attachment_id.get_variant() == uuid::Variant::RFC4122
        && !operation.operation_id.is_nil()
        && operation.operation_id.get_variant() == uuid::Variant::RFC4122
        && operation.operation_id.get_version_num() == 7;
    let actor_valid = actor.schema_version == 1
        && actor.device_generation > 0
        && !actor.device_id.is_nil()
        && actor.device_id.get_variant() == uuid::Variant::RFC4122
        && !actor.logical_attachment_id.is_nil()
        && actor.logical_attachment_id.get_variant() == uuid::Variant::RFC4122;
    if !operation_valid
        || !actor_valid
        || actor.logical_attachment_id != operation.logical_attachment_id
    {
        return Err(denied());
    }
    Ok(Some(RemoteOperationContext {
        request_id,
        logical_attachment_id: operation.logical_attachment_id,
        operation_id: operation.operation_id,
        authenticated_device_id: actor.device_id,
        authenticated_device_generation: actor.device_generation,
    }))
}
