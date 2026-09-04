//! Remote-only daemon ingress and dispatch authority.
//!
//! This module is compiled only for the opt-in `remote` profile. Keeping the
//! authenticated operation identity here prevents the local server surface
//! from growing a transport-derived authority type.

use super::*;

#[derive(Debug)]
pub(crate) struct RemoteOperationContext {
    pub(super) request_id: Uuid,
    pub(super) logical_attachment_id: Uuid,
    pub(super) operation_id: Uuid,
    pub(super) authenticated_device_id: Uuid,
    pub(super) authenticated_device_generation: u64,
    // Held from ingress until the response has been committed or rejected.
    // The key deliberately excludes request class/hash so cross-class reuse
    // cannot race an irreversible effect.
    _identity_guard: tokio::sync::OwnedMutexGuard<()>,
}

#[cfg(test)]
impl RemoteOperationContext {
    /// Construct a test identity with the same owned serialization guard held
    /// by live ingress. Tests must not manufacture an authority value which
    /// omits the production guard invariant.
    pub(crate) async fn for_test(
        request_id: Uuid,
        logical_attachment_id: Uuid,
        operation_id: Uuid,
        authenticated_device_id: Uuid,
        authenticated_device_generation: u64,
    ) -> Self {
        let identity_guard = Arc::new(tokio::sync::Mutex::new(())).lock_owned().await;
        Self {
            request_id,
            logical_attachment_id,
            operation_id,
            authenticated_device_id,
            authenticated_device_generation,
            _identity_guard: identity_guard,
        }
    }
}

fn denied() -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Authorization,
        message: "remote operations require a valid server-authenticated actor binding and operation identity"
            .to_string(),
    }
}

pub(super) async fn admit(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    request_id: Uuid,
    operation: Option<proto::RemoteOperationIdentityV1>,
    request: &Request,
) -> std::result::Result<Option<RemoteOperationContext>, ErrorPayload> {
    if principal.is_owner() || principal.is_local() {
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
    let key = (operation.logical_attachment_id, operation.operation_id);
    let lock = {
        let mut locks = ctx.remote_operation_locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            lock
        } else {
            let lock = Arc::new(tokio::sync::Mutex::new(()));
            locks.insert(key, Arc::downgrade(&lock));
            lock
        }
    };
    let identity_guard = lock.lock_owned().await;
    Ok(Some(RemoteOperationContext {
        request_id,
        logical_attachment_id: operation.logical_attachment_id,
        operation_id: operation.operation_id,
        authenticated_device_id: actor.device_id,
        authenticated_device_generation: actor.device_generation,
        _identity_guard: identity_guard,
    }))
}
