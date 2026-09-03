//! Injectable fake adapters for tests. Never touches host cgroups/jobs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::adapter::{
    AdapterHandle, AllocatedContainment, ContainerExecRequest, ContainmentAdapter,
    NativeSpawnRequest,
};
use super::types::{
    ContainmentError, ContainmentGuarantee, EmptyOutcome, PROCESS_GROUP_STILL_POPULATED,
    PlatformKind, SafeContainmentMetadata, SafeLocator,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FakeEmptyMode {
    #[default]
    ProvenEmpty,
    Uncertain,
    Hang,
}

#[derive(Debug, Default)]
struct FakeInner {
    /// handle key → (generation, populated)
    groups: HashMap<String, (u64, bool)>,
    /// record of create order for assertions
    spawn_log: Vec<String>,
    terminate_log: Vec<(String, u64)>,
    /// force Unsupported on next create
    force_unsupported: Option<String>,
    /// kill fails once
    kill_fail_once: bool,
    empty_mode: FakeEmptyMode,
    /// Remaining await_empty probes that report drain-in-progress Uncertain
    /// even after terminate, then ProvenEmpty. Exercises post-SIGKILL re-poll.
    drain_probes_remaining: u32,
    /// recovered locators seen
    recover_log: Vec<(String, u64)>,
    /// container full ids by generation
    container_ids: HashMap<u64, String>,
    /// label multi-match simulation
    multi_match: bool,
    context_digest: String,
    context_drift: bool,
}

/// Controllable Proven adapter for unit tests.
#[derive(Clone)]
pub struct FakeProvenAdapter {
    inner: Arc<Mutex<FakeInner>>,
    kind: PlatformKind,
    seq: Arc<AtomicU64>,
}

impl Default for FakeProvenAdapter {
    fn default() -> Self {
        Self::new(PlatformKind::Fake)
    }
}

impl FakeProvenAdapter {
    pub fn new(kind: PlatformKind) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeInner {
                empty_mode: FakeEmptyMode::ProvenEmpty,
                context_digest: "ctx-v1".into(),
                ..Default::default()
            })),
            kind,
            seq: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn set_empty_mode(&self, mode: FakeEmptyMode) {
        self.inner.lock().unwrap().empty_mode = mode;
    }

    pub fn set_drain_probes(&self, n: u32) {
        self.inner.lock().unwrap().drain_probes_remaining = n;
    }

    pub fn force_unsupported(&self, reason: impl Into<String>) {
        self.inner.lock().unwrap().force_unsupported = Some(reason.into());
    }

    pub fn clear_force_unsupported(&self) {
        self.inner.lock().unwrap().force_unsupported = None;
    }

    pub fn set_kill_fail_once(&self, v: bool) {
        self.inner.lock().unwrap().kill_fail_once = v;
    }

    pub fn set_multi_match(&self, v: bool) {
        self.inner.lock().unwrap().multi_match = v;
    }

    pub fn set_context_drift(&self, v: bool) {
        self.inner.lock().unwrap().context_drift = v;
    }

    pub fn mark_populated(&self, handle_key: &str, populated: bool) {
        let mut g = self.inner.lock().unwrap();
        if let Some(entry) = g.groups.get_mut(handle_key) {
            entry.1 = populated;
        }
    }

    pub fn spawn_log(&self) -> Vec<String> {
        self.inner.lock().unwrap().spawn_log.clone()
    }

    pub fn terminate_log(&self) -> Vec<(String, u64)> {
        self.inner.lock().unwrap().terminate_log.clone()
    }

    pub fn recover_log(&self) -> Vec<(String, u64)> {
        self.inner.lock().unwrap().recover_log.clone()
    }
}

#[async_trait]
impl ContainmentAdapter for FakeProvenAdapter {
    fn platform_kind(&self) -> PlatformKind {
        self.kind
    }

    fn guarantee(&self) -> ContainmentGuarantee {
        ContainmentGuarantee::Proven
    }

    fn safe_metadata(&self) -> SafeContainmentMetadata {
        SafeContainmentMetadata {
            platform_kind: self.kind,
            guarantee: ContainmentGuarantee::Proven,
            capability_reason: None,
            adapter_name: "fake_proven".into(),
            management_boundary: Some("fake_broker".into()),
        }
    }

    async fn probe(&self) -> Result<SafeContainmentMetadata, ContainmentError> {
        Ok(self.safe_metadata())
    }

    async fn create_and_spawn(
        &self,
        req: NativeSpawnRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        let mut g = self.inner.lock().unwrap();
        if let Some(reason) = g.force_unsupported.clone() {
            return Err(ContainmentError::DescendantContainmentUnavailable { reason });
        }
        let key = format!(
            "fake-{}-{}-{}",
            req.containment_id,
            req.generation,
            self.seq.fetch_add(1, Ordering::SeqCst)
        );
        g.groups.insert(key.clone(), (req.generation, true));
        g.spawn_log.push(format!(
            "native:gen={}:prog={}",
            req.generation,
            req.program.display()
        ));
        // Never record args/env in durable/safe paths; spawn_log is test-only.
        let locator = SafeLocator {
            locator_key: Some(key.clone()),
            nonce: Some(format!("n-{}", req.generation)),
            installation_digest: Some("inst-test".into()),
            ..Default::default()
        };
        Ok(AllocatedContainment {
            locator,
            guarantee: ContainmentGuarantee::Proven,
            handle: AdapterHandle { key },
        })
    }

    async fn create_container_and_exec(
        &self,
        req: ContainerExecRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        let mut g = self.inner.lock().unwrap();
        if let Some(reason) = g.force_unsupported.clone() {
            return Err(ContainmentError::DescendantContainmentUnavailable { reason });
        }
        let full_id = format!("cid{:060}", req.generation);
        let key = format!("container-{}", full_id);
        g.groups.insert(key.clone(), (req.generation, true));
        g.container_ids.insert(req.generation, full_id.clone());
        g.spawn_log
            .push(format!("container:gen={}:image_digest=img", req.generation));
        let name = format!(
            "cockpit-c-{}-{}-{}",
            &req.installation_id[..8.min(req.installation_id.len())],
            req.containment_id,
            req.nonce
        );
        let locator = SafeLocator {
            locator_key: Some(key.clone()),
            full_id_digest: Some(digest_hex(&full_id)),
            runtime_context_digest: Some(g.context_digest.clone()),
            expected_name: Some(name),
            nonce: Some(req.nonce.clone()),
            installation_digest: Some(digest_hex(&req.installation_id)),
        };
        // suppress unused
        let _ = full_id;
        Ok(AllocatedContainment {
            locator,
            guarantee: ContainmentGuarantee::Proven,
            handle: AdapterHandle { key },
        })
    }

    async fn prove_membership(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<(), ContainmentError> {
        let g = self.inner.lock().unwrap();
        match g.groups.get(&handle.key) {
            Some((entry_gen, _)) if *entry_gen == generation => Ok(()),
            Some((entry_gen, _)) => Err(ContainmentError::GenerationMismatch {
                expected: *entry_gen,
                got: generation,
            }),
            None => Err(ContainmentError::DescendantContainmentUnavailable {
                reason: "fake_group_missing_membership_unproven".into(),
            }),
        }
    }

    async fn terminate(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<(), ContainmentError> {
        let mut g = self.inner.lock().unwrap();
        g.terminate_log.push((handle.key.clone(), generation));
        if g.kill_fail_once {
            g.kill_fail_once = false;
            return Err(ContainmentError::Internal("kill_failed_retryable".into()));
        }
        if let Some(entry) = g.groups.get_mut(&handle.key) {
            if entry.0 != generation {
                return Err(ContainmentError::GenerationMismatch {
                    expected: entry.0,
                    got: generation,
                });
            }
            entry.1 = false;
        }
        Ok(())
    }

    async fn await_empty(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        let mut g = self.inner.lock().unwrap();
        match g.empty_mode {
            FakeEmptyMode::Hang => {
                return Ok(EmptyOutcome::Uncertain {
                    generation,
                    reason: "hang_simulated".into(),
                });
            }
            FakeEmptyMode::Uncertain => {
                return Ok(EmptyOutcome::Uncertain {
                    generation,
                    reason: "forced_uncertain".into(),
                });
            }
            FakeEmptyMode::ProvenEmpty => {}
        }
        if g.drain_probes_remaining > 0 {
            g.drain_probes_remaining -= 1;
            return Ok(EmptyOutcome::Uncertain {
                generation,
                reason: PROCESS_GROUP_STILL_POPULATED.into(),
            });
        }
        match g.groups.get(&handle.key) {
            Some((entry_gen, populated)) if *entry_gen == generation && !*populated => {
                Ok(EmptyOutcome::ProvenEmpty { generation })
            }
            Some((entry_gen, true)) if *entry_gen == generation => Ok(EmptyOutcome::Uncertain {
                generation,
                reason: PROCESS_GROUP_STILL_POPULATED.into(),
            }),
            Some((entry_gen, _)) => Ok(EmptyOutcome::Uncertain {
                generation,
                reason: format!("generation_mismatch_live_{entry_gen}"),
            }),
            None => Ok(EmptyOutcome::ProvenEmpty { generation }),
        }
    }

    async fn recover(
        &self,
        locator: &SafeLocator,
        generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        let mut g = self.inner.lock().unwrap();
        let key = locator.locator_key.clone().unwrap_or_default();
        g.recover_log.push((key.clone(), generation));
        if g.multi_match {
            return Ok(EmptyOutcome::Uncertain {
                generation,
                reason: "multiple_label_matches".into(),
            });
        }
        if g.context_drift {
            return Ok(EmptyOutcome::Uncertain {
                generation,
                reason: "runtime_context_drift".into(),
            });
        }
        if let Some((entry_gen, populated)) = g.groups.get(&key) {
            if *entry_gen != generation {
                return Ok(EmptyOutcome::Uncertain {
                    generation,
                    reason: "generation_mismatch".into(),
                });
            }
            if *populated {
                // Kill by full id semantics in fake
                return Ok(EmptyOutcome::Uncertain {
                    generation,
                    reason: "still_populated_after_recover".into(),
                });
            }
        }
        Ok(EmptyOutcome::ProvenEmpty { generation })
    }
}

/// Adapter that always reports Unsupported (e.g. macOS native).
#[derive(Clone, Debug)]
pub struct FakeUnsupportedAdapter {
    pub reason: String,
    pub kind: PlatformKind,
}

impl FakeUnsupportedAdapter {
    pub fn macos() -> Self {
        Self {
            reason: "macos_no_unprivileged_descendant_container".into(),
            kind: PlatformKind::MacosProcessGroup,
        }
    }

    pub fn management_boundary() -> Self {
        Self {
            reason: "management_boundary_unavailable".into(),
            kind: PlatformKind::LinuxProcessGroup,
        }
    }
}

#[async_trait]
impl ContainmentAdapter for FakeUnsupportedAdapter {
    fn platform_kind(&self) -> PlatformKind {
        self.kind
    }

    fn guarantee(&self) -> ContainmentGuarantee {
        ContainmentGuarantee::Unsupported
    }

    fn safe_metadata(&self) -> SafeContainmentMetadata {
        SafeContainmentMetadata {
            platform_kind: self.kind,
            guarantee: ContainmentGuarantee::Unsupported,
            capability_reason: Some(self.reason.clone()),
            adapter_name: "fake_unsupported".into(),
            management_boundary: None,
        }
    }

    async fn probe(&self) -> Result<SafeContainmentMetadata, ContainmentError> {
        Ok(self.safe_metadata())
    }

    async fn create_and_spawn(
        &self,
        req: NativeSpawnRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        let _ = req;
        Err(ContainmentError::DescendantContainmentUnavailable {
            reason: self.reason.clone(),
        })
    }

    async fn prove_membership(
        &self,
        _handle: &AdapterHandle,
        _generation: u64,
    ) -> Result<(), ContainmentError> {
        Err(ContainmentError::DescendantContainmentUnavailable {
            reason: self.reason.clone(),
        })
    }

    async fn create_container_and_exec(
        &self,
        req: ContainerExecRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        let _ = req;
        Err(ContainmentError::DescendantContainmentUnavailable {
            reason: self.reason.clone(),
        })
    }

    async fn terminate(
        &self,
        _handle: &AdapterHandle,
        _generation: u64,
    ) -> Result<(), ContainmentError> {
        Ok(())
    }

    async fn await_empty(
        &self,
        _handle: &AdapterHandle,
        _generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        Ok(EmptyOutcome::Unsupported {
            reason: self.reason.clone(),
        })
    }

    async fn recover(
        &self,
        _locator: &SafeLocator,
        _generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        Ok(EmptyOutcome::Unsupported {
            reason: self.reason.clone(),
        })
    }
}

// Fix FakeUnsupportedAdapter::await_empty cleanly by rewriting the impl section
// — the above has a syntax error. We'll patch the file.

fn digest_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Container runtime command fixture used by container adapter tests.
#[derive(Debug, Clone)]
pub struct FakeRuntimeCommand {
    pub argv: Vec<String>,
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}

#[derive(Clone, Default)]
pub struct FakeContainerRuntime {
    inner: Arc<Mutex<FakeRuntimeState>>,
}

#[derive(Default)]
struct FakeRuntimeState {
    /// full_id → (labels, running, name)
    objects: HashMap<String, ContainerObj>,
    commands: Vec<Vec<String>>,
    fail_ops: HashMap<String, usize>,
    next_id: u64,
    /// missing semantic flags
    missing_create_id: bool,
    allow_privileged: bool,
}

#[derive(Clone)]
struct ContainerObj {
    labels: HashMap<String, String>,
    running: bool,
    name: String,
    removed: bool,
}

impl FakeContainerRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_missing_create_id(&self, v: bool) {
        self.inner.lock().unwrap().missing_create_id = v;
    }

    pub fn set_allow_privileged(&self, v: bool) {
        self.inner.lock().unwrap().allow_privileged = v;
    }

    pub fn fail_op_once(&self, op: &str) {
        *self
            .inner
            .lock()
            .unwrap()
            .fail_ops
            .entry(op.into())
            .or_insert(0) += 1;
    }

    pub fn commands(&self) -> Vec<Vec<String>> {
        self.inner.lock().unwrap().commands.clone()
    }

    pub fn object_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .objects
            .values()
            .filter(|o| !o.removed)
            .count()
    }

    pub fn inject_label_collision(
        &self,
        full_id: &str,
        labels: HashMap<String, String>,
        name: &str,
    ) {
        let mut g = self.inner.lock().unwrap();
        g.objects.insert(
            full_id.into(),
            ContainerObj {
                labels,
                running: true,
                name: name.into(),
                removed: false,
            },
        );
    }

    /// Execute a docker/podman-like command against the fixture.
    pub fn exec(&self, argv: &[String]) -> FakeRuntimeCommand {
        let mut g = self.inner.lock().unwrap();
        g.commands.push(argv.to_vec());
        let op = argv.get(1).map(|s| s.as_str()).unwrap_or("");
        if let Some(left) = g.fail_ops.get_mut(op)
            && *left > 0
        {
            *left -= 1;
            return FakeRuntimeCommand {
                argv: argv.to_vec(),
                stdout: String::new(),
                stderr: format!("simulated {op} failure"),
                success: false,
            };
        }
        match op {
            "create" => {
                if argv.iter().any(|a| a == "--privileged") && !g.allow_privileged {
                    return FakeRuntimeCommand {
                        argv: argv.to_vec(),
                        stdout: String::new(),
                        stderr: "privileged forbidden".into(),
                        success: false,
                    };
                }
                g.next_id += 1;
                let full_id = format!("fullid{:056}", g.next_id);
                let mut labels = HashMap::new();
                let mut name = String::new();
                let mut i = 0;
                while i < argv.len() {
                    if argv[i] == "--label" {
                        if let Some(kv) = argv.get(i + 1)
                            && let Some((k, v)) = kv.split_once('=')
                        {
                            labels.insert(k.into(), v.into());
                        }
                        i += 2;
                        continue;
                    }
                    if argv[i] == "--name" {
                        name = argv.get(i + 1).cloned().unwrap_or_default();
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
                g.objects.insert(
                    full_id.clone(),
                    ContainerObj {
                        labels,
                        running: false,
                        name,
                        removed: false,
                    },
                );
                let stdout = if g.missing_create_id {
                    String::new()
                } else {
                    full_id
                };
                FakeRuntimeCommand {
                    argv: argv.to_vec(),
                    stdout,
                    stderr: String::new(),
                    // Success with empty ID models create acknowledgement without ID oracle.
                    success: true,
                }
            }
            "inspect" => {
                let id = argv.last().cloned().unwrap_or_default();
                if let Some(obj) = g.objects.get(&id) {
                    if obj.removed {
                        return FakeRuntimeCommand {
                            argv: argv.to_vec(),
                            stdout: String::new(),
                            stderr: "Error: No such object".into(),
                            success: false,
                        };
                    }
                    let labels: serde_json::Map<String, serde_json::Value> = obj
                        .labels
                        .iter()
                        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                        .collect();
                    let body = serde_json::json!([{
                        "Id": id,
                        "Name": format!("/{}", obj.name),
                        "State": { "Running": obj.running, "Status": if obj.running { "running" } else { "created" } },
                        "Config": {
                            "Labels": labels,
                            "Privileged": false,
                        },
                        "HostConfig": {
                            "Privileged": false,
                            "PidMode": "",
                            "CgroupnsMode": "private",
                            "SecurityOpt": ["no-new-privileges:true"],
                            "CapAdd": [],
                            "Binds": [],
                        }
                    }]);
                    FakeRuntimeCommand {
                        argv: argv.to_vec(),
                        stdout: body.to_string(),
                        stderr: String::new(),
                        success: true,
                    }
                } else {
                    FakeRuntimeCommand {
                        argv: argv.to_vec(),
                        stdout: String::new(),
                        stderr: "Error: No such object".into(),
                        success: false,
                    }
                }
            }
            "start" | "kill" => {
                let id = argv.last().cloned().unwrap_or_default();
                if let Some(obj) = g.objects.get_mut(&id) {
                    obj.running = op == "start";
                    FakeRuntimeCommand {
                        argv: argv.to_vec(),
                        stdout: id,
                        stderr: String::new(),
                        success: true,
                    }
                } else {
                    FakeRuntimeCommand {
                        argv: argv.to_vec(),
                        stdout: String::new(),
                        stderr: "no such container".into(),
                        success: false,
                    }
                }
            }
            "wait" => {
                let id = argv.last().cloned().unwrap_or_default();
                if let Some(obj) = g.objects.get_mut(&id) {
                    obj.running = false;
                    FakeRuntimeCommand {
                        argv: argv.to_vec(),
                        stdout: "0".into(),
                        stderr: String::new(),
                        success: true,
                    }
                } else {
                    FakeRuntimeCommand {
                        argv: argv.to_vec(),
                        stdout: String::new(),
                        stderr: "no such container".into(),
                        success: false,
                    }
                }
            }
            "rm" => {
                let id = argv
                    .iter()
                    .rev()
                    .find(|a| !a.starts_with('-'))
                    .cloned()
                    .unwrap_or_default();
                if let Some(obj) = g.objects.get_mut(&id) {
                    obj.removed = true;
                    obj.running = false;
                    FakeRuntimeCommand {
                        argv: argv.to_vec(),
                        stdout: id,
                        stderr: String::new(),
                        success: true,
                    }
                } else {
                    FakeRuntimeCommand {
                        argv: argv.to_vec(),
                        stdout: String::new(),
                        stderr: "no such container".into(),
                        success: false,
                    }
                }
            }
            "ps" => {
                // label filter recovery
                let mut filter_labels = Vec::new();
                let mut i = 0;
                while i < argv.len() {
                    if argv[i] == "--filter" {
                        if let Some(f) = argv.get(i + 1)
                            && let Some(rest) = f.strip_prefix("label=")
                        {
                            filter_labels.push(rest.to_string());
                        }
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
                let mut ids = Vec::new();
                for (id, obj) in &g.objects {
                    if obj.removed {
                        continue;
                    }
                    let ok = filter_labels.iter().all(|fl| {
                        fl.split_once('=')
                            .map(|(k, v)| obj.labels.get(k).map(|x| x == v).unwrap_or(false))
                            .unwrap_or(false)
                    });
                    if ok || filter_labels.is_empty() {
                        ids.push(id.clone());
                    }
                }
                FakeRuntimeCommand {
                    argv: argv.to_vec(),
                    stdout: ids.join("\n"),
                    stderr: String::new(),
                    success: true,
                }
            }
            _ => FakeRuntimeCommand {
                argv: argv.to_vec(),
                stdout: String::new(),
                stderr: format!("unknown op {op}"),
                success: false,
            },
        }
    }
}
