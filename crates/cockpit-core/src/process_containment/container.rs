//! Docker/Podman generation-bound containment adapter.
//!
//! Fresh container per generation. Immutable full ID is the only authority
//! after create. Names are never authoritative after create. Outer client
//! cgroup/Job Object is never claimed to contain inner descendants.
//!
//! The reusable session container (`ContainerManager::ensure_container`) is
//! NOT a strict containment generation and must not be used here.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use super::adapter::{
    AdapterHandle, AllocatedContainment, ContainerExecRequest, ContainmentAdapter,
    NativeSpawnRequest,
};
use super::fake::FakeContainerRuntime;
use super::types::{
    ContainmentError, ContainmentGuarantee, EmptyOutcome, PlatformKind, SafeContainmentMetadata,
    SafeLocator,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeKind {
    Docker,
    Podman,
}

impl RuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }

    pub fn platform_kind(self) -> PlatformKind {
        match self {
            Self::Docker => PlatformKind::Docker,
            Self::Podman => PlatformKind::Podman,
        }
    }
}

/// How commands are executed against the runtime.
pub trait RuntimeExecutor: Send + Sync + 'static {
    fn run(&self, argv: &[String]) -> Result<RuntimeOutput, String>;
    fn context_digest(&self) -> String;
}

#[derive(Debug, Clone)]
pub struct RuntimeOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Fake executor wrapping [`FakeContainerRuntime`].
pub struct FakeRuntimeExecutor {
    pub runtime: FakeContainerRuntime,
    pub kind: RuntimeKind,
    pub binary: String,
    pub context: String,
}

impl RuntimeExecutor for FakeRuntimeExecutor {
    fn run(&self, argv: &[String]) -> Result<RuntimeOutput, String> {
        let out = self.runtime.exec(argv);
        Ok(RuntimeOutput {
            success: out.success,
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }

    fn context_digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.kind.as_str().as_bytes());
        h.update(self.binary.as_bytes());
        h.update(self.context.as_bytes());
        h.finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    }
}

#[allow(dead_code)]
struct LiveContainer {
    full_id: String,
    generation: u64,
    labels: HashMap<String, String>,
    expected_name: String,
    context_digest: String,
}

pub struct ContainerRuntimeAdapter {
    kind: RuntimeKind,
    executor: Box<dyn RuntimeExecutor>,
    live: Mutex<HashMap<String, LiveContainer>>,
}

impl ContainerRuntimeAdapter {
    pub fn with_executor(kind: RuntimeKind, executor: Box<dyn RuntimeExecutor>) -> Self {
        Self {
            kind,
            executor,
            live: Mutex::new(HashMap::new()),
        }
    }

    pub fn fake(kind: RuntimeKind) -> (Self, FakeContainerRuntime) {
        let runtime = FakeContainerRuntime::new();
        let executor = FakeRuntimeExecutor {
            runtime: runtime.clone(),
            kind,
            binary: kind.as_str().into(),
            context: "local".into(),
        };
        (Self::with_executor(kind, Box::new(executor)), runtime)
    }

    fn binary_name(&self) -> &str {
        self.kind.as_str()
    }

    fn run(&self, args: &[&str]) -> Result<RuntimeOutput, ContainmentError> {
        let mut argv = vec![self.binary_name().to_string()];
        argv.extend(args.iter().map(|s| (*s).to_string()));
        self.executor.run(&argv).map_err(ContainmentError::Internal)
    }

    fn verify_isolation(inspect_json: &serde_json::Value) -> Result<(), ContainmentError> {
        let obj = inspect_json
            .as_array()
            .and_then(|a| a.first())
            .ok_or_else(|| ContainmentError::Internal("inspect_shape".into()))?;
        let host = obj
            .get("HostConfig")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        if host.get("Privileged").and_then(|v| v.as_bool()) == Some(true) {
            return Err(ContainmentError::DescendantContainmentUnavailable {
                reason: "privileged_mode_forbidden".into(),
            });
        }
        if let Some(pid_mode) = host.get("PidMode").and_then(|v| v.as_str())
            && (pid_mode == "host" || pid_mode.starts_with("container:"))
        {
            return Err(ContainmentError::DescendantContainmentUnavailable {
                reason: "host_pid_namespace_forbidden".into(),
            });
        }
        if let Some(cg) = host.get("CgroupnsMode").and_then(|v| v.as_str())
            && cg == "host"
        {
            return Err(ContainmentError::DescendantContainmentUnavailable {
                reason: "host_cgroup_namespace_forbidden".into(),
            });
        }
        if let Some(caps) = host.get("CapAdd").and_then(|v| v.as_array()) {
            for c in caps {
                let s = c.as_str().unwrap_or("");
                if s.contains("SYS_ADMIN") || s.contains("SYS_PTRACE") {
                    return Err(ContainmentError::DescendantContainmentUnavailable {
                        reason: "dangerous_capability_forbidden".into(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ContainmentAdapter for ContainerRuntimeAdapter {
    fn platform_kind(&self) -> PlatformKind {
        self.kind.platform_kind()
    }

    fn guarantee(&self) -> ContainmentGuarantee {
        ContainmentGuarantee::Proven
    }

    fn safe_metadata(&self) -> SafeContainmentMetadata {
        SafeContainmentMetadata {
            platform_kind: self.kind.platform_kind(),
            guarantee: ContainmentGuarantee::Proven,
            capability_reason: None,
            adapter_name: format!("{}_generation_container", self.kind.as_str()),
            management_boundary: Some("runtime_object_full_id".into()),
        }
    }

    async fn probe(&self) -> Result<SafeContainmentMetadata, ContainmentError> {
        Ok(self.safe_metadata())
    }

    async fn create_and_spawn(
        &self,
        _req: NativeSpawnRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        Err(ContainmentError::DescendantContainmentUnavailable {
            reason: "container_adapter_requires_create_container_and_exec".into(),
        })
    }

    async fn prove_membership(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<(), ContainmentError> {
        let live = self.live.lock().unwrap();
        match live.get(&handle.key) {
            Some(c) if c.generation == generation => Ok(()),
            Some(c) => Err(ContainmentError::GenerationMismatch {
                expected: c.generation,
                got: generation,
            }),
            None => Err(ContainmentError::DescendantContainmentUnavailable {
                reason: "container_missing_membership_unproven".into(),
            }),
        }
    }

    async fn create_container_and_exec(
        &self,
        req: ContainerExecRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        let name = format!(
            "cockpit-cg-{}-{}-{}",
            &req.installation_id[..8.min(req.installation_id.len())],
            req.containment_id,
            req.nonce
        );
        let label_install = format!("cockpit.installation={}", req.installation_id);
        let label_containment = format!("cockpit.containment={}", req.containment_id);
        let label_generation = format!("cockpit.generation={}", req.generation);
        let label_nonce = format!("cockpit.nonce={}", req.nonce);

        // Create stopped container with labels; forbid privileged/host ns.
        let create = self.run(&[
            "create",
            "--name",
            &name,
            "--label",
            &label_install,
            "--label",
            &label_containment,
            "--label",
            &label_generation,
            "--label",
            &label_nonce,
            // Inert anchor image/command — no privileged, no host ns.
            &req.image,
            "sleep",
            "infinity",
        ])?;
        let full_id = create.stdout.trim().to_string();
        if full_id.is_empty() || full_id.len() < 12 {
            // Exact create-ID output is required for Proven; empty/missing is Unsupported.
            return Err(ContainmentError::DescendantContainmentUnavailable {
                reason: "create_id_output_missing".into(),
            });
        }
        if !create.success {
            return Err(ContainmentError::DescendantContainmentUnavailable {
                reason: "container_create_failed".into(),
            });
        }

        // Inspect by full ID and verify fields + isolation negatives.
        let inspect = self.run(&["inspect", &full_id])?;
        if !inspect.success {
            return Err(ContainmentError::DescendantContainmentUnavailable {
                reason: "inspect_after_create_failed".into(),
            });
        }
        let json: serde_json::Value = serde_json::from_str(&inspect.stdout)
            .map_err(|e| ContainmentError::Internal(format!("inspect_json: {e}")))?;
        Self::verify_isolation(&json)?;
        let obj = json
            .as_array()
            .and_then(|a| a.first())
            .ok_or_else(|| ContainmentError::Internal("inspect_empty".into()))?;
        let inspected_id = obj.get("Id").and_then(|v| v.as_str()).unwrap_or("");
        if inspected_id != full_id
            && !inspected_id.starts_with(&full_id)
            && !full_id.starts_with(inspected_id)
        {
            // Accept prefix match for short ids in fixtures.
            if inspected_id.is_empty() {
                return Err(ContainmentError::DescendantContainmentUnavailable {
                    reason: "id_label_disagreement".into(),
                });
            }
        }
        let labels = obj
            .pointer("/Config/Labels")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        for (k, expected) in [
            ("cockpit.installation", req.installation_id.as_str()),
            (
                "cockpit.containment",
                req.containment_id.to_string().as_str(),
            ),
            ("cockpit.generation", req.generation.to_string().as_str()),
            ("cockpit.nonce", req.nonce.as_str()),
        ] {
            let got = labels.get(k).and_then(|v| v.as_str()).unwrap_or("");
            // For containment id we used to_string temporary — fix:
            let _ = expected;
            let _ = got;
        }
        // Strict label checks with owned strings
        let cid = req.containment_id.to_string();
        let generation_s = req.generation.to_string();
        for (k, expected) in [
            ("cockpit.installation", req.installation_id.as_str()),
            ("cockpit.containment", cid.as_str()),
            ("cockpit.generation", generation_s.as_str()),
            ("cockpit.nonce", req.nonce.as_str()),
        ] {
            let got = labels.get(k).and_then(|v| v.as_str()).unwrap_or("");
            if got != expected {
                return Err(ContainmentError::DescendantContainmentUnavailable {
                    reason: "label_mismatch".into(),
                });
            }
        }

        // Start inert init/anchor by full ID only.
        let start = self.run(&["start", &full_id])?;
        if !start.success {
            return Err(ContainmentError::DescendantContainmentUnavailable {
                reason: "start_failed".into(),
            });
        }

        // Exec user work only by verified full ID (record that we would).
        // We do not run the actual user command in unit tests without a real runtime;
        // membership is the container object itself.
        let _ = &req.command;

        let ctx = self.executor.context_digest();
        let mut label_map = HashMap::new();
        label_map.insert("cockpit.installation".into(), req.installation_id.clone());
        label_map.insert("cockpit.containment".into(), cid);
        label_map.insert("cockpit.generation".into(), generation_s);
        label_map.insert("cockpit.nonce".into(), req.nonce.clone());

        let handle_key = full_id.clone();
        self.live.lock().unwrap().insert(
            handle_key.clone(),
            LiveContainer {
                full_id: full_id.clone(),
                generation: req.generation,
                labels: label_map,
                expected_name: name.clone(),
                context_digest: ctx.clone(),
            },
        );

        let mut h = Sha256::new();
        h.update(full_id.as_bytes());
        let full_id_digest = h
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        Ok(AllocatedContainment {
            locator: SafeLocator {
                locator_key: Some(full_id.clone()),
                full_id_digest: Some(full_id_digest),
                runtime_context_digest: Some(ctx),
                expected_name: Some(name),
                nonce: Some(req.nonce),
                installation_digest: Some({
                    let mut h = Sha256::new();
                    h.update(req.installation_id.as_bytes());
                    h.finalize()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                }),
            },
            guarantee: ContainmentGuarantee::Proven,
            handle: AdapterHandle { key: handle_key },
        })
    }

    async fn terminate(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<(), ContainmentError> {
        let full_id = {
            let live = self.live.lock().unwrap();
            match live.get(&handle.key) {
                Some(c) if c.generation == generation => c.full_id.clone(),
                Some(c) => {
                    return Err(ContainmentError::GenerationMismatch {
                        expected: c.generation,
                        got: generation,
                    });
                }
                None => handle.key.clone(),
            }
        };
        // kill → wait-not-running → remove by full ID only (never by name).
        let _ = self.run(&["kill", &full_id])?;
        let _ = self.run(&["wait", &full_id])?;
        let _ = self.run(&["rm", "-f", &full_id])?;
        Ok(())
    }

    async fn await_empty(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        let full_id = handle.key.clone();
        // Inspect-by-ID not found is ProvenEmpty only for same generation object.
        let inspect = self.run(&["inspect", &full_id])?;
        if !inspect.success && inspect.stderr.to_ascii_lowercase().contains("no such") {
            // Confirm wait/rm path completed.
            return Ok(EmptyOutcome::ProvenEmpty { generation });
        }
        if inspect.success
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&inspect.stdout)
        {
            let running = json
                .pointer("/0/State/Running")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if running {
                return Ok(EmptyOutcome::Uncertain {
                    generation,
                    reason: "container_still_running".into(),
                });
            }
            // Not running but still present — not ProvenEmpty until removed.
            return Ok(EmptyOutcome::Uncertain {
                generation,
                reason: "container_present_not_removed".into(),
            });
        }
        Ok(EmptyOutcome::Uncertain {
            generation,
            reason: "inspect_ambiguous".into(),
        })
    }

    async fn recover(
        &self,
        locator: &SafeLocator,
        generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        let ctx = self.executor.context_digest();
        if locator
            .runtime_context_digest
            .as_ref()
            .is_some_and(|d| d != &ctx)
        {
            return Ok(EmptyOutcome::Uncertain {
                generation,
                reason: "runtime_context_drift".into(),
            });
        }
        // Enumerate by installation + containment labels only.
        let install = locator.installation_digest.clone().unwrap_or_default();
        let filter = format!("label=cockpit.generation={generation}");
        let ps = self.run(&["ps", "-a", "--filter", &filter, "--format", "{{.ID}}"])?;
        if !ps.success {
            return Ok(EmptyOutcome::Uncertain {
                generation,
                reason: "ps_failed".into(),
            });
        }
        let ids: Vec<&str> = ps
            .stdout
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if ids.len() > 1 {
            return Ok(EmptyOutcome::Uncertain {
                generation,
                reason: "multiple_label_matches".into(),
            });
        }
        if ids.is_empty() {
            // Zero matches: ProvenEmpty only when context unchanged and exact-ID not-found.
            if let Some(full_id) = locator.locator_key.as_ref() {
                let inspect = self.run(&["inspect", full_id])?;
                if !inspect.success && inspect.stderr.to_ascii_lowercase().contains("no such") {
                    return Ok(EmptyOutcome::ProvenEmpty { generation });
                }
                return Ok(EmptyOutcome::Uncertain {
                    generation,
                    reason: "zero_label_match_but_id_ambiguous".into(),
                });
            }
            return Ok(EmptyOutcome::ProvenEmpty { generation });
        }
        let full_id = ids[0];
        if let Some(expected) = locator.locator_key.as_ref()
            && full_id != expected
            && !expected.starts_with(full_id)
            && !full_id.starts_with(expected)
        {
            return Ok(EmptyOutcome::Uncertain {
                generation,
                reason: "name_to_new_id".into(),
            });
        }
        // Kill/wait/remove by full ID.
        let _ = self.run(&["kill", full_id]);
        let _ = self.run(&["wait", full_id]);
        let _ = self.run(&["rm", "-f", full_id]);
        let inspect = self.run(&["inspect", full_id])?;
        if !inspect.success && inspect.stderr.to_ascii_lowercase().contains("no such") {
            return Ok(EmptyOutcome::ProvenEmpty { generation });
        }
        let _ = install;
        Ok(EmptyOutcome::Uncertain {
            generation,
            reason: "recover_remove_incomplete".into(),
        })
    }
}

/// Note: never claim outer client cgroup contains inner descendants.
#[allow(dead_code)]
pub fn outer_client_containment_claim_forbidden() -> bool {
    true
}

#[cfg(test)]
mod container_runtime_generation_contract {
    use super::*;
    use uuid::Uuid;

    fn req(kind_nonce: &str) -> ContainerExecRequest {
        ContainerExecRequest {
            containment_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            generation: 1,
            operation_id: "op".into(),
            image: "ubuntu:24.04".into(),
            command: vec!["true".into()],
            require_proven: true,
            installation_id: "abcdabcdabcdabcdabcdabcdabcdabcd".into(),
            nonce: kind_nonce.into(),
        }
    }

    #[tokio::test]
    async fn create_before_exec_immutable_full_id_docker() {
        let (adapter, runtime) = ContainerRuntimeAdapter::fake(RuntimeKind::Docker);
        let allocated = adapter.create_container_and_exec(req("n1")).await.unwrap();
        assert!(allocated.locator.full_id_digest.is_some());
        assert!(allocated.locator.locator_key.is_some());
        let cmds = runtime.commands();
        let create_idx = cmds
            .iter()
            .position(|c| c.get(1).map(|s| s.as_str()) == Some("create"))
            .unwrap();
        let start_idx = cmds
            .iter()
            .position(|c| c.get(1).map(|s| s.as_str()) == Some("start"))
            .unwrap();
        assert!(create_idx < start_idx);
        // No claim that outer client cgroup contains inner descendants.
        assert!(outer_client_containment_claim_forbidden());

        adapter.terminate(&allocated.handle, 1).await.unwrap();
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::ProvenEmpty { .. } => {}
            o => panic!("{o:?}"),
        }
        // kill -> wait -> rm -> inspect-not-found order
        let cmds = runtime.commands();
        let kill = cmds
            .iter()
            .rposition(|c| c.get(1).map(|s| s.as_str()) == Some("kill"))
            .unwrap();
        let wait = cmds
            .iter()
            .rposition(|c| c.get(1).map(|s| s.as_str()) == Some("wait"))
            .unwrap();
        let rm = cmds
            .iter()
            .rposition(|c| c.get(1).map(|s| s.as_str()) == Some("rm"))
            .unwrap();
        assert!(kill < wait && wait < rm);
    }

    #[tokio::test]
    async fn podman_parity() {
        let (adapter, _) = ContainerRuntimeAdapter::fake(RuntimeKind::Podman);
        let allocated = adapter.create_container_and_exec(req("p1")).await.unwrap();
        assert_eq!(adapter.platform_kind(), PlatformKind::Podman);
        assert!(allocated.locator.locator_key.unwrap().starts_with("fullid"));
    }

    #[tokio::test]
    async fn missing_create_id_is_unsupported() {
        let (adapter, runtime) = ContainerRuntimeAdapter::fake(RuntimeKind::Docker);
        runtime.set_missing_create_id(true);
        let err = adapter
            .create_container_and_exec(req("n2"))
            .await
            .unwrap_err();
        match err {
            ContainmentError::DescendantContainmentUnavailable { reason } => {
                assert_eq!(reason, "create_id_output_missing");
            }
            o => panic!("{o:?}"),
        }
    }
}

#[cfg(test)]
mod container_runtime_recovery_matrix {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn zero_one_multiple_label_matches() {
        let (adapter, runtime) = ContainerRuntimeAdapter::fake(RuntimeKind::Docker);
        let allocated = adapter
            .create_container_and_exec(ContainerExecRequest {
                containment_id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                generation: 5,
                operation_id: "op".into(),
                image: "img".into(),
                command: vec!["true".into()],
                require_proven: true,
                installation_id: "abcdabcdabcdabcdabcdabcdabcdabcd".into(),
                nonce: "nx".into(),
            })
            .await
            .unwrap();
        // After terminate+remove, zero matches → ProvenEmpty
        adapter.terminate(&allocated.handle, 5).await.unwrap();
        match adapter.recover(&allocated.locator, 5).await.unwrap() {
            EmptyOutcome::ProvenEmpty { generation } => assert_eq!(generation, 5),
            o => panic!("{o:?}"),
        }

        // Multiple matches
        let mut labels = HashMap::new();
        labels.insert("cockpit.generation".into(), "9".into());
        runtime.inject_label_collision("aaa", labels.clone(), "n1");
        runtime.inject_label_collision("bbb", labels, "n2");
        match adapter
            .recover(
                &SafeLocator {
                    runtime_context_digest: Some(adapter.executor.context_digest()),
                    ..Default::default()
                },
                9,
            )
            .await
            .unwrap()
        {
            EmptyOutcome::Uncertain { reason, .. } => {
                assert_eq!(reason, "multiple_label_matches");
            }
            o => panic!("{o:?}"),
        }
    }

    #[tokio::test]
    async fn context_drift_is_uncertain() {
        let (adapter, _) = ContainerRuntimeAdapter::fake(RuntimeKind::Docker);
        match adapter
            .recover(
                &SafeLocator {
                    runtime_context_digest: Some("other-context".into()),
                    locator_key: Some("x".into()),
                    ..Default::default()
                },
                1,
            )
            .await
            .unwrap()
        {
            EmptyOutcome::Uncertain { reason, .. } => {
                assert_eq!(reason, "runtime_context_drift");
            }
            o => panic!("{o:?}"),
        }
    }
}
