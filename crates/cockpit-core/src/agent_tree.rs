//! Daemon-owned recursive agent lifecycle and decision routing.
//!
//! The database is the state-machine authority; this module deliberately owns
//! only routing, recovery, and contract validation.  In particular, cache
//! warmth is never persisted as authority: it chooses a resolver route for a
//! single attempt, while the redacted durable request and its CAS receipt are
//! what make restart/retry deterministic.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::agent_installations::{
        AgentBindingRevision, AgentBindingRevisionMap, AgentExecutionKind, AgentInstallationInput,
        AgentInstallationScope, ProviderAlias, RedactedAgentProfileSnapshot,
        RedactedBindingEvidence, RedactedQuestionPolicy,
    };
    use crate::db::db::agent_tree_decisions::{AgentInstanceState, NewAgentInstance};
    use crate::db::wire::{InterruptOption, InterruptQuestion, InterruptQuestionSet};
    use sha2::{Digest, Sha256};

    fn digest(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn host_capability_refresh_is_the_closed_low_risk_ingress() {
        assert_eq!(
            classify_host_capabilities_refresh().decision_class(),
            DecisionClass::LowRisk
        );
        for prohibited in [
            HostEffectClass::Credential,
            HostEffectClass::Authorization,
            HostEffectClass::Destructive,
            HostEffectClass::ExternalAction,
            HostEffectClass::Publish,
            HostEffectClass::Purchase,
            HostEffectClass::Production,
        ] {
            assert_ne!(prohibited.decision_class(), DecisionClass::LowRisk);
        }
    }

    #[test]
    fn host_approval_authority_is_bound_to_one_exact_settlement_interrupt() {
        let session_id = Uuid::new_v4();
        let agent_instance_id = Uuid::new_v4();
        let interrupt_id = Uuid::new_v4();
        let authority = HostApprovalAuthority::for_registered_interrupt(
            session_id,
            agent_instance_id,
            interrupt_id,
        )
        .unwrap();
        assert!(
            authority
                .db_for_settlement(session_id, agent_instance_id, interrupt_id)
                .is_ok()
        );
        assert!(
            authority
                .db_for_settlement(session_id, agent_instance_id, Uuid::new_v4())
                .is_err()
        );
        assert!(
            authority
                .db_for_effect_handoff(session_id, Uuid::new_v4(), interrupt_id)
                .is_err()
        );
        assert!(
            HostApprovalAuthority::for_registered_interrupt(
                session_id,
                agent_instance_id,
                Uuid::nil(),
            )
            .is_err()
        );
    }

    #[test]
    fn free_text_decision_contract_is_explicitly_bounded_at_creation() {
        for contract in [
            FreeTextContract {
                allowed: true,
                max_chars: None,
            },
            FreeTextContract {
                allowed: true,
                max_chars: Some(0),
            },
            FreeTextContract {
                allowed: true,
                max_chars: Some(10_001),
            },
            FreeTextContract {
                allowed: false,
                max_chars: Some(1),
            },
        ] {
            assert!(validate_bounded_free_text_contract(&contract).is_err());
        }
        assert!(
            validate_bounded_free_text_contract(&FreeTextContract {
                allowed: true,
                max_chars: Some(1),
            })
            .is_ok()
        );
        assert!(
            validate_bounded_free_text_contract(&FreeTextContract {
                allowed: false,
                max_chars: None,
            })
            .is_ok()
        );
    }

    #[test]
    fn public_free_text_answers_fail_closed_without_panicking_on_non_capabilities() {
        let base = DecisionRequestRow {
            decision_request_id: Uuid::new_v4(),
            agent_instance_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            task_call_id: None,
            workspace_ref: None,
            options_contract_json:
                r#"{"options":[{"id":"option:018f47a2-7b3c-7def-8123-000000000001"}]}"#.into(),
            free_text_contract_json: Some(r#"{"allowed":false,"max_chars":null}"#.into()),
            recommendation_json: None,
            rationale_redaction_class: "public".into(),
            decision_class: "user_question".into(),
            host_approval_operation_id: None,
            deadline_unix_ms: None,
            policy_receipt_json: "{}".into(),
            resolver_route: None,
            state: DecisionState::Pending,
            revision: 0,
            created_at_unix_ms: 0,
            updated_at_unix_ms: 0,
        };
        let answer = PublicDecisionAnswer::FreeText { text: "no".into() };
        assert!(
            validate_answer(&base, &answer).is_err(),
            "the public ResolveAgentDecision free-text variant must reject an explicit non-capability"
        );

        let malformed = DecisionRequestRow {
            free_text_contract_json: Some(r#"{"allowed":true}"#.into()),
            ..base
        };
        assert!(
            validate_answer(&malformed, &answer).is_err(),
            "a malformed persisted free-text capability must return an error rather than panic the session worker"
        );
    }

    #[tokio::test]
    async fn generic_decisions_require_an_answer_channel_at_typed_and_lifecycle_ingress() {
        let presentation = DecisionPresentation {
            question: "Choose an action".into(),
            description: "One answer is required".into(),
            task_call_id: None,
            workspace_ref: None,
            recommendation_rationale: None,
        };
        assert!(
            NewDecisionContract::user_question(
                Uuid::new_v4(),
                0,
                Vec::new(),
                None,
                None,
                "public".into(),
                presentation.clone(),
            )
            .is_err(),
            "a cancellation-only generic question is not answerable"
        );
        assert!(
            NewDecisionContract::user_question(
                Uuid::new_v4(),
                0,
                Vec::new(),
                Some(FreeTextContract {
                    allowed: true,
                    max_chars: Some(120),
                }),
                None,
                "public".into(),
                presentation.clone(),
            )
            .is_ok()
        );

        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let agent = running_agent(&db, session.session_id, false).await;
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        // Direct construction is available inside this crate for trusted host
        // composition. The lifecycle must preserve the constructor invariant
        // so a malformed internal/import adapter cannot park this agent.
        let invalid = NewDecisionContract {
            agent_instance_id: agent.agent_instance_id,
            expected_agent_revision: agent.revision,
            options: Vec::new(),
            free_text: None,
            recommended_option_id: None,
            rationale_redaction_class: "public".into(),
            presentation,
            interrupt_response_contract: None,
            decision_subject: HostDecisionSubject::UserQuestion,
            host_approval_authority: None,
        };
        let error = lifecycle
            .request_decision(session.session_id, invalid, 100)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("generic decision must offer an option or allow bounded free-text")
        );
        let after = db
            .agent_instance(session.session_id, agent.agent_instance_id)
            .await
            .unwrap()
            .expect("decision owner remains durable");
        assert_eq!(after.state, AgentInstanceState::Running);
        assert_eq!(after.revision, agent.revision);
    }

    #[tokio::test]
    async fn generic_lifecycle_decision_round_trips_the_canonical_null_question_tool_marker() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let agent = running_agent(&db, session.session_id, false).await;
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let decision = lifecycle
            .request_decision(
                session.session_id,
                NewDecisionContract::user_question(
                    agent.agent_instance_id,
                    agent.revision,
                    vec![DecisionOption {
                        id: "continue".into(),
                        label: "Continue".into(),
                    }],
                    Some(FreeTextContract {
                        allowed: true,
                        max_chars: Some(120),
                    }),
                    Some("continue".into()),
                    "public".into(),
                    DecisionPresentation {
                        question: "Continue?".into(),
                        description: "A bounded generic decision is waiting".into(),
                        task_call_id: None,
                        workspace_ref: None,
                        recommendation_rationale: None,
                    },
                )
                .unwrap(),
                100,
            )
            .await
            .expect("generic None must not be decoded as a QuestionTool contract");
        let recovered = db
            .decision_request(session.session_id, decision.decision_request_id)
            .await
            .unwrap()
            .expect("generic lifecycle decision survives durable reload");
        let public: serde_json::Value =
            serde_json::from_str(&recovered.options_contract_json).unwrap();
        assert_eq!(
            public["interrupt_response_contract"],
            serde_json::Value::Null
        );
        assert_eq!(public["question"], "Decision required");
        assert_eq!(public["description"], "An agent decision is waiting");
        assert!(recovered.free_text_contract_json.is_some());
    }

    #[tokio::test]
    async fn public_answer_boundary_requires_opaque_tokens_and_private_continuations_translate_exactly()
     {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let agent = running_agent(&db, session.session_id, false).await;
        let public_decision = lifecycle
            .request_decision(session.session_id, contract(&agent), 100)
            .await
            .unwrap();
        let public_option = only_public_option_id(&public_decision.options_contract_json);

        // The public AgentTree route cannot accept a caller/model-owned
        // continuation ID even when it is a real private mapping.
        assert!(
            lifecycle
                .resolve_user_answer(
                    session.session_id,
                    public_decision.decision_request_id,
                    PublicDecisionAnswer::option("refresh"),
                    101,
                )
                .await
                .is_err()
        );
        assert!(matches!(
            lifecycle
                .resolve_user_answer(
                    session.session_id,
                    public_decision.decision_request_id,
                    PublicDecisionAnswer::option(public_option),
                    102,
                )
                .await
                .unwrap(),
            DecisionSettlement::Resolved(DecisionState::Answered)
        ));

        // The only private-ID path is a separate crate-private continuation
        // API. It translates through the exact durable mapping before it can
        // reach the public validator or a persisted receipt.
        let running = db
            .agent_instance(session.session_id, agent.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        let private_decision = lifecycle
            .request_decision(session.session_id, contract(&running), 103)
            .await
            .unwrap();
        assert!(matches!(
            lifecycle
                .resolve_trusted_private_continuation_answer(
                    session.session_id,
                    private_decision.decision_request_id,
                    PrivateDecisionContinuationAnswer::option("refresh"),
                    104,
                )
                .await
                .unwrap(),
            DecisionSettlement::Resolved(DecisionState::Answered)
        ));
    }

    #[test]
    fn question_tool_contract_requires_a_nonempty_typed_answer_channel() {
        let empty_choice = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Choose".into(),
                options: Vec::new(),
                allow_freetext: false,
                command_detail: None,
                permission: false,
                approval_class: None,
                sandbox_escalation: None,
            }],
        };
        assert!(
            NewDecisionContract::user_question_interrupt(Uuid::new_v4(), 0, &empty_choice, None,)
                .is_err(),
            "QuestionTool cancellation cannot be its only answer path"
        );
        let valid_choice = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Choose".into(),
                options: vec![InterruptOption {
                    id: "continue".into(),
                    label: "Continue".into(),
                    description: None,
                    secondary: false,
                }],
                allow_freetext: false,
                command_detail: None,
                permission: false,
                approval_class: None,
                sandbox_escalation: None,
            }],
        };
        assert!(
            NewDecisionContract::user_question_interrupt(Uuid::new_v4(), 0, &valid_choice, None,)
                .is_ok()
        );
    }

    /// Tests exercise the same immutable snapshot reconstruction that
    /// production recovery uses.  This intentionally does not use a
    /// cfg(test) policy default: a missing/corrupt persisted profile remains
    /// fail-closed in every target.
    async fn persist_active_question_profile(db: &crate::db::Db, session_id: Uuid) -> Uuid {
        if let Some(snapshot) = db.agent_profile_snapshot(session_id).await.unwrap() {
            snapshot.reconstruct().unwrap();
            return snapshot.snapshot_id;
        }
        let installation_id = Uuid::new_v4();
        let definition_digest = digest(b"agent-tree-test-definition");
        db.install_agent(AgentInstallationInput {
            installation_id,
            scope: AgentInstallationScope::Global,
            canonical_workspace_id: None,
            source_agent_id: "agent-tree-test".into(),
            source_identity: format!("daemon-local:{installation_id}"),
            source_revision: Some("test-v1".into()),
            source_digest: definition_digest.clone(),
            fetched_at_unix_ms: 1,
        })
        .await
        .unwrap();
        let profile = RedactedAgentProfileSnapshot {
            agent_id: "agent-tree-test".into(),
            execution_kind: AgentExecutionKind::Coding,
            effective_delegation: None,
            recommendations: Vec::new(),
            question_policy: RedactedQuestionPolicy::Active {
                auto_answer_disabled: false,
                prohibited_classes: vec!["credential".into(), "destructive".into()],
                required_decision_timeout_ms: 6,
                host_resource_ceiling_ms: 6,
                resolver_order:
                    crate::db::agent_installations::QuestionResolverOrder::WarmParentThenUtility,
                resolver_slot: "primary".into(),
            },
            verification_regions: Vec::new(),
            bindings: vec![RedactedBindingEvidence {
                slot_id: "primary".into(),
                binding_revision: 1,
                provider_profile_handle: "test-profile".into(),
                model_id: "test-model".into(),
                selected_provider_alias: ProviderAlias {
                    provider_id: "test-provider".into(),
                    model_id: "test-model".into(),
                },
                provenance_digest: digest(b"agent-tree-test-provenance"),
                hard_capability_verified: true,
            }],
        };
        let payload = serde_json::to_vec(&profile).unwrap();
        let binding_map = serde_json::to_vec(&AgentBindingRevisionMap {
            bindings: vec![AgentBindingRevision {
                slot_id: "primary".into(),
                binding_revision: 1,
            }],
        })
        .unwrap();
        let payload_digest = digest(&payload);
        let binding_map_digest = digest(&binding_map);
        let snapshot_id = Uuid::new_v4();
        db.transaction(move |conn| {
            conn.execute(
                "INSERT INTO agent_profile_snapshots (
                     snapshot_id, session_id, installation_id, schema_version,
                     canonical_payload, canonical_payload_digest, definition_digest,
                     binding_revision_map_payload, binding_revision_map_digest,
                     created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, 1)",
                rusqlite::params![
                    snapshot_id.to_string(),
                    session_id.to_string(),
                    installation_id.to_string(),
                    payload,
                    payload_digest,
                    definition_digest,
                    binding_map,
                    binding_map_digest,
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        db.agent_profile_snapshot_by_id(session_id, snapshot_id)
            .await
            .unwrap()
            .expect("persisted test profile")
            .reconstruct()
            .unwrap();
        snapshot_id
    }

    /// Materialize a second immutable profile for a child.  The test keeps
    /// both profiles in the same session specifically to prove that resolver
    /// routing keys off the requesting child's profile/slot rather than the
    /// root's compatible-looking primary binding.
    async fn persist_child_question_profile_with_distinct_binding(
        db: &crate::db::Db,
        session_id: Uuid,
    ) -> Uuid {
        let root = db
            .agent_profile_snapshot(session_id)
            .await
            .unwrap()
            .expect("root test profile exists");
        let mut profile = root.reconstruct().unwrap();
        profile.agent_id = "agent-tree-child-test".into();
        match &mut profile.question_policy {
            RedactedQuestionPolicy::Active { resolver_slot, .. } => {
                *resolver_slot = "child-utility".into();
            }
            RedactedQuestionPolicy::Off => panic!("root test profile must enable question policy"),
        }
        let binding = profile
            .bindings
            .first_mut()
            .expect("root test profile has one verified binding");
        binding.slot_id = "child-utility".into();
        binding.model_id = "child-utility-model".into();
        binding.selected_provider_alias.model_id = "child-utility-model".into();
        binding.provenance_digest = digest(b"agent-tree-child-test-provenance");
        let payload = serde_json::to_vec(&profile).unwrap();
        let binding_map = serde_json::to_vec(&AgentBindingRevisionMap {
            bindings: vec![AgentBindingRevision {
                slot_id: "child-utility".into(),
                binding_revision: 1,
            }],
        })
        .unwrap();
        let payload_digest = digest(&payload);
        let binding_map_digest = digest(&binding_map);
        let snapshot_id = Uuid::new_v4();
        let installation_id = root.installation_id;
        let definition_digest = root.definition_digest;
        db.transaction(move |conn| {
            conn.execute(
                "INSERT INTO agent_profile_snapshots (
                     snapshot_id, session_id, installation_id, schema_version,
                     canonical_payload, canonical_payload_digest, definition_digest,
                     binding_revision_map_payload, binding_revision_map_digest,
                     created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, 2)",
                rusqlite::params![
                    snapshot_id.to_string(),
                    session_id.to_string(),
                    installation_id.to_string(),
                    payload,
                    payload_digest,
                    definition_digest,
                    binding_map,
                    binding_map_digest,
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        db.agent_profile_snapshot_by_id(session_id, snapshot_id)
            .await
            .unwrap()
            .expect("persisted child test profile")
            .reconstruct()
            .unwrap();
        snapshot_id
    }

    struct TestResolvers {
        parent_warm: bool,
        utility_compatible: bool,
    }

    struct ExactProfileSlotResolvers {
        expected_agent_instance_id: Uuid,
        expected_profile_snapshot_id: Uuid,
        expected_slot: String,
        observed: std::sync::Mutex<Vec<(Uuid, Option<Uuid>, String)>>,
    }

    impl DecisionResolverDirectory for ExactProfileSlotResolvers {
        fn exact_owner_executor_is_live(
            &self,
            _session_id: Uuid,
            _agent_instance_id: Uuid,
        ) -> bool {
            true
        }

        fn parent_cache_resumable(
            &self,
            _session_id: Uuid,
            _parent_agent_instance_id: Uuid,
        ) -> bool {
            false
        }

        fn utility_slot_is_compatible(
            &self,
            _session_id: Uuid,
            agent_instance_id: Uuid,
            profile_snapshot_id: Option<Uuid>,
            resolver_slot: &str,
        ) -> bool {
            self.observed
                .lock()
                .expect("profile resolver observation lock")
                .push((
                    agent_instance_id,
                    profile_snapshot_id,
                    resolver_slot.to_owned(),
                ));
            agent_instance_id == self.expected_agent_instance_id
                && profile_snapshot_id == Some(self.expected_profile_snapshot_id)
                && resolver_slot == self.expected_slot
        }
    }

    impl DecisionResolverDirectory for TestResolvers {
        fn exact_owner_executor_is_live(
            &self,
            _session_id: Uuid,
            _agent_instance_id: Uuid,
        ) -> bool {
            // This deterministic unit-test directory owns the only executor
            // synchronously; make that fact explicit rather than inheriting
            // an unsafe default from the production contract.
            true
        }

        fn parent_cache_resumable(
            &self,
            _session_id: Uuid,
            _parent_agent_instance_id: Uuid,
        ) -> bool {
            self.parent_warm
        }

        fn utility_slot_is_compatible(
            &self,
            _session_id: Uuid,
            _agent_instance_id: Uuid,
            _profile_snapshot_id: Option<Uuid>,
            _resolver_slot: &str,
        ) -> bool {
            self.utility_compatible
        }
    }

    struct AttachmentResolvers {
        owner_live: Arc<std::sync::atomic::AtomicBool>,
    }

    impl DecisionResolverDirectory for AttachmentResolvers {
        fn exact_owner_executor_is_live(
            &self,
            _session_id: Uuid,
            _agent_instance_id: Uuid,
        ) -> bool {
            self.owner_live.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn parent_cache_resumable(
            &self,
            _session_id: Uuid,
            _parent_agent_instance_id: Uuid,
        ) -> bool {
            false
        }

        fn utility_slot_is_compatible(
            &self,
            _session_id: Uuid,
            _agent_instance_id: Uuid,
            _profile_snapshot_id: Option<Uuid>,
            _resolver_slot: &str,
        ) -> bool {
            true
        }
    }

    /// Models the production registry's immutable agent-instance ownership:
    /// a terminal host-operation child can detach while its still-running
    /// requesting parent remains the only valid receiver for a post-auto
    /// user steer.
    struct PerAgentAttachmentResolvers {
        live_agents: Arc<std::sync::Mutex<std::collections::HashSet<Uuid>>>,
    }

    impl DecisionResolverDirectory for PerAgentAttachmentResolvers {
        fn exact_owner_executor_is_live(&self, _session_id: Uuid, agent_instance_id: Uuid) -> bool {
            self.live_agents
                .lock()
                .expect("per-agent attachment lock")
                .contains(&agent_instance_id)
        }

        fn parent_cache_resumable(
            &self,
            _session_id: Uuid,
            _parent_agent_instance_id: Uuid,
        ) -> bool {
            false
        }

        fn utility_slot_is_compatible(
            &self,
            _session_id: Uuid,
            _agent_instance_id: Uuid,
            _profile_snapshot_id: Option<Uuid>,
            _resolver_slot: &str,
        ) -> bool {
            true
        }
    }

    struct FixedClock(i64);

    impl AgentTreeClock for FixedClock {
        fn now_unix_ms(&self) -> i64 {
            self.0
        }
    }

    struct NoopDeadlines;

    impl DecisionDeadlineScheduler for NoopDeadlines {
        fn schedule(&self, _session_id: Uuid, _decision_request_id: Uuid, _deadline_unix_ms: i64) {}

        fn cancel(&self, _session_id: Uuid, _decision_request_id: Uuid) {}
    }

    #[derive(Default)]
    struct RecordingDeadlines(std::sync::Mutex<Vec<Uuid>>);

    impl DecisionDeadlineScheduler for RecordingDeadlines {
        fn schedule(&self, _session_id: Uuid, decision_request_id: Uuid, _deadline_unix_ms: i64) {
            self.0
                .lock()
                .expect("recording deadline lock")
                .push(decision_request_id);
        }

        fn cancel(&self, _session_id: Uuid, _decision_request_id: Uuid) {}
    }

    struct WarmThenUtilityResolvers {
        parent_live: Arc<std::sync::atomic::AtomicBool>,
    }

    impl DecisionResolverDirectory for WarmThenUtilityResolvers {
        fn exact_owner_executor_is_live(
            &self,
            _session_id: Uuid,
            _agent_instance_id: Uuid,
        ) -> bool {
            true
        }

        fn parent_cache_resumable(
            &self,
            _session_id: Uuid,
            _parent_agent_instance_id: Uuid,
        ) -> bool {
            self.parent_live.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn utility_slot_is_compatible(
            &self,
            _session_id: Uuid,
            _agent_instance_id: Uuid,
            _profile_snapshot_id: Option<Uuid>,
            _resolver_slot: &str,
        ) -> bool {
            true
        }
    }

    struct WarmThenUtilityDelivery {
        parent_live: Arc<std::sync::atomic::AtomicBool>,
        accepted: std::sync::Mutex<Vec<DecisionResolverRoute>>,
    }

    impl DecisionResolverDelivery for WarmThenUtilityDelivery {
        fn accept(
            &self,
            _session_id: Uuid,
            route: DecisionResolverRoute,
            _packet: RedactedDecisionPacket,
        ) -> Result<()> {
            self.accepted
                .lock()
                .expect("test delivery lock")
                .push(route);
            if route == DecisionResolverRoute::WarmParent {
                // Simulate the exact live parent disappearing between route
                // selection and executor acknowledgement.
                self.parent_live
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                bail!("warm parent disappeared before delivery acknowledgement");
            }
            Ok(())
        }
    }

    struct RecordingResolverDelivery {
        accepted: std::sync::Mutex<Vec<(Uuid, DecisionResolverRoute)>>,
        succeeds: bool,
    }

    impl RecordingResolverDelivery {
        fn succeeding() -> Self {
            Self {
                accepted: std::sync::Mutex::new(Vec::new()),
                succeeds: true,
            }
        }
    }

    impl DecisionResolverDelivery for RecordingResolverDelivery {
        fn accept(
            &self,
            _session_id: Uuid,
            route: DecisionResolverRoute,
            packet: RedactedDecisionPacket,
        ) -> Result<()> {
            self.accepted
                .lock()
                .expect("recording resolver delivery lock")
                .push((packet.decision_request_id, route));
            if self.succeeds {
                Ok(())
            } else {
                bail!("deterministic resolver delivery rejection")
            }
        }
    }

    async fn running_agent(
        db: &crate::db::Db,
        session_id: Uuid,
        auto_answer_enabled: bool,
    ) -> AgentInstanceRow {
        let snapshot_id = persist_active_question_profile(db, session_id).await;
        let created = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: Some(snapshot_id),
                    workspace_ref: None,
                    auto_answer_enabled,
                },
                10,
            )
            .await
            .unwrap();
        if auto_answer_enabled {
            db.set_agent_auto_answer_from_resolved_profile(
                session_id,
                created.agent_instance_id,
                snapshot_id,
                10,
            )
            .await
            .unwrap();
        }
        match db
            .transition_agent_instance(
                session_id,
                created.agent_instance_id,
                created.revision,
                AgentInstanceState::Running,
                "{}",
                11,
            )
            .await
            .unwrap()
        {
            AgentTransitionOutcome::Transitioned(row) => row,
            other => panic!("running transition lost: {other:?}"),
        }
    }

    async fn running_child(
        db: &crate::db::Db,
        session_id: Uuid,
        parent: &AgentInstanceRow,
        auto_answer_enabled: bool,
    ) -> AgentInstanceRow {
        let created = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id,
                    parent_agent_instance_id: Some(parent.agent_instance_id),
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: parent.resolved_profile_snapshot_id,
                    workspace_ref: parent.workspace_ref.clone(),
                    auto_answer_enabled,
                },
                10,
            )
            .await
            .unwrap();
        if auto_answer_enabled {
            db.set_agent_auto_answer_from_resolved_profile(
                session_id,
                created.agent_instance_id,
                parent
                    .resolved_profile_snapshot_id
                    .expect("test parent has profile"),
                10,
            )
            .await
            .unwrap();
        }
        match db
            .transition_agent_instance(
                session_id,
                created.agent_instance_id,
                created.revision,
                AgentInstanceState::Running,
                "{}",
                11,
            )
            .await
            .unwrap()
        {
            AgentTransitionOutcome::Transitioned(row) => row,
            other => panic!("child running transition lost: {other:?}"),
        }
    }

    async fn running_child_with_profile(
        db: &crate::db::Db,
        session_id: Uuid,
        parent: &AgentInstanceRow,
        profile_snapshot_id: Uuid,
    ) -> AgentInstanceRow {
        let created = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id,
                    parent_agent_instance_id: Some(parent.agent_instance_id),
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: Some(profile_snapshot_id),
                    workspace_ref: parent.workspace_ref.clone(),
                    auto_answer_enabled: true,
                },
                10,
            )
            .await
            .unwrap();
        db.set_agent_auto_answer_from_resolved_profile(
            session_id,
            created.agent_instance_id,
            profile_snapshot_id,
            10,
        )
        .await
        .unwrap();
        match db
            .transition_agent_instance(
                session_id,
                created.agent_instance_id,
                created.revision,
                AgentInstanceState::Running,
                "{}",
                11,
            )
            .await
            .unwrap()
        {
            AgentTransitionOutcome::Transitioned(row) => row,
            other => panic!("child with profile running transition lost: {other:?}"),
        }
    }

    fn contract(agent: &AgentInstanceRow) -> NewDecisionContract {
        NewDecisionContract {
            agent_instance_id: agent.agent_instance_id,
            expected_agent_revision: agent.revision,
            options: vec![DecisionOption {
                // The host-owned low-risk subject below has one typed,
                // allowlisted action. Keep its private continuation id exact
                // in this fixture so the production redactor can map it to
                // an opaque resolver token.
                id: "refresh".into(),
                label: "Refresh".into(),
            }],
            free_text: None,
            recommended_option_id: Some("refresh".into()),
            rationale_redaction_class: "public".into(),
            presentation: DecisionPresentation {
                question: "Refresh local host capabilities?".into(),
                description: "The requesting agent needs one bounded decision.".into(),
                task_call_id: None,
                workspace_ref: agent.workspace_ref.clone(),
                recommendation_rationale: Some("The existing plan is reversible.".into()),
            },
            interrupt_response_contract: None,
            decision_subject: HostDecisionSubject::UserQuestion,
            host_approval_authority: None,
        }
    }

    /// Tests that exercise automatic routing use the same narrow production
    /// ingress as the daemon: a real interrupt and one durably bound refresh
    /// operation. Generic decision construction cannot stand in for it.
    async fn host_capability_refresh_decision(
        lifecycle: &AgentTreeLifecycle,
        db: &crate::db::Db,
        session_id: Uuid,
        agent: &AgentInstanceRow,
        now_unix_ms: i64,
    ) -> DecisionRequestRow {
        let questions = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Refresh local host capabilities?".into(),
                options: vec![
                    crate::db::wire::InterruptOption {
                        id: "refresh".into(),
                        label: "Refresh".into(),
                        description: None,
                        secondary: false,
                    },
                    crate::db::wire::InterruptOption {
                        id: "cancel".into(),
                        label: "Cancel".into(),
                        description: None,
                        secondary: true,
                    },
                ],
                allow_freetext: false,
                command_detail: None,
                permission: false,
                approval_class: None,
                sandbox_escalation: None,
            }],
        };
        let interrupt_id = db
            .raise_interrupt_questions_with_agent_instance_and_payload(
                session_id,
                "host-capability-refresh",
                Some(agent.agent_instance_id),
                "host capability refresh decision",
                &questions,
                None,
            )
            .await
            .unwrap();
        lifecycle
            .request_decision_for_interrupt(
                session_id,
                NewDecisionContract::user_question_interrupt(
                    agent.agent_instance_id,
                    agent.revision,
                    &questions,
                    agent.workspace_ref.clone(),
                )
                .unwrap()
                .with_host_subject(HostDecisionSubject::HostCapabilitiesRefresh {
                    operation: HostCapabilitiesRefreshOperation::new(),
                }),
                interrupt_id,
                now_unix_ms,
            )
            .await
            .unwrap()
    }

    fn only_public_option_id(options_contract_json: &str) -> String {
        let contract: serde_json::Value = serde_json::from_str(options_contract_json).unwrap();
        let id = contract["options"]
            .as_array()
            .and_then(|options| options.first())
            .and_then(|option| option["id"].as_str())
            .expect("one opaque public option")
            .to_owned();
        assert!(id.starts_with("option:"));
        id
    }

    #[tokio::test]
    async fn agent_tree_attention_lifecycle_parent_resolver_and_utility_fallback_matrix() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());

        let parent = running_agent(&db, session.session_id, false).await;
        let warm = running_child(&db, session.session_id, &parent, true).await;
        let decision =
            host_capability_refresh_decision(&lifecycle, &db, session.session_id, &warm, 20).await;
        let recommendation: serde_json::Value = serde_json::from_str(
            decision
                .recommendation_json
                .as_deref()
                .expect("typed local-refresh contract must persist its host semantic"),
        )
        .unwrap();
        assert_eq!(
            recommendation["host_action"].as_str(),
            Some("refresh_local_host_capabilities"),
            "only the typed daemon-host classifier may publish this resolver semantic"
        );
        let opaque_refresh = recommendation["option_id"]
            .as_str()
            .expect("host semantic must identify an offered opaque option");
        assert!(opaque_refresh.starts_with("option:"));
        assert_ne!(opaque_refresh, "refresh");
        let outcome = lifecycle
            .begin_auto_resolution(
                session.session_id,
                decision.decision_request_id,
                &TestResolvers {
                    parent_warm: true,
                    utility_compatible: true,
                },
                21,
            )
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            AutoResolutionBegin::Claimed {
                route: DecisionResolverRoute::WarmParent,
                ..
            }
        ));
        assert_eq!(
            db.decision_request(session.session_id, decision.decision_request_id)
                .await
                .unwrap()
                .unwrap()
                .resolver_route
                .as_deref(),
            Some("warm_parent")
        );

        let cold = running_child(&db, session.session_id, &parent, true).await;
        let decision =
            host_capability_refresh_decision(&lifecycle, &db, session.session_id, &cold, 30).await;
        let outcome = lifecycle
            .begin_auto_resolution(
                session.session_id,
                decision.decision_request_id,
                &TestResolvers {
                    parent_warm: false,
                    utility_compatible: true,
                },
                31,
            )
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            AutoResolutionBegin::Claimed {
                route: DecisionResolverRoute::Utility,
                ..
            }
        ));
        assert_eq!(
            db.decision_request(session.session_id, decision.decision_request_id)
                .await
                .unwrap()
                .unwrap()
                .resolver_route
                .as_deref(),
            Some("utility")
        );

        let unavailable = running_child(&db, session.session_id, &parent, true).await;
        let decision =
            host_capability_refresh_decision(&lifecycle, &db, session.session_id, &unavailable, 40)
                .await;
        let outcome = lifecycle
            .begin_auto_resolution(
                session.session_id,
                decision.decision_request_id,
                &TestResolvers {
                    parent_warm: false,
                    utility_compatible: false,
                },
                41,
            )
            .await
            .unwrap();
        assert_eq!(outcome, AutoResolutionBegin::WaitingForUser);
        assert_eq!(
            db.decision_request(session.session_id, decision.decision_request_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            DecisionState::Pending,
            "unavailable resolvers must not manufacture a result or timeout"
        );
    }

    #[tokio::test]
    async fn utility_fallback_uses_the_requesting_child_profile_and_slot_not_the_root_binding() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let root = running_agent(&db, session.session_id, false).await;
        let root_snapshot_id = root
            .resolved_profile_snapshot_id
            .expect("root has the primary profile");
        let child_snapshot_id =
            persist_child_question_profile_with_distinct_binding(&db, session.session_id).await;
        assert_ne!(child_snapshot_id, root_snapshot_id);
        assert_eq!(
            db.agent_profile_snapshot(session.session_id)
                .await
                .unwrap()
                .expect("session root profile remains addressable")
                .snapshot_id,
            root_snapshot_id,
            "a child profile must not replace the session/root profile lookup"
        );
        let child =
            running_child_with_profile(&db, session.session_id, &root, child_snapshot_id).await;
        let resolvers = ExactProfileSlotResolvers {
            expected_agent_instance_id: child.agent_instance_id,
            expected_profile_snapshot_id: child_snapshot_id,
            expected_slot: "child-utility".into(),
            observed: std::sync::Mutex::new(Vec::new()),
        };
        let decision =
            host_capability_refresh_decision(&lifecycle, &db, session.session_id, &child, 20).await;
        let outcome = lifecycle
            .begin_auto_resolution(
                session.session_id,
                decision.decision_request_id,
                &resolvers,
                21,
            )
            .await
            .unwrap();
        let packet = match outcome {
            AutoResolutionBegin::Claimed {
                route: DecisionResolverRoute::Utility,
                packet,
            } => packet,
            other => panic!("expected child-profile utility claim, got {other:?}"),
        };
        assert_eq!(packet.resolver_profile_snapshot_id, Some(child_snapshot_id));
        assert_eq!(packet.resolver_slot.as_deref(), Some("child-utility"));
        let serialized = serde_json::to_value(&packet).unwrap();
        assert!(
            serialized.get("resolver_profile_snapshot_id").is_none()
                && serialized.get("resolver_slot").is_none(),
            "profile routing metadata remains daemon-private and is not part of the resolver packet"
        );
        assert_eq!(
            resolvers
                .observed
                .lock()
                .expect("profile resolver observation lock")
                .as_slice(),
            &[(
                child.agent_instance_id,
                Some(child_snapshot_id),
                "child-utility".to_string(),
            )]
        );
    }

    #[tokio::test]
    async fn bounded_reconciliation_round_robins_the_durable_decision_backlog() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let owners = [
            running_agent(&db, session.session_id, false).await,
            running_agent(&db, session.session_id, false).await,
            running_agent(&db, session.session_id, false).await,
        ];
        let decisions = [
            lifecycle
                .request_decision(session.session_id, contract(&owners[0]), 20)
                .await
                .unwrap(),
            lifecycle
                .request_decision(session.session_id, contract(&owners[1]), 21)
                .await
                .unwrap(),
            lifecycle
                .request_decision(session.session_id, contract(&owners[2]), 22)
                .await
                .unwrap(),
        ];
        let deadlines = Arc::new(RecordingDeadlines::default());
        let runtime = AgentTreeRuntime::new(
            lifecycle,
            Arc::new(FixedClock(0)),
            Arc::new(TestResolvers {
                parent_warm: false,
                utility_compatible: false,
            }),
            deadlines.clone(),
        );

        runtime
            .reconcile_pending_requests_limited(session.session_id, 2)
            .await
            .unwrap();
        runtime
            .reconcile_pending_requests_limited(session.session_id, 2)
            .await
            .unwrap();
        assert_eq!(
            deadlines
                .0
                .lock()
                .expect("recording deadline lock")
                .as_slice(),
            &[
                decisions[0].decision_request_id,
                decisions[1].decision_request_id,
                decisions[2].decision_request_id,
                decisions[0].decision_request_id,
            ],
            "each bounded turn advances through the durable order before wrapping"
        );
    }

    #[tokio::test]
    async fn runtime_retries_a_rejected_warm_parent_with_utility_delivery() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let parent = running_agent(&db, session.session_id, false).await;
        let child = running_child(&db, session.session_id, &parent, true).await;
        let parent_live = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let delivery = Arc::new(WarmThenUtilityDelivery {
            parent_live: parent_live.clone(),
            accepted: std::sync::Mutex::new(Vec::new()),
        });
        let resolvers = Arc::new(WarmThenUtilityResolvers {
            parent_live: parent_live.clone(),
        });
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let runtime = AgentTreeRuntime::new(
            lifecycle.clone(),
            Arc::new(FixedClock(20)),
            resolvers.clone(),
            Arc::new(NoopDeadlines),
        )
        .with_resolver_delivery(delivery.clone());
        let decision =
            host_capability_refresh_decision(&lifecycle, &db, session.session_id, &child, 20).await;
        runtime
            .reconcile_pending_requests_limited(session.session_id, 1)
            .await
            .unwrap();
        assert_eq!(
            delivery
                .accepted
                .lock()
                .expect("test delivery lock")
                .as_slice(),
            &[
                DecisionResolverRoute::WarmParent,
                DecisionResolverRoute::Utility
            ]
        );
        let durable = db
            .decision_request(session.session_id, decision.decision_request_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(durable.state, DecisionState::Resolving);
        assert_eq!(durable.resolver_route.as_deref(), Some("utility"));
    }

    #[tokio::test]
    async fn failed_optional_resolver_delivery_leaves_the_question_waiting_for_user() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let parent = running_agent(&db, session.session_id, false).await;
        let child = running_child(&db, session.session_id, &parent, true).await;
        let parent_live = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let delivery = Arc::new(WarmThenUtilityDelivery {
            parent_live,
            accepted: std::sync::Mutex::new(Vec::new()),
        });
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let runtime = AgentTreeRuntime::new(
            lifecycle.clone(),
            Arc::new(FixedClock(20)),
            Arc::new(TestResolvers {
                parent_warm: true,
                utility_compatible: false,
            }),
            Arc::new(NoopDeadlines),
        )
        .with_resolver_delivery(delivery.clone());

        let decision =
            host_capability_refresh_decision(&lifecycle, &db, session.session_id, &child, 20).await;
        runtime
            .reconcile_pending_requests_limited(session.session_id, 1)
            .await
            .unwrap();

        assert_eq!(
            delivery
                .accepted
                .lock()
                .expect("test delivery lock")
                .as_slice(),
            &[DecisionResolverRoute::WarmParent]
        );
        let durable = db
            .decision_request(session.session_id, decision.decision_request_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(durable.state, DecisionState::Pending);
        assert_eq!(durable.resolver_route, None);
    }

    #[tokio::test]
    async fn unattached_decision_owner_blocks_manual_auto_and_deadline_settlement() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let owner = running_agent(&db, session.session_id, true).await;
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let decision = lifecycle
            .request_decision(session.session_id, contract(&owner), 20)
            .await
            .unwrap();
        let owner_live = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let runtime = AgentTreeRuntime::new(
            lifecycle,
            Arc::new(FixedClock(30)),
            Arc::new(AttachmentResolvers {
                owner_live: owner_live.clone(),
            }),
            Arc::new(NoopDeadlines),
        );

        assert_eq!(
            runtime
                .begin_auto_resolution(session.session_id, decision.decision_request_id)
                .await
                .unwrap(),
            AutoResolutionBegin::WaitingForUser,
            "an unattached owner cannot receive an automatic resolver claim"
        );
        assert_eq!(
            runtime
                .expire_deadline(session.session_id, decision.decision_request_id)
                .await
                .unwrap(),
            DecisionSettlement::Retry,
            "an unattached owner cannot consume a deadline cancellation"
        );
        assert_eq!(
            runtime
                .resolve_trusted_private_continuation_answer(
                    session.session_id,
                    decision.decision_request_id,
                    PrivateDecisionContinuationAnswer::option("refresh"),
                )
                .await
                .unwrap(),
            DecisionSettlement::Retry,
            "an unattached owner cannot consume a manual one-shot answer"
        );
        assert_eq!(
            db.decision_request(session.session_id, decision.decision_request_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            DecisionState::Pending
        );

        owner_live.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            runtime
                .resolve_trusted_private_continuation_answer(
                    session.session_id,
                    decision.decision_request_id,
                    PrivateDecisionContinuationAnswer::option("refresh"),
                )
                .await
                .unwrap(),
            DecisionSettlement::Resolved(DecisionState::Answered)
        ));
    }

    #[tokio::test]
    async fn runtime_returns_due_deadline_winners_once_for_live_and_recovered_questiontool_delivery()
     {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let owner = running_agent(&db, session.session_id, true).await;
        let live =
            host_capability_refresh_decision(&lifecycle, &db, session.session_id, &owner, 20).await;
        let live_runtime = AgentTreeRuntime::new(
            lifecycle.clone(),
            Arc::new(FixedClock(30)),
            Arc::new(TestResolvers {
                parent_warm: false,
                utility_compatible: true,
            }),
            Arc::new(NoopDeadlines),
        );

        let settled = live_runtime
            .reconcile_pending_requests_limited(session.session_id, 1)
            .await
            .unwrap();
        assert_eq!(
            settled,
            vec![TerminalDeadlineSettlement {
                decision_request_id: live.decision_request_id,
                terminal_state: DecisionState::TimedOut,
            }],
            "the worker must receive the live deadline CAS winner to wake its direct QuestionTool waiter"
        );
        assert!(
            live_runtime
                .reconcile_pending_requests_limited(session.session_id, 1)
                .await
                .unwrap()
                .is_empty(),
            "a later maintenance tick is only an idempotent terminal-CAS loser"
        );

        let owner_after_live = db
            .agent_instance(session.session_id, owner.agent_instance_id)
            .await
            .unwrap()
            .expect("timed-out decision owner remains runnable");
        let recovered = host_capability_refresh_decision(
            &lifecycle,
            &db,
            session.session_id,
            &owner_after_live,
            40,
        )
        .await;
        let recovered_interrupt = db
            .interrupt_for_decision_request(session.session_id, recovered.decision_request_id)
            .await
            .unwrap()
            .expect("host refresh has its real QuestionTool interrupt");
        assert!(db.park_interrupt(recovered_interrupt).await.unwrap());
        let recovered_runtime = AgentTreeRuntime::new(
            lifecycle,
            Arc::new(FixedClock(50)),
            Arc::new(TestResolvers {
                parent_warm: false,
                utility_compatible: true,
            }),
            Arc::new(NoopDeadlines),
        );
        let recovery = AgentTreeRecovery {
            claimed_agents: vec![owner_after_live.agent_instance_id],
            pending_decisions: vec![recovered.decision_request_id],
            claimed_late_user_steers: Vec::new(),
            accepted_late_user_steers: Vec::new(),
        };
        assert_eq!(
            recovered_runtime
                .resume_recovered_decisions(session.session_id, &recovery)
                .await
                .unwrap(),
            vec![TerminalDeadlineSettlement {
                decision_request_id: recovered.decision_request_id,
                terminal_state: DecisionState::TimedOut,
            }],
            "recovery must return the parked deadline winner for the worker's one replay boundary"
        );
        assert_eq!(
            db.get_interrupt(recovered_interrupt)
                .await
                .unwrap()
                .expect("persisted recovered interrupt")
                .state,
            crate::db::needs_attention::InterruptState::Executing,
            "the durable terminal winner claims the parked continuation; only the worker may replay it"
        );
        assert!(
            recovered_runtime
                .resume_recovered_decisions(session.session_id, &recovery)
                .await
                .unwrap()
                .is_empty(),
            "recovery cannot hand the same parked continuation to a second replay"
        );
    }

    #[tokio::test]
    async fn host_refresh_resolving_claim_redelivers_once_after_typed_restart_attachment() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let parent = running_agent(&db, session.session_id, false).await;
        let child = running_child(&db, session.session_id, &parent, true).await;
        let decision =
            host_capability_refresh_decision(&lifecycle, &db, session.session_id, &child, 20).await;
        let interrupt_id = db
            .interrupt_for_decision_request(session.session_id, decision.decision_request_id)
            .await
            .unwrap()
            .expect("host refresh decision owns one real interrupt");
        let operation = db
            .host_capability_refresh_operation_for_interrupt(
                daemon_host_capability_refresh_authority(),
                session.session_id,
                interrupt_id,
            )
            .await
            .unwrap()
            .expect("host refresh decision has one typed operation binding");
        assert_eq!(operation.agent_instance_id, child.agent_instance_id);
        assert_eq!(
            operation.decision_request_id,
            Some(decision.decision_request_id)
        );

        // The old worker has claimed utility routing but dies before its
        // resolver reports completion. This is the precise `pending ->
        // resolving` crash window that a replacement worker must recover.
        assert!(matches!(
            lifecycle
                .begin_auto_resolution(
                    session.session_id,
                    decision.decision_request_id,
                    &TestResolvers {
                        parent_warm: false,
                        utility_compatible: true,
                    },
                    21,
                )
                .await
                .unwrap(),
            AutoResolutionBegin::Claimed {
                route: DecisionResolverRoute::Utility,
                ..
            }
        ));
        assert_eq!(
            db.decision_request(session.session_id, decision.decision_request_id)
                .await
                .unwrap()
                .expect("crash-window decision remains durable")
                .state,
            DecisionState::Resolving
        );

        let recovery_epoch = Uuid::new_v4();
        let recovery = lifecycle
            .recover_session(session.session_id, recovery_epoch, 22)
            .await
            .unwrap();
        assert!(
            recovery.claimed_agents.contains(&child.agent_instance_id),
            "the daemon-owned refresh child requires an exact restart claim"
        );
        assert!(
            recovery
                .pending_decisions
                .contains(&decision.decision_request_id),
            "the unresolved typed refresh decision is recoverable"
        );
        let child_after_claim = db
            .agent_instance(session.session_id, child.agent_instance_id)
            .await
            .unwrap()
            .expect("refresh child still exists for its typed reattachment");
        assert!(
            db.consume_agent_resume_claims_atomically(
                session.session_id,
                vec![(child.agent_instance_id, child_after_claim.revision)],
                recovery_epoch,
                23,
            )
            .await
            .unwrap(),
            "a replacement worker installs the typed endpoint before it consumes the child claim"
        );

        // This is the filtered worker handoff: only the reattached typed
        // host-operation decision enters `resume_recovered_decisions`.
        let recovered_handoff = AgentTreeRecovery {
            claimed_agents: vec![child.agent_instance_id],
            pending_decisions: vec![decision.decision_request_id],
            claimed_late_user_steers: Vec::new(),
            accepted_late_user_steers: Vec::new(),
        };
        let delivery = Arc::new(RecordingResolverDelivery::succeeding());
        let runtime = AgentTreeRuntime::new(
            lifecycle,
            Arc::new(FixedClock(24)),
            Arc::new(TestResolvers {
                parent_warm: false,
                utility_compatible: true,
            }),
            Arc::new(NoopDeadlines),
        )
        .with_resolver_delivery(delivery.clone());
        assert!(
            runtime
                .resume_recovered_decisions(session.session_id, &recovered_handoff)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            delivery
                .accepted
                .lock()
                .expect("recorded restart delivery")
                .as_slice(),
            &[(decision.decision_request_id, DecisionResolverRoute::Utility)],
            "the replacement worker redelivers the stranded resolving claim exactly once"
        );

        // Completion of the recovered delivery wins the durable terminal CAS;
        // replaying the same recovery handoff after it has a receipt cannot
        // deliver it again.
        let public_option = only_public_option_id(
            &db.decision_request(session.session_id, decision.decision_request_id)
                .await
                .unwrap()
                .expect("redelivered decision remains durable")
                .options_contract_json,
        );
        assert!(matches!(
            runtime
                .accept_resolver_result(
                    session.session_id,
                    decision.decision_request_id,
                    DecisionResolverRoute::Utility,
                    PublicDecisionAnswer::option(public_option),
                )
                .await
                .unwrap(),
            DecisionSettlement::Resolved(DecisionState::AutoResolved)
        ));
        runtime
            .resume_recovered_decisions(session.session_id, &recovered_handoff)
            .await
            .unwrap();
        assert_eq!(
            delivery
                .accepted
                .lock()
                .expect("recorded terminal restart delivery")
                .len(),
            1,
            "the terminal receipt makes a duplicate restart redelivery impossible"
        );
    }

    #[tokio::test]
    async fn runtime_routes_post_auto_host_child_answer_to_live_parent_after_child_detaches_once() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let parent = running_agent(&db, session.session_id, false).await;
        let child = running_child(&db, session.session_id, &parent, true).await;
        let live_agents = Arc::new(std::sync::Mutex::new(std::collections::HashSet::from([
            parent.agent_instance_id,
            child.agent_instance_id,
        ])));
        let runtime = AgentTreeRuntime::new(
            lifecycle.clone(),
            Arc::new(FixedClock(22)),
            Arc::new(PerAgentAttachmentResolvers {
                live_agents: live_agents.clone(),
            }),
            Arc::new(NoopDeadlines),
        );
        let decision =
            host_capability_refresh_decision(&lifecycle, &db, session.session_id, &child, 20).await;
        let (route, packet) = match runtime
            .begin_auto_resolution(session.session_id, decision.decision_request_id)
            .await
            .unwrap()
        {
            AutoResolutionBegin::Claimed { route, packet } => (route, packet),
            other => panic!("expected automatic host refresh claim, got {other:?}"),
        };
        let answer =
            PublicDecisionAnswer::option(only_public_option_id(&packet.options_contract_json));
        assert!(matches!(
            runtime
                .accept_resolver_result(
                    session.session_id,
                    decision.decision_request_id,
                    route,
                    answer.clone(),
                )
                .await
                .unwrap(),
            DecisionSettlement::Resolved(DecisionState::AutoResolved)
        ));

        // The host child is daemon-owned. Model its normal terminal/detached
        // state after the automatic operation completes while preserving the
        // direct requesting parent as the only live model endpoint.
        let operation = db
            .host_capability_refresh_operation_for_interrupt(
                crate::agent_tree::daemon_host_capability_refresh_authority(),
                session.session_id,
                db.interrupt_for_decision_request(session.session_id, decision.decision_request_id)
                    .await
                    .unwrap()
                    .expect("host refresh decision owns one interrupt"),
            )
            .await
            .unwrap()
            .expect("host refresh operation exists");
        let lease = match db
            .claim_host_capability_refresh_execution(
                crate::agent_tree::daemon_host_capability_refresh_authority(),
                session.session_id,
                operation.operation_id,
                Uuid::new_v4(),
                40,
                23,
            )
            .await
            .unwrap()
        {
            crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::Claimed {
                lease,
            } => lease,
            other => {
                panic!("auto-resolved host operation must claim for completion, got {other:?}")
            }
        };
        let snapshot = cockpit_proto::HostCapabilitySnapshot {
            generation: lease.snapshot_generation(),
            features: Vec::new(),
            dependencies: Vec::new(),
            secret_store: cockpit_proto::SecretStoreSnapshot::unconfigured_placeholder(),
        };
        let canonical_snapshot = crate::db::agent_tree_decisions::canonical_json_bytes(
            &serde_json::to_value(snapshot).unwrap(),
        )
        .unwrap();
        let snapshot_json = String::from_utf8(canonical_snapshot.clone()).unwrap();
        assert!(
            db.complete_host_capability_refresh_execution(
                crate::agent_tree::daemon_host_capability_refresh_authority(),
                session.session_id,
                operation.operation_id,
                &lease,
                snapshot_json,
                lease.snapshot_generation(),
                digest(&canonical_snapshot),
                24,
            )
            .await
            .unwrap()
        );
        let child_after_auto = db
            .agent_instance(session.session_id, child.agent_instance_id)
            .await
            .unwrap()
            .expect("auto-resolved host child remains addressable");
        assert!(matches!(
            db.transition_agent_instance(
                session.session_id,
                child.agent_instance_id,
                child_after_auto.revision,
                AgentInstanceState::Completed,
                r#"{"reason":"test_completed_host_child"}"#,
                24,
            )
            .await
            .unwrap(),
            AgentTransitionOutcome::Transitioned(_)
        ));
        live_agents
            .lock()
            .expect("per-agent attachment lock")
            .remove(&child.agent_instance_id);
        assert!(
            live_agents
                .lock()
                .expect("per-agent attachment lock")
                .contains(&parent.agent_instance_id)
        );

        for _ in 0..2 {
            assert!(matches!(
                runtime
                    .resolve_user_answer(session.session_id, decision.decision_request_id, answer.clone())
                    .await
                    .unwrap(),
                DecisionSettlement::Steered { target_agent_instance_id }
                    if target_agent_instance_id == parent.agent_instance_id
            ));
        }
        let claimed = db
            .claim_late_user_decision_steers(
                session.session_id,
                parent.agent_instance_id,
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        assert_eq!(
            claimed.len(),
            1,
            "the detached child cannot create a second parent steer"
        );
        assert_eq!(
            claimed[0].requesting_agent_instance_id,
            child.agent_instance_id
        );
        assert_eq!(claimed[0].agent_instance_id, parent.agent_instance_id);
    }

    #[tokio::test]
    async fn questiontool_contract_is_manual_and_resumes_only_with_its_exact_wire_response() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let agent = running_agent(&db, session.session_id, true).await;
        let questions = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Choose a bounded continuation".into(),
                options: vec![crate::db::wire::InterruptOption {
                    id: "continue".into(),
                    label: "Continue".into(),
                    description: None,
                    secondary: false,
                }],
                allow_freetext: false,
                command_detail: None,
                permission: false,
                approval_class: None,
                sandbox_escalation: None,
            }],
        };
        let interrupt_id = db
            .raise_interrupt_questions_with_agent_instance_and_payload(
                session.session_id,
                "tree-test-agent",
                Some(agent.agent_instance_id),
                "real question continuation",
                &questions,
                None,
            )
            .await
            .unwrap();
        let decision = lifecycle
            .request_decision_for_interrupt(
                session.session_id,
                NewDecisionContract::user_question_interrupt(
                    agent.agent_instance_id,
                    agent.revision,
                    &questions,
                    agent.workspace_ref.clone(),
                )
                .unwrap(),
                interrupt_id,
                20,
            )
            .await
            .unwrap();
        assert!(
            !decision.options_contract_json.contains("continue"),
            "the public QuestionTool contract must not retain caller option IDs"
        );
        let mappings = db
            .private_decision_option_mappings(session.session_id, decision.decision_request_id)
            .await
            .unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].continuation_option_id, "continue");
        assert!(mappings[0].opaque_option_id.starts_with("option:"));
        let public_option_id = mappings[0].opaque_option_id.clone();

        assert!(matches!(
            lifecycle
                .begin_auto_resolution(
                    session.session_id,
                    decision.decision_request_id,
                    &TestResolvers {
                        parent_warm: true,
                        utility_compatible: true,
                    },
                    21,
                )
                .await
                .unwrap(),
            AutoResolutionBegin::WaitingForUser
        ));
        assert!(
            lifecycle
                .resolve_user_answer(
                    session.session_id,
                    decision.decision_request_id,
                    PublicDecisionAnswer::Option {
                        id: "continue".into()
                    },
                    22,
                )
                .await
                .is_err()
        );
        assert!(
            lifecycle
                .resolve_user_answer(
                    session.session_id,
                    decision.decision_request_id,
                    PublicDecisionAnswer::InterruptResponse {
                        response: ResolveResponse::Single {
                            selected_id: "foreign".into(),
                        },
                    },
                    23,
                )
                .await
                .is_err()
        );
        assert!(matches!(
            lifecycle
                .resolve_user_answer(
                    session.session_id,
                    decision.decision_request_id,
                    PublicDecisionAnswer::InterruptResponse {
                        response: ResolveResponse::Single {
                            selected_id: public_option_id,
                        },
                    },
                    24,
                )
                .await
                .unwrap(),
            DecisionSettlement::Resolved(DecisionState::Answered)
        ));
        let interrupt = db.get_interrupt(interrupt_id).await.unwrap().unwrap();
        assert!(matches!(
            interrupt.response,
            Some(ResolveResponse::Single { selected_id }) if selected_id == "continue"
        ));
    }

    #[tokio::test]
    async fn host_refresh_uses_its_linked_questiontool_option_as_the_only_recommendation_authority()
    {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let agent = running_agent(&db, session.session_id, true).await;
        let questions = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Refresh local host capabilities?".into(),
                options: vec![
                    crate::db::wire::InterruptOption {
                        id: "cancel".into(),
                        label: "Keep current snapshot".into(),
                        description: None,
                        secondary: true,
                    },
                    crate::db::wire::InterruptOption {
                        id: "refresh".into(),
                        label: "Refresh".into(),
                        description: None,
                        secondary: false,
                    },
                ],
                allow_freetext: false,
                command_detail: None,
                permission: false,
                approval_class: None,
                sandbox_escalation: None,
            }],
        };
        let interrupt_id = db
            .raise_interrupt_questions_with_agent_instance_and_payload(
                session.session_id,
                "host-capability-refresh",
                Some(agent.agent_instance_id),
                "host capability refresh decision",
                &questions,
                None,
            )
            .await
            .unwrap();
        let operation = HostCapabilitiesRefreshOperation::new();
        let decision = lifecycle
            .request_decision_for_interrupt(
                session.session_id,
                NewDecisionContract::user_question_interrupt(
                    agent.agent_instance_id,
                    agent.revision,
                    &questions,
                    agent.workspace_ref.clone(),
                )
                .unwrap()
                .with_host_subject(HostDecisionSubject::HostCapabilitiesRefresh { operation }),
                interrupt_id,
                20,
            )
            .await
            .expect("the real host-refresh linked QuestionTool contract is persistable");
        let contract: serde_json::Value =
            serde_json::from_str(&decision.options_contract_json).unwrap();
        assert_eq!(contract["options"], serde_json::json!([]));
        let recommendation: serde_json::Value = serde_json::from_str(
            decision
                .recommendation_json
                .as_deref()
                .expect("host refresh has a typed recommendation"),
        )
        .unwrap();
        let offered = contract["interrupt_response_contract"]["questions"][0]["option_ids"]
            .as_array()
            .expect("linked response contract owns public option ids");
        assert!(offered.iter().any(|id| id == &recommendation["option_id"]));
        assert_eq!(
            recommendation["host_action"].as_str(),
            Some("refresh_local_host_capabilities")
        );
        let operation_id = operation.operation_id;
        let request_id = operation.request_id;
        let binding_session_id = session.session_id;
        let binding_agent_id = agent.agent_instance_id;
        let binding_decision_id = decision.decision_request_id;
        let persisted: (String, String, String, String) = db
            .read(move |conn| {
                let binding = conn.query_row(
                    "SELECT operation_id, request_id, interrupt_id, decision_request_id
                       FROM host_capability_refresh_operations
                      WHERE operation_id = ?1 AND request_id = ?2
                        AND session_id = ?3 AND agent_instance_id = ?4
                        AND state = 'pending'",
                    rusqlite::params![
                        operation_id.to_string(),
                        request_id.to_string(),
                        binding_session_id.to_string(),
                        binding_agent_id.to_string(),
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )?;
                Ok(binding)
            })
            .await
            .expect("the typed refresh ingress atomically persists its operation binding");
        assert_eq!(persisted.0, operation_id.to_string());
        assert_eq!(persisted.1, request_id.to_string());
        assert_eq!(persisted.2, interrupt_id.to_string());
        assert_eq!(persisted.3, binding_decision_id.to_string());
    }

    #[tokio::test]
    async fn agent_tree_attention_lifecycle_auto_disabled_deadline_and_prohibited_matrix() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());

        let disabled = running_agent(&db, session.session_id, false).await;
        let disabled_decision = lifecycle
            .request_decision(session.session_id, contract(&disabled), 20)
            .await
            .unwrap();
        assert_eq!(
            lifecycle
                .begin_auto_resolution(
                    session.session_id,
                    disabled_decision.decision_request_id,
                    &TestResolvers {
                        parent_warm: true,
                        utility_compatible: true
                    },
                    21,
                )
                .await
                .unwrap(),
            AutoResolutionBegin::WaitingForUser
        );

        let prohibited = running_agent(&db, session.session_id, true).await;
        let prohibited_contract = contract(&prohibited).with_host_subject(
            HostDecisionSubject::HostEffect(HostEffectClass::Destructive),
        );
        let prohibited_decision = lifecycle
            .request_decision(session.session_id, prohibited_contract, 22)
            .await
            .unwrap();
        assert_eq!(
            lifecycle
                .begin_auto_resolution(
                    session.session_id,
                    prohibited_decision.decision_request_id,
                    &TestResolvers {
                        parent_warm: true,
                        utility_compatible: true
                    },
                    23,
                )
                .await
                .unwrap(),
            AutoResolutionBegin::WaitingForUser
        );

        let deadline_agent = running_agent(&db, session.session_id, true).await;
        let deadline_decision = lifecycle
            .request_decision(session.session_id, contract(&deadline_agent), 24)
            .await
            .unwrap();
        assert!(
            lifecycle
                .expire_deadlines(session.session_id, 29)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            lifecycle
                .expire_deadlines(session.session_id, 30)
                .await
                .unwrap(),
            vec![deadline_decision.decision_request_id]
        );
        assert!(
            lifecycle
                .expire_deadlines(session.session_id, 31)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn agent_tree_attention_lifecycle_restart_rehydrates_each_state_once_and_rejects_late_results()
     {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let agent = running_agent(&db, session.session_id, true).await;
        let decision =
            host_capability_refresh_decision(&lifecycle, &db, session.session_id, &agent, 20).await;
        let begin = lifecycle
            .begin_auto_resolution(
                session.session_id,
                decision.decision_request_id,
                &TestResolvers {
                    parent_warm: true,
                    utility_compatible: true,
                },
                21,
            )
            .await
            .unwrap();
        let packet = match begin {
            AutoResolutionBegin::Claimed { route, packet } => {
                assert_eq!(route, DecisionResolverRoute::Utility);
                packet
            }
            other => panic!("expected resolver claim, got {other:?}"),
        };
        let public_option_id = only_public_option_id(&packet.options_contract_json);

        let epoch = Uuid::new_v4();
        let recovery = lifecycle
            .recover_session(session.session_id, epoch, 22)
            .await
            .unwrap();
        assert_eq!(recovery.pending_decisions, vec![packet.decision_request_id]);
        assert!(recovery.claimed_agents.is_empty());

        assert!(matches!(
            lifecycle
                .resolve_auto_result(
                    session.session_id,
                    packet.decision_request_id,
                    DecisionResolverRoute::Utility,
                    PublicDecisionAnswer::option(&public_option_id),
                    23,
                )
                .await
                .unwrap(),
            DecisionSettlement::Resolved(DecisionState::AutoResolved)
        ));
        assert!(matches!(
            lifecycle
                .resolve_auto_result(
                    session.session_id,
                    packet.decision_request_id,
                    DecisionResolverRoute::Utility,
                    PublicDecisionAnswer::option(&public_option_id),
                    24,
                )
                .await
                .unwrap(),
            DecisionSettlement::AlreadyTerminal(_)
        ));

        let recovery = lifecycle
            .recover_session(session.session_id, epoch, 25)
            .await
            .unwrap();
        assert_eq!(recovery.claimed_agents, vec![agent.agent_instance_id]);
        assert!(
            lifecycle
                .recover_session(session.session_id, epoch, 26)
                .await
                .unwrap()
                .claimed_agents
                .is_empty()
        );
        assert_eq!(
            lifecycle
                .recover_session(session.session_id, Uuid::new_v4(), 27)
                .await
                .unwrap()
                .claimed_agents,
            vec![agent.agent_instance_id],
            "a later daemon boot gets one new recovery claim for the live revision"
        );
    }

    #[tokio::test]
    async fn late_user_steer_is_exact_owner_bound_and_retryable_until_acknowledged() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let agent = running_agent(&db, session.session_id, true).await;
        let decision =
            host_capability_refresh_decision(&lifecycle, &db, session.session_id, &agent, 20).await;
        let packet = match lifecycle
            .begin_auto_resolution(
                session.session_id,
                decision.decision_request_id,
                &TestResolvers {
                    parent_warm: false,
                    utility_compatible: true,
                },
                21,
            )
            .await
            .unwrap()
        {
            AutoResolutionBegin::Claimed { route, packet } => {
                assert_eq!(route, DecisionResolverRoute::Utility);
                packet
            }
            other => panic!("expected utility claim, got {other:?}"),
        };
        let public_option_id = only_public_option_id(&packet.options_contract_json);
        assert!(matches!(
            lifecycle
                .resolve_auto_result(
                    session.session_id,
                    decision.decision_request_id,
                    DecisionResolverRoute::Utility,
                    PublicDecisionAnswer::option(&public_option_id),
                    22,
                )
                .await
                .unwrap(),
            DecisionSettlement::Resolved(DecisionState::AutoResolved)
        ));
        assert!(matches!(
            lifecycle
                .resolve_user_answer(
                    session.session_id,
                    decision.decision_request_id,
                    PublicDecisionAnswer::option(&public_option_id),
                    23,
                )
                .await
                .unwrap(),
            DecisionSettlement::Steered { .. }
        ));

        // A later question can park the root again before the post-auto user
        // steer is delivered. Recovery must claim both the steer and the
        // waiting root executor before queued durable input may run.
        let waiting_root = db
            .agent_instance(session.session_id, agent.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        let waiting_root_decision = lifecycle
            .request_decision(session.session_id, contract(&waiting_root), 23)
            .await
            .unwrap();
        assert_ne!(
            waiting_root_decision.decision_request_id,
            decision.decision_request_id
        );
        assert_eq!(
            db.agent_instance(session.session_id, agent.agent_instance_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            AgentInstanceState::WaitingForUser
        );

        let first_epoch = Uuid::new_v4();
        let first_recovery = lifecycle
            .recover_session(session.session_id, first_epoch, 24)
            .await
            .unwrap();
        assert!(
            first_recovery
                .claimed_agents
                .contains(&agent.agent_instance_id),
            "a waiting root needs the same exact activation claim as a running root"
        );
        let [first_steer] = first_recovery.claimed_late_user_steers.as_slice() else {
            panic!("expected exactly one recovered late user steer");
        };
        assert_eq!(first_steer.agent_instance_id, packet.agent_instance_id);
        assert_eq!(
            first_steer.decision_request_id,
            decision.decision_request_id
        );
        assert!(
            !lifecycle
                .ack_late_user_steer_delivery(
                    session.session_id,
                    first_steer.steer_id,
                    Uuid::new_v4(),
                    25,
                )
                .await
                .unwrap(),
            "a different executor epoch cannot acknowledge this owner's steer"
        );
        assert!(
            db.release_late_user_decision_steer_claim(
                session.session_id,
                first_steer.steer_id,
                first_epoch,
                26,
            )
            .await
            .unwrap()
        );

        let retry_epoch = Uuid::new_v4();
        let retry_recovery = lifecycle
            .recover_session(session.session_id, retry_epoch, 27)
            .await
            .unwrap();
        let [retry_steer] = retry_recovery.claimed_late_user_steers.as_slice() else {
            panic!("released late user steer must be rehydrated for its exact owner");
        };
        assert_eq!(retry_steer.steer_id, first_steer.steer_id);
        assert!(
            !lifecycle
                .ack_late_user_steer_delivery(
                    session.session_id,
                    retry_steer.steer_id,
                    retry_epoch,
                    28,
                )
                .await
                .unwrap(),
            "an executor cannot acknowledge a steer before its durable completion"
        );
        assert!(
            db.accept_late_user_decision_steer_execution(
                session.session_id,
                retry_steer.steer_id,
                retry_epoch,
                29,
            )
            .await
            .unwrap()
        );
        assert!(
            db.complete_late_user_decision_steer_execution(
                session.session_id,
                retry_steer.steer_id,
                retry_epoch,
                30,
            )
            .await
            .unwrap()
        );
        let receipt_epoch = Uuid::new_v4();
        let receipt_recovery = lifecycle
            .recover_session(session.session_id, receipt_epoch, 31)
            .await
            .unwrap();
        let [completed_steer] = receipt_recovery.claimed_late_user_steers.as_slice() else {
            panic!("a completed steer must recover for receipt-only acknowledgement");
        };
        assert_eq!(completed_steer.steer_id, retry_steer.steer_id);
        assert!(completed_steer.completed_at_unix_ms.is_some());
        assert!(
            lifecycle
                .ack_late_user_steer_delivery(
                    session.session_id,
                    completed_steer.steer_id,
                    receipt_epoch,
                    32,
                )
                .await
                .unwrap()
        );
        assert!(
            lifecycle
                .recover_session(session.session_id, Uuid::new_v4(), 33)
                .await
                .unwrap()
                .claimed_late_user_steers
                .is_empty()
        );
    }

    #[tokio::test]
    async fn host_refresh_post_auto_user_answer_reroutes_to_requesting_parent_once_across_recovery()
    {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let parent = running_agent(&db, session.session_id, true).await;
        // The production host-refresh child is daemon-owned and has no model
        // mailbox. This durable test uses an ordinary child solely to prove
        // the DB routing invariant: the refresh operation's direct parent is
        // the exact executor which must receive a post-auto user steer.
        let refresh_child = running_child(&db, session.session_id, &parent, true).await;
        let decision = host_capability_refresh_decision(
            &lifecycle,
            &db,
            session.session_id,
            &refresh_child,
            20,
        )
        .await;
        let packet = match lifecycle
            .begin_auto_resolution(
                session.session_id,
                decision.decision_request_id,
                &TestResolvers {
                    parent_warm: false,
                    utility_compatible: true,
                },
                21,
            )
            .await
            .unwrap()
        {
            AutoResolutionBegin::Claimed { route, packet } => {
                assert_eq!(route, DecisionResolverRoute::Utility);
                packet
            }
            other => panic!("expected utility auto-resolution claim, got {other:?}"),
        };
        let public_option_id = only_public_option_id(&packet.options_contract_json);
        assert!(matches!(
            lifecycle
                .resolve_auto_result(
                    session.session_id,
                    decision.decision_request_id,
                    DecisionResolverRoute::Utility,
                    PublicDecisionAnswer::option(&public_option_id),
                    22,
                )
                .await
                .unwrap(),
            DecisionSettlement::Resolved(DecisionState::AutoResolved)
        ));
        assert!(matches!(
            lifecycle
                .resolve_user_answer(
                    session.session_id,
                    decision.decision_request_id,
                    PublicDecisionAnswer::option(&public_option_id),
                    23,
                )
                .await
                .unwrap(),
            DecisionSettlement::Steered { target_agent_instance_id }
                if target_agent_instance_id == parent.agent_instance_id
        ));
        // Replaying the same client response is an idempotent receipt lookup,
        // never a second parent turn. The durable claim below must therefore
        // contain one row even across a later recovery epoch.
        assert!(matches!(
            lifecycle
                .resolve_user_answer(
                    session.session_id,
                    decision.decision_request_id,
                    PublicDecisionAnswer::option(&public_option_id),
                    24,
                )
                .await
                .unwrap(),
            DecisionSettlement::Steered { target_agent_instance_id }
                if target_agent_instance_id == parent.agent_instance_id
        ));

        let recovery_epoch = Uuid::new_v4();
        let claimed = db
            .claim_late_user_decision_steers(
                session.session_id,
                parent.agent_instance_id,
                recovery_epoch,
            )
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(
            claimed[0].requesting_agent_instance_id,
            refresh_child.agent_instance_id
        );
        assert_eq!(claimed[0].agent_instance_id, parent.agent_instance_id);
        let retry = db
            .claim_late_user_decision_steers(
                session.session_id,
                refresh_child.agent_instance_id,
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        assert!(
            retry.is_empty(),
            "the daemon-only child must never receive a model steer"
        );
        assert!(
            db.release_late_user_decision_steer_claim(
                session.session_id,
                claimed[0].steer_id,
                recovery_epoch,
                25,
            )
            .await
            .unwrap()
        );
        let recovery = lifecycle
            .recover_session(session.session_id, Uuid::new_v4(), 26)
            .await
            .unwrap();
        assert!(
            recovery
                .claimed_late_user_steers
                .iter()
                .any(|steer| steer.steer_id == claimed[0].steer_id
                    && steer.agent_instance_id == parent.agent_instance_id
                    && steer.requesting_agent_instance_id == refresh_child.agent_instance_id)
        );
    }

    #[tokio::test]
    async fn agent_tree_recovery_claims_waiting_children_before_their_decisions_can_replay() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let parent = running_agent(&db, session.session_id, false).await;
        let waiting = running_child(&db, session.session_id, &parent, false).await;
        let sibling = running_child(&db, session.session_id, &parent, false).await;
        lifecycle
            .request_decision(session.session_id, contract(&waiting), 20)
            .await
            .unwrap();

        let recovery = lifecycle
            .recover_session(session.session_id, Uuid::new_v4(), 21)
            .await
            .unwrap();
        assert!(recovery.claimed_agents.contains(&parent.agent_instance_id));
        assert!(recovery.claimed_agents.contains(&sibling.agent_instance_id));
        assert!(
            recovery.claimed_agents.contains(&waiting.agent_instance_id),
            "a waiting child must be reconciled with its executor before any pending decision can resume it"
        );
        assert_eq!(recovery.pending_decisions.len(), 1);
    }

    #[tokio::test]
    async fn recursive_completion_rejects_a_child_with_a_live_decision_without_checkpointing_parent()
     {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let root = running_agent(&db, session.session_id, false).await;
        let parent = running_child(&db, session.session_id, &root, false).await;
        db.insert_recursive_noninteractive_executor(
            session.session_id,
            parent.agent_instance_id,
            root.agent_instance_id,
            crate::db::agent_tree_decisions::ValidatedRecursiveNoninteractiveLaunch::parse_and_canonicalize(
                r#"{"version":2,"task_call_id":"task","label":"parent","child_agent":"child","model":{},"granted_tools":[],"cwd":"/repo"}"#,
            )
            .unwrap(),
            crate::db::agent_tree_decisions::ValidatedRecursiveNoninteractiveSnapshot::parse_and_canonicalize(
                r#"{"version":2,"history":[],"next_prompt":null,"pending_recursive":null}"#,
            )
            .unwrap(),
            20,
        )
        .await
        .unwrap();
        let child = running_child(&db, session.session_id, &parent, false).await;
        let decision = lifecycle
            .request_decision(session.session_id, contract(&child), 21)
            .await
            .unwrap();

        assert!(db
            .complete_recursive_noninteractive_children_and_checkpoint_parent(
                session.session_id,
                parent.agent_instance_id,
                crate::db::agent_tree_decisions::ValidatedRecursiveNoninteractiveSnapshot::parse_and_canonicalize(
                    r#"{"version":2,"history":["must-not-commit"],"next_prompt":null,"pending_recursive":null}"#,
                )
                .unwrap(),
                vec![(child.agent_instance_id, false)],
                22,
            )
            .await
            .is_err());
        let descriptor = db
            .recursive_noninteractive_recovery_descriptor(
                session.session_id,
                parent.agent_instance_id,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            descriptor.snapshot.as_json(),
            crate::db::agent_tree_decisions::ValidatedRecursiveNoninteractiveSnapshot::parse_and_canonicalize(
                r#"{"version":2,"history":[],"next_prompt":null,"pending_recursive":null}"#,
            )
            .unwrap()
            .as_json()
        );
        assert_eq!(
            db.agent_instance(session.session_id, child.agent_instance_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            AgentInstanceState::WaitingForUser
        );
        assert!(
            db.agent_terminal_receipt(session.session_id, child.agent_instance_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.decision_request(session.session_id, decision.decision_request_id)
                .await
                .unwrap()
                .is_some()
        );
        let public_option_id = only_public_option_id(&decision.options_contract_json);

        assert!(matches!(
            lifecycle
                .resolve_user_answer(
                    session.session_id,
                    decision.decision_request_id,
                    PublicDecisionAnswer::option(public_option_id),
                    23,
                )
                .await
                .unwrap(),
            DecisionSettlement::Resolved(DecisionState::Answered)
        ));
        db.complete_recursive_noninteractive_children_and_checkpoint_parent(
            session.session_id,
            parent.agent_instance_id,
            crate::db::agent_tree_decisions::ValidatedRecursiveNoninteractiveSnapshot::parse_and_canonicalize(
                r#"{"version":2,"history":["committed"],"next_prompt":null,"pending_recursive":null}"#,
            )
            .unwrap(),
            vec![(child.agent_instance_id, false)],
            24,
        )
        .await
        .unwrap();
        let child_after = db
            .agent_instance(session.session_id, child.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(child_after.state, AgentInstanceState::Completed);
        let receipt = db
            .agent_terminal_receipt(session.session_id, child.agent_instance_id)
            .await
            .unwrap()
            .expect("recursive terminalization records the normal lifecycle receipt");
        assert_eq!(receipt.terminal_state, "completed");
    }

    #[tokio::test]
    async fn recovery_covers_created_running_waiting_resolving_and_skips_every_terminal_state() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let parent = running_agent(&db, session.session_id, true).await;

        let created = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: Some(parent.agent_instance_id),
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: parent.resolved_profile_snapshot_id,
                    workspace_ref: parent.workspace_ref.clone(),
                    auto_answer_enabled: false,
                },
                20,
            )
            .await
            .unwrap();
        let running = running_child(&db, session.session_id, &parent, false).await;
        let waiting_user = running_child(&db, session.session_id, &parent, false).await;
        let waiting_user_decision = lifecycle
            .request_decision(session.session_id, contract(&waiting_user), 21)
            .await
            .unwrap();

        let waiting_approval = running_child(&db, session.session_id, &parent, false).await;
        let waiting_approval = match db
            .transition_agent_instance(
                session.session_id,
                waiting_approval.agent_instance_id,
                waiting_approval.revision,
                AgentInstanceState::WaitingForApproval,
                "{}",
                22,
            )
            .await
            .unwrap()
        {
            AgentTransitionOutcome::Transitioned(row) => row,
            other => panic!("approval-wait transition lost: {other:?}"),
        };

        let resolving = running_child(&db, session.session_id, &parent, true).await;
        let resolving_decision =
            host_capability_refresh_decision(&lifecycle, &db, session.session_id, &resolving, 23)
                .await;
        assert!(matches!(
            lifecycle
                .begin_auto_resolution(
                    session.session_id,
                    resolving_decision.decision_request_id,
                    &TestResolvers {
                        parent_warm: false,
                        utility_compatible: true,
                    },
                    24,
                )
                .await
                .unwrap(),
            AutoResolutionBegin::Claimed { .. }
        ));

        let mut terminal_ids = Vec::new();
        for (state, at) in [
            (AgentInstanceState::Completed, 25),
            (AgentInstanceState::Failed, 26),
            (AgentInstanceState::Cancelled, 27),
        ] {
            let agent = running_child(&db, session.session_id, &parent, false).await;
            let terminal = match db
                .transition_agent_instance(
                    session.session_id,
                    agent.agent_instance_id,
                    agent.revision,
                    state,
                    "{}",
                    at,
                )
                .await
                .unwrap()
            {
                AgentTransitionOutcome::Transitioned(row) => row,
                other => panic!("terminal transition lost: {other:?}"),
            };
            terminal_ids.push(terminal.agent_instance_id);
        }

        let recovery_epoch = Uuid::new_v4();
        let recovery = lifecycle
            .recover_session(session.session_id, recovery_epoch, 30)
            .await
            .unwrap();
        for agent_instance_id in [
            created.agent_instance_id,
            running.agent_instance_id,
            waiting_user.agent_instance_id,
            waiting_approval.agent_instance_id,
            resolving.agent_instance_id,
        ] {
            assert!(
                recovery.claimed_agents.contains(&agent_instance_id),
                "nonterminal state {agent_instance_id} must receive one executor reconciliation claim"
            );
        }
        assert!(
            recovery
                .pending_decisions
                .contains(&waiting_user_decision.decision_request_id)
        );
        assert!(
            recovery
                .pending_decisions
                .contains(&resolving_decision.decision_request_id)
        );
        let waiting_user_after = db
            .agent_instance(session.session_id, waiting_user.agent_instance_id)
            .await
            .unwrap()
            .expect("waiting-user child remains durable");
        assert!(
            db.consume_agent_resume_claims_atomically(
                session.session_id,
                vec![
                    (
                        waiting_user_after.agent_instance_id,
                        waiting_user_after.revision,
                    ),
                    (
                        waiting_approval.agent_instance_id,
                        waiting_approval.revision,
                    ),
                ],
                recovery_epoch,
                31,
            )
            .await
            .unwrap(),
            "a restarted worker must attach WaitingForUser and WaitingForApproval executors before replaying either decision"
        );
        for agent_instance_id in terminal_ids {
            assert!(
                !recovery.claimed_agents.contains(&agent_instance_id),
                "terminal agent {agent_instance_id} must not be resurrected by recovery"
            );
        }
    }

    #[tokio::test]
    async fn recovery_claims_waiting_root_before_any_queued_input_can_activate_it() {
        for waiting_state in [
            AgentInstanceState::WaitingForUser,
            AgentInstanceState::WaitingForApproval,
        ] {
            let db = crate::db::Db::open_in_memory().unwrap();
            let session = db.create_session("project", "/repo", "tree").await.unwrap();
            let lifecycle = AgentTreeLifecycle::new(db.clone());
            let root = running_agent(&db, session.session_id, false).await;
            let root = match db
                .transition_agent_instance(
                    session.session_id,
                    root.agent_instance_id,
                    root.revision,
                    waiting_state,
                    "{}",
                    20,
                )
                .await
                .unwrap()
            {
                AgentTransitionOutcome::Transitioned(root) => root,
                other => panic!("waiting root transition lost: {other:?}"),
            };
            let recovery_epoch = Uuid::new_v4();
            let recovery = lifecycle
                .recover_session(session.session_id, recovery_epoch, 21)
                .await
                .unwrap();
            assert!(
                recovery.claimed_agents.contains(&root.agent_instance_id),
                "{waiting_state:?} root must be activation-fenced before recovered input/replay"
            );
            // A client/FCM submission may already be buffered when startup
            // attaches the root endpoint.  Model work must remain behind the
            // same recovery gate until the exact durable attachment claim is
            // consumed; otherwise a waiting root could run the queued input
            // before its restored decision/deadline/replay state exists.
            let activation_gate = crate::engine::driver::RecoveryActivationGate::new();
            let queued_input_gate = activation_gate.clone();
            let (started_tx, mut started_rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                queued_input_gate
                    .wait()
                    .await
                    .expect("claimed recovery gate must be released, not aborted");
                let _ = started_tx.send(());
            });
            tokio::task::yield_now().await;
            assert!(matches!(
                started_rx.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ));
            assert!(
                db.consume_agent_resume_claim(
                    session.session_id,
                    root.agent_instance_id,
                    root.revision,
                    recovery_epoch,
                    22,
                )
                .await
                .unwrap()
            );
            activation_gate.release();
            tokio::time::timeout(std::time::Duration::from_secs(1), started_rx)
                .await
                .expect("queued input must start once recovery attachment is complete")
                .expect("queued input activation task must remain live");
        }
    }

    #[tokio::test]
    async fn recursive_recovery_claim_ack_is_all_or_nothing() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let parent = running_agent(&db, session.session_id, false).await;
        let child = running_child(&db, session.session_id, &parent, false).await;
        let epoch = Uuid::new_v4();

        assert!(
            db.claim_agent_resume(
                session.session_id,
                parent.agent_instance_id,
                parent.revision,
                epoch,
                20,
            )
            .await
            .unwrap()
        );
        assert!(
            db.claim_agent_resume(
                session.session_id,
                child.agent_instance_id,
                child.revision,
                epoch,
                20,
            )
            .await
            .unwrap()
        );

        assert!(
            !db.consume_agent_resume_claims_atomically(
                session.session_id,
                vec![
                    (parent.agent_instance_id, parent.revision),
                    // A stale subtree member must reject the whole recovery
                    // acknowledgement rather than consuming the parent.
                    (child.agent_instance_id, child.revision + 1),
                ],
                epoch,
                21,
            )
            .await
            .unwrap()
        );

        let claimed_rows: i64 = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM agent_resume_claims
                      WHERE session_id = ?1 AND recovery_epoch = ?2
                        AND consumed_at_unix_ms IS NULL",
                    [session.session_id.to_string(), epoch.to_string()],
                    |row| row.get(0),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(
            claimed_rows, 2,
            "partial subtree recovery acknowledgement is forbidden"
        );
    }

    #[tokio::test]
    async fn agent_tree_attention_lifecycle_attention_packet_is_redacted_and_host_approval_is_bound()
     {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let agent = running_agent(&db, session.session_id, true).await;
        let operation = HostApprovalOperation::new(
            "test-host-operation",
            serde_json::json!({
                "operation": "test",
                "candidate_effects": [{"selection": "approve", "execute": {"operation": "test"}}],
            }),
        )
        .unwrap();
        let operation_id = operation.operation_id;
        let operation_kind = operation.operation_kind.clone();
        let canonical_input_json = operation.canonical_input_json.clone();
        let input_digest = operation.input_digest.clone();
        let different_input = HostApprovalOperation::new(
            "test-host-operation",
            serde_json::json!({
                "operation": "different",
                "candidate_effects": [{"selection": "approve", "execute": {"operation": "different"}}],
            }),
        )
        .unwrap();
        let approval_question = crate::db::wire::InterruptQuestion::Single {
            prompt: "Approve the final host operation?".into(),
            options: vec![crate::db::wire::InterruptOption {
                id: "approve".into(),
                label: "Approve".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        let approval_questions = InterruptQuestionSet {
            questions: vec![approval_question.clone()],
        };
        let mut request = NewDecisionContract::user_question_interrupt(
            agent.agent_instance_id,
            agent.revision,
            &approval_questions,
            agent.workspace_ref.clone(),
        )
        .unwrap()
        .with_host_approval_subject(operation, HostApprovalAuthority::trusted_host());
        request.rationale_redaction_class = "secret".into();
        let interrupt_id = db
            .raise_interrupt_with_agent_instance(
                session.session_id,
                "host-approval-test",
                Some(agent.agent_instance_id),
                "approval prompt",
                Some(&approval_question),
            )
            .await
            .unwrap();
        db.reserve_host_approval_final_operation(
            session.session_id,
            agent.agent_instance_id,
            operation_id,
            operation_kind.clone(),
            canonical_input_json.clone(),
            input_digest.clone(),
            HostApprovalAuthority::trusted_host().into_db(),
            19,
        )
        .await
        .unwrap();
        let decision = lifecycle
            .request_decision_for_interrupt(session.session_id, request, interrupt_id, 20)
            .await
            .unwrap();
        assert_eq!(decision.host_approval_operation_id, Some(operation_id));
        let decision_request_id = decision.decision_request_id;
        let persisted_operation: String = db
            .read(move |conn| {
                let operation_id = conn.query_row(
                    "SELECT operation_id FROM agent_host_approval_operations
                     WHERE decision_request_id = ?1",
                    [decision_request_id.to_string()],
                    |row| row.get(0),
                )?;
                Ok(operation_id)
            })
            .await
            .unwrap();
        assert_eq!(persisted_operation, operation_id.to_string());

        let attention = lifecycle
            .attention_page(session.session_id, None, 10)
            .await
            .unwrap()
            .entries
            .pop()
            .unwrap();
        let serialized = format!("{attention:?}");
        assert!(!serialized.contains("resolver-context"));
        assert!(!serialized.contains("secret-value"));
        assert!(serialized.contains("redacted"));

        assert!(
            lifecycle
                .resolve_user_answer(
                    session.session_id,
                    decision.decision_request_id,
                    PublicDecisionAnswer::option("continue"),
                    21,
                )
                .await
                .is_err()
        );
        assert!(
            lifecycle
                .resolve_host_approval(
                    session.session_id,
                    decision.decision_request_id,
                    interrupt_id,
                    r#"{"kind":"single","data":{"selected_id":"approve_once"}}"#,
                    HostApprovalAuthority::trusted_host(),
                    22,
                )
                .await
                .is_err()
        );
        assert!(
            lifecycle
                .resolve_host_approval(
                    session.session_id,
                    decision.decision_request_id,
                    interrupt_id,
                    r#"{"kind":"single","data":{"selected_id":"approve"}}"#,
                    HostApprovalAuthority::trusted_host(),
                    23,
                )
                .await
                .unwrap()
                .is_resolved()
        );
        let selected_operation_id = operation_id.to_string();
        let (selected_response, selected_candidate): (serde_json::Value, serde_json::Value) = db
            .read(move |conn| {
                let (response_raw, candidate_raw): (String, String) = conn.query_row(
                    "SELECT selected_response_json, selected_candidate_json
                       FROM agent_host_approval_operations
                      WHERE operation_id = ?1",
                    [selected_operation_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                Ok((
                    serde_json::from_str(&response_raw)?,
                    serde_json::from_str(&candidate_raw)?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            selected_response
                .pointer("/data/selected_id")
                .and_then(serde_json::Value::as_str),
            Some("approve"),
            "the approved operation must retain the exact selected candidate"
        );
        assert_eq!(
            selected_candidate
                .pointer("/selection")
                .and_then(serde_json::Value::as_str),
            Some("approve"),
            "the terminal host operation must persist the full selected candidate, not only its UI option id"
        );
        assert_eq!(
            selected_candidate
                .pointer("/execute/operation")
                .and_then(serde_json::Value::as_str),
            Some("test"),
            "the persisted candidate must retain the exact selected effect"
        );
        assert!(
            !db.consume_host_approval_final_operation(
                HostApprovalAuthority::trusted_host().into_db(),
                interrupt_id,
                session.session_id,
                agent.agent_instance_id,
                operation_id,
                operation_kind.clone(),
                different_input.canonical_input_json,
                different_input.input_digest,
                24,
            )
            .await
            .unwrap(),
            "a matching operation id cannot consume approval for different immutable input"
        );
        assert!(
            db.consume_host_approval_final_operation(
                HostApprovalAuthority::trusted_host().into_db(),
                interrupt_id,
                session.session_id,
                agent.agent_instance_id,
                operation_id,
                operation_kind.clone(),
                canonical_input_json.clone(),
                input_digest.clone(),
                25,
            )
            .await
            .unwrap()
        );
        let (operation_state, handoff_state, handoff_key): (String, String, String) = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT operation.state, handoff.state, handoff.idempotency_key
                       FROM agent_host_approval_operations operation
                       JOIN agent_host_approval_effect_handoffs handoff
                         ON handoff.operation_id = operation.operation_id
                      WHERE operation.operation_id = ?1",
                    [operation_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(operation_state, "approved");
        assert_eq!(handoff_state, "ready");
        assert_eq!(handoff_key, operation_id.to_string());
        assert_eq!(
            db.claim_host_approval_effect_handoff(
                HostApprovalAuthority::trusted_host().into_db(),
                interrupt_id,
                session.session_id,
                agent.agent_instance_id,
                operation_id,
                operation_kind.clone(),
                canonical_input_json.clone(),
                input_digest.clone(),
                serde_json::to_string(&[serde_json::json!({
                    "execute": {"operation": "test"},
                })])
                .unwrap(),
                26,
            )
            .await
            .unwrap(),
            crate::db::agent_tree_decisions::HostApprovalEffectFence::Claimed,
            "only the concrete effect boundary may make the approval irrevocable"
        );
        assert!(
            !db.consume_host_approval_final_operation(
                HostApprovalAuthority::trusted_host().into_db(),
                interrupt_id,
                session.session_id,
                agent.agent_instance_id,
                operation_id,
                operation_kind.clone(),
                canonical_input_json.clone(),
                input_digest.clone(),
                27,
            )
            .await
            .unwrap(),
            "recovery must not redeliver an effect whose dispatch outcome is unknown"
        );
        assert!(
            db.complete_host_approval_final_operation(
                HostApprovalAuthority::trusted_host().into_db(),
                interrupt_id,
                session.session_id,
                agent.agent_instance_id,
                operation_id,
                operation_kind.clone(),
                canonical_input_json.clone(),
                input_digest.clone(),
                true,
                r#"{"outcome":"completed"}"#.into(),
                28,
            )
            .await
            .unwrap()
        );
        assert!(
            !db.consume_host_approval_final_operation(
                HostApprovalAuthority::trusted_host().into_db(),
                interrupt_id,
                session.session_id,
                agent.agent_instance_id,
                operation_id,
                operation_kind,
                canonical_input_json,
                input_digest,
                29,
            )
            .await
            .unwrap(),
            "a host approval operation is single-use"
        );
    }

    #[tokio::test]
    async fn host_approval_deadline_cancels_its_bound_operation_and_interrupt() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let lifecycle = AgentTreeLifecycle::new(db.clone());
        let agent = running_agent(&db, session.session_id, false).await;
        let operation = HostApprovalOperation::new(
            "deadline-bound-host-effect",
            serde_json::json!({
                "target":"safe-target",
                "payload_digest":"f".repeat(64),
                "candidate_effects": [{"selection": "approve", "execute": {"target": "safe-target"}}],
            }),
        )
        .unwrap();
        let question = crate::db::wire::InterruptQuestion::Single {
            prompt: "Approve?".into(),
            options: vec![crate::db::wire::InterruptOption {
                id: "approve".into(),
                label: "Approve".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        let interrupt_id = db
            .raise_interrupt_with_agent_instance(
                session.session_id,
                "host-approval-test",
                Some(agent.agent_instance_id),
                "approval",
                Some(&question),
            )
            .await
            .unwrap();
        db.reserve_host_approval_final_operation(
            session.session_id,
            agent.agent_instance_id,
            operation.operation_id,
            operation.operation_kind.clone(),
            operation.canonical_input_json.clone(),
            operation.input_digest.clone(),
            HostApprovalAuthority::trusted_host().into_db(),
            10,
        )
        .await
        .unwrap();
        let decision = lifecycle
            .request_decision_for_interrupt(
                session.session_id,
                NewDecisionContract::user_question_interrupt(
                    agent.agent_instance_id,
                    agent.revision,
                    &InterruptQuestionSet {
                        questions: vec![question.clone()],
                    },
                    agent.workspace_ref.clone(),
                )
                .unwrap()
                .with_host_approval_subject(operation, HostApprovalAuthority::trusted_host()),
                interrupt_id,
                10,
            )
            .await
            .unwrap();

        let foreign_cancel = serde_json::to_string(&ResolveResponse::Single {
            selected_id: "not-an-offered-deny".to_string(),
        })
        .unwrap();
        assert!(
            lifecycle
                .cancel_host_approval(
                    session.session_id,
                    decision.decision_request_id,
                    interrupt_id,
                    &foreign_cancel,
                    11,
                )
                .await
                .is_err()
        );
        assert_eq!(
            db.decision_request(session.session_id, decision.decision_request_id)
                .await
                .unwrap()
                .expect("invalid response must not terminalize the real decision")
                .state,
            DecisionState::Pending,
        );

        assert_eq!(
            lifecycle
                .expire_deadlines(session.session_id, 16)
                .await
                .unwrap(),
            vec![decision.decision_request_id]
        );
        let terminal = db
            .decision_request(session.session_id, decision.decision_request_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(terminal.state, DecisionState::TimedOut);
        let interrupt = db.get_interrupt(interrupt_id).await.unwrap().unwrap();
        assert_eq!(
            interrupt.state,
            crate::db::needs_attention::InterruptState::Resolved
        );
        assert_eq!(
            interrupt.response,
            Some(ResolveResponse::Cancel),
            "deadline expiry must deliver the terminal cancel response to the linked interrupt"
        );
        let receipt = db
            .decision_terminal_receipt(session.session_id, decision.decision_request_id)
            .await
            .unwrap()
            .expect("deadline terminalization must retain its receipt");
        assert_eq!(receipt.terminal_state, DecisionState::TimedOut.as_str());
        assert!(
            receipt.receipt_json.contains("\"redacted\":true"),
            "the terminal receipt must remain redacted while its typed state records timeout ownership"
        );
        let operation_state: String = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT state FROM agent_host_approval_operations WHERE operation_id = ?1",
                    [terminal.host_approval_operation_id.unwrap().to_string()],
                    |row| row.get(0),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(operation_state, "cancelled");
    }

    #[tokio::test]
    async fn cancellation_fences_approved_operations_and_boot_reconciles_dispatches() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let agent = running_agent(&db, session.session_id, false).await;
        let approved_operation_id = Uuid::new_v4();
        let dispatching_operation_id = Uuid::new_v4();
        let binding = HostApprovalOperation::new(
            "test_host_effect",
            serde_json::json!({
                "operation": "cancellation-fence",
                "candidate_effects": [{
                    "selection": "approve",
                    "execute": {"operation": "cancellation-fence"},
                }],
            }),
        )
        .unwrap();
        let operation_kind = binding.operation_kind;
        let canonical_input_json = binding.canonical_input_json;
        let input_digest = binding.input_digest;
        let session_id = session.session_id.to_string();
        let agent_id = agent.agent_instance_id.to_string();
        let approved_operation = approved_operation_id.to_string();
        let dispatching_operation = dispatching_operation_id.to_string();
        let operation_kind_for_insert = operation_kind.clone();
        let canonical_input_for_insert = canonical_input_json.clone();
        let input_digest_for_insert = input_digest.clone();
        let approved_operation_for_handoff = approved_operation.clone();
        let operation_kind_for_ready_handoff = operation_kind.clone();
        let canonical_input_for_ready_handoff = canonical_input_json.clone();
        let input_digest_for_ready_handoff = input_digest.clone();
        let operation_kind_for_consume = operation_kind.clone();
        let canonical_input_for_consume = canonical_input_json.clone();
        let input_digest_for_consume = input_digest.clone();
        let operation_kind_for_scope_cleanup = operation_kind.clone();
        let canonical_input_for_scope_cleanup = canonical_input_json.clone();
        let input_digest_for_scope_cleanup = input_digest.clone();
        let selected_response_json =
            r#"{"data":{"selected_id":"approve"},"kind":"single"}"#.to_owned();
        let selected_candidate_json = String::from_utf8(
            canonical_json_bytes(&serde_json::json!({
                "selection": "approve",
                "execute": {"operation": "cancellation-fence"},
            }))
            .unwrap(),
        )
        .unwrap();
        let selected_response_for_insert = selected_response_json.clone();
        let selected_candidate_for_insert = selected_candidate_json.clone();
        let selected_candidate_for_ready_handoff = selected_candidate_json.clone();
        let approved_revision = agent.revision;
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO agent_host_approval_operations (
                     operation_id, session_id, agent_instance_id, operation_kind, canonical_input_json, input_digest,
                     selected_response_json, selected_candidate_json, state, approved_agent_revision, created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'approved', ?9, 20)",
                rusqlite::params![
                    approved_operation,
                    session_id.clone(),
                    agent_id.clone(),
                    operation_kind_for_insert,
                    canonical_input_for_insert,
                    input_digest_for_insert,
                    selected_response_for_insert,
                    selected_candidate_for_insert,
                    approved_revision,
                ],
            )?;
            // A ready handoff is still pre-dispatch.  Subtree cancellation
            // must terminalize it atomically with the approved operation, so
            // normal effect-scope cleanup cannot hit an impossible CAS.
            conn.execute(
                "INSERT INTO agent_host_approval_effect_handoffs (
                     operation_id, session_id, agent_instance_id, operation_kind, canonical_input_json, input_digest,
                     selected_candidate_json, idempotency_key, state, dispatch_started_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'ready', 20)",
                rusqlite::params![
                    approved_operation_for_handoff,
                    session_id.clone(),
                    agent_id.clone(),
                    operation_kind_for_ready_handoff,
                    canonical_input_for_ready_handoff,
                    input_digest_for_ready_handoff,
                    selected_candidate_for_ready_handoff,
                    approved_operation_id.to_string(),
                ],
            )?;
            conn.execute(
                "INSERT INTO agent_host_approval_operations (
                     operation_id, session_id, agent_instance_id, operation_kind, canonical_input_json, input_digest,
                     selected_response_json, selected_candidate_json, state, approved_agent_revision, created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'dispatching', ?9, 20)",
                rusqlite::params![
                    dispatching_operation,
                    session_id.clone(),
                    agent_id.clone(),
                    operation_kind.clone(),
                    canonical_input_json.clone(),
                    input_digest.clone(),
                    selected_response_json,
                    selected_candidate_json.clone(),
                    approved_revision,
                ],
            )?;
            conn.execute(
                "INSERT INTO agent_host_approval_effect_handoffs (
                     operation_id, session_id, agent_instance_id, operation_kind, canonical_input_json, input_digest,
                     selected_candidate_json, idempotency_key, state, dispatch_started_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'dispatching', 20)",
                rusqlite::params![
                    dispatching_operation_id.to_string(),
                    session_id,
                    agent_id,
                    operation_kind,
                    canonical_input_json.clone(),
                    input_digest,
                    selected_candidate_json,
                    dispatching_operation_id.to_string(),
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let question = crate::db::wire::InterruptQuestion::Single {
            prompt: "Approve?".into(),
            options: vec![crate::db::wire::InterruptOption {
                id: "approve".into(),
                label: "Approve".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        let interrupt_id = db
            .raise_interrupt_with_agent_instance(
                session.session_id,
                "host-approval-test",
                Some(agent.agent_instance_id),
                "approval",
                Some(&question),
            )
            .await
            .unwrap();
        let decision_request_id = Uuid::new_v4();
        let bind_decision = decision_request_id.to_string();
        let bind_session = session.session_id.to_string();
        let bind_agent = agent.agent_instance_id.to_string();
        let bind_operation = approved_operation_id.to_string();
        let bind_interrupt = interrupt_id.to_string();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO decision_requests (
                     decision_request_id, agent_instance_id, session_id,
                     task_call_id_ref, workspace_ref,
                     options_contract_json, free_text_contract_json, recommendation_json,
                     rationale_redaction_class, decision_class, host_approval_operation_id,
                     deadline_unix_ms, policy_receipt_json,
                     resolver_route, state, revision, created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, NULL, NULL, '{}', NULL, NULL, 'none', 'host_approval', ?4, NULL, NULL, 'user', 'pending', 0, 20, 20)",
                rusqlite::params![bind_decision, bind_agent, bind_session, bind_operation],
            )?;
            conn.execute(
                "UPDATE agent_host_approval_operations
                 SET decision_request_id = ?1
                 WHERE operation_id = ?2 AND session_id = ?3",
                rusqlite::params![
                    decision_request_id.to_string(),
                    approved_operation_id.to_string(),
                    session.session_id.to_string()
                ],
            )?;
            conn.execute(
                "UPDATE needs_attention
                 SET decision_request_id = ?1
                 WHERE interrupt_id = ?2",
                rusqlite::params![decision_request_id.to_string(), bind_interrupt],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        assert!(matches!(
            db.transition_agent_instance(
                session.session_id,
                agent.agent_instance_id,
                agent.revision,
                AgentInstanceState::Cancelled,
                "{}",
                21,
            )
            .await
            .unwrap(),
            AgentTransitionOutcome::Transitioned(_)
        ));
        assert!(
            !db.consume_host_approval_final_operation(
                HostApprovalAuthority::trusted_host().into_db(),
                interrupt_id,
                session.session_id,
                agent.agent_instance_id,
                approved_operation_id,
                operation_kind_for_consume,
                canonical_input_for_consume,
                input_digest_for_consume,
                22,
            )
            .await
            .unwrap(),
            "cancellation must close an approved operation before it can dispatch"
        );
        assert!(
            db.reject_unclaimed_host_approval_final_operation(
                HostApprovalAuthority::trusted_host().into_db(),
                interrupt_id,
                session.session_id,
                agent.agent_instance_id,
                approved_operation_id,
                operation_kind_for_scope_cleanup,
                canonical_input_for_scope_cleanup,
                input_digest_for_scope_cleanup,
                22,
            )
            .await
            .unwrap(),
            "ordinary scope cleanup must accept the cancellation-owned ready handoff terminalization"
        );
        assert_eq!(
            db.reconcile_host_approval_dispatches(session.session_id, 23)
                .await
                .unwrap(),
            1
        );
        let states: (String, String, String, String, String) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM agent_host_approval_operations WHERE operation_id = ?1",
                        [approved_operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT state FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                        [approved_operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT completion_receipt_json FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                        [approved_operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT state FROM agent_host_approval_operations WHERE operation_id = ?1",
                        [dispatching_operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT state FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                        [dispatching_operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (states.0, states.1, states.3, states.4),
            (
                "cancelled".into(),
                "rejected".into(),
                "submission_unknown".into(),
                "submission_unknown".into(),
            )
        );
        assert!(
            states.2.contains("not_submitted") && states.2.contains("tree_cancelled"),
            "cancellation must leave an authoritative known-not-submitted receipt on the ready handoff"
        );
    }

    #[tokio::test]
    async fn boot_rejects_ready_host_handoff_without_replaying_approval() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("project", "/repo", "tree").await.unwrap();
        let agent = running_agent(&db, session.session_id, false).await;
        let operation = HostApprovalOperation::new(
            "restart_ready_effect",
            serde_json::json!({
                "candidate_effects": [{
                    "selection": "approve",
                    "execute": {"operation": "restart-ready"},
                }],
            }),
        )
        .unwrap();
        let selected_candidate = String::from_utf8(
            canonical_json_bytes(&serde_json::json!({
                "selection": "approve",
                "execute": {"operation": "restart-ready"},
            }))
            .unwrap(),
        )
        .unwrap();
        let operation_id = operation.operation_id;
        let session_id = session.session_id.to_string();
        let agent_id = agent.agent_instance_id.to_string();
        let operation_kind = operation.operation_kind.clone();
        let canonical_input_json = operation.canonical_input_json.clone();
        let input_digest = operation.input_digest.clone();
        let selected_candidate_for_handoff = selected_candidate.clone();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO agent_host_approval_operations (
                     operation_id, session_id, agent_instance_id, operation_kind,
                     canonical_input_json, input_digest, selected_response_json,
                     selected_candidate_json, state, approved_agent_revision, created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'approved', ?9, 20)",
                rusqlite::params![
                    operation_id.to_string(),
                    session_id,
                    agent_id,
                    operation_kind.clone(),
                    canonical_input_json.clone(),
                    input_digest.clone(),
                    r#"{"data":{"selected_id":"approve"},"kind":"single"}"#,
                    selected_candidate,
                    agent.revision,
                ],
            )?;
            conn.execute(
                "INSERT INTO agent_host_approval_effect_handoffs (
                     operation_id, session_id, agent_instance_id, operation_kind,
                     canonical_input_json, input_digest, selected_candidate_json,
                     idempotency_key, state, dispatch_started_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'ready', 20)",
                rusqlite::params![
                    operation_id.to_string(),
                    session.session_id.to_string(),
                    agent.agent_instance_id.to_string(),
                    operation_kind,
                    canonical_input_json,
                    input_digest,
                    selected_candidate_for_handoff,
                    operation_id.to_string(),
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        assert_eq!(
            db.reconcile_host_approval_dispatches(session.session_id, 21)
                .await
                .unwrap(),
            0,
            "only irrevocably dispatching handoffs count as submission-unknown reconciliation"
        );
        let states: (String, String, String) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM agent_host_approval_operations WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT state FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT completion_receipt_json FROM agent_host_approval_effect_handoffs WHERE operation_id = ?1",
                        [operation_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(states.0, "rejected");
        assert_eq!(states.1, "rejected");
        assert!(states.2.contains("not_submitted"));
    }
}

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::db::Db;
use crate::db::agent_installations::RedactedQuestionPolicy;
use crate::db::agent_tree_decisions::{
    AgentInstanceRow, AgentInstanceState, AgentTransitionOutcome, AgentTreePage,
    AgentTreePageCursor, DecisionAttentionRow, DecisionRequestRow, DecisionState,
    DecisionTransitionOutcome, HostCapabilityRefreshAuthority as DbHostCapabilityRefreshAuthority,
    NewDecisionRequest, StoredQuestionOverride,
};
use crate::db::wire::{InterruptQuestion, InterruptQuestionSet, ResolveResponse};

/// Closed host-owned classification. Only `LowRisk` may enter automatic
/// resolver routing; all other variants are intentionally non-auto-resolvable
/// even if a profile or resolver packet claims otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionClass {
    /// A model-originated QuestionTool prompt. These are manual by default:
    /// neither a model nor a profile can assert that arbitrary question text is
    /// low-risk.
    UserQuestion,
    LowRisk,
    Credential,
    Authorization,
    Destructive,
    ExternalAction,
    Publish,
    Purchase,
    Production,
    HostApproval,
}

impl DecisionClass {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "user_question" => Ok(Self::UserQuestion),
            "low_risk" => Ok(Self::LowRisk),
            "credential" => Ok(Self::Credential),
            "authorization" => Ok(Self::Authorization),
            "destructive" => Ok(Self::Destructive),
            "external_action" => Ok(Self::ExternalAction),
            "publish" => Ok(Self::Publish),
            "purchase" => Ok(Self::Purchase),
            "production" => Ok(Self::Production),
            "host_approval" => Ok(Self::HostApproval),
            _ => bail!("unknown durable decision class"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserQuestion => "user_question",
            Self::LowRisk => "low_risk",
            Self::Credential => "credential",
            Self::Authorization => "authorization",
            Self::Destructive => "destructive",
            Self::ExternalAction => "external_action",
            Self::Publish => "publish",
            Self::Purchase => "purchase",
            Self::Production => "production",
            Self::HostApproval => "host_approval",
        }
    }

    fn permits_auto_resolution(self) -> bool {
        self == Self::LowRisk
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionOption {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreeTextContract {
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_chars: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDecisionContract {
    pub agent_instance_id: Uuid,
    pub expected_agent_revision: i64,
    pub options: Vec<DecisionOption>,
    pub free_text: Option<FreeTextContract>,
    pub recommended_option_id: Option<String>,
    pub rationale_redaction_class: String,
    pub presentation: DecisionPresentation,
    /// The exact shape of a QuestionTool continuation, stripped of all prompt
    /// text and option labels. This lets the daemon validate a typed
    /// `ResolveResponse` without giving a resolver the original tool context.
    interrupt_response_contract: Option<RedactedInterruptQuestionSet>,
    /// Private host-owned classification. Tool and question callers can only
    /// build `UserQuestion` through the public constructor below; actual
    /// operations receive their class from the daemon host.
    decision_subject: HostDecisionSubject,
    /// The actual QuestionTool host composition boundary attaches this opaque
    /// capability only after it has raised the real interrupt and reserved
    /// the exact final operation. A string/UUID in `decision_subject` is
    /// deliberately insufficient to bind an approval decision.
    host_approval_authority: Option<HostApprovalAuthority>,
}

/// Bounded presentation metadata for a decision request. The DB persists only
/// its safe display fields; caller-supplied task/workspace selectors are
/// discarded and the separately typed opaque references are derived from the
/// exact daemon-owned agent row. Neither a caller's tool context nor an
/// approval operation payload is accepted here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionPresentation {
    pub question: String,
    pub description: String,
    pub task_call_id: Option<String>,
    pub workspace_ref: Option<String>,
    /// Human rationale is bounded at ingress but deliberately replaced by a
    /// redaction marker before persistence/public projection.
    pub recommendation_rationale: Option<String>,
}

/// Exhaustive daemon-side effect classifier. A model, protocol client, or
/// prompt string cannot construct one. The single auto-resolvable category is
/// deliberately a host-local metadata refresh with no credential, authority,
/// mutation, external call, publish, purchase, or production effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostEffectClass {
    LocalMetadataRefresh,
    Credential,
    Authorization,
    Destructive,
    ExternalAction,
    Publish,
    Purchase,
    Production,
}

impl HostEffectClass {
    pub(crate) const fn decision_class(self) -> DecisionClass {
        match self {
            Self::LocalMetadataRefresh => DecisionClass::LowRisk,
            Self::Credential => DecisionClass::Credential,
            Self::Authorization => DecisionClass::Authorization,
            Self::Destructive => DecisionClass::Destructive,
            Self::ExternalAction => DecisionClass::ExternalAction,
            Self::Publish => DecisionClass::Publish,
            Self::Purchase => DecisionClass::Purchase,
            Self::Production => DecisionClass::Production,
        }
    }

    /// Narrow, host-owned semantics that may be exposed in a *redacted*
    /// resolver packet.  This is deliberately exhaustive and does not accept
    /// prompt text, labels, or caller-provided recommendation prose.  The
    /// semantic identifies the one daemon-local action, while the durable
    /// option mapping keeps the actual continuation option opaque.
    const fn resolver_recommendation(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::LocalMetadataRefresh => Some(("refresh", "refresh_local_host_capabilities")),
            Self::Credential
            | Self::Authorization
            | Self::Destructive
            | Self::ExternalAction
            | Self::Publish
            | Self::Purchase
            | Self::Production => None,
        }
    }
}

/// The only production unattended-effect ingress. Refreshing the locally
/// probed host-capability snapshot reads daemon-owned metadata and does not
/// execute a command, disclose a credential, alter authorization, mutate a
/// destructive target, contact an external service, publish, purchase, or
/// touch production. Keep the classifier at this host boundary rather than
/// allowing a request label or UI string to select `LowRisk`.
pub(crate) const fn classify_host_capabilities_refresh() -> HostEffectClass {
    HostEffectClass::LocalMetadataRefresh
}

/// Immutable daemon-owned identity for one locally probed host-capability
/// refresh.  Unlike a generic low-risk decision, this describes a real host
/// operation with a restart-recoverable execution state machine.  The request
/// UUID is deliberately distinct from the decision/interrupt UUIDs: one RPC
/// owns one operation even while the decision is reattached after a daemon
/// restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostCapabilitiesRefreshOperation {
    pub operation_id: Uuid,
    pub request_id: Uuid,
    /// Only the direct daemon RPC creates a dedicated child.  Isolated
    /// lifecycle fixtures use the same durable decision state machine but no
    /// daemon operation child; production composition must carry this marker
    /// so storage requires the pre-bind initialization descriptor.
    requires_dedicated_child_initialization: bool,
}

impl HostCapabilitiesRefreshOperation {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self {
            operation_id: Uuid::now_v7(),
            request_id: Uuid::now_v7(),
            requires_dedicated_child_initialization: false,
        }
    }

    pub(crate) fn for_dedicated_child() -> Self {
        Self {
            operation_id: Uuid::now_v7(),
            request_id: Uuid::now_v7(),
            requires_dedicated_child_initialization: true,
        }
    }

    pub(crate) const fn requires_dedicated_child_initialization(self) -> bool {
        self.requires_dedicated_child_initialization
    }
}

/// Concrete operation facts classified by the daemon host before a durable
/// decision is created. This is deliberately not a public wire/request field:
/// callers cannot label a destructive, external, credential, publish,
/// purchase, production, authorization, or approval operation as low-risk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostApprovalOperation {
    pub operation_id: Uuid,
    pub operation_kind: String,
    /// Canonical JSON for the complete candidate set the host composition
    /// point derived. It is private durable state, never prompt prose or a
    /// client-provided capability. The database independently verifies that
    /// this exact canonical value hashes to `input_digest` on every boundary
    /// transition.
    pub canonical_input_json: String,
    pub input_digest: String,
}

impl HostApprovalOperation {
    /// Allocate one host-owned approval binding from the exact canonical input
    /// that will be handed to the effect boundary. Prompt copy is deliberately
    /// not an authority input: callers include the complete command, wire
    /// input, targets, scopes, and plan data appropriate to their effect.
    pub(crate) fn new(operation_kind: impl Into<String>, input: serde_json::Value) -> Result<Self> {
        let operation_kind = operation_kind.into();
        ensure!(
            !operation_kind.is_empty() && operation_kind.len() <= 128,
            "host approval operation kind is invalid"
        );
        let canonical = canonical_json_bytes(&input)?;
        ensure!(
            canonical.len() <= 512 * 1024,
            "host approval canonical input exceeds durable limit"
        );
        let mut digest = Sha256::new();
        digest.update(b"flycockpit.host-approval-input.v1\0");
        digest.update(&canonical);
        Ok(Self {
            operation_id: Uuid::now_v7(),
            operation_kind,
            canonical_input_json: String::from_utf8(canonical)
                .context("canonical host approval input was not UTF-8")?,
            input_digest: digest
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        })
    }

    /// Rehydrate the durable operation identity after the caller has
    /// recomputed this effect's kind and canonical input digest.  This is
    /// intentionally not a constructor: replay must first prove that its
    /// freshly-derived facts still match the persisted capability, then carry
    /// that same UUID through the concrete effect handoff and terminal receipt.
    pub(crate) fn with_persisted_operation_id(mut self, operation_id: Uuid) -> Result<Self> {
        ensure!(
            !operation_id.is_nil(),
            "persisted host approval operation id must not be nil"
        );
        self.operation_id = operation_id;
        Ok(self)
    }
}

pub(crate) fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
    fn write(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
        match value {
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
                out.extend(serde_json::to_vec(value)?);
            }
            serde_json::Value::String(_) => out.extend(serde_json::to_vec(value)?),
            serde_json::Value::Array(values) => {
                out.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    write(value, out)?;
                }
                out.push(b']');
            }
            serde_json::Value::Object(values) => {
                out.push(b'{');
                let mut entries = values.iter().collect::<Vec<_>>();
                entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
                for (index, (key, value)) in entries.into_iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(key)?);
                    out.push(b':');
                    write(value, out)?;
                }
                out.push(b'}');
            }
        }
        Ok(())
    }

    let mut canonical = Vec::new();
    write(value, &mut canonical)?;
    Ok(canonical)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostDecisionSubject {
    UserQuestion,
    /// Only daemon effect boundaries construct this exhaustive classification.
    /// QuestionTool itself always uses `UserQuestion`, so arbitrary model text
    /// can never be auto-resolved by claiming low risk.
    HostEffect(HostEffectClass),
    /// The one low-risk host effect with a durable execution descriptor.
    /// Keeping this separate from `HostEffect` prevents an ordinary future
    /// low-risk classification from accidentally inheriting probe-replay
    /// semantics.
    HostCapabilitiesRefresh {
        operation: HostCapabilitiesRefreshOperation,
    },
    HostApproval {
        operation: HostApprovalOperation,
    },
}

impl HostDecisionSubject {
    const fn decision_class(&self) -> DecisionClass {
        match self {
            Self::UserQuestion => DecisionClass::UserQuestion,
            Self::HostEffect(effect) => effect.decision_class(),
            Self::HostCapabilitiesRefresh { .. } => {
                classify_host_capabilities_refresh().decision_class()
            }
            Self::HostApproval { .. } => DecisionClass::HostApproval,
        }
    }

    fn host_approval_operation_id(&self) -> Option<Uuid> {
        match self {
            Self::HostApproval { operation } => Some(operation.operation_id),
            _ => None,
        }
    }

    fn resolver_recommendation(&self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::HostEffect(effect) => effect.resolver_recommendation(),
            Self::HostCapabilitiesRefresh { .. } => {
                classify_host_capabilities_refresh().resolver_recommendation()
            }
            Self::UserQuestion | Self::HostApproval { .. } => None,
        }
    }

    pub(crate) fn host_approval_operation(&self) -> Option<&HostApprovalOperation> {
        match self {
            Self::HostApproval { operation } => Some(operation),
            _ => None,
        }
    }

    pub(crate) fn host_capabilities_refresh_operation(
        &self,
    ) -> Option<&HostCapabilitiesRefreshOperation> {
        match self {
            Self::HostCapabilitiesRefresh { operation } => Some(operation),
            Self::UserQuestion | Self::HostEffect(_) | Self::HostApproval { .. } => None,
        }
    }
}

impl NewDecisionContract {
    /// Construct a regular user question. This path cannot select a decision
    /// class; the host operation composition point owns every elevated class.
    pub fn user_question(
        agent_instance_id: Uuid,
        expected_agent_revision: i64,
        options: Vec<DecisionOption>,
        free_text: Option<FreeTextContract>,
        recommended_option_id: Option<String>,
        rationale_redaction_class: String,
        presentation: DecisionPresentation,
    ) -> Result<Self> {
        validate_generic_decision_answer_channels(&options, free_text.as_ref())?;
        Ok(Self {
            agent_instance_id,
            expected_agent_revision,
            options,
            free_text,
            recommended_option_id,
            rationale_redaction_class,
            presentation,
            interrupt_response_contract: None,
            decision_subject: HostDecisionSubject::UserQuestion,
            host_approval_authority: None,
        })
    }

    /// Construct the one durable contract for a real QuestionTool interrupt.
    /// The stored representation deliberately contains only answer kinds and
    /// option identifiers; prompt text, labels, command details, and masking
    /// context remain on the existing interrupt row.
    pub(crate) fn user_question_interrupt(
        agent_instance_id: Uuid,
        expected_agent_revision: i64,
        questions: &InterruptQuestionSet,
        workspace_ref: Option<String>,
    ) -> Result<Self> {
        let contract = Self {
            agent_instance_id,
            expected_agent_revision,
            options: Vec::new(),
            free_text: None,
            recommended_option_id: None,
            rationale_redaction_class: "sensitive".to_string(),
            presentation: DecisionPresentation {
                question: "User question requires an answer".to_string(),
                description: "An interactive agent question is waiting".to_string(),
                task_call_id: None,
                workspace_ref,
                recommendation_rationale: None,
            },
            interrupt_response_contract: Some(RedactedInterruptQuestionSet::from_questions(
                questions,
            )?),
            decision_subject: HostDecisionSubject::UserQuestion,
            host_approval_authority: None,
        };
        validate_new_decision_contract_answer_channels(&contract)?;
        Ok(contract)
    }

    pub(crate) fn with_host_subject(mut self, subject: HostDecisionSubject) -> Self {
        assert!(
            !matches!(subject, HostDecisionSubject::HostApproval { .. }),
            "host approvals must be attached by the trusted QuestionTool host boundary"
        );
        self.decision_subject = subject;
        self
    }

    /// Attach the final-operation approval subject at the real QuestionTool
    /// host composition boundary. This is intentionally separate from the
    /// generic host-subject helper: callers cannot bind an approval merely by
    /// choosing the `HostApproval` enum variant and an operation UUID.
    pub(crate) fn with_host_approval_subject(
        mut self,
        operation: HostApprovalOperation,
        authority: HostApprovalAuthority,
    ) -> Self {
        self.decision_subject = HostDecisionSubject::HostApproval { operation };
        self.host_approval_authority = Some(authority);
        self
    }
}

/// The continuation portion of a QuestionTool contract. It is intentionally
/// not the wire `InterruptQuestionSet`: that type contains prompts, labels,
/// command detail, and other context a resolver/Attention projection must not
/// receive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RedactedInterruptQuestionSet {
    schema: String,
    questions: Vec<RedactedInterruptQuestion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RedactedInterruptQuestion {
    Single {
        option_ids: Vec<String>,
        allow_freetext: bool,
    },
    Multi {
        option_ids: Vec<String>,
        allow_freetext: bool,
    },
    Freetext,
}

impl RedactedInterruptQuestionSet {
    fn from_questions(set: &InterruptQuestionSet) -> Result<Self> {
        ensure!(
            !set.questions.is_empty() && set.questions.len() <= 16,
            "QuestionTool continuation must contain between one and sixteen questions"
        );
        let questions = set
            .questions
            .iter()
            .map(|question| match question {
                InterruptQuestion::Single {
                    options,
                    allow_freetext,
                    ..
                } => Ok(RedactedInterruptQuestion::Single {
                    option_ids: redacted_option_ids(
                        options.iter().map(|option| option.id.as_str()),
                    )?,
                    allow_freetext: *allow_freetext,
                }),
                InterruptQuestion::Multi {
                    options,
                    allow_freetext,
                    ..
                } => Ok(RedactedInterruptQuestion::Multi {
                    option_ids: redacted_option_ids(
                        options.iter().map(|option| option.id.as_str()),
                    )?,
                    allow_freetext: *allow_freetext,
                }),
                InterruptQuestion::Freetext { .. } => Ok(RedactedInterruptQuestion::Freetext),
            })
            .collect::<Result<Vec<_>>>()?;
        let contract = Self {
            schema: "interrupt_question_set_v1".to_string(),
            questions,
        };
        contract.validate_contract()?;
        Ok(contract)
    }

    /// A QuestionTool has its own typed response envelope, but it still must
    /// expose a real answer channel. `Cancel` aborts an existing interaction;
    /// it is not an answer channel that can make an otherwise empty question
    /// satisfiable.
    fn validate_contract(&self) -> Result<()> {
        ensure!(
            self.schema == "interrupt_question_set_v1",
            "unknown QuestionTool continuation contract schema"
        );
        ensure!(
            !self.questions.is_empty() && self.questions.len() <= 16,
            "QuestionTool continuation must contain between one and sixteen questions"
        );
        for question in &self.questions {
            question.validate_answer_channel()?;
        }
        Ok(())
    }

    fn validate_response(&self, response: &ResolveResponse) -> Result<()> {
        match response {
            ResolveResponse::Cancel => return Ok(()),
            ResolveResponse::Batch { responses } => {
                ensure!(
                    self.questions.len() > 1 && responses.len() == self.questions.len(),
                    "QuestionTool batch answer does not match its durable question count"
                );
                for (question, response) in self.questions.iter().zip(responses) {
                    ensure!(
                        !matches!(response, ResolveResponse::Batch { .. }),
                        "QuestionTool batch answer cannot nest a batch"
                    );
                    question.validate_response(response)?;
                }
            }
            response => {
                ensure!(
                    self.questions.len() == 1,
                    "QuestionTool multi-question answer must use a batch envelope"
                );
                self.questions[0].validate_response(response)?;
            }
        }
        Ok(())
    }
}

impl RedactedInterruptQuestion {
    fn validate_answer_channel(&self) -> Result<()> {
        match self {
            Self::Single {
                option_ids,
                allow_freetext,
            }
            | Self::Multi {
                option_ids,
                allow_freetext,
            } => {
                ensure!(
                    !option_ids.is_empty() || *allow_freetext,
                    "QuestionTool choice contract must offer an option or allow free-text"
                );
                Ok(())
            }
            Self::Freetext => Ok(()),
        }
    }

    fn validate_response(&self, response: &ResolveResponse) -> Result<()> {
        match (self, response) {
            (_, ResolveResponse::Cancel) => Ok(()),
            (
                Self::Single {
                    option_ids,
                    allow_freetext,
                },
                ResolveResponse::Single { selected_id },
            ) => {
                ensure!(
                    option_ids.iter().any(|id| id == selected_id),
                    "QuestionTool answer selected an option not offered by this question"
                );
                Ok(())
            }
            (
                Self::Single {
                    allow_freetext: true,
                    ..
                },
                ResolveResponse::Freetext { text },
            ) => validate_interrupt_free_text(text),
            (
                Self::Multi {
                    option_ids,
                    allow_freetext: _,
                },
                ResolveResponse::Multi { selected_ids },
            ) => {
                ensure!(
                    !selected_ids.is_empty() && selected_ids.len() <= option_ids.len(),
                    "QuestionTool multi-select answer has an invalid number of options"
                );
                let unique = selected_ids
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>();
                ensure!(
                    unique.len() == selected_ids.len()
                        && selected_ids
                            .iter()
                            .all(|id| option_ids.iter().any(|offered| offered == id)),
                    "QuestionTool multi-select answer contains an option not offered by this question"
                );
                Ok(())
            }
            (
                Self::Multi {
                    allow_freetext: true,
                    ..
                },
                ResolveResponse::Freetext { text },
            ) => validate_interrupt_free_text(text),
            (Self::Freetext, ResolveResponse::Freetext { text }) => {
                validate_interrupt_free_text(text)
            }
            _ => bail!("QuestionTool answer shape does not match its durable question contract"),
        }
    }
}

fn redacted_option_ids<'a>(ids: impl Iterator<Item = &'a str>) -> Result<Vec<String>> {
    let ids = ids.map(str::to_owned).collect::<Vec<_>>();
    ensure!(
        ids.len() <= 64 && ids.iter().all(|id| is_safe_option_id(id)),
        "QuestionTool option id is not a safe durable identifier"
    );
    ensure!(
        ids.iter().collect::<std::collections::BTreeSet<_>>().len() == ids.len(),
        "QuestionTool option identifiers must be unique"
    );
    Ok(ids)
}

fn validate_interrupt_free_text(text: &str) -> Result<()> {
    ensure!(
        !text.is_empty() && text.chars().count() <= 10_000 && !text.contains('\0'),
        "QuestionTool free-text answer violates its durable contract"
    );
    Ok(())
}

/// The only decision contract a parent or utility resolver receives. All
/// fields are persisted allowlisted projections; live model context, tool
/// handles, credentials, and approval material never appear here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedactedDecisionPacket {
    pub decision_request_id: Uuid,
    pub agent_instance_id: Uuid,
    /// Opaque immutable profile identity and resolver slot. These select the
    /// daemon-owned utility directory; they are not model credentials or a
    /// caller-supplied route.  The packet remains redaction-only.
    #[serde(skip)]
    pub resolver_profile_snapshot_id: Option<Uuid>,
    #[serde(skip)]
    pub resolver_slot: Option<String>,
    /// Stable topology identity only. A warm-parent executor registry uses it
    /// to select the already-live parent cache; it carries no transcript,
    /// tool context, or provider credential.
    pub parent_agent_instance_id: Option<Uuid>,
    pub session_id: Uuid,
    /// Opaque daemon-owned lineage copied from the decision row.  This is
    /// intentionally separate from the redacted presentation contract, whose
    /// caller-provided selectors are always discarded.
    pub task_call_id: Option<String>,
    /// Opaque daemon-owned workspace reference copied from the exact owner.
    pub workspace_ref: Option<String>,
    pub options_contract_json: String,
    pub free_text_contract_json: Option<String>,
    pub recommendation_json: Option<String>,
    pub rationale_redaction_class: String,
    pub decision_class: DecisionClass,
    pub deadline_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionResolverRoute {
    WarmParent,
    Utility,
}

impl DecisionResolverRoute {
    const fn as_str(self) -> &'static str {
        match self {
            Self::WarmParent => "warm_parent",
            Self::Utility => "utility",
        }
    }
}

/// Live daemon facts used only to select a resolver attempt after the
/// immutable profile and durable parent lineage have allowed it. These facts
/// are intentionally read-only; callers cannot pass authority booleans.
pub trait DecisionResolverDirectory: Send + Sync {
    /// Whether the exact executor which owns the decision is attached to this
    /// worker and has accepted its recovery claim.  Routing eligibility is
    /// deliberately separate from ownership: a utility can be available
    /// while the child continuation that must consume a manual reply, an
    /// automatic result, or a deadline has not yet been reattached.
    ///
    /// This must be an affirmative attachment fact, never a policy default.
    /// A directory that does not manage separate executors can return `true`
    /// from its own explicit implementation, but omitting the method must not
    /// make a pending one-shot decision settleable by accident.
    fn exact_owner_executor_is_live(&self, session_id: Uuid, agent_instance_id: Uuid) -> bool;

    fn parent_cache_resumable(&self, session_id: Uuid, parent_agent_instance_id: Uuid) -> bool;
    fn utility_slot_is_compatible(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        profile_snapshot_id: Option<Uuid>,
        resolver_slot: &str,
    ) -> bool;
}

/// Daemon time is injected so deadline behavior is deterministic in both the
/// worker and lifecycle tests.
pub trait AgentTreeClock: Send + Sync {
    fn now_unix_ms(&self) -> i64;
}

/// Scheduler boundary: production arranges a session-worker timer while
/// deterministic callers can record and explicitly fire the same work item.
pub trait DecisionDeadlineScheduler: Send + Sync {
    fn schedule(&self, session_id: Uuid, decision_request_id: Uuid, deadline_unix_ms: i64);
    fn cancel(&self, session_id: Uuid, decision_request_id: Uuid);
}

/// The daemon-owned resolver hand-off. An implementation must return only
/// after the verified warm parent or configured utility executor has accepted
/// the redacted packet for delivery; callers never receive model context or a
/// boolean that can impersonate this acknowledgement.
pub trait DecisionResolverDelivery: Send + Sync {
    fn accept(
        &self,
        session_id: Uuid,
        route: DecisionResolverRoute,
        packet: RedactedDecisionPacket,
    ) -> Result<()>;
}

/// Production composition point for durable request creation, injected clock,
/// resolver facts, and deadline scheduling. It owns no worker state; a timer
/// merely asks the lifecycle to execute the same terminal CAS.
#[derive(Clone)]
pub struct AgentTreeRuntime {
    lifecycle: AgentTreeLifecycle,
    clock: Arc<dyn AgentTreeClock>,
    resolvers: Arc<dyn DecisionResolverDirectory>,
    deadlines: Arc<dyn DecisionDeadlineScheduler>,
    resolver_delivery: Option<Arc<dyn DecisionResolverDelivery>>,
    /// Stable fair cursor for bounded live-maintenance reconciliation, scoped
    /// to the session whose durable order it represents. It is local
    /// scheduling state only; durable request order remains DB-owned.
    reconcile_cursors: Arc<std::sync::Mutex<std::collections::HashMap<Uuid, Option<(i64, Uuid)>>>>,
}

impl AgentTreeRuntime {
    pub fn new(
        lifecycle: AgentTreeLifecycle,
        clock: Arc<dyn AgentTreeClock>,
        resolvers: Arc<dyn DecisionResolverDirectory>,
        deadlines: Arc<dyn DecisionDeadlineScheduler>,
    ) -> Self {
        Self {
            lifecycle,
            clock,
            resolvers,
            deadlines,
            resolver_delivery: None,
            reconcile_cursors: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Production composition installs this only with the verified parent /
    /// utility executor registry. Leaving it absent keeps requests waiting for
    /// a user rather than manufacturing an unowned resolver claim.
    pub fn with_resolver_delivery(mut self, delivery: Arc<dyn DecisionResolverDelivery>) -> Self {
        self.resolver_delivery = Some(delivery);
        self
    }

    /// A decision is not merely a session-level task: its exact executor owns
    /// the parked continuation.  Do not settle, route, or expire it until the
    /// worker has registered that executor's live endpoint after recovery.
    async fn decision_owner_is_live(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
    ) -> Result<bool> {
        let Some(decision) = self
            .lifecycle
            .db
            .decision_request(session_id, decision_request_id)
            .await?
        else {
            return Ok(false);
        };
        Ok(self
            .resolvers
            .exact_owner_executor_is_live(session_id, decision.agent_instance_id))
    }

    pub async fn request_decision(
        &self,
        session_id: Uuid,
        contract: NewDecisionContract,
    ) -> Result<DecisionRequestRow> {
        let decision = self
            .lifecycle
            .request_decision(session_id, contract, self.clock.now_unix_ms())
            .await?;
        if !self
            .resolvers
            .exact_owner_executor_is_live(session_id, decision.agent_instance_id)
        {
            // The durable request remains pending. Recovery will either
            // attach this exact owner and activate it, or fail the worker
            // epoch rather than silently resolving someone else's parked
            // continuation.
            return Ok(decision);
        }
        if let Some(deadline) = decision.deadline_unix_ms {
            self.deadlines
                .schedule(session_id, decision.decision_request_id, deadline);
        }
        // Creating an eligible request is also the delivery boundary.  Do not
        // leave a durable `resolving` claim for a later recovery pass merely
        // because this is the first request in a freshly started daemon.
        self.begin_delivery(session_id, decision.decision_request_id)
            .await?;
        Ok(decision)
    }

    pub async fn begin_auto_resolution(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
    ) -> Result<AutoResolutionBegin> {
        if !self
            .decision_owner_is_live(session_id, decision_request_id)
            .await?
        {
            return Ok(AutoResolutionBegin::WaitingForUser);
        }
        self.lifecycle
            .begin_auto_resolution(
                session_id,
                decision_request_id,
                self.resolvers.as_ref(),
                self.clock.now_unix_ms(),
            )
            .await
    }

    /// Claim and hand off one automatic request as one production operation.
    /// A claim is retained only after a real executor accepts the redacted
    /// packet.  Without a delivery boundary the request remains pending for
    /// the user; a missing registry is never permission to strand it in
    /// `resolving`.
    async fn begin_delivery(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
    ) -> Result<AutoResolutionBegin> {
        if !self
            .decision_owner_is_live(session_id, decision_request_id)
            .await?
        {
            return Ok(AutoResolutionBegin::WaitingForUser);
        }
        let outcome = self
            .lifecycle
            .begin_auto_resolution(
                session_id,
                decision_request_id,
                self.resolvers.as_ref(),
                self.clock.now_unix_ms(),
            )
            .await?;
        let AutoResolutionBegin::Claimed { route, packet } = &outcome else {
            return Ok(outcome);
        };
        let Some(delivery) = self.resolver_delivery.as_ref() else {
            self.lifecycle
                .abandon_auto_resolution(
                    session_id,
                    packet.decision_request_id,
                    self.clock.now_unix_ms(),
                )
                .await?;
            return Ok(AutoResolutionBegin::WaitingForUser);
        };
        if delivery.accept(session_id, *route, packet.clone()).is_err() {
            self.lifecycle
                .abandon_auto_resolution(
                    session_id,
                    packet.decision_request_id,
                    self.clock.now_unix_ms(),
                )
                .await?;
            // A parent can disappear after the durable route selection but
            // before its executor acknowledges the packet. Re-evaluate the
            // live registry once and hand off to the configured utility when
            // it is now the deterministic fallback; never leave the old
            // warm-parent claim stranded.
            if *route == DecisionResolverRoute::WarmParent {
                let fallback = self
                    .lifecycle
                    .begin_auto_resolution(
                        session_id,
                        packet.decision_request_id,
                        self.resolvers.as_ref(),
                        self.clock.now_unix_ms(),
                    )
                    .await?;
                if let AutoResolutionBegin::Claimed {
                    route: DecisionResolverRoute::Utility,
                    packet,
                } = &fallback
                {
                    if delivery
                        .accept(session_id, DecisionResolverRoute::Utility, packet.clone())
                        .is_ok()
                    {
                        return Ok(fallback);
                    }
                    self.lifecycle
                        .abandon_auto_resolution(
                            session_id,
                            packet.decision_request_id,
                            self.clock.now_unix_ms(),
                        )
                        .await?;
                }
            }
            // Resolver availability is a routing optimization, never part of
            // the durable QuestionTool/Attention contract.  Once the claim
            // has been released, let the caller keep the waiting request and
            // its registered continuation instead of surfacing a transient
            // parent or utility failure as a failed question.
            return Ok(AutoResolutionBegin::WaitingForUser);
        }
        Ok(outcome)
    }

    pub async fn expire_deadline(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
    ) -> Result<DecisionSettlement> {
        if !self
            .decision_owner_is_live(session_id, decision_request_id)
            .await?
        {
            // Keep the timer registered: it is a no-op until the exact
            // owner attaches, at which point reconciliation retries the
            // same durable deadline transition.
            return Ok(DecisionSettlement::Retry);
        }
        let settlement = self
            .lifecycle
            .expire_decision_if_due(session_id, decision_request_id, self.clock.now_unix_ms())
            .await?;
        if settlement.is_terminal() {
            self.deadlines.cancel(session_id, decision_request_id);
        }
        Ok(settlement)
    }

    /// Reconcile requests created by a live executor after worker startup.
    /// Question and approval tools persist through the lifecycle directly so
    /// their worker-owned timer and resolver hand-off must not wait for a
    /// process restart to become active.  Only `pending` requests are started
    /// here; a persisted `resolving` request is a recovery concern and must
    /// never be claimed again through an illegal resolving-to-resolving CAS.
    pub(crate) async fn reconcile_pending_requests(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<TerminalDeadlineSettlement>> {
        self.reconcile_pending_requests_limited(
            session_id,
            crate::db::agent_tree_decisions::MAX_AGENT_TREE_PAGE_SIZE,
        )
        .await
    }

    /// Bounded worker-maintenance variant. Durable requests are sorted by the
    /// DB recovery query, so repeated calls make deterministic forward
    /// progress without letting a large attention backlog starve client work
    /// or deadline/event maintenance.
    pub(crate) async fn reconcile_pending_requests_limited(
        &self,
        session_id: Uuid,
        limit: usize,
    ) -> Result<Vec<TerminalDeadlineSettlement>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let now_unix_ms = self.clock.now_unix_ms();
        let mut after = self
            .reconcile_cursors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&session_id)
            .copied()
            .flatten();
        let started_after = after.is_some();
        let mut wrapped = false;
        let mut processed = 0usize;
        let mut last_processed = None;
        // A lifecycle CAS is deliberately not the continuation delivery
        // boundary.  Return every deadline winner to the session worker so it
        // can wake the live QuestionTool waiter or replay the exact parked
        // continuation through `deliver_terminal_agent_tree_interrupt`.
        // Keeping this list local to one bounded pass also makes a second
        // maintenance pass an idempotent CAS loser rather than a duplicate
        // delivery source.
        let mut terminal_deadlines = Vec::new();
        while processed < limit {
            let page_limit =
                (limit - processed).min(crate::db::agent_tree_decisions::MAX_AGENT_TREE_PAGE_SIZE);
            let page = self
                .lifecycle
                .db
                .recoverable_decision_requests_page(
                    session_id,
                    after.map(|(created_at_unix_ms, id)| AgentTreePageCursor {
                        created_at_unix_ms,
                        id,
                    }),
                    page_limit,
                )
                .await?;
            if page.entries.is_empty() {
                // A cursor can point past a concurrently settled/deleted tail.
                // Reset once and read the head to retain the old round-robin
                // behavior without re-materializing the full durable list.
                if after.is_some() && !wrapped {
                    after = None;
                    wrapped = true;
                    continue;
                }
                break;
            }
            let reached_end = page.next_cursor.is_none();
            for decision in page.entries {
                processed = processed.saturating_add(1);
                last_processed = Some((decision.created_at_unix_ms, decision.decision_request_id));
                if !self
                    .resolvers
                    .exact_owner_executor_is_live(session_id, decision.agent_instance_id)
                {
                    continue;
                }
                if let Some(deadline) = decision.deadline_unix_ms {
                    if deadline <= now_unix_ms {
                        let settlement = self
                            .expire_deadline(session_id, decision.decision_request_id)
                            .await?;
                        if let DecisionSettlement::Resolved(terminal_state) = settlement {
                            terminal_deadlines.push(TerminalDeadlineSettlement {
                                decision_request_id: decision.decision_request_id,
                                terminal_state,
                            });
                        }
                        continue;
                    }
                    self.deadlines
                        .schedule(session_id, decision.decision_request_id, deadline);
                }
                if decision.state == DecisionState::Pending {
                    self.begin_delivery(session_id, decision.decision_request_id)
                        .await?;
                }
            }
            if !reached_end {
                after = last_processed;
                continue;
            }
            // Preserve the previous cycle semantics: a turn that began
            // behind the head can fill its remaining bounded budget from the
            // head, but a head-started turn never repeats an entry merely
            // because the caller supplied a larger limit.
            if started_after && !wrapped && processed < limit {
                after = None;
                wrapped = true;
                continue;
            }
            after = None;
            break;
        }
        self.reconcile_cursors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(session_id, after.or(last_processed));
        Ok(terminal_deadlines)
    }

    /// Reconcile a persisted session after boot with injected daemon time.
    /// Every future deadline is deterministically re-registered; due ones use
    /// the same terminal CAS as a timer. Automatic routing occurs only when a
    /// real resolver delivery boundary is installed and accepts the redacted
    /// packet, while final results always re-enter `resolve_auto_result`.
    pub async fn recover_session(
        &self,
        session_id: Uuid,
        recovery_epoch: Uuid,
    ) -> Result<AgentTreeRecovery> {
        let now_unix_ms = self.clock.now_unix_ms();
        self.lifecycle
            .recover_session(session_id, recovery_epoch, now_unix_ms)
            .await
    }

    /// Resume durable decisions only after the worker has reconciled every
    /// non-root executor claim for this recovery epoch.  In particular, a
    /// waiting child must be reattached with its continuation or terminalized
    /// before a decision could make that child runnable again.
    pub(crate) async fn resume_recovered_decisions(
        &self,
        session_id: Uuid,
        recovery: &AgentTreeRecovery,
    ) -> Result<Vec<TerminalDeadlineSettlement>> {
        let now_unix_ms = self.clock.now_unix_ms();
        // As with live reconciliation, recovery owns only the durable
        // deadline CAS.  The worker must receive every winning settlement so
        // an already-attached live waiter is woken and a parked continuation
        // is replayed exactly once instead of being terminalized silently.
        let mut terminal_deadlines = Vec::new();
        for decision_id in &recovery.pending_decisions {
            let Some(decision) = self
                .lifecycle
                .db
                .decision_request(session_id, *decision_id)
                .await?
            else {
                continue;
            };
            if !self
                .resolvers
                .exact_owner_executor_is_live(session_id, decision.agent_instance_id)
            {
                continue;
            }
            if let Some(deadline) = decision.deadline_unix_ms {
                if deadline <= now_unix_ms {
                    let settlement = self.expire_deadline(session_id, *decision_id).await?;
                    if let DecisionSettlement::Resolved(terminal_state) = settlement {
                        terminal_deadlines.push(TerminalDeadlineSettlement {
                            decision_request_id: *decision_id,
                            terminal_state,
                        });
                    }
                    continue;
                }
                self.deadlines.schedule(session_id, *decision_id, deadline);
            }
            if decision.state == DecisionState::Resolving {
                // This boot may be recovering after the old worker claimed a
                // route but crashed before its executor acknowledged.  Never
                // CAS `resolving -> resolving`: redeliver the durable claim
                // to the same route, or release its exact revision so a user
                // (or a later healthy resolver) can make progress.
                let route = decision
                    .resolver_route
                    .as_deref()
                    .and_then(|route| match route {
                        "warm_parent" => Some(DecisionResolverRoute::WarmParent),
                        "utility" => Some(DecisionResolverRoute::Utility),
                        _ => None,
                    });
                let owner = self
                    .lifecycle
                    .db
                    .agent_instance(session_id, decision.agent_instance_id)
                    .await?;
                let parent = owner
                    .as_ref()
                    .and_then(|agent| agent.parent_agent_instance_id);
                let resolver_policy = match owner.as_ref() {
                    Some(owner) => {
                        self.lifecycle
                            .resolved_question_policy(session_id, owner)
                            .await?
                    }
                    None => None,
                };
                // A persisted warm route is only a prior attempt, never a
                // lease on a parent that has since stopped. Re-select after
                // releasing it so the normal parent-first policy can choose
                // a live utility fallback instead of redelivering to a stale
                // cache handle.
                let warm_parent_is_still_live = match parent {
                    Some(parent_id) => self
                        .lifecycle
                        .db
                        .agent_instance(session_id, parent_id)
                        .await?
                        .is_some_and(|parent| {
                            parent.state == AgentInstanceState::Running
                                && self.resolvers.parent_cache_resumable(session_id, parent_id)
                        }),
                    None => false,
                };
                if route == Some(DecisionResolverRoute::WarmParent) && !warm_parent_is_still_live {
                    self.lifecycle
                        .abandon_auto_resolution(session_id, *decision_id, now_unix_ms)
                        .await?;
                    self.begin_delivery(session_id, *decision_id).await?;
                    continue;
                }
                let delivered = match (route, self.resolver_delivery.as_ref()) {
                    (Some(route), Some(delivery)) => delivery
                        .accept(
                            session_id,
                            route,
                            packet_from_decision(
                                &decision,
                                parent,
                                owner
                                    .as_ref()
                                    .and_then(|agent| agent.resolved_profile_snapshot_id),
                                resolver_policy
                                    .as_ref()
                                    .map(|policy| policy.resolver_slot.clone()),
                            )?,
                        )
                        .is_ok(),
                    _ => false,
                };
                if !delivered {
                    self.lifecycle
                        .abandon_auto_resolution(session_id, *decision_id, now_unix_ms)
                        .await?;
                    if route == Some(DecisionResolverRoute::WarmParent) {
                        self.begin_delivery(session_id, *decision_id).await?;
                    }
                }
                continue;
            }
            self.begin_delivery(session_id, *decision_id).await?;
        }
        Ok(terminal_deadlines)
    }

    pub async fn accept_resolver_result(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        route: DecisionResolverRoute,
        answer: PublicDecisionAnswer,
    ) -> Result<DecisionSettlement> {
        if !self
            .decision_owner_is_live(session_id, decision_request_id)
            .await?
        {
            return Ok(DecisionSettlement::Retry);
        }
        let settlement = self
            .lifecycle
            .resolve_auto_result(
                session_id,
                decision_request_id,
                route,
                answer,
                self.clock.now_unix_ms(),
            )
            .await?;
        if settlement.is_terminal() {
            self.deadlines.cancel(session_id, decision_request_id);
        }
        Ok(settlement)
    }

    /// Settle a user decision only while the exact continuation owner is
    /// attached. This is the manual counterpart to the automatic/deadline
    /// guards above; otherwise a worker that failed to reattach a child could
    /// consume its one-shot answer and strand the durable continuation.
    pub async fn resolve_user_answer(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        answer: PublicDecisionAnswer,
    ) -> Result<DecisionSettlement> {
        let Some(decision) = self
            .lifecycle
            .db
            .decision_request(session_id, decision_request_id)
            .await?
        else {
            return Ok(DecisionSettlement::Retry);
        };
        // A nonterminal decision still owns one parked continuation, so it
        // may only be settled by that exact attached executor.  `AutoResolved`
        // is different: the durable terminal receipt intentionally converts a
        // late answer into a new user-authored steer.  Its daemon-only
        // host-operation child can already be terminal/detached while the
        // durable DB transaction routes that steer to its live requesting
        // parent, so applying the old owner-liveness gate here would strand
        // an otherwise valid user instruction.
        if !is_terminal(decision.state)
            && !self
                .resolvers
                .exact_owner_executor_is_live(session_id, decision.agent_instance_id)
        {
            return Ok(DecisionSettlement::Retry);
        }
        let settlement = self
            .lifecycle
            .resolve_user_answer(
                session_id,
                decision_request_id,
                answer,
                self.clock.now_unix_ms(),
            )
            .await?;
        if settlement.is_terminal() {
            self.deadlines.cancel(session_id, decision_request_id);
        }
        Ok(settlement)
    }

    /// Resolve an answer that the daemon has obtained from the exact linked
    /// private continuation. This is intentionally crate-private: public
    /// clients must use [`Self::resolve_user_answer`] with opaque tokens from
    /// the Attention projection, while the legacy QuestionTool path keeps its
    /// raw IDs confined to the parked continuation boundary.
    pub(crate) async fn resolve_trusted_private_continuation_answer(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        answer: PrivateDecisionContinuationAnswer,
    ) -> Result<DecisionSettlement> {
        let Some(decision) = self
            .lifecycle
            .db
            .decision_request(session_id, decision_request_id)
            .await?
        else {
            return Ok(DecisionSettlement::Retry);
        };
        if !is_terminal(decision.state)
            && !self
                .resolvers
                .exact_owner_executor_is_live(session_id, decision.agent_instance_id)
        {
            return Ok(DecisionSettlement::Retry);
        }
        let settlement = self
            .lifecycle
            .resolve_trusted_private_continuation_answer(
                session_id,
                decision_request_id,
                answer,
                self.clock.now_unix_ms(),
            )
            .await?;
        if settlement.is_terminal() {
            self.deadlines.cancel(session_id, decision_request_id);
        }
        Ok(settlement)
    }

    /// The trusted host path still belongs to the exact parked executor. A
    /// client may answer the real interrupt while recovery is attaching a
    /// child, but that reply must remain pending rather than consuming the
    /// child's one-shot approval continuation through the root worker.
    pub(crate) async fn resolve_host_approval(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        interrupt_id: Uuid,
        response_json: &str,
        authority: HostApprovalAuthority,
    ) -> Result<DecisionSettlement> {
        if !self
            .decision_owner_is_live(session_id, decision_request_id)
            .await?
        {
            return Ok(DecisionSettlement::Retry);
        }
        let settlement = self
            .lifecycle
            .resolve_host_approval(
                session_id,
                decision_request_id,
                interrupt_id,
                response_json,
                authority,
                self.clock.now_unix_ms(),
            )
            .await?;
        if settlement.is_terminal() {
            self.deadlines.cancel(session_id, decision_request_id);
        }
        Ok(settlement)
    }

    pub(crate) async fn cancel_host_approval(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        interrupt_id: Uuid,
        response_json: &str,
    ) -> Result<DecisionSettlement> {
        if !self
            .decision_owner_is_live(session_id, decision_request_id)
            .await?
        {
            return Ok(DecisionSettlement::Retry);
        }
        let settlement = self
            .lifecycle
            .cancel_host_approval(
                session_id,
                decision_request_id,
                interrupt_id,
                response_json,
                self.clock.now_unix_ms(),
            )
            .await?;
        if settlement.is_terminal() {
            self.deadlines.cancel(session_id, decision_request_id);
        }
        Ok(settlement)
    }

    /// A delivery worker reports a failure only after it has accepted the
    /// durable packet but cannot obtain a valid result. Release that exact
    /// resolving claim so the request is user-visible and recoverable rather
    /// than leaving a phantom resolver lease behind.
    pub async fn abandon_resolver_delivery(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
    ) -> Result<bool> {
        self.lifecycle
            .abandon_auto_resolution(session_id, decision_request_id, self.clock.now_unix_ms())
            .await
    }

    /// Retry one released warm-parent claim after its exact endpoint rejected
    /// or dropped the packet. The caller must first remove that endpoint from
    /// the live directory, so this re-evaluation can select only the utility
    /// fallback rather than manufacturing a second warm receipt.
    pub async fn retry_after_warm_parent_delivery_failure(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
    ) -> Result<AutoResolutionBegin> {
        self.begin_delivery(session_id, decision_request_id).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoResolutionBegin {
    Claimed {
        route: DecisionResolverRoute,
        packet: RedactedDecisionPacket,
    },
    WaitingForUser,
    AlreadyTerminal(String),
    Retry,
}

/// An answer received from the public AgentTree daemon boundary. Option IDs
/// are daemon-minted opaque capabilities from the redacted Attention
/// contract, never the original QuestionTool continuation IDs.
#[derive(Debug, Clone, PartialEq)]
pub enum PublicDecisionAnswer {
    Option {
        id: String,
    },
    FreeText {
        text: String,
    },
    /// A real QuestionTool continuation. This is deliberately distinct from
    /// free text: a resolver must return the daemon wire envelope that the
    /// parked tool call understands, and it is checked against the redacted
    /// question contract before the decision can settle.
    InterruptResponse {
        response: ResolveResponse,
    },
}

impl PublicDecisionAnswer {
    pub fn option(id: impl Into<String>) -> Self {
        Self::Option { id: id.into() }
    }
}

/// The private answer shape understood by a parked QuestionTool continuation.
///
/// This is deliberately distinct from [`PublicDecisionAnswer`].  A raw
/// continuation ID can be meaningful only after a daemon-owned continuation
/// boundary has selected the exact linked decision and translated it through
/// its private mapping.  In particular, this type has no daemon-wire decoder
/// and the public `ResolveAgentDecision` route cannot construct it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PrivateDecisionContinuationAnswer {
    Option { id: String },
    FreeText { text: String },
    InterruptResponse { response: ResolveResponse },
}

impl PrivateDecisionContinuationAnswer {
    pub(crate) fn option(id: impl Into<String>) -> Self {
        Self::Option { id: id.into() }
    }

    pub(crate) fn interrupt_response(response: ResolveResponse) -> Self {
        Self::InterruptResponse { response }
    }
}

/// Unforgeable-in-the-wire internal capability. The daemon's approval owner
/// constructs it after real host operation lookup; client requests and agent
/// prompts have no representation of this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HostApprovalRuntimeBinding {
    session_id: Uuid,
    agent_instance_id: Uuid,
    interrupt_id: Uuid,
}

/// Opaque capability carried only by a real host-owned QuestionTool
/// continuation.  The private runtime binding prevents a worker from
/// turning a database-shaped operation id or agent-id string into approval
/// authority: issuance happens either while holding the live pending
/// interrupt guard, or after re-validating the complete durable
/// decision/interrupt ownership tuple during recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostApprovalAuthority {
    db_authority: crate::db::agent_tree_decisions::HostApprovalAuthority,
    binding: HostApprovalRuntimeBinding,
}

impl HostApprovalAuthority {
    /// Issue an authority from the live `PendingInterrupt` guard after the
    /// real QuestionTool interrupt has been persisted and registered.  This
    /// is intentionally not a generic UUID constructor.
    pub(crate) fn for_registered_interrupt(
        session_id: Uuid,
        agent_instance_id: Uuid,
        interrupt_id: Uuid,
    ) -> Result<Self> {
        // This is a production authority constructor, not an assertion-only
        // debugging aid.  A nil member would otherwise turn the DB's exact
        // interrupt fence into a test-shaped escape hatch in release builds.
        ensure!(
            !session_id.is_nil() && !agent_instance_id.is_nil() && !interrupt_id.is_nil(),
            "host approval authority requires non-nil session, agent, and interrupt identities"
        );
        // SAFETY: cockpit-db deliberately exposes no safe constructor for
        // this private-field marker. Core is the daemon composition layer;
        // the caller above has already established the runtime binding, and
        // every DB transition independently verifies the persisted tuple.
        Ok(Self {
            db_authority: unsafe { std::mem::zeroed() },
            binding: HostApprovalRuntimeBinding {
                session_id,
                agent_instance_id,
                interrupt_id,
            },
        })
    }

    /// Reconstruct the authority only from a complete, typed durable binding
    /// owned by the worker.  In particular, this does not accept an arbitrary
    /// `agent_id: String` from an Attention packet as proof of host authority.
    pub(crate) fn for_durable_interrupt_binding(
        session_id: Uuid,
        decision: &DecisionRequestRow,
        interrupt: &crate::db::needs_attention::NeedsAttentionRow,
    ) -> Result<Self> {
        ensure!(
            decision.session_id == session_id && interrupt.session_id == session_id,
            "host approval decision and interrupt must belong to the active session"
        );
        ensure!(
            decision.decision_class == "host_approval",
            "host approval authority requires a host approval decision"
        );
        ensure!(
            decision.host_approval_operation_id.is_some(),
            "host approval decision is missing its final operation binding"
        );
        ensure!(
            interrupt.agent_instance_id == Some(decision.agent_instance_id),
            "host approval interrupt is not owned by the decision agent"
        );
        ensure!(
            matches!(
                interrupt.state,
                crate::db::needs_attention::InterruptState::Open
                    | crate::db::needs_attention::InterruptState::Parked
                    | crate::db::needs_attention::InterruptState::Executing
            ),
            "host approval interrupt is no longer live"
        );
        ensure!(
            interrupt.questions.is_some() || interrupt.question.is_some(),
            "host approval interrupt has no offered question set"
        );
        Self::for_registered_interrupt(
            session_id,
            decision.agent_instance_id,
            interrupt.interrupt_id,
        )
    }

    /// Narrow the capability to the reservation boundary. An authority from
    /// one registered continuation cannot reserve an operation for another
    /// session or agent, even inside the daemon composition crate.
    pub(crate) fn db_for_reservation(
        self,
        session_id: Uuid,
        agent_instance_id: Uuid,
    ) -> Result<crate::db::agent_tree_decisions::HostApprovalAuthority> {
        #[cfg(test)]
        if self.is_test_authority() {
            return Ok(self.db_authority);
        }
        ensure!(
            self.binding.session_id == session_id
                && self.binding.agent_instance_id == agent_instance_id,
            "host approval authority does not own this reservation"
        );
        Ok(self.db_authority)
    }

    /// Narrow the capability to the single atomic decision/interrupt bind.
    /// The DB remains the final state-machine authority, but this rejects a
    /// same-process attempt to reuse a real pending interrupt for a different
    /// decision owner or Attention row before it reaches storage.
    pub(crate) fn db_for_decision_binding(
        self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        interrupt_id: Uuid,
    ) -> Result<crate::db::agent_tree_decisions::HostApprovalAuthority> {
        #[cfg(test)]
        if self.is_test_authority() {
            return Ok(self.db_authority);
        }
        ensure!(
            self.binding.session_id == session_id
                && self.binding.agent_instance_id == agent_instance_id
                && self.binding.interrupt_id == interrupt_id,
            "host approval authority does not own this decision binding"
        );
        Ok(self.db_authority)
    }

    /// Narrow the capability to one terminal settlement.  Keep this distinct
    /// from reservation/binding: an authority minted for another live
    /// QuestionTool continuation must never be reusable merely because both
    /// continuations happen to belong to the same agent.
    pub(crate) fn db_for_settlement(
        self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        interrupt_id: Uuid,
    ) -> Result<crate::db::agent_tree_decisions::HostApprovalAuthority> {
        #[cfg(test)]
        if self.is_test_authority() {
            return Ok(self.db_authority);
        }
        ensure!(
            self.binding.session_id == session_id
                && self.binding.agent_instance_id == agent_instance_id
                && self.binding.interrupt_id == interrupt_id,
            "host approval authority does not own this settlement"
        );
        Ok(self.db_authority)
    }

    /// The exact effect handoff is a continuation of the same settled
    /// QuestionTool interrupt.  Keeping the interrupt in this accessor makes
    /// the authority non-transferable between two approved operations of the
    /// same agent; the typed DB handoff APIs also re-check that durable link.
    pub(crate) fn db_for_effect_handoff(
        self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        interrupt_id: Uuid,
    ) -> Result<crate::db::agent_tree_decisions::HostApprovalAuthority> {
        self.db_for_settlement(session_id, agent_instance_id, interrupt_id)
    }

    #[cfg(test)]
    pub(crate) fn trusted_host() -> Self {
        // Unit tests that exercise a storage transition directly have no live
        // daemon interrupt guard. Keep that seam test-only; production must
        // use one of the two runtime/durable binding constructors above.
        Self {
            db_authority: crate::db::agent_tree_decisions::HostApprovalAuthority::test_only(),
            binding: HostApprovalRuntimeBinding {
                session_id: Uuid::nil(),
                agent_instance_id: Uuid::nil(),
                interrupt_id: Uuid::nil(),
            },
        }
    }

    #[cfg(test)]
    fn is_test_authority(self) -> bool {
        self.binding.session_id.is_nil()
            && self.binding.agent_instance_id.is_nil()
            && self.binding.interrupt_id.is_nil()
    }

    #[cfg(test)]
    pub(crate) fn into_db(self) -> crate::db::agent_tree_decisions::HostApprovalAuthority {
        self.db_authority
    }
}

/// Internal call-graph capability for the one automatic decision ingress.
/// The database type has no safe constructor, and the storage transaction
/// still proves the exact durable refresh operation/interrupt/decision triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostCapabilityRefreshAuthority(DbHostCapabilityRefreshAuthority);

impl HostCapabilityRefreshAuthority {
    pub(crate) fn trusted_daemon_host() -> Self {
        // SAFETY: mirrors the approval composition bridge above. `cockpit-db`
        // exposes no safe constructor, so only this daemon-owned composition
        // path can carry the opaque marker into the typed DB entrypoint.
        Self(unsafe { std::mem::zeroed() })
    }

    pub(crate) fn into_db(self) -> DbHostCapabilityRefreshAuthority {
        self.0
    }
}

/// Issue the daemon-local capability used by worker and boot composition
/// paths. It is intentionally crate-private: protocol requests, agent
/// prompts, and a generic storage client cannot obtain this marker.
pub(crate) fn daemon_host_capability_refresh_authority() -> DbHostCapabilityRefreshAuthority {
    HostCapabilityRefreshAuthority::trusted_daemon_host().into_db()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionSettlement {
    Resolved(DecisionState),
    /// A user reply arrived after the automatic terminal receipt. The reply
    /// is a new durable steer. The target is normally the requesting agent;
    /// a daemon-only host-operation child records its direct requesting
    /// parent here because it has no model mailbox of its own.
    Steered {
        target_agent_instance_id: Uuid,
    },
    AlreadyTerminal(String),
    Retry,
}

/// A deadline transition which won the durable decision CAS.  The runtime
/// returns this to its worker composition boundary rather than attempting to
/// deliver a QuestionTool continuation itself: only that worker owns the
/// live interrupt hub and parked-replay registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalDeadlineSettlement {
    pub(crate) decision_request_id: Uuid,
    pub(crate) terminal_state: DecisionState,
}

enum DecisionForSettlement {
    Active(DecisionRequestRow),
    AlreadyTerminal(String),
}

impl DecisionSettlement {
    #[cfg(test)]
    fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved(_))
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Resolved(_) | Self::Steered { .. } | Self::AlreadyTerminal(_)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTreeRecovery {
    /// Agents this boot has claimed to rehydrate or reconcile. Every
    /// nonterminal child, including a waiting decision owner, is included so
    /// recovery cannot redeliver a decision before its exact executor is
    /// attached or terminalized.
    pub claimed_agents: Vec<Uuid>,
    pub pending_decisions: Vec<Uuid>,
    /// Private user steers claimed together with the recovery epoch. The
    /// session worker delivers these only to the associated existing
    /// continuation, then acknowledges the exact epoch.
    pub claimed_late_user_steers: Vec<crate::db::agent_tree_decisions::LateUserDecisionSteer>,
    /// Accepted-but-incomplete steers are not new deliveries. Their immutable
    /// continuation identity/checkpoint must be resumed by the reconstructed
    /// exact executor, never redelivered as another user message.
    pub accepted_late_user_steers: Vec<crate::db::agent_tree_decisions::LateUserDecisionSteer>,
}

#[derive(Debug, Clone)]
struct ResolvedDecisionPolicy {
    auto_answer_enabled: bool,
    auto_answer_disabled: bool,
    prohibited_classes: Vec<String>,
    required_decision_timeout_ms: u64,
    resolver_slot: String,
}

impl ResolvedDecisionPolicy {
    fn allows_automatic_resolution(&self, class: DecisionClass) -> bool {
        self.auto_answer_enabled
            && !self.auto_answer_disabled
            && class.permits_auto_resolution()
            && !self
                .prohibited_classes
                .iter()
                .any(|prohibited| prohibited == class.as_str())
    }

    fn deadline_from(&self, now_unix_ms: i64) -> Result<i64> {
        let timeout = i64::try_from(self.required_decision_timeout_ms)
            .context("resolved question timeout exceeds i64")?;
        now_unix_ms
            .checked_add(timeout)
            .context("resolved question deadline overflow")
    }
}

#[derive(Clone)]
pub struct AgentTreeLifecycle {
    db: Db,
}

impl AgentTreeLifecycle {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    async fn resolved_question_policy(
        &self,
        session_id: Uuid,
        agent: &AgentInstanceRow,
    ) -> Result<Option<ResolvedDecisionPolicy>> {
        let Some(snapshot_id) = agent.resolved_profile_snapshot_id else {
            // Absence is fail-closed. Mutable session defaults are never a
            // substitute for the profile that selected this agent.
            return Ok(None);
        };
        let snapshot = self
            .db
            .agent_profile_snapshot_by_id(session_id, snapshot_id)
            .await?
            .context("agent profile snapshot is not authorized for this session")?;
        match snapshot.reconstruct()?.question_policy {
            RedactedQuestionPolicy::Off => Ok(None),
            RedactedQuestionPolicy::Active {
                auto_answer_disabled,
                prohibited_classes,
                required_decision_timeout_ms,
                host_resource_ceiling_ms,
                resolver_slot,
                ..
            } => {
                let mut policy = ResolvedDecisionPolicy {
                    // The immutable profile determines whether automation is
                    // permitted at all; this durable per-agent reduction decides
                    // whether this concrete executor opted into it.
                    auto_answer_enabled: agent.auto_answer_enabled,
                    auto_answer_disabled,
                    prohibited_classes,
                    required_decision_timeout_ms,
                    resolver_slot,
                };
                // Apply the node's effective (consumed) session question
                // override on top of the immutable base (modes AC7). The
                // override was authorized reduce-only by
                // `agent_session_override::authorize_question`, but we re-clamp
                // defensively so a stale/replayed value can only ever tighten:
                // `Disable` forces auto-answer off, and `Reduce` may only
                // lengthen the wait, never below the base and never above the
                // host ceiling.
                self.apply_effective_question_override(
                    session_id,
                    agent.agent_instance_id,
                    host_resource_ceiling_ms,
                    &mut policy,
                )
                .await?;
                Ok(Some(policy))
            }
        }
    }

    /// Fold the node's effective session question override into `policy`. A
    /// no-op when the node carries no question override. Reduce-only by
    /// construction and re-clamped here for defence in depth.
    async fn apply_effective_question_override(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        host_resource_ceiling_ms: u64,
        policy: &mut ResolvedDecisionPolicy,
    ) -> Result<()> {
        let Some(state) = self
            .db
            .read_agent_override_state(session_id, agent_instance_id)
            .await?
        else {
            return Ok(());
        };
        let Some(question) = state.effective.and_then(|effective| effective.question) else {
            return Ok(());
        };
        match question {
            StoredQuestionOverride::Disable => {
                policy.auto_answer_disabled = true;
            }
            StoredQuestionOverride::Reduce {
                required_decision_timeout_seconds,
            } => {
                let requested_ms = u64::from(required_decision_timeout_seconds) * 1000;
                // Cap at the host ceiling, then floor at the immutable base LAST
                // so the base always wins: even a corrupt snapshot with
                // `base > ceiling` can only ever lengthen the wait (tighten),
                // never shorten it below the base (which would widen authority).
                policy.required_decision_timeout_ms = requested_ms
                    .min(host_resource_ceiling_ms)
                    .max(policy.required_decision_timeout_ms);
            }
        }
        Ok(())
    }

    async fn decision_deadline_from_resolved_profile(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<Option<i64>> {
        let agent = self
            .db
            .agent_instance(session_id, agent_instance_id)
            .await?
            .context("decision owner is not authorized for this session")?;
        self.resolved_question_policy(session_id, &agent)
            .await?
            .map(|policy| policy.deadline_from(now_unix_ms))
            .transpose()
    }

    pub async fn request_decision(
        &self,
        session_id: Uuid,
        contract: NewDecisionContract,
        now_unix_ms: i64,
    ) -> Result<DecisionRequestRow> {
        self.request_decision_with_attention(session_id, contract, None, now_unix_ms)
            .await
    }

    /// Bind a QuestionTool interrupt's pre-existing Attention row to the
    /// durable decision.  The interrupt remains the concrete waiter and
    /// restart replay anchor; this lifecycle owns the state/receipt.
    pub async fn request_decision_for_interrupt(
        &self,
        session_id: Uuid,
        contract: NewDecisionContract,
        interrupt_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<DecisionRequestRow> {
        self.request_decision_with_attention(session_id, contract, Some(interrupt_id), now_unix_ms)
            .await
    }

    async fn request_decision_with_attention(
        &self,
        session_id: Uuid,
        contract: NewDecisionContract,
        interrupt_id: Option<Uuid>,
        now_unix_ms: i64,
    ) -> Result<DecisionRequestRow> {
        // `NewDecisionContract` is a typed ingress, but tests and future
        // in-crate composition code can construct it directly. Recheck the
        // answer-channel invariant before deriving any deadline or touching
        // durable state so an empty generic decision can never park an agent.
        validate_new_decision_contract_answer_channels(&contract)?;
        let decision_class = contract.decision_subject.decision_class();
        let host_approval_operation_id = contract.decision_subject.host_approval_operation_id();
        let host_approval_authority = contract.host_approval_authority;
        let host_capability_refresh_operation = contract
            .decision_subject
            .host_capabilities_refresh_operation()
            .copied();
        ensure!(
            decision_class != DecisionClass::LowRisk || host_capability_refresh_operation.is_some(),
            "the only low-risk decision ingress is a daemon-owned host capability refresh"
        );
        // The timeout is selected solely from the immutable profile snapshot;
        // an agent/question caller cannot lengthen, omit, or invent it.
        let deadline_unix_ms = self
            .decision_deadline_from_resolved_profile(
                session_id,
                contract.agent_instance_id,
                now_unix_ms,
            )
            .await?;
        // Keep the ingress and persisted shape aligned: the DB allowlists and
        // normalizes this object, and answer validation reads its `options`
        // member after recovery. Do not serialize a bare array here.
        // Do not serialize `None` as a JSON `null` at this ingress.  The
        // storage codec treats an interrupt-response object as the one
        // QuestionTool discriminator, while `null` has no semantic value at
        // all.  Omitting it here keeps generic and QuestionTool ingress
        // unambiguous; the one persistence codec below emits the canonical
        // public `null` marker for a generic durable row.
        let mut options_contract = serde_json::Map::new();
        options_contract.insert(
            "options".to_string(),
            serde_json::to_value(contract.options)?,
        );
        options_contract.insert(
            "question".to_string(),
            serde_json::Value::String(contract.presentation.question),
        );
        options_contract.insert(
            "description".to_string(),
            serde_json::Value::String(contract.presentation.description),
        );
        // Presentation selectors are caller/model supplied context, not
        // lineage authority.  Do not even pass them through the durable
        // contract encoder; `create_decision_request_with_attention` derives
        // the separately typed opaque references from the exact daemon-owned
        // agent row in its lifecycle CAS.
        options_contract.insert("task_call_id".to_string(), serde_json::Value::Null);
        options_contract.insert("workspace_ref".to_string(), serde_json::Value::Null);
        if let Some(interrupt_response_contract) = contract.interrupt_response_contract {
            options_contract.insert(
                "interrupt_response_contract".to_string(),
                serde_json::to_value(interrupt_response_contract)?,
            );
        }
        let options_contract_json = serde_json::to_string(&options_contract)?;
        let free_text_contract_json = contract
            .free_text
            .map(|contract| {
                validate_bounded_free_text_contract(&contract)?;
                serde_json::to_string(&contract).context("serializing bounded free-text contract")
            })
            .transpose()?;
        let recommendation_rationale_is_present = contract
            .presentation
            .recommendation_rationale
            .as_deref()
            .map(str::trim)
            .filter(|rationale| !rationale.is_empty())
            .map(|rationale| {
                ensure!(
                    rationale.chars().count() <= 2_000 && !rationale.contains('\0'),
                    "decision recommendation rationale is not safely bounded"
                );
                Ok::<bool, anyhow::Error>(true)
            })
            .transpose()?
            .unwrap_or(false);
        let host_recommendation = contract.decision_subject.resolver_recommendation();
        let recommendation_json = host_recommendation
            .map(|(option_id, host_action)| {
                serde_json::to_string(&serde_json::json!({
                    "option_id": option_id,
                    // This is a typed daemon-host action identifier, never
                    // caller/model prose. The DB accepts exactly this one
                    // non-sensitive semantic and maps its private option id
                    // to an opaque resolver token.
                    "host_action": host_action,
                    // Rationale remains useful as an audit fact without
                    // carrying prompt/tool context into Attention.
                    "rationale": serde_json::Value::Null,
                    "rationale_redaction_class": contract.rationale_redaction_class,
                }))
            })
            .or_else(|| {
                contract.recommended_option_id.map(|option_id| {
                    serde_json::to_string(&serde_json::json!({
                        "option_id": option_id,
                        "rationale": recommendation_rationale_is_present.then_some("redacted"),
                        "rationale_redaction_class": contract.rationale_redaction_class,
                    }))
                })
            })
            .transpose()?;
        let input = NewDecisionRequest {
            session_id,
            agent_instance_id: contract.agent_instance_id,
            expected_agent_revision: contract.expected_agent_revision,
            waiting_state: if decision_class == DecisionClass::HostApproval {
                AgentInstanceState::WaitingForApproval
            } else {
                AgentInstanceState::WaitingForUser
            },
            options_contract_json,
            free_text_contract_json,
            recommendation_json,
            rationale_redaction_class: contract.rationale_redaction_class,
            decision_class: decision_class.as_str().into(),
            host_approval_operation_id,
            deadline_unix_ms,
            policy_receipt_json: serde_json::to_string(&serde_json::json!({
                "policy": if decision_class.permits_auto_resolution() { "automatic" } else { "manual" }
            }))?,
            // Resolver choice is host policy. The agent supplies no
            // route because a persisted request must not be able to
            // self-authorize a resolver after restart.
            resolver_route: None,
        };
        match (
            interrupt_id,
            host_capability_refresh_operation,
            host_approval_authority,
        ) {
            (Some(interrupt_id), None, Some(authority)) => {
                let authority = authority.db_for_decision_binding(
                    session_id,
                    input.agent_instance_id,
                    interrupt_id,
                )?;
                self.db
                    .create_host_approval_decision_for_interrupt(
                        input,
                        interrupt_id,
                        authority,
                        now_unix_ms,
                    )
                    .await
            }
            (Some(interrupt_id), Some(operation), None) => {
                self.db
                    .create_host_capability_refresh_decision_for_interrupt(
                        input,
                        operation.operation_id,
                        operation.request_id,
                        operation.requires_dedicated_child_initialization(),
                        interrupt_id,
                        HostCapabilityRefreshAuthority::trusted_daemon_host().into_db(),
                        now_unix_ms,
                    )
                    .await
            }
            (None, Some(_), None) => bail!(
                "host capability refresh must be composed through its real QuestionTool interrupt"
            ),
            (None, None, Some(_)) => {
                bail!("host approval must be composed through its real QuestionTool interrupt")
            }
            (Some(interrupt_id), None, None) => {
                self.db
                    .create_decision_request_for_interrupt(input, interrupt_id, now_unix_ms)
                    .await
            }
            (None, None, None) => self.db.create_decision_request(input, now_unix_ms).await,
            (_, Some(_), Some(_)) => bail!(
                "one decision cannot combine host capability refresh and host approval authority"
            ),
        }
    }

    pub async fn attention_page(
        &self,
        session_id: Uuid,
        after: Option<AgentTreePageCursor>,
        limit: usize,
    ) -> Result<AgentTreePage<DecisionAttentionRow>> {
        self.db
            .decision_attention_page(session_id, after, limit)
            .await
    }

    /// Chooses a resolver only after reading the durable policy class and the
    /// per-agent/session reductions. A cold parent never blocks the utility
    /// fallback, but unavailable routes leave the request pending for a user.
    pub async fn begin_auto_resolution(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        resolvers: &dyn DecisionResolverDirectory,
        now_unix_ms: i64,
    ) -> Result<AutoResolutionBegin> {
        let Some(decision) = self
            .db
            .decision_request(session_id, decision_request_id)
            .await?
        else {
            return Ok(AutoResolutionBegin::Retry);
        };
        if is_terminal(decision.state) {
            let receipt = self
                .db
                .decision_terminal_receipt(session_id, decision_request_id)
                .await?
                .context("terminal decision has no receipt")?;
            return Ok(AutoResolutionBegin::AlreadyTerminal(receipt.terminal_state));
        }
        let class = DecisionClass::parse(&decision.decision_class)?;
        let agent = self
            .db
            .agent_instance(session_id, decision.agent_instance_id)
            .await?
            .context("decision owner disappeared")?;
        let Some(policy) = self.resolved_question_policy(session_id, &agent).await? else {
            return Ok(AutoResolutionBegin::WaitingForUser);
        };
        let route = if !policy.allows_automatic_resolution(class) {
            None
        } else if let Some(parent_agent_instance_id) = agent.parent_agent_instance_id {
            let parent_is_running = self
                .db
                .agent_instance(session_id, parent_agent_instance_id)
                .await?
                .is_some_and(|parent| parent.state == AgentInstanceState::Running);
            if parent_is_running
                && resolvers.parent_cache_resumable(session_id, parent_agent_instance_id)
            {
                Some(DecisionResolverRoute::WarmParent)
            } else if resolvers.utility_slot_is_compatible(
                session_id,
                agent.agent_instance_id,
                agent.resolved_profile_snapshot_id,
                &policy.resolver_slot,
            ) {
                Some(DecisionResolverRoute::Utility)
            } else {
                None
            }
        } else if resolvers.utility_slot_is_compatible(
            session_id,
            agent.agent_instance_id,
            agent.resolved_profile_snapshot_id,
            &policy.resolver_slot,
        ) {
            Some(DecisionResolverRoute::Utility)
        } else {
            None
        };
        let Some(route) = route else {
            return Ok(AutoResolutionBegin::WaitingForUser);
        };
        match self
            .db
            .claim_decision_request_with_route(
                session_id,
                decision_request_id,
                decision.revision,
                route.as_str().to_owned(),
                now_unix_ms,
            )
            .await?
        {
            DecisionTransitionOutcome::Transitioned(claimed) => Ok(AutoResolutionBegin::Claimed {
                route,
                packet: packet_from_decision(
                    &claimed,
                    agent.parent_agent_instance_id,
                    agent.resolved_profile_snapshot_id,
                    Some(policy.resolver_slot),
                )?,
            }),
            DecisionTransitionOutcome::AlreadyTerminal(receipt) => {
                Ok(AutoResolutionBegin::AlreadyTerminal(receipt.terminal_state))
            }
            DecisionTransitionOutcome::RevisionConflict => Ok(AutoResolutionBegin::Retry),
        }
    }

    pub async fn resolve_user_answer(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        answer: PublicDecisionAnswer,
        now_unix_ms: i64,
    ) -> Result<DecisionSettlement> {
        validate_public_answer_option_tokens(&answer)?;
        let decision = self
            .db
            .decision_request(session_id, decision_request_id)
            .await?
            .context("decision request is not authorized for this session")?;
        if decision.state == DecisionState::AutoResolved {
            let private_answer = self
                .private_continuation_answer_for_public_answer(
                    session_id,
                    decision_request_id,
                    &answer,
                )
                .await?;
            validate_answer(&decision, &answer)?;
            let steer = self
                .db
                .record_late_user_decision_steer(
                    session_id,
                    decision_request_id,
                    answer_resume_payload("user", &private_answer),
                    now_unix_ms,
                )
                .await?;
            return Ok(DecisionSettlement::Steered {
                target_agent_instance_id: steer.agent_instance_id,
            });
        }
        if is_terminal(decision.state) {
            let receipt = self
                .db
                .decision_terminal_receipt(session_id, decision_request_id)
                .await?
                .context("terminal decision has no receipt")?;
            return Ok(DecisionSettlement::AlreadyTerminal(receipt.terminal_state));
        }
        ensure!(
            DecisionClass::parse(&decision.decision_class)? != DecisionClass::HostApproval,
            "host approvals are bound and resolved only by the host"
        );
        let owner = self
            .db
            .agent_instance(session_id, decision.agent_instance_id)
            .await?
            .context("decision owner disappeared")?;
        ensure!(
            owner.state == AgentInstanceState::WaitingForUser,
            "user answer does not own this decision state"
        );
        let private_answer = self
            .private_continuation_answer_for_public_answer(session_id, decision_request_id, &answer)
            .await?;
        validate_answer(&decision, &answer)?;
        self.settle(
            session_id,
            decision,
            DecisionState::Answered,
            &answer_receipt("user", &answer),
            Some(answer_resume_payload("user", &private_answer)),
            now_unix_ms,
        )
        .await
    }

    /// Resolve a response supplied by an already-authenticated private
    /// continuation boundary. The private IDs are translated *exactly* to
    /// daemon-minted public tokens before the normal public-answer path is
    /// reached; neither the daemon RPC nor resolver packets can select this
    /// route.
    pub(crate) async fn resolve_trusted_private_continuation_answer(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        answer: PrivateDecisionContinuationAnswer,
        now_unix_ms: i64,
    ) -> Result<DecisionSettlement> {
        let mappings = self
            .db
            .private_decision_option_mappings(session_id, decision_request_id)
            .await?;
        let public_answer = public_decision_answer_from_private_continuation(&answer, &mappings)?;
        self.resolve_user_answer(session_id, decision_request_id, public_answer, now_unix_ms)
            .await
    }

    pub async fn resolve_auto_result(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        route: DecisionResolverRoute,
        answer: PublicDecisionAnswer,
        now_unix_ms: i64,
    ) -> Result<DecisionSettlement> {
        validate_public_answer_option_tokens(&answer)?;
        let decision = match self
            .load_decision_for_settlement(session_id, decision_request_id)
            .await?
        {
            DecisionForSettlement::Active(decision) => decision,
            DecisionForSettlement::AlreadyTerminal(state) => {
                return Ok(DecisionSettlement::AlreadyTerminal(state));
            }
        };
        ensure!(
            DecisionClass::parse(&decision.decision_class)?.permits_auto_resolution(),
            "prohibited decision class cannot accept an automatic result"
        );
        ensure!(
            decision.state == DecisionState::Resolving,
            "automatic result requires the durable resolving claim"
        );
        ensure!(
            decision.resolver_route.as_deref() == Some(route.as_str()),
            "automatic result does not match the durable resolver claim"
        );
        let private_answer = self
            .private_continuation_answer_for_public_answer(session_id, decision_request_id, &answer)
            .await?;
        validate_answer(&decision, &answer)?;
        let source = match route {
            DecisionResolverRoute::WarmParent => "warm_parent",
            DecisionResolverRoute::Utility => "utility",
        };
        self.settle(
            session_id,
            decision,
            DecisionState::AutoResolved,
            &answer_receipt(source, &answer),
            Some(answer_resume_payload(source, &private_answer)),
            now_unix_ms,
        )
        .await
    }

    /// Recover the original continuation IDs only after the caller has used
    /// the public opaque answer API. Public tokens remain in receipts and
    /// every Attention/resolver packet.
    async fn private_continuation_answer_for_public_answer(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        answer: &PublicDecisionAnswer,
    ) -> Result<PrivateDecisionContinuationAnswer> {
        let mappings = self
            .db
            .private_decision_option_mappings(session_id, decision_request_id)
            .await?;
        private_decision_continuation_answer_from_public(answer, &mappings)
    }

    async fn abandon_auto_resolution(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<bool> {
        let Some(decision) = self
            .db
            .decision_request(session_id, decision_request_id)
            .await?
        else {
            return Ok(false);
        };
        if decision.state != DecisionState::Resolving {
            return Ok(false);
        }
        self.db
            .abandon_decision_resolver_claim(
                session_id,
                decision_request_id,
                decision.revision,
                now_unix_ms,
            )
            .await
    }

    /// Approval state is host-authored by an internal capability. The database
    /// joins the decision to its daemon-minted operation identity in the same
    /// terminal transaction; no boolean or string-shaped operation is trusted.
    pub(crate) async fn resolve_host_approval(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        interrupt_id: Uuid,
        response_json: &str,
        authority: HostApprovalAuthority,
        now_unix_ms: i64,
    ) -> Result<DecisionSettlement> {
        let decision = match self
            .load_decision_for_settlement(session_id, decision_request_id)
            .await?
        {
            DecisionForSettlement::Active(decision) => decision,
            DecisionForSettlement::AlreadyTerminal(state) => {
                return Ok(DecisionSettlement::AlreadyTerminal(state));
            }
        };
        ensure!(
            DecisionClass::parse(&decision.decision_class)? == DecisionClass::HostApproval,
            "decision is not a host approval"
        );
        let owner = self
            .db
            .agent_instance(session_id, decision.agent_instance_id)
            .await?
            .context("decision owner disappeared")?;
        ensure!(
            owner.state == AgentInstanceState::WaitingForApproval,
            "approval record does not own this decision state"
        );
        let response: ResolveResponse = serde_json::from_str(response_json)
            .context("host approval response is not a daemon response envelope")?;
        // The exact offered option set is part of the host-owned approval
        // contract. Check the persisted real interrupt here as well as at the
        // worker boundary, so no internal caller can turn a globally-known
        // allow id into approval for a different prompt.
        let interrupt = self
            .db
            .get_interrupt(interrupt_id)
            .await?
            .context("host approval interrupt is not available")?;
        let offered = interrupt.questions.or_else(|| {
            interrupt.question.map(|question| InterruptQuestionSet {
                questions: vec![question],
            })
        });
        let offered = offered.context("host approval interrupt has no offered question set")?;
        ensure!(
            crate::approval::host_approval_response_allows(&response, &offered),
            "host approval response is not offered by its exact prompt"
        );
        match self
            .db
            .resolve_host_approval_decision(
                session_id,
                decision.decision_request_id,
                interrupt_id,
                authority.db_for_settlement(
                    session_id,
                    decision.agent_instance_id,
                    interrupt_id,
                )?,
                decision.revision,
                &serde_json::json!({ "source": "host_approval" }).to_string(),
                &answer_resume_payload(
                    "user",
                    &PrivateDecisionContinuationAnswer::InterruptResponse { response },
                ),
                now_unix_ms,
            )
            .await?
        {
            DecisionTransitionOutcome::Transitioned(row) => {
                Ok(DecisionSettlement::Resolved(row.state))
            }
            DecisionTransitionOutcome::AlreadyTerminal(receipt) => {
                Ok(DecisionSettlement::AlreadyTerminal(receipt.terminal_state))
            }
            DecisionTransitionOutcome::RevisionConflict => Ok(DecisionSettlement::Retry),
        }
    }

    /// A user can always decline the real host prompt. This terminal path is
    /// deliberately separate from trusted approval: it never grants the bound
    /// operation, and the database atomically marks that operation cancelled
    /// with the decision receipt before the original interrupt is woken.
    pub(crate) async fn cancel_host_approval(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        interrupt_id: Uuid,
        response_json: &str,
        now_unix_ms: i64,
    ) -> Result<DecisionSettlement> {
        let decision = match self
            .load_decision_for_settlement(session_id, decision_request_id)
            .await?
        {
            DecisionForSettlement::Active(decision) => decision,
            DecisionForSettlement::AlreadyTerminal(state) => {
                return Ok(DecisionSettlement::AlreadyTerminal(state));
            }
        };
        ensure!(
            DecisionClass::parse(&decision.decision_class)? == DecisionClass::HostApproval,
            "decision is not a host approval"
        );
        let owner = self
            .db
            .agent_instance(session_id, decision.agent_instance_id)
            .await?
            .context("decision owner disappeared")?;
        ensure!(
            owner.state == AgentInstanceState::WaitingForApproval,
            "approval cancellation does not own this decision state"
        );
        let response: ResolveResponse = serde_json::from_str(response_json)
            .context("host approval cancellation is not a daemon response envelope")?;
        // Use the actual persisted QuestionTool row, not a caller-provided
        // approximation of its options.  This ties a denial to the exact
        // decision/interrupt binding and keeps arbitrary response envelopes
        // from becoming a generic "cancel host operation" capability.
        let linked_decision = self
            .db
            .decision_request_for_interrupt(session_id, interrupt_id)
            .await?
            .context("host approval cancellation interrupt is not bound to a decision")?;
        ensure!(
            linked_decision.decision_request_id == decision_request_id,
            "host approval cancellation interrupt belongs to a different decision"
        );
        let interrupt = self
            .db
            .get_interrupt(interrupt_id)
            .await?
            .context("host approval cancellation interrupt is not available")?;
        ensure!(
            interrupt.session_id == session_id,
            "host approval cancellation interrupt belongs to a different session"
        );
        let offered = interrupt.questions.or_else(|| {
            interrupt.question.map(|question| InterruptQuestionSet {
                questions: vec![question],
            })
        });
        let offered = offered.context("host approval cancellation has no offered question set")?;
        ensure!(
            crate::approval::host_approval_response_declines(&response, &offered),
            "host approval cancellation response is not cancel, an exact offered deny option, or the structured noninteractive denial"
        );
        // Parsing then re-serializing the typed response normalizes the
        // durable continuation payload. The response shape is still the exact
        // user-facing Cancel or offered deny selection, never arbitrary UI
        // text or a lossy synthetic marker.
        let canonical_response: ResolveResponse = serde_json::from_str(
            &serde_json::to_string(&response)
                .context("canonicalizing host approval cancellation response")?,
        )
        .context("canonical host approval cancellation response is invalid")?;
        self.settle(
            session_id,
            decision,
            DecisionState::Cancelled,
            &serde_json::json!({ "source": "host_approval_declined" }).to_string(),
            Some(answer_resume_payload(
                "user",
                &PrivateDecisionContinuationAnswer::InterruptResponse {
                    response: canonical_response,
                },
            )),
            now_unix_ms,
        )
        .await
    }

    /// Reconcile deadlines against the caller-injected time. A late timeout is
    /// a normal CAS loser and never invents another terminal receipt.
    pub async fn expire_deadlines(&self, session_id: Uuid, now_unix_ms: i64) -> Result<Vec<Uuid>> {
        let mut expired = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .db
                .recoverable_decision_requests_page(
                    session_id,
                    after.clone(),
                    crate::db::agent_tree_decisions::MAX_AGENT_TREE_PAGE_SIZE,
                )
                .await?;
            for decision in page.entries {
                if decision
                    .deadline_unix_ms
                    .is_none_or(|deadline| deadline > now_unix_ms)
                {
                    continue;
                }
                if matches!(
                    self.settle(
                        session_id,
                        decision.clone(),
                        DecisionState::TimedOut,
                        &serde_json::json!({ "source": "deadline" }).to_string(),
                        None,
                        now_unix_ms,
                    )
                    .await?,
                    DecisionSettlement::Resolved(DecisionState::TimedOut)
                ) {
                    expired.push(decision.decision_request_id);
                }
            }
            let Some(cursor) = page.next_cursor else {
                break;
            };
            after = Some(cursor);
        }
        Ok(expired)
    }

    /// Executes one timer delivery through the same durable deadline CAS.
    /// It is safe for a timer that fires after a user answer or cancellation.
    pub async fn expire_decision_if_due(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<DecisionSettlement> {
        let Some(decision) = self
            .db
            .decision_request(session_id, decision_request_id)
            .await?
        else {
            return Ok(DecisionSettlement::Retry);
        };
        if is_terminal(decision.state) {
            let receipt = self
                .db
                .decision_terminal_receipt(session_id, decision_request_id)
                .await?
                .context("terminal decision has no receipt")?;
            return Ok(DecisionSettlement::AlreadyTerminal(receipt.terminal_state));
        }
        if decision
            .deadline_unix_ms
            .is_none_or(|deadline| deadline > now_unix_ms)
        {
            return Ok(DecisionSettlement::Retry);
        }
        self.settle(
            session_id,
            decision,
            DecisionState::TimedOut,
            &serde_json::json!({ "source": "deadline" }).to_string(),
            None,
            now_unix_ms,
        )
        .await
    }

    /// Rehydration reads only durable tree state. It claims every nonterminal
    /// root and child by `(agent revision, daemon boot)` so a waiting decision
    /// owner can attach its exact executor before replay; the provider-dispatch
    /// permit remains independently running-only.
    pub async fn recover_session(
        &self,
        session_id: Uuid,
        recovery_epoch: Uuid,
        now_unix_ms: i64,
    ) -> Result<AgentTreeRecovery> {
        // A successor daemon first fences stale unacknowledged steer claims
        // from the crashed worker, then claims each delivery atomically below.
        self.db
            .begin_late_user_decision_steer_recovery(session_id, recovery_epoch)
            .await?;
        let mut after = None;
        let mut claimed_agents = Vec::new();
        // Steer delivery is deliberately independent from executor recovery
        // claims. Every nonterminal root is claimed below, but either a
        // running or waiting root can still own a durable post-terminal user
        // steer. Filtering delivery by a later attachment list used to lose a
        // root steer after restart whenever an auto-result had left the root
        // waiting for its original continuation.
        let mut nonterminal_steer_owners = Vec::new();
        loop {
            let page = self
                .db
                .agent_lineage_page(
                    session_id,
                    None,
                    after.clone(),
                    crate::db::agent_tree_decisions::MAX_AGENT_TREE_PAGE_SIZE,
                )
                .await?;
            for agent in page.entries {
                if !agent.state.is_terminal() {
                    nonterminal_steer_owners.push(agent.agent_instance_id);
                }
                // Every nonterminal node, including a root that is waiting
                // for a user or host approval, needs an exact boot claim.
                // The root driver is an executor just like a child: without
                // this claim its pre-queued durable input could run before
                // the waiting decision/late-steer attachment has completed.
                if !agent.state.is_terminal()
                    && self
                        .db
                        .claim_agent_resume(
                            session_id,
                            agent.agent_instance_id,
                            agent.revision,
                            recovery_epoch,
                            now_unix_ms,
                        )
                        .await?
                {
                    claimed_agents.push(agent.agent_instance_id);
                }
            }
            let Some(cursor) = page.next_cursor else {
                break;
            };
            after = Some(cursor);
        }
        let mut pending_decisions = Vec::new();
        let mut decision_after = None;
        loop {
            let page = self
                .db
                .recoverable_decision_requests_page(
                    session_id,
                    decision_after.clone(),
                    crate::db::agent_tree_decisions::MAX_AGENT_TREE_PAGE_SIZE,
                )
                .await?;
            pending_decisions.extend(
                page.entries
                    .into_iter()
                    .map(|decision| decision.decision_request_id),
            );
            let Some(cursor) = page.next_cursor else {
                break;
            };
            decision_after = Some(cursor);
        }
        let mut claimed_late_user_steers = Vec::new();
        let mut accepted_late_user_steers = Vec::new();
        for agent_instance_id in nonterminal_steer_owners {
            claimed_late_user_steers.extend(
                self.db
                    .claim_late_user_decision_steers(session_id, agent_instance_id, recovery_epoch)
                    .await?,
            );
            accepted_late_user_steers.extend(
                self.db
                    .accepted_late_user_decision_steers_for_recovery(
                        session_id,
                        agent_instance_id,
                        recovery_epoch,
                    )
                    .await?,
            );
        }
        Ok(AgentTreeRecovery {
            claimed_agents,
            pending_decisions,
            claimed_late_user_steers,
            accepted_late_user_steers,
        })
    }

    /// Runtime entrypoint for normal daemon recovery. The epoch is allocated
    /// once per process, while the deterministic `recover_session` variant is
    /// retained for lifecycle tests and callers that own a daemon boot ID.
    pub async fn recover_current_daemon_session(
        &self,
        session_id: Uuid,
    ) -> Result<AgentTreeRecovery> {
        self.recover_session(
            session_id,
            agent_tree_recovery_epoch(),
            system_now_unix_ms(),
        )
        .await
    }

    /// Acknowledge a private late-user steer after the original requesting
    /// continuation has accepted it. This is deliberately separate from
    /// `resolve_user_answer`: it closes the delivery CAS, not the immutable
    /// decision receipt.
    pub async fn ack_late_user_steer_delivery(
        &self,
        session_id: Uuid,
        steer_id: Uuid,
        recovery_epoch: Uuid,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.db
            .ack_late_user_decision_steer_delivery(
                session_id,
                steer_id,
                recovery_epoch,
                now_unix_ms,
            )
            .await
    }

    async fn load_decision_for_settlement(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
    ) -> Result<DecisionForSettlement> {
        let decision = self
            .db
            .decision_request(session_id, decision_request_id)
            .await?
            .context("decision request is not authorized for this session")?;
        if !is_terminal(decision.state) {
            return Ok(DecisionForSettlement::Active(decision));
        }
        let receipt = self
            .db
            .decision_terminal_receipt(session_id, decision_request_id)
            .await?
            .context("terminal decision has no receipt")?;
        Ok(DecisionForSettlement::AlreadyTerminal(
            receipt.terminal_state,
        ))
    }

    async fn settle(
        &self,
        session_id: Uuid,
        decision: DecisionRequestRow,
        terminal_state: DecisionState,
        receipt_json: &str,
        resume_payload_json: Option<String>,
        now_unix_ms: i64,
    ) -> Result<DecisionSettlement> {
        let outcome = match resume_payload_json {
            Some(payload) => {
                self.db
                    .resolve_decision_request_with_resume_payload(
                        session_id,
                        decision.decision_request_id,
                        decision.revision,
                        terminal_state,
                        receipt_json,
                        &payload,
                        now_unix_ms,
                    )
                    .await?
            }
            None => {
                self.db
                    .resolve_decision_request(
                        session_id,
                        decision.decision_request_id,
                        decision.revision,
                        terminal_state,
                        receipt_json,
                        now_unix_ms,
                    )
                    .await?
            }
        };
        match outcome {
            DecisionTransitionOutcome::Transitioned(row) => {
                Ok(DecisionSettlement::Resolved(row.state))
            }
            DecisionTransitionOutcome::AlreadyTerminal(receipt) => {
                Ok(DecisionSettlement::AlreadyTerminal(receipt.terminal_state))
            }
            DecisionTransitionOutcome::RevisionConflict => Ok(DecisionSettlement::Retry),
        }
    }
}

fn agent_tree_recovery_epoch() -> Uuid {
    static EPOCH: OnceLock<Uuid> = OnceLock::new();
    *EPOCH.get_or_init(Uuid::now_v7)
}

pub(crate) fn system_now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Produce the opaque, daemon-owned workspace identity that anchors a root
/// agent.  It intentionally contains neither a client-supplied path nor a
/// resolver-visible filesystem capability.  Descendants inherit this value
/// from their durable parent rather than rebuilding it from a display path.
pub(crate) fn workspace_ref_for_host_path(
    path: &std::path::Path,
) -> Result<crate::db::agent_tree_decisions::HostWorkspaceRef> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("canonicalizing daemon workspace root {}", path.display()))?;
    let mut digest = Sha256::new();
    digest.update(b"flycockpit.workspace-ref.v1\0");
    digest.update(canonical.as_os_str().as_encoded_bytes());
    // SAFETY: the only input is the daemon worker's authoritative session
    // workspace path. This helper deliberately has no request/presentation
    // input, so callers cannot inject a workspace selector into an AgentTree
    // root or decision packet.
    unsafe {
        crate::db::agent_tree_decisions::HostWorkspaceRef::from_daemon_derived(format!(
            "workspace:v1:{}",
            digest
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
    }
}

fn packet_from_decision(
    decision: &DecisionRequestRow,
    parent_agent_instance_id: Option<Uuid>,
    resolver_profile_snapshot_id: Option<Uuid>,
    resolver_slot: Option<String>,
) -> Result<RedactedDecisionPacket> {
    Ok(RedactedDecisionPacket {
        decision_request_id: decision.decision_request_id,
        agent_instance_id: decision.agent_instance_id,
        resolver_profile_snapshot_id,
        resolver_slot,
        parent_agent_instance_id,
        session_id: decision.session_id,
        task_call_id: decision.task_call_id.clone(),
        workspace_ref: decision.workspace_ref.clone(),
        options_contract_json: decision.options_contract_json.clone(),
        free_text_contract_json: decision.free_text_contract_json.clone(),
        recommendation_json: decision.recommendation_json.clone(),
        rationale_redaction_class: decision.rationale_redaction_class.clone(),
        decision_class: DecisionClass::parse(&decision.decision_class)?,
        deadline_unix_ms: decision.deadline_unix_ms,
    })
}

fn validate_answer(decision: &DecisionRequestRow, answer: &PublicDecisionAnswer) -> Result<()> {
    let contract: serde_json::Value = serde_json::from_str(&decision.options_contract_json)
        .context("decoding durable decision options")?;
    let interrupt_contract = contract
        .get("interrupt_response_contract")
        .filter(|value| !value.is_null())
        .map(|value| {
            serde_json::from_value::<RedactedInterruptQuestionSet>(value.clone())
                .context("decoding durable QuestionTool continuation contract")
        })
        .transpose()?;
    if let Some(interrupt_contract) = interrupt_contract {
        let PublicDecisionAnswer::InterruptResponse { response } = answer else {
            bail!("QuestionTool continuation requires a typed daemon response envelope");
        };
        ensure!(
            interrupt_contract.schema == "interrupt_question_set_v1",
            "unknown QuestionTool continuation contract schema"
        );
        return interrupt_contract.validate_response(response);
    }
    match answer {
        PublicDecisionAnswer::Option { id } => {
            ensure!(is_safe_option_id(id), "decision option id is invalid");
            ensure!(
                contract["options"].as_array().is_some_and(|options| options
                    .iter()
                    .any(|option| { option["id"].as_str() == Some(id) })),
                "decision answer is not an offered option"
            );
        }
        PublicDecisionAnswer::FreeText { text } => {
            let Some(raw) = decision.free_text_contract_json.as_deref() else {
                bail!("decision does not permit free-text answers");
            };
            let contract: FreeTextContract = serde_json::from_str(raw)
                .context("decoding durable free-text decision contract")?;
            validate_bounded_free_text_contract(&contract)?;
            ensure!(
                contract.allowed,
                "decision does not permit free-text answers"
            );
            let max_chars = contract
                .max_chars
                .context("allowed free-text decision is missing its bounded maximum")?;
            ensure!(
                text.chars().count() <= max_chars as usize,
                "free-text decision answer exceeds its durable contract"
            );
            ensure!(
                !text.contains('\0'),
                "free-text decision answer contains NUL"
            );
        }
        PublicDecisionAnswer::InterruptResponse { .. } => {
            bail!("decision does not own a QuestionTool continuation");
        }
    }
    Ok(())
}

/// Free-text is intentionally an explicit bounded capability.  A missing cap
/// cannot mean different things to manual validation, utility parsing, and
/// the wire contract after restart, so an allowed contract always persists a
/// positive upper bound.  Disallowed free text carries no dormant bound.
fn validate_bounded_free_text_contract(contract: &FreeTextContract) -> Result<()> {
    match (contract.allowed, contract.max_chars) {
        (true, Some(max_chars @ 1..=10_000)) => {
            let _ = max_chars;
            Ok(())
        }
        (true, Some(_)) => {
            bail!("free-text decision maximum must be between 1 and 10000 characters")
        }
        (true, None) => bail!("allowed free-text decisions require an explicit bounded maximum"),
        (false, None) => Ok(()),
        (false, Some(_)) => bail!("disallowed free-text decisions must not carry a maximum"),
    }
}

/// Generic decisions are answerable only through their bounded options or an
/// explicitly bounded free-text capability. Cancellation ends an already
/// valid interaction; it cannot make an empty generic decision answerable.
fn validate_generic_decision_answer_channels(
    options: &[DecisionOption],
    free_text: Option<&FreeTextContract>,
) -> Result<()> {
    ensure!(options.len() <= 64, "generic decision has too many options");
    for option in options {
        ensure!(
            is_safe_option_id(&option.id),
            "generic decision option id is not a safe bounded identifier"
        );
    }
    if let Some(contract) = free_text {
        validate_bounded_free_text_contract(contract)?;
    }
    ensure!(
        !options.is_empty() || free_text.is_some_and(|contract| contract.allowed),
        "generic decision must offer an option or allow bounded free-text"
    );
    Ok(())
}

fn validate_new_decision_contract_answer_channels(contract: &NewDecisionContract) -> Result<()> {
    match contract.interrupt_response_contract.as_ref() {
        Some(interrupt_contract) => {
            ensure!(
                contract.free_text.is_none(),
                "QuestionTool continuation must not carry a generic free-text contract"
            );
            interrupt_contract.validate_contract()
        }
        None => validate_generic_decision_answer_channels(
            &contract.options,
            contract.free_text.as_ref(),
        ),
    }
}

/// Translate a response from the exact private continuation into the public
/// opaque contract. Every private option ID must have a mapping: this is a
/// trusted internal boundary, not a permissive compatibility parser.
fn public_decision_answer_from_private_continuation(
    answer: &PrivateDecisionContinuationAnswer,
    mappings: &[crate::db::agent_tree_decisions::DecisionPrivateOptionMapping],
) -> Result<PublicDecisionAnswer> {
    match answer {
        PrivateDecisionContinuationAnswer::Option { id } => Ok(PublicDecisionAnswer::Option {
            id: private_option_to_public(id, mappings)?,
        }),
        PrivateDecisionContinuationAnswer::FreeText { text } => {
            Ok(PublicDecisionAnswer::FreeText { text: text.clone() })
        }
        PrivateDecisionContinuationAnswer::InterruptResponse { response } => {
            Ok(PublicDecisionAnswer::InterruptResponse {
                response: public_interrupt_response_from_private_continuation(response, mappings)?,
            })
        }
    }
}

fn private_option_to_public(
    private_option_id: &str,
    mappings: &[crate::db::agent_tree_decisions::DecisionPrivateOptionMapping],
) -> Result<String> {
    mappings
        .iter()
        .find(|mapping| mapping.continuation_option_id == private_option_id)
        .map(|mapping| mapping.opaque_option_id.clone())
        .context("private continuation option has no public opaque mapping")
}

fn public_interrupt_response_from_private_continuation(
    response: &ResolveResponse,
    mappings: &[crate::db::agent_tree_decisions::DecisionPrivateOptionMapping],
) -> Result<ResolveResponse> {
    let to_public = |id: &str| private_option_to_public(id, mappings);
    Ok(match response {
        ResolveResponse::Single { selected_id } => ResolveResponse::Single {
            selected_id: to_public(selected_id)?,
        },
        ResolveResponse::Multi { selected_ids } => ResolveResponse::Multi {
            selected_ids: selected_ids
                .iter()
                .map(|id| to_public(id))
                .collect::<Result<Vec<_>>>()?,
        },
        ResolveResponse::Freetext { text } => ResolveResponse::Freetext { text: text.clone() },
        ResolveResponse::Batch { responses } => ResolveResponse::Batch {
            responses: responses
                .iter()
                .map(|response| {
                    public_interrupt_response_from_private_continuation(response, mappings)
                })
                .collect::<Result<Vec<_>>>()?,
        },
        ResolveResponse::Cancel => ResolveResponse::Cancel,
    })
}

/// After validation of a public opaque answer, recover the original local IDs
/// only for the private durable continuation. Unknown opaque IDs are an
/// invariant failure: they cannot be an offered public option without a
/// matching private row.
fn private_decision_continuation_answer_from_public(
    answer: &PublicDecisionAnswer,
    mappings: &[crate::db::agent_tree_decisions::DecisionPrivateOptionMapping],
) -> Result<PrivateDecisionContinuationAnswer> {
    let to_private = |opaque_option_id: &str| {
        mappings
            .iter()
            .find(|mapping| mapping.opaque_option_id == opaque_option_id)
            .map(|mapping| mapping.continuation_option_id.clone())
            .context("decision option has no private continuation mapping")
    };
    match answer {
        PublicDecisionAnswer::Option { id } => Ok(PrivateDecisionContinuationAnswer::Option {
            id: to_private(id)?,
        }),
        PublicDecisionAnswer::FreeText { text } => {
            Ok(PrivateDecisionContinuationAnswer::FreeText { text: text.clone() })
        }
        PublicDecisionAnswer::InterruptResponse { response } => {
            Ok(PrivateDecisionContinuationAnswer::InterruptResponse {
                response: private_interrupt_response_for_continuation(response, mappings)?,
            })
        }
    }
}

fn private_interrupt_response_for_continuation(
    response: &ResolveResponse,
    mappings: &[crate::db::agent_tree_decisions::DecisionPrivateOptionMapping],
) -> Result<ResolveResponse> {
    let to_private = |opaque_option_id: &str| {
        mappings
            .iter()
            .find(|mapping| mapping.opaque_option_id == opaque_option_id)
            .map(|mapping| mapping.continuation_option_id.clone())
            .context("decision option has no private continuation mapping")
    };
    Ok(match response {
        ResolveResponse::Single { selected_id } => ResolveResponse::Single {
            selected_id: to_private(selected_id)?,
        },
        ResolveResponse::Multi { selected_ids } => ResolveResponse::Multi {
            selected_ids: selected_ids
                .iter()
                .map(|id| to_private(id))
                .collect::<Result<Vec<_>>>()?,
        },
        ResolveResponse::Freetext { text } => ResolveResponse::Freetext { text: text.clone() },
        ResolveResponse::Batch { responses } => ResolveResponse::Batch {
            responses: responses
                .iter()
                .map(|response| private_interrupt_response_for_continuation(response, mappings))
                .collect::<Result<Vec<_>>>()?,
        },
        ResolveResponse::Cancel => ResolveResponse::Cancel,
    })
}

fn answer_receipt(source: &str, answer: &PublicDecisionAnswer) -> String {
    // The DB reduces this to a non-reversible marker before its transaction
    // begins. Keeping the source/shape here lets audit code distinguish user,
    // parent, and utility winners without persisting resolver context.
    match answer {
        PublicDecisionAnswer::Option { id } => serde_json::json!({
            "source": source,
            "answer_kind": "option",
            "option_id": id,
        })
        .to_string(),
        PublicDecisionAnswer::FreeText { text } => serde_json::json!({
            "source": source,
            "answer_kind": "free_text",
            "answer": text,
        })
        .to_string(),
        PublicDecisionAnswer::InterruptResponse { response } => serde_json::json!({
            "source": source,
            "answer_kind": "interrupt_response",
            "response_kind": response_kind(response),
        })
        .to_string(),
    }
}

fn answer_resume_payload(source: &str, answer: &PrivateDecisionContinuationAnswer) -> String {
    // Unlike the public receipt marker, this is daemon-private continuation
    // data. It is validated and retained so an answered decision can resume
    // the requesting agent after a process crash.
    match answer {
        PrivateDecisionContinuationAnswer::Option { id } => serde_json::json!({
            "source": source,
            "answer_kind": "option",
            "option_id": id,
        })
        .to_string(),
        PrivateDecisionContinuationAnswer::FreeText { text } => serde_json::json!({
            "source": source,
            "answer_kind": "free_text",
            "answer": text,
        })
        .to_string(),
        PrivateDecisionContinuationAnswer::InterruptResponse { response } => serde_json::json!({
            "source": source,
            "answer_kind": "interrupt_response",
            "answer": response,
        })
        .to_string(),
    }
}

fn response_kind(response: &ResolveResponse) -> &'static str {
    match response {
        ResolveResponse::Single { .. } => "single",
        ResolveResponse::Multi { .. } => "multi",
        ResolveResponse::Freetext { .. } => "freetext",
        ResolveResponse::Batch { .. } => "batch",
        ResolveResponse::Cancel => "cancel",
    }
}

fn is_terminal(state: DecisionState) -> bool {
    matches!(
        state,
        DecisionState::Answered
            | DecisionState::AutoResolved
            | DecisionState::TimedOut
            | DecisionState::Cancelled
    )
}

fn is_safe_option_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

/// The AgentTree daemon endpoint exposes only opaque option capabilities.
/// Validate their canonical form before looking up the durable contract, so a
/// private continuation identifier cannot accidentally be accepted through a
/// future broader matching rule.
fn validate_public_answer_option_tokens(answer: &PublicDecisionAnswer) -> Result<()> {
    match answer {
        PublicDecisionAnswer::Option { id } => validate_public_option_token(id),
        PublicDecisionAnswer::FreeText { .. } => Ok(()),
        PublicDecisionAnswer::InterruptResponse { response } => {
            validate_public_interrupt_response_option_tokens(response)
        }
    }
}

fn validate_public_interrupt_response_option_tokens(response: &ResolveResponse) -> Result<()> {
    match response {
        ResolveResponse::Single { selected_id } => validate_public_option_token(selected_id),
        ResolveResponse::Multi { selected_ids } => {
            for selected_id in selected_ids {
                validate_public_option_token(selected_id)?;
            }
            Ok(())
        }
        ResolveResponse::Freetext { .. } | ResolveResponse::Cancel => Ok(()),
        ResolveResponse::Batch { responses } => {
            for response in responses {
                validate_public_interrupt_response_option_tokens(response)?;
            }
            Ok(())
        }
    }
}

fn validate_public_option_token(value: &str) -> Result<()> {
    let uuid_text = value
        .strip_prefix("option:")
        .context("public decision option id is not an opaque daemon token")?;
    let uuid =
        Uuid::parse_str(uuid_text).context("public decision option id has an invalid UUID")?;
    ensure!(
        !uuid.is_nil()
            && uuid.get_version_num() == 7
            && uuid.get_variant() == uuid::Variant::RFC4122
            && uuid.to_string() == uuid_text,
        "public decision option id is not a canonical UUIDv7 token"
    );
    Ok(())
}
