use super::*;

impl Approver {
    pub async fn approve_harness_invoke(
        &self,
        harness: &str,
        model: Option<&str>,
        policy: crate::harness::run::WritePolicy,
    ) -> Result<Decision> {
        let target = format!("harness:{harness}");
        let offered = [Scope::Once, Scope::Session];
        let writes = match policy {
            crate::harness::run::WritePolicy::Direct => "directly into this project",
            crate::harness::run::WritePolicy::Isolated => "into a throwaway git worktree",
        };
        let prompt = format!(
            "Run external harness `{target}`?\n\nModel: {}\nWrites: {writes}\n\nThe external agent runs outside cockpit's sandbox with its own permission prompts disabled.",
            model.unwrap_or("harness default")
        );
        let question = InterruptQuestion::Single {
            prompt: prompt.clone(),
            options: vec![
                opt(
                    ApprovalOptionId::ApproveSession,
                    &format!("Allow `{target}` for this session"),
                ),
                opt(ApprovalOptionId::ApproveOnce, "Allow once"),
                opt(ApprovalOptionId::Reject, "Deny"),
            ],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: Some(GrantKind::Harness),
            sandbox_escalation: None,
        };
        let set = ApprovalOptionSet::new(
            "harness_invoke_approval",
            [
                ApprovalOptionId::ApproveSession,
                ApprovalOptionId::ApproveOnce,
                ApprovalOptionId::Reject,
            ],
        );
        let response = self.raise_and_wait(&prompt, question).await?;
        let choice = response_to_approval_choice(&response, &set).unwrap_or_else(|foreign| {
            warn_foreign_option_id(&foreign);
            ApprovalChoice::Deny
        });
        let decision = match choice {
            ApprovalChoice::Approve(Scope::Session) => {
                if let Err(e) = self.store.record_harness(harness, Scope::Session) {
                    tracing::warn!(error = %e, harness, "recording harness session grant failed; applying once");
                    Decision::Allow { scope: Scope::Once }
                } else {
                    Decision::Allow {
                        scope: Scope::Session,
                    }
                }
            }
            ApprovalChoice::Approve(Scope::Once) => Decision::Allow { scope: Scope::Once },
            ApprovalChoice::NoninteractiveDeny => Decision::NoninteractiveDeny,
            ApprovalChoice::Deny
            | ApprovalChoice::Reject(_)
            | ApprovalChoice::ApproveAllOnce
            | ApprovalChoice::GrantPaths(_)
            | ApprovalChoice::Approve(Scope::Project | Scope::Global) => Decision::Deny,
        };
        self.record_permission_decision(
            "harness_invoke",
            &target,
            &offered,
            decision,
            DecisionSource::UserPrompt,
        )
        .await;
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::proto::ResolveResponse;
    use crate::harness::run::WritePolicy;
    use std::path::Path;
    use std::sync::Arc;

    fn approver(cwd: &Path) -> Arc<Approver> {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session =
            crate::session::Session::create(db.clone(), cwd.to_path_buf(), "builder").unwrap();
        let config = crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(cwd);
        let store = GrantStore::new(db.clone(), session.id, cwd.to_path_buf(), config);
        Arc::new(Approver::new(
            store,
            db,
            session.id,
            "builder",
            Arc::new(InterruptHub::detached()),
        ))
    }

    async fn resolve_next(
        approver: &Approver,
        response: ResolveResponse,
    ) -> crate::db::db::needs_attention::NeedsAttentionRow {
        loop {
            let open = approver
                .db
                .list_open_interrupts(approver.session_id)
                .unwrap();
            if let Some(row) = open.first() {
                let row = row.clone();
                approver
                    .db
                    .resolve_interrupt(row.interrupt_id, &response)
                    .unwrap();
                assert!(
                    approver
                        .interrupts
                        .resolve(row.interrupt_id, response.clone())
                );
                return row;
            }
            tokio::task::yield_now().await;
        }
    }

    async fn permission_events(approver: &Approver) -> Vec<serde_json::Value> {
        approver
            .db
            .list_session_events(approver.session_id)
            .await
            .unwrap()
            .into_iter()
            .filter(|event| event.kind == "permission_decision")
            .map(|event| event.data)
            .collect()
    }

    async fn answer(
        approver: Arc<Approver>,
        response: ResolveResponse,
    ) -> (Decision, crate::db::db::needs_attention::NeedsAttentionRow) {
        let task_approver = approver.clone();
        let task = tokio::spawn(async move {
            task_approver
                .approve_harness_invoke("codex", Some("gpt-5"), WritePolicy::Direct)
                .await
                .unwrap()
        });
        let row = resolve_next(&approver, response).await;
        let decision = task.await.unwrap();
        (decision, row)
    }

    #[tokio::test]
    async fn harness_invoke_prompt_shape_mentions_selector_model_write_and_sandbox() {
        let tmp = tempfile::tempdir().unwrap();
        let approver = approver(tmp.path());
        let task_approver = approver.clone();
        let task = tokio::spawn(async move {
            task_approver
                .approve_harness_invoke("codex", Some("gpt-5"), WritePolicy::Isolated)
                .await
                .unwrap()
        });

        let row = resolve_next(
            &approver,
            ResolveResponse::Single {
                selected_id: ID_REJECT.to_string(),
            },
        )
        .await;
        let mut questions = row.questions.unwrap().questions;
        let question = questions.remove(0);
        let InterruptQuestion::Single {
            prompt,
            options,
            allow_freetext,
            permission,
            approval_class,
            command_detail,
            sandbox_escalation,
        } = question
        else {
            panic!("expected single harness approval question");
        };
        assert!(prompt.contains("harness:codex"), "{prompt}");
        assert!(prompt.contains("Model: gpt-5"), "{prompt}");
        assert!(
            prompt.contains("Writes: into a throwaway git worktree"),
            "{prompt}"
        );
        assert!(prompt.contains("outside cockpit's sandbox"), "{prompt}");
        assert!(prompt.contains("permission prompts disabled"), "{prompt}");
        assert!(permission);
        assert_eq!(approval_class, Some(GrantKind::Harness));
        assert!(!allow_freetext);
        assert!(command_detail.is_none());
        assert!(sandbox_escalation.is_none());
        assert_eq!(
            options
                .iter()
                .map(|option| option.id.as_str())
                .collect::<Vec<_>>(),
            vec![ID_APPROVE_SESSION, ID_APPROVE_ONCE, ID_REJECT]
        );
        assert_eq!(task.await.unwrap(), Decision::Deny);
    }

    #[tokio::test]
    async fn harness_invoke_approval_session_records_grant_and_permission_decision() {
        let tmp = tempfile::tempdir().unwrap();
        let approver = approver(tmp.path());
        let (decision, _) = answer(
            approver.clone(),
            ResolveResponse::Single {
                selected_id: ID_APPROVE_SESSION.to_string(),
            },
        )
        .await;

        assert_eq!(
            decision,
            Decision::Allow {
                scope: Scope::Session
            }
        );
        assert!(approver.store.is_harness_granted("codex"));
        let events = permission_events(&approver).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["tool"], "harness_invoke");
        assert_eq!(events[0]["target"], "harness:codex");
        assert_eq!(events[0]["decision"], "allow");
        assert_eq!(events[0]["scope"], "session");
        assert_eq!(
            events[0]["offered_scopes"],
            serde_json::json!(["once", "session"])
        );
        assert_eq!(events[0]["source"], "user_prompt");
    }

    #[tokio::test]
    async fn harness_invoke_approval_once_records_no_grant_and_permission_decision() {
        let tmp = tempfile::tempdir().unwrap();
        let approver = approver(tmp.path());
        let (decision, _) = answer(
            approver.clone(),
            ResolveResponse::Single {
                selected_id: ID_APPROVE_ONCE.to_string(),
            },
        )
        .await;

        assert_eq!(decision, Decision::Allow { scope: Scope::Once });
        assert!(!approver.store.is_harness_granted("codex"));
        let events = permission_events(&approver).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["decision"], "allow");
        assert_eq!(events[0]["scope"], "once");
    }

    #[tokio::test]
    async fn harness_invoke_approval_reject_cancel_unknown_and_noninteractive_deny() {
        let cases = [
            (
                ResolveResponse::Single {
                    selected_id: ID_REJECT.to_string(),
                },
                Decision::Deny,
                "user_prompt",
            ),
            (ResolveResponse::Cancel, Decision::Deny, "user_prompt"),
            (
                ResolveResponse::Single {
                    selected_id: "foreign".to_string(),
                },
                Decision::Deny,
                "user_prompt",
            ),
            (
                ResolveResponse::Freetext {
                    text: NONINTERACTIVE_RUN_DENIAL.to_string(),
                },
                Decision::NoninteractiveDeny,
                "headless_auto_reject",
            ),
        ];

        for (response, expected, source) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let approver = approver(tmp.path());
            let (decision, _) = answer(approver.clone(), response).await;
            assert_eq!(decision, expected);
            assert!(!approver.store.is_harness_granted("codex"));
            let events = permission_events(&approver).await;
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["tool"], "harness_invoke");
            assert_eq!(events[0]["target"], "harness:codex");
            assert_eq!(events[0]["decision"], "deny");
            assert_eq!(events[0]["source"], source);
        }
    }
}
