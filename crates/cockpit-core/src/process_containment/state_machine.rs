//! Pure durable reducer for execution containment state.
//!
//! Generation changes invalidate all prior callbacks. Immediate child exit is
//! never the empty oracle — only same-generation adapter OracleEmpty is.

use super::types::{
    ContainmentEvent, ContainmentRecord, ContainmentState, LateCallbackKind, ReduceResult,
};

/// Apply an event to an optional existing record (None only for BeginCreate).
pub fn reduce(current: Option<ContainmentRecord>, event: ContainmentEvent) -> ReduceResult {
    match event {
        ContainmentEvent::BeginCreate {
            containment_id,
            session_id,
            operation_id,
            generation,
            platform_kind,
            guarantee,
            now_wall_ms,
        } => {
            if let Some(existing) = current {
                return ReduceResult::Illegal {
                    from: existing.state,
                    event: "begin_create".into(),
                };
            }
            ReduceResult::Applied(Box::new(ContainmentRecord {
                containment_id,
                session_id,
                operation_id,
                generation,
                platform_kind,
                state: ContainmentState::Creating,
                guarantee,
                locator: Default::default(),
                unsupported_reason: None,
                created_at_wall_ms: now_wall_ms,
                updated_at_wall_ms: now_wall_ms,
                emptied_at_wall_ms: None,
                pending_command: Some("create".into()),
            }))
        }
        ContainmentEvent::LateCallback {
            callback_generation,
            kind,
        } => {
            let Some(rec) = current else {
                return ReduceResult::Illegal {
                    from: ContainmentState::Empty,
                    event: format!("late_{kind:?}"),
                };
            };
            if callback_generation != rec.generation {
                return ReduceResult::IgnoredLate {
                    current_generation: rec.generation,
                    callback_generation,
                    kind,
                };
            }
            // Same-generation process/client exit is only an event, never Empty.
            match kind {
                LateCallbackKind::ProcessExit
                | LateCallbackKind::ClientExit
                | LateCallbackKind::EmptyNotification
                    if matches!(
                        rec.state,
                        ContainmentState::Active | ContainmentState::Stopping
                    ) =>
                {
                    // EmptyNotification without oracle still does not empty.
                    ReduceResult::Applied(Box::new(rec))
                }
                LateCallbackKind::Cancellation => {
                    // Same-gen cancel is RequestStop territory; if already applied, no-op.
                    ReduceResult::Applied(Box::new(rec))
                }
                LateCallbackKind::Recovery
                | LateCallbackKind::ImmutableIdReuse
                | LateCallbackKind::NameReuse
                | LateCallbackKind::LocatorReuse => ReduceResult::Applied(Box::new(rec)),
                _ => ReduceResult::Applied(Box::new(rec)),
            }
        }
        other => {
            let Some(mut rec) = current else {
                return ReduceResult::Illegal {
                    from: ContainmentState::Empty,
                    event: format!("{other:?}"),
                };
            };
            apply_to_existing(&mut rec, other)
        }
    }
}

fn apply_to_existing(rec: &mut ContainmentRecord, event: ContainmentEvent) -> ReduceResult {
    match event {
        ContainmentEvent::PlatformAllocated {
            generation,
            locator,
            now_wall_ms,
        } => {
            if generation != rec.generation {
                return ReduceResult::GenerationMismatch {
                    expected: rec.generation,
                    got: generation,
                };
            }
            if rec.state != ContainmentState::Creating {
                return illegal(rec, "platform_allocated");
            }
            rec.locator = locator;
            rec.updated_at_wall_ms = now_wall_ms;
            rec.pending_command = Some("await_membership".into());
            ReduceResult::Applied(Box::new(rec.clone()))
        }
        ContainmentEvent::MembershipProven {
            generation,
            locator,
            now_wall_ms,
        } => {
            if generation != rec.generation {
                return ReduceResult::GenerationMismatch {
                    expected: rec.generation,
                    got: generation,
                };
            }
            if rec.state != ContainmentState::Creating {
                return illegal(rec, "membership_proven");
            }
            rec.state = ContainmentState::Active;
            rec.locator = locator;
            rec.updated_at_wall_ms = now_wall_ms;
            rec.pending_command = None;
            ReduceResult::Applied(Box::new(rec.clone()))
        }
        ContainmentEvent::MarkUnsupported {
            generation,
            reason,
            now_wall_ms,
        } => {
            if generation != rec.generation {
                return ReduceResult::GenerationMismatch {
                    expected: rec.generation,
                    got: generation,
                };
            }
            // Unsupported before user code: Creating only. Never silently Active.
            if rec.state != ContainmentState::Creating {
                return illegal(rec, "mark_unsupported");
            }
            rec.guarantee = super::types::ContainmentGuarantee::Unsupported;
            rec.unsupported_reason = Some(reason);
            // No durable Active membership; treat as Empty for barriers with
            // Unsupported guarantee so recovery does not claim ProvenEmpty.
            rec.state = ContainmentState::Empty;
            rec.emptied_at_wall_ms = Some(now_wall_ms);
            rec.updated_at_wall_ms = now_wall_ms;
            rec.pending_command = None;
            ReduceResult::Applied(Box::new(rec.clone()))
        }
        ContainmentEvent::CreateFailed {
            generation,
            now_wall_ms,
        } => {
            if generation != rec.generation {
                return ReduceResult::GenerationMismatch {
                    expected: rec.generation,
                    got: generation,
                };
            }
            if rec.state != ContainmentState::Creating {
                return illegal(rec, "create_failed");
            }
            rec.state = ContainmentState::Empty;
            rec.emptied_at_wall_ms = Some(now_wall_ms);
            rec.updated_at_wall_ms = now_wall_ms;
            rec.pending_command = None;
            ReduceResult::Applied(Box::new(rec.clone()))
        }
        ContainmentEvent::RequestStop {
            generation,
            now_wall_ms,
        } => {
            if generation != rec.generation {
                return ReduceResult::GenerationMismatch {
                    expected: rec.generation,
                    got: generation,
                };
            }
            match rec.state {
                ContainmentState::Empty => ReduceResult::Applied(Box::new(rec.clone())), // idempotent
                ContainmentState::Stopping => {
                    // Duplicate terminate is idempotent.
                    if rec.pending_command.as_deref() == Some("terminate") {
                        return ReduceResult::DuplicateCommand {
                            command: "terminate".into(),
                        };
                    }
                    rec.pending_command = Some("terminate".into());
                    rec.updated_at_wall_ms = now_wall_ms;
                    ReduceResult::Applied(Box::new(rec.clone()))
                }
                ContainmentState::Creating
                | ContainmentState::Active
                | ContainmentState::Uncertain => {
                    rec.state = ContainmentState::Stopping;
                    rec.pending_command = Some("terminate".into());
                    rec.updated_at_wall_ms = now_wall_ms;
                    ReduceResult::Applied(Box::new(rec.clone()))
                }
            }
        }
        ContainmentEvent::OracleEmpty {
            generation,
            now_wall_ms,
        } => {
            if generation != rec.generation {
                return ReduceResult::GenerationMismatch {
                    expected: rec.generation,
                    got: generation,
                };
            }
            match rec.state {
                ContainmentState::Empty => ReduceResult::Applied(Box::new(rec.clone())),
                ContainmentState::Stopping
                | ContainmentState::Active
                | ContainmentState::Creating
                | ContainmentState::Uncertain => {
                    rec.state = ContainmentState::Empty;
                    rec.emptied_at_wall_ms = Some(now_wall_ms);
                    rec.updated_at_wall_ms = now_wall_ms;
                    rec.pending_command = None;
                    ReduceResult::Applied(Box::new(rec.clone()))
                }
            }
        }
        ContainmentEvent::MarkUncertain {
            generation,
            reason,
            now_wall_ms,
        } => {
            if generation != rec.generation {
                return ReduceResult::GenerationMismatch {
                    expected: rec.generation,
                    got: generation,
                };
            }
            if rec.state == ContainmentState::Empty {
                return illegal(rec, "mark_uncertain");
            }
            rec.state = ContainmentState::Uncertain;
            rec.unsupported_reason = Some(reason);
            rec.updated_at_wall_ms = now_wall_ms;
            rec.pending_command = None;
            ReduceResult::Applied(Box::new(rec.clone()))
        }
        ContainmentEvent::ReplaceGeneration {
            from_generation,
            to_generation,
            now_wall_ms,
        } => {
            if from_generation != rec.generation {
                return ReduceResult::GenerationMismatch {
                    expected: rec.generation,
                    got: from_generation,
                };
            }
            if to_generation <= from_generation {
                return illegal(rec, "replace_generation_non_monotonic");
            }
            rec.generation = to_generation;
            rec.state = ContainmentState::Creating;
            rec.locator = Default::default();
            rec.unsupported_reason = None;
            rec.emptied_at_wall_ms = None;
            rec.updated_at_wall_ms = now_wall_ms;
            rec.pending_command = Some("recover".into());
            ReduceResult::Applied(Box::new(rec.clone()))
        }
        ContainmentEvent::BeginCreate { .. } | ContainmentEvent::LateCallback { .. } => {
            // Handled in reduce().
            illegal(rec, "unexpected_top_level")
        }
    }
}

fn illegal(rec: &ContainmentRecord, event: &str) -> ReduceResult {
    ReduceResult::Illegal {
        from: rec.state,
        event: event.into(),
    }
}

/// Whether a CAS from → to is legal for durable state machine transitions.
#[allow(dead_code)]
pub fn is_legal_cas(from: ContainmentState, to: ContainmentState) -> bool {
    use ContainmentState::*;
    matches!(
        (from, to),
        (Creating, Active)
            | (Creating, Stopping)
            | (Creating, Empty)
            | (Creating, Uncertain)
            | (Active, Stopping)
            | (Active, Empty)
            | (Active, Uncertain)
            | (Stopping, Empty)
            | (Stopping, Uncertain)
            | (Stopping, Stopping) // idempotent terminate
            | (Uncertain, Stopping)
            | (Uncertain, Empty)
            | (Uncertain, Uncertain)
            | (Empty, Empty)
    )
}

#[cfg(test)]
mod containment_state_machine {
    use super::*;
    use crate::process_containment::types::{
        ContainmentGuarantee, LateCallbackKind, PlatformKind, SafeLocator,
    };
    use uuid::Uuid;

    fn begin() -> ContainmentRecord {
        let r = reduce(
            None,
            ContainmentEvent::BeginCreate {
                containment_id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                operation_id: "op".into(),
                generation: 1,
                platform_kind: PlatformKind::Fake,
                guarantee: ContainmentGuarantee::Proven,
                now_wall_ms: 1,
            },
        );
        match r {
            ReduceResult::Applied(rec) => *rec,
            other => panic!("expected Applied, got {other:?}"),
        }
    }

    #[test]
    fn covers_every_state_and_generation_transition() {
        let mut rec = begin();
        assert_eq!(rec.state, ContainmentState::Creating);

        rec = match reduce(
            Some(rec.clone()),
            ContainmentEvent::MembershipProven {
                generation: 1,
                locator: SafeLocator {
                    locator_key: Some("k".into()),
                    ..Default::default()
                },
                now_wall_ms: 2,
            },
        ) {
            ReduceResult::Applied(r) => *r,
            o => panic!("{o:?}"),
        };
        assert_eq!(rec.state, ContainmentState::Active);

        rec = match reduce(
            Some(rec.clone()),
            ContainmentEvent::RequestStop {
                generation: 1,
                now_wall_ms: 3,
            },
        ) {
            ReduceResult::Applied(r) => *r,
            o => panic!("{o:?}"),
        };
        assert_eq!(rec.state, ContainmentState::Stopping);

        // Duplicate terminate while pending → DuplicateCommand
        match reduce(
            Some(rec.clone()),
            ContainmentEvent::RequestStop {
                generation: 1,
                now_wall_ms: 4,
            },
        ) {
            ReduceResult::DuplicateCommand { command } => assert_eq!(command, "terminate"),
            o => panic!("expected duplicate, got {o:?}"),
        }

        rec = match reduce(
            Some(rec.clone()),
            ContainmentEvent::OracleEmpty {
                generation: 1,
                now_wall_ms: 5,
            },
        ) {
            ReduceResult::Applied(r) => *r,
            o => panic!("{o:?}"),
        };
        assert_eq!(rec.state, ContainmentState::Empty);
        assert_eq!(rec.emptied_at_wall_ms, Some(5));

        // Replacement generation
        rec = match reduce(
            Some(rec.clone()),
            ContainmentEvent::ReplaceGeneration {
                from_generation: 1,
                to_generation: 2,
                now_wall_ms: 6,
            },
        ) {
            ReduceResult::Applied(r) => *r,
            o => panic!("{o:?}"),
        };
        assert_eq!(rec.generation, 2);
        assert_eq!(rec.state, ContainmentState::Creating);

        // Uncertain path
        rec = match reduce(
            Some(rec.clone()),
            ContainmentEvent::MarkUncertain {
                generation: 2,
                reason: "locator_collision".into(),
                now_wall_ms: 7,
            },
        ) {
            ReduceResult::Applied(r) => *r,
            o => panic!("{o:?}"),
        };
        assert_eq!(rec.state, ContainmentState::Uncertain);
    }

    #[test]
    fn legal_and_illegal_cas_matrix() {
        assert!(is_legal_cas(
            ContainmentState::Creating,
            ContainmentState::Active
        ));
        assert!(is_legal_cas(
            ContainmentState::Active,
            ContainmentState::Stopping
        ));
        assert!(is_legal_cas(
            ContainmentState::Stopping,
            ContainmentState::Empty
        ));
        assert!(!is_legal_cas(
            ContainmentState::Empty,
            ContainmentState::Active
        ));
        assert!(!is_legal_cas(
            ContainmentState::Empty,
            ContainmentState::Creating
        ));
        assert!(!is_legal_cas(
            ContainmentState::Active,
            ContainmentState::Creating
        ));
    }

    #[test]
    fn caller_cancellation_drives_stopping_not_forget() {
        let mut rec = begin();
        rec = match reduce(
            Some(rec),
            ContainmentEvent::MembershipProven {
                generation: 1,
                locator: SafeLocator::default(),
                now_wall_ms: 2,
            },
        ) {
            ReduceResult::Applied(r) => *r,
            o => panic!("{o:?}"),
        };
        rec = match reduce(
            Some(rec),
            ContainmentEvent::RequestStop {
                generation: 1,
                now_wall_ms: 3,
            },
        ) {
            ReduceResult::Applied(r) => *r,
            o => panic!("{o:?}"),
        };
        assert_eq!(rec.state, ContainmentState::Stopping);
        assert_ne!(rec.state, ContainmentState::Empty);
    }

    #[test]
    fn late_callback_from_old_generation_ignored() {
        let mut rec = begin();
        rec = match reduce(
            Some(rec),
            ContainmentEvent::ReplaceGeneration {
                from_generation: 1,
                to_generation: 3,
                now_wall_ms: 2,
            },
        ) {
            ReduceResult::Applied(r) => *r,
            o => panic!("{o:?}"),
        };
        match reduce(
            Some(rec.clone()),
            ContainmentEvent::LateCallback {
                callback_generation: 1,
                kind: LateCallbackKind::EmptyNotification,
            },
        ) {
            ReduceResult::IgnoredLate {
                current_generation,
                callback_generation,
                kind,
            } => {
                assert_eq!(current_generation, 3);
                assert_eq!(callback_generation, 1);
                assert_eq!(kind, LateCallbackKind::EmptyNotification);
            }
            o => panic!("{o:?}"),
        }
        // Stale OracleEmpty also rejected
        match reduce(
            Some(rec),
            ContainmentEvent::OracleEmpty {
                generation: 1,
                now_wall_ms: 9,
            },
        ) {
            ReduceResult::GenerationMismatch { expected, got } => {
                assert_eq!(expected, 3);
                assert_eq!(got, 1);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn process_exit_is_never_empty_oracle() {
        let mut rec = begin();
        rec = match reduce(
            Some(rec),
            ContainmentEvent::MembershipProven {
                generation: 1,
                locator: SafeLocator::default(),
                now_wall_ms: 2,
            },
        ) {
            ReduceResult::Applied(r) => *r,
            o => panic!("{o:?}"),
        };
        match reduce(
            Some(rec.clone()),
            ContainmentEvent::LateCallback {
                callback_generation: 1,
                kind: LateCallbackKind::ProcessExit,
            },
        ) {
            ReduceResult::Applied(r) => {
                assert_eq!(r.state, ContainmentState::Active);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn unsupported_before_user_code_does_not_create_active() {
        let rec = begin();
        let rec = match reduce(
            Some(rec),
            ContainmentEvent::MarkUnsupported {
                generation: 1,
                reason: "management_boundary_unavailable".into(),
                now_wall_ms: 2,
            },
        ) {
            ReduceResult::Applied(r) => *r,
            o => panic!("{o:?}"),
        };
        assert_eq!(rec.guarantee, ContainmentGuarantee::Unsupported);
        assert_ne!(rec.state, ContainmentState::Active);
        assert_eq!(
            rec.unsupported_reason.as_deref(),
            Some("management_boundary_unavailable")
        );
    }
}
