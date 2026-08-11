//! Tests for the image-generation control plane.
//!
//! These tests cover the key acceptance criteria from the prompt:
//! - `image_generation_control_authz`: Owner and hosted access scopes
//! - `image_generation_control_old_behavior_rejection`: legacy snapshot rejection
//! - `image_generation_admin_capability_matrix`: foundation import and disjoint
//! - `image_generation_operation_kind_codec`: JSON/FCOR ordinals
//! - `image_generation_control_schema_conformance`: exhaustive tag/result/error/event
//! - `image_generation_control_redaction`: forbidden sentinels absent
//! - `image_generation_budget_plan_scope`: nullability and CAS
//! - `image_generation_admin_grant_resolution`: active authority key and lifecycle

use super::*;
use crate::daemon::principal::{ClientPrincipal, PrincipalGrant, PrincipalScope};
use crate::daemon::relay_envelope::RelayGrantScope;
use cockpit_proto::remote_public_service_policy::{
    RemoteAttachmentCapabilityV1, RemotePermissionCeilingV1, RemoteProjectCapabilityV1,
    permission_ceiling_digest,
};

// ---------------------------------------------------------------------------
// Helper: build a remote principal
// ---------------------------------------------------------------------------

fn remote_principal(scope: RelayGrantScope, project_root: Option<String>) -> ClientPrincipal {
    // After the standalone relay cutover, `ClientPrincipal::from_relay` is
    // gone. The daemon constructs remote principals only from
    // transport-neutral verified fields. The legacy `RelayGrantScope` is
    // mapped to `PrincipalScope` here at the test boundary.
    let principal_scope = match scope {
        RelayGrantScope::Terminal => PrincipalScope::Terminal,
        RelayGrantScope::Agent => PrincipalScope::Agent,
        RelayGrantScope::AgentReadonly => PrincipalScope::AgentReadonly,
        RelayGrantScope::ProjectFiles => PrincipalScope::ProjectFiles,
    };
    ClientPrincipal::from_verified_remote(
        "user-1".to_string(),
        vec![PrincipalGrant {
            scope: principal_scope,
            project_root,
        }],
        None,
    )
}

fn nonzero_project_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    id[0] = 1;
    id
}

// ---------------------------------------------------------------------------
// 1. image_generation_control_authz
// ---------------------------------------------------------------------------

mod authz {
    use super::*;

    #[test]
    fn owner_allows_every_request_family() {
        for tag in ImageControlRequestTag::all() {
            let family = tag.family();
            let decision = authorize_local_owner(family);
            assert!(decision.allowed, "Owner should be allowed for {:?}", tag);
        }
    }

    #[test]
    fn remote_legacy_grants_never_authorize_mutation() {
        // A remote principal with any legacy scope can never authorize a
        // management mutation, regardless of project root.
        for scope in [
            RelayGrantScope::Terminal,
            RelayGrantScope::Agent,
            RelayGrantScope::AgentReadonly,
            RelayGrantScope::ProjectFiles,
        ] {
            let principal = remote_principal(scope, Some("/workspace/app".to_string()));
            assert!(
                !legacy_grants_can_authorize_mutation(&principal),
                "Legacy {:?} grant must not authorize mutation",
                scope
            );
        }
    }

    #[test]
    fn remote_principal_without_admin_grant_cannot_mutate() {
        let principal =
            remote_principal(RelayGrantScope::Agent, Some("/workspace/app".to_string()));
        assert!(!legacy_grants_can_authorize_mutation(&principal));
    }

    #[test]
    fn remote_principal_with_rootless_grant_cannot_mutate() {
        // The rootless wildcard never applies for image admin.
        let principal = remote_principal(RelayGrantScope::ProjectFiles, None);
        assert!(!legacy_grants_can_authorize_mutation(&principal));
    }

    #[test]
    fn config_reads_require_admin_capability_for_remote() {
        let family = RequestFamily::ConfigReadsAndSnapshot;
        assert_eq!(
            family.remote_capability(),
            RemoteAttemptCapability::ImageGenerationAdmin
        );
    }

    #[test]
    fn health_reads_require_project_read_for_remote() {
        let family = RequestFamily::HealthReadsAndRefresh;
        assert_eq!(
            family.remote_capability(),
            RemoteAttemptCapability::ProjectRead
        );
    }

    #[test]
    fn plan_get_requires_session_read() {
        let family = RequestFamily::PlanGet;
        assert_eq!(
            family.remote_capability(),
            RemoteAttemptCapability::SessionRead
        );
    }

    #[test]
    fn job_reads_require_session_read() {
        let family = RequestFamily::JobReadsAndSnapshot;
        assert_eq!(
            family.remote_capability(),
            RemoteAttemptCapability::SessionRead
        );
    }

    #[test]
    fn job_cancel_allows_session_write_or_admin() {
        let family = RequestFamily::JobCancel;
        assert_eq!(
            family.remote_capability(),
            RemoteAttemptCapability::SessionWriteOrImageGenerationAdmin
        );
    }

    #[test]
    fn config_mutations_require_admin() {
        let family = RequestFamily::ConfigMutations;
        assert_eq!(
            family.remote_capability(),
            RemoteAttemptCapability::ImageGenerationAdmin
        );
    }

    #[test]
    fn late_result_requires_admin() {
        let family = RequestFamily::LateResult;
        assert_eq!(
            family.remote_capability(),
            RemoteAttemptCapability::ImageGenerationAdmin
        );
    }

    #[test]
    fn operation_status_allows_project_read_or_admin() {
        let family = RequestFamily::OperationStatus;
        assert_eq!(
            family.remote_capability(),
            RemoteAttemptCapability::ProjectReadOrImageGenerationAdmin
        );
    }

    #[test]
    fn admin_alone_is_not_session_authority() {
        // ImageGenerationAdmin alone is not session authority for job reads.
        // The matrix requires session_read=7, not admin.
        let job_read_family = RequestFamily::JobReadsAndSnapshot;
        assert_eq!(
            job_read_family.remote_capability(),
            RemoteAttemptCapability::SessionRead
        );
        // Admin is NOT the capability for job reads.
        assert_ne!(
            job_read_family.remote_capability(),
            RemoteAttemptCapability::ImageGenerationAdmin
        );
    }

    #[test]
    fn every_request_family_allows_local_owner() {
        for family in [
            RequestFamily::ConfigReadsAndSnapshot,
            RequestFamily::HealthReadsAndRefresh,
            RequestFamily::PlanGet,
            RequestFamily::JobReadsAndSnapshot,
            RequestFamily::JobCancel,
            RequestFamily::ConfigMutations,
            RequestFamily::LateResult,
            RequestFamily::OperationStatus,
        ] {
            assert!(family.local_owner_allowed());
        }
    }
}

// ---------------------------------------------------------------------------
// 2. image_generation_control_old_behavior_rejection
// ---------------------------------------------------------------------------

mod old_behavior_rejection {
    use super::*;

    #[test]
    fn legacy_remote_principal_grants_cannot_authorize_mutation() {
        for scope in [
            RelayGrantScope::Terminal,
            RelayGrantScope::Agent,
            RelayGrantScope::AgentReadonly,
            RelayGrantScope::ProjectFiles,
        ] {
            let principal = remote_principal(scope, Some("/workspace/app".to_string()));
            assert!(!legacy_grants_can_authorize_mutation(&principal));
        }
    }

    #[test]
    fn rootless_wildcard_does_not_apply_for_image_admin() {
        // The existing rootless wildcard (project_root: None matches any
        // project) never applies for ImageGenerationAdmin.
        assert!(!validate_admin_grant_root(
            HostedAccessScope::ImageGenerationAdmin,
            None
        ));
        assert!(!validate_admin_grant_root(
            HostedAccessScope::ImageGenerationAdmin,
            Some("")
        ));
        assert!(validate_admin_grant_root(
            HostedAccessScope::ImageGenerationAdmin,
            Some("/workspace/app")
        ));
    }

    #[test]
    fn non_admin_scopes_do_not_require_root() {
        // Every other scope retains its reviewed project-binding rules.
        for scope in [
            HostedAccessScope::Terminal,
            HostedAccessScope::Agent,
            HostedAccessScope::AgentReadonly,
            HostedAccessScope::ProjectFiles,
        ] {
            assert!(!scope.requires_project_root());
            // Root is optional for non-admin scopes.
            assert!(validate_admin_grant_root(scope, None));
            assert!(validate_admin_grant_root(scope, Some("/workspace/app")));
        }
    }

    #[test]
    fn generic_attached_writer_cannot_authorize_config_mutation() {
        // A generic attached session writer (Agent scope) cannot authorize
        // image management.
        let writer = remote_principal(RelayGrantScope::Agent, Some("/workspace/app".to_string()));
        assert!(!legacy_grants_can_authorize_mutation(&writer));
    }

    #[test]
    fn client_supplied_project_path_is_not_authoritative() {
        // The server derives principal, scope, project root from the
        // authenticated transport. Client-supplied values are never
        // authoritative. The legacy grants snapshot is grounding only.
        let principal = remote_principal(RelayGrantScope::Agent, None);
        assert!(!legacy_grants_can_authorize_mutation(&principal));
    }

    #[test]
    fn instance_wide_grant_still_matches_any_project_for_non_image_scopes() {
        // Preserve the still-correct instance_wide_grant_matches_any_project
        // behavior for existing non-image scopes.
        let principal = remote_principal(RelayGrantScope::ProjectFiles, None);
        assert!(principal.has_project_files("/workspace/app"));
        assert!(principal.has_project_files("/elsewhere"));
    }
}

// ---------------------------------------------------------------------------
// 3. image_generation_admin_capability_matrix
// ---------------------------------------------------------------------------

mod capability_matrix {
    use super::*;

    #[test]
    fn image_generation_admin_ordinal_is_15() {
        assert_eq!(image_generation_admin_ordinal(), 15);
        assert!(verify_image_generation_admin_ordinal());
    }

    #[test]
    fn capability_imported_from_foundation() {
        let cap = image_generation_admin_capability();
        assert_eq!(cap, RemoteProjectCapabilityV1::ImageGenerationAdmin);
        assert_eq!(cap.ordinal(), 15);
    }

    #[test]
    fn capability_disjoint_from_attachment() {
        // image_generation_admin=15 is type/field-disjoint from attachment
        // capabilities despite intentional numeric overlap.
        assert!(verify_capability_disjoint());
        assert!(RemoteProjectCapabilityV1::from_ordinal(15).is_ok());
        assert!(RemoteAttachmentCapabilityV1::from_ordinal(15).is_err());
    }

    #[test]
    fn ceiling_includes_admin_ordinal() {
        let pid = nonzero_project_id();
        let (ceiling, digest) = build_admin_permission_ceiling(pid).unwrap();
        assert!(ceiling_authorizes_admin(&ceiling, &pid));
        // The ceiling bytes include ordinal 15.
        let bytes = ceiling.encode().unwrap();
        assert!(bytes.contains(&15u8));
        // The digest is computed from the complete canonical bytes.
        let expected = permission_ceiling_digest(&ceiling).unwrap();
        assert_eq!(digest.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn ceiling_digest_is_lowercase_64_hex() {
        let pid = nonzero_project_id();
        let (_ceiling, digest) = build_admin_permission_ceiling(pid).unwrap();
        let hex = digest.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|b| (b'a'..=b'f').contains(&b) || b.is_ascii_digit())
        );
    }

    #[test]
    fn ceiling_does_not_authorize_wrong_project() {
        let pid = nonzero_project_id();
        let (ceiling, _digest) = build_admin_permission_ceiling(pid).unwrap();
        let wrong_pid = {
            let mut w = [0u8; 16];
            w[0] = 2;
            w
        };
        assert!(!ceiling_authorizes_admin(&ceiling, &wrong_pid));
    }

    #[test]
    fn ceiling_rejects_zero_project_id() {
        let zero = [0u8; 16];
        assert!(build_admin_permission_ceiling(zero).is_err());
    }

    #[test]
    fn no_local_enum_redefinition() {
        // The implementation imports RemoteProjectCapabilityV1 from the
        // foundation; it does not register, redefine, alias, renumber,
        // re-encode, or independently hash any capability.
        // Verify ordinal 15 is exactly ImageGenerationAdmin in the foundation.
        let cap = RemoteProjectCapabilityV1::from_ordinal(15).unwrap();
        assert_eq!(cap, RemoteProjectCapabilityV1::ImageGenerationAdmin);
        assert_eq!(cap.ordinal(), 15);
    }
}

// ---------------------------------------------------------------------------
// 4. image_generation_operation_kind_codec
// ---------------------------------------------------------------------------

mod operation_kind_codec {
    use super::*;

    #[test]
    fn json_values_are_exact() {
        assert_eq!(
            serde_json::to_string(&ImageOperationKindV1::RemoteAttachment).unwrap(),
            "\"remote_attachment\""
        );
        assert_eq!(
            serde_json::to_string(&ImageOperationKindV1::LocalOwner).unwrap(),
            "\"local_owner\""
        );
    }

    #[test]
    fn fcor_ordinals_are_exact() {
        assert_eq!(ImageOperationKindV1::RemoteAttachment.fcor_ordinal(), 1);
        assert_eq!(ImageOperationKindV1::LocalOwner.fcor_ordinal(), 2);
    }

    #[test]
    fn fcor_encode_decode_roundtrip() {
        for kind in [
            ImageOperationKindV1::RemoteAttachment,
            ImageOperationKindV1::LocalOwner,
        ] {
            let bytes = encode_operation_kind_fcor(kind);
            let decoded = decode_operation_kind_fcor(bytes).unwrap();
            assert_eq!(kind, decoded);
        }
    }

    #[test]
    fn fcor_encode_is_u16be() {
        // RemoteAttachment = 1 -> [0x00, 0x01]
        assert_eq!(
            encode_operation_kind_fcor(ImageOperationKindV1::RemoteAttachment),
            [0x00, 0x01]
        );
        // LocalOwner = 2 -> [0x00, 0x02]
        assert_eq!(
            encode_operation_kind_fcor(ImageOperationKindV1::LocalOwner),
            [0x00, 0x02]
        );
    }

    #[test]
    fn fcor_rejects_zero() {
        assert!(ImageOperationKindV1::from_fcor_ordinal(0).is_none());
        assert!(decode_operation_kind_fcor([0x00, 0x00]).is_none());
    }

    #[test]
    fn fcor_rejects_unknown_ordinal() {
        assert!(ImageOperationKindV1::from_fcor_ordinal(3).is_none());
        assert!(ImageOperationKindV1::from_fcor_ordinal(u16::MAX).is_none());
        assert!(decode_operation_kind_fcor([0x00, 0x03]).is_none());
        assert!(decode_operation_kind_fcor([0xFF, 0xFF]).is_none());
    }

    #[test]
    fn from_str_rejects_unknown() {
        assert!(ImageOperationKindV1::from_str("remote_attachment").is_some());
        assert!(ImageOperationKindV1::from_str("local_owner").is_some());
        assert!(ImageOperationKindV1::from_str("unknown").is_none());
        assert!(ImageOperationKindV1::from_str("").is_none());
        assert!(ImageOperationKindV1::from_str("RemoteAttachment").is_none());
    }

    #[test]
    fn json_rejects_unknown_variant() {
        assert!(serde_json::from_str::<ImageOperationKindV1>("\"unknown\"").is_err());
        assert!(serde_json::from_str::<ImageOperationKindV1>("\"\"").is_err());
        assert!(serde_json::from_str::<ImageOperationKindV1>("\"remote\"").is_err());
        assert!(serde_json::from_str::<ImageOperationKindV1>("0").is_err());
        assert!(serde_json::from_str::<ImageOperationKindV1>("1").is_err());
        assert!(serde_json::from_str::<ImageOperationKindV1>("2").is_err());
    }
}

// ---------------------------------------------------------------------------
// 5. image_generation_control_schema_conformance
// ---------------------------------------------------------------------------

mod schema_conformance {
    use super::*;

    #[test]
    fn all_tags_have_unique_strings() {
        let mut seen = std::collections::BTreeSet::new();
        for tag in ImageControlRequestTag::all() {
            let s = tag.as_str();
            assert!(seen.insert(s), "duplicate tag string: {s}");
        }
        assert_eq!(seen.len(), ImageControlRequestTag::all().len());
    }

    #[test]
    fn all_tags_roundtrip_through_strings() {
        for tag in ImageControlRequestTag::all() {
            let s = tag.as_str();
            assert_eq!(ImageControlRequestTag::from_str(s), Some(*tag));
        }
    }

    #[test]
    fn unknown_tag_string_rejected() {
        assert!(ImageControlRequestTag::from_str("unknown_tag").is_none());
        assert!(ImageControlRequestTag::from_str("").is_none());
    }

    #[test]
    fn tag_count_is_exact() {
        // 31 tags total: 15 reads + 16 mutations.
        assert_eq!(ImageControlRequestTag::all().len(), 31);
    }

    #[test]
    fn read_tags_classify_as_read_only() {
        for tag in ImageControlRequestTag::all() {
            if tag.classification() == RequestClassification::ReadOnly {
                assert!(matches!(
                    tag,
                    ImageControlRequestTag::ImageEndpointList
                        | ImageControlRequestTag::ImageEndpointGet
                        | ImageControlRequestTag::ImageTargetList
                        | ImageControlRequestTag::ImageTargetGet
                        | ImageControlRequestTag::ImageWorkflowList
                        | ImageControlRequestTag::ImageWorkflowGet
                        | ImageControlRequestTag::ImageBudgetGet
                        | ImageControlRequestTag::ImageDestinationGrantList
                        | ImageControlRequestTag::ImageHealthGet
                        | ImageControlRequestTag::ImagePlanGet
                        | ImageControlRequestTag::ImageJobList
                        | ImageControlRequestTag::ImageJobGet
                        | ImageControlRequestTag::ImageOperationStatus
                        | ImageControlRequestTag::ImageControlAdminSnapshot
                        | ImageControlRequestTag::ImageControlSessionSnapshot
                ));
            }
        }
    }

    #[test]
    fn mutation_tags_classify_as_transactional_mutation() {
        for tag in ImageControlRequestTag::all() {
            if tag.classification() == RequestClassification::TransactionalMutation {
                assert!(matches!(
                    tag,
                    ImageControlRequestTag::ImageEndpointCreate
                        | ImageControlRequestTag::ImageEndpointUpdate
                        | ImageControlRequestTag::ImageEndpointDelete
                        | ImageControlRequestTag::ImageTargetCreate
                        | ImageControlRequestTag::ImageTargetUpdate
                        | ImageControlRequestTag::ImageTargetDelete
                        | ImageControlRequestTag::ImageTargetSetDefault
                        | ImageControlRequestTag::ImageWorkflowUpload
                        | ImageControlRequestTag::ImageWorkflowBind
                        | ImageControlRequestTag::ImageWorkflowDelete
                        | ImageControlRequestTag::ImageHealthRefresh
                        | ImageControlRequestTag::ImageBudgetSet
                        | ImageControlRequestTag::ImageDestinationGrantRevoke
                        | ImageControlRequestTag::ImageJobCancel
                        | ImageControlRequestTag::ImageLateResultPublish
                        | ImageControlRequestTag::ImageLateResultDiscard
                ));
            }
        }
    }

    #[test]
    fn session_requiring_tags_are_exact() {
        for tag in ImageControlRequestTag::all() {
            let requires = tag.requires_session_id();
            let expected = matches!(
                tag,
                ImageControlRequestTag::ImageBudgetGet
                    | ImageControlRequestTag::ImagePlanGet
                    | ImageControlRequestTag::ImageJobList
                    | ImageControlRequestTag::ImageJobGet
                    | ImageControlRequestTag::ImageControlSessionSnapshot
                    | ImageControlRequestTag::ImageBudgetSet
                    | ImageControlRequestTag::ImageJobCancel
                    | ImageControlRequestTag::ImageLateResultPublish
                    | ImageControlRequestTag::ImageLateResultDiscard
            );
            assert_eq!(
                requires, expected,
                "session requirement mismatch for {:?}",
                tag
            );
        }
    }

    #[test]
    fn error_codes_are_exact() {
        let codes = [
            ImageControlErrorCode::Malformed,
            ImageControlErrorCode::Unauthenticated,
            ImageControlErrorCode::Forbidden,
            ImageControlErrorCode::NotFound,
            ImageControlErrorCode::VersionConflict,
            ImageControlErrorCode::IdempotencyConflict,
            ImageControlErrorCode::CursorStale,
            ImageControlErrorCode::InvalidState,
            ImageControlErrorCode::LocalPathReauthorizationRequired,
            ImageControlErrorCode::BudgetUnconfigured,
            ImageControlErrorCode::CapabilityUnavailable,
            ImageControlErrorCode::AuthorityUnavailable,
            ImageControlErrorCode::LeaseExpired,
            ImageControlErrorCode::OperationIndeterminate,
            ImageControlErrorCode::Capacity,
            ImageControlErrorCode::Internal,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for code in codes {
            let s = code.as_str();
            assert!(seen.insert(s), "duplicate error code: {s}");
        }
        assert_eq!(seen.len(), 16);
    }

    #[test]
    fn only_retryable_before_commit_codes() {
        for code in [
            ImageControlErrorCode::Malformed,
            ImageControlErrorCode::Unauthenticated,
            ImageControlErrorCode::Forbidden,
            ImageControlErrorCode::NotFound,
            ImageControlErrorCode::VersionConflict,
            ImageControlErrorCode::IdempotencyConflict,
            ImageControlErrorCode::CursorStale,
            ImageControlErrorCode::InvalidState,
            ImageControlErrorCode::LocalPathReauthorizationRequired,
            ImageControlErrorCode::BudgetUnconfigured,
            ImageControlErrorCode::CapabilityUnavailable,
            ImageControlErrorCode::LeaseExpired,
            ImageControlErrorCode::OperationIndeterminate,
        ] {
            assert!(
                !code.is_retryable_before_commit(),
                "{:?} must not be retryable",
                code
            );
        }
        for code in [
            ImageControlErrorCode::AuthorityUnavailable,
            ImageControlErrorCode::Capacity,
            ImageControlErrorCode::Internal,
        ] {
            assert!(
                code.is_retryable_before_commit(),
                "{:?} must be retryable before commit",
                code
            );
        }
    }

    #[test]
    fn error_v1_serializes_with_schema_version() {
        let err = ImageControlErrorV1::new(ImageControlErrorCode::Forbidden);
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["schemaVersion"], 1);
        assert_eq!(json["code"], "forbidden");
        assert_eq!(json["retryable"], false);
        assert!(json["operationId"].is_null());
        assert!(json["currentEntityGeneration"].is_null());
        assert!(json["currentConfigGeneration"].is_null());
    }

    #[test]
    fn mutation_result_serializes() {
        let result = ImageMutationResultV1 {
            operation_id: "01923f5e-9a16-7abc-8def-0123456789ab".to_string(),
            outcome: MutationOutcome::Committed,
            entity_refs: vec![EntityRef {
                kind: ImageEntityKind::Endpoint,
                id: "abcdefghijklmnopqrstuv".to_string(),
                generation: "1".to_string(),
            }],
            config_generation: Some("2".to_string()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["operationId"], "01923f5e-9a16-7abc-8def-0123456789ab");
        assert_eq!(json["outcome"], "committed");
        assert_eq!(json["entityRefs"][0]["kind"], "endpoint");
        assert_eq!(json["configGeneration"], "2");
    }

    #[test]
    fn operation_status_serializes() {
        let status = ImageOperationStatusV1 {
            operation_kind: ImageOperationKindV1::RemoteAttachment,
            queried_operation_id: "01923f5e-9a16-7abc-8def-0123456789ab".to_string(),
            state: OperationState::Committed,
            outcome: None,
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["operationKind"], "remote_attachment");
        assert_eq!(
            json["queriedOperationId"],
            "01923f5e-9a16-7abc-8def-0123456789ab"
        );
        assert_eq!(json["state"], "committed");
        assert!(json["outcome"].is_null());
    }

    #[test]
    fn snapshot_components_are_exact() {
        let admin_components = [
            SnapshotComponent::Endpoints,
            SnapshotComponent::Targets,
            SnapshotComponent::Workflows,
            SnapshotComponent::Health,
            SnapshotComponent::Budget,
            SnapshotComponent::DestinationGrants,
        ];
        let session_components = [SnapshotComponent::Plans, SnapshotComponent::Jobs];
        for c in admin_components {
            assert!(c.is_admin());
            assert!(!c.is_session());
        }
        for c in session_components {
            assert!(!c.is_admin());
            assert!(c.is_session());
        }
    }

    #[test]
    fn event_kinds_are_exact() {
        let kinds = [
            EventKind::ConfigChanged,
            EventKind::HealthChanged,
            EventKind::BudgetChanged,
            EventKind::DestinationGrantChanged,
            EventKind::PlanChanged,
            EventKind::JobChanged,
            EventKind::SlotChanged,
            EventKind::LateResultChanged,
            EventKind::OperationChanged,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for k in kinds {
            let s = serde_json::to_string(&k).unwrap();
            assert!(seen.insert(s), "duplicate event kind: {s}");
        }
        assert_eq!(seen.len(), 9);
    }

    #[test]
    fn remote_envelope_serializes() {
        let env = RemoteImageControlEnvelopeV1 {
            schema_version: 1,
            request_id: "abcdefghijklmnopqrstuv".to_string(),
            operation_id: Some("01923f5e-9a16-7abc-8def-0123456789ab".to_string()),
            command: serde_json::json!({"request": "image_endpoint_list", "params": {}}),
        };
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["schemaVersion"], 1);
        assert_eq!(json["requestId"], "abcdefghijklmnopqrstuv");
        assert!(json["operationId"].is_string());
    }

    #[test]
    fn local_owner_envelope_serializes() {
        let env = LocalOwnerImageControlEnvelopeV1 {
            schema_version: 1,
            request_id: "abcdefghijklmnopqrstuv".to_string(),
            local_operation_id: None,
            command: serde_json::json!({"request": "image_endpoint_list", "params": {}}),
        };
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["schemaVersion"], 1);
        assert!(json["localOperationId"].is_null());
    }

    #[test]
    fn reply_outcome_ok_serializes() {
        let response = ImageControlResponseV1 {
            schema_version: 1,
            kind: ImageControlRequestTag::ImageEndpointGet,
            daemon_instance_id: "abcdefghijklmnopqrstuv".to_string(),
            project_id: "abcdefghijklmnopqrstuv".to_string(),
            result: ControlResult::Entity {
                item: serde_json::json!({}),
            },
        };
        let outcome = ReplyOutcome::Ok { response };
        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json["kind"], "ok");
    }

    #[test]
    fn reply_outcome_error_serializes() {
        let error = ImageControlErrorV1::new(ImageControlErrorCode::Forbidden);
        let outcome = ReplyOutcome::Error { error };
        let json = serde_json::to_value(&outcome).unwrap();
        assert_eq!(json["kind"], "error");
        assert_eq!(json["error"]["code"], "forbidden");
    }
}

// ---------------------------------------------------------------------------
// 6. image_generation_control_redaction
// ---------------------------------------------------------------------------

mod redaction {
    use super::*;

    #[test]
    fn error_v1_has_no_free_form_message() {
        let err = ImageControlErrorV1::new(ImageControlErrorCode::NotFound);
        let json = serde_json::to_value(&err).unwrap();
        let obj = json.as_object().unwrap();
        // The body contains no free-form message, path, provider body,
        // credential, workflow bytes, quarantine state, or hidden identity.
        for forbidden in [
            "message",
            "path",
            "providerBody",
            "credential",
            "quarantine",
            "identity",
        ] {
            assert!(
                !obj.contains_key(forbidden),
                "error must not contain {forbidden}"
            );
        }
    }

    #[test]
    fn forbidden_sentinels_scan_finds_them() {
        let value = serde_json::json!({
            "apiKey": "secret123",
            "nested": {
                "localPath": "/some/path",
                "providerBody": "data"
            }
        });
        let found = scan_for_forbidden_sentinels(&value);
        assert!(found.contains(&"apiKey".to_string()));
        assert!(found.contains(&"localPath".to_string()));
        assert!(found.contains(&"providerBody".to_string()));
    }

    #[test]
    fn safe_response_has_no_forbidden_sentinels() {
        let response = ImageControlResponseV1 {
            schema_version: 1,
            kind: ImageControlRequestTag::ImageEndpointGet,
            daemon_instance_id: "abcdefghijklmnopqrstuv".to_string(),
            project_id: "abcdefghijklmnopqrstuv".to_string(),
            result: ControlResult::Entity {
                item: serde_json::json!({
                    "schemaVersion": 1,
                    "endpointId": "abcdefghijklmnopqrstuv",
                    "entityGeneration": "1",
                    "displayName": "My Endpoint",
                    "adapterKind": "openai",
                    "enabled": true
                }),
            },
        };
        let json = serde_json::to_value(&response).unwrap();
        let found = scan_for_forbidden_sentinels(&json);
        assert!(found.is_empty(), "forbidden sentinels found: {found:?}");
    }

    #[test]
    fn safe_error_has_no_forbidden_sentinels() {
        let err = ImageControlErrorV1::new(ImageControlErrorCode::VersionConflict);
        let json = serde_json::to_value(&err).unwrap();
        let found = scan_for_forbidden_sentinels(&json);
        assert!(found.is_empty(), "forbidden sentinels found: {found:?}");
    }

    #[test]
    fn event_has_no_forbidden_sentinels() {
        let event = ImageControlEventV1 {
            schema_version: 1,
            delivery_id: "abcdefghijklmnopqrstuv".to_string(),
            event_seq: "1".to_string(),
            daemon_instance_id: "abcdefghijklmnopqrstuv".to_string(),
            project_id: "abcdefghijklmnopqrstuv".to_string(),
            session_id: None,
            entity_kind: EventEntityKind::Project,
            entity_id: "abcdefghijklmnopqrstuv".to_string(),
            entity_generation: "1".to_string(),
            kind: EventKind::ConfigChanged,
            safe_projection: serde_json::json!({
                "schemaVersion": 1,
                "configGeneration": "2",
                "changes": []
            }),
        };
        let json = serde_json::to_value(&event).unwrap();
        let found = scan_for_forbidden_sentinels(&json);
        assert!(found.is_empty(), "forbidden sentinels found: {found:?}");
    }
}

// ---------------------------------------------------------------------------
// 7. image_generation_budget_plan_scope_and_config_events
// ---------------------------------------------------------------------------

mod budget_and_config {
    use super::*;

    #[test]
    fn budget_unconfigured_requires_null_generation() {
        let proj = BudgetScopeProjection::unconfigured();
        assert!(proj.validate());
        assert_eq!(proj.policy, BudgetPolicy::Unconfigured);
        assert!(proj.generation.is_none());
    }

    #[test]
    fn budget_finite_requires_positive_generation() {
        let proj = BudgetScopeProjection::finite("1".to_string());
        assert!(proj.validate());
        let proj = BudgetScopeProjection::finite("0".to_string());
        assert!(!proj.validate(), "generation 0 must reject");
    }

    #[test]
    fn budget_unlimited_requires_positive_generation() {
        let proj = BudgetScopeProjection::unlimited("1".to_string());
        assert!(proj.validate());
    }

    #[test]
    fn budget_unconfigured_with_generation_rejects() {
        // Unconfigured must have null generation.
        let proj = BudgetScopeProjection {
            policy: BudgetPolicy::Unconfigured,
            generation: Some("1".to_string()),
        };
        assert!(!proj.validate());
    }

    #[test]
    fn budget_finite_without_generation_rejects() {
        let proj = BudgetScopeProjection {
            policy: BudgetPolicy::Finite,
            generation: None,
        };
        assert!(!proj.validate());
    }

    #[test]
    fn budget_set_pair_unchanged() {
        assert!(validate_budget_set_pair(None, None));
    }

    #[test]
    fn budget_set_pair_create() {
        // Nonnull policy with null expected generation creates generation 1.
        assert!(validate_budget_set_pair(Some(BudgetPolicy::Finite), None));
        assert!(validate_budget_set_pair(
            Some(BudgetPolicy::Unlimited),
            None
        ));
    }

    #[test]
    fn budget_set_pair_cas_update() {
        // Nonnull policy with positive expected generation CAS-updates.
        assert!(validate_budget_set_pair(
            Some(BudgetPolicy::Finite),
            Some("1")
        ));
        assert!(validate_budget_set_pair(
            Some(BudgetPolicy::Unlimited),
            Some("5")
        ));
    }

    #[test]
    fn budget_set_pair_unconfigured_rejects() {
        // Unconfigured in a save rejects.
        assert!(!validate_budget_set_pair(
            Some(BudgetPolicy::Unconfigured),
            None
        ));
        assert!(!validate_budget_set_pair(
            Some(BudgetPolicy::Unconfigured),
            Some("1")
        ));
    }

    #[test]
    fn budget_set_pair_half_present_rejects() {
        // Half-present tuple rejects.
        assert!(!validate_budget_set_pair(None, Some("1")));
    }

    #[test]
    fn budget_set_pair_zero_generation_rejects() {
        assert!(!validate_budget_set_pair(
            Some(BudgetPolicy::Finite),
            Some("0")
        ));
    }

    #[test]
    fn budget_set_at_least_one_policy() {
        assert!(!validate_at_least_one_policy(None, None, None));
        assert!(validate_at_least_one_policy(
            Some(BudgetPolicy::Finite),
            None,
            None
        ));
        assert!(validate_at_least_one_policy(
            None,
            Some(BudgetPolicy::Unlimited),
            None
        ));
        assert!(validate_at_least_one_policy(
            None,
            None,
            Some(BudgetPolicy::Finite)
        ));
        assert!(validate_at_least_one_policy(
            Some(BudgetPolicy::Finite),
            Some(BudgetPolicy::Unlimited),
            Some(BudgetPolicy::Finite)
        ));
    }

    #[test]
    fn config_change_set_sorts_by_kind_then_id() {
        let mut changes = vec![
            ConfigChange::Upsert {
                entity_kind: ConfigEntityKind::Target,
                entity_id: "zzzzzzzzzzzzzzzzzzzzzz".to_string(),
                entity_generation: "1".to_string(),
                item: serde_json::json!({}),
            },
            ConfigChange::Upsert {
                entity_kind: ConfigEntityKind::Endpoint,
                entity_id: "abcdefghijklmnopqrstuv".to_string(),
                entity_generation: "1".to_string(),
                item: serde_json::json!({}),
            },
            ConfigChange::Deleted {
                entity_kind: ConfigEntityKind::Endpoint,
                entity_id: "zzzzzzzzzzzzzzzzzzzzzz".to_string(),
                entity_generation: "2".to_string(),
                item: None,
            },
        ];
        sort_config_changes(&mut changes);
        // After sort: Endpoint/abc, Endpoint/zzz, Target/zzz
        match &changes[0] {
            ConfigChange::Upsert {
                entity_kind,
                entity_id,
                ..
            } => {
                assert_eq!(*entity_kind, ConfigEntityKind::Endpoint);
                assert_eq!(entity_id, "abcdefghijklmnopqrstuv");
            }
            _ => panic!("expected upsert"),
        }
        match &changes[1] {
            ConfigChange::Deleted {
                entity_kind,
                entity_id,
                ..
            } => {
                assert_eq!(*entity_kind, ConfigEntityKind::Endpoint);
                assert_eq!(entity_id, "zzzzzzzzzzzzzzzzzzzzzz");
            }
            _ => panic!("expected deleted"),
        }
        match &changes[2] {
            ConfigChange::Upsert { entity_kind, .. } => {
                assert_eq!(*entity_kind, ConfigEntityKind::Target);
            }
            _ => panic!("expected upsert"),
        }
    }

    #[test]
    fn config_change_set_validates_bounds() {
        // Empty rejects.
        assert!(!validate_config_change_set(&[]));
        // One valid change accepts.
        let one = vec![ConfigChange::Upsert {
            entity_kind: ConfigEntityKind::Endpoint,
            entity_id: "abcdefghijklmnopqrstuv".to_string(),
            entity_generation: "1".to_string(),
            item: serde_json::json!({}),
        }];
        assert!(validate_config_change_set(&one));
        // Duplicate entity ID rejects.
        let dup = vec![
            ConfigChange::Upsert {
                entity_kind: ConfigEntityKind::Endpoint,
                entity_id: "abcdefghijklmnopqrstuv".to_string(),
                entity_generation: "1".to_string(),
                item: serde_json::json!({}),
            },
            ConfigChange::Deleted {
                entity_kind: ConfigEntityKind::Endpoint,
                entity_id: "abcdefghijklmnopqrstuv".to_string(),
                entity_generation: "2".to_string(),
                item: None,
            },
        ];
        assert!(!validate_config_change_set(&dup));
    }
}

// ---------------------------------------------------------------------------
// 8. image_generation_admin_grant_resolution
// ---------------------------------------------------------------------------

mod grant_resolution {
    use super::*;

    #[test]
    fn active_authority_key_is_lowercase_64_hex() {
        let key = compute_active_authority_key(b"instance-1", b"grantee-1", &nonzero_project_id());
        assert_eq!(key.len(), 64);
        assert!(
            key.bytes()
                .all(|b| (b'a'..=b'f').contains(&b) || b.is_ascii_digit())
        );
    }

    #[test]
    fn active_authority_key_is_deterministic() {
        let pid = nonzero_project_id();
        let key1 = compute_active_authority_key(b"instance-1", b"grantee-1", &pid);
        let key2 = compute_active_authority_key(b"instance-1", b"grantee-1", &pid);
        assert_eq!(key1, key2);
    }

    #[test]
    fn active_authority_key_differs_for_different_inputs() {
        let pid = nonzero_project_id();
        let key1 = compute_active_authority_key(b"instance-1", b"grantee-1", &pid);
        let key2 = compute_active_authority_key(b"instance-2", b"grantee-1", &pid);
        let key3 = compute_active_authority_key(b"instance-1", b"grantee-2", &pid);
        let mut pid2 = pid;
        pid2[0] = 2;
        let key4 = compute_active_authority_key(b"instance-1", b"grantee-1", &pid2);
        assert_ne!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);
    }

    #[test]
    fn grant_id_validates_cuid2() {
        assert!(validate_grant_id("abcdefghijklmnopqrstuvx"));
        assert!(validate_grant_id("a12345678901234567890123"));
        assert!(!validate_grant_id("A12345678901234567890123")); // uppercase first
        assert!(!validate_grant_id("1abcdefghijklmnopqrstuvx")); // digit first
        assert!(!validate_grant_id("abcdefghijklmnopqrstuv")); // 23 chars
        assert!(!validate_grant_id("abcdefghijklmnopqrstuvxyz")); // 25 chars
    }

    #[test]
    fn access_grant_status_enum_includes_revoking() {
        // The extended status enum includes REVOKING.
        let statuses = [
            AccessGrantStatus::Pending,
            AccessGrantStatus::Active,
            AccessGrantStatus::Revoking,
            AccessGrantStatus::Revoked,
            AccessGrantStatus::Expired,
            AccessGrantStatus::Declined,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for s in statuses {
            let json = serde_json::to_string(&s).unwrap();
            assert!(seen.insert(json));
        }
        assert_eq!(seen.len(), 6);
    }

    #[test]
    fn pending_terminal_transitions_increment_once_no_drain() {
        assert!(AccessGrantTransition::PendingDecline.increments_generation());
        assert!(AccessGrantTransition::PendingExpiry.increments_generation());
        assert!(AccessGrantTransition::PendingDecline.is_pending_terminal());
        assert!(AccessGrantTransition::PendingExpiry.is_pending_terminal());
    }

    #[test]
    fn active_terminal_transitions_use_revoking_barrier() {
        assert!(AccessGrantTransition::ActiveExpiry.is_active_terminal());
        assert!(AccessGrantTransition::RevokeStart.is_active_terminal());
        assert!(AccessGrantTransition::ActiveExpiry.increments_generation());
        assert!(AccessGrantTransition::RevokeStart.increments_generation());
    }

    #[test]
    fn revoke_complete_does_not_increment() {
        // RevokeComplete is the drain barrier completion: no second increment.
        assert!(!AccessGrantTransition::RevokeComplete.increments_generation());
    }

    #[test]
    fn renewal_increments_once_stays_active() {
        // Renewal of an active expiry increments once and leaves ACTIVE.
        assert!(AccessGrantTransition::ActiveRenewal.increments_generation());
    }
}

// ---------------------------------------------------------------------------
// 9. Lease and API validation
// ---------------------------------------------------------------------------

mod lease_validation {
    use super::*;

    #[test]
    fn mutation_lease_header_validates() {
        let header = serde_json::json!({
            "alg": "ES256",
            "kid": "key-1",
            "typ": "flycockpit-image-admin-mutation-lease+jws"
        });
        assert!(validate_mutation_lease_header(&header));
    }

    #[test]
    fn mutation_lease_header_rejects_extra_fields() {
        let header = serde_json::json!({
            "alg": "ES256",
            "kid": "key-1",
            "typ": "flycockpit-image-admin-mutation-lease+jws",
            "extra": "field"
        });
        assert!(!validate_mutation_lease_header(&header));
    }

    #[test]
    fn mutation_lease_header_rejects_wrong_typ() {
        let header = serde_json::json!({
            "alg": "ES256",
            "kid": "key-1",
            "typ": "wrong-typ"
        });
        assert!(!validate_mutation_lease_header(&header));
    }

    #[test]
    fn mutation_lease_header_rejects_wrong_alg() {
        let header = serde_json::json!({
            "alg": "RS256",
            "kid": "key-1",
            "typ": "flycockpit-image-admin-mutation-lease+jws"
        });
        assert!(!validate_mutation_lease_header(&header));
    }

    #[test]
    fn read_claim_header_validates() {
        let header = serde_json::json!({
            "alg": "ES256",
            "kid": "key-1",
            "typ": "flycockpit-image-admin-read-claim+jws"
        });
        assert!(validate_read_claim_header(&header));
    }

    #[test]
    fn read_claim_header_rejects_mutation_typ() {
        let header = serde_json::json!({
            "alg": "ES256",
            "kid": "key-1",
            "typ": "flycockpit-image-admin-mutation-lease+jws"
        });
        assert!(!validate_read_claim_header(&header));
    }

    #[test]
    fn lease_times_valid() {
        assert!(validate_lease_times(1000, 1000, 1015));
        assert!(validate_lease_times(1000, 1000, 1001));
    }

    #[test]
    fn lease_times_reject_nbf_not_iat() {
        assert!(!validate_lease_times(1000, 1001, 1015));
    }

    #[test]
    fn lease_times_reject_zero_lifetime() {
        assert!(!validate_lease_times(1000, 1000, 1000));
    }

    #[test]
    fn lease_times_reject_over_15_seconds() {
        assert!(!validate_lease_times(1000, 1000, 1016));
    }

    #[test]
    fn lease_id_validates_22_char_base64url() {
        assert!(validate_lease_id("abcdefghijklmnopqrstuv"));
        assert!(!validate_lease_id("abcdefghijklmnopqrstuvx"));
        assert!(!validate_lease_id("short"));
    }

    #[test]
    fn api_format_blob_validates() {
        assert!(validate_api_format_blob(
            1,
            "abcdefghijklmnopqrstuv",
            "1024",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn api_format_blob_rejects_zero_length() {
        assert!(!validate_api_format_blob(
            1,
            "abcdefghijklmnopqrstuv",
            "0",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn api_format_blob_rejects_over_max_length() {
        assert!(!validate_api_format_blob(
            1,
            "abcdefghijklmnopqrstuv",
            "16777217",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn api_format_blob_rejects_bad_sha256() {
        assert!(!validate_api_format_blob(
            1,
            "abcdefghijklmnopqrstuv",
            "1024",
            "not-a-hash"
        ));
    }

    #[test]
    fn api_format_blob_rejects_bad_schema_version() {
        assert!(!validate_api_format_blob(
            2,
            "abcdefghijklmnopqrstuv",
            "1024",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }
}

// ---------------------------------------------------------------------------
// 10. Validation helpers
// ---------------------------------------------------------------------------

mod validation_helpers {
    use super::*;

    #[test]
    fn validate_limit_bounds() {
        assert!(!validate_limit(0));
        assert!(validate_limit(1));
        assert!(validate_limit(50));
        assert!(validate_limit(100));
        assert!(!validate_limit(101));
    }

    #[test]
    fn validate_cursor_charset() {
        assert!(validate_cursor("abc123-_"));
        assert!(!validate_cursor("abc+123")); // + not in base64url
        assert!(!validate_cursor("abc=123")); // = not unpadded
        assert!(!validate_cursor(""));
    }

    #[test]
    fn validate_display_name_nfc_no_nul() {
        assert!(validate_display_name("Hello World"));
        assert!(!validate_display_name(""));
        assert!(!validate_display_name(&"a".repeat(257)));
        assert!(!validate_display_name("hello\0world"));
    }

    #[test]
    fn validate_stable_code() {
        assert!(validate_stable_code("a"));
        assert!(validate_stable_code("abc_def_123"));
        assert!(!validate_stable_code("")); // empty
        assert!(!validate_stable_code("1abc")); // digit first
        assert!(!validate_stable_code("Abc")); // uppercase
        assert!(!validate_stable_code(&"a".repeat(65))); // too long
    }

    #[test]
    fn validate_canonical_decimal() {
        assert!(validate_canonical_decimal("0"));
        assert!(validate_canonical_decimal("1"));
        assert!(validate_canonical_decimal("12345"));
        assert!(validate_canonical_decimal("18446744073709551615")); // u64::MAX
        assert!(!validate_canonical_decimal("")); // empty
        assert!(!validate_canonical_decimal("01")); // leading zero
        assert!(!validate_canonical_decimal("18446744073709551616")); // > u64::MAX (20 digits)
        assert!(!validate_canonical_decimal("abc"));
    }

    #[test]
    fn validate_sha256_hex() {
        assert!(validate_sha256_hex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        assert!(!validate_sha256_hex("ABCDEF")); // uppercase
        assert!(!validate_sha256_hex("short"));
        assert!(!validate_sha256_hex(""));
    }

    #[test]
    fn sha256_hex_matches_known() {
        // SHA-256 of empty string
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn validate_uuid_lowercase() {
        assert!(validate_uuid_lowercase_hyphenated(
            "01923f5e-9a16-7abc-8def-0123456789ab"
        ));
        assert!(!validate_uuid_lowercase_hyphenated(
            "01923F5E-9A16-7ABC-8DEF-0123456789AB"
        )); // uppercase
        assert!(!validate_uuid_lowercase_hyphenated("not-a-uuid"));
    }
}
