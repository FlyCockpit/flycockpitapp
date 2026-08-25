//! Non-leakage proofs for the LOCAL image-control safe projections.
//!
//! Every test plants a DISTINCT secret in a secret-bearing field, projects the
//! domain value through the single funnel, serializes the projection to JSON,
//! and asserts (a) a precondition that the raw domain value REALLY carries the
//! secret, then (b) that the secret substring is ABSENT from the serialized
//! projection. A broken projection that copied the field through would fail (b).

use chrono::Utc;

use cockpit_config::config::image_generation::ImageParameter;
use cockpit_config::config::image_generation::{
    ImageAdapterKind, ImageBillableUnit, ImageCapabilityEvidence, ImageDimensionDescriptor,
    ImageEndpoint, ImageEvidence, ImageFormat, ImageGenerationTarget, ImageLocationClass,
    ImagePrice, ImagePriceMethod, ImageTargetIdentity, ReferenceImageSupport,
    RegisteredComfyWorkflow, WorkflowBinding, WorkflowOutput, WorkflowValueType,
};
use cockpit_config::config::providers::{CapabilityStatus, HeaderSpec};

use super::*;

const CREDENTIAL_SECRET: &str = "sk-CREDENTIAL-SUPERSECRET-abcdef";
const HEADER_NAME_SECRET: &str = "X-Leak-Header-Name";
const HEADER_VALUE_SECRET: &str = "Bearer HEADER-VALUE-SUPERSECRET";
const GRAPH_SECRET: &str = "GRAPH-JSON-SUPERSECRET-TOKEN";
const SOURCE_URL_SECRET: &str = "https://leak-host.example/path?token=SOURCE-URL-SUPERSECRET";

fn secret_bearing_endpoint() -> ImageEndpoint {
    ImageEndpoint {
        id: "ep1".to_string(),
        adapter: ImageAdapterKind::OpenaiImages,
        origin: "https://api.example.com".to_string(),
        path_prefix: Some("/v1".to_string()),
        credential_ref: Some(CREDENTIAL_SECRET.to_string()),
        headers: vec![HeaderSpec {
            name: HEADER_NAME_SECRET.to_string(),
            value: HEADER_VALUE_SECRET.to_string(),
        }],
        allow_insecure_transport: false,
        location: ImageLocationClass::PublicCloud,
        enabled: true,
        route_profile_version: 1,
        exclusive_server: false,
    }
}

fn secret_bearing_workflow() -> RegisteredComfyWorkflow {
    RegisteredComfyWorkflow {
        id: "wf1".to_string(),
        graph_json: format!("{{\"node\":{{\"secret\":\"{GRAPH_SECRET}\"}}}}"),
        graph_digest: "a".repeat(64),
        bindings: vec![WorkflowBinding {
            parameter: ImageParameter::Steps,
            node_id: "node".to_string(),
            input: "value".to_string(),
            value_type: WorkflowValueType::Integer,
            min: Some(1),
            max: Some(50),
        }],
        outputs: vec![WorkflowOutput {
            node_id: "node".to_string(),
            output: "IMAGE".to_string(),
            value_type: WorkflowValueType::Image,
        }],
    }
}

fn secret_bearing_target() -> ImageGenerationTarget {
    let evidence = ImageEvidence::CheckedIn {
        source_url: SOURCE_URL_SECRET.to_string(),
        last_verified: Utc::now(),
    };
    ImageGenerationTarget {
        id: "t1".to_string(),
        display_name: Some("Target One".to_string()),
        endpoint_id: "ep1".to_string(),
        identity: ImageTargetIdentity::HostedModel {
            model: "gpt-image-1".to_string(),
        },
        enabled: true,
        is_default: true,
        formats: vec![ImageFormat::Png],
        reference_support: ReferenceImageSupport::Unsupported,
        max_reference_images: 0,
        max_samples: 1,
        max_outputs: 1,
        dimensions: ImageDimensionDescriptor::ProviderDefault,
        dimension_policy: Default::default(),
        parameters: Vec::new(),
        openrouter_routing: None,
        // Not projected, but planted to prove even the unprojected evidence
        // source_url cannot leak.
        generation_capability: ImageCapabilityEvidence::new(
            CapabilityStatus::Supported,
            Some(evidence.clone()),
        )
        .expect("capability evidence"),
        // Projected via ImageCostSummaryV1, which must DROP the evidence.
        price: ImagePrice::Known {
            usd_micros: 1234,
            unit: ImageBillableUnit::Image,
            variant: "standard".to_string(),
            method: ImagePriceMethod::ConservativeMaximum,
            evidence,
        },
    }
}

fn assert_absent(haystack: &str, needle: &str, field: &str) {
    assert!(
        !haystack.contains(needle),
        "projected wire value leaked {field}: {needle} present in {haystack}"
    );
}

#[test]
fn image_endpoint_safe_projection_drops_credential_and_headers() {
    let endpoint = secret_bearing_endpoint();
    // Precondition: the raw domain value really carries the secrets.
    let raw = serde_json::to_string(&endpoint).unwrap();
    assert!(
        raw.contains(CREDENTIAL_SECRET),
        "test fixture lost credential"
    );
    assert!(
        raw.contains(HEADER_VALUE_SECRET),
        "test fixture lost header value"
    );
    assert!(
        raw.contains(HEADER_NAME_SECRET),
        "test fixture lost header name"
    );

    let projection = ImageEndpointSafeV1::project(&endpoint, "7".to_string());
    // The summarized signals are present and honest.
    assert!(projection.credential_configured);
    assert_eq!(projection.header_reference_count, 1);

    let wire = serde_json::to_string(&projection).unwrap();
    assert_absent(&wire, CREDENTIAL_SECRET, "credential_ref");
    assert_absent(&wire, HEADER_VALUE_SECRET, "header value");
    assert_absent(&wire, HEADER_NAME_SECRET, "header name");
    // Round-trips.
    let back: ImageEndpointSafeV1 = serde_json::from_str(&wire).unwrap();
    assert_eq!(back, projection);
}

#[test]
fn image_workflow_safe_projection_drops_graph_json() {
    let workflow = secret_bearing_workflow();
    let raw = serde_json::to_string(&workflow).unwrap();
    assert!(raw.contains(GRAPH_SECRET), "test fixture lost graph secret");

    let projection = ImageWorkflowSafeV1::project(
        &workflow,
        vec!["t1".to_string(), "t2".to_string()],
        "7".to_string(),
    );
    assert_eq!(projection.workflow_digest, "a".repeat(64));
    assert_eq!(projection.referencing_target_ids, vec!["t1", "t2"]);

    let wire = serde_json::to_string(&projection).unwrap();
    assert_absent(&wire, GRAPH_SECRET, "graph_json");
    // The digest (a hash) is fine; the raw graph text is not.
    let back: ImageWorkflowSafeV1 = serde_json::from_str(&wire).unwrap();
    assert_eq!(back, projection);
}

#[test]
fn image_target_safe_projection_drops_source_urls() {
    let target = secret_bearing_target();
    let raw = serde_json::to_string(&target).unwrap();
    assert!(
        raw.contains(SOURCE_URL_SECRET),
        "test fixture lost source url"
    );

    let projection = ImageTargetSafeV1::project(
        &target,
        Some(ImageAdapterKind::OpenaiImages),
        "7".to_string(),
    );
    // Non-secret price scalars survive.
    assert!(projection.cost_evidence.known);
    assert_eq!(projection.cost_evidence.usd_micros, Some(1234));

    let wire = serde_json::to_string(&projection).unwrap();
    assert_absent(&wire, SOURCE_URL_SECRET, "price/capability source_url");
    // The unprojected capability evidence must not smuggle it either.
    assert_absent(&wire, "SOURCE-URL-SUPERSECRET", "any source_url fragment");
    let back: ImageTargetSafeV1 = serde_json::from_str(&wire).unwrap();
    assert_eq!(back, projection);
}

#[test]
fn image_mutation_capability_debug_is_redacted() {
    let secret = "ab".repeat(32);
    let capability = ImageConfigMutationCapabilityV1::new(secret.clone());
    let debug = format!("{capability:?}");
    assert!(!debug.contains(&secret));
    assert!(debug.contains("REDACTED"));
    assert_eq!(
        serde_json::to_string(&capability).unwrap(),
        format!("\"{secret}\"")
    );
}

#[test]
fn image_mutation_capability_decode_requires_exact_lowercase_hex() {
    assert!(serde_json::from_str::<ImageConfigMutationCapabilityV1>("\"short\"").is_err());
    assert!(
        serde_json::from_str::<ImageConfigMutationCapabilityV1>(&format!(
            "\"{}\"",
            "AA".repeat(32)
        ))
        .is_err()
    );
    assert!(
        serde_json::from_str::<ImageConfigMutationCapabilityV1>(&format!(
            "\"{}\"",
            "ab".repeat(32)
        ))
        .is_ok()
    );
}

#[test]
fn image_read_authority_fields_are_mandatory() {
    let missing_capability = serde_json::json!({
        "schemaVersion": 1,
        "daemonInstanceId": "daemon",
        "requestedProjectRoot": "/requested",
        "canonicalProjectRoot": "/canonical",
        "targetPath": "/canonical/config.json",
        "targetRevision": "revision",
        "configGeneration": 1,
        "result": {
            "type": "endpoint_page",
            "items": [],
            "nextCursor": null,
            "snapshotGeneration": "1"
        }
    });
    assert!(serde_json::from_value::<ImageControlReadResponseV1>(missing_capability).is_err());
}
