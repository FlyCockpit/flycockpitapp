use std::collections::HashSet;
use std::sync::Arc;

use serde_json::{Value, json};

use super::*;
use crate::engine::model::wire_schema::for_responses;
use crate::engine::tool::{InvalidToolInput, Tool};
use crate::media_storage::{
    TYPED_AUDIO_CONTAINER_CODECS, TYPED_VIDEO_CONTAINER_CODECS, container_allows_audio_codec,
    container_allows_video_codec,
};
use crate::tool_media_authority::session_authority::{
    AdmittedAttachment, AdmittedRetainedSource, AttachmentResolver, HandleEvidence,
    LocalPathPolicy, MAX_AV_SOURCE_BYTES, RetainedHttpsPolicy, SubjectLiveness,
};
use crate::tool_media_authority::{AdmissionDenial, NestedMediaSource, SessionMediaAuthority};

const FORBIDDEN_KEYWORDS: &[&str] = &[
    "allOf",
    "oneOf",
    "not",
    "dependentRequired",
    "dependentSchemas",
    "if",
    "then",
    "else",
];

const SOURCE_BRANCHES: &[&str] = &["attachment_id", "path", "url"];

#[derive(Clone, Copy)]
enum AvKind {
    Audio,
    Video,
}

fn av_tools() -> [Box<dyn Tool>; 4] {
    [
        Box::new(InspectAudioTool::new()),
        Box::new(InspectVideoTool::new()),
        Box::new(ExtractVideoClipTool::new()),
        Box::new(ExtractAudioTool::new()),
    ]
}

fn tool_kinds() -> [ToolKind; 4] {
    [
        ToolKind::InspectAudio,
        ToolKind::InspectVideo,
        ToolKind::ExtractVideoClip,
        ToolKind::ExtractAudio,
    ]
}

fn av_tool_schemas() -> Vec<(&'static str, Value)> {
    let mut schemas = Vec::new();
    for tool in av_tools() {
        let name: &'static str = match tool.name() {
            "inspect_audio" => "inspect_audio",
            "inspect_video" => "inspect_video",
            "extract_video_clip" => "extract_video_clip",
            "extract_audio" => "extract_audio",
            other => panic!("unexpected A/V tool {other}"),
        };
        schemas.push((name, tool.parameters()));
        if let Some(verbose) = tool.verbose_parameters() {
            schemas.push((name, verbose));
        }
    }
    schemas
}

fn validator(schema: &Value) -> jsonschema::Validator {
    jsonschema::validator_for(schema).expect("schema must compile")
}

fn assert_valid(schema: &Value, instance: &Value) {
    assert!(
        validator(schema).is_valid(instance),
        "expected valid instance {instance} for {schema}"
    );
}

fn assert_invalid(schema: &Value, instance: &Value) {
    assert!(
        !validator(schema).is_valid(instance),
        "expected invalid instance {instance} for {schema}"
    );
}

fn is_object_schema(object: &serde_json::Map<String, Value>) -> bool {
    object.contains_key("properties")
        || matches!(object.get("type"), Some(Value::String(kind)) if kind == "object")
        || object
            .get("type")
            .and_then(Value::as_array)
            .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("object")))
}

fn has_null_type(schema: &Value) -> bool {
    let Some(object) = schema.as_object() else {
        return false;
    };
    match object.get("type") {
        Some(Value::String(kind)) if kind == "null" => return true,
        Some(Value::Array(kinds))
            if kinds
                .iter()
                .any(|kind| kind.as_str().is_some_and(|kind| kind == "null")) =>
        {
            return true;
        }
        _ => {}
    }
    if object
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(Value::is_null))
        || object.get("const").is_some_and(Value::is_null)
    {
        return true;
    }
    ["anyOf", "oneOf"].into_iter().any(|key| {
        object
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|variants| variants.iter().any(has_null_type))
    })
}

fn walk_schema(schema: &Value, visit: &mut impl FnMut(&Value)) {
    visit(schema);
    let Some(object) = schema.as_object() else {
        return;
    };
    for key in [
        "properties",
        "$defs",
        "definitions",
        "patternProperties",
        "dependentSchemas",
    ] {
        if let Some(entries) = object.get(key).and_then(Value::as_object) {
            for child in entries.values() {
                walk_schema(child, visit);
            }
        }
    }
    if let Some(Value::Object(entries)) = object.get("dependencies") {
        for child in entries.values() {
            if child.is_object() {
                walk_schema(child, visit);
            }
        }
    }
    for key in ["items", "prefixItems"] {
        match object.get(key) {
            Some(Value::Array(schemas)) => {
                for child in schemas {
                    walk_schema(child, visit);
                }
            }
            Some(child) => walk_schema(child, visit),
            None => {}
        }
    }
    for key in [
        "contains",
        "propertyNames",
        "additionalProperties",
        "additionalItems",
        "unevaluatedItems",
        "unevaluatedProperties",
        "not",
        "if",
        "then",
        "else",
        "contentSchema",
    ] {
        match object.get(key) {
            Some(child) if !child.is_boolean() => walk_schema(child, visit),
            _ => {}
        }
    }
    for key in ["anyOf", "oneOf", "allOf"] {
        if let Some(variants) = object.get(key).and_then(Value::as_array) {
            for variant in variants {
                walk_schema(variant, visit);
            }
        }
    }
}

fn forbidden_keyword_hits(schema: &Value) -> Vec<&'static str> {
    let mut hits = Vec::new();
    walk_schema(schema, &mut |node| {
        let Some(object) = node.as_object() else {
            return;
        };
        for keyword in FORBIDDEN_KEYWORDS {
            if object.contains_key(*keyword) {
                hits.push(*keyword);
            }
        }
    });
    hits
}

fn assert_no_forbidden_keywords(schema: &Value, label: &str) {
    let hits = forbidden_keyword_hits(schema);
    assert!(
        hits.is_empty(),
        "{label} contains forbidden keyword(s) {hits:?} in {schema}"
    );
}

fn assert_root_is_object_not_union(schema: &Value, label: &str) {
    let object = schema
        .as_object()
        .unwrap_or_else(|| panic!("{label} root must be an object schema"));
    assert_eq!(
        object.get("type"),
        Some(&Value::String("object".into())),
        "{label} root must declare type=object"
    );
    for keyword in ["anyOf", "oneOf", "allOf"] {
        assert!(
            !object.contains_key(keyword),
            "{label} root must not be a union (`{keyword}`)"
        );
    }
}

fn assert_objects_are_closed(schema: &Value, require_all_properties: bool, label: &str) {
    walk_schema(schema, &mut |node| {
        let Some(object) = node.as_object() else {
            return;
        };
        if !is_object_schema(object) {
            return;
        }
        assert_eq!(
            object.get("additionalProperties"),
            Some(&Value::Bool(false)),
            "{label} object is not closed: {node}"
        );
        if !require_all_properties {
            return;
        }
        let property_names: HashSet<&str> = object
            .get("properties")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|properties| properties.keys().map(String::as_str))
            .collect();
        let required: HashSet<&str> = object
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            required, property_names,
            "{label} strict object must require all fields: {node}"
        );
    });
}

fn assert_optional_properties_nullable(canonical: &Value, strict: &Value, label: &str) {
    let (Some(canonical_object), Some(strict_object)) = (canonical.as_object(), strict.as_object())
    else {
        return;
    };
    let required: HashSet<&str> = canonical_object
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if let (Some(canonical_properties), Some(strict_properties)) = (
        canonical_object
            .get("properties")
            .and_then(Value::as_object),
        strict_object.get("properties").and_then(Value::as_object),
    ) {
        for (name, canonical_property) in canonical_properties {
            let strict_property = &strict_properties[name];
            if !required.contains(name.as_str()) {
                assert!(
                    has_null_type(strict_property),
                    "{label} canonical-optional `{name}` is not nullable: {strict_property}"
                );
            }
            assert_optional_properties_nullable(
                canonical_property,
                strict_property,
                &format!("{label}.{name}"),
            );
        }
    }
    if let (Some(canonical_items), Some(strict_items)) =
        (canonical_object.get("items"), strict_object.get("items"))
    {
        assert_optional_properties_nullable(
            canonical_items,
            strict_items,
            &format!("{label}.items"),
        );
    }
    for canonical_key in ["anyOf", "oneOf", "allOf"] {
        let strict_key = if canonical_key == "oneOf" {
            "anyOf"
        } else {
            canonical_key
        };
        if let (Some(canonical_variants), Some(strict_variants)) = (
            canonical_object
                .get(canonical_key)
                .and_then(Value::as_array),
            strict_object.get(strict_key).and_then(Value::as_array),
        ) {
            for (index, (canonical_variant, strict_variant)) in
                canonical_variants.iter().zip(strict_variants).enumerate()
            {
                assert_optional_properties_nullable(
                    canonical_variant,
                    strict_variant,
                    &format!("{label}.{strict_key}[{index}]"),
                );
            }
        }
    }
}

fn assert_source_union(schema: &Value, label: &str) {
    let source = schema
        .pointer("/properties/source")
        .unwrap_or_else(|| panic!("{label} missing properties.source"));
    assert!(
        source.get("oneOf").is_none(),
        "{label} source must use anyOf, not oneOf"
    );
    let arms = source
        .get("anyOf")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{label} source must be an anyOf union"));
    assert_eq!(
        arms.len(),
        SOURCE_BRANCHES.len(),
        "{label} source arm count"
    );
    for (arm, key) in arms.iter().zip(SOURCE_BRANCHES) {
        assert_eq!(
            arm["type"], "object",
            "{label} `{key}` arm must be an object"
        );
        let properties = arm["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{label} `{key}` arm missing properties"));
        assert_eq!(
            properties.len(),
            1,
            "{label} `{key}` arm must declare exactly one property"
        );
        assert!(
            properties.contains_key(*key),
            "{label} `{key}` arm missing its branch property"
        );
        assert_eq!(
            arm["required"],
            json!([key]),
            "{label} `{key}` required list must match the single branch property"
        );
        assert_eq!(
            arm["additionalProperties"], false,
            "{label} `{key}` arm must be closed"
        );
        if *key == "url" {
            assert_eq!(arm["properties"]["url"]["pattern"], "^https://");
        } else {
            assert_eq!(arm["properties"][key]["type"], "string");
            assert_eq!(arm["properties"][key]["minLength"], 1);
        }
    }
}

fn assert_stream_interval_sampling(name: &str, schema: &Value) {
    assert_eq!(schema["properties"]["stream_index"]["type"], "integer");
    assert_eq!(schema["properties"]["stream_index"]["minimum"], 0);
    assert_eq!(schema["properties"]["start"]["type"], "number");
    assert_eq!(schema["properties"]["start"]["minimum"], 0);
    assert_eq!(schema["properties"]["start"]["multipleOf"], 0.001);
    assert_eq!(schema["properties"]["end"]["type"], "number");
    assert_eq!(schema["properties"]["end"]["exclusiveMinimum"], 0);
    assert_eq!(schema["properties"]["end"]["multipleOf"], 0.001);
    if name == "inspect_video" {
        let sampling = &schema["properties"]["sampling"];
        assert!(
            sampling.get("oneOf").is_none(),
            "inspect_video sampling must be exclusive anyOf closed objects"
        );
        let arms = sampling["anyOf"]
            .as_array()
            .expect("inspect_video sampling anyOf");
        assert_eq!(arms.len(), 2);
        let every = &arms[0];
        let max_frames = &arms[1];
        assert_eq!(every["type"], "object");
        assert_eq!(every["required"], json!(["every_seconds"]));
        assert_eq!(every["additionalProperties"], false);
        assert_eq!(every["properties"]["every_seconds"]["type"], "number");
        assert_eq!(every["properties"]["every_seconds"]["exclusiveMinimum"], 0);
        assert_eq!(max_frames["type"], "object");
        assert_eq!(max_frames["required"], json!(["max_frames"]));
        assert_eq!(max_frames["additionalProperties"], false);
        assert_eq!(max_frames["properties"]["max_frames"]["type"], "integer");
        assert_eq!(max_frames["properties"]["max_frames"]["minimum"], 1);
        assert_eq!(
            max_frames["properties"]["max_frames"]["maximum"],
            MAX_STORYBOARD_FRAMES
        );
    } else {
        assert!(
            schema
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|properties| !properties.contains_key("sampling")),
            "{name} must not advertise inspect_video sampling"
        );
    }
}

fn source_instance(branch: &str) -> Value {
    match branch {
        "attachment_id" => json!({"source": {"attachment_id": "att-1"}}),
        "path" => json!({"source": {"path": "/tmp/media.bin"}}),
        "url" => json!({"source": {"url": "https://example.com/media.bin"}}),
        other => panic!("unknown source branch {other}"),
    }
}

fn rejected_source_instances() -> Vec<Value> {
    let mut instances = malformed_nested_source_instances();
    instances.extend([
        json!({"source": {"attachment_id": "att-1"}, "path": "/tmp/a"}),
        json!({"source": {"attachment_id": "att-1"}, "url": "https://example.com/a"}),
    ]);
    instances
}

fn assert_source_denied_hides_kind(err: &anyhow::Error) {
    let text = err.to_string();
    let input = err.downcast_ref::<InvalidToolInput>();
    assert_eq!(
        input.map(|value| value.0.as_str()),
        Some("source_denied"),
        "wrong/revoked/denied sources must fail as existence-hiding source_denied, got {text}"
    );
    assert!(
        !text.contains(':'),
        "source_denied must not leak a denial-kind suffix: {text}"
    );
    for leaked in [
        "attachment not found",
        "local path denied",
        "canonical authorization",
        "SSRF",
        "DNS",
        "redirect policy",
        "subject mismatch",
        "replacement",
        "symlink",
        "reparse",
        "HttpsDenied",
        "AttachmentNotFound",
        "LocalPathDenied",
        "HandleReplacement",
    ] {
        assert!(
            !text
                .to_ascii_lowercase()
                .contains(&leaked.to_ascii_lowercase()),
            "existence-hiding leaked {leaked:?} in {text}"
        );
    }
}

fn malformed_nested_source_instances() -> Vec<Value> {
    vec![
        json!({}),
        json!({"source": {}}),
        json!({"source": {"attachment_id": "att-1", "path": "/tmp/a"}}),
        json!({"source": {"attachment_id": "att-1", "url": "https://example.com/a"}}),
        json!({"source": {"path": "/tmp/a", "url": "https://example.com/a"}}),
        json!({"source": {"attachment_id": "att-1", "path": "/tmp/a", "url": "https://example.com/a"}}),
        json!({"source": {"blob": "nope"}}),
        json!({"attachment_id": "att-1"}),
        json!({"path": "/tmp/a"}),
        json!({"url": "https://example.com/a"}),
        json!({"source": {"attachment_id": ""}}),
        json!({"source": {"url": "http://example.test/x"}}),
        json!({"source": {"attachment_id": "att-1"}, "path": "/tmp/a"}),
        json!({"source": {"attachment_id": "att-1"}, "url": "https://example.com/a"}),
        json!({"source": null}),
        json!({"source": true}),
        json!({"source": false}),
        json!({"source": 1}),
        json!({"source": 1.5}),
        json!({"source": "att-1"}),
        json!({"source": ["att-1"]}),
    ]
}

#[test]
fn audio_video_tool_schema_nested_source_is_closed_any_of() {
    for (name, canonical) in av_tool_schemas() {
        let label = format!("{name} canonical");
        assert_root_is_object_not_union(&canonical, &label);
        assert_no_forbidden_keywords(&canonical, &label);
        assert_objects_are_closed(&canonical, false, &label);
        assert_source_union(&canonical, &label);
        assert_stream_interval_sampling(name, &canonical);
        assert_eq!(canonical["required"], json!(["source"]));
        for key in SOURCE_BRANCHES {
            assert!(
                canonical["properties"].get(*key).is_none(),
                "{name} must not keep legacy flat `{key}`"
            );
        }

        for branch in SOURCE_BRANCHES {
            assert_valid(&canonical, &source_instance(branch));
        }
        assert_valid(
            &canonical,
            &json!({
                "source": {"attachment_id": "att-1"},
                "stream_index": 0,
                "start": 0.0,
                "end": 1.5
            }),
        );
        if name == "inspect_video" {
            assert_valid(
                &canonical,
                &json!({
                    "source": {"attachment_id": "att-1"},
                    "sampling": {"every_seconds": 0.5}
                }),
            );
            assert_valid(
                &canonical,
                &json!({
                    "source": {"path": "/tmp/clip.mp4"},
                    "sampling": {"max_frames": 8}
                }),
            );
            assert_invalid(
                &canonical,
                &json!({
                    "source": {"attachment_id": "att-1"},
                    "sampling": {"every_seconds": 0.5, "max_frames": 8}
                }),
            );
            assert_invalid(
                &canonical,
                &json!({
                    "source": {"attachment_id": "att-1"},
                    "sampling": {}
                }),
            );
        }

        let responses = for_responses(&canonical);
        let responses_label = format!("{name} responses");
        assert_root_is_object_not_union(&responses, &responses_label);
        assert_no_forbidden_keywords(&responses, &responses_label);
        assert_objects_are_closed(&responses, false, &responses_label);
        assert_source_union(&responses, &responses_label);
        assert_optional_properties_nullable(&canonical, &responses, &responses_label);
        assert!(
            !has_null_type(&responses["properties"]["source"]),
            "{name} required source must not gain a null arm"
        );

        let strict =
            rig::providers::openai::responses_api::ResponsesToolDefinition::strict_function(
                name,
                name,
                responses.clone(),
            );
        let strict_label = format!("{name} strict");
        assert_root_is_object_not_union(&strict.parameters, &strict_label);
        assert_no_forbidden_keywords(&strict.parameters, &strict_label);
        assert_objects_are_closed(&strict.parameters, true, &strict_label);
        assert_source_union(&strict.parameters, &strict_label);
        assert_optional_properties_nullable(&canonical, &strict.parameters, &strict_label);

        for instance in rejected_source_instances() {
            assert_invalid(&canonical, &instance);
            assert_invalid(&responses, &instance);
        }

        for branch in SOURCE_BRANCHES {
            let instance = source_instance(branch);
            assert_valid(&responses, &instance);
            let mut strict_instance = instance;
            if let Some(object) = strict_instance.as_object_mut() {
                for key in strict.parameters["properties"]
                    .as_object()
                    .expect("strict properties")
                    .keys()
                {
                    object.entry(key.clone()).or_insert(Value::Null);
                }
            }
            assert_valid(&strict.parameters, &strict_instance);
        }
    }
}

#[test]
fn audio_video_tool_schema_walker_rejects_forbidden_keywords_in_nested_schema_locations() {
    let buried = [
        (
            "prefixItems",
            json!({"type": "array", "prefixItems": [{"allOf": [{"type": "string"}]}]}),
        ),
        (
            "contains",
            json!({"type": "array", "contains": {"allOf": [{"type": "string"}]}}),
        ),
        (
            "propertyNames",
            json!({"type": "object", "propertyNames": {"allOf": [{"type": "string"}]}}),
        ),
        (
            "additionalProperties",
            json!({"type": "object", "additionalProperties": {"not": {"type": "string"}}}),
        ),
        (
            "patternProperties",
            json!({"type": "object", "patternProperties": {"^x": {"if": {"type": "string"}}}}),
        ),
        (
            "unevaluatedItems",
            json!({"type": "array", "unevaluatedItems": {"dependentSchemas": {"a": {}}}}),
        ),
        (
            "oneOf",
            json!({"type": "array", "prefixItems": [{"oneOf": [{"type": "string"}]}]}),
        ),
        (
            "dependencies",
            json!({"dependencies": {"x": {"allOf": [{"type": "string"}]}, "y": ["a"]}}),
        ),
    ];
    for (location, schema) in buried {
        let hits = forbidden_keyword_hits(&schema);
        assert!(
            !hits.is_empty(),
            "walker must reject a forbidden keyword buried under {location}: {hits:?}"
        );
    }
    let one_of_hits = forbidden_keyword_hits(&json!({
        "type": "array",
        "prefixItems": [{"oneOf": [{"type": "string"}]}]
    }));
    assert!(
        one_of_hits.contains(&"oneOf"),
        "walker must see oneOf: {one_of_hits:?}"
    );
    let dependencies = json!({"dependencies": {"x": {"allOf": [{"type": "string"}]}, "y": ["a"]}});
    assert!(
        forbidden_keyword_hits(&dependencies).contains(&"allOf"),
        "walker must see allOf under dependencies"
    );
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_no_forbidden_keywords(&dependencies, "dependencies fixture");
    }));
    assert!(
        panicked.is_err(),
        "assert_no_forbidden_keywords must reject dependencies.allOf"
    );
}

fn well_formed_sampling() -> Value {
    json!({"source": {"attachment_id": "a"}, "sampling": {"max_frames": 1}})
}

#[test]
fn audio_video_tool_schema_rejects_malformed_nested_source_before_authority_bail() {
    for kind in tool_kinds() {
        for instance in malformed_nested_source_instances() {
            let err = validate_tool_args(&instance, kind).expect_err("malformed source");
            assert!(
                err.downcast_ref::<crate::engine::tool::InvalidToolInput>()
                    .is_some(),
                "malformed {instance} for {kind:?} must be invalid input, not an environmental failure: {err}"
            );
            let message = err.to_string();
            assert!(
                !message.contains("media_attachment_authority_unavailable"),
                "malformed {instance} for {kind:?} must not reach the authority bail: {message}"
            );
            assert!(
                !message.contains("exactly one of attachment_id, path, or url is required"),
                "must not treat retired flat root keys as valid: {message}"
            );
        }
        for branch in SOURCE_BRANCHES {
            validate_tool_args(&source_instance(branch), kind).expect("well-formed nested source");
        }
        let sampling = well_formed_sampling();
        if kind == ToolKind::InspectVideo {
            validate_tool_args(&sampling, kind).expect("inspect_video sampling");
        } else {
            let err = validate_tool_args(&sampling, kind).expect_err("sampling rejected");
            assert!(
                err.downcast_ref::<crate::engine::tool::InvalidToolInput>()
                    .is_some(),
                "{kind:?} must reject sampling as invalid input: {err}"
            );
            assert!(
                !err.to_string()
                    .contains("media_attachment_authority_unavailable"),
                "{kind:?} sampling must not reach the authority bail: {err}"
            );
        }
    }
}

async fn call_without_authority(args: Value, kind: ToolKind) -> anyhow::Error {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    let err = match kind {
        ToolKind::InspectAudio => InspectAudioTool::new().call(args, &ctx).await,
        ToolKind::InspectVideo => InspectVideoTool::new().call(args, &ctx).await,
        ToolKind::ExtractVideoClip => ExtractVideoClipTool::new().call(args, &ctx).await,
        ToolKind::ExtractAudio => ExtractAudioTool::new().call(args, &ctx).await,
    }
    .expect_err("expected a closed call");
    err
}

#[tokio::test]
async fn audio_video_tool_schema_fail_closed_validates_nested_source() {
    for kind in tool_kinds() {
        for instance in [
            json!({"source": {}}),
            json!({"source": {"url": "http://example.test/x"}}),
            json!({"source": {"attachment_id": "att-1"}, "path": "/tmp/a"}),
        ] {
            let malformed = call_without_authority(instance.clone(), kind).await;
            assert!(
                malformed
                    .downcast_ref::<crate::engine::tool::InvalidToolInput>()
                    .is_some(),
                "{instance} for {kind:?} must stay an invocation failure: {malformed}"
            );
            assert!(
                !malformed
                    .to_string()
                    .contains("media_attachment_authority_unavailable"),
                "{instance} for {kind:?} must not reach the authority bail: {malformed}"
            );
        }
        let well_formed =
            call_without_authority(json!({"source": {"attachment_id": "att-1"}}), kind).await;
        assert!(
            well_formed
                .downcast_ref::<crate::engine::tool::InvalidToolInput>()
                .is_none(),
            "well-formed source for {kind:?} must reach the authority bail"
        );
        assert!(
            well_formed
                .to_string()
                .contains("media_attachment_authority_unavailable"),
            "{well_formed}"
        );

        let sampling = call_without_authority(well_formed_sampling(), kind).await;
        if kind == ToolKind::InspectVideo {
            assert!(
                sampling
                    .downcast_ref::<crate::engine::tool::InvalidToolInput>()
                    .is_none(),
                "inspect_video sampling must reach the authority bail"
            );
            assert!(
                sampling
                    .to_string()
                    .contains("media_attachment_authority_unavailable"),
                "{sampling}"
            );
        } else {
            assert!(
                sampling
                    .downcast_ref::<crate::engine::tool::InvalidToolInput>()
                    .is_some(),
                "{kind:?} must reject sampling as invalid input: {sampling}"
            );
            assert!(
                !sampling
                    .to_string()
                    .contains("media_attachment_authority_unavailable"),
                "{kind:?} sampling must not reach the authority bail: {sampling}"
            );
        }
    }
}

fn container_allows(container: &str, codec: &str, kind: AvKind) -> bool {
    match kind {
        AvKind::Audio => container_allows_audio_codec(container, codec),
        AvKind::Video => container_allows_video_codec(container, codec),
    }
}

fn disallowed_codec(container: &str, kind: AvKind) -> &'static str {
    let table = match kind {
        AvKind::Audio => TYPED_AUDIO_CONTAINER_CODECS,
        AvKind::Video => TYPED_VIDEO_CONTAINER_CODECS,
    };
    table
        .iter()
        .flat_map(|(_, codecs)| codecs.iter().copied())
        .find(|codec| !container_allows(container, codec, kind))
        .expect("every typed container has at least one disallowed matrix codec")
}

fn candidate(
    container: &str,
    codec: &str,
    kind: AvKind,
    index: u32,
    disposition_default: bool,
) -> StreamCandidate {
    StreamCandidate {
        index,
        disposition_default,
        allowed: container_allows(container, codec, kind),
    }
}

fn audio_video_stream_matrix_pairs() -> Vec<(&'static str, &'static str, AvKind)> {
    let mut pairs = Vec::new();
    for (container, codecs) in TYPED_AUDIO_CONTAINER_CODECS {
        for codec in *codecs {
            pairs.push((*container, *codec, AvKind::Audio));
        }
    }
    for (container, codecs) in TYPED_VIDEO_CONTAINER_CODECS {
        for codec in *codecs {
            pairs.push((*container, *codec, AvKind::Video));
        }
    }
    pairs
}

#[test]
fn audio_video_stream_matrix_covers_every_typed_container_codec_pair() {
    let pairs = audio_video_stream_matrix_pairs();
    assert_eq!(
        pairs.len(),
        TYPED_AUDIO_CONTAINER_CODECS
            .iter()
            .map(|(_, codecs)| codecs.len())
            .sum::<usize>()
            + TYPED_VIDEO_CONTAINER_CODECS
                .iter()
                .map(|(_, codecs)| codecs.len())
                .sum::<usize>()
    );
    for (container, codec, kind) in pairs {
        let banned = disallowed_codec(container, kind);
        assert!(
            container_allows(container, codec, kind),
            "{container}/{codec} must be allowed"
        );
        assert!(
            !container_allows(container, banned, kind),
            "{container}/{banned} must be disallowed"
        );

        let allowed_explicit = candidate(container, codec, kind, 2, false);
        let disallowed_default = candidate(container, banned, kind, 1, true);
        let allowed_default_high = candidate(container, codec, kind, 5, true);
        let allowed_default_low = candidate(container, codec, kind, 4, true);
        let allowed_lowest = candidate(container, codec, kind, 0, false);

        let streams = vec![
            allowed_explicit.clone(),
            disallowed_default.clone(),
            allowed_default_high.clone(),
            allowed_default_low.clone(),
            allowed_lowest.clone(),
        ];
        assert_eq!(
            select_stream(&streams, Some(2)).unwrap(),
            2,
            "{container}/{codec} explicit allowed index"
        );
        assert!(
            select_stream(&streams, Some(1)).is_err(),
            "{container}/{codec} explicit disallowed index"
        );
        assert_eq!(
            select_stream(&streams, None).unwrap(),
            4,
            "{container}/{codec} lowest default allowed"
        );

        let no_default = vec![
            allowed_explicit.clone(),
            disallowed_default.clone(),
            allowed_lowest.clone(),
        ];
        assert_eq!(
            select_stream(&no_default, None).unwrap(),
            0,
            "{container}/{codec} lowest allowed when no default"
        );

        let none_allowed = vec![
            disallowed_default,
            candidate(container, banned, kind, 7, false),
        ];
        assert!(
            select_stream(&none_allowed, None).is_err(),
            "{container}/{codec} no-allowed-stream"
        );
        assert!(
            select_stream(&none_allowed, Some(1)).is_err(),
            "{container}/{codec} explicit index among no-allowed-stream"
        );
    }
}

fn expected_every_seconds(start_ms: u64, end_ms: u64, period_ms: u64) -> Vec<Milliseconds> {
    let mut output = Vec::new();
    let mut timestamp = start_ms;
    while timestamp < end_ms {
        output.push(Milliseconds(timestamp));
        timestamp += period_ms;
    }
    output
}

fn expected_max_frames(start_ms: u64, end_ms: u64, n: u32) -> Vec<Milliseconds> {
    if n == 1 {
        return vec![Milliseconds(start_ms)];
    }
    (0..n)
        .map(|k| Milliseconds(start_ms + u64::from(k) * (end_ms - start_ms - 1) / u64::from(n - 1)))
        .collect()
}

#[test]
fn audio_video_storyboard_timestamps_are_exact_and_end_exclusive() {
    let interval = Interval::checked(Milliseconds(1_000), Milliseconds(2_001)).unwrap();
    assert_eq!(
        storyboard_timestamps(&interval, StoryboardMode::Every(Milliseconds(500))).unwrap(),
        expected_every_seconds(1_000, 2_001, 500)
    );
    assert_eq!(
        storyboard_timestamps(&interval, StoryboardMode::MaxFrames(3)).unwrap(),
        expected_max_frames(1_000, 2_001, 3)
    );

    let ends_on_period = Interval::checked(Milliseconds(1_000), Milliseconds(2_000)).unwrap();
    assert_eq!(
        storyboard_timestamps(&ends_on_period, StoryboardMode::Every(Milliseconds(500))).unwrap(),
        vec![Milliseconds(1_000), Milliseconds(1_500)]
    );
    assert!(
        !storyboard_timestamps(&ends_on_period, StoryboardMode::Every(Milliseconds(500)))
            .unwrap()
            .iter()
            .any(|timestamp| timestamp.0 >= 2_000),
        "every_seconds must be end-exclusive"
    );

    let unit = Interval::checked(Milliseconds(40), Milliseconds(41)).unwrap();
    assert_eq!(
        storyboard_timestamps(&unit, StoryboardMode::MaxFrames(1)).unwrap(),
        vec![Milliseconds(40)]
    );
    assert_eq!(
        storyboard_timestamps(&unit, StoryboardMode::MaxFrames(4)).unwrap(),
        expected_max_frames(40, 41, 4)
    );
}

#[test]
fn audio_video_storyboard_timestamps_select_vfr_pts_and_dynamic_tolerance() {
    assert_eq!(frame_tolerance_ms(None), 100);
    assert_eq!(frame_tolerance_ms(Some(2)), 100);
    assert_eq!(frame_tolerance_ms(Some(240)), 120);
    assert_eq!(frame_tolerance_ms(Some(2_000)), 500);

    let requested = [
        Milliseconds(0),
        Milliseconds(100),
        Milliseconds(250),
        Milliseconds(700),
    ];
    let actual = [
        Milliseconds(0),
        Milliseconds(40),
        Milliseconds(90),
        Milliseconds(200),
        Milliseconds(400),
        Milliseconds(900),
    ];
    let selected = select_storyboard_frames(&requested, &actual, Some(80));
    assert_eq!(
        selected.frames,
        vec![
            StoryboardFrame {
                requested_ms: 0,
                actual_pts_ms: 0
            },
            StoryboardFrame {
                requested_ms: 100,
                actual_pts_ms: 200
            },
        ]
    );
    assert_eq!(selected.sample_unavailable_ms, vec![250, 700]);
    assert!(selected.omitted_duplicates.is_empty());

    let at_boundary = select_storyboard_frames(&[Milliseconds(0)], &[Milliseconds(100)], None);
    assert_eq!(
        at_boundary.frames,
        vec![StoryboardFrame {
            requested_ms: 0,
            actual_pts_ms: 100
        }]
    );
    let outside = select_storyboard_frames(&[Milliseconds(0)], &[Milliseconds(101)], None);
    assert!(outside.frames.is_empty());
    assert_eq!(outside.sample_unavailable_ms, vec![0]);
    assert!(
        outside.omitted_duplicates.is_empty(),
        "out-of-tolerance samples must stay sample_unavailable, never relabeled"
    );
}

#[test]
fn audio_video_storyboard_timestamps_deduplicate_and_preserve_request_order() {
    let selected = select_storyboard_frames(
        &[Milliseconds(0), Milliseconds(5), Milliseconds(400)],
        &[Milliseconds(90), Milliseconds(550)],
        Some(240),
    );
    assert_eq!(
        selected.frames,
        vec![StoryboardFrame {
            requested_ms: 0,
            actual_pts_ms: 90
        }]
    );
    assert_eq!(
        selected.omitted_duplicates,
        vec![StoryboardFrame {
            requested_ms: 5,
            actual_pts_ms: 90
        }]
    );
    assert_eq!(selected.sample_unavailable_ms, vec![400]);

    let ordered = select_storyboard_frames(
        &[Milliseconds(10), Milliseconds(80), Milliseconds(200)],
        &[Milliseconds(12), Milliseconds(90), Milliseconds(205)],
        Some(200),
    );
    assert_eq!(
        ordered
            .frames
            .iter()
            .map(|frame| frame.requested_ms)
            .collect::<Vec<_>>(),
        vec![10, 80, 200]
    );
}

#[test]
fn audio_video_storyboard_timestamps_report_source_rotation_sar_dar() {
    let selected = select_storyboard_frames(
        &[Milliseconds(0), Milliseconds(1_000)],
        &[Milliseconds(0), Milliseconds(1_000)],
        Some(200),
    );
    let source = StoryboardSourceGeometry {
        rotation_degrees: 90,
        sar_num: 4,
        sar_den: 3,
        dar_num: 16,
        dar_den: 9,
    };
    let reported = report_storyboard_frames(&selected.frames, &source);
    assert_eq!(
        reported
            .iter()
            .map(|frame| frame.requested_ms)
            .collect::<Vec<_>>(),
        vec![0, 1_000]
    );
    assert_eq!(
        reported
            .iter()
            .map(|frame| frame.actual_pts_ms)
            .collect::<Vec<_>>(),
        vec![0, 1_000]
    );
    for frame in &reported {
        assert_eq!(frame.rotation_degrees, 90);
        assert_eq!(frame.sar_num, 4);
        assert_eq!(frame.sar_den, 3);
        assert_eq!(frame.dar_num, 16);
        assert_eq!(frame.dar_den, 9);
    }
}

fn assert_nested_source_description(text: &str, label: &str) {
    assert!(
        text.contains("source: {attachment_id|path|url}"),
        "{label} must document nested first-source branches: {text}"
    );
    assert!(
        text.contains("source: {attachment_id}"),
        "{label} must document later nested attachment-ID reuse: {text}"
    );
    let lower = text.to_ascii_lowercase();
    assert!(
        !lower.contains("only an attachment id")
            && !lower.contains("only attachment_id")
            && !lower.contains("attachment_id only"),
        "{label} must not say that only an attachment ID is accepted: {text}"
    );
    let remainder = text
        .replace("source: {attachment_id|path|url}", "")
        .replace("source: {attachment_id}", "");
    for banned in [
        "exactly one of attachment_id, path, or url",
        "attachment_id, path, or url",
        "pass attachment_id",
        "flat source",
        "`attachment_id`",
        "`path`",
        "`url`",
    ] {
        assert!(
            !remainder.contains(banned),
            "{label} must not treat flat source keys as valid ({banned}): {text}"
        );
    }
}

#[test]
fn audio_video_descriptions_document_nested_source_branches() {
    for tool in av_tools() {
        assert!(
            tool.honors_dispatch_cancel(),
            "{} must retain process/artifact cleanup after dispatcher cancellation",
            tool.name()
        );
        assert_nested_source_description(
            tool.description(),
            &format!("{} description", tool.name()),
        );
        let defensive = tool
            .verbose_description()
            .unwrap_or_else(|| panic!("{} must supply a defensive description", tool.name()));
        assert_nested_source_description(
            &defensive,
            &format!("{} verbose_description", tool.name()),
        );
    }
}

#[test]
fn audio_video_process_specs_are_argv_only_and_capped() {
    let spec = probe_process("name; touch nope");
    assert_eq!(spec.program, std::path::PathBuf::from("ffprobe"));
    assert_eq!(spec.argv.last().unwrap(), "name; touch nope");
    assert!(spec.stdin_closed);
    assert_eq!(spec.environment.len(), 2);
    assert!(spec.stdout_limit > spec.stderr_limit);
}

#[test]
fn audio_video_ffprobe_times_accept_bounded_submillisecond_precision() {
    assert_eq!(
        Milliseconds::from_decimal_seconds("1.234").unwrap(),
        Milliseconds(1_234)
    );
    assert!(Milliseconds::from_decimal_seconds("1.234000").is_err());
    assert_eq!(
        Milliseconds::from_ffprobe_decimal_seconds("1.234000").unwrap(),
        Milliseconds(1_234)
    );
    assert_eq!(
        Milliseconds::from_ffprobe_decimal_seconds("1.234500").unwrap(),
        Milliseconds(1_235)
    );
    assert_eq!(
        Milliseconds::from_ffprobe_decimal_seconds("0.040000").unwrap(),
        Milliseconds(40)
    );
    assert!(Milliseconds::from_ffprobe_decimal_seconds("1.1234567890").is_err());
    assert!(Milliseconds::from_ffprobe_decimal_seconds("NaN").is_err());
    assert!(Milliseconds::from_ffprobe_decimal_seconds("-0.001000").is_err());
}

fn argv_has_lone_double_dash(spec: &ProcessSpec) -> bool {
    spec.argv.iter().any(|arg| arg == "--")
}

#[tokio::test]
async fn audio_video_argv_snapshots() {
    let interval = Interval::checked(Milliseconds(1_500), Milliseconds(2_250)).unwrap();
    let probe = probe_process("/held/source.wav");
    let frames = probe_frames_process("/held/source.wav", 1_500);
    let clip = clip_process("/held/video.mp4", &interval, 0, Some((2, 22_050, 1)), 15, 1);
    let audio = audio_process("/held/audio.wav", &interval, 0, 22_050, 1);
    let video_only = clip_process("/held/video-only.mp4", &interval, 0, None, 15, 1);
    for spec in [&probe, &frames, &clip, &video_only, &audio] {
        assert!(
            !argv_has_lone_double_dash(spec),
            "{} argv must not contain a lone --: {:?}",
            spec.program.display(),
            spec.argv
        );
        assert!(spec.stdin_closed);
        assert_eq!(
            spec.environment,
            vec![("LC_ALL", "C".into()), ("LANG", "C".into())]
        );
    }
    assert!(
        !probe.argv.iter().any(|arg| arg == "-show_frames"),
        "metadata probe must not dump unbounded frames: {:?}",
        probe.argv
    );
    assert!(
        frames
            .argv
            .windows(2)
            .any(|pair| pair[0] == "-read_intervals" && pair[1].contains("%+#")),
        "frame probe must cap packets: {:?}",
        frames.argv
    );
    assert!(
        frames
            .argv
            .windows(2)
            .any(|pair| { pair[0] == "-show_entries" && pair[1].contains("pts_time") }),
        "frame probe must request compact frame entries: {:?}",
        frames.argv
    );
    assert!(
        clip.argv.windows(2).any(|pair| pair[0] == "-b:v")
            && clip.argv.windows(2).any(|pair| pair[0] == "-maxrate"),
        "clip must bitrate-cap H.264 so a legal WAV duration cannot exceed 4 MiB: {:?}",
        clip.argv
    );
    assert!(
        clip.argv
            .windows(2)
            .any(|pair| pair[0] == "-fs" && pair[1] == MAX_PROCESS_STDOUT_BYTES.to_string()),
        "clip must stop the muxer at the 4 MiB ceiling: {:?}",
        clip.argv
    );
    assert_eq!(clip.argv.last().map(String::as_str), Some("pipe:1"));
    assert_eq!(audio.argv.last().map(String::as_str), Some("pipe:1"));
    assert!(
        clip.argv
            .windows(2)
            .any(|args| args[0] == "-f" && args[1] == "mp4")
    );
    assert!(
        audio
            .argv
            .windows(2)
            .any(|args| args[0] == "-f" && args[1] == "wav")
    );
    assert_eq!(
        clip.argv
            .iter()
            .position(|arg| arg == "-ss")
            .and_then(|i| clip.argv.get(i + 1))
            .map(String::as_str),
        Some("1.500")
    );
    assert_eq!(
        clip.argv
            .iter()
            .position(|arg| arg == "-t")
            .and_then(|i| clip.argv.get(i + 1))
            .map(String::as_str),
        Some("0.750")
    );
    assert_eq!(
        audio
            .argv
            .iter()
            .position(|arg| arg == "-ss")
            .and_then(|i| audio.argv.get(i + 1))
            .map(String::as_str),
        Some("1.500")
    );
    let clip_ar = clip
        .argv
        .iter()
        .position(|arg| arg == "-ar")
        .and_then(|i| clip.argv.get(i + 1))
        .unwrap();
    let clip_ac = clip
        .argv
        .iter()
        .position(|arg| arg == "-ac")
        .and_then(|i| clip.argv.get(i + 1))
        .unwrap();
    assert_eq!(
        clip_ar, "22050",
        "clip must cap from source, never upsample to 48000"
    );
    assert_eq!(clip_ac, "1", "clip must not force 2ch when source is mono");
    let audio_ar = audio
        .argv
        .iter()
        .position(|arg| arg == "-ar")
        .and_then(|i| audio.argv.get(i + 1))
        .unwrap();
    assert_eq!(audio_ar, "22050");
    let vf = clip
        .argv
        .iter()
        .position(|arg| arg == "-vf")
        .and_then(|i| clip.argv.get(i + 1))
        .unwrap();
    assert!(
        vf.contains("fps=15/1"),
        "exact reduced fps rational, not a string expression: {vf}"
    );
    assert!(!vf.contains("source_fps"));
    assert_eq!(format_ffmpeg_seconds(1_500), "1.500");
    assert!(
        clip.argv.windows(2).any(|pair| pair == ["-map", "0:2?"]),
        "clip maps exactly the audio stream whose caps were derived"
    );
    assert!(!clip.argv.iter().any(|arg| arg == "0:a?"));
    assert!(video_only.argv.iter().any(|arg| arg == "-an"));
    assert!(!video_only.argv.iter().any(|arg| arg == "-ar"));
    assert!(!video_only.argv.iter().any(|arg| arg.ends_with('?')));

    let ntsc_probe = parse_probe_document(
        br#"{
          "format":{"duration":"1.000"},
          "streams":[{"index":1,"codec_type":"video","width":1280,"height":720,"time_base":"1/24000"}],
          "frames":[
            {"media_type":"video","stream_index":1,"best_effort_timestamp":"-1001","pts_time":"0.000"},
            {"media_type":"video","stream_index":1,"best_effort_timestamp":"0","pts_time":"0.041708"},
            {"media_type":"video","stream_index":1,"best_effort_timestamp":"1001","pts_time":"0.083417"}
          ]
        }"#,
    )
    .unwrap();
    assert_eq!(
        reduced_fps_from_probe(&ntsc_probe, 1).unwrap(),
        (24_000, 1_001),
        "FPS must retain exact ffprobe ticks/time_base, including negative leading PTS"
    );

    // Required suite crosses Tool::call and asserts the argv that reached the
    // injected runner, not only the free builders above.
    let (_tmp, ctx, _, _, _, _) = authorized_ctx();
    let runner =
        Arc::new(FakeAvArgvRunner::new().with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes().to_vec()));
    ExtractVideoClipTool::with_runner(runner.clone())
        .call(
            json!({
                "source": {"attachment_id": "att-1"},
                "start": 0.0,
                "end": 1.0
            }),
            &ctx,
        )
        .await
        .unwrap();
    let calls = runner.calls();
    let probes: Vec<_> = calls
        .iter()
        .filter(|call| call.program.ends_with("ffprobe"))
        .collect();
    assert!(
        probes
            .first()
            .is_some_and(|call| !call.argv.iter().any(|arg| arg == "-show_frames")),
        "first probe must be metadata-only: {:?}",
        probes.first().map(|call| &call.argv)
    );
    assert!(
        probes.iter().any(|call| {
            call.argv.iter().any(|arg| arg == "-show_frames")
                && call
                    .argv
                    .windows(2)
                    .any(|pair| pair[0] == "-read_intervals")
        }),
        "clip must follow metadata with a packet-capped frame probe: {probes:?}"
    );
    let executed = calls
        .iter()
        .find(|call| call.program.ends_with("ffmpeg"))
        .expect("clip Tool::call must reach the injected ffmpeg boundary");
    assert!(!executed.argv.iter().any(|arg| arg == "--"));
    assert!(
        executed
            .argv
            .windows(2)
            .any(|pair| pair == ["-ss", "0.000"])
    );
    assert!(executed.argv.windows(2).any(|pair| pair == ["-t", "1.000"]));

    let mut multi_audio: Value = serde_json::from_str(DEFAULT_FFPROBE_JSON).unwrap();
    multi_audio["streams"][0]["disposition"]["default"] = json!(0);
    multi_audio["streams"].as_array_mut().unwrap().push(json!({
        "index": 2,
        "codec_type": "audio",
        "codec_name": "aac",
        "sample_rate": "8000",
        "channels": 1,
        "disposition": {"default": 1}
    }));
    let multi_runner = Arc::new(
        FakeAvArgvRunner::new().with_probe_json(serde_json::to_vec(&multi_audio).unwrap()),
    );
    ExtractVideoClipTool::with_runner(multi_runner.clone())
        .call(
            json!({
                "source": {"attachment_id": "att-1"},
                "start": 0.0,
                "end": 1.0
            }),
            &ctx,
        )
        .await
        .unwrap();
    let multi_call = multi_runner
        .calls()
        .into_iter()
        .find(|call| call.program.ends_with("ffmpeg"))
        .expect("multi-audio clip reaches ffmpeg");
    assert!(
        multi_call
            .argv
            .windows(2)
            .any(|pair| pair == ["-map", "0:2?"])
    );
    assert!(!multi_call.argv.iter().any(|arg| arg == "0:a?"));
    assert!(
        multi_call
            .argv
            .windows(2)
            .any(|pair| pair == ["-ar", "8000"])
    );
    assert!(multi_call.argv.windows(2).any(|pair| pair == ["-ac", "1"]));
}

struct FixtureAttachments {
    by_id: std::collections::HashMap<[u8; 16], AdmittedAttachment>,
    aliases: std::collections::HashMap<String, [u8; 16]>,
    revoked: std::sync::atomic::AtomicBool,
}

/// Canonical UUID whose resolve arm reports a body larger than
/// [`MAX_AV_SOURCE_BYTES`] without allocating that body in every fixture.
const OVERSIZED_AV_ATTACHMENT_ID: [u8; 16] = [0x77; 16];

impl AttachmentResolver for FixtureAttachments {
    fn resolve(
        &self,
        _session_id: &str,
        attachment_id: &[u8; 16],
        max_bytes: usize,
    ) -> Result<Option<AdmittedAttachment>, AdmissionDenial> {
        if self.revoked.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(None);
        }
        if *attachment_id == OVERSIZED_AV_ATTACHMENT_ID {
            return Ok(if MAX_AV_SOURCE_BYTES.saturating_add(1) <= max_bytes {
                Some(AdmittedAttachment {
                    attachment_id: OVERSIZED_AV_ATTACHMENT_ID,
                    attachment_version: 1,
                    checksum: [0x00; 32],
                    kind: 2,
                    content: vec![0u8; MAX_AV_SOURCE_BYTES + 1],
                })
            } else {
                None
            });
        }
        Ok(self
            .by_id
            .get(attachment_id)
            .filter(|attachment| {
                attachment.content.is_empty() || attachment.content.len() <= max_bytes
            })
            .cloned())
    }

    fn resolve_alias(
        &self,
        _session_id: &str,
        alias: &str,
    ) -> Result<Option<AdmittedAttachment>, AdmissionDenial> {
        if self.revoked.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(None);
        }
        Ok(self
            .aliases
            .get(alias)
            .and_then(|id| self.by_id.get(id))
            .cloned())
    }

    fn open(
        &self,
        _session_id: &str,
        attachment: &AdmittedAttachment,
        max_bytes: usize,
    ) -> Result<Option<crate::tool_media_authority::AdmittedHandle>, AdmissionDenial> {
        if self.revoked.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(None);
        }
        if attachment.content.len() > max_bytes {
            return Ok(None);
        }
        Ok(Some(
            crate::tool_media_authority::AdmittedHandle::RetainedHttps(AdmittedRetainedSource {
                canonical_url: SessionMediaAuthority::attachment_id_hex(&attachment.attachment_id),
                content: b"fake-av-bytes".to_vec(),
                content_type: "application/octet-stream".to_string(),
            }),
        ))
    }
}

struct FixturePaths {
    swapped: Arc<std::sync::Mutex<Option<String>>>,
    held: Arc<std::sync::Mutex<Option<std::fs::File>>>,
}

impl LocalPathPolicy for FixturePaths {
    fn authorize(
        &self,
        _session_id: &str,
        path: &str,
    ) -> Result<(std::fs::File, HandleEvidence), AdmissionDenial> {
        if path.contains("denied") {
            return Err(AdmissionDenial::LocalPathDenied);
        }
        use std::io::{Seek as _, SeekFrom, Write as _};

        let held = self
            .swapped
            .lock()
            .expect("swap lock")
            .clone()
            .unwrap_or_else(|| path.to_string());
        let mut file =
            tempfile::tempfile().map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
        file.write_all(held.as_bytes())
            .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
        *self.held.lock().expect("held file lock") = Some(
            file.try_clone()
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?,
        );
        Ok((
            file,
            HandleEvidence {
                metadata_fingerprint: [0xAA; 32],
            },
        ))
    }

    fn admit(
        &self,
        session_id: &str,
        path: &str,
        _max_bytes: usize,
    ) -> Result<crate::tool_media_authority::session_authority::AdmittedLocalHandle, AdmissionDenial>
    {
        let (file, evidence) = self.authorize(session_id, path)?;
        Ok(
            crate::tool_media_authority::session_authority::AdmittedLocalHandle::from_held_file(
                std::path::PathBuf::from(path),
                file,
                evidence,
            ),
        )
    }
}

struct FixtureLiveness(crate::tool_media_authority::revalidator::RevalidatedSubject);

impl SubjectLiveness for FixtureLiveness {
    fn revalidate(
        &self,
    ) -> Result<crate::tool_media_authority::revalidator::RevalidatedSubject, AdmissionDenial> {
        Ok(self.0.clone())
    }
}

struct FixtureHttps;

impl RetainedHttpsPolicy for FixtureHttps {
    fn admit(
        &self,
        _session_id: &str,
        url: &str,
        max_bytes: usize,
    ) -> Result<AdmittedRetainedSource, AdmissionDenial> {
        if url.contains("denied") {
            return Err(AdmissionDenial::HttpsDenied);
        }
        let simulated_len = if url.contains("oversize") {
            MAX_AV_SOURCE_BYTES + 1
        } else {
            b"fake-av-bytes".len()
        };
        if simulated_len > max_bytes {
            return Err(AdmissionDenial::HttpsDenied);
        }
        Ok(AdmittedRetainedSource {
            canonical_url: url.to_string(),
            content: if url.contains("oversize") {
                vec![0u8; simulated_len]
            } else {
                b"fake-av-bytes".to_vec()
            },
            content_type: "audio/mpeg".to_string(),
        })
    }
}

fn fixture_authority(
    session_id: [u8; 16],
) -> (
    SessionMediaAuthority,
    Arc<FixtureAttachments>,
    Arc<std::sync::Mutex<Option<String>>>,
    Arc<std::sync::Mutex<Option<std::fs::File>>>,
) {
    fixture_authority_with_backend(session_id, None)
}

fn fixture_authority_with_backend(
    session_id: [u8; 16],
    media_backend: Option<(
        Arc<crate::media_storage::MediaStorageRecovery>,
        crate::media_reservation::MediaReservationLedger,
    )>,
) -> (
    SessionMediaAuthority,
    Arc<FixtureAttachments>,
    Arc<std::sync::Mutex<Option<String>>>,
    Arc<std::sync::Mutex<Option<std::fs::File>>>,
) {
    use crate::tool_media_authority::receipt::{IssuerKind, ToolMediaSubjectReceiptV1};
    use crate::tool_media_authority::revalidator::RevalidatedSubject;
    let subject = RevalidatedSubject {
        receipt: ToolMediaSubjectReceiptV1 {
            issuer_kind: IssuerKind::LocalOwner,
            principal_digest: [0x11; 32],
            project_digest: [0x22; 32],
            session_id,
            authorization_epoch: 0,
            subject_digest: [0x33; 32],
        },
        issuer_kind: IssuerKind::LocalOwner,
        principal_digest: [0x11; 32],
        project_digest: [0x22; 32],
        session_id,
        authorization_epoch: 0,
    };
    let att = AdmittedAttachment {
        attachment_id: [0x44; 16],
        attachment_version: 1,
        checksum: [0x55; 32],
        kind: 2,
        content: Vec::new(),
    };
    let mut aliases = std::collections::HashMap::new();
    aliases.insert("att-1".to_string(), [0x44; 16]);
    let mut by_id = std::collections::HashMap::new();
    by_id.insert([0x44; 16], att);
    let attachments = Arc::new(FixtureAttachments {
        by_id,
        aliases,
        revoked: std::sync::atomic::AtomicBool::new(false),
    });
    let swapped = Arc::new(std::sync::Mutex::new(None));
    let held = Arc::new(std::sync::Mutex::new(None));
    let authority = SessionMediaAuthority::new(
        subject.clone(),
        Arc::new(FixtureLiveness(subject)),
        attachments.clone(),
        Arc::new(FixturePaths {
            swapped: swapped.clone(),
            held: held.clone(),
        }),
        Arc::new(FixtureHttps),
        media_backend,
    );
    (authority, attachments, swapped, held)
}

struct FixedReservationClock;

impl crate::media_reservation::MonotonicClock for FixedReservationClock {
    fn now_ms(&self) -> u64 {
        1
    }
}

async fn durable_authorized_ctx() -> (
    tempfile::TempDir,
    crate::engine::tool::ToolCtx,
    Arc<SessionMediaAuthority>,
    Arc<crate::media_storage::MediaStorageRecovery>,
    cockpit_db::Db,
) {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = crate::tools::common::test_ctx(tmp.path());
    ctx.media_availability = crate::tool_media_authority::MediaToolAvailability::available();
    let session_id = ctx.session.id;
    let db = cockpit_db::Db::open_in_memory().unwrap();
    db.transaction(move |conn| {
        conn.execute(
            "INSERT INTO sessions(session_id,project_id,project_root,started_at_unix_ms,last_active_at_unix_ms) VALUES(?1,'p','/redacted',1,1)",
            [session_id.to_string()],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    let storage = Arc::new(
        crate::media_storage::MediaStorageRecovery::open_or_create(
            db.clone(),
            &tmp.path().join("media"),
        )
        .unwrap(),
    );
    let reservations = crate::media_reservation::MediaReservationLedger::new(
        db.clone(),
        Arc::new(FixedReservationClock),
    );
    let (authority, _, _, _) = fixture_authority_with_backend(
        *ctx.session.id.as_bytes(),
        Some((storage.clone(), reservations)),
    );
    let authority = Arc::new(authority);
    ctx = ctx.with_media_authority(authority.clone());
    (tmp, ctx, authority, storage, db)
}

fn authorized_ctx() -> (
    tempfile::TempDir,
    crate::engine::tool::ToolCtx,
    Arc<SessionMediaAuthority>,
    Arc<FixtureAttachments>,
    Arc<std::sync::Mutex<Option<String>>>,
    Arc<std::sync::Mutex<Option<std::fs::File>>>,
) {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = crate::tools::common::test_ctx(tmp.path());
    ctx.media_availability = crate::tool_media_authority::MediaToolAvailability::available();
    let session_id = *ctx.session.id.as_bytes();
    let (authority, attachments, swapped, held) = fixture_authority(session_id);
    let authority = Arc::new(authority);
    ctx = ctx.with_media_authority(authority.clone());
    (tmp, ctx, authority, attachments, swapped, held)
}

fn tool_for(kind: ToolKind, runner: Arc<dyn AvArgvRunner>) -> Box<dyn Tool> {
    match kind {
        ToolKind::InspectAudio => Box::new(InspectAudioTool::with_runner(runner)),
        ToolKind::InspectVideo => Box::new(InspectVideoTool::with_runner(runner)),
        ToolKind::ExtractVideoClip => Box::new(ExtractVideoClipTool::with_runner(runner)),
        ToolKind::ExtractAudio => Box::new(ExtractAudioTool::with_runner(runner)),
    }
}

struct InPlaceMutatingRunner {
    inner: FakeAvArgvRunner,
    held: Arc<std::sync::Mutex<Option<std::fs::File>>>,
    mutated: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl AvArgvRunner for InPlaceMutatingRunner {
    async fn run(
        &self,
        spec: &ProcessSpec,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<AvRunnerOutput> {
        if !self.mutated.swap(true, std::sync::atomic::Ordering::SeqCst) {
            use std::io::{Seek as _, SeekFrom, Write as _};

            let mut held = self.held.lock().expect("held mutation lock");
            let file = held
                .as_mut()
                .expect("path admission retained its descriptor");
            file.seek(SeekFrom::Start(0))?;
            file.write_all(b"mutated-in-place!!")?;
            file.set_len(b"mutated-in-place!!".len() as u64)?;
            file.flush()?;
        }
        self.inner.run(spec, cancel).await
    }
}

#[tokio::test]
async fn audio_video_source_execution() {
    let (_tmp, ctx, authority, attachments, swapped, held) = authorized_ctx();
    let runner = Arc::new(
        FakeAvArgvRunner::new()
            .with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes())
            .with_ffmpeg_bytes(DEFAULT_WAV_BYTES),
    );
    let branches = [
        json!({"source": {"attachment_id": "att-1"}}),
        json!({"source": {"path": "/held/media.bin"}}),
        json!({"source": {"url": "https://example.test/media.bin"}}),
    ];
    for kind in tool_kinds() {
        for args in &branches {
            let before = authority.io_counters();
            let semantic_runner: Arc<dyn AvArgvRunner> = match kind {
                ToolKind::InspectVideo => Arc::new(
                    FakeAvArgvRunner::new()
                        .with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes())
                        .with_ffmpeg_bytes(DEFAULT_PNG_BYTES),
                ),
                ToolKind::ExtractVideoClip => Arc::new(
                    FakeAvArgvRunner::new()
                        .with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes())
                        .with_ffmpeg_bytes(DEFAULT_MP4_BYTES),
                ),
                _ => runner.clone(),
            };
            let tool = tool_for(kind, semantic_runner);
            let output = tool.call(args.clone(), &ctx).await.expect("happy path");
            assert!(
                !output
                    .content
                    .contains("media_attachment_authority_unavailable"),
                "{kind:?} must not retain a permanent authority bail: {}",
                output.content
            );
            let value: Value = serde_json::from_str(&output.content).expect("json result");
            let ordinals = output
                .content
                .parts()
                .iter()
                .map(crate::typed_media_result::CanonicalToolResultContent::ordinal)
                .collect::<Vec<_>>();
            assert_eq!(ordinals.first(), Some(&1), "JSON is always ordinal 1");
            let expected_ordinals =
                (1..=u32::try_from(ordinals.len()).unwrap()).collect::<Vec<_>>();
            assert_eq!(
                ordinals, expected_ordinals,
                "canonical JSON/media parts must use one collision-free sequence"
            );
            assert!(
                value.get("attachment_id").is_some() || value.get("source_attachment_id").is_some()
            );
            let after = authority.io_counters();
            if args["source"].get("path").is_some() {
                assert!(after.path_authorizations > before.path_authorizations);
                assert!(after.attachments_created > before.attachments_created);
            }
            if args["source"].get("url").is_some() {
                assert!(after.fetches > before.fetches);
                assert!(after.attachments_created > before.attachments_created);
            }
            if args["source"].get("attachment_id").is_some() {
                assert_eq!(after.fetches, before.fetches);
                assert_eq!(after.path_authorizations, before.path_authorizations);
            }
            if kind == ToolKind::ExtractAudio || kind == ToolKind::ExtractVideoClip {
                assert!(value.get("reservation_id").is_some(), "{value}");
                let reference = output
                    .content
                    .parts()
                    .iter()
                    .find_map(|part| part.as_media_reference())
                    .expect("extraction must return a real canonical media part");
                assert_eq!(
                    reference.purpose,
                    crate::typed_media_result::MediaReferencePurpose::Primary
                );
                assert_eq!(reference.ordinal, 2);
                assert_eq!(value["media_ordinal"], 2);
                assert!(value.get("result").is_none(), "{value}");
            }
            if kind == ToolKind::InspectVideo {
                let references = output
                    .content
                    .parts()
                    .iter()
                    .filter_map(|part| part.as_media_reference())
                    .collect::<Vec<_>>();
                assert!(!references.is_empty());
                assert_eq!(references[0].ordinal, 2);
                assert_eq!(
                    value["storyboard"]["artifacts"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|artifact| artifact["media_ordinal"].as_u64().unwrap())
                        .collect::<Vec<_>>(),
                    (2..2 + references.len() as u64).collect::<Vec<_>>()
                );
                assert!(references.iter().all(|reference| {
                    reference.purpose == crate::typed_media_result::MediaReferencePurpose::Primary
                }));
                let reference = references[0];
                let auth = crate::typed_media_result::MediaReferenceAuthContext {
                    session_id: ctx.session.id,
                    canonical_project_digest: "fixture-project".into(),
                };
                let capabilities = crate::typed_media_result::ModelCapabilityProfile {
                    image_in_tool_result: false,
                    image_in_user_content: true,
                    audio_in_user_content: true,
                    video_in_user_content: true,
                };
                let live = crate::typed_media_result::LiveAttachmentSnapshot {
                    attachment_id: reference.attachment_id,
                    session_id: ctx.session.id,
                    canonical_project_digest: "fixture-project".into(),
                    attachment_version: reference.attachment_version,
                    availability: crate::typed_media_result::LiveAttachmentAvailability::Ready,
                    has_normalized_derivative: true,
                    synthetic_lease_authorized: true,
                    media_kind: reference.media_kind,
                    mime_type: reference.mime_type.clone(),
                };
                let handoff =
                    crate::typed_media_result::MediaReferenceResolver::new(&auth, &capabilities)
                        .resolve(
                            reference,
                            &live,
                            crate::typed_media_result::MediaRoute::Primary,
                            "inspect-video-call",
                            None,
                        )
                        .expect(
                            "supported inspect_video storyboard image resolves for real handoff",
                        );
                assert_eq!(
                    handoff.capability,
                    crate::typed_media_result::ModelMediaCapability::ImageInUserContent
                );
            }
        }
    }

    *swapped.lock().expect("swap lock") = Some("immutable-original".into());
    let immutable_runner = FakeAvArgvRunner::new().with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes());
    let mutating_runner = Arc::new(InPlaceMutatingRunner {
        inner: immutable_runner.clone(),
        held: held.clone(),
        mutated: std::sync::atomic::AtomicBool::new(false),
    });
    let created = InspectAudioTool::with_runner(mutating_runner)
        .call(json!({"source": {"path": "/held/in-place.bin"}}), &ctx)
        .await
        .unwrap();
    assert_eq!(
        immutable_runner.staged_inputs().last().map(Vec::as_slice),
        Some(b"immutable-original".as_slice()),
        "the first execution must use the immutable admission snapshot after the original descriptor mutates"
    );
    let created_json: Value = serde_json::from_str(&created.content).unwrap();
    let immutable_id = created_json["attachment_id"].as_str().unwrap();
    InspectAudioTool::with_runner(Arc::new(immutable_runner.clone()))
        .call(json!({"source": {"attachment_id": immutable_id}}), &ctx)
        .await
        .unwrap();
    assert_eq!(
        immutable_runner.staged_inputs().last().map(Vec::as_slice),
        Some(b"immutable-original".as_slice()),
        "attachment-id reuse must use the same immutable admitted bytes"
    );

    for (label, source, admitted_bytes) in [
        (
            "path",
            json!({"source": {"path": "/held/second.bin"}}),
            b"authority-held-original".as_slice(),
        ),
        (
            "url",
            json!({"source": {"url": "https://example.test/reusable.bin"}}),
            b"fake-av-bytes".as_slice(),
        ),
    ] {
        if label == "path" {
            *swapped.lock().expect("swap lock") = Some("authority-held-original".into());
        }
        let before_creation = authority.io_counters();
        let created = InspectAudioTool::with_runner(runner.clone())
            .call(source, &ctx)
            .await
            .unwrap();
        let after_creation = authority.io_counters();
        assert_eq!(
            after_creation.attachments_created,
            before_creation.attachments_created + 1,
            "{label} admission must create exactly one attachment"
        );
        assert_eq!(
            after_creation.path_authorizations,
            before_creation.path_authorizations + if label == "path" { 1 } else { 0 }
        );
        assert_eq!(
            after_creation.fetches,
            before_creation.fetches + if label == "url" { 1 } else { 0 }
        );
        let created_json: Value = serde_json::from_str(&created.content).unwrap();
        assert_eq!(created_json["attachment_created"], true);
        let id = created_json["attachment_id"].as_str().unwrap().to_string();

        if label == "path" {
            *swapped.lock().expect("swap lock") = Some("path-name-replacement".into());
        }
        let before_reuse = authority.io_counters();
        let reused = InspectAudioTool::with_runner(runner.clone())
            .call(json!({"source": {"attachment_id": id}}), &ctx)
            .await
            .unwrap();
        let reused_json: Value = serde_json::from_str(&reused.content).unwrap();
        assert_eq!(reused_json["attachment_created"], false);
        let after_reuse = authority.io_counters();
        assert_eq!(after_reuse.fetches, before_reuse.fetches, "{label}");
        assert_eq!(
            after_reuse.path_authorizations, before_reuse.path_authorizations,
            "{label}"
        );
        assert_eq!(
            after_reuse.attachment_opens, before_reuse.attachment_opens,
            "{label} reuse must use the authority-held ledger object"
        );
        assert_eq!(
            after_reuse.attachments_created, before_reuse.attachments_created,
            "{label} reuse must not create another attachment"
        );
        assert_eq!(
            runner.staged_inputs().last().map(Vec::as_slice),
            Some(admitted_bytes),
            "{label} attachment-id reuse must consume the admitted descriptor"
        );
    }

    attachments
        .revoked
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let before_revoked = authority.io_counters();
    let revoked = InspectAudioTool::with_runner(runner.clone())
        .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
        .await
        .unwrap_err();
    assert_source_denied_hides_kind(&revoked);
    let after_revoked = authority.io_counters();
    assert_eq!(after_revoked.runner_calls, before_revoked.runner_calls);
    assert_eq!(after_revoked.reservations, before_revoked.reservations);
    attachments
        .revoked
        .store(false, std::sync::atomic::Ordering::SeqCst);

    for instance in malformed_nested_source_instances() {
        let before = authority.io_counters();
        let err = InspectAudioTool::with_runner(runner.clone())
            .call(instance, &ctx)
            .await
            .unwrap_err();
        assert!(
            err.downcast_ref::<crate::engine::tool::InvalidToolInput>()
                .is_some()
        );
        let after = authority.io_counters();
        assert_eq!(after.fetches, before.fetches);
        assert_eq!(after.runner_calls, before.runner_calls);
        assert_eq!(after.path_authorizations, before.path_authorizations);
    }

    let denied_path = InspectAudioTool::with_runner(runner.clone())
        .call(json!({"source": {"path": "/held/denied.bin"}}), &ctx)
        .await
        .unwrap_err();
    assert_source_denied_hides_kind(&denied_path);
    let denied_url = InspectAudioTool::with_runner(runner.clone())
        .call(json!({"source": {"url": "https://denied.example/x"}}), &ctx)
        .await
        .unwrap_err();
    assert_source_denied_hides_kind(&denied_url);
    let missing = InspectAudioTool::with_runner(runner.clone())
        .call(json!({"source": {"attachment_id": "missing-id"}}), &ctx)
        .await
        .unwrap_err();
    assert_source_denied_hides_kind(&missing);

    let swapped = parse_nested_source(&json!({"source": {"path": "/held/original.bin"}})).unwrap();
    assert!(matches!(swapped, NestedMediaSource::Path(_)));

    let tmp = tempfile::tempdir().unwrap();
    let stripped = crate::tools::common::test_ctx(tmp.path());
    let mcp_err = InspectAudioTool::with_runner(runner)
        .call(json!({"source": {"path": "/held/media.bin"}}), &stripped)
        .await
        .unwrap_err();
    assert!(
        mcp_err
            .to_string()
            .contains("media_attachment_authority_unavailable")
    );
}

#[tokio::test]
async fn extract_audio_persists_video_source_kind_and_reuses_typed_attachment() {
    let (_tmp, ctx, authority, _storage, db) = durable_authorized_ctx().await;
    let runner = Arc::new(
        FakeAvArgvRunner::new()
            .with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes())
            .with_ffmpeg_bytes(DEFAULT_WAV_BYTES),
    );

    let created = ExtractAudioTool::with_runner(runner.clone())
        .call(
            json!({"source": {"path": "/held/video-with-audio.mp4"}}),
            &ctx,
        )
        .await
        .unwrap();
    let created_json: Value = serde_json::from_str(&created.content).unwrap();
    let source_id = created_json["source_attachment_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(created_json["attachment_created"], true);
    let persisted_kind = db
        .read({
            let source_id = uuid::Uuid::parse_str(&source_id).unwrap().to_string();
            move |conn| {
                Ok(conn.query_row(
                    "SELECT media_kind FROM media_attachments WHERE attachment_id=?1 AND source_kind='tool_admitted_source'",
                    [source_id],
                    |row| row.get::<_, String>(0),
                )?)
            }
        })
        .await
        .unwrap();
    assert_eq!(persisted_kind, "video");

    let before_reuse = authority.io_counters();
    let reused = ExtractAudioTool::with_runner(runner)
        .call(
            json!({"source": {"attachment_id": source_id.clone()}}),
            &ctx,
        )
        .await
        .unwrap();
    let reused_json: Value = serde_json::from_str(&reused.content).unwrap();
    assert_eq!(reused_json["source_attachment_id"], source_id);
    assert_eq!(reused_json["attachment_created"], false);
    let after_reuse = authority.io_counters();
    assert_eq!(
        after_reuse.path_authorizations,
        before_reuse.path_authorizations
    );
    assert_eq!(after_reuse.fetches, before_reuse.fetches);
    assert_eq!(
        db.read(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM media_attachments WHERE source_kind='tool_admitted_source' AND media_kind='video'",
                [],
                |row| row.get::<_, i64>(0),
            )?)
        })
        .await
        .unwrap(),
        1
    );
}

#[tokio::test]
async fn audio_video_provider_modality_gate() {
    use crate::config::providers::CapabilityStatus;
    use crate::tool_media_authority::{
        AvRuntimeProfile, MediaToolAvailability, MediaToolAvailabilityReason,
    };

    let avail = MediaToolAvailability::available_with(
        AvRuntimeProfile::FullClip,
        CapabilityStatus::Supported,
        CapabilityStatus::RequiresEntitlement,
        CapabilityStatus::Unsupported,
    );
    assert!(!avail.exposes_direct_tool("inspect_audio"));
    assert!(!avail.exposes_direct_tool("inspect_video"));
    assert!(avail.exposes_direct_tool("extract_audio"));
    assert!(avail.exposes_direct_tool("extract_video_clip"));
    assert_eq!(
        avail.reason_for("inspect_audio"),
        MediaToolAvailabilityReason::ModelCapabilityRequiresEntitlement
    );
    let rows = avail.av_availability_rows();
    assert!(rows.iter().any(|row| {
        row.tool == "inspect_audio"
            && row.reason == MediaToolAvailabilityReason::ModelCapabilityRequiresEntitlement
            && !row.present
    }));

    for (image, expected) in [
        (
            CapabilityStatus::Unsupported,
            MediaToolAvailabilityReason::ModelCapabilityUnsupported,
        ),
        (
            CapabilityStatus::Unknown,
            MediaToolAvailabilityReason::ModelCapabilityUnknown,
        ),
        (
            CapabilityStatus::RequiresEntitlement,
            MediaToolAvailabilityReason::ModelCapabilityRequiresEntitlement,
        ),
    ] {
        let image_gate = MediaToolAvailability::available_with(
            AvRuntimeProfile::FullClip,
            image,
            CapabilityStatus::Supported,
            CapabilityStatus::Supported,
        );
        assert!(image_gate.exposes_direct_tool("inspect_audio"));
        assert!(!image_gate.exposes_direct_tool("inspect_video"));
        assert_eq!(image_gate.reason_for("inspect_video"), expected);
    }

    let (_tmp, mut ctx, authority, _, _, _) = authorized_ctx();
    let runner = Arc::new(FakeAvArgvRunner::new().with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes()));
    for status in [
        CapabilityStatus::Unsupported,
        CapabilityStatus::Unknown,
        CapabilityStatus::RequiresEntitlement,
    ] {
        let expected = match status {
            CapabilityStatus::Unsupported => "model_capability_unsupported",
            CapabilityStatus::Unknown => "model_capability_unknown",
            CapabilityStatus::RequiresEntitlement => "model_capability_requires_entitlement",
            CapabilityStatus::Supported => unreachable!(),
        };
        for video in [false, true] {
            ctx.media_availability = MediaToolAvailability::available_with(
                AvRuntimeProfile::FullClip,
                CapabilityStatus::Supported,
                if video {
                    CapabilityStatus::Supported
                } else {
                    status
                },
                if video {
                    status
                } else {
                    CapabilityStatus::Supported
                },
            );
            let before = authority.io_counters();
            let tool: Box<dyn Tool> = if video {
                Box::new(ExtractVideoClipTool::with_runner(runner.clone()))
            } else {
                Box::new(ExtractAudioTool::with_runner(runner.clone()))
            };
            let err = tool
                .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
                .await
                .unwrap_err();
            assert!(err.to_string().contains(expected), "{status:?}: {err}");
            let after = authority.io_counters();
            assert_eq!(after.fetches, before.fetches);
            assert_eq!(after.runner_calls, before.runner_calls);
            assert_eq!(after.reservations, before.reservations);
            assert_eq!(after.path_authorizations, before.path_authorizations);
        }
    }
}

#[test]
fn extraction_duration_cap_fits_pcm_wav_byte_ceiling() {
    let fits = super::WAV_HEADER_BYTES + MAX_EXTRACTION_DURATION_MS * super::MAX_WAV_BYTES_PER_MS;
    assert!(
        fits <= MAX_PROCESS_STDOUT_BYTES as u64,
        "MAX_EXTRACTION_DURATION_MS must fit in the 4 MiB WAV ceiling"
    );
    let overflows =
        super::WAV_HEADER_BYTES + (MAX_EXTRACTION_DURATION_MS + 1) * super::MAX_WAV_BYTES_PER_MS;
    assert!(
        overflows > MAX_PROCESS_STDOUT_BYTES as u64,
        "the next millisecond must exceed the 4 MiB WAV ceiling"
    );
    let overflow = json!({
        "source": {"attachment_id": "att-1"},
        "start": 0.0,
        "end": 30.0
    });
    for kind in [ToolKind::ExtractAudio, ToolKind::ExtractVideoClip] {
        let err = parse_semantic_args(&overflow, kind).unwrap_err();
        assert!(
            err.to_string().contains("resource_limit"),
            "{kind:?}: {err}"
        );
    }
}

#[tokio::test]
async fn extract_omitted_interval_rejects_long_source_before_persist_or_reserve() {
    let (_tmp, ctx, authority, _, _, _) = authorized_ctx();
    let runner: Arc<dyn AvArgvRunner> = Arc::new(
        FakeAvArgvRunner::new()
            .with_probe_json(DEFAULT_FFPROBE_JSON.replace("2.000", "30.000").into_bytes()),
    );
    for kind in [ToolKind::ExtractAudio, ToolKind::ExtractVideoClip] {
        let before = authority.io_counters();
        let err = tool_for(kind, runner.clone())
            .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("resource_limit"),
            "{kind:?}: {err}"
        );
        let after = authority.io_counters();
        assert_eq!(
            after.reservations, before.reservations,
            "{kind:?} must not reserve a derivative that cannot fit"
        );
        assert_eq!(
            after.attachments_created, before.attachments_created,
            "{kind:?} must not persist before the duration ceiling"
        );
        assert_eq!(
            after.runner_calls,
            before.runner_calls + 1,
            "{kind:?} may metadata-probe, but must not dump frames or encode"
        );
    }
}

#[tokio::test]
async fn durable_av_uuid_reuse_applies_source_byte_ceiling() {
    let (_tmp, ctx, authority, _, _, _) = authorized_ctx();
    let runner = Arc::new(
        FakeAvArgvRunner::new()
            .with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes())
            .with_ffmpeg_bytes(DEFAULT_WAV_BYTES),
    );
    let oversized_id = uuid::Uuid::from_bytes(OVERSIZED_AV_ATTACHMENT_ID).to_string();
    let before = authority.io_counters();
    let err = InspectAudioTool::with_runner(runner.clone())
        .call(json!({"source": {"attachment_id": oversized_id}}), &ctx)
        .await
        .unwrap_err();
    assert_source_denied_hides_kind(&err);
    let after = authority.io_counters();
    assert_eq!(after.runner_calls, before.runner_calls);
    assert_eq!(after.attachment_opens, before.attachment_opens);
    assert_eq!(after.reservations, before.reservations);
}

#[tokio::test]
async fn audio_video_bomb_ceiling() {
    let (_tmp, ctx, authority, _, _, _) = authorized_ctx();
    let runner = FakeAvArgvRunner::new();
    runner.bomb_stdout(MAX_PROCESS_STDOUT_BYTES + 16);
    let err = InspectAudioTool::with_runner(Arc::new(runner))
        .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("resource_limit"), "{err}");

    let corrupt = FakeAvArgvRunner::new();
    corrupt.corrupt();
    let err = InspectVideoTool::with_runner(Arc::new(corrupt))
        .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("invalid_media"), "{err}");

    let extract_runner = Arc::new(
        FakeAvArgvRunner::new()
            .with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes())
            .with_ffmpeg_bytes(DEFAULT_WAV_BYTES),
    );
    let before_duration = authority.io_counters();
    let too_long = ExtractAudioTool::with_runner(extract_runner.clone())
        .call(
            json!({
                "source": {"attachment_id": "att-1"},
                "start": 0.0,
                "end": 30.0
            }),
            &ctx,
        )
        .await
        .unwrap_err();
    assert!(
        too_long.to_string().contains("resource_limit"),
        "{too_long}"
    );
    let after_duration = authority.io_counters();
    assert_eq!(after_duration.runner_calls, before_duration.runner_calls);
    assert_eq!(after_duration.reservations, before_duration.reservations);
    assert_eq!(after_duration.fetches, before_duration.fetches);

    let before_fetch = authority.io_counters();
    let oversize = InspectAudioTool::with_runner(extract_runner)
        .call(
            json!({"source": {"url": "https://example.test/oversize.bin"}}),
            &ctx,
        )
        .await
        .unwrap_err();
    assert_source_denied_hides_kind(&oversize);
    let after_fetch = authority.io_counters();
    assert_eq!(
        after_fetch.fetches, before_fetch.fetches,
        "HTTPS bombs must be rejected by the A/V fetch ceiling before retain"
    );
    assert_eq!(after_fetch.runner_calls, before_fetch.runner_calls);
}

#[tokio::test]
async fn inspect_video_storyboard_honors_requested_interval() {
    let (_tmp, ctx, _, _, _, _) = authorized_ctx();
    let runner = Arc::new(
        FakeAvArgvRunner::new()
            .with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes())
            .with_ffmpeg_bytes(DEFAULT_PNG_BYTES),
    );
    let output = InspectVideoTool::with_runner(runner.clone())
        .call(
            json!({
                "source": {"attachment_id": "att-1"},
                "start": 0.08,
                "end": 0.2,
                "sampling": {"max_frames": 4}
            }),
            &ctx,
        )
        .await
        .expect("in-bounds inspect interval");
    let value: Value = serde_json::from_str(&output.content).unwrap();
    let artifacts = value["storyboard"]["artifacts"]
        .as_array()
        .expect("storyboard artifacts");
    assert!(
        !artifacts.is_empty(),
        "requested interval must still produce storyboard work: {value}"
    );
    for artifact in artifacts {
        let requested = artifact["requested_ms"].as_u64().expect("requested_ms");
        assert!(
            (80..200).contains(&requested),
            "storyboard request {requested} must stay inside start/end"
        );
        let actual = artifact["actual_pts_ms"].as_u64().expect("actual_pts_ms");
        assert!(
            (80..200).contains(&actual),
            "storyboard PTS {actual} must stay inside start/end"
        );
    }
    let ffmpeg_seeks: Vec<u64> = runner
        .calls()
        .into_iter()
        .filter(|call| call.program.ends_with("ffmpeg"))
        .filter_map(|call| {
            call.argv
                .windows(2)
                .find(|pair| pair[0] == "-ss")
                .and_then(|pair| Milliseconds::from_decimal_seconds(&pair[1]).ok())
                .map(|timestamp| timestamp.0)
        })
        .collect();
    assert!(
        !ffmpeg_seeks.is_empty(),
        "inspect_video must launch storyboard ffmpeg for an in-bounds interval"
    );
    assert!(
        ffmpeg_seeks.iter().all(|seek| (80..200).contains(seek)),
        "ffmpeg -ss must honor inspect start/end, got {ffmpeg_seeks:?}"
    );
}

#[tokio::test]
async fn inspect_video_rejects_submillisecond_duration_before_storyboard_math() {
    let (_tmp, ctx, _, _, _, _) = authorized_ctx();
    let runner = FakeAvArgvRunner::new()
        .with_probe_json(DEFAULT_FFPROBE_JSON.replace("2.000", "0.0004").into_bytes());

    let error = InspectVideoTool::with_runner(Arc::new(runner.clone()))
        .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("invalid_media"), "{error}");
    assert_eq!(runner.calls().len(), 1, "no storyboard process may launch");
}

#[tokio::test]
async fn audio_video_storyboard_rolls_back_every_prior_derivative_on_nth_failure() {
    let (_tmp, ctx, authority, _, _, _) = authorized_ctx();
    let runner = FakeAvArgvRunner::new()
        .with_probe_json(DEFAULT_FFPROBE_JSON.replace("2.000", "0.121").into_bytes())
        .with_ffmpeg_bytes(DEFAULT_PNG_BYTES);
    runner.fail_program_on_call("ffmpeg", 2);
    let before = authority.io_counters();

    let error = InspectVideoTool::with_runner(Arc::new(runner))
        .call(
            json!({
                "source": {"attachment_id": "att-1"},
                "sampling": {"max_frames": 4}
            }),
            &ctx,
        )
        .await
        .unwrap_err();

    assert!(error.to_string().contains("media_process_failed"));
    let after = authority.io_counters();
    assert_eq!(
        after.derivatives_published - before.derivatives_published,
        1
    );
    assert_eq!(
        after.derivatives_discarded - before.derivatives_discarded,
        1
    );
    assert_eq!(
        after.reservations_aborted - before.reservations_aborted,
        2,
        "the failed current reservation and every earlier published reservation are released"
    );
}

#[tokio::test]
async fn audio_video_storyboard_final_publication_cancellation_rolls_back_all_frames() {
    let (_tmp, ctx, authority, _, _, _) = authorized_ctx();
    authority.cancel_after_publications(4, ctx.cancel.clone());
    let runner = FakeAvArgvRunner::new()
        .with_probe_json(DEFAULT_FFPROBE_JSON.replace("2.000", "0.121").into_bytes())
        .with_ffmpeg_bytes(DEFAULT_PNG_BYTES);
    let before = authority.io_counters();

    let error = InspectVideoTool::with_runner(Arc::new(runner))
        .call(
            json!({
                "source": {"attachment_id": "att-1"},
                "sampling": {"max_frames": 4}
            }),
            &ctx,
        )
        .await
        .unwrap_err();

    assert!(error.to_string().contains("cancelled"), "{error}");
    let after = authority.io_counters();
    assert_eq!(
        after.derivatives_published - before.derivatives_published,
        4
    );
    assert_eq!(
        after.derivatives_discarded - before.derivatives_discarded,
        4
    );
    assert_eq!(after.reservations_aborted - before.reservations_aborted, 4);
}

#[tokio::test]
async fn audio_video_storyboard_cancellation_deletes_durable_rows_and_releases_reservations() {
    let (_tmp, ctx, authority, _storage, db) = durable_authorized_ctx().await;
    authority.cancel_after_publications(2, ctx.cancel.clone());
    let runner = FakeAvArgvRunner::new()
        .with_probe_json(DEFAULT_FFPROBE_JSON.replace("2.000", "0.121").into_bytes())
        .with_ffmpeg_bytes(DEFAULT_PNG_BYTES);

    let error = InspectVideoTool::with_runner(Arc::new(runner))
        .call(
            json!({
                "source": {"attachment_id": "att-1"},
                "sampling": {"max_frames": 4}
            }),
            &ctx,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("cancelled"), "{error}");

    let durable = db
        .read(|conn| {
            Ok((
                conn.query_row(
                    "SELECT COUNT(*) FROM media_attachments WHERE source_kind='tool_derivative'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?,
                conn.query_row(
                    "SELECT COUNT(*) FROM media_attachment_components WHERE component_kind='image_model'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?,
                conn.query_row(
                    "SELECT COUNT(*) FROM media_reservations WHERE operation='audio_video_tool'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?,
                conn.query_row(
                    "SELECT COUNT(*) FROM media_reservations WHERE operation='audio_video_tool' AND state='released'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?,
            ))
        })
        .await
        .unwrap();
    assert_eq!(durable.0, 0, "published attachment rows must be deleted");
    assert_eq!(durable.1, 0, "published component rows must be deleted");
    assert_eq!(durable.2, 2, "two frame reservations reached publication");
    assert_eq!(durable.3, durable.2, "every reservation must be released");
}

#[tokio::test]
async fn inspect_video_tool_call_reaches_provider_mapping_through_real_storage_lease() {
    use base64::Engine as _;

    let (_tmp, ctx, _authority, storage, db) = durable_authorized_ctx().await;
    let runner = FakeAvArgvRunner::new()
        .with_probe_json(DEFAULT_FFPROBE_JSON.replace("2.000", "0.121").into_bytes())
        .with_ffmpeg_bytes(DEFAULT_PNG_BYTES);
    let output = InspectVideoTool::with_runner(Arc::new(runner))
        .call(
            json!({
                "source": {"attachment_id": "att-1"},
                "sampling": {"max_frames": 1}
            }),
            &ctx,
        )
        .await
        .unwrap();
    let reference = output
        .content
        .parts()
        .iter()
        .find_map(|part| part.as_media_reference())
        .expect("InspectVideoTool::call emits a canonical storyboard reference");
    let attachment_id = reference.attachment_id;
    let auth = crate::typed_media_result::MediaReferenceAuthContext {
        session_id: ctx.session.id,
        canonical_project_digest: "22".repeat(32),
    };
    let capabilities = crate::typed_media_result::ModelCapabilityProfile {
        image_in_user_content: true,
        ..Default::default()
    };
    let resolver = crate::typed_media_result::MediaReferenceResolver::new(&auth, &capabilities);
    let now = chrono::Utc::now().timestamp_millis();
    let (resolved, held) = storage
        .resolve_tool_media_reference(
            &resolver,
            &auth,
            reference,
            crate::typed_media_result::MediaRoute::Primary,
            "inspect-video-call",
            Some("provider-call"),
            now,
        )
        .await
        .unwrap();
    let resolved_bytes = &resolved.bytes.as_ref().expect("primary bytes").bytes;
    assert_eq!(resolved_bytes.as_slice(), DEFAULT_PNG_BYTES);
    assert_eq!(&resolved_bytes[..8], b"\x89PNG\r\n\x1a\n");
    assert!(resolved_bytes.ends_with(b"IEND\xaeB\x60\x82"));
    let encoded = base64::engine::general_purpose::STANDARD.encode(resolved_bytes);
    let provider =
        crate::typed_media_result::map_to_provider_rig(&resolved, reference, &encoded).unwrap();
    assert!(provider.is_adjacent_content());
    assert_eq!(provider.tool_call_id(), "inspect-video-call");
    held.expect("primary provider handoff retains the acquired lease")
        .release(now.saturating_add(1))
        .await
        .unwrap();
    let live_leases = db
        .read(move |conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM media_attachment_component_leases WHERE attachment_id=?1 AND released_at_unix_ms IS NULL",
                [attachment_id.to_string()],
                |row| row.get::<_, i64>(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(live_leases, 0);
}

#[tokio::test]
async fn audio_video_over_limit_source_removes_every_provisional_ledger_entry() {
    let (_tmp, ctx, authority, _, swapped, _) = authorized_ctx();
    *swapped.lock().expect("swap lock") = Some("x".repeat(MAX_PROCESS_STDOUT_BYTES + 1));
    let before = authority.provisional_ledger_counts();

    let error = InspectAudioTool::with_runner(Arc::new(FakeAvArgvRunner::new()))
        .call(json!({"source": {"path": "/held/over-limit.bin"}}), &ctx)
        .await
        .unwrap_err();

    assert!(
        error.to_string().contains("media resource denied"),
        "{error}"
    );
    assert_eq!(
        authority.provisional_ledger_counts(),
        before,
        "failed persistence must remove the provisional attachment, held handle/bytes, and aliases"
    );
}

#[tokio::test]
async fn audio_video_durable_new_source_runner_failure_discards_rows_and_reservation() {
    for (label, source) in [
        (
            "path",
            json!({"source": {"path": "/held/fails-after-persist.bin"}}),
        ),
        (
            "url",
            json!({"source": {"url": "https://example.test/fails-after-persist.bin"}}),
        ),
    ] {
        let (_tmp, ctx, _authority, _storage, db) = durable_authorized_ctx().await;
        let runner = FakeAvArgvRunner::new();
        runner.fail_program_on_call("ffmpeg", 1);

        let error = InspectVideoTool::with_runner(Arc::new(runner))
            .call(source, &ctx)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("media_process_failed"),
            "{label}: {error}"
        );

        let counts = db
            .read(|conn| {
                Ok((
                    conn.query_row(
                        "SELECT COUNT(*) FROM media_attachments WHERE source_kind='tool_admitted_source'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM media_attachment_components",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM media_reservations WHERE operation='audio_video_tool'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM media_reservations WHERE operation='audio_video_tool' AND state='released'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(counts.0, 0, "{label}: durable source row must be deleted");
        assert_eq!(
            counts.1, 0,
            "{label}: durable source bytes row must be deleted"
        );
        assert_eq!(
            counts.2, 2,
            "{label}: source publication and storyboard each reserve once"
        );
        assert_eq!(
            counts.3, counts.2,
            "{label}: source reservation must be released"
        );
    }
}

#[tokio::test]
async fn audio_video_extraction_publication_cancellation_discards_derivative() {
    let (_tmp, ctx, authority, _storage, db) = durable_authorized_ctx().await;
    authority.cancel_after_publications(1, ctx.cancel.clone());
    let runner = FakeAvArgvRunner::new()
        .with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes())
        .with_ffmpeg_bytes(DEFAULT_WAV_BYTES);

    let error = ExtractAudioTool::with_runner(Arc::new(runner))
        .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("cancelled"), "{error}");

    let counts = db
        .read(|conn| {
            Ok((
                conn.query_row(
                    "SELECT COUNT(*) FROM media_attachments WHERE source_kind='tool_derivative'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?,
                conn.query_row(
                    "SELECT COUNT(*) FROM media_attachment_components",
                    [],
                    |row| row.get::<_, i64>(0),
                )?,
                conn.query_row(
                    "SELECT COUNT(*) FROM media_reservations WHERE operation='audio_video_tool'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?,
                conn.query_row(
                    "SELECT COUNT(*) FROM media_reservations WHERE operation='audio_video_tool' AND state='released'",
                    [],
                    |row| row.get::<_, i64>(0),
                )?,
            ))
        })
        .await
        .unwrap();
    assert_eq!(
        counts.0, 0,
        "cancelled extraction must delete attachment rows"
    );
    assert_eq!(
        counts.1, 0,
        "cancelled extraction must delete component bytes rows"
    );
    assert_eq!(counts.2, 1, "extraction reserves exactly once");
    assert_eq!(
        counts.3, counts.2,
        "extraction reservation must be released"
    );
}

#[tokio::test]
async fn audio_video_invalid_extraction_metadata_fails_before_second_source_stage() {
    let (_tmp, ctx, _, _, _, _) = authorized_ctx();
    let invalid_audio_caps = DEFAULT_FFPROBE_JSON.replace("44100", "invalid-rate");
    let runner = FakeAvArgvRunner::new().with_probe_json(invalid_audio_caps.into_bytes());

    let error = ExtractAudioTool::with_runner(Arc::new(runner.clone()))
        .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("invalid_media"), "{error}");
    assert_eq!(runner.calls().len(), 1, "ffmpeg must not run");
    assert_eq!(
        runner.staged_inputs().len(),
        1,
        "only the probe source may be staged before metadata validation"
    );
    let cleaned = runner.cleaned_paths();
    assert!(!cleaned.is_empty());
    assert!(cleaned.iter().all(|path| !path.exists()));
}

#[tokio::test]
async fn audio_video_fake_process_lifecycle() {
    let (_tmp, ctx, _, _, _, _) = authorized_ctx();
    let runner = FakeAvArgvRunner::new().with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes());
    runner.force_timeout();
    let err = InspectAudioTool::with_runner(Arc::new(runner.clone()))
        .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("deadline_exceeded"), "{err}");
    let timed_out_paths = runner.cleaned_paths();
    assert!(!timed_out_paths.is_empty());
    assert!(timed_out_paths.iter().all(|path| !path.exists()));
    assert_eq!(runner.reaped_processes(), runner.calls().len());

    let cancel_runner = FakeAvArgvRunner::new().with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes());
    cancel_runner.force_cancel();
    let err = InspectAudioTool::with_runner(Arc::new(cancel_runner.clone()))
        .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("cancelled"), "{err}");
    let cancelled_paths = cancel_runner.cleaned_paths();
    assert!(!cancelled_paths.is_empty());
    assert!(cancelled_paths.iter().all(|path| !path.exists()));
    assert_eq!(
        cancel_runner.reaped_processes(),
        cancel_runner.calls().len()
    );

    let (_tmp2, ctx2, _, _, _, _) = authorized_ctx();
    let ok_runner = FakeAvArgvRunner::new().with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes());
    InspectAudioTool::with_runner(Arc::new(ok_runner.clone()))
        .call(json!({"source": {"path": "/held/ok.bin"}}), &ctx2)
        .await
        .unwrap();
    let recorded = ok_runner.calls();
    assert!(!recorded.is_empty());
    assert_eq!(ok_runner.reaped_processes(), recorded.len());
    for call in &recorded {
        assert!(call.stdin_closed);
        assert!(call.stderr_limit <= MAX_PROCESS_STDERR_BYTES);
        assert_eq!(
            call.environment,
            vec![
                ("LC_ALL".to_string(), "C".to_string()),
                ("LANG".to_string(), "C".to_string())
            ]
        );
        assert!(!call.argv.iter().any(|arg| arg == "--"));
    }
}

#[tokio::test]
async fn audio_video_capability_matrix() {
    use crate::config::providers::CapabilityStatus;
    use crate::tool_media_authority::{
        AvRuntimeCapabilities, AvRuntimeProfile, MediaToolAvailability,
    };

    let cases = [
        (
            AvRuntimeCapabilities {
                ffprobe_compatible: false,
                ..AvRuntimeCapabilities::default()
            },
            AvRuntimeProfile::None,
            &[] as &[&str],
        ),
        (
            AvRuntimeCapabilities {
                ffprobe_compatible: true,
                ffmpeg_decode: false,
                audio_encoder: false,
                clip_encoders: false,
            },
            AvRuntimeProfile::ProbeOnly,
            &["inspect_audio"][..],
        ),
        (
            AvRuntimeCapabilities {
                ffprobe_compatible: true,
                ffmpeg_decode: true,
                audio_encoder: false,
                clip_encoders: false,
            },
            AvRuntimeProfile::Inspect,
            &["inspect_audio", "inspect_video"][..],
        ),
        (
            AvRuntimeCapabilities {
                ffprobe_compatible: true,
                ffmpeg_decode: true,
                audio_encoder: true,
                clip_encoders: false,
            },
            AvRuntimeProfile::ExtractAudio,
            &["inspect_audio", "inspect_video", "extract_audio"][..],
        ),
        (
            AvRuntimeCapabilities {
                ffprobe_compatible: true,
                ffmpeg_decode: true,
                audio_encoder: true,
                clip_encoders: true,
            },
            AvRuntimeProfile::FullClip,
            &[
                "inspect_audio",
                "inspect_video",
                "extract_audio",
                "extract_video_clip",
            ][..],
        ),
    ];
    for (caps, profile, tools) in cases {
        assert_eq!(caps.profile(), profile);
        let avail = MediaToolAvailability::available_with(
            profile,
            CapabilityStatus::Supported,
            CapabilityStatus::Supported,
            CapabilityStatus::Supported,
        );
        assert_eq!(avail.runtime_and_modality_exposed_av_tools(), tools);

        // Cross the injected execution boundary for every capability row so
        // this required suite cannot regress into helper-only coverage.
        let runner = FakeAvArgvRunner::new();
        let spec = probe_process("/held/capability-matrix.bin");
        runner
            .run(&spec, &tokio_util::sync::CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(runner.calls().len(), 1);
    }
}
