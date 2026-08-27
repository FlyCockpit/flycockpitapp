use std::collections::HashSet;
use std::sync::Arc;

use serde_json::{Value, json};

use super::*;
use crate::engine::model::wire_schema::for_responses;
use crate::engine::tool::Tool;
use crate::media_storage::{
    TYPED_AUDIO_CONTAINER_CODECS, TYPED_VIDEO_CONTAINER_CODECS, container_allows_audio_codec,
    container_allows_video_codec,
};
use crate::tool_media_authority::session_authority::{
    AdmittedAttachment, AdmittedRetainedSource, AttachmentResolver, HandleEvidence,
    LocalPathPolicy, RetainedHttpsPolicy,
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
        if let Some(defensive) = tool.defensive_parameters() {
            schemas.push((name, defensive));
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
        assert_nested_source_description(
            tool.description(),
            &format!("{} description", tool.name()),
        );
        let defensive = tool
            .defensive_description()
            .unwrap_or_else(|| panic!("{} must supply a defensive description", tool.name()));
        assert_nested_source_description(
            &defensive,
            &format!("{} defensive_description", tool.name()),
        );
    }
}

#[test]
fn audio_video_process_specs_are_argv_only_and_capped() {
    let spec = probe_process("name; touch nope");
    assert_eq!(spec.program, "ffprobe");
    assert_eq!(spec.argv.last().unwrap(), "name; touch nope");
    assert!(spec.stdin_closed);
    assert_eq!(spec.environment.len(), 2);
    assert!(spec.stdout_limit > spec.stderr_limit);
}

fn argv_has_lone_double_dash(spec: &ProcessSpec) -> bool {
    spec.argv.iter().any(|arg| arg == "--")
}

#[test]
fn audio_video_argv_snapshots() {
    let interval = Interval::checked(Milliseconds(1_500), Milliseconds(2_250)).unwrap();
    let probe = probe_process("/held/source.wav");
    let clip = clip_process(
        "/held/video.mp4",
        "/tmp/out.mp4",
        &interval,
        0,
        22_050,
        1,
        15,
        1,
    );
    let audio = audio_process("/held/audio.wav", "/tmp/out.wav", &interval, 0, 22_050, 1);
    for spec in [&probe, &clip, &audio] {
        assert!(
            !argv_has_lone_double_dash(spec),
            "{} argv must not contain a lone --: {:?}",
            spec.program,
            spec.argv
        );
        assert!(spec.stdin_closed);
        assert_eq!(
            spec.environment,
            vec![("LC_ALL", "C".into()), ("LANG", "C".into())]
        );
    }
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
    assert_eq!(reduced_fps_from_pts_ms(&[0, 40, 80, 120]), (24, 1));
    assert_eq!(reduced_fps_from_pts_ms(&[0, 100, 200]), (10, 1));
}

struct FixtureAttachments {
    by_id: std::collections::HashMap<[u8; 16], AdmittedAttachment>,
    aliases: std::collections::HashMap<String, [u8; 16]>,
    revoked: std::sync::atomic::AtomicBool,
}

impl AttachmentResolver for FixtureAttachments {
    fn resolve(
        &self,
        _session_id: &str,
        attachment_id: &[u8; 16],
    ) -> Result<Option<AdmittedAttachment>, AdmissionDenial> {
        if self.revoked.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(None);
        }
        Ok(self.by_id.get(attachment_id).cloned())
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
}

struct FixturePaths {
    swapped: std::sync::Mutex<Option<String>>,
}

impl LocalPathPolicy for FixturePaths {
    fn authorize(
        &self,
        _session_id: &str,
        path: &str,
    ) -> Result<(std::path::PathBuf, HandleEvidence), AdmissionDenial> {
        if path.contains("denied") {
            return Err(AdmissionDenial::LocalPathDenied);
        }
        let held = self
            .swapped
            .lock()
            .expect("swap lock")
            .clone()
            .unwrap_or_else(|| path.to_string());
        Ok((
            std::path::PathBuf::from(held),
            HandleEvidence {
                metadata_fingerprint: [0xAA; 32],
            },
        ))
    }
}

struct FixtureHttps;

impl RetainedHttpsPolicy for FixtureHttps {
    fn admit(
        &self,
        _session_id: &str,
        url: &str,
    ) -> Result<AdmittedRetainedSource, AdmissionDenial> {
        if url.contains("denied") {
            return Err(AdmissionDenial::HttpsDenied);
        }
        Ok(AdmittedRetainedSource {
            canonical_url: url.to_string(),
            content: b"fake-av-bytes".to_vec(),
            content_type: "audio/mpeg".to_string(),
        })
    }
}

fn fixture_authority(session_id: [u8; 16]) -> (SessionMediaAuthority, Arc<FixtureAttachments>) {
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
    let authority = SessionMediaAuthority::new(
        subject,
        attachments.clone(),
        Arc::new(FixturePaths {
            swapped: std::sync::Mutex::new(None),
        }),
        Arc::new(FixtureHttps),
    );
    (authority, attachments)
}

fn authorized_ctx() -> (
    tempfile::TempDir,
    crate::engine::tool::ToolCtx,
    Arc<SessionMediaAuthority>,
) {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = crate::tools::common::test_ctx(tmp.path());
    ctx.media_availability = crate::tool_media_authority::MediaToolAvailability::available();
    let session_id = *ctx.session.id.as_bytes();
    let (authority, _) = fixture_authority(session_id);
    let authority = Arc::new(authority);
    ctx = ctx.with_media_authority(authority.clone());
    (tmp, ctx, authority)
}

fn tool_for(kind: ToolKind, runner: Arc<dyn AvArgvRunner>) -> Box<dyn Tool> {
    match kind {
        ToolKind::InspectAudio => Box::new(InspectAudioTool::with_runner(runner)),
        ToolKind::InspectVideo => Box::new(InspectVideoTool::with_runner(runner)),
        ToolKind::ExtractVideoClip => Box::new(ExtractVideoClipTool::with_runner(runner)),
        ToolKind::ExtractAudio => Box::new(ExtractAudioTool::with_runner(runner)),
    }
}

#[tokio::test]
async fn audio_video_source_execution() {
    let (_tmp, ctx, authority) = authorized_ctx();
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
            let tool = tool_for(kind, runner.clone());
            let output = tool.call(args.clone(), &ctx).await.expect("happy path");
            assert!(
                !output
                    .content
                    .contains("media_attachment_authority_unavailable"),
                "{kind:?} must not retain a permanent authority bail: {}",
                output.content
            );
            let value: Value = serde_json::from_str(&output.content).expect("json result");
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
                assert!(value.get("result").is_some(), "{value}");
            }
        }
    }

    let created = InspectAudioTool::with_runner(runner.clone())
        .call(json!({"source": {"path": "/held/second.bin"}}), &ctx)
        .await
        .unwrap();
    let created_json: Value = serde_json::from_str(&created.content).unwrap();
    let id = created_json["attachment_id"].as_str().unwrap().to_string();
    let before_reuse = authority.io_counters();
    InspectAudioTool::with_runner(runner.clone())
        .call(json!({"source": {"attachment_id": id}}), &ctx)
        .await
        .unwrap();
    let after_reuse = authority.io_counters();
    assert_eq!(after_reuse.fetches, before_reuse.fetches);
    assert_eq!(
        after_reuse.path_authorizations,
        before_reuse.path_authorizations
    );

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
    assert!(denied_path.to_string().contains("source_denied"));
    let denied_url = InspectAudioTool::with_runner(runner.clone())
        .call(json!({"source": {"url": "https://denied.example/x"}}), &ctx)
        .await
        .unwrap_err();
    assert!(denied_url.to_string().contains("source_denied"));
    let missing = InspectAudioTool::with_runner(runner.clone())
        .call(json!({"source": {"attachment_id": "missing-id"}}), &ctx)
        .await
        .unwrap_err();
    assert!(missing.to_string().contains("source_denied"));

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
async fn audio_video_provider_modality_gate() {
    use crate::config::providers::CapabilityStatus;
    use crate::tool_media_authority::{
        AvRuntimeProfile, MediaToolAvailability, MediaToolAvailabilityReason,
    };

    let avail = MediaToolAvailability::available_with(
        AvRuntimeProfile::FullClip,
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

    let (_tmp, mut ctx, authority) = authorized_ctx();
    ctx.media_availability = avail;
    let runner = Arc::new(FakeAvArgvRunner::new().with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes()));
    let before = authority.io_counters();
    let err = ExtractAudioTool::with_runner(runner.clone())
        .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("model_capability_requires_entitlement")
    );
    let after = authority.io_counters();
    assert_eq!(after.fetches, before.fetches);
    assert_eq!(after.runner_calls, before.runner_calls);
    assert_eq!(after.reservations, before.reservations);
    assert_eq!(after.path_authorizations, before.path_authorizations);

    ctx.media_availability = MediaToolAvailability::available_with(
        AvRuntimeProfile::FullClip,
        CapabilityStatus::Unknown,
        CapabilityStatus::Unknown,
    );
    let err = ExtractVideoClipTool::with_runner(runner)
        .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("model_capability_unknown"));
}

#[tokio::test]
async fn audio_video_bomb_ceiling() {
    let (_tmp, ctx, _) = authorized_ctx();
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
}

#[tokio::test]
async fn audio_video_fake_process_lifecycle() {
    let (_tmp, mut ctx, _) = authorized_ctx();
    let runner = FakeAvArgvRunner::new().with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes());
    runner.force_timeout();
    let err = InspectAudioTool::with_runner(Arc::new(runner.clone()))
        .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("deadline_exceeded"), "{err}");
    assert!(
        !runner.cleaned_paths().is_empty() || runner.calls().iter().all(|call| call.stdin_closed)
    );

    let cancel_runner = FakeAvArgvRunner::new().with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes());
    ctx.cancel.cancel();
    let err = InspectAudioTool::with_runner(Arc::new(cancel_runner.clone()))
        .call(json!({"source": {"attachment_id": "att-1"}}), &ctx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("cancelled"), "{err}");

    let (_tmp2, ctx2, _) = authorized_ctx();
    let ok_runner = FakeAvArgvRunner::new().with_probe_json(DEFAULT_FFPROBE_JSON.as_bytes());
    InspectAudioTool::with_runner(Arc::new(ok_runner.clone()))
        .call(json!({"source": {"path": "/held/ok.bin"}}), &ctx2)
        .await
        .unwrap();
    let recorded = ok_runner.calls();
    assert!(!recorded.is_empty());
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

#[test]
fn audio_video_capability_matrix() {
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
        );
        assert_eq!(avail.runtime_and_modality_exposed_av_tools(), tools);
    }
}
