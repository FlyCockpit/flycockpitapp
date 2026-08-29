use std::collections::HashSet;

use serde_json::{Value, json};

use super::*;
use crate::engine::model::wire_schema::for_responses;
use crate::engine::tool::Tool;
use crate::media_storage::{
    TYPED_AUDIO_CONTAINER_CODECS, TYPED_VIDEO_CONTAINER_CODECS, container_allows_audio_codec,
    container_allows_video_codec,
};

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

fn av_tools() -> [&'static dyn Tool; 4] {
    [
        &InspectAudioTool,
        &InspectVideoTool,
        &ExtractVideoClipTool,
        &ExtractAudioTool,
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
        schemas.push((tool.name(), tool.parameters()));
        if let Some(defensive) = tool.verbose_parameters() {
            schemas.push((tool.name(), defensive));
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

#[tokio::test]
async fn audio_video_tool_schema_fail_closed_validates_nested_source() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    for kind in tool_kinds() {
        for instance in [
            json!({"source": {}}),
            json!({"source": {"url": "http://example.test/x"}}),
            json!({"source": {"attachment_id": "att-1"}, "path": "/tmp/a"}),
        ] {
            let malformed = fail_closed(instance.clone(), kind, &ctx).await.unwrap_err();
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
        let well_formed = fail_closed(json!({"source": {"attachment_id": "att-1"}}), kind, &ctx)
            .await
            .unwrap_err();
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

        let sampling = fail_closed(well_formed_sampling(), kind, &ctx)
            .await
            .unwrap_err();
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
    assert_eq!(spec.program, "ffprobe");
    assert_eq!(spec.argv.last().unwrap(), "name; touch nope");
    assert!(spec.stdin_closed);
    assert_eq!(spec.environment.len(), 2);
    assert!(spec.stdout_limit > spec.stderr_limit);
}
