//! Cockpit-owned compatibility between canonical tool schemas and strict wires.
//!
//! Canonical tool schemas describe optional properties by omitting them from
//! `required`. OpenAI Responses strict mode makes every property required, so
//! those properties need a `null` arm on that wire. The inverse normalization
//! removes strict-wire placeholder nulls before a tool sees its arguments while
//! preserving nulls that the canonical schema genuinely permits.

use std::borrow::Cow;
use std::collections::HashSet;

use serde_json::{Value, json};

use crate::config::providers::WireApi;
use crate::engine::message::ToolDefinition;

/// Return the tool definitions appropriate for one concrete OpenAI-compatible
/// endpoint. Callers must resolve `Auto` to the endpoint they are actually
/// about to use; it deliberately remains canonical here.
pub(super) fn definitions_for_wire<'a>(
    wire: WireApi,
    definitions: &'a [ToolDefinition],
) -> Cow<'a, [ToolDefinition]> {
    if wire != WireApi::Responses {
        return Cow::Borrowed(definitions);
    }

    Cow::Owned(
        definitions
            .iter()
            .cloned()
            .map(|mut definition| {
                definition.parameters = for_responses(&definition.parameters);
                definition
            })
            .collect(),
    )
}

/// Add explicit nullability to every canonically optional property.
pub(crate) fn for_responses(schema: &Value) -> Value {
    let mut transformed = schema.clone();
    make_optional_properties_nullable(&mut transformed);
    close_object_schemas(&mut transformed);
    transformed
}

fn close_object_schemas(schema: &mut Value) {
    let Value::Object(object) = schema else {
        return;
    };

    if is_object_schema(object) {
        object
            .entry("properties".to_string())
            .or_insert_with(|| json!({}));
        object.insert("additionalProperties".to_string(), Value::Bool(false));
    }

    if let Some(Value::Object(properties)) = object.get_mut("properties") {
        for property in properties.values_mut() {
            close_object_schemas(property);
        }
    }
    if let Some(items) = object.get_mut("items") {
        close_object_schemas(items);
    }
    if let Some(Value::Object(definitions)) = object.get_mut("$defs") {
        for definition in definitions.values_mut() {
            close_object_schemas(definition);
        }
    }
    for combinator in ["anyOf", "oneOf", "allOf"] {
        if let Some(Value::Array(variants)) = object.get_mut(combinator) {
            for variant in variants {
                close_object_schemas(variant);
            }
        }
    }
}

fn is_object_schema(object: &serde_json::Map<String, Value>) -> bool {
    object.contains_key("properties")
        || matches!(object.get("type"), Some(Value::String(kind)) if kind == "object")
        || object
            .get("type")
            .and_then(Value::as_array)
            .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("object")))
}

fn make_optional_properties_nullable(schema: &mut Value) {
    let Value::Object(object) = schema else {
        return;
    };

    let required: HashSet<String> = object
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();

    if let Some(Value::Object(properties)) = object.get_mut("properties") {
        for (name, property) in properties {
            make_optional_properties_nullable(property);
            if !required.contains(name) {
                add_null_arm(property);
            }
        }
    }

    if let Some(items) = object.get_mut("items") {
        make_optional_properties_nullable(items);
    }
    if let Some(Value::Object(definitions)) = object.get_mut("$defs") {
        for definition in definitions.values_mut() {
            make_optional_properties_nullable(definition);
        }
    }
    for combinator in ["anyOf", "oneOf", "allOf"] {
        if let Some(Value::Array(variants)) = object.get_mut(combinator) {
            for variant in variants {
                make_optional_properties_nullable(variant);
            }
        }
    }
}

fn add_null_arm(schema: &mut Value) {
    if explicitly_allows_null(schema) {
        return;
    }

    let Value::Object(object) = schema else {
        let original = std::mem::take(schema);
        *schema = json!({ "anyOf": [original, { "type": "null" }] });
        return;
    };

    if object.contains_key("$ref") || object.contains_key("enum") || object.contains_key("const") {
        let original = std::mem::take(schema);
        *schema = json!({ "anyOf": [original, { "type": "null" }] });
        return;
    }

    match object.get_mut("type") {
        Some(Value::String(kind)) => {
            let kind = std::mem::take(kind);
            object.insert(
                "type".to_string(),
                Value::Array(vec![Value::String(kind), Value::String("null".to_string())]),
            );
            return;
        }
        Some(Value::Array(kinds)) => {
            kinds.push(Value::String("null".to_string()));
            return;
        }
        _ => {}
    }

    if let Some(Value::Array(variants)) = object.get_mut("anyOf") {
        variants.push(json!({ "type": "null" }));
        return;
    }
    if let Some(Value::Array(variants)) = object.get_mut("oneOf") {
        variants.push(json!({ "type": "null" }));
        return;
    }

    // `$ref` cannot have siblings on OpenAI's strict subset, and enum-only or
    // otherwise untyped schemas have no safe type to infer. Wrap the complete
    // schema so rig can sanitize each arm without dropping the reference.
    let original = std::mem::take(schema);
    *schema = json!({ "anyOf": [original, { "type": "null" }] });
}

fn explicitly_allows_null(schema: &Value) -> bool {
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
            .is_some_and(|variants| variants.iter().any(explicitly_allows_null))
    })
}

/// Remove object-property nulls introduced only for strict-wire optionality.
/// Arrays are intentionally opaque: their elements are model data, not the
/// object-property omission encoding owned by this boundary.
pub(crate) fn strip_wire_nulls(canonical_schema: &Value, mut args: Value) -> Value {
    strip_object_nulls(canonical_schema, canonical_schema, &mut args);
    args
}

fn strip_object_nulls(root: &Value, schema: &Value, value: &mut Value) {
    let Value::Object(arguments) = value else {
        return;
    };

    let keys: Vec<String> = arguments.keys().cloned().collect();
    for key in keys {
        let property_schema = find_property_schema(root, schema, &key, 0);
        let remove = arguments.get(&key).is_some_and(Value::is_null)
            && !property_schema.is_some_and(|property| schema_allows_null(root, property));
        if remove {
            arguments.remove(&key);
            continue;
        }

        let Some(property_schema) = property_schema else {
            continue;
        };
        if let Some(child) = arguments.get_mut(&key)
            && child.is_object()
        {
            strip_object_nulls(root, property_schema, child);
        }
    }
}

fn find_property_schema<'a>(
    root: &'a Value,
    schema: &'a Value,
    property: &str,
    depth: usize,
) -> Option<&'a Value> {
    if depth > 64 {
        return None;
    }
    let object = schema.as_object()?;
    if let Some(found) = object
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(property))
    {
        return Some(found);
    }
    if let Some(reference) = object.get("$ref").and_then(Value::as_str)
        && let Some(target) = resolve_local_ref(root, reference)
    {
        return find_property_schema(root, target, property, depth + 1);
    }
    for combinator in ["anyOf", "oneOf", "allOf"] {
        if let Some(found) = object
            .get(combinator)
            .and_then(Value::as_array)
            .and_then(|variants| {
                variants
                    .iter()
                    .find_map(|variant| find_property_schema(root, variant, property, depth + 1))
            })
        {
            return Some(found);
        }
    }
    None
}

fn schema_allows_null(root: &Value, schema: &Value) -> bool {
    schema_allows_null_inner(root, schema, &mut HashSet::new())
}

fn schema_allows_null_inner(root: &Value, schema: &Value, seen_refs: &mut HashSet<String>) -> bool {
    if explicitly_allows_null(schema) {
        return true;
    }
    if let Some(object) = schema.as_object() {
        for combinator in ["anyOf", "oneOf"] {
            if object
                .get(combinator)
                .and_then(Value::as_array)
                .is_some_and(|variants| {
                    variants
                        .iter()
                        .any(|variant| schema_allows_null_inner(root, variant, seen_refs))
                })
            {
                return true;
            }
        }
        if let Some(variants) = object.get("allOf").and_then(Value::as_array)
            && !variants.is_empty()
            && variants
                .iter()
                .all(|variant| schema_allows_null_inner(root, variant, seen_refs))
        {
            return true;
        }
    }
    let Some(reference) = schema.get("$ref").and_then(Value::as_str) else {
        return false;
    };
    if !seen_refs.insert(reference.to_string()) {
        return false;
    }
    resolve_local_ref(root, reference)
        .is_some_and(|target| schema_allows_null_inner(root, target, seen_refs))
}

fn resolve_local_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let pointer = reference.strip_prefix('#')?;
    if pointer.is_empty() {
        Some(root)
    } else {
        root.pointer(pointer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task_schema() -> Value {
        crate::engine::builtin::invariant_builtin_tools()
            .into_iter()
            .find(|tool| tool.name() == "task")
            .expect("task tool is registered")
            .parameters()
    }

    fn has_null_type(schema: &Value) -> bool {
        explicitly_allows_null(schema)
    }

    fn open_object_violations(schema: &Value, path: &str, out: &mut Vec<String>) {
        let Some(object) = schema.as_object() else {
            return;
        };
        if is_object_schema(object) {
            if !object.contains_key("properties") {
                out.push(format!("{path}: object schema has no properties"));
            }
            if let Some(additional) = object.get("additionalProperties")
                && additional != &Value::Bool(false)
            {
                out.push(format!(
                    "{path}: additionalProperties must be false, got {additional}"
                ));
            }
        }
        for key in ["properties", "$defs"] {
            if let Some(entries) = object.get(key).and_then(Value::as_object) {
                for (name, child) in entries {
                    open_object_violations(child, &format!("{path}.{key}.{name}"), out);
                }
            }
        }
        if let Some(items) = object.get("items") {
            open_object_violations(items, &format!("{path}.items"), out);
        }
        for key in ["anyOf", "oneOf", "allOf"] {
            if let Some(variants) = object.get(key).and_then(Value::as_array) {
                for (index, variant) in variants.iter().enumerate() {
                    open_object_violations(variant, &format!("{path}.{key}[{index}]"), out);
                }
            }
        }
    }

    #[test]
    fn optional_fields_gain_null_arm_recursively() {
        let canonical = task_schema();
        let transformed = for_responses(&canonical);

        assert!(!has_null_type(&transformed["properties"]["intent"]));
        assert!(has_null_type(&transformed["properties"]["payload"]));
        assert_eq!(
            transformed["properties"]["payload"]["properties"]["model"]["properties"]["kind"],
            canonical["properties"]["payload"]["properties"]["model"]["properties"]["kind"]
        );
        for field in ["agent", "prompt"] {
            assert_eq!(
                transformed["properties"]["payload"]["items"]["properties"][field],
                canonical["properties"]["payload"]["items"]["properties"][field]
            );
        }
        for field in ["min_context_tokens", "trust"] {
            assert!(
                has_null_type(
                    &transformed["properties"]["payload"]["properties"]["model"]["properties"]
                        [field]
                ),
                "nested optional `{field}` must be nullable"
            );
        }
    }

    #[test]
    fn transform_is_idempotent_and_preserves_constraints() {
        let canonical = json!({
            "type": "object",
            "properties": {
                "count": {
                    "type": "integer",
                    "minimum": 1,
                    "enum": [1, 2],
                    "description": "A constrained optional count"
                },
                "choice": {
                    "enum": ["a", "b"],
                    "description": "An enum-only optional"
                },
                "reference": {
                    "$ref": "#/$defs/item",
                    "type": "object",
                    "description": "A referenced optional"
                }
            },
            "$defs": {
                "item": {
                    "type": "object",
                    "properties": { "label": { "type": "string" } }
                }
            }
        });
        let once = for_responses(&canonical);
        let twice = for_responses(&once);

        assert_eq!(once, twice);
        let constrained = &once["properties"]["count"]["anyOf"][0];
        assert_eq!(constrained["minimum"], 1);
        assert_eq!(constrained["enum"], json!([1, 2]));
        assert_eq!(constrained["description"], "A constrained optional count");
        assert!(has_null_type(&once["properties"]["choice"]));
        assert!(has_null_type(&once["properties"]["reference"]));
        let strict = rig::providers::openai::responses_api::ResponsesToolDefinition::function(
            "sample",
            "sample schema",
            once.clone(),
        );
        assert!(has_null_type(&strict.parameters["properties"]["reference"]));
        let constrained_validator =
            jsonschema::validator_for(&strict.parameters["properties"]["count"])
                .expect("post-rig constrained optional schema compiles");
        assert!(
            constrained_validator.is_valid(&Value::Null),
            "post-rig constrained optional must accept an actual null instance"
        );
        assert_eq!(
            strict.parameters["properties"]["reference"]["anyOf"][0],
            json!({ "$ref": "#/$defs/item" })
        );
    }

    fn assert_objects_are_closed(schema: &Value) {
        let Some(object) = schema.as_object() else {
            return;
        };
        if is_object_schema(object) {
            assert_eq!(
                object.get("additionalProperties"),
                Some(&Value::Bool(false))
            );
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
                "strict object must require all fields"
            );
        }
        for key in ["properties", "$defs"] {
            if let Some(entries) = object.get(key).and_then(Value::as_object) {
                for child in entries.values() {
                    assert_objects_are_closed(child);
                }
            }
        }
        if let Some(items) = object.get("items") {
            assert_objects_are_closed(items);
        }
        for key in ["anyOf", "oneOf", "allOf"] {
            if let Some(variants) = object.get(key).and_then(Value::as_array) {
                for variant in variants {
                    assert_objects_are_closed(variant);
                }
            }
        }
    }

    fn assert_optional_properties_nullable(canonical: &Value, strict: &Value) {
        let (Some(canonical_object), Some(strict_object)) =
            (canonical.as_object(), strict.as_object())
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
                        "canonical-optional property `{name}` is not nullable: {strict_property}"
                    );
                }
                assert_optional_properties_nullable(canonical_property, strict_property);
            }
        }
        if let (Some(canonical_items), Some(strict_items)) =
            (canonical_object.get("items"), strict_object.get("items"))
        {
            assert_optional_properties_nullable(canonical_items, strict_items);
        }
        if let (Some(canonical_defs), Some(strict_defs)) = (
            canonical_object.get("$defs").and_then(Value::as_object),
            strict_object.get("$defs").and_then(Value::as_object),
        ) {
            for (name, canonical_definition) in canonical_defs {
                assert_optional_properties_nullable(canonical_definition, &strict_defs[name]);
            }
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
                assert!(
                    strict_variants.len() >= canonical_variants.len(),
                    "strict `{strict_key}` lost canonical variants"
                );
                for (canonical_variant, strict_variant) in
                    canonical_variants.iter().zip(strict_variants)
                {
                    assert_optional_properties_nullable(canonical_variant, strict_variant);
                }
            }
        }
    }

    #[test]
    fn all_builtin_tools_strict_compatible() {
        for tool in crate::engine::builtin::invariant_builtin_tools() {
            let canonical = tool.parameters();
            let canonical_definitions = vec![ToolDefinition {
                name: tool.name().to_string(),
                description: tool.description().to_string(),
                parameters: canonical.clone(),
            }];
            assert_eq!(
                definitions_for_wire(WireApi::Completions, &canonical_definitions).as_ref(),
                canonical_definitions.as_slice(),
                "chat-completions schema changed for `{}`",
                tool.name()
            );
            assert_eq!(
                definitions_for_wire(WireApi::Auto, &canonical_definitions).as_ref(),
                canonical_definitions.as_slice(),
                "unresolved canonical schema changed for `{}`",
                tool.name()
            );
            let transformed = for_responses(&canonical);
            let strict = rig::providers::openai::responses_api::ResponsesToolDefinition::function(
                tool.name(),
                tool.description(),
                transformed,
            );
            assert_optional_properties_nullable(&canonical, &strict.parameters);
            assert_objects_are_closed(&strict.parameters);
            assert_eq!(tool.parameters(), canonical, "canonical schema mutated");
        }
    }

    #[test]
    fn nullable_object_arm_is_closed() {
        let canonical = json!({
            "type": "object",
            "properties": {
                "args": {
                    "type": "object",
                    "description": "x"
                }
            },
            "required": []
        });

        let transformed = for_responses(&canonical);
        let args = &transformed["properties"]["args"];

        assert!(has_null_type(args));
        assert_eq!(args["type"], json!(["object", "null"]));
        assert_eq!(args["properties"], json!({}));
        assert_eq!(args["additionalProperties"], false);
    }

    #[test]
    fn schedule_schema_survives_rig_sanitize() {
        for schema in [
            crate::tools::schedule::schedule_parameters(),
            crate::tools::schedule::schedule_parameters_defensive(),
        ] {
            let transformed = for_responses(&schema);
            let strict = rig::providers::openai::responses_api::ResponsesToolDefinition::function(
                "schedule",
                "schedule",
                transformed,
            );
            assert_objects_are_closed(&strict.parameters);
        }
    }

    #[test]
    fn skill_manage_schema_survives_rig_sanitize() {
        let tool = crate::tools::skill_manage::SkillManageTool;
        let schemas = [
            crate::engine::tool::Tool::parameters(&tool),
            crate::engine::tool::Tool::defensive_parameters(&tool)
                .expect("skill_manage has defensive parameters"),
        ];
        for schema in schemas {
            let transformed = for_responses(&schema);
            let strict = rig::providers::openai::responses_api::ResponsesToolDefinition::function(
                "skill_manage",
                "skill_manage",
                transformed,
            );
            assert_objects_are_closed(&strict.parameters);
        }
    }

    #[test]
    fn no_builtin_tool_schema_has_an_open_object() {
        let mut violations = Vec::new();
        for tool in crate::engine::builtin::invariant_builtin_tools() {
            open_object_violations(
                &tool.parameters(),
                &format!("{}.parameters", tool.name()),
                &mut violations,
            );
            if let Some(defensive) = tool.defensive_parameters() {
                open_object_violations(
                    &defensive,
                    &format!("{}.defensive_parameters", tool.name()),
                    &mut violations,
                );
            }
        }
        assert!(
            violations.is_empty(),
            "open object schemas are not strict-wire compatible:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn open_object_violation_detector_rejects_free_form_shapes() {
        let mut violations = Vec::new();
        open_object_violations(
            &json!({
                "type": "object",
                "properties": {
                    "args": { "type": "object" }
                }
            }),
            "missing-properties",
            &mut violations,
        );
        open_object_violations(
            &json!({
                "type": "object",
                "properties": {
                    "resources": {
                        "type": "object",
                        "additionalProperties": { "type": "integer" }
                    }
                }
            }),
            "map-object",
            &mut violations,
        );

        assert_eq!(
            violations,
            vec![
                "missing-properties.properties.args: object schema has no properties",
                "map-object.properties.resources: object schema has no properties",
                "map-object.properties.resources: additionalProperties must be false, got {\"type\":\"integer\"}",
            ]
        );
    }

    #[test]
    fn definitions_for_responses_wire_transform_without_mutating_canonical() {
        let canonical = ToolDefinition {
            name: "sample".to_string(),
            description: "sample tool".to_string(),
            parameters: json!({
                "type": "object",
                "properties": { "optional": { "type": "string" } }
            }),
        };
        let definitions = vec![canonical.clone()];

        let responses = definitions_for_wire(WireApi::Responses, &definitions);
        assert!(has_null_type(
            &responses[0].parameters["properties"]["optional"]
        ));
        assert_eq!(
            definitions_for_wire(WireApi::Completions, &definitions).as_ref(),
            definitions.as_slice()
        );
        assert_eq!(
            definitions_for_wire(WireApi::Auto, &definitions).as_ref(),
            definitions.as_slice()
        );
        assert_eq!(definitions[0], canonical, "canonical definition mutated");
    }

    #[test]
    fn schema_aware_strip_preserves_real_nulls_and_arrays() {
        let schema = json!({
            "type": "object",
            "properties": {
                "model": {
                    "type": "object",
                    "properties": {
                        "kind": { "type": "string" },
                        "selector": { "type": "string" },
                        "min_context_tokens": { "type": "integer" }
                    }
                },
                "cwd": { "type": "string" },
                "explicit": { "type": ["string", "null"] },
                "ref_nullable": { "$ref": "#/$defs/nullable" },
                "items": { "type": "array", "items": {} }
            },
            "$defs": {
                "nullable": { "type": ["string", "null"] }
            }
        });
        let args = json!({
            "model": {
                "kind": "exact",
                "selector": "p:m",
                "min_context_tokens": null
            },
            "cwd": null,
            "explicit": null,
            "ref_nullable": null,
            "items": [null, {"nested": null}]
        });

        assert_eq!(
            strip_wire_nulls(&schema, args),
            json!({
                "model": { "kind": "exact", "selector": "p:m" },
                "explicit": null,
                "ref_nullable": null,
                "items": [null, {"nested": null}]
            })
        );
    }
}
