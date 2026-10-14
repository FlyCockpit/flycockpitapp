//! Cockpit-owned compatibility between canonical tool schemas and the wires
//! that carry them. This module is the one place a tool's JSON Schema is
//! lowered for a provider wire; every OpenAI-compatible dispatch path sends
//! [`definitions_for_wire`]'s output, so built-in, delegation, utility and
//! MCP-provided schemas all pass through it.
//!
//! ## Subsets
//!
//! The subsets below were established by probing the live endpoints
//! (OpenRouter, 2026-10: `openai/gpt-5.4-nano` on Responses and Chat
//! Completions in strict and non-strict mode, `anthropic/claude-haiku-5.5` on
//! Messages, `google/gemini-3.5-flash-lite` on Chat Completions):
//!
//! - **Strict OpenAI** (Responses here, which always sends `strict: true`)
//!   rejects `propertyNames`, `minProperties`, `maxProperties`,
//!   `uniqueItems`, `contains`, `oneOf`, `allOf`, `not`, `if`/`then`/`else`,
//!   `dependentRequired`, `dependentSchemas`, `unevaluatedProperties`,
//!   `format` values outside [`STRICT_STRING_FORMATS`], and any schema
//!   without a `type` (bare `{}`, untyped `const`, an array without
//!   `items`). It accepts but cannot honor open-keyed maps
//!   (`additionalProperties: <schema>`): constrained decoding emits `{}`.
//! - **Every OpenAI mode** rejects `-2^63` as a numeric keyword value ("a
//!   numeric value in the function parameters is too large").
//! - **Gemini** (through OpenRouter Chat Completions) rejects an array
//!   without `items`.
//! - Non-strict OpenAI, Anthropic Messages and Gemini accept every other
//!   keyword probed, including `x-cockpit-*` annotations.
//!
//! Canonical built-in schemas are authored in [`PORTABLE_KEYWORDS`], the
//! subset every wire accepts after the lossless lowering below (`oneOf` →
//! `anyOf`, optional → nullable, objects closed). Constraints a wire cannot
//! carry are enforced where the tool parses its arguments, never only in the
//! schema. Lowering a third-party (MCP) schema for a stricter wire only drops
//! keywords; it never invents constraints, except that strict mode needs a
//! concrete `type` for an untyped leaf.
//!
//! ## Optionality
//!
//! Canonical tool schemas describe optional properties by omitting them from
//! `required`. OpenAI Responses strict mode makes every property required, so
//! those properties need a `null` arm on that wire. The inverse normalization
//! removes strict-wire placeholder nulls before a tool sees its arguments while
//! preserving nulls that the canonical schema genuinely permits.

use std::borrow::Cow;
use std::collections::HashSet;

use serde_json::{Map, Value, json};

use crate::config::providers::WireApi;
use crate::engine::message::ToolDefinition;

/// Return the tool definitions appropriate for one concrete OpenAI-compatible
/// endpoint: Responses (strict) gets [`for_responses`], Chat Completions gets
/// the non-strict lowering only when a schema needs it, and Anthropic Messages
/// takes the canonical schema unchanged. Callers must resolve `Auto` to the
/// endpoint they are actually about to use; it deliberately remains canonical
/// here.
pub(super) fn definitions_for_wire<'a>(
    wire: WireApi,
    definitions: &'a [ToolDefinition],
) -> Cow<'a, [ToolDefinition]> {
    let lower: fn(&Value) -> Value = match wire {
        WireApi::Responses => for_responses,
        WireApi::Completions => {
            if !definitions
                .iter()
                .any(|definition| needs_lenient_lowering(&definition.parameters))
            {
                return Cow::Borrowed(definitions);
            }
            for_lenient
        }
        WireApi::Auto | WireApi::Anthropic => return Cow::Borrowed(definitions),
    };

    Cow::Owned(
        definitions
            .iter()
            .cloned()
            .map(|mut definition| {
                definition.parameters = lower(&definition.parameters);
                definition
            })
            .collect(),
    )
}

/// Lower a canonical schema to OpenAI's strict subset and add explicit
/// nullability to every canonically optional property.
pub(crate) fn for_responses(schema: &Value) -> Value {
    let mut transformed = schema.clone();
    lower_to_strict(&mut transformed);
    make_optional_properties_nullable(&mut transformed);
    close_object_schemas(&mut transformed);
    transformed
}

/// Lower a schema for a non-strict Chat Completions wire: only the shapes no
/// non-strict endpoint accepts are touched.
fn for_lenient(schema: &Value) -> Value {
    let mut transformed = schema.clone();
    lower_to_lenient(&mut transformed);
    transformed
}

/// Keywords every wire accepts once [`for_responses`] has lowered `oneOf` to
/// `anyOf`. Canonical built-in schemas must stay inside this set (plus
/// `x-cockpit-*` annotations); the per-tool lint in the tests enforces it.
pub(crate) const PORTABLE_KEYWORDS: &[&str] = &[
    // Structure.
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "anyOf",
    "oneOf",
    "$defs",
    "$ref",
    // Annotations.
    "description",
    "title",
    "default",
    "examples",
    "deprecated",
    "readOnly",
    "writeOnly",
    "$comment",
    // Strings.
    "minLength",
    "maxLength",
    "pattern",
    "format",
    // Numbers.
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    // Arrays.
    "minItems",
    "maxItems",
];

/// `format` values OpenAI strict mode accepts; any other value is a 400.
pub(crate) const STRICT_STRING_FORMATS: &[&str] = &[
    "date-time",
    "time",
    "date",
    "duration",
    "email",
    "hostname",
    "ipv4",
    "ipv6",
    "uuid",
];

const NUMERIC_KEYWORDS: &[&str] = &[
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
];

/// The largest numeric keyword magnitude Cockpit sends. OpenAI rejects
/// `-2^63`; JSON-safe integers are exact in every JavaScript gateway.
pub(crate) const MAX_PORTABLE_SCHEMA_NUMBER: f64 = 9_007_199_254_740_991.0;

/// The type strict mode gets for a schema that canonically accepts anything.
/// Strict decoding cannot express "any value"; scalars are the widest closed
/// choice that never forces a fabricated object shape.
fn strict_any_type() -> Value {
    json!(["string", "number", "boolean"])
}

/// Whether a numeric keyword value can travel on every wire.
pub(crate) fn is_portable_schema_number(value: &Value) -> bool {
    value
        .as_f64()
        .is_some_and(|number| number.abs() <= MAX_PORTABLE_SCHEMA_NUMBER)
}

fn is_extension_keyword(key: &str) -> bool {
    key.starts_with("x-")
}

fn remove_unportable_numbers(object: &mut Map<String, Value>) {
    for keyword in NUMERIC_KEYWORDS {
        if object
            .get(*keyword)
            .is_some_and(|value| !is_portable_schema_number(value))
        {
            object.remove(*keyword);
        }
    }
}

fn is_array_schema(object: &Map<String, Value>) -> bool {
    match object.get("type") {
        Some(Value::String(kind)) => kind == "array",
        Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind.as_str() == Some("array")),
        _ => false,
    }
}

/// Subschema positions this module lowers. Positions only some wires reject
/// (for example `not`) are removed by the strict pass before it descends, so
/// they are deliberately absent here.
const MAP_POSITIONS: &[&str] = &["properties", "$defs", "definitions"];
const SINGLE_POSITIONS: &[&str] = &["items", "additionalProperties"];
const LIST_POSITIONS: &[&str] = &["anyOf", "oneOf", "allOf"];

fn for_each_subschema(object: &mut Map<String, Value>, mut visit: impl FnMut(&mut Value)) {
    for (key, child) in object.iter_mut() {
        let key = key.as_str();
        match child {
            Value::Object(entries) if MAP_POSITIONS.contains(&key) => {
                entries.values_mut().for_each(&mut visit);
            }
            Value::Object(_) if SINGLE_POSITIONS.contains(&key) => visit(child),
            Value::Array(variants) if LIST_POSITIONS.contains(&key) => {
                variants.iter_mut().for_each(&mut visit);
            }
            _ => {}
        }
    }
}

fn subschemas(object: &Map<String, Value>) -> impl Iterator<Item = &Value> {
    object.iter().flat_map(|(key, child)| {
        let key = key.as_str();
        let children: Box<dyn Iterator<Item = &Value>> = match child {
            Value::Object(entries) if MAP_POSITIONS.contains(&key) => Box::new(entries.values()),
            Value::Object(_) if SINGLE_POSITIONS.contains(&key) => Box::new(std::iter::once(child)),
            Value::Array(variants) if LIST_POSITIONS.contains(&key) => Box::new(variants.iter()),
            _ => Box::new(std::iter::empty()),
        };
        children
    })
}

fn needs_lenient_lowering(schema: &Value) -> bool {
    let Some(object) = schema.as_object() else {
        return false;
    };
    NUMERIC_KEYWORDS.iter().any(|keyword| {
        object
            .get(*keyword)
            .is_some_and(|value| !is_portable_schema_number(value))
    }) || (is_array_schema(object) && !object.contains_key("items"))
        || subschemas(object).any(needs_lenient_lowering)
}

fn lower_to_lenient(schema: &mut Value) {
    let Value::Object(object) = schema else {
        return;
    };
    remove_unportable_numbers(object);
    if is_array_schema(object) && !object.contains_key("items") {
        object.insert("items".to_string(), json!({}));
    }
    for_each_subschema(object, lower_to_lenient);
}

/// Rewrite one schema into OpenAI's strict subset. Only drops keywords the
/// subset rejects (relaxing the advertised contract) and gives untyped leaves
/// a concrete type; the canonical schema still governs argument validation.
fn lower_to_strict(schema: &mut Value) {
    let Value::Object(object) = schema else {
        return;
    };

    merge_all_of(object);
    // OpenAI strict forbids siblings next to `$ref`.
    if object.contains_key("$ref") {
        object.retain(|key, _| key == "$ref");
        return;
    }
    if let Some(one_of) = object.remove("oneOf") {
        match (object.get_mut("anyOf"), one_of) {
            (Some(Value::Array(any_of)), Value::Array(mut variants)) => {
                any_of.append(&mut variants)
            }
            (_, one_of) => {
                object.insert("anyOf".to_string(), one_of);
            }
        }
    }

    object.retain(|key, value| {
        if is_extension_keyword(key) {
            return true;
        }
        if !PORTABLE_KEYWORDS.contains(&key.as_str()) && key != "definitions" {
            return false;
        }
        match key.as_str() {
            "format" => value
                .as_str()
                .is_some_and(|format| STRICT_STRING_FORMATS.contains(&format)),
            "items" => value.is_object(),
            _ => true,
        }
    });
    remove_unportable_numbers(object);

    if !object.contains_key("type") && !object.contains_key("anyOf") {
        if let Some(constant) = object.get("const") {
            if let Some(kind) = json_type_name(constant) {
                object.insert("type".to_string(), Value::String(kind.to_string()));
            }
        } else if object.contains_key("properties") {
            object.insert("type".to_string(), json!("object"));
        } else if !object.contains_key("enum") {
            object.insert("type".to_string(), strict_any_type());
        }
    }
    if is_array_schema(object) && !object.contains_key("items") {
        object.insert("items".to_string(), json!({}));
    }

    for_each_subschema(object, lower_to_strict);
}

/// Fold `allOf` (rejected by strict mode) into its parent. A single branch
/// merges exactly; several object branches merge their properties and
/// `required` lists (the first branch wins a property collision, which only
/// relaxes the contract). Branches that are not plain object fragments are
/// dropped.
fn merge_all_of(object: &mut Map<String, Value>) {
    let Some(Value::Array(branches)) = object.remove("allOf") else {
        return;
    };
    let single = branches.len() == 1;
    for branch in branches {
        let Value::Object(branch) = branch else {
            continue;
        };
        if !single && !branch.contains_key("properties") {
            continue;
        }
        for (key, value) in branch {
            match (key.as_str(), object.get_mut(&key)) {
                ("properties", Some(Value::Object(existing))) => {
                    if let Value::Object(incoming) = value {
                        for (name, property) in incoming {
                            existing.entry(name).or_insert(property);
                        }
                    }
                }
                ("required", Some(Value::Array(existing))) => {
                    if let Value::Array(incoming) = value {
                        for name in incoming {
                            if !existing.contains(&name) {
                                existing.push(name);
                            }
                        }
                    }
                }
                (_, Some(_)) => {}
                (_, None) => {
                    object.insert(key, value);
                }
            }
        }
    }
}

fn json_type_name(value: &Value) -> Option<&'static str> {
    match value {
        Value::String(_) => Some("string"),
        Value::Bool(_) => Some("boolean"),
        Value::Number(number) if number.is_i64() || number.is_u64() => Some("integer"),
        Value::Number(_) => Some("number"),
        Value::Null => Some("null"),
        Value::Array(_) | Value::Object(_) => None,
    }
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
pub(crate) mod tests {
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
        // `trust` is deliberately absent from the selector: data custody is
        // host policy, never a model-authored delegation field.
        assert!(
            canonical["properties"]["payload"]["properties"]["model"]["properties"]
                .get("trust")
                .is_none(),
            "the delegation selector must not offer a custody field"
        );
        for field in ["min_context_tokens", "optimize"] {
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
        let strict =
            rig::providers::openai::responses_api::ResponsesToolDefinition::strict_function(
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
            let strict =
                rig::providers::openai::responses_api::ResponsesToolDefinition::strict_function(
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
    fn safety_and_risk_tools_are_strict_compatible_after_responses_wire() {
        // The utility safety/injection verdict tools do NOT declare
        // `additionalProperties:false` in canonical form. A strict Responses
        // model (ChatGPT/Codex) requires a closed schema; the dispatch path
        // normalizes these through `definitions_for_wire` before sending
        // (rather than relying on rig's own strict-tool sanitizer) so the
        // safety-critical verdict schemas are closed by Cockpit itself. Guard
        // that the wire normalization closes both.
        for tool in [
            crate::engine::safety_gate::safety_tool(),
            crate::engine::injection_check::risk_tool(),
        ] {
            assert!(
                tool.parameters.get("additionalProperties").is_none(),
                "canonical `{}` is already closed; the wire-normalization test premise is stale",
                tool.name
            );
            let wire = definitions_for_wire(WireApi::Responses, std::slice::from_ref(&tool));
            let wire_tool = wire.as_ref().first().expect("one normalized wire tool");
            assert_objects_are_closed(&wire_tool.parameters);
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
            let strict =
                rig::providers::openai::responses_api::ResponsesToolDefinition::strict_function(
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
            crate::engine::tool::Tool::verbose_parameters(&tool)
                .expect("skill_manage has defensive parameters"),
        ];
        for schema in schemas {
            let transformed = for_responses(&schema);
            let strict =
                rig::providers::openai::responses_api::ResponsesToolDefinition::strict_function(
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
            if let Some(defensive) = tool.verbose_parameters() {
                open_object_violations(
                    &defensive,
                    &format!("{}.verbose_parameters", tool.name()),
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

    // ---- Wire-subset lint -------------------------------------------------

    fn is_typed(object: &Map<String, Value>) -> bool {
        ["type", "anyOf", "oneOf", "$ref", "enum"]
            .iter()
            .any(|key| object.contains_key(*key))
    }

    fn check_common(object: &Map<String, Value>, path: &str, out: &mut Vec<String>) {
        if let Some(format) = object.get("format")
            && !format
                .as_str()
                .is_some_and(|format| STRICT_STRING_FORMATS.contains(&format))
        {
            out.push(format!("{path}: format {format} is not portable"));
        }
        for keyword in NUMERIC_KEYWORDS {
            if let Some(value) = object.get(*keyword)
                && !is_portable_schema_number(value)
            {
                out.push(format!(
                    "{path}: {keyword} {value} is not a portable number"
                ));
            }
        }
        if is_array_schema(object) && !object.get("items").is_some_and(Value::is_object) {
            out.push(format!("{path}: array schema has no items schema"));
        }
    }

    /// One subset rule set, applied to each schema node with its path.
    type NodeCheck = dyn Fn(&Map<String, Value>, &str, &mut Vec<String>);

    fn walk(schema: &Value, path: &str, out: &mut Vec<String>, check: &NodeCheck) {
        let Some(object) = schema.as_object() else {
            out.push(format!("{path}: schema is not an object: {schema}"));
            return;
        };
        check(object, path, out);
        for key in MAP_POSITIONS {
            if let Some(entries) = object.get(*key).and_then(Value::as_object) {
                for (name, child) in entries {
                    walk(child, &format!("{path}.{key}.{name}"), out, check);
                }
            }
        }
        for key in SINGLE_POSITIONS {
            if let Some(child) = object.get(*key).filter(|child| child.is_object()) {
                walk(child, &format!("{path}.{key}"), out, check);
            }
        }
        for key in LIST_POSITIONS {
            if let Some(variants) = object.get(*key).and_then(Value::as_array) {
                for (index, variant) in variants.iter().enumerate() {
                    walk(variant, &format!("{path}.{key}[{index}]"), out, check);
                }
            }
        }
    }

    /// What a canonical built-in schema may use: the portable keywords,
    /// closed or implicitly closed objects, typed leaves, typed arrays.
    fn portable_violations(schema: &Value, path: &str) -> Vec<String> {
        let mut out = Vec::new();
        walk(schema, path, &mut out, &|object, path, out| {
            for key in object.keys() {
                if !PORTABLE_KEYWORDS.contains(&key.as_str()) && !is_extension_keyword(key) {
                    out.push(format!("{path}: `{key}` is outside the portable subset"));
                }
            }
            if let Some(additional) = object.get("additionalProperties")
                && additional != &Value::Bool(false)
            {
                out.push(format!(
                    "{path}: additionalProperties {additional} cannot be carried by strict wires"
                ));
            }
            if !is_typed(object) {
                out.push(format!("{path}: schema has no type"));
            }
            check_common(object, path, out);
        });
        out
    }

    /// What OpenAI strict mode accepts, as observed on the live endpoint.
    fn strict_violations(schema: &Value, path: &str) -> Vec<String> {
        let mut out = Vec::new();
        walk(schema, path, &mut out, &|object, path, out| {
            if object.contains_key("$ref") {
                if object.len() != 1 {
                    out.push(format!("{path}: `$ref` has siblings"));
                }
                return;
            }
            for key in object.keys() {
                let allowed = (PORTABLE_KEYWORDS.contains(&key.as_str()) && key != "oneOf")
                    || key == "definitions"
                    || is_extension_keyword(key);
                if !allowed {
                    out.push(format!("{path}: `{key}` is rejected by strict mode"));
                }
            }
            if !is_typed(object) {
                out.push(format!("{path}: strict mode requires a type"));
            }
            if is_object_schema(object) {
                if object.get("additionalProperties") != Some(&Value::Bool(false)) {
                    out.push(format!("{path}: strict object is not closed"));
                }
                let properties: HashSet<&str> = object
                    .get("properties")
                    .and_then(Value::as_object)
                    .map(|properties| properties.keys().map(String::as_str).collect())
                    .unwrap_or_default();
                let required: HashSet<&str> = object
                    .get("required")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                if !object.contains_key("properties") || properties != required {
                    out.push(format!(
                        "{path}: strict object must require exactly its properties"
                    ));
                }
            }
            check_common(object, path, out);
        });
        out
    }

    /// What every non-strict wire accepts.
    fn lenient_violations(schema: &Value, path: &str) -> Vec<String> {
        let mut out = Vec::new();
        walk(schema, path, &mut out, &|object, path, out| {
            for keyword in NUMERIC_KEYWORDS {
                if let Some(value) = object.get(*keyword)
                    && !is_portable_schema_number(value)
                {
                    out.push(format!("{path}: {keyword} {value} is rejected by OpenAI"));
                }
            }
            if is_array_schema(object) && !object.contains_key("items") {
                out.push(format!("{path}: array without items is rejected by Gemini"));
            }
        });
        out
    }

    /// Strict-wire request body exactly as rig serializes it after Cockpit's
    /// lowering: `with_strict_tools` runs rig's sanitizer over every tool.
    fn strict_wire_parameters(definition: &ToolDefinition) -> Value {
        let lowered = definitions_for_wire(WireApi::Responses, std::slice::from_ref(definition));
        rig::providers::openai::responses_api::ResponsesToolDefinition::strict_function(
            definition.name.clone(),
            definition.description.clone(),
            lowered[0].parameters.clone(),
        )
        .parameters
    }

    /// Every tool definition Cockpit can put on a function-calling wire that
    /// does not depend on a configured agent: each invariant built-in in both
    /// steerings (the media-generation tools join with `extended`), the
    /// recursive delegation `task`, and the utility tools the safety,
    /// injection and leak paths send on their own.
    pub(crate) fn wire_tool_definitions() -> Vec<ToolDefinition> {
        use crate::agents::ToolSteering;
        let mut tools = crate::engine::builtin::invariant_builtin_tools();
        tools.push(std::sync::Arc::new(
            crate::tools::task::TaskTool::with_recursive_subagents(
                &["builder", "explore"],
                2,
                false,
            ),
        ));
        tools.push(std::sync::Arc::new(
            crate::tools::task::TaskTool::with_recursive_subagents(
                &["builder", "explore"],
                2,
                true,
            ),
        ));
        let mut definitions: Vec<ToolDefinition> = tools
            .iter()
            .flat_map(|tool| {
                [ToolSteering::Terse, ToolSteering::Verbose]
                    .map(|steering| crate::engine::tool::definition_of(&**tool, steering, None))
            })
            .collect();
        definitions.push(crate::engine::safety_gate::safety_tool());
        definitions.push(crate::engine::injection_check::risk_tool());
        definitions.push(crate::leak_report::report_leak_tool_definition());
        definitions
    }

    /// Lint every definition against the subsets: the canonical schema is
    /// portable, and each wire's lowering is accepted by that wire.
    pub(crate) fn wire_subset_violations(definitions: &[ToolDefinition]) -> Vec<String> {
        let mut violations = Vec::new();
        for definition in definitions {
            let name = &definition.name;
            violations.extend(portable_violations(
                &definition.parameters,
                &format!("{name} canonical"),
            ));
            violations.extend(strict_violations(
                &strict_wire_parameters(definition),
                &format!("{name} responses"),
            ));
            let completions =
                definitions_for_wire(WireApi::Completions, std::slice::from_ref(definition));
            violations.extend(lenient_violations(
                &completions[0].parameters,
                &format!("{name} completions"),
            ));
        }
        violations.sort();
        violations.dedup();
        violations
    }

    /// Issue #549: `task` (and `generate_image`) shipped `propertyNames`,
    /// `maxProperties` and open-keyed maps, so every OpenAI Responses request
    /// failed with HTTP 400. Every schema Cockpit emits must sit inside the
    /// subset each wire accepts.
    #[test]
    fn every_tool_schema_fits_every_wire_subset() {
        let definitions = wire_tool_definitions();
        assert!(
            definitions
                .iter()
                .any(|definition| definition.name == "task")
        );
        let violations = wire_subset_violations(&definitions);
        assert!(
            violations.is_empty(),
            "tool schemas outside the wire subsets:\n{}",
            violations.join("\n")
        );
    }

    /// The lint is only as good as its detectors: the shapes the live
    /// endpoints rejected must each be reported.
    #[test]
    fn wire_subset_lint_rejects_the_probed_failures() {
        let canonical = json!({
            "type": "object",
            "properties": {
                "args": {
                    "type": "object",
                    "maxProperties": 12,
                    "propertyNames": { "type": "string", "minLength": 1 },
                    "additionalProperties": { "type": "string" }
                },
                "huge": { "type": "integer", "minimum": i64::MIN },
                "path": { "type": "string", "format": "cockpit-path" },
                "list": { "type": "array" },
                "anything": {}
            }
        });
        let portable = portable_violations(&canonical, "$").join("\n");
        for needle in [
            "`propertyNames` is outside the portable subset",
            "`maxProperties` is outside the portable subset",
            "additionalProperties {\"type\":\"string\"} cannot be carried",
            "minimum -9223372036854775808 is not a portable number",
            "format \"cockpit-path\" is not portable",
            "$.properties.list: array schema has no items schema",
            "$.properties.anything: schema has no type",
        ] {
            assert!(
                portable.contains(needle),
                "missing `{needle}` in:\n{portable}"
            );
        }
        let strict = strict_violations(&canonical, "$").join("\n");
        for needle in [
            "`propertyNames` is rejected by strict mode",
            "$.properties.args: strict object is not closed",
            "$: strict object must require exactly its properties",
        ] {
            assert!(strict.contains(needle), "missing `{needle}` in:\n{strict}");
        }
        let lenient = lenient_violations(&canonical, "$").join("\n");
        assert!(lenient.contains("is rejected by OpenAI"), "{lenient}");
        assert!(lenient.contains("rejected by Gemini"), "{lenient}");
    }

    /// A third-party schema full of keywords strict mode rejects is lowered
    /// into the strict subset by dropping them, never by inventing
    /// constraints, and the non-strict lowering only touches the shapes no
    /// endpoint accepts.
    #[test]
    fn foreign_schema_is_lowered_into_each_wire_subset() {
        let foreign = ToolDefinition {
            name: "foreign".to_string(),
            description: "third-party schema".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "path": { "type": "string", "format": "cockpit-path", "minLength": 1 },
                    "tags": { "type": "array", "items": { "type": "string" }, "uniqueItems": true, "contains": { "const": "a" } },
                    "bare": { "type": "array" },
                    "anything": { "description": "free-form" },
                    "kind": { "const": "fixed" },
                    "choice": { "oneOf": [{ "type": "string" }, { "type": "integer" }] },
                    "referenced": { "allOf": [{ "$ref": "#/$defs/item" }], "description": "wrapped ref" },
                    "merged": {
                        "allOf": [
                            { "type": "object", "properties": { "a": { "type": "string" } }, "required": ["a"] },
                            { "type": "object", "properties": { "b": { "type": "integer" } }, "required": ["b"] }
                        ]
                    },
                    "labels": {
                        "type": "object",
                        "propertyNames": { "minLength": 1 },
                        "minProperties": 1,
                        "maxProperties": 4,
                        "patternProperties": { "^x": { "type": "string" } },
                        "additionalProperties": { "type": "string" }
                    },
                    "conditional": {
                        "type": "string",
                        "not": { "const": "x" },
                        "if": { "const": "a" },
                        "then": { "minLength": 2 }
                    },
                    "wide": { "type": "integer", "minimum": i64::MIN, "maximum": i64::MAX },
                    "bounded": { "type": "integer", "minimum": 1, "maximum": 10 }
                },
                "required": ["id"],
                "dependentRequired": { "id": ["path"] },
                "unevaluatedProperties": false,
                "$defs": { "item": { "type": "object", "properties": { "label": { "type": "string" } } } }
            }),
        };

        let violations = wire_subset_violations(std::slice::from_ref(&foreign))
            .into_iter()
            .filter(|violation| !violation.starts_with("foreign canonical"))
            .collect::<Vec<_>>();
        assert!(violations.is_empty(), "{}", violations.join("\n"));

        let strict = for_responses(&foreign.parameters);
        let props = &strict["properties"];
        assert_eq!(props["id"]["format"], "uuid", "accepted formats survive");
        assert!(
            props["path"].get("format").is_none(),
            "unknown format dropped"
        );
        assert_eq!(
            props["path"]["minLength"], 1,
            "accepted constraints survive"
        );
        assert!(props["tags"].get("uniqueItems").is_none());
        assert!(props["tags"].get("contains").is_none());
        assert!(
            props["bare"]["items"].is_object(),
            "bare arrays gain an items schema"
        );
        assert_eq!(
            props["kind"]["anyOf"][0]["type"], "string",
            "const gains its type"
        );
        assert!(props["choice"].get("oneOf").is_none());
        assert!(props["choice"]["anyOf"].is_array());
        assert_eq!(
            props["referenced"]["anyOf"][0],
            json!({ "$ref": "#/$defs/item" })
        );
        assert_eq!(
            props["merged"]["properties"]["a"]["type"], "string",
            "allOf object branches merge"
        );
        assert!(props["merged"]["properties"]["b"].is_object());
        for dropped in [
            "propertyNames",
            "minProperties",
            "maxProperties",
            "patternProperties",
        ] {
            assert!(props["labels"].get(dropped).is_none(), "{dropped} kept");
        }
        for dropped in ["not", "if", "then"] {
            assert!(
                props["conditional"].get(dropped).is_none(),
                "{dropped} kept"
            );
        }
        assert!(props["wide"].get("minimum").is_none());
        assert!(props["wide"].get("maximum").is_none());
        assert_eq!(props["bounded"]["minimum"], 1);
        assert_eq!(props["bounded"]["maximum"], 10);
        assert!(strict.get("dependentRequired").is_none());
        assert!(strict.get("unevaluatedProperties").is_none());

        let completions =
            definitions_for_wire(WireApi::Completions, std::slice::from_ref(&foreign));
        let lenient = &completions[0].parameters;
        assert!(lenient["properties"]["wide"].get("minimum").is_none());
        assert_eq!(
            lenient["properties"]["bounded"],
            foreign.parameters["properties"]["bounded"]
        );
        assert_eq!(
            lenient["properties"]["labels"],
            foreign.parameters["properties"]["labels"]
        );
        assert_eq!(lenient["properties"]["bare"]["items"], json!({}));
        assert_eq!(
            foreign.parameters["properties"]["wide"]["minimum"],
            i64::MIN,
            "canonical mutated"
        );
    }
}
