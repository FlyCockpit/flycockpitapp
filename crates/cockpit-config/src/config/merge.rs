//! Raw JSON merge machinery shared by config loaders.

use std::collections::HashMap;

use serde_json::Value;

pub fn deep_merge_value(base: &mut Value, overlay: &Value) {
    deep_merge_value_at(base, overlay, &mut Vec::new());
}

// `image_spend` is intentionally absent: spend policy is never a layered
// config value, so it has no atomic-merge path here.
pub(crate) const ATOMIC_CONFIG_VALUE_PATHS: &[&[&str]] =
    &[&["active_model"], &["image_generation"], &["image_sidecar"]];

pub(crate) fn deep_merge_value_at(base: &mut Value, overlay: &Value, path: &mut Vec<String>) {
    if is_atomic_config_value_path(path) {
        *base = overlay.clone();
        return;
    }
    match (base, overlay) {
        (Value::Object(base_map), Value::Object(overlay_map)) => {
            // A fetched/saved catalog is a complete inventory. In particular,
            // an empty list must not resurrect inherited entries after trim.
            let replace_models = path.len() == 2
                && path[0] == "providers"
                && overlay_map.get("models_replace").and_then(Value::as_bool) == Some(true);
            for (k, v) in overlay_map {
                if replace_models && k == "models" {
                    base_map.insert(k.clone(), v.clone());
                    continue;
                }
                match base_map.get_mut(k) {
                    Some(existing) => {
                        path.push(k.clone());
                        deep_merge_value_at(existing, v, path);
                        path.pop();
                    }
                    None => {
                        base_map.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (Value::Array(base_items), Value::Array(overlay_items))
            if is_providers_models_path(path) =>
        {
            merge_model_arrays_by_id(base_items, overlay_items);
        }
        (base_slot, _) => *base_slot = overlay.clone(),
    }
}

pub(crate) fn is_atomic_config_value_path(path: &[String]) -> bool {
    ATOMIC_CONFIG_VALUE_PATHS.iter().any(|candidate| {
        candidate.len() == path.len()
            && candidate
                .iter()
                .zip(path.iter())
                .all(|(expected, actual)| *expected == actual)
    })
}

fn is_providers_models_path(path: &[String]) -> bool {
    path.len() == 3 && path[0] == "providers" && path[2] == "models"
}

fn array_is_id_object_list(items: &[Value]) -> bool {
    items.iter().all(|item| {
        item.as_object()
            .and_then(|object| object.get("id"))
            .and_then(Value::as_str)
            .is_some()
    })
}

pub(crate) fn merge_model_arrays_by_id(base: &mut Vec<Value>, overlay: &[Value]) {
    if overlay.is_empty() {
        return;
    }
    if !array_is_id_object_list(base) || !array_is_id_object_list(overlay) {
        *base = overlay.to_vec();
        return;
    }

    let mut index_by_id: HashMap<String, usize> = HashMap::new();
    let old_base = std::mem::take(base);
    for item in old_base {
        let id = item
            .as_object()
            .and_then(|object| object.get("id"))
            .and_then(Value::as_str)
            .expect("array_is_id_object_list checked base ids")
            .to_string();
        if let Some(previous_idx) = index_by_id.get(&id).copied() {
            base[previous_idx] = item;
        } else {
            index_by_id.insert(id, base.len());
            base.push(item);
        }
    }

    for overlay_item in overlay {
        let id = overlay_item
            .as_object()
            .and_then(|object| object.get("id"))
            .and_then(Value::as_str)
            .expect("array_is_id_object_list checked overlay ids")
            .to_string();
        if let Some(idx) = index_by_id.get(&id).copied() {
            deep_merge_value_at(&mut base[idx], overlay_item, &mut Vec::new());
        } else {
            index_by_id.insert(id, base.len());
            base.push(overlay_item.clone());
        }
    }
}

#[cfg(test)]
mod catalog_membership_tests {
    use super::*;
    #[test]
    fn complete_catalog_replaces_inherited_rows_including_an_empty_catalog() {
        for models in [
            serde_json::json!([]),
            serde_json::json!([{"id":"kept", "name":"fresh"}]),
        ] {
            let mut base = serde_json::json!({"providers":{"p":{"url":"https://example.com", "models":[{"id":"trimmed"},{"id":"kept", "name":"old", "context_length":123}]}}});
            let overlay =
                serde_json::json!({"providers":{"p":{"models_replace":true,"models":models}}});
            deep_merge_value(&mut base, &overlay);
            assert_eq!(base["providers"]["p"]["models"], models);
            assert_eq!(base["providers"]["p"]["url"], "https://example.com");
        }
    }
    #[test]
    fn partial_authored_model_overlays_still_inherit_unmentioned_rows_and_fields() {
        let mut base = serde_json::json!({"providers":{"p":{"models":[{"id":"a", "name":"useful", "context_length":123},{"id":"b"}]}}});
        deep_merge_value(
            &mut base,
            &serde_json::json!({"providers":{"p":{"models":[{"id":"a","favorite":true}]}}}),
        );
        assert_eq!(
            base["providers"]["p"]["models"],
            serde_json::json!([{"id":"a", "name":"useful", "context_length":123, "favorite":true},{"id":"b"}])
        );
    }
}
