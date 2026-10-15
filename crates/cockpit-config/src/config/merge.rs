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
                    None if v.is_object()
                        && ((path.len() == 1 && path[0] == "providers")
                            || (path.is_empty() && k == "providers")) =>
                    {
                        let mut provider = Value::Object(Default::default());
                        path.push(k.clone());
                        deep_merge_value_at(&mut provider, v, path);
                        path.pop();
                        base_map.insert(k.clone(), provider);
                    }
                    None => {
                        base_map.insert(k.clone(), v.clone());
                    }
                }
            }
            if path.len() == 2 && path[0] == "providers" {
                apply_model_layer_edits(base_map);
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

fn apply_model_layer_edits(provider: &mut serde_json::Map<String, Value>) {
    // Malformed edits remain present for typed config validation. Valid sparse
    // rows and explicit membership have the same semantics at every loader.
    if let Some(raw) = provider.get("model_field_patches") {
        let Ok(patches) =
            serde_json::from_value::<Vec<super::providers::ModelEntryFieldPatch>>(raw.clone())
        else {
            return;
        };
        if patches
            .iter()
            .any(|patch| patch.set.contains_key("id") || patch.remove.iter().any(|key| key == "id"))
        {
            return;
        }
        let models = provider
            .entry("models")
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Some(models) = models.as_array_mut() {
            for patch in patches {
                let index = models.iter().position(|model| {
                    model.get("id").and_then(Value::as_str) == Some(patch.id.as_str())
                });
                let index = index.unwrap_or_else(|| {
                    models.push(serde_json::json!({"id": patch.id}));
                    models.len() - 1
                });
                patch
                    .apply_value(&mut models[index])
                    .expect("validated model field patch");
            }
        }
        provider.remove("model_field_patches");
    }
    if let Some(raw) = provider.get("model_membership") {
        let Ok(patch) =
            serde_json::from_value::<super::providers::ModelMembershipPatch>(raw.clone())
        else {
            return;
        };
        if let Some(models) = provider.get_mut("models").and_then(Value::as_array_mut) {
            if !array_is_id_object_list(models) {
                return;
            }
            models.retain(|row| {
                !patch
                    .deletes
                    .iter()
                    .any(|id| row.get("id").and_then(Value::as_str) == Some(id.as_str()))
            });
            // Match the ordinary merge-by-ID rule: last image wins, first
            // position wins. Repeated raw IDs must not panic during replay.
            let mut seen = std::collections::BTreeSet::new();
            let mut order = models
                .iter()
                .filter_map(|row| row.get("id")?.as_str().map(str::to_owned))
                .filter(|id| seen.insert(id.clone()))
                .collect::<Vec<_>>();
            for placement in patch.placements {
                if placement.apply(&mut order, false).is_err() {
                    return;
                }
            }
            let mut rows = std::mem::take(models)
                .into_iter()
                .filter_map(|row| Some((row.get("id")?.as_str()?.to_owned(), row)))
                .collect::<std::collections::BTreeMap<_, _>>();
            *models = order
                .iter()
                .map(|id| rows.remove(id).expect("existing model placement"))
                .collect();
        }
        provider.remove("model_membership");
    }
    if let Some(raw) = provider.get("model_order") {
        let Ok(order) = serde_json::from_value::<Vec<String>>(raw.clone()) else {
            return;
        };
        if order
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != order.len()
        {
            return;
        }
        let rows = provider
            .entry("models")
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Some(models) = rows.as_array_mut() {
            let mut remaining = std::mem::take(models)
                .into_iter()
                .filter_map(|model| Some((model.get("id")?.as_str()?.to_owned(), model)))
                .collect::<std::collections::BTreeMap<_, _>>();
            *models = order
                .iter()
                .map(|id| {
                    remaining
                        .remove(id)
                        .unwrap_or_else(|| serde_json::json!({"id":id}))
                })
                .collect();
        }
        provider.remove("model_order");
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
    fn sparse_membership_replay_preserves_unique_rows_without_resurrecting_missing_rows() {
        let overlay = serde_json::json!({"providers":{"p":{"model_membership":{"deletes":["gone"],"placements":[{"id":"b","after":null},{"id":"missing","after":"a"}]}}}});
        let mut base = serde_json::json!({"providers":{"p":{"models":[{"id":"a","name":"first"},{"id":"a","name":"last"},{"id":"b"},{"id":"gone"}]}}});
        deep_merge_value(&mut base, &overlay);
        assert_eq!(
            base["providers"]["p"]["models"],
            serde_json::json!([{"id":"b"},{"id":"a","name":"last"}])
        );
        assert!(base["providers"]["p"].get("model_membership").is_none());
        let mut refreshed =
            serde_json::json!({"providers":{"p":{"models":[{"id":"a","name":"fresh"}]}}});
        deep_merge_value(&mut refreshed, &overlay);
        assert_eq!(
            refreshed["providers"]["p"]["models"],
            serde_json::json!([{"id":"a","name":"fresh"}]),
            "missing lower rows are never recreated by placements"
        );
        for invalid in [
            serde_json::json!({"model_membership":{"deletes":["a","a"]}}),
            serde_json::json!({"model_membership":{"placements":[{"id":"a","after":"a"}]}}),
            serde_json::json!({"model_membership":{"deletes":["a"],"placements":[{"id":"a","after":null}]}}),
        ] {
            assert!(
                serde_json::from_value::<super::super::providers::ProviderEntry>(invalid).is_err()
            );
        }
    }

    #[test]
    fn complete_row_edits_reset_only_the_target_model_and_preserve_its_sibling() {
        let mut base = serde_json::json!({"providers":{"p":{"models":[{"id":"m","name":"old","extra":{"old":true}},{"id":"sibling","name":"keep"}]}}});
        deep_merge_value(
            &mut base,
            &serde_json::json!({"providers":{"p":{"model_field_patches":[{"id":"m","replace":true,"set":{"favorite":true},"remove":[]}]}}}),
        );
        assert_eq!(
            base["providers"]["p"]["models"],
            serde_json::json!([{"id":"m","favorite":true},{"id":"sibling","name":"keep"}])
        );
    }

    #[test]
    fn sparse_owner_fields_and_explicit_membership_survive_lower_catalog_removal() {
        let overlay = serde_json::json!({"providers":{"p":{"model_field_patches":[{"id":"m","set":{"favorite":true},"remove":[]}],"model_order":["m","manual"]}}});
        for lower in [
            serde_json::json!({}),
            serde_json::json!({"providers":{"p":{"models":[]}}}),
        ] {
            let mut merged = lower;
            deep_merge_value(&mut merged, &overlay);
            assert_eq!(
                merged["providers"]["p"]["models"],
                serde_json::json!([{"id":"m","favorite":true},{"id":"manual"}])
            );
            assert!(
                merged["providers"]["p"]
                    .get("model_field_patches")
                    .is_none()
            );
            assert!(merged["providers"]["p"].get("model_order").is_none());
        }
        let mut membership_only = serde_json::json!({});
        deep_merge_value(
            &mut membership_only,
            &serde_json::json!({"providers":{"p":{"model_order":["only"]}}}),
        );
        assert_eq!(
            membership_only["providers"]["p"]["models"],
            serde_json::json!([{"id":"only"}])
        );
        let invalid = serde_json::json!({"id":"m","set":{"id":"other"},"remove":[]});
        assert!(
            serde_json::from_value::<super::super::providers::ModelEntryFieldPatch>(invalid)
                .is_err()
        );
        let invalid = serde_json::json!({"model_order":["m","m"]});
        assert!(serde_json::from_value::<super::super::providers::ProviderEntry>(invalid).is_err());
    }

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
