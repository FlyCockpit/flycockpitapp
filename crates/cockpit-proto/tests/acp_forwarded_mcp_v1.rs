use cockpit_proto::{Request, Response};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/acp_forwarded_mcp_v1/routes.json"))
        .expect("ACP forwarded-MCP fixture is valid JSON")
}

fn assert_exact_round_trip<T: DeserializeOwned + serde::Serialize>(value: &Value) {
    let decoded: T = serde_json::from_value(value.clone()).expect("fixture matches wire type");
    assert_eq!(serde_json::to_value(decoded).unwrap(), *value);
}

fn with_extra_at(value: &Value, path: &[&str]) -> Value {
    let mut changed = value.clone();
    let mut current = &mut changed;
    for segment in path {
        current = current.get_mut(*segment).expect("fixture path exists");
    }
    current
        .as_object_mut()
        .expect("fixture path names an object")
        .insert("forbidden_extra".to_string(), json!(true));
    changed
}

#[test]
fn canonical_minimal_and_maximal_route_fixtures_are_object_exact() {
    let fixture = fixture();
    for name in [
        "create_min",
        "create_max",
        "attach_min",
        "attach_max",
        "close_min",
        "close_max",
    ] {
        assert_exact_round_trip::<Request>(&fixture["requests"][name]);
    }
    for name in ["create", "attach", "close_closed", "close_already_closed"] {
        assert_exact_round_trip::<Response>(&fixture["responses"][name]);
    }
}

#[test]
fn every_request_and_response_depth_rejects_unknown_fields() {
    let fixture = fixture();
    let create = &fixture["requests"]["create_max"];
    for path in [
        vec!["params"],
        vec!["params", "base"],
        vec!["params", "base", "workspace_selector"],
        vec!["params", "ingress"],
        vec!["params", "ingress", "declarations", "0"],
        vec!["params", "ingress", "declarations", "0", "transport"],
    ] {
        let changed = if path.contains(&"0") {
            let mut changed = create.clone();
            let declaration = changed["params"]["ingress"]["declarations"]
                .as_array_mut()
                .unwrap()
                .first_mut()
                .unwrap();
            let target = if path.last() == Some(&"transport") {
                &mut declaration["transport"]
            } else {
                declaration
            };
            target
                .as_object_mut()
                .unwrap()
                .insert("forbidden_extra".to_string(), json!(true));
            changed
        } else {
            with_extra_at(create, &path)
        };
        assert!(serde_json::from_value::<Request>(changed).is_err());
    }

    for name in ["create", "attach", "close_closed", "close_already_closed"] {
        let response = &fixture["responses"][name];
        let mut paths = vec![vec!["data"]];
        if matches!(name, "create" | "attach") {
            paths.extend([
                vec!["data", "base"],
                vec!["data", "base", "attachment"],
                vec!["data", "base", "root"],
            ]);
        }
        for path in paths {
            assert!(serde_json::from_value::<Response>(with_extra_at(response, &path)).is_err());
        }
    }
}

#[test]
fn caller_authority_and_catalog_fields_have_no_ingress_slot() {
    let fixture = fixture();
    let create = &fixture["requests"]["create_min"];
    for forbidden in [
        "principal",
        "origin",
        "trust",
        "profile",
        "canonical_identity",
        "capture_generation",
        "epoch",
        "binding_id",
        "ownership_handle",
        "root_id",
    ] {
        let mut changed = create.clone();
        changed["params"]
            .as_object_mut()
            .unwrap()
            .insert(forbidden.to_string(), json!("caller-value"));
        assert!(serde_json::from_value::<Request>(changed).is_err());
    }
}

#[test]
fn duplicate_json_members_fail_before_semantic_dispatch() {
    let duplicate_outer = r#"{
        "request":"close_acp_code_root_attachment_v1",
        "params":{"attachment_capability":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","client_request_id":"one"},
        "params":{"attachment_capability":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","client_request_id":"two"}
    }"#;
    assert!(serde_json::from_str::<Request>(duplicate_outer).is_err());
}

#[test]
fn fixture_inventory_contains_no_generic_json_or_authority_field() {
    fn visit(value: &Value, keys: &mut Vec<String>) {
        match value {
            Value::Object(object) => {
                keys.extend(object.keys().cloned());
                for value in object.values() {
                    visit(value, keys);
                }
            }
            Value::Array(values) => {
                for value in values {
                    visit(value, keys);
                }
            }
            _ => {}
        }
    }
    let mut keys = Vec::new();
    visit(&fixture()["requests"], &mut keys);
    let forbidden = ["metadata", "_meta", "credential_ref", "binding_id", "epoch"];
    assert!(!keys.iter().any(|key| forbidden.contains(&key.as_str())));
}
