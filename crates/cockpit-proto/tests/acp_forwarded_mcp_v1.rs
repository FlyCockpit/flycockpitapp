use cockpit_proto::{Request, Response};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn minimal_fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/acp_forwarded_mcp_v1/routes.json"))
        .expect("ACP forwarded-MCP fixture is valid JSON")
}

fn maximal_fixture() -> Value {
    serde_json::from_str(include_str!(
        "fixtures/acp_forwarded_mcp_v1/routes_max.json"
    ))
    .expect("maximal ACP forwarded-MCP fixture is valid JSON")
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
    let minimal = minimal_fixture();
    let maximal = maximal_fixture();
    for name in ["create_min", "attach_min", "close_min"] {
        assert_exact_round_trip::<Request>(&minimal["requests"][name]);
    }
    for name in ["create_max", "attach_max", "close_max"] {
        assert_exact_round_trip::<Request>(&maximal["requests"][name]);
    }
    for name in ["create", "attach", "close_closed", "close_already_closed"] {
        assert_exact_round_trip::<Response>(&minimal["responses"][name]);
    }
}

#[test]
fn maximal_route_fixtures_hit_closed_ingress_and_identity_boundaries() {
    let fixture = maximal_fixture();
    let mut ingress_assertions = 0;
    for name in ["create_max", "attach_max"] {
        let request: Request = serde_json::from_value(fixture["requests"][name].clone()).unwrap();
        let ingress = match request {
            Request::CreateCodeRootWithAcpIngressV1(request) => {
                assert_eq!(request.base.logical_client_id.as_str().len(), 128);
                assert_eq!(request.base.client_request_id.as_str().len(), 128);
                request.ingress
            }
            Request::AttachExistingCodeRootWithAcpIngressV1(request) => {
                assert_eq!(request.base.logical_client_id.as_str().len(), 128);
                assert_eq!(request.base.client_request_id.as_str().len(), 128);
                request.ingress
            }
            _ => panic!("{name} must decode to its exact ACP composed route"),
        };
        assert_eq!(ingress.client_provenance_id.as_str().len(), 128);
        assert_eq!(ingress.ingress_request_id.as_str().len(), 128);
        assert_eq!(ingress.declarations.len(), 32);
        assert_eq!(
            serde_json::to_vec(&ingress.declarations).unwrap().len(),
            1_048_576
        );
        assert!(
            ingress
                .declarations
                .iter()
                .any(|declaration| serde_json::to_vec(declaration).unwrap().len() == 131_072)
        );
        assert!(ingress.declarations.iter().all(|declaration| {
            declaration.name.chars().count() == 64 && declaration.name.len() == 64
        }));
        assert!(
            ingress
                .declarations
                .iter()
                .any(|declaration| match &declaration.transport {
                    cockpit_proto::AcpForwardedMcpTransportV1::Stdio { command, args, env } => {
                        command.len() == 4_096
                            && args.len() == 64
                            && env.len() == 64
                            && args.iter().any(|argument| argument.len() == 8_192)
                    }
                    _ => false,
                })
        );
        assert!(
            ingress
                .declarations
                .iter()
                .any(|declaration| match &declaration.transport {
                    cockpit_proto::AcpForwardedMcpTransportV1::Http { url, headers }
                    | cockpit_proto::AcpForwardedMcpTransportV1::Sse { url, headers } => {
                        url.len() == 4_096
                            && headers.len() == 64
                            && headers.iter().any(|header| header.value.len() == 8_192)
                    }
                    _ => false,
                })
        );
        ingress_assertions += 1;
    }
    assert_eq!(ingress_assertions, 2);

    let close: Request = serde_json::from_value(fixture["requests"]["close_max"].clone()).unwrap();
    let Request::CloseAcpCodeRootAttachmentV1(close) = close else {
        panic!("close_max must decode to the ACP close route");
    };
    assert_eq!(close.attachment_capability.expose_opaque().len(), 128);
    assert_eq!(close.client_request_id.as_str().len(), 128);
}

#[test]
fn every_request_and_response_depth_rejects_unknown_fields() {
    let fixture = maximal_fixture();
    let minimal = minimal_fixture();
    for (name, paths) in [
        (
            "create_max",
            vec![
                vec![],
                vec!["params"],
                vec!["params", "base"],
                vec!["params", "base", "workspace_selector"],
                vec!["params", "base", "options"],
                vec!["params", "ingress"],
                vec!["params", "ingress", "declarations", "0"],
                vec!["params", "ingress", "declarations", "0", "transport"],
            ],
        ),
        (
            "attach_max",
            vec![
                vec![],
                vec!["params"],
                vec!["params", "base"],
                vec!["params", "base", "options"],
                vec!["params", "ingress"],
                vec!["params", "ingress", "declarations", "0"],
                vec!["params", "ingress", "declarations", "0", "transport"],
            ],
        ),
        ("close_max", vec![vec![], vec!["params"]]),
    ] {
        let request = &fixture["requests"][name];
        for path in paths {
            assert!(
                serde_json::from_value::<Request>(with_extra_at(request, &path)).is_err(),
                "{name} accepted unknown field at {path:?}"
            );
        }
    }

    for name in ["create", "attach", "close_closed", "close_already_closed"] {
        let response = &minimal["responses"][name];
        let mut paths = vec![vec![], vec!["data"]];
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
    let fixture = minimal_fixture();
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
    visit(&minimal_fixture()["requests"], &mut keys);
    visit(&maximal_fixture()["requests"], &mut keys);
    let forbidden = ["metadata", "_meta", "credential_ref", "binding_id", "epoch"];
    assert!(!keys.iter().any(|key| forbidden.contains(&key.as_str())));
}
