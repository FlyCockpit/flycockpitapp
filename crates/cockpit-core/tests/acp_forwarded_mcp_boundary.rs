use std::fs;
use std::path::{Path, PathBuf};

use syn::{Fields, Item, ItemEnum, Type, Visibility};

fn public_type_fields(item: &Item) -> Option<(String, Vec<String>)> {
    let (visibility, ident, fields) = match item {
        Item::Struct(item) => (&item.vis, &item.ident, &item.fields),
        _ => return None,
    };
    if !matches!(visibility, Visibility::Public(_)) {
        return None;
    }
    let Fields::Named(fields) = fields else {
        return None;
    };
    Some((
        ident.to_string(),
        fields
            .named
            .iter()
            .map(|field| field.ident.as_ref().unwrap().to_string())
            .collect(),
    ))
}

fn variant_payload_type(variant: &syn::Variant) -> Option<String> {
    let Fields::Unnamed(fields) = &variant.fields else {
        return None;
    };
    let field = fields.unnamed.first()?;
    let Type::Path(path) = &field.ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn type_mentions(ty: &Type, needle: &str) -> bool {
    match ty {
        Type::Path(path) => path.path.segments.iter().any(|segment| {
            segment.ident.to_string().to_ascii_lowercase().contains(needle)
                || match &segment.arguments {
                    syn::PathArguments::AngleBracketed(arguments) => arguments.args.iter().any(|arg| {
                        matches!(arg, syn::GenericArgument::Type(ty) if type_mentions(ty, needle))
                    }),
                    _ => false,
                }
        }),
        Type::Reference(reference) => type_mentions(&reference.elem, needle),
        Type::Tuple(tuple) => tuple.elems.iter().any(|ty| type_mentions(ty, needle)),
        _ => false,
    }
}

fn collect_rust_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("read source directory") {
        let path = entry.expect("read source entry").path();
        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn cockpit_core_has_no_cli_or_acp_transport_schema_dependency() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files);
    assert!(!files.is_empty());
    for path in files {
        let source = fs::read_to_string(&path).expect("read Rust source");
        for forbidden in [
            "apps::cli",
            "apps/cli",
            "agent_client_protocol",
            "jsonrpsee",
            "SessionAdmissionDto",
            "McpServerDto",
        ] {
            assert!(
                !source.contains(forbidden),
                "{} imports forbidden ACP/CLI boundary spelling {forbidden}",
                path.display()
            );
        }
    }
}

#[test]
fn proto_exposes_one_forwarded_mcp_ingress_and_no_public_catalog_lifecycle_rpc() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto = manifest.join("../cockpit-proto/src");
    let mut files = Vec::new();
    collect_rust_files(&proto, &mut files);
    let mut public_records = std::collections::HashMap::new();
    let mut request_enum: Option<ItemEnum> = None;
    for path in files {
        let source = fs::read_to_string(&path).expect("read proto source");
        let file = syn::parse_file(&source).expect("parse proto source");
        for item in &file.items {
            if let Some((name, fields)) = public_type_fields(item) {
                public_records.insert(name, fields);
            }
            if let Item::Enum(item) = item
                && item.ident == "Request"
            {
                request_enum = Some(item.clone());
            }
        }
    }

    // Recognize the closed ingress by its wire-owned shape, not its Rust
    // spelling. Renaming either the ingress or declaration type must not evade
    // this ratchet.
    let mut ingress_types = public_records
        .iter()
        .filter_map(|(name, fields)| {
            (fields
                == &[
                    "version",
                    "declarations",
                    "client_provenance_id",
                    "ingress_request_id",
                ])
                .then(|| name.clone())
        })
        .collect::<Vec<_>>();
    ingress_types.sort();
    assert_eq!(
        ingress_types,
        vec!["AcpForwardedMcpIngressV1".to_string()],
        "exactly one closed declaration ingress shape is allowed"
    );

    let acp_path = proto.join("acp.rs");
    let acp_source = fs::read_to_string(&acp_path).expect("read ACP proto source");
    let acp_file = syn::parse_file(&acp_source).expect("parse ACP proto source");
    let mut forwarded_mcp_public_types = Vec::new();
    for item in acp_file.items {
        let (visibility, ident) = match item {
            Item::Struct(item) => (&item.vis, item.ident),
            Item::Enum(item) => (&item.vis, item.ident),
            Item::Type(item) => (&item.vis, item.ident),
            _ => continue,
        };
        let name = ident.to_string();
        if matches!(visibility, Visibility::Public(_))
            && name.contains("Acp")
            && name.contains("Mcp")
        {
            forwarded_mcp_public_types.push(name);
        }
    }
    forwarded_mcp_public_types.sort();
    assert_eq!(
        forwarded_mcp_public_types,
        vec![
            "AcpForwardedMcpDeclarationV1".to_string(),
            "AcpForwardedMcpIngressV1".to_string(),
            "AcpForwardedMcpTransportV1".to_string(),
            "AcpNameValuePairV1".to_string(),
        ],
        "the closed ingress family is the only public ACP/MCP type family"
    );

    let request_enum = request_enum.expect("Request enum is present");
    let ingress_routes = request_enum
        .variants
        .iter()
        .filter_map(|variant| {
            let payload = variant_payload_type(variant)?;
            let fields = public_records.get(&payload)?;
            fields
                .contains(&"ingress".to_string())
                .then(|| (variant.ident.to_string(), payload, fields.clone()))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        ingress_routes.len(),
        2,
        "only create and attach may carry ingress"
    );
    assert!(
        ingress_routes
            .iter()
            .all(|(_, _, fields)| { fields == &["base".to_string(), "ingress".to_string()] }),
        "ingress routes must retain the exact non-flattened base/ingress shape: {ingress_routes:?}"
    );

    // No sibling public request payload may expose declaration/catalog input.
    // This is shape-based, so lifecycle API renames do not bypass it.
    let declaration_or_catalog_routes = request_enum
        .variants
        .iter()
        .filter_map(|variant| {
            let payload = variant_payload_type(variant)?;
            let fields = public_records.get(&payload)?;
            fields
                .iter()
                .any(|field| {
                    matches!(
                        field.as_str(),
                        "declarations" | "catalog" | "binding" | "epoch"
                    )
                })
                .then(|| variant.ident.to_string())
        })
        .collect::<Vec<_>>();
    assert!(
        declaration_or_catalog_routes.is_empty(),
        "catalog lifecycle/input must remain internal: {declaration_or_catalog_routes:?}"
    );

    let generic_attach = request_enum
        .variants
        .iter()
        .find(|variant| variant.ident == "Attach")
        .expect("generic Request::Attach remains explicit until its owning migration");
    let Fields::Named(attach_fields) = &generic_attach.fields else {
        panic!("generic Request::Attach must remain a closed named-field variant");
    };
    let forbidden_attach_fields = attach_fields
        .named
        .iter()
        .filter_map(|field| {
            let name = field.ident.as_ref().unwrap().to_string();
            let lower = name.to_ascii_lowercase();
            (lower.contains("mcp")
                || lower.contains("catalog")
                || lower.contains("declaration")
                || lower.contains("ingress")
                || type_mentions(&field.ty, "acpforwardedmcp")
                || type_mentions(&field.ty, "acpnamevaluepair"))
            .then_some(name)
        })
        .collect::<Vec<_>>();
    assert!(
        forbidden_attach_fields.is_empty(),
        "generic Request::Attach cannot forward MCP ingress: {forbidden_attach_fields:?}"
    );
}
