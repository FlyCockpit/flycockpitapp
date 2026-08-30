use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use syn::{Fields, Item, ItemEnum, Type, Visibility};

#[derive(Clone, Debug)]
struct PublicField {
    name: String,
    ty: Type,
}

fn public_type_fields(item: &Item) -> Option<(String, Vec<PublicField>)> {
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
            .map(|field| PublicField {
                name: field.ident.as_ref().unwrap().to_string(),
                ty: field.ty.clone(),
            })
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

fn type_idents(ty: &Type, out: &mut Vec<String>) {
    match ty {
        Type::Path(path) => {
            for segment in &path.path.segments {
                out.push(segment.ident.to_string());
                if let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments {
                    for argument in &arguments.args {
                        if let syn::GenericArgument::Type(ty) = argument {
                            type_idents(ty, out);
                        }
                    }
                }
            }
        }
        Type::Reference(reference) => type_idents(&reference.elem, out),
        Type::Tuple(tuple) => {
            for ty in &tuple.elems {
                type_idents(ty, out);
            }
        }
        _ => {}
    }
}

fn type_reaches_any(
    ty: &Type,
    targets: &HashSet<String>,
    public_records: &HashMap<String, Vec<PublicField>>,
    visited: &mut HashSet<String>,
) -> bool {
    let mut idents = Vec::new();
    type_idents(ty, &mut idents);
    for ident in idents {
        if targets.contains(&ident) {
            return true;
        }
        if !visited.insert(ident.clone()) {
            continue;
        }
        if public_records.get(&ident).is_some_and(|fields| {
            fields
                .iter()
                .any(|field| type_reaches_any(&field.ty, targets, public_records, visited))
        }) {
            return true;
        }
    }
    false
}

fn record_reaches_any(
    fields: &[PublicField],
    targets: &HashSet<String>,
    public_records: &HashMap<String, Vec<PublicField>>,
) -> bool {
    fields
        .iter()
        .any(|field| type_reaches_any(&field.ty, targets, public_records, &mut HashSet::new()))
}

fn field_names(fields: &[PublicField]) -> Vec<&str> {
    fields.iter().map(|field| field.name.as_str()).collect()
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

    // Anchor this check at the declaration record, then follow every public
    // type edge. A renamed carrier, added wrapper, or `Attach` field such as
    // `forwarded_servers` therefore cannot bypass the ratchet.
    let declaration_types = public_records
        .iter()
        .filter_map(|(name, fields)| {
            (field_names(fields) == ["name", "transport"]).then(|| name.clone())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        declaration_types,
        vec!["AcpForwardedMcpDeclarationV1".to_string()],
        "exactly one public forwarded-server declaration shape is allowed"
    );
    let declaration_types = declaration_types.into_iter().collect::<HashSet<_>>();

    let mut ingress_types = public_records
        .iter()
        .filter_map(|(name, fields)| {
            fields
                .iter()
                .any(|field| {
                    let mut idents = Vec::new();
                    type_idents(&field.ty, &mut idents);
                    idents.iter().any(|ident| declaration_types.contains(ident))
                })
                .then(|| name.clone())
        })
        .collect::<Vec<_>>();
    ingress_types.sort();
    assert_eq!(
        ingress_types,
        vec!["AcpForwardedMcpIngressV1".to_string()],
        "declarations may enter a public record only through the sole closed ingress"
    );
    let ingress_types = ingress_types.into_iter().collect::<HashSet<_>>();
    let ingress_fields = public_records
        .get("AcpForwardedMcpIngressV1")
        .expect("closed ingress record is public");
    assert_eq!(
        field_names(ingress_fields),
        [
            "version",
            "declarations",
            "client_provenance_id",
            "ingress_request_id",
        ],
        "the sole ingress remains a closed declaration/provenance record"
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
    let mut ingress_routes = request_enum
        .variants
        .iter()
        .filter_map(|variant| {
            let payload = variant_payload_type(variant)?;
            let fields = public_records.get(&payload)?;
            record_reaches_any(fields, &declaration_types, &public_records)
                .then(|| (variant.ident.to_string(), payload, fields.clone()))
        })
        .collect::<Vec<_>>();
    ingress_routes.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(
        ingress_routes
            .iter()
            .map(|(route, _, _)| route.as_str())
            .collect::<Vec<_>>(),
        [
            "AttachExistingCodeRootWithAcpIngressV1",
            "CreateCodeRootWithAcpIngressV1",
        ],
        "only the two composed routes may reach forwarded declarations"
    );
    assert!(
        ingress_routes.iter().all(|(_, _, fields)| {
            field_names(fields) == ["base", "ingress"]
                && fields.iter().any(|field| {
                    let mut idents = Vec::new();
                    type_idents(&field.ty, &mut idents);
                    idents.iter().any(|ident| ingress_types.contains(ident))
                })
        }),
        "ingress routes must retain the exact non-flattened base/ingress shape: {ingress_routes:?}"
    );

    // Public catalog lifecycle cannot reappear as a differently-cased route
    // name. This rejects `Install*`/`Release*` and conventional Rust
    // `install_*`/`release_*` spellings while allowing nouns such as
    // `Installation` and result states such as `Released`.
    let lifecycle_routes = request_enum
        .variants
        .iter()
        .filter_map(|variant| {
            is_catalog_lifecycle_ident(&variant.ident.to_string())
                .then(|| variant.ident.to_string())
        })
        .collect::<Vec<_>>();
    assert!(
        lifecycle_routes.is_empty(),
        "catalog lifecycle must remain internal: {lifecycle_routes:?}"
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
            type_reaches_any(
                &field.ty,
                &declaration_types,
                &public_records,
                &mut HashSet::new(),
            )
            .then_some(name)
        })
        .collect::<Vec<_>>();
    assert!(
        forbidden_attach_fields.is_empty(),
        "generic Request::Attach cannot forward MCP ingress: {forbidden_attach_fields:?}"
    );
}

fn is_catalog_lifecycle_ident(name: &str) -> bool {
    ["Install", "Release", "install", "release"]
        .into_iter()
        .any(|prefix| {
            name == prefix
                || name.strip_prefix(prefix).is_some_and(|suffix| {
                    suffix.starts_with('_')
                        || suffix.starts_with(|character: char| character.is_ascii_uppercase())
                })
        })
}
