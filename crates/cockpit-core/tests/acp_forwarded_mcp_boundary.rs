use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use syn::{Fields, Item, ItemEnum, Type, Visibility};

#[derive(Clone, Debug)]
struct PublicField {
    name: String,
    ty: Type,
    module: Vec<String>,
}

fn symbol(module: &[String], name: &str) -> String {
    if module.is_empty() {
        name.to_string()
    } else {
        format!("{}::{name}", module.join("::"))
    }
}

fn public_type_fields(item: &Item, module: &[String]) -> Option<(String, Vec<PublicField>)> {
    fn fields(prefix: &str, fields: &Fields, module: &[String]) -> Vec<PublicField> {
        match fields {
            Fields::Named(fields) => fields
                .named
                .iter()
                .map(|field| PublicField {
                    name: format!("{prefix}{}", field.ident.as_ref().unwrap()),
                    ty: field.ty.clone(),
                    module: module.to_vec(),
                })
                .collect(),
            Fields::Unnamed(fields) => fields
                .unnamed
                .iter()
                .enumerate()
                .map(|(index, field)| PublicField {
                    name: format!("{prefix}{index}"),
                    ty: field.ty.clone(),
                    module: module.to_vec(),
                })
                .collect(),
            Fields::Unit => Vec::new(),
        }
    }

    match item {
        Item::Struct(item) if matches!(item.vis, Visibility::Public(_)) => Some((
            symbol(module, &item.ident.to_string()),
            fields("", &item.fields, module),
        )),
        Item::Enum(item) if matches!(item.vis, Visibility::Public(_)) => Some((
            symbol(module, &item.ident.to_string()),
            item.variants
                .iter()
                .flat_map(|variant| fields(&format!("{}.", variant.ident), &variant.fields, module))
                .collect(),
        )),
        Item::Type(item) if matches!(item.vis, Visibility::Public(_)) => Some((
            symbol(module, &item.ident.to_string()),
            vec![PublicField {
                name: "alias".to_string(),
                ty: (*item.ty).clone(),
                module: module.to_vec(),
            }],
        )),
        Item::Union(item) if matches!(item.vis, Visibility::Public(_)) => Some((
            symbol(module, &item.ident.to_string()),
            item.fields
                .named
                .iter()
                .map(|field| PublicField {
                    name: field.ident.as_ref().unwrap().to_string(),
                    ty: field.ty.clone(),
                    module: module.to_vec(),
                })
                .collect(),
        )),
        _ => None,
    }
}

fn public_use_aliases(item: &Item, module: &[String]) -> Vec<(String, Vec<PublicField>)> {
    fn collect(
        tree: &syn::UseTree,
        prefix: &mut Vec<String>,
        module: &[String],
        aliases: &mut Vec<(String, Vec<PublicField>)>,
    ) {
        match tree {
            syn::UseTree::Name(name) => {
                let mut source = prefix.clone();
                source.push(name.ident.to_string());
                aliases.push((
                    symbol(module, &name.ident.to_string()),
                    vec![PublicField {
                        name: "alias".to_string(),
                        ty: syn::parse_str(&source.join("::")).expect("use alias type"),
                        module: module.to_vec(),
                    }],
                ));
            }
            syn::UseTree::Rename(rename) => {
                let mut source = prefix.clone();
                source.push(rename.ident.to_string());
                aliases.push((
                    symbol(module, &rename.rename.to_string()),
                    vec![PublicField {
                        name: "alias".to_string(),
                        ty: syn::parse_str(&source.join("::")).expect("use alias type"),
                        module: module.to_vec(),
                    }],
                ));
            }
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                collect(&path.tree, prefix, module, aliases);
                prefix.pop();
            }
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    collect(tree, prefix, module, aliases);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }

    let Item::Use(item) = item else {
        return Vec::new();
    };
    if !matches!(item.vis, Visibility::Public(_)) {
        return Vec::new();
    }
    let mut aliases = Vec::new();
    collect(&item.tree, &mut Vec::new(), module, &mut aliases);
    aliases
}

fn variant_payload_symbol(
    variant: &syn::Variant,
    module: &[String],
    public_records: &HashMap<String, Vec<PublicField>>,
) -> Option<String> {
    let Fields::Unnamed(fields) = &variant.fields else {
        return None;
    };
    let field = fields.unnamed.first()?;
    let mut symbols = Vec::new();
    type_symbols(&field.ty, module, public_records, &mut symbols);
    symbols.sort();
    symbols
        .into_iter()
        .find_map(|symbol| canonical_public_record(&symbol, public_records))
}

fn canonical_public_record(
    symbol: &str,
    public_records: &HashMap<String, Vec<PublicField>>,
) -> Option<String> {
    let mut current = symbol.to_string();
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(current.clone()) {
            return None;
        }
        let fields = public_records.get(&current)?;
        if field_names(fields) != ["alias"] {
            return Some(current);
        }
        let mut targets = Vec::new();
        type_symbols(
            &fields[0].ty,
            &fields[0].module,
            public_records,
            &mut targets,
        );
        targets.sort();
        current = targets.into_iter().find(|target| target != &current)?;
    }
}

fn type_symbols(
    ty: &Type,
    module: &[String],
    public_records: &HashMap<String, Vec<PublicField>>,
    out: &mut Vec<String>,
) {
    match ty {
        Type::Path(path) => {
            let segments = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            let candidates = match segments.first().map(String::as_str) {
                Some("crate") => vec![segments[1..].join("::")],
                Some("self") => vec![symbol(module, &segments[1..].join("::"))],
                Some("super") => vec![symbol(
                    &module[..module.len().saturating_sub(1)],
                    &segments[1..].join("::"),
                )],
                Some(_) => vec![symbol(module, &segments.join("::")), segments.join("::")],
                None => Vec::new(),
            };
            for candidate in candidates {
                if public_records.contains_key(&candidate) {
                    out.push(candidate);
                }
            }
            for segment in &path.path.segments {
                if let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments {
                    for argument in &arguments.args {
                        if let syn::GenericArgument::Type(ty) = argument {
                            type_symbols(ty, module, public_records, out);
                        }
                    }
                }
            }
        }
        Type::Reference(reference) => type_symbols(&reference.elem, module, public_records, out),
        Type::Tuple(tuple) => {
            for ty in &tuple.elems {
                type_symbols(ty, module, public_records, out);
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
    let mut symbols = Vec::new();
    type_symbols(ty, &[], public_records, &mut symbols);
    for symbol in symbols {
        if targets.contains(&symbol) {
            return true;
        }
        if !visited.insert(symbol.clone()) {
            continue;
        }
        if public_records.get(&symbol).is_some_and(|fields| {
            fields.iter().any(|field| {
                type_reaches_any_in_module(
                    &field.ty,
                    &field.module,
                    targets,
                    public_records,
                    visited,
                )
            })
        }) {
            return true;
        }
    }
    false
}

fn type_reaches_any_in_module(
    ty: &Type,
    module: &[String],
    targets: &HashSet<String>,
    public_records: &HashMap<String, Vec<PublicField>>,
    visited: &mut HashSet<String>,
) -> bool {
    let mut symbols = Vec::new();
    type_symbols(ty, module, public_records, &mut symbols);
    for symbol in symbols {
        if targets.contains(&symbol) {
            return true;
        }
        if !visited.insert(symbol.clone()) {
            continue;
        }
        if public_records.get(&symbol).is_some_and(|fields| {
            fields.iter().any(|field| {
                type_reaches_any_in_module(
                    &field.ty,
                    &field.module,
                    targets,
                    public_records,
                    visited,
                )
            })
        }) {
            return true;
        }
    }
    false
}

fn variant_reaches_any(
    variant: &syn::Variant,
    targets: &HashSet<String>,
    public_records: &HashMap<String, Vec<PublicField>>,
) -> bool {
    match &variant.fields {
        Fields::Named(fields) => fields.named.iter().any(|field| {
            type_reaches_any_in_module(&field.ty, &[], targets, public_records, &mut HashSet::new())
        }),
        Fields::Unnamed(fields) => fields.unnamed.iter().any(|field| {
            type_reaches_any_in_module(&field.ty, &[], targets, public_records, &mut HashSet::new())
        }),
        Fields::Unit => false,
    }
}

fn variant_reaches_any_in_module(
    variant: &syn::Variant,
    module: &[String],
    targets: &HashSet<String>,
    public_records: &HashMap<String, Vec<PublicField>>,
) -> bool {
    match &variant.fields {
        Fields::Named(fields) => fields.named.iter().any(|field| {
            type_reaches_any_in_module(
                &field.ty,
                module,
                targets,
                public_records,
                &mut HashSet::new(),
            )
        }),
        Fields::Unnamed(fields) => fields.unnamed.iter().any(|field| {
            type_reaches_any_in_module(
                &field.ty,
                module,
                targets,
                public_records,
                &mut HashSet::new(),
            )
        }),
        Fields::Unit => false,
    }
}

fn field_names(fields: &[PublicField]) -> Vec<&str> {
    fields.iter().map(|field| field.name.as_str()).collect()
}

fn collect_rust_files(root: &Path, files: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(root)
        .expect("read source directory")
        .map(|entry| entry.expect("read source entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn source_module(root: &Path, path: &Path) -> Vec<String> {
    let relative = path.strip_prefix(root).expect("source path is under root");
    let mut module = relative
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .map(str::to_string)
        .collect::<Vec<_>>();
    let file = module.pop().expect("Rust source has a file name");
    if file != "lib.rs" && file != "mod.rs" {
        module.push(file.trim_end_matches(".rs").to_string());
    }
    module
}

fn collect_public_records(
    items: &[Item],
    module: &[String],
    records: &mut HashMap<String, Vec<PublicField>>,
) {
    for item in items {
        if let Some((name, fields)) = public_type_fields(item, module) {
            assert!(
                records.insert(name.clone(), fields).is_none(),
                "duplicate public symbol {name}"
            );
        }
        for (name, fields) in public_use_aliases(item, module) {
            assert!(
                records.insert(name.clone(), fields).is_none(),
                "duplicate public reexport {name}"
            );
        }
        if let Item::Mod(item) = item
            && let Some((_, nested)) = &item.content
        {
            let mut nested_module = module.to_vec();
            nested_module.push(item.ident.to_string());
            collect_public_records(nested, &nested_module, records);
        }
    }
}

#[test]
fn public_wrapper_graph_reaches_aliases_and_named_or_tuple_enum_variants() {
    let file = syn::parse_file(
        r#"
        pub struct AcpForwardedMcpDeclarationV1 { pub name: String, pub transport: String }
        pub type ForwardedAlias = AcpForwardedMcpDeclarationV1;
        pub enum NamedWrapper { Forwarded { ingress: ForwardedAlias } }
        pub enum TupleWrapper(ForwardedAlias);
        pub enum Request {
            Attach { payload: NamedWrapper },
            Other(TupleWrapper),
        }
        "#,
    )
    .expect("synthetic public protocol parses");
    let mut public_records = HashMap::new();
    let mut request = None;
    for item in &file.items {
        if let Some((name, fields)) = public_type_fields(item, &[]) {
            public_records.insert(name, fields);
        }
        if let Item::Enum(item) = item
            && item.ident == "Request"
        {
            request = Some(item);
        }
    }
    let declarations = ["AcpForwardedMcpDeclarationV1".to_string()]
        .into_iter()
        .collect::<HashSet<_>>();
    let request = request.expect("synthetic Request enum");
    let attach = request
        .variants
        .iter()
        .find(|variant| variant.ident == "Attach")
        .expect("synthetic generic Attach variant");
    let other = request
        .variants
        .iter()
        .find(|variant| variant.ident == "Other")
        .expect("synthetic tuple route variant");

    assert!(
        type_reaches_any(
            &syn::parse_str::<Type>("ForwardedAlias").expect("synthetic alias type"),
            &declarations,
            &public_records,
            &mut HashSet::new(),
        ),
        "public type aliases must be followed"
    );
    assert!(
        variant_reaches_any(attach, &declarations, &public_records),
        "a named generic Attach wrapper must be rejected"
    );
    assert!(
        variant_reaches_any(other, &declarations, &public_records),
        "a tuple enum wrapper must be rejected"
    );
}

#[test]
fn public_wrapper_graph_resolves_module_paths_and_reexports_without_name_collisions() {
    let file = syn::parse_file(
        r#"
        mod forwarded { pub struct Declaration { pub name: String, pub transport: String } }
        mod decoy { pub struct Declaration { pub ignored: String } }
        mod surface {
            pub use super::forwarded::Declaration as Forwarded;
            pub struct Payload { pub ingress: Forwarded }
        }
        pub use surface::Payload as ExportedPayload;
        "#,
    )
    .expect("synthetic module/reexport protocol parses");
    let mut public_records = HashMap::new();
    collect_public_records(&file.items, &[], &mut public_records);

    let forwarded = ["forwarded::Declaration".to_string()]
        .into_iter()
        .collect::<HashSet<_>>();
    let decoy = ["decoy::Declaration".to_string()]
        .into_iter()
        .collect::<HashSet<_>>();
    let exported: Type = syn::parse_str("ExportedPayload").expect("synthetic exported type");
    assert!(
        type_reaches_any(&exported, &forwarded, &public_records, &mut HashSet::new()),
        "the reexport must resolve to its declaration's module path"
    );
    assert!(
        !type_reaches_any(&exported, &decoy, &public_records, &mut HashSet::new()),
        "same-named declarations in another module must not collide"
    );
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
    let mut request_enum: Option<(ItemEnum, Vec<String>)> = None;
    for path in files {
        let source = fs::read_to_string(&path).expect("read proto source");
        let file = syn::parse_file(&source).expect("parse proto source");
        let module = source_module(&proto, &path);
        collect_public_records(&file.items, &module, &mut public_records);
        for item in &file.items {
            if let Item::Enum(item) = item
                && item.ident == "Request"
            {
                request_enum = Some((item.clone(), module.clone()));
            }
        }
    }

    // Anchor this check at the declaration record, then follow every public
    // type edge. A renamed carrier, added wrapper, or `Attach` field such as
    // `forwarded_servers` therefore cannot bypass the ratchet.
    let mut declaration_types = public_records
        .iter()
        .filter_map(|(name, fields)| {
            (field_names(fields) == ["name", "transport"]).then(|| name.clone())
        })
        .collect::<Vec<_>>();
    declaration_types.sort();
    assert_eq!(
        declaration_types,
        vec!["acp::AcpForwardedMcpDeclarationV1".to_string()],
        "exactly one public forwarded-server declaration shape is allowed"
    );
    let declaration_types = declaration_types.into_iter().collect::<HashSet<_>>();

    let mut ingress_types = public_records
        .iter()
        .filter_map(|(name, fields)| {
            (field_names(fields)
                == [
                    "version",
                    "declarations",
                    "client_provenance_id",
                    "ingress_request_id",
                ])
                && fields
                    .iter()
                    .any(|field| {
                        type_reaches_any_in_module(
                            &field.ty,
                            &field.module,
                            &declaration_types,
                            &public_records,
                            &mut HashSet::new(),
                        )
                    })
                    .then(|| name.clone())
        })
        .collect::<Vec<_>>();
    ingress_types.sort();
    assert_eq!(
        ingress_types,
        vec!["acp::AcpForwardedMcpIngressV1".to_string()],
        "declarations may enter a public record only through the sole closed ingress"
    );
    let ingress_types = ingress_types.into_iter().collect::<HashSet<_>>();
    let ingress_fields = public_records
        .get("acp::AcpForwardedMcpIngressV1")
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

    let (request_enum, request_module) = request_enum.expect("Request enum is present");
    let mut ingress_routes = request_enum
        .variants
        .iter()
        .filter_map(|variant| {
            variant_reaches_any_in_module(
                variant,
                &request_module,
                &declaration_types,
                &public_records,
            )
            .then(|| variant.ident.to_string())
        })
        .collect::<Vec<_>>();
    ingress_routes.sort();
    assert_eq!(
        ingress_routes,
        [
            "AttachExistingCodeRootWithAcpIngressV1",
            "CreateCodeRootWithAcpIngressV1",
        ],
        "only the two composed routes may reach forwarded declarations"
    );
    let composed_payloads = [
        "CreateCodeRootWithAcpIngressV1",
        "AttachExistingCodeRootWithAcpIngressV1",
    ]
    .into_iter()
    .map(|route| {
        let variant = request_enum
            .variants
            .iter()
            .find(|variant| variant.ident == route)
            .expect("composed request route is present");
        let payload = variant_payload_symbol(variant, &request_module, &public_records)
            .expect("composed route wraps one public payload");
        public_records
            .get(&payload)
            .expect("composed route payload is public")
    })
    .collect::<Vec<_>>();
    assert!(
        composed_payloads.iter().all(|fields| {
            field_names(fields) == ["base", "ingress"]
                && fields.iter().any(|field| {
                    type_reaches_any_in_module(
                        &field.ty,
                        &field.module,
                        &ingress_types,
                        &public_records,
                        &mut HashSet::new(),
                    )
                })
        }),
        "ingress routes must retain the exact non-flattened base/ingress shape"
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
    assert!(
        !variant_reaches_any_in_module(
            generic_attach,
            &request_module,
            &declaration_types,
            &public_records,
        ),
        "generic Request::Attach cannot forward MCP ingress through a public alias or wrapper"
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
