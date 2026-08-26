use quote::ToTokens;
use syn::{ImplItem, Item, Meta, Visibility};

fn cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr.parse_args::<Meta>().is_ok_and(|meta| match meta {
                Meta::Path(path) => path.is_ident("test"),
                _ => false,
            })
    })
}

fn compact(tokens: impl ToTokens) -> String {
    tokens.to_token_stream().to_string().replace(' ', "")
}

#[test]
fn raw_whole_buffer_mutators_are_private_and_registered_mutators_are_atomic() {
    let source = include_str!("../src/tui/composer.rs");
    let file = syn::parse_file(source).expect("composer source parses");
    let implementation = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Impl(item) if compact(&item.self_ty) == "Composer" && item.trait_.is_none() => {
                Some(item)
            }
            _ => None,
        })
        .expect("Composer implementation");

    let methods = implementation
        .items
        .iter()
        .filter_map(|item| match item {
            ImplItem::Fn(method) => Some((method.sig.ident.to_string(), method)),
            _ => None,
        })
        .collect::<std::collections::HashMap<_, _>>();

    for raw in ["set_unregistered", "clear_unregistered"] {
        let method = methods.get(raw).expect("raw mutator exists");
        assert!(matches!(method.vis, Visibility::Inherited));
    }
    for legacy in ["set", "clear"] {
        let method = methods.get(legacy).expect("test setup mutator exists");
        assert!(cfg_test(&method.attrs), "{legacy} must remain test-only");
    }

    let contracts = [
        (
            "replace_registered",
            "registry.clear();self.set_unregistered(text);",
        ),
        (
            "clear_registered",
            "registry.clear();self.clear_unregistered();",
        ),
        (
            "rebuild_registered",
            "self.set_unregistered(rebuilt.buffer);*registry=rebuilt.registry;",
        ),
    ];
    for (name, body) in contracts {
        let method = methods.get(name).expect("registered mutator exists");
        assert!(matches!(method.vis, Visibility::Restricted(_)));
        let signature = compact(&method.sig);
        assert!(
            signature.contains("registry:&mutcrate::tui::paste::PasteRegistry"),
            "{name} must require its registry: {signature}"
        );
        assert_eq!(compact(&method.block), format!("{{{body}}}"));
    }
}

#[test]
fn app_whole_buffer_helpers_only_delegate_to_registered_mutators() {
    let source = include_str!("../src/tui/app/mod.rs");
    let compact_source = source.replace(char::is_whitespace, "");
    for contract in [
        ".replace_registered(&mutself.paste_registry,text)",
        ".clear_registered(&mutself.paste_registry)",
        ".rebuild_registered(&mutself.paste_registry,rebuilt)",
    ] {
        assert!(compact_source.contains(contract), "missing {contract}");
    }
    for forbidden in ["self.composer.set(", "self.composer.clear("] {
        assert!(!source.contains(forbidden), "raw App mutation: {forbidden}");
    }
}

#[test]
fn standalone_composer_reset_replaces_the_value() {
    let source = include_str!("../src/tui/app/btw_pane.rs");
    assert!(source.contains("self.composer = Composer::new(self.composer.vim_enabled())"));
}
