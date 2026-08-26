use quote::ToTokens;
use syn::{Fields, ImplItem, Item, Meta, Visibility};

const COMPOSER_SOURCE: &str = include_str!("../src/tui/composer.rs");
const OWNER_SOURCE: &str = include_str!("../src/tui/composer/registered.rs");
const APP_SOURCE: &str = include_str!("../src/tui/app/mod.rs");
const APP_INPUT_SOURCE: &str = include_str!("../src/tui/app/input.rs");

fn compact(tokens: impl ToTokens) -> String {
    tokens.to_token_stream().to_string().replace(' ', "")
}

fn cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr.parse_args::<Meta>().is_ok_and(|meta| match meta {
                Meta::Path(path) => path.is_ident("test"),
                _ => false,
            })
    })
}

fn named_struct<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemStruct {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Struct(item) if item.ident == name => Some(item),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{name} struct exists"))
}

fn inherent_impl<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemImpl {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Impl(item) if item.trait_.is_none() && compact(&item.self_ty) == name => {
                Some(item)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("{name} implementation exists"))
}

fn app_authority_field_types(source: &str) -> Vec<String> {
    let file = syn::parse_file(source).expect("app source parses");
    let Fields::Named(fields) = &named_struct(&file, "App").fields else {
        panic!("App has named fields");
    };
    fields
        .named
        .iter()
        .map(|field| compact(&field.ty))
        .filter(|ty| {
            ty.ends_with("Composer")
                || ty.ends_with("RegisteredComposer")
                || ty.ends_with("PasteRegistry")
        })
        .collect()
}

fn has_deref_mut(source: &str) -> bool {
    let file = syn::parse_file(source).expect("owner source parses");
    file.items.iter().any(|item| match item {
        Item::Impl(item) => item
            .trait_
            .as_ref()
            .is_some_and(|(_, path, _)| compact(path).ends_with("DerefMut")),
        _ => false,
    })
}

fn has_mutable_escape_trait(source: &str) -> bool {
    let file = syn::parse_file(source).expect("owner source parses");
    file.items.iter().any(|item| match item {
        Item::Impl(item) => item.trait_.as_ref().is_some_and(|(_, path, _)| {
            ["DerefMut", "AsMut", "BorrowMut", "IndexMut"]
                .iter()
                .any(|name| compact(path).ends_with(name))
        }),
        _ => false,
    })
}

#[test]
fn registered_composer_is_the_exact_private_two_value_owner() {
    let file = syn::parse_file(OWNER_SOURCE).expect("owner source parses");
    let owner = named_struct(&file, "RegisteredComposer");
    assert!(matches!(owner.vis, Visibility::Restricted(_)));
    let Fields::Named(fields) = &owner.fields else {
        panic!("RegisteredComposer has named fields");
    };
    let actual = fields
        .named
        .iter()
        .map(|field| {
            (
                field.ident.as_ref().expect("named field").to_string(),
                compact(&field.ty),
                matches!(field.vis, Visibility::Inherited),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![
            ("composer".into(), "Composer".into(), true),
            ("paste_registry".into(), "PasteRegistry".into(), true),
        ]
    );

    let deref = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Impl(item)
                if item
                    .trait_
                    .as_ref()
                    .is_some_and(|(_, path, _)| compact(path).ends_with("Deref")) =>
            {
                Some(item)
            }
            _ => None,
        })
        .expect("immutable Deref implementation");
    let target = deref.items.iter().find_map(|item| match item {
        ImplItem::Type(item) if item.ident == "Target" => Some(compact(&item.ty)),
        _ => None,
    });
    assert_eq!(target.as_deref(), Some("Composer"));
    assert!(
        !has_deref_mut(OWNER_SOURCE),
        "DerefMut would expose raw edits"
    );
    assert!(
        !has_mutable_escape_trait(OWNER_SOURCE),
        "mutable component escape trait"
    );
}

#[test]
fn owner_api_is_closed_and_never_lends_mutable_components() {
    let file = syn::parse_file(OWNER_SOURCE).expect("owner source parses");
    let motion = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Enum(item) if item.ident == "ComposerMotion" => Some(item),
            _ => None,
        })
        .expect("closed motion enum exists");
    let motion_variants = motion
        .variants
        .iter()
        .map(|variant| variant.ident.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        motion_variants,
        vec![
            "Up",
            "Down",
            "LineStart",
            "LineEnd",
            "BufferStart",
            "BufferEnd",
            "WordForward",
            "WordBackward",
            "WordEnd",
            "WordEndBackward",
            "MatchBracket",
            "RepeatFind",
            "Absolute",
        ]
    );
    let implementation = inherent_impl(&file, "RegisteredComposer");
    let mut public_methods = implementation
        .items
        .iter()
        .filter_map(|item| match item {
            ImplItem::Fn(method) if !matches!(method.vis, Visibility::Inherited) => {
                let signature = compact(&method.sig);
                assert!(
                    !signature.contains("&mutComposer")
                        && !signature.contains("&mutPasteRegistry")
                        && !signature.contains("->&mut")
                        && !signature.contains("->&Composer")
                        && !signature.contains("->&PasteRegistry"),
                    "{} lends mutable authority: {signature}",
                    method.sig.ident
                );
                Some(method.sig.ident.to_string())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    public_methods.sort();
    let mut expected = vec![
        "apply_find",
        "apply_operator_motion",
        "apply_operator_range",
        "apply_paste_token_count",
        "begin_visual",
        "clear",
        "clear_buffer",
        "cut_char_forward",
        "delete_current_line",
        "delete_left",
        "delete_paste_block",
        "delete_range",
        "delete_right",
        "delete_to_line_end",
        "display_text",
        "editor_snapshot",
        "editor_text",
        "end_visual",
        "image_ingress_drafts",
        "insert_char",
        "insert_pasted_text",
        "insert_registered_image",
        "insert_registered_text",
        "insert_str",
        "move_buffer_end",
        "move_buffer_start",
        "move_cursor",
        "move_down",
        "move_left",
        "move_line_end",
        "move_line_start",
        "move_right",
        "move_up",
        "new",
        "open_above",
        "open_below",
        "paste_after",
        "paste_before",
        "paste_block_left",
        "paste_block_right",
        "paste_blocks",
        "paste_is_empty",
        "plain_payload",
        "probe_motion",
        "rebuild_from_editor",
        "repeat_find",
        "replace_at_token",
        "replace_buffer",
        "set",
        "set_cursor",
        "set_cursor_from_visual_position",
        "set_last_find",
        "set_pending_find",
        "set_pending_g",
        "set_register",
        "set_vim_enabled",
        "set_vim_mode",
        "set_visual_selection",
        "try_insert_image",
        "try_insert_image_handle",
        "visual_operate",
        "wire_image_ingress_drafts",
        "wire_parts",
        "yank_current_line",
    ];
    expected.sort_unstable();
    assert_eq!(public_methods, expected);

    for test_only in [
        "set",
        "clear",
        "insert_registered_image",
        "insert_registered_text",
    ] {
        let method = implementation
            .items
            .iter()
            .find_map(|item| match item {
                ImplItem::Fn(method) if method.sig.ident == test_only => Some(method),
                _ => None,
            })
            .expect("test fixture method exists");
        assert!(cfg_test(&method.attrs), "{test_only} must stay test-only");
    }
}

#[test]
fn app_owns_one_registered_composer_and_no_raw_authority() {
    assert_eq!(
        app_authority_field_types(APP_SOURCE),
        vec!["RegisteredComposer"]
    );
    for forbidden in [
        "self.paste_registry",
        "app.paste_registry",
        "&mut self.composer",
        "&mut app.composer",
        "paste_registry:",
    ] {
        assert!(
            !APP_SOURCE.contains(forbidden) && !APP_INPUT_SOURCE.contains(forbidden),
            "raw App authority escaped through {forbidden}"
        );
    }
    for retired_domain_helper in [
        "fn composer_insert_char",
        "fn composer_delete_left",
        "fn composer_delete_right",
        "fn composer_move_left",
        "fn composer_move_right",
        "fn block_aware_delete",
        "fn reconcile_paste_blocks",
        "FnOnce(&mut crate::tui::composer::Composer)",
    ] {
        assert!(
            !APP_INPUT_SOURCE.contains(retired_domain_helper),
            "block domain leaked back into App: {retired_domain_helper}"
        );
    }
}

#[test]
fn plain_composer_has_no_registry_argument_or_production_whole_buffer_escape() {
    let file = syn::parse_file(COMPOSER_SOURCE).expect("composer source parses");
    let implementation = inherent_impl(&file, "Composer");
    for item in &implementation.items {
        let ImplItem::Fn(method) = item else {
            continue;
        };
        let signature = compact(&method.sig);
        assert!(
            !signature.contains("PasteRegistry"),
            "plain Composer accepts throwaway registry authority: {}",
            method.sig.ident
        );
    }
    for raw in ["set_unregistered", "clear_unregistered"] {
        let method = implementation
            .items
            .iter()
            .find_map(|item| match item {
                ImplItem::Fn(method) if method.sig.ident == raw => Some(method),
                _ => None,
            })
            .expect("raw standalone mutator exists");
        assert!(matches!(method.vis, Visibility::Inherited));
    }
}

#[test]
fn ratchet_detectors_reject_adversarial_aliases_and_extra_authorities() {
    let extra_field = r#"
        struct App {
            composer: RegisteredComposer,
            shadow: crate::tui::composer::Composer,
            registry_alias: crate::tui::paste::PasteRegistry,
        }
    "#;
    assert_eq!(
        app_authority_field_types(extra_field),
        vec![
            "RegisteredComposer",
            "crate::tui::composer::Composer",
            "crate::tui::paste::PasteRegistry",
        ]
    );

    let deref_mut = r#"
        struct RegisteredComposer;
        struct Composer;
        impl std::ops::DerefMut for RegisteredComposer {
            fn deref_mut(&mut self) -> &mut Self::Target { todo!() }
        }
    "#;
    assert!(has_deref_mut(deref_mut));
    assert!(has_mutable_escape_trait(deref_mut));

    let as_mut = r#"
        struct RegisteredComposer;
        struct Composer;
        impl AsMut<Composer> for RegisteredComposer {
            fn as_mut(&mut self) -> &mut Composer { todo!() }
        }
    "#;
    assert!(has_mutable_escape_trait(as_mut));
}

#[test]
fn standalone_editors_replace_plain_composer_values() {
    let btw = include_str!("../src/tui/app/btw_pane.rs");
    let notes = include_str!("../src/tui/notes_pane.rs");
    let vim = include_str!("../src/tui/vim_editor.rs");
    assert!(btw.contains("self.composer = Composer::new(self.composer.vim_enabled())"));
    assert!(notes.contains("self.editor = Composer::with_text(content, self.vim_enabled)"));
    assert!(vim.contains("Composer::with_text(text, vim_enabled)"));
}
