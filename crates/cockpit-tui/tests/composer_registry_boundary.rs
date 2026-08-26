use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::visit::{self, Visit};
use syn::{Fields, ImplItem, Item, Meta, Visibility};

const COMPOSER_SOURCE: &str = include_str!("../src/tui/composer.rs");
const OWNER_SOURCE: &str = include_str!("../src/tui/composer/registered.rs");
const APP_SOURCE: &str = include_str!("../src/tui/app/mod.rs");

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

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn authority_name(path: &syn::Path) -> Option<&'static str> {
    let name = path.segments.last()?.ident.to_string();
    ["RegisteredComposer", "Composer", "PasteRegistry"]
        .into_iter()
        .find(|candidate| name == *candidate)
}

#[derive(Default)]
struct MutableAuthorityReturn(bool);

impl<'ast> Visit<'ast> for MutableAuthorityReturn {
    fn visit_type_reference(&mut self, reference: &'ast syn::TypeReference) {
        if reference.mutability.is_some()
            && matches!(&*reference.elem, syn::Type::Path(path)
                if authority_name(&path.path).is_some())
        {
            self.0 = true;
        }
        visit::visit_type_reference(self, reference);
    }
}

struct ProductionInventory<'a> {
    relative: &'a str,
    function: Option<String>,
    test_depth: usize,
    constructor_callee_depth: usize,
    constructors: Vec<(String, String)>,
    violations: Vec<String>,
}

impl ProductionInventory<'_> {
    fn violation(&mut self, message: impl Into<String>) {
        self.violations
            .push(format!("{}: {}", self.relative, message.into()));
    }

    fn is_authority_owner(&self) -> bool {
        matches!(self.relative, "tui/composer/registered.rs" | "tui/paste.rs")
    }
}

impl<'ast> Visit<'ast> for ProductionInventory<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        let test_only = usize::from(cfg_test(&item.attrs));
        self.test_depth += test_only;
        visit::visit_item_mod(self, item);
        self.test_depth -= test_only;
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let previous = self.function.replace(item.sig.ident.to_string());
        let test_only = usize::from(
            cfg_test(&item.attrs) || item.attrs.iter().any(|attr| attr.path().is_ident("test")),
        );
        self.test_depth += test_only;
        visit::visit_item_fn(self, item);
        self.test_depth -= test_only;
        self.function = previous;
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        let previous = self.function.replace(item.sig.ident.to_string());
        let test_only = usize::from(
            cfg_test(&item.attrs) || item.attrs.iter().any(|attr| attr.path().is_ident("test")),
        );
        self.test_depth += test_only;
        visit::visit_impl_item_fn(self, item);
        self.test_depth -= test_only;
        self.function = previous;
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        fn inspect(
            tree: &syn::UseTree,
            names: &mut Vec<String>,
            renamed: &mut bool,
            glob: &mut bool,
        ) {
            match tree {
                syn::UseTree::Path(path) => {
                    names.push(path.ident.to_string());
                    inspect(&path.tree, names, renamed, glob);
                }
                syn::UseTree::Name(name) => names.push(name.ident.to_string()),
                syn::UseTree::Rename(rename) => {
                    names.push(rename.ident.to_string());
                    *renamed = true;
                }
                syn::UseTree::Glob(_) => *glob = true,
                syn::UseTree::Group(group) => {
                    for item in &group.items {
                        inspect(item, names, renamed, glob);
                    }
                }
            }
        }
        if self.test_depth == 0 {
            let mut names = Vec::new();
            let mut renamed = false;
            let mut glob = false;
            inspect(&item.tree, &mut names, &mut renamed, &mut glob);
            let has_authority = names.iter().any(|name| {
                ["RegisteredComposer", "Composer", "PasteRegistry"].contains(&name.as_str())
            });
            if has_authority && renamed {
                self.violation("composer authority imports may not be renamed");
            }
            if renamed
                && names
                    .iter()
                    .any(|name| name == "composer" || name == "paste")
            {
                self.violation("composer authority modules may not be renamed");
            }
            if glob
                && names
                    .iter()
                    .any(|name| name == "composer" || name == "paste")
            {
                self.violation("composer authority modules may not be glob-imported");
            }
            let expected_reexport = self.relative == "tui/composer.rs"
                && names.iter().any(|name| name == "registered")
                && names.iter().any(|name| name == "RegisteredComposer");
            if has_authority && !matches!(item.vis, Visibility::Inherited) && !expected_reexport {
                self.violation("composer authority may not be re-exported");
            }
        }
        visit::visit_item_use(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if self.test_depth == 0 {
            let ty = compact(&item.ty);
            if ["RegisteredComposer", "PasteRegistry"]
                .iter()
                .any(|name| ty.contains(name))
            {
                self.violation("composer authority type alias");
            }
        }
        visit::visit_item_type(self, item);
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if self.test_depth == 0
            && !self.is_authority_owner()
            && item.ident != "App"
            && item.ident != "RegisteredComposer"
        {
            for field in &item.fields {
                let ty = compact(&field.ty);
                if ty.contains("RegisteredComposer") || ty.contains("PasteRegistry") {
                    self.violation(format!("wrapper `{}` owns composer authority", item.ident));
                }
            }
        }
        visit::visit_item_struct(self, item);
    }

    fn visit_signature(&mut self, signature: &'ast syn::Signature) {
        if self.test_depth == 0 {
            let mut mutable = MutableAuthorityReturn::default();
            mutable.visit_return_type(&signature.output);
            if mutable.0 {
                self.violation(format!(
                    "{} returns mutable composer authority",
                    signature.ident
                ));
            }
        }
        visit::visit_signature(self, signature);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let is_constructor = matches!(&*call.func, syn::Expr::Path(path)
            if path.path.segments.iter().rev().take(2).map(|segment| segment.ident.to_string()).eq(["new", "RegisteredComposer"]));
        if self.test_depth == 0 && is_constructor {
            self.constructors.push((
                self.relative.to_owned(),
                self.function.clone().unwrap_or_else(|| "<none>".into()),
            ));
        }
        self.constructor_callee_depth += usize::from(is_constructor);
        self.visit_expr(&call.func);
        self.constructor_callee_depth -= usize::from(is_constructor);
        for argument in &call.args {
            self.visit_expr(argument);
        }
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        let is_constructor = path
            .path
            .segments
            .iter()
            .rev()
            .take(2)
            .map(|segment| segment.ident.to_string())
            .eq(["new", "RegisteredComposer"]);
        if self.test_depth == 0 && is_constructor && self.constructor_callee_depth == 0 {
            self.violation("RegisteredComposer constructor may only be called directly");
        }
        if self.test_depth == 0
            && !self.is_authority_owner()
            && authority_name(&path.path) == Some("PasteRegistry")
        {
            self.violation("production code references raw PasteRegistry as a value");
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        if self.test_depth == 0 && !self.is_authority_owner() {
            let tokens = invocation.tokens.to_string();
            if ["RegisteredComposer", "PasteRegistry"].iter().any(|name| {
                tokens
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .any(|token| token == *name)
            }) {
                self.violation("composer authority hidden in macro");
            }
        }
        visit::visit_macro(self, invocation);
    }
}

fn inspect_production<'a>(source: &str, relative: &'a str) -> ProductionInventory<'a> {
    let file = syn::parse_file(source).unwrap();
    let mut inventory = ProductionInventory {
        relative,
        function: None,
        test_depth: 0,
        constructor_callee_depth: 0,
        constructors: Vec::new(),
        violations: Vec::new(),
    };
    inventory.visit_file(&file);
    inventory
}

#[test]
fn app_is_the_only_production_registered_composer_owner_and_constructor() {
    let app = syn::parse_file(APP_SOURCE).unwrap();
    let Fields::Named(fields) = &named_struct(&app, "App").fields else {
        panic!("App fields");
    };
    let authority = fields
        .named
        .iter()
        .filter(|field| {
            compact(&field.ty).contains("Composer") || compact(&field.ty).contains("PasteRegistry")
        })
        .collect::<Vec<_>>();
    assert_eq!(authority.len(), 1);
    assert_eq!(authority[0].ident.as_ref().unwrap(), "composer");
    assert_eq!(compact(&authority[0].ty), "RegisteredComposer");
    assert!(matches!(authority[0].vis, Visibility::Inherited));

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut constructors = Vec::new();
    let mut violations = Vec::new();
    for path in rust_files(&root) {
        let relative = path.strip_prefix(&root).unwrap().to_string_lossy();
        let source = std::fs::read_to_string(path).unwrap();
        let inventory = inspect_production(&source, &relative);
        constructors.extend(inventory.constructors);
        violations.extend(inventory.violations);
    }
    assert!(violations.is_empty(), "{}", violations.join("\n"));
    assert_eq!(
        constructors,
        vec![("tui/app/mod.rs".into(), "new_inner".into())]
    );
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
    for source in [
        "use crate::tui::composer::RegisteredComposer as Owner; fn f() { Owner::new(false); }",
        "use crate::tui::composer as editing; fn f() { editing::RegisteredComposer::new(false); }",
        "type Owner = RegisteredComposer;",
        "struct Wrapper { owner: RegisteredComposer }",
        "fn leak(owner: &mut RegisteredComposer) -> &mut RegisteredComposer { owner }",
        "pub(super) use crate::tui::composer::RegisteredComposer;",
        "fn f() { let constructor = RegisteredComposer::new; let _ = constructor(false); }",
        "macro_rules! owner { () => { RegisteredComposer::new(false) } }",
    ] {
        let inventory = inspect_production(source, "tui/adversarial.rs");
        assert!(!inventory.violations.is_empty(), "accepted: {source}");
    }

    let unlisted = inspect_production(
        "fn surprise() { let _ = RegisteredComposer::new(false); }",
        "tui/surprise.rs",
    );
    assert_eq!(
        unlisted.constructors,
        vec![("tui/surprise.rs".into(), "surprise".into())]
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
