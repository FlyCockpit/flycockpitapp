use std::collections::HashSet;
use std::path::PathBuf;

const MOVED_HOST_MODULES: &[&str] = &["goal_scratch", "path_containment", "private_fs", "process"];

fn use_tree_starts_with_host_alias(tree: &syn::UseTree, aliases: &HashSet<String>) -> bool {
    match tree {
        syn::UseTree::Path(path) => aliases.contains(&path.ident.to_string()),
        syn::UseTree::Name(name) => aliases.contains(&name.ident.to_string()),
        syn::UseTree::Rename(rename) => aliases.contains(&rename.ident.to_string()),
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|tree| use_tree_starts_with_host_alias(tree, aliases)),
        syn::UseTree::Glob(_) => false,
    }
}

fn collect_host_aliases(
    tree: &syn::UseTree,
    aliases: &HashSet<String>,
    rooted_at_host: bool,
    discovered: &mut HashSet<String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            let rooted = rooted_at_host || aliases.contains(&path.ident.to_string());
            collect_host_aliases(&path.tree, aliases, rooted, discovered);
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                collect_host_aliases(tree, aliases, rooted_at_host, discovered);
            }
        }
        syn::UseTree::Rename(rename)
            if aliases.contains(&rename.ident.to_string())
                || (rooted_at_host && rename.ident == "self") =>
        {
            discovered.insert(rename.rename.to_string());
        }
        syn::UseTree::Name(name) if rooted_at_host => {
            discovered.insert(name.ident.to_string());
        }
        _ => {}
    }
}

fn assert_items_respect_host_boundary(items: &[syn::Item], path: &std::path::Path) {
    // Resolve direct crate aliases before checking exports so source order
    // cannot hide `pub use alias::*`. Rust raw identifiers normalize through
    // Ident::to_string, and grouped/absolute trees recurse below.
    let mut host_aliases =
        HashSet::from(["cockpit_host".to_string(), "r#cockpit_host".to_string()]);
    // Alias discovery is a fixed point: `cockpit_host as a; a as b` remains
    // forbidden regardless of source order or grouped `self as` spelling.
    loop {
        let mut discovered = HashSet::new();
        for item in items {
            match item {
                syn::Item::Use(item_use) => {
                    collect_host_aliases(&item_use.tree, &host_aliases, false, &mut discovered)
                }
                syn::Item::ExternCrate(extern_crate) if extern_crate.ident == "cockpit_host" => {
                    discovered.insert(extern_crate.rename.as_ref().map_or_else(
                        || extern_crate.ident.to_string(),
                        |(_, alias)| alias.to_string(),
                    ));
                }
                _ => {}
            }
        }
        let before = host_aliases.len();
        host_aliases.extend(discovered);
        if host_aliases.len() == before {
            break;
        }
    }
    for item in items {
        match item {
            syn::Item::Mod(module) => {
                let raw_name = module.ident.to_string();
                let name = raw_name.strip_prefix("r#").unwrap_or(&raw_name);
                assert!(
                    !MOVED_HOST_MODULES.contains(&name),
                    "cockpit-core must not shim moved host authority with module `{name}` in {}",
                    path.display()
                );
                if let Some((_, nested)) = &module.content {
                    assert_items_respect_host_boundary(nested, path);
                } else {
                    for attribute in &module.attrs {
                        let syn::Meta::NameValue(meta) = &attribute.meta else {
                            continue;
                        };
                        if !meta.path.is_ident("path") {
                            continue;
                        }
                        let syn::Expr::Lit(expression) = &meta.value else {
                            panic!("non-literal #[path] module in {}", path.display());
                        };
                        let syn::Lit::Str(relative) = &expression.lit else {
                            panic!("non-string #[path] module in {}", path.display());
                        };
                        let external = path
                            .parent()
                            .expect("Rust source has a parent")
                            .join(relative.value());
                        let source = std::fs::read_to_string(&external).unwrap_or_else(|error| {
                            panic!("read external module {}: {error}", external.display())
                        });
                        let syntax = syn::parse_file(&source).unwrap_or_else(|error| {
                            panic!("parse external module {}: {error}", external.display())
                        });
                        assert_items_respect_host_boundary(&syntax.items, &external);
                    }
                }
            }
            syn::Item::Use(item_use)
                if !matches!(item_use.vis, syn::Visibility::Inherited)
                    && use_tree_starts_with_host_alias(&item_use.tree, &host_aliases) =>
            {
                panic!(
                    "cockpit-core production source must not publicly re-export cockpit_host in {}",
                    path.display()
                );
            }
            syn::Item::ExternCrate(extern_crate)
                if !matches!(extern_crate.vis, syn::Visibility::Inherited)
                    && extern_crate.ident == "cockpit_host" =>
            {
                panic!(
                    "cockpit-core production source must not publicly re-export cockpit_host with extern crate in {}",
                    path.display()
                );
            }
            _ => {}
        }
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("cockpit-host must remain under crates/")
        .to_path_buf()
}

#[test]
fn host_is_a_workspace_dependency_leaf() {
    let manifest =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read cockpit-host manifest");
    for forbidden in [
        "cockpit-core",
        "cockpit-config",
        "cockpit-db",
        "cockpit-proto",
        "cockpit-tui",
        "relay-protocol",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "cockpit-host must not depend on {forbidden}"
        );
    }
}

#[test]
fn core_does_not_reexport_moved_host_authority() {
    let core = workspace_root().join("crates/cockpit-core/src");
    for module in [
        "goal_scratch.rs",
        "path_containment.rs",
        "private_fs.rs",
        "process.rs",
    ] {
        assert!(
            !core.join(module).exists(),
            "moved host authority must not remain in cockpit-core: {module}"
        );
    }
    let mut pending = vec![core];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("read core source directory") {
            let path = entry.expect("core source entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                let source = std::fs::read_to_string(&path).expect("read core production source");
                let syntax = syn::parse_file(&source).unwrap_or_else(|error| {
                    panic!("parse cockpit-core source {}: {error}", path.display())
                });
                assert_items_respect_host_boundary(&syntax.items, &path);
            }
        }
    }
}

#[test]
fn host_boundary_ast_guard_handles_inline_and_grouped_syntax() {
    let allowed = syn::parse_file("pub mod process_containment {}\nuse cockpit_host::private_fs;")
        .expect("parse allowed fixture");
    assert_items_respect_host_boundary(&allowed.items, std::path::Path::new("allowed.rs"));

    for forbidden in [
        "mod nested { pub mod process {} }",
        "pub use cockpit_host::{private_fs, process};",
        "pub use {cockpit_host::private_fs, std::path::Path};",
        "use cockpit_host as host_authority; pub(crate) use host_authority::*;",
        "use cockpit_host::private_fs; pub use private_fs::*;",
        "pub(super) use ::cockpit_host::*;",
        "use cockpit_host as a; use a as b; pub use b::*;",
        "use cockpit_host::{self as grouped}; pub use grouped::*;",
        "extern crate cockpit_host as external; pub use external::*;",
        "pub extern crate cockpit_host as host_authority;",
        "pub mod r#process {}",
    ] {
        let syntax = syn::parse_file(forbidden).expect("parse adversarial fixture");
        let rejected = std::panic::catch_unwind(|| {
            assert_items_respect_host_boundary(&syntax.items, std::path::Path::new("forbidden.rs"));
        });
        assert!(rejected.is_err(), "boundary guard accepted `{forbidden}`");
    }
}

#[test]
fn daemon_pid_and_metadata_guard_live_only_in_host() {
    let daemon =
        std::fs::read_to_string(workspace_root().join("crates/cockpit-core/src/daemon/mod.rs"))
            .expect("read daemon module");
    for forbidden in [
        "struct ForegroundMetadataGuard",
        "enum PidIdentity",
        "fn verify_daemon_pid_identity",
        "fn read_process_cmdline",
        "fn process_exists",
        "libc::kill(pid as libc::pid_t, libc::SIGTERM)",
        "remove_metadata_if_pid_matches",
        "let pid_receipt = write_pid_file",
    ] {
        assert!(
            !daemon.contains(forbidden),
            "daemon lifecycle host primitive leaked back into core: {forbidden}"
        );
    }
    let host = std::fs::read_to_string(
        workspace_root().join("crates/cockpit-host/src/daemon_lifecycle.rs"),
    )
    .expect("read host daemon lifecycle");
    for required in [
        "struct DaemonPidReceipt",
        "fn read_daemon_pid_record",
        "cockpit-daemon-pid-v2",
        "unix-bytes:",
        "windows-utf16le:",
        "struct ProcessStartIdentity",
        "publication_nonce: [u8; 32]",
        "struct SerializedDaemonPidReceipt",
        "write_private_file_exclusive",
        "fn read_process_start_identity",
        "offset_of!(ProcBsdInfo, start_sec) == 120",
        "let error = (ok == 0).then(std::io::Error::last_os_error)",
        "with_lifecycle_lock",
        "reclaim_stale_and_reserve",
        "retire_incumbent_locked",
        "retire_matching_endpoint",
        "error.kind() == std::io::ErrorKind::NotFound",
        "retire_metadata_if_receipt_matches",
        "SYS_pidfd_open",
        "SYS_pidfd_send_signal",
        "pub fn is_alive(&self) -> std::io::Result<bool>",
    ] {
        assert!(
            host.contains(required),
            "stable receipt-bound lifecycle primitive is missing: {required}"
        );
    }
    for required in [
        "fn read_bound_endpoint_record_from",
        "reclaim_stale_and_reserve(",
        "record.socket != canonical.socket",
        "DaemonPidRecord::Receipt(receipt)",
        "preserving metadata and refusing numeric signaling",
    ] {
        assert!(
            daemon.contains(required),
            "daemon endpoint/stop fail-closed contract is missing: {required}"
        );
    }
}
