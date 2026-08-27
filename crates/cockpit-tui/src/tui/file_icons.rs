//! Nerd Font file-type icons for write/edit tool lines.
//!
//! Glyphs in this table are single-cell Nerd Font symbols (unicode display
//! width 1). Double-width glyphs are excluded so the tool glyph column
//! (`TOOL_GLYPH_COLUMN` = 3: icon + spaces) does not shift when a file-type
//! icon replaces the generic write/edit emoji.

use std::path::Path;

use cockpit_config::extended::FileIconsSetting;

/// Generic file glyph (`nf-seti-text` / default). Used for unknown
/// extensions and extensionless names that are not a special filename.
pub const GENERIC_FILE_GLYPH: &str = "\u{e612}";

/// Whether `tool` is a write/edit (or plan-document) variant whose glyph
/// column may be replaced with a file-type icon derived from the path.
pub fn is_file_icon_tool(tool: &str) -> bool {
    matches!(
        tool,
        "write"
            | "edit"
            | "plan_write"
            | "plan_edit"
            // Historical display only: pre-rename persisted sessions used
            // these retired verb names in tool-call rows.
            | "writeunlock"
            | "editunlock"
    )
}

/// Icon for `path` when `tool` is a write/edit variant; `None` otherwise.
pub fn glyph_for_tool_path(tool: &str, path: &str) -> Option<&'static str> {
    is_file_icon_tool(tool).then(|| glyph_for_path(path))
}

/// Nerd Font glyph for `path`. Filename special-cases (Dockerfile,
/// Makefile, …) win over extension matching so conventional extensionless
/// files classify; unknown names fall back to [`GENERIC_FILE_GLYPH`].
pub fn glyph_for_path(path: &str) -> &'static str {
    let path = path.trim();
    let p = Path::new(path);
    let file_name = p
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path);

    if let Some(glyph) = glyph_for_filename(file_name) {
        return glyph;
    }

    if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
        if let Some(glyph) = glyph_for_extension(&ext.to_ascii_lowercase()) {
            return glyph;
        }
    }

    GENERIC_FILE_GLYPH
}

fn glyph_for_filename(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    Some(match lower.as_str() {
        "dockerfile" => ICON_DOCKER,
        n if n.starts_with("dockerfile.") => ICON_DOCKER,
        "makefile" | "gnumakefile" => ICON_MAKE,
        "cmakelists.txt" | "justfile" => ICON_MAKE,
        ".gitignore" | ".gitattributes" | ".gitmodules" => ICON_GIT,
        ".env" => ICON_CONFIG,
        n if n.starts_with(".env.") || n.starts_with(".env-") => ICON_CONFIG,
        _ => return None,
    })
}

fn glyph_for_extension(ext: &str) -> Option<&'static str> {
    Some(match ext {
        // Rust
        "rs" => ICON_RUST,
        // Web
        "ts" | "mts" | "cts" => ICON_TYPESCRIPT,
        "tsx" | "jsx" => ICON_REACT,
        "js" | "mjs" | "cjs" => ICON_JAVASCRIPT,
        "html" | "htm" => ICON_HTML,
        "css" => ICON_CSS,
        "scss" | "sass" => ICON_SASS,
        "less" => ICON_LESS,
        "vue" => ICON_VUE,
        "svelte" => ICON_SVELTE,
        // Backend / systems
        "py" | "pyi" => ICON_PYTHON,
        "go" => ICON_GO,
        "rb" | "rake" => ICON_RUBY,
        "java" => ICON_JAVA,
        "kt" | "kts" => ICON_KOTLIN,
        "swift" => ICON_SWIFT,
        "scala" => ICON_SCALA,
        "cs" => ICON_CSHARP,
        "fs" | "fsi" => ICON_FSHARP,
        "c" => ICON_C,
        "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => ICON_CPP,
        "h" => ICON_C,
        "m" | "mm" => ICON_OBJC,
        "zig" => ICON_ZIG,
        "nim" => ICON_NIM,
        // Scripting
        "sh" | "bash" | "zsh" | "fish" => ICON_SHELL,
        "ps1" => ICON_POWERSHELL,
        "lua" => ICON_LUA,
        "pl" | "pm" => ICON_PERL,
        "php" => ICON_PHP,
        "r" => ICON_R,
        // Data / config
        "json" | "jsonc" | "json5" => ICON_JSON,
        "toml" => ICON_TOML,
        "yaml" | "yml" => ICON_YAML,
        "xml" => ICON_XML,
        "sql" => ICON_SQL,
        "proto" => ICON_PROTO,
        "graphql" | "gql" => ICON_GRAPHQL,
        // Markup
        "md" | "markdown" => ICON_MARKDOWN,
        "tex" => ICON_TEX,
        "rst" => ICON_MARKDOWN,
        // Other
        "dockerfile" => ICON_DOCKER,
        "makefile" | "mk" => ICON_MAKE,
        "nix" => ICON_NIX,
        "tf" | "tfvars" | "hcl" => ICON_TERRAFORM,
        "ex" | "exs" => ICON_ELIXIR,
        "erl" | "hrl" => ICON_ERLANG,
        "elm" => ICON_ELM,
        "dart" => ICON_DART,
        "ml" | "mli" => ICON_OCAML,
        "hs" | "lhs" => ICON_HASKELL,
        "clj" | "cljs" | "cljc" | "edn" => ICON_CLOJURE,
        _ => return None,
    })
}

/// Every unique glyph in the table. Tests assert each is a single cell
/// (unicode width 1); a width-2 pick would shift the tool glyph column.
#[cfg(test)]
const ALL_GLYPHS: &[&str] = &[
    GENERIC_FILE_GLYPH,
    ICON_RUST,
    ICON_TYPESCRIPT,
    ICON_REACT,
    ICON_JAVASCRIPT,
    ICON_HTML,
    ICON_CSS,
    ICON_SASS,
    ICON_LESS,
    ICON_VUE,
    ICON_SVELTE,
    ICON_PYTHON,
    ICON_GO,
    ICON_RUBY,
    ICON_JAVA,
    ICON_KOTLIN,
    ICON_SWIFT,
    ICON_SCALA,
    ICON_CSHARP,
    ICON_FSHARP,
    ICON_C,
    ICON_CPP,
    ICON_OBJC,
    ICON_ZIG,
    ICON_NIM,
    ICON_SHELL,
    ICON_POWERSHELL,
    ICON_LUA,
    ICON_PERL,
    ICON_PHP,
    ICON_R,
    ICON_JSON,
    ICON_TOML,
    ICON_YAML,
    ICON_XML,
    ICON_SQL,
    ICON_PROTO,
    ICON_GRAPHQL,
    ICON_MARKDOWN,
    ICON_TEX,
    ICON_DOCKER,
    ICON_MAKE,
    ICON_NIX,
    ICON_TERRAFORM,
    ICON_ELIXIR,
    ICON_ERLANG,
    ICON_ELM,
    ICON_DART,
    ICON_OCAML,
    ICON_HASKELL,
    ICON_CLOJURE,
    ICON_GIT,
    ICON_CONFIG,
];

// Nerd Font Seti / Devicons private-use-area glyphs (BMP). Width 1.
const ICON_RUST: &str = "\u{e68b}";
const ICON_TYPESCRIPT: &str = "\u{e628}";
const ICON_REACT: &str = "\u{e7ba}";
const ICON_JAVASCRIPT: &str = "\u{e60c}";
const ICON_HTML: &str = "\u{e60e}";
const ICON_CSS: &str = "\u{e614}";
const ICON_SASS: &str = "\u{e603}";
const ICON_LESS: &str = "\u{e758}";
const ICON_VUE: &str = "\u{e6a1}";
const ICON_SVELTE: &str = "\u{e697}";
const ICON_PYTHON: &str = "\u{e606}";
const ICON_GO: &str = "\u{e627}";
const ICON_RUBY: &str = "\u{e605}";
const ICON_JAVA: &str = "\u{e738}";
const ICON_KOTLIN: &str = "\u{e634}";
const ICON_SWIFT: &str = "\u{e755}";
const ICON_SCALA: &str = "\u{e737}";
const ICON_CSHARP: &str = "\u{e648}";
const ICON_FSHARP: &str = "\u{e7a7}";
const ICON_C: &str = "\u{e61e}";
const ICON_CPP: &str = "\u{e61d}";
const ICON_OBJC: &str = "\u{e711}";
const ICON_ZIG: &str = "\u{e6a9}";
const ICON_NIM: &str = "\u{e677}";
const ICON_SHELL: &str = "\u{e795}";
const ICON_POWERSHELL: &str = "\u{e7a8}";
const ICON_LUA: &str = "\u{e620}";
const ICON_PERL: &str = "\u{e769}";
const ICON_PHP: &str = "\u{e608}";
const ICON_R: &str = "\u{e68a}";
const ICON_JSON: &str = "\u{e60b}";
const ICON_TOML: &str = "\u{e6b2}";
const ICON_YAML: &str = "\u{e6a8}";
const ICON_XML: &str = "\u{e619}";
const ICON_SQL: &str = "\u{e706}";
const ICON_PROTO: &str = "\u{e60b}";
const ICON_GRAPHQL: &str = "\u{e654}";
const ICON_MARKDOWN: &str = "\u{e609}";
const ICON_TEX: &str = "\u{e69b}";
const ICON_DOCKER: &str = "\u{e7b0}";
const ICON_MAKE: &str = "\u{e779}";
const ICON_NIX: &str = "\u{f313}";
const ICON_TERRAFORM: &str = "\u{e69a}";
const ICON_ELIXIR: &str = "\u{e62d}";
const ICON_ERLANG: &str = "\u{e7b1}";
const ICON_ELM: &str = "\u{e62c}";
const ICON_DART: &str = "\u{e798}";
const ICON_OCAML: &str = "\u{e67a}";
const ICON_HASKELL: &str = "\u{e61f}";
const ICON_CLOJURE: &str = "\u{e768}";
const ICON_GIT: &str = "\u{e702}";
const ICON_CONFIG: &str = "\u{e615}";

/// Env values that identify terminals with builtin Nerd Font / symbol
/// fallback (kitty, WezTerm, Ghostty). Pure so the detection matrix is
/// unit-testable; [`file_icons_supported`] is the env-reading wrapper.
pub fn file_icons_supported_from_env(
    kitty_window_id: Option<&str>,
    term: Option<&str>,
    wezterm_executable: Option<&str>,
    term_program: Option<&str>,
    ghostty_resources_dir: Option<&str>,
) -> bool {
    if kitty_window_id.is_some() || term == Some("xterm-kitty") {
        return true;
    }
    if wezterm_executable.is_some() || term_program == Some("WezTerm") {
        return true;
    }
    if ghostty_resources_dir.is_some() || term_program == Some("ghostty") {
        return true;
    }
    false
}

/// Read kitty / WezTerm / Ghostty env markers and classify via
/// [`file_icons_supported_from_env`]. Absent markers mean no builtin
/// symbol fallback — `tui.file_icons = auto` stays off.
pub fn file_icons_supported() -> bool {
    file_icons_supported_from_env(
        env_opt("KITTY_WINDOW_ID").as_deref(),
        env_opt("TERM").as_deref(),
        env_opt("WEZTERM_EXECUTABLE").as_deref(),
        env_opt("TERM_PROGRAM").as_deref(),
        env_opt("GHOSTTY_RESOURCES_DIR").as_deref(),
    )
}

/// Resolve `tui.file_icons`: `on`/`off` override, `auto` follows
/// [`file_icons_supported`].
pub fn file_icons_resolved(setting: FileIconsSetting) -> bool {
    setting.resolve(file_icons_supported())
}

fn env_opt(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_width::UnicodeWidthStr;

    /// Extensions covered by `crates/cockpit-db/src/db/lang.rs` plus the
    /// extra TypeScript suffixes from the intel/highlight tables.
    const LANG_EXTENSIONS: &[&str] = &[
        "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "html", "htm", "css", "scss", "sass", "less",
        "vue", "svelte", "py", "pyi", "go", "rb", "rake", "java", "kt", "kts", "swift", "scala",
        "cs", "fs", "fsi", "c", "cc", "cpp", "cxx", "hpp", "hh", "hxx", "h", "m", "mm", "zig",
        "nim", "sh", "bash", "zsh", "fish", "ps1", "lua", "pl", "pm", "php", "r", "json", "jsonc",
        "json5", "toml", "yaml", "yml", "xml", "sql", "proto", "graphql", "gql", "md", "markdown",
        "tex", "rst", "dockerfile", "makefile", "mk", "nix", "tf", "tfvars", "hcl", "ex", "exs",
        "erl", "hrl", "elm", "dart", "ml", "mli", "hs", "lhs", "clj", "cljs", "cljc", "edn", "mts",
        "cts",
    ];

    #[test]
    fn lang_extensions_map_to_a_glyph() {
        for ext in LANG_EXTENSIONS {
            let path = format!("src/file.{ext}");
            let glyph = glyph_for_path(&path);
            assert!(
                !glyph.is_empty(),
                "{ext}: expected a file-type glyph, got empty"
            );
            assert_eq!(
                glyph.width(),
                1,
                "{ext}: glyph {glyph:?} must be single-cell, got width {}",
                glyph.width()
            );
        }
    }

    #[test]
    fn unknown_extension_uses_generic_glyph() {
        assert_eq!(glyph_for_path("unknown.xyz"), GENERIC_FILE_GLYPH);
        assert_eq!(glyph_for_path("no_extension"), GENERIC_FILE_GLYPH);
        assert_eq!(glyph_for_path(""), GENERIC_FILE_GLYPH);
    }

    #[test]
    fn filename_special_cases() {
        assert_eq!(glyph_for_path("Dockerfile"), ICON_DOCKER);
        assert_eq!(glyph_for_path("dockerfile"), ICON_DOCKER);
        assert_eq!(glyph_for_path("Dockerfile.prod"), ICON_DOCKER);
        assert_eq!(glyph_for_path("Makefile"), ICON_MAKE);
        assert_eq!(glyph_for_path("GNUmakefile"), ICON_MAKE);
        assert_eq!(glyph_for_path(".gitignore"), ICON_GIT);
        assert_eq!(glyph_for_path(".env"), ICON_CONFIG);
        assert_eq!(glyph_for_path(".env.local"), ICON_CONFIG);
    }

    #[test]
    fn extension_is_case_insensitive() {
        assert_eq!(glyph_for_path("FOO.RS"), ICON_RUST);
        assert_eq!(glyph_for_path("Foo.Py"), ICON_PYTHON);
        assert_eq!(glyph_for_path("app.TSX"), ICON_REACT);
    }

    #[test]
    fn rust_and_markdown_use_distinct_glyphs() {
        assert_eq!(glyph_for_path("src/main.rs"), ICON_RUST);
        assert_eq!(glyph_for_path("README.md"), ICON_MARKDOWN);
        assert_ne!(ICON_RUST, GENERIC_FILE_GLYPH);
        assert_ne!(ICON_RUST, ICON_MARKDOWN);
    }

    #[test]
    fn all_table_glyphs_are_single_cell() {
        for glyph in ALL_GLYPHS {
            assert_eq!(
                glyph.width(),
                1,
                "glyph {glyph:?} (U+{:04X}) display width must be 1, got {}",
                glyph.chars().next().unwrap() as u32,
                glyph.width()
            );
            assert_eq!(
                glyph.chars().count(),
                1,
                "glyph {glyph:?} must be a single codepoint"
            );
        }
    }

    #[test]
    fn file_icon_tools_include_write_edit_and_plan_variants() {
        for tool in [
            "write",
            "edit",
            "writeunlock",
            "editunlock",
            "plan_write",
            "plan_edit",
        ] {
            assert!(is_file_icon_tool(tool), "{tool}");
            assert_eq!(
                glyph_for_tool_path(tool, "src/lib.rs"),
                Some(ICON_RUST)
            );
        }
        assert!(!is_file_icon_tool("bash"));
        assert!(!is_file_icon_tool("read"));
        assert!(glyph_for_tool_path("bash", "src/lib.rs").is_none());
    }

    #[test]
    fn auto_detection_pure_fn_matrix() {
        // kitty
        assert!(file_icons_supported_from_env(
            Some("1"),
            None,
            None,
            None,
            None
        ));
        assert!(file_icons_supported_from_env(
            None,
            Some("xterm-kitty"),
            None,
            None,
            None
        ));
        // WezTerm
        assert!(file_icons_supported_from_env(
            None,
            None,
            Some("/usr/bin/wezterm"),
            None,
            None
        ));
        assert!(file_icons_supported_from_env(
            None,
            None,
            None,
            Some("WezTerm"),
            None
        ));
        // Ghostty
        assert!(file_icons_supported_from_env(
            None,
            None,
            None,
            None,
            Some("/usr/share/ghostty")
        ));
        assert!(file_icons_supported_from_env(
            None,
            None,
            None,
            Some("ghostty"),
            None
        ));
        // Elsewhere: no builtin symbol fallback.
        assert!(!file_icons_supported_from_env(
            None,
            Some("xterm-256color"),
            None,
            Some("iTerm.app"),
            None
        ));
        assert!(!file_icons_supported_from_env(
            None, None, None, None, None
        ));
        assert!(!file_icons_supported_from_env(
            None,
            Some("xterm-kitty-invalid"),
            None,
            Some("wezterm"),
            None
        ));
    }

    #[test]
    fn setting_resolves_on_off_and_auto() {
        assert!(FileIconsSetting::On.resolve(false));
        assert!(!FileIconsSetting::Off.resolve(true));
        assert!(FileIconsSetting::Auto.resolve(true));
        assert!(!FileIconsSetting::Auto.resolve(false));
    }
}
