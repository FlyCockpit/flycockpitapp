//! File-extension → language attribution (GOALS §15c).
//!
//! v1: a static extension map. v2 (deferred) would swap this for
//! [`hyperpolyglot`](https://github.com/monkslc/hyperpolyglot) so
//! ambiguous extensions (`.h`, `.m`, `.t`) and extensionless shebang
//! files get classified correctly. Per GOALS the v2 swap can be a
//! `cockpit stats rebuild --languages` one-shot UPDATE — no schema
//! migration needed.

use std::path::Path;

/// Resolve a file path to a language name. Returns `None` for paths
/// with no extension or an extension we don't recognize; the caller
/// (the §15b INSERT) maps `None` to the SQL value `NULL`.
pub fn language_for_path(path: &str) -> Option<&'static str> {
    let p = Path::new(path);
    let ext = p.extension()?.to_str()?.to_ascii_lowercase();
    language_for_extension(&ext)
}

fn language_for_extension(ext: &str) -> Option<&'static str> {
    Some(match ext {
        // Rust
        "rs" => "Rust",
        // Web
        "ts" | "tsx" => "TypeScript",
        "js" | "jsx" | "mjs" | "cjs" => "JavaScript",
        "html" | "htm" => "HTML",
        "css" | "scss" | "sass" | "less" => "CSS",
        "vue" => "Vue",
        "svelte" => "Svelte",
        // Backend / systems
        "py" | "pyi" => "Python",
        "go" => "Go",
        "rb" | "rake" => "Ruby",
        "java" => "Java",
        "kt" | "kts" => "Kotlin",
        "swift" => "Swift",
        "scala" => "Scala",
        "cs" => "C#",
        "fs" | "fsi" => "F#",
        "c" => "C",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => "C++",
        "h" => "C/C++ Header",
        "m" | "mm" => "Objective-C",
        "zig" => "Zig",
        "nim" => "Nim",
        // Scripting
        "sh" | "bash" | "zsh" | "fish" => "Shell",
        "ps1" => "PowerShell",
        "lua" => "Lua",
        "pl" | "pm" => "Perl",
        "php" => "PHP",
        "r" => "R",
        // Data / config
        "json" | "jsonc" | "json5" => "JSON",
        "toml" => "TOML",
        "yaml" | "yml" => "YAML",
        "xml" => "XML",
        "sql" => "SQL",
        "proto" => "Protobuf",
        "graphql" | "gql" => "GraphQL",
        // Markup
        "md" | "markdown" => "Markdown",
        "tex" => "TeX",
        "rst" => "reStructuredText",
        // Other
        "dockerfile" => "Dockerfile",
        "makefile" => "Makefile",
        "mk" => "Makefile",
        "nix" => "Nix",
        "tf" | "tfvars" => "Terraform",
        "hcl" => "HCL",
        "ex" | "exs" => "Elixir",
        "erl" | "hrl" => "Erlang",
        "elm" => "Elm",
        "dart" => "Dart",
        "ml" | "mli" => "OCaml",
        "hs" | "lhs" => "Haskell",
        "clj" | "cljs" | "cljc" | "edn" => "Clojure",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_extensions() {
        assert_eq!(language_for_path("src/main.rs"), Some("Rust"));
        assert_eq!(language_for_path("README.md"), Some("Markdown"));
        assert_eq!(language_for_path("app.ts"), Some("TypeScript"));
        assert_eq!(language_for_path("a.py"), Some("Python"));
        assert_eq!(language_for_path("Cargo.toml"), Some("TOML"));
    }

    #[test]
    fn unknown_returns_none() {
        assert_eq!(language_for_path("unknown.xyz"), None);
        assert_eq!(language_for_path("no_extension"), None);
        assert_eq!(language_for_path(""), None);
    }

    #[test]
    fn case_insensitive_extension() {
        assert_eq!(language_for_path("FOO.RS"), Some("Rust"));
        assert_eq!(language_for_path("Foo.Py"), Some("Python"));
    }
}
