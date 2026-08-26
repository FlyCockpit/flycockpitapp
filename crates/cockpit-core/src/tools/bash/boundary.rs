use std::path::{Path, PathBuf};

const OUTSIDE_CWD_ERROR: &str = "Error: command working directory resolves outside the session root. Use a subdirectory of {root}, or ask the user for approval to work outside it.";

pub(super) fn outside_cwd_error(root: &Path) -> String {
    OUTSIDE_CWD_ERROR.replace("{root}", &root.display().to_string())
}

pub fn outside_session_boundary(
    path: &Path,
    root: &Path,
    tmp_dir: Option<&Path>,
) -> Option<PathBuf> {
    crate::tools::sandbox::outside_session_boundary(path, root, tmp_dir)
}

pub fn command_directory_escape(
    command: &str,
    command_cwd: &Path,
    root: &Path,
    tmp_dir: Option<&Path>,
) -> Option<PathBuf> {
    let tokens = shell_tokens(command);
    let mut i = 0;
    let mut command_start = true;
    let mut current_program: Option<String> = None;
    while i < tokens.len() {
        match &tokens[i] {
            ShellToken::Operator(op) => {
                command_start = matches!(op.as_str(), ";" | "&" | "&&" | "||" | "|" | "(" | "\n");
                if command_start || op == ")" {
                    current_program = None;
                }
                i += 1;
            }
            ShellToken::Word(word) => {
                if command_start {
                    if (word == "cd" || word == "pushd")
                        && let Some(target) =
                            directory_change_target(&tokens, i + 1, word == "pushd")
                    {
                        let resolved = crate::tools::common::resolve(&target, command_cwd);
                        if let Some(outside) = outside_session_boundary(&resolved, root, tmp_dir) {
                            return Some(outside);
                        }
                    }
                    // Resolve the effective program past any leading env-var
                    // assignments and known command wrappers (`env`, `command`,
                    // `nice`, `busybox`, `sudo`, ...) so `env cat …` and
                    // `/bin/cat …` are gated by `cat`, not by `env`/`/bin/cat`.
                    let (prog_i, skipped) = effective_program_index(&tokens, i);
                    // When wrappers/assignments were stripped, the program token
                    // was an operand in the un-stripped reading, so it keeps its
                    // absolute-path check (`env /etc/shadow` stays flagged).
                    if skipped
                        && prog_i > i
                        && let Some(ShellToken::Word(prog)) = tokens.get(prog_i)
                        && Path::new(prog).is_absolute()
                        && let Some(outside) =
                            literal_path_word_escape(prog, command_cwd, root, tmp_dir)
                    {
                        return Some(outside);
                    }
                    current_program = match tokens.get(prog_i) {
                        Some(ShellToken::Word(prog)) => Some(program_basename(prog).to_string()),
                        _ => None,
                    };
                    command_start = false;
                    // Advance past the wrapper run and the program token itself.
                    // If no program word was found (trailing wrapper / operator),
                    // resume at `prog_i` so the operator is processed normally.
                    i = match tokens.get(prog_i) {
                        Some(ShellToken::Word(_)) => prog_i + 1,
                        _ => prog_i,
                    };
                    continue;
                }
                // Best-effort native boundary gate for unconfined platforms
                // and `/sandbox off`: absolute path tokens are always checked,
                // while relative path-looking operands are checked for common
                // path-oriented commands. This static pass is intentionally
                // partial and is NOT the security boundary — the sandbox is.
                // Residual gaps that remain governed by sandboxing/approval:
                // dynamic/eval-expanded paths (`$HOME`, command substitution,
                // globs the shell expands); relative script paths and file
                // paths embedded in interpreter `-c`/`-e` code (`python`,
                // `node`, …, which are excluded from the allowlist); and any
                // path operand of a command outside the allowlist below.
                if current_program.as_deref() == Some("dd")
                    && let Some(value) = dd_file_operand(word)
                    && let Some(outside) =
                        literal_path_word_escape(value, command_cwd, root, tmp_dir)
                {
                    return Some(outside);
                }
                if literal_path_operand_command(current_program.as_deref())
                    && let Some(outside) =
                        literal_path_word_escape(word, command_cwd, root, tmp_dir)
                {
                    return Some(outside);
                }
                if Path::new(word).is_absolute()
                    && let Some(outside) =
                        literal_path_word_escape(word, command_cwd, root, tmp_dir)
                {
                    return Some(outside);
                }
                i += 1;
            }
        }
    }
    None
}

fn literal_path_operand_command(program: Option<&str>) -> bool {
    // Commands whose non-option operands are genuinely filesystem paths.
    // For these we boundary-check relative operands as well as absolute
    // ones (absolute operands are checked for *every* command separately).
    //
    // Inclusion rule: the program's bare (non-`-`) operands are the files it
    // reads or writes. Deliberately EXCLUDED are commands whose primary
    // operands are not paths — subcommand tools (`git`, `cargo`, `npm`),
    // string emitters (`echo`, `printf`), network tools (`curl`, `ssh`),
    // stdin-only filters (`tr`), and pure path-string manipulators that never
    // open the file (`dirname`, `basename`) — to avoid false-positive
    // approval prompts on their non-path arguments. Language interpreters
    // (`python`, `node`, `ruby`, `perl`, `bash`, `sh`) are also excluded: they
    // accept inline code via `-c`/`-e`, and this static pass cannot separate a
    // script-path operand from a code operand, so their script-path traversal
    // vector remains governed by sandboxing/approval (documented residual).
    matches!(
        program,
        Some(
            // Original allowlist (unchanged).
            "cat"
                | "head"
                | "tail"
                | "less"
                | "more"
                | "ls"
                | "find"
                | "stat"
                | "file"
                | "wc"
                | "cp"
                | "mv"
                | "rm"
                | "mkdir"
                | "touch"
                | "tee"
                | "chmod"
                | "chown"
                | "grep"
                | "rg"
                // Stream editors / text processors that take file operands.
                | "sed"
                | "awk"
                | "gawk"
                | "mawk"
                | "sort"
                | "cut"
                | "nl"
                | "tac"
                | "rev"
                | "paste"
                | "join"
                | "comm"
                | "split"
                | "csplit"
                | "expand"
                | "unexpand"
                | "fold"
                | "fmt"
                | "pr"
                // Binary / encoding viewers and transcoders.
                | "base64"
                | "base32"
                | "xxd"
                | "hexdump"
                | "od"
                | "strings"
                // File comparison.
                | "cmp"
                | "diff"
                | "sdiff"
                | "colordiff"
                // Checksums / digests (operands are the files hashed).
                | "sha1sum"
                | "sha224sum"
                | "sha256sum"
                | "sha384sum"
                | "sha512sum"
                | "md5sum"
                | "b2sum"
                | "cksum"
                | "sum"
                // Truncation / secure delete / link + path resolution.
                | "truncate"
                | "shred"
                | "readlink"
                | "realpath"
                | "install"
                | "ln"
                // Compression / archive tools (file operands are paths).
                | "gzip"
                | "gunzip"
                | "zcat"
                | "gzcat"
                | "bzip2"
                | "bunzip2"
                | "bzcat"
                | "xz"
                | "unxz"
                | "xzcat"
                | "zstd"
                | "unzstd"
                | "zstdcat"
                | "lz4"
                | "tar"
                | "cpio"
                | "unzip"
                | "zip"
                // Structured-data / db / crypto file tools.
                | "jq"
                | "yq"
                | "sqlite3"
                | "openssl"
        )
    )
}

/// Extract the path value of a `dd` `if=`/`of=` key-value operand.
///
/// `dd` takes its source/destination files as `if=PATH` / `of=PATH` words
/// rather than bare path operands, so the generic operand scan (which sees
/// a token like `if=../../etc/shadow` whose first `if=..` component absorbs
/// one `..` level and masks the traversal) never resolves the real path.
/// Other `dd` operands (`bs=`, `count=`, `conv=`, …) are not paths and are
/// intentionally ignored.
fn dd_file_operand(word: &str) -> Option<&str> {
    word.strip_prefix("if=").or_else(|| word.strip_prefix("of="))
}

/// Last path component of a program word, treating both `/` and `\` as
/// separators, so `/bin/cat` and `C:\\bin\\cat.exe` normalize to `cat` /
/// `cat.exe`. A trailing separator (`/bin/`) falls back to the whole word.
fn program_basename(word: &str) -> &str {
    word.rsplit(['/', '\\'])
        .find(|segment| !segment.is_empty())
        .unwrap_or(word)
}

/// Known command wrappers whose first non-option operand is the *real*
/// program. We skip a leading run of these so the allowlist / `dd` gate is
/// applied to the effective program (`env nice cat …` gates on `cat`).
/// Basename-normalized so `/usr/bin/env` counts. Conservative on purpose:
/// only wrappers we can safely resolve past are listed; anything else falls
/// through to being treated as the program itself.
fn is_command_wrapper(word: &str) -> bool {
    matches!(
        program_basename(word),
        "env"
            | "command"
            | "exec"
            | "nice"
            | "time"
            | "stdbuf"
            | "nohup"
            | "setsid"
            | "xargs"
            | "busybox"
            | "sudo"
            | "doas"
    )
}

/// A `NAME=value` environment-variable assignment prefix (shell allows these
/// before the program, and `env` takes them as arguments). Only a valid
/// identifier before `=` qualifies, so a path like `../a=b` is not mistaken
/// for one.
fn looks_like_assignment(word: &str) -> bool {
    match word.find('=') {
        Some(eq) if eq > 0 => word[..eq].char_indices().all(|(idx, c)| {
            c == '_' || c.is_ascii_alphabetic() || (idx > 0 && c.is_ascii_digit())
        }),
        _ => false,
    }
}

/// Resolve the index of the effective program word starting at `start`,
/// skipping a leading run of env-var assignments and known command wrappers
/// (plus each wrapper's option/assignment arguments). Returns that index and
/// whether anything was skipped. Stops at the first non-wrapper word, an
/// operator, or end of tokens — never crashing, never skipping an actual path
/// operand out of the scan. `skipped` lets the caller keep the absolute-path
/// check on the effective-program token that it had before stripping.
fn effective_program_index(tokens: &[ShellToken], mut i: usize) -> (usize, bool) {
    let mut skipped = false;
    loop {
        let Some(ShellToken::Word(word)) = tokens.get(i) else {
            return (i, skipped);
        };
        // Leading `FOO=bar` assignments are not the program.
        if looks_like_assignment(word) {
            skipped = true;
            i += 1;
            continue;
        }
        if is_command_wrapper(word) {
            let is_env = program_basename(word) == "env";
            skipped = true;
            i += 1;
            // Skip this wrapper's own options; for `env`, also its `VAR=value`
            // assignment arguments. A bare `-` is a real operand, not an option.
            while let Some(ShellToken::Word(arg)) = tokens.get(i) {
                let is_option = arg.starts_with('-') && arg != "-";
                let is_env_assignment = is_env && looks_like_assignment(arg);
                if is_option || is_env_assignment {
                    i += 1;
                } else {
                    break;
                }
            }
            continue;
        }
        return (i, skipped);
    }
}

fn literal_path_word_escape(
    word: &str,
    command_cwd: &Path,
    root: &Path,
    tmp_dir: Option<&Path>,
) -> Option<PathBuf> {
    if word.starts_with('-') || dynamic_shell_path(word) {
        return None;
    }
    let path = Path::new(word);
    let path_like = path.is_absolute()
        || word.contains('/')
        || word.contains('\\')
        || word == "."
        || word == "..";
    if !path_like {
        return None;
    }
    let resolved = crate::tools::common::resolve(word, command_cwd);
    outside_session_boundary(&resolved, root, tmp_dir)
}

fn directory_change_target(tokens: &[ShellToken], mut i: usize, pushd: bool) -> Option<String> {
    while i < tokens.len() {
        match &tokens[i] {
            ShellToken::Operator(_) => return None,
            ShellToken::Word(word) if word.is_empty() => i += 1,
            ShellToken::Word(word) if word.contains('=') && !word.starts_with('/') => i += 1,
            ShellToken::Word(word) if pushd && (word.starts_with('+') || word.starts_with('-')) => {
                i += 1
            }
            ShellToken::Word(word) if word.starts_with('-') && word != "-" => i += 1,
            ShellToken::Word(word) => return Some(word.clone()),
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ShellToken {
    Word(String),
    Operator(String),
}

fn shell_tokens(command: &str) -> Vec<ShellToken> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut chars = command.chars().peekable();
    let mut quote: Option<char> = None;
    // True while the current position is mid-word. An unquoted `#` starts a
    // comment only at a word boundary (command start or right after
    // whitespace / a separator), never mid-token — matching shell semantics.
    // Entering a quote counts as starting a word, so `''#x` / `'a'#b` keep the
    // `#` literal.
    let mut word_started = false;

    while let Some(ch) = chars.next() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else if ch == '\\' && q == '"' {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            } else {
                word.push(ch);
            }
            continue;
        }

        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                word_started = true;
            }
            '\\' => {
                // Escaped char (including an escaped `#` or newline) is a
                // literal part of the word, never a comment or separator.
                word_started = true;
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            }
            '#' if !word_started => {
                // Unquoted `#` at a word boundary begins a comment running to
                // end of line. The terminating newline is left in the stream
                // so the next iteration still emits it as a command separator.
                while let Some(&next) = chars.peek() {
                    if next == '\n' {
                        break;
                    }
                    chars.next();
                }
            }
            // An unquoted newline is a command separator, exactly like `;`, so
            // a following line is scanned under its own first word rather than
            // the previous command's program.
            '\n' => {
                push_word(&mut tokens, &mut word);
                tokens.push(ShellToken::Operator("\n".to_string()));
                word_started = false;
            }
            c if c.is_whitespace() => {
                push_word(&mut tokens, &mut word);
                word_started = false;
            }
            ';' | '(' | ')' => {
                push_word(&mut tokens, &mut word);
                tokens.push(ShellToken::Operator(ch.to_string()));
                word_started = false;
            }
            '&' | '|' => {
                push_word(&mut tokens, &mut word);
                let mut op = ch.to_string();
                if chars.peek().copied() == Some(ch) {
                    op.push(chars.next().unwrap());
                }
                tokens.push(ShellToken::Operator(op));
                word_started = false;
            }
            _ => {
                word.push(ch);
                word_started = true;
            }
        }
    }
    push_word(&mut tokens, &mut word);
    tokens
}

fn push_word(tokens: &mut Vec<ShellToken>, word: &mut String) {
    if !word.is_empty() {
        tokens.push(ShellToken::Word(std::mem::take(word)));
    }
}

pub(super) fn dynamic_shell_path(path: &str) -> bool {
    path.is_empty()
        || path == "-"
        || path.starts_with('~')
        || path.contains('$')
        || path.contains('`')
        || path.contains('*')
        || path.contains('?')
        || path.contains('[')
        || path.contains(']')
        || path.contains('{')
        || path.contains('}')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build `(root, cwd, outside)` where `cwd` is two levels below the
    /// tmp root and `outside` is a sibling file the boundary must reject.
    /// Mirrors the `command_directory_escape` idiom in `bash/tests.rs`.
    fn boundary_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let cwd = root.join("sub");
        std::fs::create_dir_all(&cwd).unwrap();
        let outside = tmp.path().join("outside");
        std::fs::write(&outside, "secret").unwrap();
        (tmp, root, cwd, outside)
    }

    // Vectors that were previously NOT boundary-checked because the command
    // was outside the relative-operand allowlist. Each must now resolve to
    // the escaping `outside` path. These assertions fail against the
    // pre-expansion allowlist and pass after it.

    #[test]
    fn sed_relative_operand_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        assert_eq!(
            command_directory_escape("sed -n 1p ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn xxd_relative_operand_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        assert_eq!(
            command_directory_escape("xxd ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn sort_relative_operand_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        assert_eq!(
            command_directory_escape("sort ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn awk_relative_operand_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // The awk program (`{print}`) contains `{`, so it is treated as a
        // dynamic/eval token and skipped; only the file operand is checked.
        assert_eq!(
            command_directory_escape("awk {print} ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    // `dd` names its files via `if=`/`of=` key-value operands. A bare-path
    // scan is defeated by the `if=..` component absorbing one `..` level, so
    // this needs the dedicated `dd_file_operand` extraction.

    #[test]
    fn dd_if_operand_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        assert_eq!(
            command_directory_escape("dd if=../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn dd_of_operand_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        assert_eq!(
            command_directory_escape("dd of=../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn dd_absolute_if_operand_is_flagged() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // `if=/etc/passwd` is not an absolute *token* (it starts with `if=`),
        // so the generic absolute-operand check misses it; `dd_file_operand`
        // still surfaces the absolute path inside the value.
        assert_eq!(
            command_directory_escape("dd if=/etc/passwd", &cwd, &root, None).as_deref(),
            Some(Path::new(if cfg!(target_os = "macos") {
                "/private/etc/passwd"
            } else {
                "/etc/passwd"
            }))
        );
    }

    // Negative tests: locking in that the expansion did NOT over-broaden.
    // Excluded commands must not have their non-path (or even relative
    // path-looking) operands flagged as escapes.

    #[test]
    fn excluded_subcommand_tool_operand_is_not_flagged() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // `git` is deliberately excluded; `checkout`/`main` must not prompt.
        assert!(command_directory_escape("git checkout main", &cwd, &root, None).is_none());
    }

    #[test]
    fn excluded_echo_relative_operand_is_not_flagged() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // `echo` never opens its arguments; even a `../` operand is inert.
        assert!(command_directory_escape("echo ../foo", &cwd, &root, None).is_none());
    }

    #[test]
    fn allowlisted_relative_operand_inside_root_is_not_flagged() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        std::fs::write(cwd.join("inside"), "ok").unwrap();
        // A newly-allowlisted command reading an in-boundary file is allowed.
        assert!(command_directory_escape("sort ./inside", &cwd, &root, None).is_none());
    }

    // CONCERN 1: newlines and `#` comments must act as command boundaries so a
    // later line/command is scanned under its own program, not the first
    // line's word. These fail pre-fix (the tokenizer folded `\n` into generic
    // whitespace and treated `#` as an ordinary char).

    #[test]
    fn comment_line_does_not_hide_following_operand() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // Pre-fix the `#` word and the newline were inert, so the `sed`
        // operand was checked under `#`/first-word and slipped through.
        assert_eq!(
            command_directory_escape("# comment\nsed -n 1p ../../outside", &cwd, &root, None)
                .as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn newline_separated_second_command_is_scanned_under_its_own_program() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // Second line must be gated by `cat`, not the first line's `git`.
        assert_eq!(
            command_directory_escape("git log --oneline\ncat ../../outside", &cwd, &root, None)
                .as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn newline_second_command_with_non_path_program_is_not_flagged() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        std::fs::write(cwd.join("inside"), "ok").unwrap();
        // First line reads an in-boundary file; the second line is a non-path
        // command. The newline separator must not smuggle a false positive.
        assert!(command_directory_escape("cat ./inside\necho hi", &cwd, &root, None).is_none());
    }

    #[test]
    fn quoted_hash_is_not_a_comment() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // `#` inside quotes is a literal, not a comment; the in-boundary
        // operand is read normally and nothing is hidden or flagged.
        assert!(
            command_directory_escape("grep '#notacomment' ./inside", &cwd, &root, None).is_none()
        );
    }

    #[test]
    fn hash_inside_word_is_literal() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // A `#` inside a quoted filename is part of the path, not a comment.
        assert!(command_directory_escape("cat './has#hash'", &cwd, &root, None).is_none());
    }

    #[test]
    fn trailing_comment_operand_is_not_scanned() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        std::fs::write(cwd.join("inside"), "ok").unwrap();
        // A word-boundary `#` starts a comment to end-of-line, so the escaping
        // token after it is not a real operand and must be ignored. This
        // discriminates the `#`-comment arm specifically: without it, the
        // `../../outside` word would be scanned under the allowlisted `cat`
        // and wrongly flagged (the newline-based tests still pass via the
        // newline separator alone, so they do not cover this path).
        assert!(
            command_directory_escape("cat ./inside # ../../outside", &cwd, &root, None).is_none()
        );
    }

    // CONCERN 2: program is matched by BASENAME after skipping known wrappers,
    // so path prefixes (`/bin/cat`) and wrapper prefixes (`env`, `command`)
    // no longer evade the allowlist. These fail pre-fix (exact first-word
    // match against `/bin/cat`, `env`, `command`).

    #[test]
    fn absolute_program_path_is_basename_matched() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        assert_eq!(
            command_directory_escape("/bin/cat ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn env_wrapper_is_skipped_to_effective_program() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        assert_eq!(
            command_directory_escape("env cat ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn command_wrapper_is_skipped_to_effective_program() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        assert_eq!(
            command_directory_escape("command sed -n 1p ../../outside", &cwd, &root, None)
                .as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn stacked_wrappers_resolve_to_effective_program() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // `env nice cat` must still gate on `cat`.
        assert_eq!(
            command_directory_escape("env nice cat ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn env_assignment_prefix_is_skipped() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // `env FOO=bar cat` — the assignment argument is skipped, `cat` gates.
        assert_eq!(
            command_directory_escape("env FOO=bar cat ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn wrapper_skip_preserves_absolute_program_check() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // The effective program token keeps the absolute check it had as an
        // operand before wrapper stripping; wrapper-skipping must not let it
        // go unchecked.
        assert_eq!(
            command_directory_escape("env /etc/passwd", &cwd, &root, None).as_deref(),
            Some(Path::new(if cfg!(target_os = "macos") {
                "/private/etc/passwd"
            } else {
                "/etc/passwd"
            }))
        );
    }

    #[test]
    fn wrapped_dd_operand_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // Basename + wrapper skip also feeds the `dd` if=/of= handler.
        assert_eq!(
            command_directory_escape("/usr/bin/dd if=../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }
}
