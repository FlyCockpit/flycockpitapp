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
    // Inside a `[[ … ]]` conditional, `<`/`>` are string-comparison operators,
    // not redirections, and nothing opens a file — so redirect handling is
    // suppressed while this is set. Bash always terminates `[[` with a
    // standalone `]]` word, which is the only thing that clears it (word arm).
    // Clearing solely on `]]` (never on an operator) is what keeps valid
    // parenthesized (`[[ ( … ) ]]`) and `&&`/`||`-continued multi-line
    // conditionals from being misread as redirects. The cost is that an
    // *unterminated* `[[` leaves this set for the rest of the string — but that
    // is a shell syntax error bash never executes, so nothing is written and no
    // real escape is missed.
    let mut in_double_bracket = false;
    while i < tokens.len() {
        match &tokens[i] {
            ShellToken::Operator(op) => {
                let operand = match tokens.get(i + 1) {
                    Some(ShellToken::Word(word)) => Some(word.as_str()),
                    _ => None,
                };
                // Redirect handling is suppressed inside `[[ … ]]` (see the
                // `in_double_bracket` note above); the operator otherwise falls
                // through to the normal separator/command-start bookkeeping.
                if !in_double_bracket
                    && let Some(kind) = redirect_kind(op, operand)
                {
                    // The word following a redirection operator is consumed by
                    // the redirection, not by the command, so it must never be
                    // re-read as a program or a command operand. Target-file
                    // forms (`> ../out`, `>> ../out`, `< ../in`, `&> ../out`,
                    // and `>&file`) are additionally boundary-checked because
                    // the shell opens them regardless of the current program —
                    // `echo`/`printf` never open their operands, but the shell
                    // opens the redirect target. Heredoc/here-string/fd-dup
                    // forms are skipped without a path check (their operand is a
                    // delimiter, literal text, or a file descriptor).
                    if kind == RedirectKind::TargetFile
                        && let Some(target) = operand
                        && let Some(outside) =
                            redirect_target_escape(target, command_cwd, root, tmp_dir)
                    {
                        return Some(outside);
                    }
                    // A redirection continues the current command, so keep
                    // `command_start`/`current_program` and step past both the
                    // operator and its consumed operand word (if present).
                    i += if operand.is_some() { 2 } else { 1 };
                    continue;
                }
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
                    // A `[[` keyword opens a conditional in which `<`/`>` are
                    // comparisons rather than redirections.
                    if current_program.as_deref() == Some("[[") {
                        in_double_bracket = true;
                    }
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
                // A closing `]]` ends the conditional; its operands (compared
                // as strings) are never opened, so no boundary check applies.
                if in_double_bracket {
                    if word == "]]" {
                        in_double_bracket = false;
                    }
                    i += 1;
                    continue;
                }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirectKind {
    /// Operand is a filesystem path the shell opens — boundary-check it.
    TargetFile,
    /// Operand is a heredoc delimiter, a here-string literal, or a duplicated
    /// file descriptor — consumed by the redirection but never a path.
    NonPath,
}

/// Classify a shell operator as a redirection, if it is one, given the word
/// that follows it. The following word is consumed by the shell, not passed to
/// the command, so the scanner skips it in every case; only `TargetFile` forms
/// name a real filesystem path to boundary-check.
///
/// The `>&` form is operand-sensitive: `>&2` / `>&-` duplicate a file
/// descriptor (`NonPath`), but `>&file` (a non-numeric operand) truncates and
/// opens that file for both stdout and stderr — standard bash, identical to
/// `&>file` — so it is a real `TargetFile`. `<&` has no such filename form
/// (`<&file` is a bash error), so it stays `NonPath`.
fn redirect_kind(op: &str, operand: Option<&str>) -> Option<RedirectKind> {
    match op {
        ">" | ">>" | ">|" | "<" | "<>" | "&>" | "&>>" => Some(RedirectKind::TargetFile),
        ">&" => Some(if operand.map(is_fd_operand).unwrap_or(true) {
            RedirectKind::NonPath
        } else {
            RedirectKind::TargetFile
        }),
        "<<" | "<<-" | "<<<" | "<&" => Some(RedirectKind::NonPath),
        _ => None,
    }
}

/// A file-descriptor operand for `>&`/`<&`: a bare descriptor number or the
/// close form `-`. Anything else is a filename.
fn is_fd_operand(word: &str) -> bool {
    word == "-" || (!word.is_empty() && word.bytes().all(|b| b.is_ascii_digit()))
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
    // A command operand beginning with `-` is an option flag, not a path.
    if word.starts_with('-') {
        return None;
    }
    path_word_escape(word, command_cwd, root, tmp_dir)
}

/// Boundary-check a redirection target. Unlike a command operand, a redirect
/// target is always a pathname — a leading `-` is a literal filename character,
/// not an option — so the option skip in `literal_path_word_escape` must not
/// apply (`> -d/../../outside` still escapes). Dynamic/eval targets remain
/// deferred to the sandbox.
fn redirect_target_escape(
    word: &str,
    command_cwd: &Path,
    root: &Path,
    tmp_dir: Option<&Path>,
) -> Option<PathBuf> {
    path_word_escape(word, command_cwd, root, tmp_dir)
}

fn path_word_escape(
    word: &str,
    command_cwd: &Path,
    root: &Path,
    tmp_dir: Option<&Path>,
) -> Option<PathBuf> {
    if dynamic_shell_path(word) {
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

/// Tokenizer for the native boundary gate. NOTE: this is a second, independent
/// shell tokenizer distinct from `super::shell_write_tokens` /
/// `tokenize_write_line` in `mod.rs`, which drives the SOUL.md/USER.md identity
/// write-guard and the durable-write hint. The two must be kept in rough sync
/// on redirection handling — this one additionally recognizes `&>`/`&>>`/`>&`/
/// `<&`/`<>`, which `tokenize_write_line` does not — but they cannot trivially
/// share code because that one also slurps heredoc *bodies* (`WriteToken::
/// HeredocBody`) that this gate deliberately ignores. If you add a redirection
/// operator here, check whether the write-guard tokenizer needs the same.
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
            '|' => {
                push_word(&mut tokens, &mut word);
                let mut op = String::from("|");
                if chars.peek().copied() == Some('|') {
                    chars.next();
                    op.push('|');
                }
                tokens.push(ShellToken::Operator(op));
                word_started = false;
            }
            '&' => {
                push_word(&mut tokens, &mut word);
                let mut op = String::from("&");
                match chars.peek().copied() {
                    Some('&') => {
                        chars.next();
                        op.push('&');
                    }
                    // `&>` / `&>>` redirect both stdout and stderr to a file.
                    Some('>') => {
                        chars.next();
                        op.push('>');
                        if chars.peek().copied() == Some('>') {
                            chars.next();
                            op.push('>');
                        }
                    }
                    _ => {}
                }
                tokens.push(ShellToken::Operator(op));
                word_started = false;
            }
            '>' => {
                push_word(&mut tokens, &mut word);
                let mut op = String::from(">");
                match chars.peek().copied() {
                    Some('>') => {
                        chars.next();
                        op.push('>');
                    }
                    Some('|') => {
                        chars.next();
                        op.push('|');
                    }
                    // `>&` duplicates a file descriptor (operand is an fd).
                    Some('&') => {
                        chars.next();
                        op.push('&');
                    }
                    _ => {}
                }
                tokens.push(ShellToken::Operator(op));
                word_started = false;
            }
            '<' => {
                push_word(&mut tokens, &mut word);
                let mut op = String::from("<");
                match chars.peek().copied() {
                    Some('<') => {
                        chars.next();
                        op.push('<');
                        match chars.peek().copied() {
                            // `<<<` here-string: operand is literal text.
                            Some('<') => {
                                chars.next();
                                op.push('<');
                            }
                            // `<<-` heredoc: operand is a delimiter word.
                            Some('-') => {
                                chars.next();
                                op.push('-');
                            }
                            _ => {}
                        }
                    }
                    // `<>` opens the target for read-write.
                    Some('>') => {
                        chars.next();
                        op.push('>');
                    }
                    // `<&` duplicates a file descriptor (operand is an fd).
                    Some('&') => {
                        chars.next();
                        op.push('&');
                    }
                    _ => {}
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

    // Redirection targets are opened by the shell, not the command, so they
    // must be boundary-checked even behind a program (`echo`, `printf`, …) that
    // never opens its own operands. These fail pre-fix because the tokenizer
    // folded `>`/`<` into ordinary word characters, so the target was scanned
    // under the (non-path-operand) program and slipped through.

    #[test]
    fn write_redirect_target_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        assert_eq!(
            command_directory_escape("echo pwned > ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn write_redirect_target_without_space_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // No whitespace between `>` and the path — the operator still splits it.
        assert_eq!(
            command_directory_escape("echo pwned >../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn append_redirect_target_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        assert_eq!(
            command_directory_escape("echo pwned >> ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn clobber_redirect_target_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        assert_eq!(
            command_directory_escape("echo pwned >| ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn read_redirect_target_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // `<` reads a file the shell opens; escaping reads are gated too.
        assert_eq!(
            command_directory_escape("grep secret < ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn fd_prefixed_redirect_target_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // `2>PATH` — the leading fd digit is a separate token; the `>` operator
        // still splits off and checks the target.
        assert_eq!(
            command_directory_escape("run 2>../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn stdout_stderr_redirect_target_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // `&>` redirects both stdout and stderr to a file.
        assert_eq!(
            command_directory_escape("run &>../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn append_stdout_stderr_redirect_target_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // `&>>` appends both stdout and stderr to a file.
        assert_eq!(
            command_directory_escape("run &>>../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn read_write_redirect_target_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // `<>` opens the target for read-write; it is a real file operand.
        assert_eq!(
            command_directory_escape("run <> ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn dup_redirect_with_filename_target_is_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // `>&file` (non-numeric operand) truncates and opens that file for both
        // stdout and stderr — standard bash, identical to `&>file`.
        assert_eq!(
            command_directory_escape("echo x >& ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn dup_redirect_with_fd_number_is_not_flagged() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // `>&2` duplicates a descriptor; the operand is an fd, not a path.
        assert!(command_directory_escape("echo x >&2", &cwd, &root, None).is_none());
    }

    #[test]
    fn dash_prefixed_redirect_target_is_flagged() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // A redirect target is always a pathname: a leading `-` is a literal
        // filename character, not an option flag, so the option skip that
        // applies to command operands must not suppress the boundary check.
        assert!(
            command_directory_escape("echo x > -d/../../../outside", &cwd, &root, None).is_some()
        );
    }

    // `[[ … ]]` is a shell keyword in which `<`/`>` are string-comparison
    // operators, not redirections; nothing opens a file, so nothing prompts.

    #[test]
    fn double_bracket_comparison_is_not_a_redirect() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        assert!(command_directory_escape("[[ ../a < ../b ]]", &cwd, &root, None).is_none());
        assert!(command_directory_escape("[[ ../a > ../b ]]", &cwd, &root, None).is_none());
    }

    #[test]
    fn double_bracket_with_logical_ops_is_not_a_redirect() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // `&&`/`||` may appear inside `[[ … ]]`; they must not prematurely
        // close the conditional and re-enable redirect handling.
        assert!(
            command_directory_escape("[[ ../a < ../b && ../c > ../d ]]", &cwd, &root, None)
                .is_none()
        );
    }

    #[test]
    fn double_bracket_grouping_is_not_a_redirect() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // Parentheses group sub-expressions inside `[[ … ]]`; they must not
        // close the conditional and re-enable redirect handling for `<`/`>`.
        assert!(
            command_directory_escape("[[ ( ../a < ../b ) || -n ../c ]]", &cwd, &root, None)
                .is_none()
        );
    }

    #[test]
    fn double_bracket_multiline_continuation_is_not_a_redirect() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // A `[[ … ]]` continued across a newline after `&&` is one conditional;
        // the newline must not close it and turn `>` into a redirect.
        assert!(
            command_directory_escape("[[ ../a < ../b &&\n../c > ../d ]]", &cwd, &root, None)
                .is_none()
        );
    }

    #[test]
    fn single_bracket_redirect_is_still_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // `[ … ]` is the `test` *command* (not a keyword); bash really does
        // treat a following `<` as a redirection, so it stays gated.
        assert_eq!(
            command_directory_escape("[ -n x ] < ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn redirect_after_double_bracket_is_still_flagged() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // Once the conditional closes, a redirect on a following command is
        // gated again — the `[[` suppression does not leak past `]]`/`;`.
        assert_eq!(
            command_directory_escape("[[ -n x ]]; cat > ../../outside", &cwd, &root, None)
                .as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn write_redirect_absolute_target_is_flagged() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        assert_eq!(
            command_directory_escape("echo x > /etc/cron.d/x", &cwd, &root, None).as_deref(),
            Some(Path::new(if cfg!(target_os = "macos") {
                "/private/etc/cron.d/x"
            } else {
                "/etc/cron.d/x"
            }))
        );
    }

    // Negative tests: the redirect handling must not over-flag.

    #[test]
    fn in_boundary_redirect_target_is_not_flagged() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // A redirect that lands inside the session root is allowed silently.
        assert!(command_directory_escape("echo x > ./out.txt", &cwd, &root, None).is_none());
    }

    #[test]
    fn heredoc_delimiter_is_not_treated_as_a_path() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // `<<EOF` names a delimiter, not a file; nothing to flag.
        assert!(command_directory_escape("cat <<EOF", &cwd, &root, None).is_none());
    }

    #[test]
    fn here_string_literal_is_not_treated_as_a_path() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // `<<<` supplies literal text on stdin; the token is not opened as a
        // file, and (critically) must not be scanned as `cat`'s path operand.
        assert!(
            command_directory_escape("cat <<< ../../outside", &cwd, &root, None).is_none()
        );
    }

    #[test]
    fn fd_duplication_operand_is_not_treated_as_a_path() {
        let (_tmp, root, cwd, _outside) = boundary_fixture();
        // `2>&1` duplicates a descriptor; `1` is an fd, not a path.
        assert!(command_directory_escape("run 2>&1", &cwd, &root, None).is_none());
    }

    #[test]
    fn command_after_leading_redirect_is_still_scanned() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // A leading redirect (`> f cmd …`) is valid bash; the command that
        // follows the redirect target must still be gated on its own operands.
        assert_eq!(
            command_directory_escape("> ./out.txt cat ../../outside", &cwd, &root, None)
                .as_deref(),
            Some(outside.as_path())
        );
    }

    #[test]
    fn pipe_still_separates_commands() {
        let (_tmp, root, cwd, outside) = boundary_fixture();
        // Restructuring the `&`/`|` tokenizer arms must not break the pipe
        // separator: the second stage is gated under `cat`, not `echo`.
        assert_eq!(
            command_directory_escape("echo hi | cat ../../outside", &cwd, &root, None).as_deref(),
            Some(outside.as_path())
        );
    }
}
