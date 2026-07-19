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
                command_start = matches!(op.as_str(), ";" | "&" | "&&" | "||" | "|" | "(");
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
                    current_program = Some(word.clone());
                    command_start = false;
                    i += 1;
                    continue;
                }
                // Best-effort native boundary gate for unconfined platforms
                // and `/sandbox off`: absolute path tokens are always checked,
                // while relative path-looking operands are checked for common
                // path-oriented commands. Dynamic/eval-expanded paths (`$HOME`,
                // command substitution, globs expanded by the shell) are outside
                // this static pass and remain governed by sandboxing or approval.
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
    matches!(
        program,
        Some(
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
        )
    )
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
            '\'' | '"' => quote = Some(ch),
            '\\' => {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            }
            c if c.is_whitespace() => {
                push_word(&mut tokens, &mut word);
            }
            ';' | '(' | ')' => {
                push_word(&mut tokens, &mut word);
                tokens.push(ShellToken::Operator(ch.to_string()));
            }
            '&' | '|' => {
                push_word(&mut tokens, &mut word);
                let mut op = ch.to_string();
                if chars.peek().copied() == Some(ch) {
                    op.push(chars.next().unwrap());
                }
                tokens.push(ShellToken::Operator(op));
            }
            _ => word.push(ch),
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
