//! Slash commands for the composer's command palette, mirroring the web
//! console's set (`agentic-chat-ui/apps/web/src/lib/agent/commands.ts`).
//!
//! The palette opens when the composer holds a bare `/query` with no space yet;
//! once you type a space you're writing arguments and the palette closes.
//! Ranking puts prefix matches above substring matches, so `/co` lists
//! `compact` before `background`.

/// One entry in the command palette.
pub struct Command {
    pub name: &'static str,
    pub hint: &'static str,
}

/// The catalog, in reach-for-most-first order (the tiebreak when several
/// commands match a query equally well).
pub const COMMANDS: &[Command] = &[
    Command {
        name: "new",
        hint: "Start a fresh session",
    },
    Command {
        name: "clear",
        hint: "Clear this conversation",
    },
    Command {
        name: "model",
        hint: "Switch the model",
    },
    Command {
        name: "effort",
        hint: "Set reasoning effort",
    },
    Command {
        name: "think",
        hint: "Show or hide thinking for this conversation",
    },
    Command {
        name: "compact",
        hint: "Summarise and shrink the context",
    },
    Command {
        name: "prune",
        hint: "Drop stale tool output",
    },
    Command {
        name: "agents",
        hint: "List running subagents",
    },
    Command {
        name: "timers",
        hint: "Show timers and loops",
    },
    Command {
        name: "background",
        hint: "Show background commands",
    },
    Command {
        name: "export",
        hint: "Export the transcript as markdown",
    },
];

/// The bare `/query` the composer is typing, or `None` when it isn't in command
/// mode. Commands only count at the very start of the message, up to the first
/// whitespace — after that you're writing arguments.
pub fn slash_query(value: &str) -> Option<&str> {
    let rest = value.strip_prefix('/')?;
    if rest.contains(char::is_whitespace) {
        return None;
    }
    Some(rest)
}

/// Commands matching `query`, prefix matches first. An empty query lists all.
pub fn matches(query: &str) -> Vec<&'static Command> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return COMMANDS.iter().collect();
    }
    let mut prefix = Vec::new();
    let mut contains = Vec::new();
    for command in COMMANDS {
        if command.name.starts_with(&needle) {
            prefix.push(command);
        } else if command.name.contains(&needle) {
            contains.push(command);
        }
    }
    prefix.extend(contains);
    prefix
}

/// Look up a command by exact name, for executing a completed `/name`.
pub fn find(name: &str) -> Option<&'static Command> {
    COMMANDS.iter().find(|command| command.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_query_stops_at_the_first_space() {
        assert_eq!(slash_query("/mod"), Some("mod"));
        assert_eq!(slash_query("/"), Some(""));
        assert_eq!(slash_query("/new arg"), None);
        assert_eq!(slash_query("hello"), None);
    }

    #[test]
    fn matches_rank_prefix_above_substring() {
        // `a` prefixes `agents` and is a substring of several others; the
        // prefix match must sort first.
        let names: Vec<&str> = matches("a").iter().map(|c| c.name).collect();
        assert_eq!(names.first(), Some(&"agents"));
        assert!(names.contains(&"clear") && names.contains(&"background"));
        // A pure substring with no prefix match still comes through.
        assert_eq!(
            matches("port").iter().map(|c| c.name).collect::<Vec<_>>(),
            vec!["export"]
        );
        assert_eq!(
            matches("thi").iter().map(|c| c.name).collect::<Vec<_>>(),
            vec!["think"]
        );
    }

    #[test]
    fn an_empty_query_lists_everything() {
        assert_eq!(matches("").len(), COMMANDS.len());
    }
}
