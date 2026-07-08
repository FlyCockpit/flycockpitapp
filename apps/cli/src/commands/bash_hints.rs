//! `cockpit bash-hints` — inspect the `bash` post-result hint rules.
//!
//! Today the only subcommand is `list`, which prints each built-in rule's
//! stable id and one-sentence description (implementation note).
//! The user-extension surface (config-defined rules) is deferred; when it lands
//! this command also lists the user's rules off the same [`registry`].
//!
//! [`registry`]: crate::engine::bash_hints::registry

use anyhow::Result;

use crate::cli::BashHintsCommand;
use crate::engine::bash_hints::registry;

pub async fn run(cmd: BashHintsCommand) -> Result<()> {
    match cmd {
        BashHintsCommand::List => {
            for rule in registry() {
                println!("{}\t{}", rule.id(), rule.description());
            }
            Ok(())
        }
    }
}
