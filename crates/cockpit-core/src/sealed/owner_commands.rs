//! The `/sealed` Owner command grammar.
//!
//! This module owns the explicit `/sealed` and `/sealed action` command
//! grammar. Metadata commands map to peer-authenticated sealed-record/action
//! RPCs; no ellipsis/free-form origin/revision payload exists.
//!
//! # Grammar
//!
//! ```text
//! /sealed                                  -> list (machine-wide inventory)
//! /sealed create <name> --scope <s> --description <safe-text>
//! /sealed edit <record-id> --description <safe-text>
//! /sealed replace <record-id>
//! /sealed rotate <record-id>
//! /sealed delete <record-id> --confirm <record-id>
//! /sealed recover <record-id>
//! /sealed action list
//! /sealed action create <kind-id> --project <id> --description <safe-text> --origin-id <id> --projection-id <id>
//! /sealed action revise <action-id> --description <safe-text>|--enabled true|false
//! /sealed action retire <action-id> --confirm <action-id>
//! ```
//!
//! # Invariants
//!
//! * Unknown IDs/flags reject before persistence.
//! * No ellipsis or free-form origin/revision payload.
//! * `--scope` accepts only `session`, `project`, `global`.
//! * `--confirm` must exactly match the record/action id for delete/retire.
//! * Description is safe text (bounded, control-character free).
//! * No secret material in any command field: create/replace/rotate open a
//!   local no-echo sensitive frame; recover opens an ephemeral foreground
//!   reveal overlay.

use anyhow::{Context, Result, bail};

use super::identity::{SealedDescription, SealedName, SealedRecordId, SealedScopeKind};

/// The parsed `/sealed` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedCommand {
    /// `/sealed` — machine-wide Owner inventory. Literals hidden by default.
    List {
        /// Optional safe scope filter.
        scope: Option<SealedScopeKind>,
        /// Optional canonical project filter.
        project: Option<String>,
    },
    /// `/sealed create <name> --scope <s> --description <safe-text>`
    Create {
        name: SealedName,
        scope: SealedScopeKind,
        description: SealedDescription,
    },
    /// `/sealed edit <record-id> --description <safe-text>`
    Edit {
        record_id: SealedRecordId,
        description: SealedDescription,
    },
    /// `/sealed replace <record-id>` — opens a no-echo sensitive frame.
    Replace { record_id: SealedRecordId },
    /// `/sealed rotate <record-id>` — opens a no-echo sensitive frame.
    Rotate { record_id: SealedRecordId },
    /// `/sealed delete <record-id> --confirm <record-id>`
    Delete {
        record_id: SealedRecordId,
        confirm: SealedRecordId,
    },
    /// `/sealed recover <record-id>` — opens an ephemeral foreground reveal.
    Recover { record_id: SealedRecordId },
    /// `/sealed action ...`
    Action(SealedActionCommand),
}

/// The parsed `/sealed action` subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedActionCommand {
    /// `/sealed action list`
    List,
    /// `/sealed action create <kind-id> --project <id> --description <safe-text> --origin-id <id> --projection-id <id>`.
    /// For `knowledge_base_copy`, `origin_id` is the configured KB registry
    /// label; the daemon resolves and pins its immutable sealed namespace.
    Create {
        kind_id: String,
        project_id: String,
        description: SealedDescription,
        origin_id: String,
        projection_id: String,
    },
    /// `/sealed action revise <action-id> --description <safe-text>`
    ReviseDescription {
        action_id: String,
        description: SealedDescription,
    },
    /// `/sealed action revise <action-id> --enabled true|false`
    ReviseEnabled { action_id: String, enabled: bool },
    /// `/sealed action retire <action-id> --confirm <action-id>`
    Retire { action_id: String, confirm: String },
}

/// Parse a `/sealed` command from its argument tokens.
///
/// The tokens are the space-separated words after `/sealed`. Unknown IDs/flags
/// reject before persistence. No free-form origin/revision payload.
pub fn parse_sealed_command(tokens: &[&str]) -> Result<SealedCommand> {
    if tokens.is_empty() {
        return Ok(SealedCommand::List {
            scope: None,
            project: None,
        });
    }
    match tokens[0] {
        "create" => parse_create(&tokens[1..]),
        "edit" => parse_edit(&tokens[1..]),
        "replace" => parse_replace(&tokens[1..]),
        "rotate" => parse_rotate(&tokens[1..]),
        "delete" => parse_delete(&tokens[1..]),
        "recover" => parse_recover(&tokens[1..]),
        "action" => parse_action(&tokens[1..]).map(SealedCommand::Action),
        "list" => parse_list(&tokens[1..]),
        _ => bail!("unknown `/sealed` subcommand: `{}`", tokens[0]),
    }
}

fn parse_list(tokens: &[&str]) -> Result<SealedCommand> {
    let mut scope = None;
    let mut project = None;
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i] {
            "--scope" => {
                i += 1;
                scope = Some(parse_scope(
                    tokens.get(i).context("--scope requires a value")?,
                )?);
            }
            "--project" => {
                i += 1;
                project = Some(
                    tokens
                        .get(i)
                        .context("--project requires a value")?
                        .to_string(),
                );
            }
            _ => bail!("unknown `/sealed list` flag: `{}`", tokens[i]),
        }
        i += 1;
    }
    Ok(SealedCommand::List { scope, project })
}

fn parse_create(tokens: &[&str]) -> Result<SealedCommand> {
    let name = tokens.first().context("`/sealed create` requires a name")?;
    let name = SealedName::canonical(name)?;
    let mut scope = None;
    let mut description = None;
    let mut i = 1;
    while i < tokens.len() {
        match tokens[i] {
            "--scope" => {
                i += 1;
                scope = Some(parse_scope(
                    tokens.get(i).context("--scope requires a value")?,
                )?);
            }
            "--description" => {
                i += 1;
                description = Some(SealedDescription::parse(
                    tokens.get(i).context("--description requires a value")?,
                )?);
            }
            _ => bail!("unknown `/sealed create` flag: `{}`", tokens[i]),
        }
        i += 1;
    }
    let scope = scope.context("`/sealed create` requires --scope")?;
    let description = description.context("`/sealed create` requires --description")?;
    Ok(SealedCommand::Create {
        name,
        scope,
        description,
    })
}

fn parse_edit(tokens: &[&str]) -> Result<SealedCommand> {
    let record_id = SealedRecordId::parse(
        tokens
            .first()
            .context("`/sealed edit` requires a record id")?,
    )?;
    let mut description = None;
    let mut i = 1;
    while i < tokens.len() {
        match tokens[i] {
            "--description" => {
                i += 1;
                description = Some(SealedDescription::parse(
                    tokens.get(i).context("--description requires a value")?,
                )?);
            }
            _ => bail!("unknown `/sealed edit` flag: `{}`", tokens[i]),
        }
        i += 1;
    }
    let description = description.context("`/sealed edit` requires --description")?;
    Ok(SealedCommand::Edit {
        record_id,
        description,
    })
}

fn parse_replace(tokens: &[&str]) -> Result<SealedCommand> {
    let record_id = SealedRecordId::parse(
        tokens
            .first()
            .context("`/sealed replace` requires a record id")?,
    )?;
    if tokens.len() > 1 {
        bail!("`/sealed replace` accepts no flags");
    }
    Ok(SealedCommand::Replace { record_id })
}

fn parse_rotate(tokens: &[&str]) -> Result<SealedCommand> {
    let record_id = SealedRecordId::parse(
        tokens
            .first()
            .context("`/sealed rotate` requires a record id")?,
    )?;
    if tokens.len() > 1 {
        bail!("`/sealed rotate` accepts no flags");
    }
    Ok(SealedCommand::Rotate { record_id })
}

fn parse_delete(tokens: &[&str]) -> Result<SealedCommand> {
    let record_id = SealedRecordId::parse(
        tokens
            .first()
            .context("`/sealed delete` requires a record id")?,
    )?;
    let mut confirm = None;
    let mut i = 1;
    while i < tokens.len() {
        match tokens[i] {
            "--confirm" => {
                i += 1;
                confirm = Some(SealedRecordId::parse(
                    tokens.get(i).context("--confirm requires a value")?,
                )?);
            }
            _ => bail!("unknown `/sealed delete` flag: `{}`", tokens[i]),
        }
        i += 1;
    }
    let confirm = confirm.context("`/sealed delete` requires --confirm")?;
    if record_id != confirm {
        bail!("`/sealed delete` confirmation must exactly match the record id");
    }
    Ok(SealedCommand::Delete { record_id, confirm })
}

fn parse_recover(tokens: &[&str]) -> Result<SealedCommand> {
    let record_id = SealedRecordId::parse(
        tokens
            .first()
            .context("`/sealed recover` requires a record id")?,
    )?;
    if tokens.len() > 1 {
        bail!("`/sealed recover` accepts no flags");
    }
    Ok(SealedCommand::Recover { record_id })
}

fn parse_action(tokens: &[&str]) -> Result<SealedActionCommand> {
    if tokens.is_empty() {
        bail!("`/sealed action` requires a subcommand");
    }
    match tokens[0] {
        "list" => {
            if tokens.len() > 1 {
                bail!("`/sealed action list` accepts no flags");
            }
            Ok(SealedActionCommand::List)
        }
        "create" => parse_action_create(&tokens[1..]),
        "revise" => parse_action_revise(&tokens[1..]),
        "retire" => parse_action_retire(&tokens[1..]),
        _ => bail!("unknown `/sealed action` subcommand: `{}`", tokens[0]),
    }
}

fn parse_action_create(tokens: &[&str]) -> Result<SealedActionCommand> {
    let kind_id = tokens
        .first()
        .context("`/sealed action create` requires a kind-id")?;
    let mut project_id = None;
    let mut description = None;
    let mut origin_id = None;
    let mut projection_id = None;
    let mut i = 1;
    while i < tokens.len() {
        match tokens[i] {
            "--project" => {
                i += 1;
                project_id = Some(
                    tokens
                        .get(i)
                        .context("--project requires a value")?
                        .to_string(),
                );
            }
            "--description" => {
                i += 1;
                description = Some(SealedDescription::parse(
                    tokens.get(i).context("--description requires a value")?,
                )?);
            }
            "--origin-id" => {
                i += 1;
                origin_id = Some(
                    tokens
                        .get(i)
                        .context("--origin-id requires a value")?
                        .to_string(),
                );
            }
            "--projection-id" => {
                i += 1;
                projection_id = Some(
                    tokens
                        .get(i)
                        .context("--projection-id requires a value")?
                        .to_string(),
                );
            }
            _ => bail!("unknown `/sealed action create` flag: `{}`", tokens[i]),
        }
        i += 1;
    }
    let project_id = project_id.context("`/sealed action create` requires --project")?;
    let description = description.context("`/sealed action create` requires --description")?;
    let origin_id = origin_id.context("`/sealed action create` requires --origin-id")?;
    let projection_id =
        projection_id.context("`/sealed action create` requires --projection-id")?;
    Ok(SealedActionCommand::Create {
        kind_id: kind_id.to_string(),
        project_id,
        description,
        origin_id,
        projection_id,
    })
}

fn parse_action_revise(tokens: &[&str]) -> Result<SealedActionCommand> {
    let action_id = tokens
        .first()
        .context("`/sealed action revise` requires an action-id")?;
    let mut description = None;
    let mut enabled = None;
    let mut i = 1;
    while i < tokens.len() {
        match tokens[i] {
            "--description" => {
                i += 1;
                description = Some(SealedDescription::parse(
                    tokens.get(i).context("--description requires a value")?,
                )?);
            }
            "--enabled" => {
                i += 1;
                let value = tokens.get(i).context("--enabled requires a value")?;
                enabled = Some(match *value {
                    "true" => true,
                    "false" => false,
                    _ => bail!("--enabled must be `true` or `false`"),
                });
            }
            _ => bail!("unknown `/sealed action revise` flag: `{}`", tokens[i]),
        }
        i += 1;
    }
    match (description, enabled) {
        (Some(desc), None) => Ok(SealedActionCommand::ReviseDescription {
            action_id: action_id.to_string(),
            description: desc,
        }),
        (None, Some(en)) => Ok(SealedActionCommand::ReviseEnabled {
            action_id: action_id.to_string(),
            enabled: en,
        }),
        (Some(_), Some(_)) => {
            bail!("`/sealed action revise` accepts --description or --enabled, not both")
        }
        (None, None) => bail!("`/sealed action revise` requires --description or --enabled"),
    }
}

fn parse_action_retire(tokens: &[&str]) -> Result<SealedActionCommand> {
    let action_id = tokens
        .first()
        .context("`/sealed action retire` requires an action-id")?;
    let mut confirm = None;
    let mut i = 1;
    while i < tokens.len() {
        match tokens[i] {
            "--confirm" => {
                i += 1;
                confirm = Some(
                    tokens
                        .get(i)
                        .context("--confirm requires a value")?
                        .to_string(),
                );
            }
            _ => bail!("unknown `/sealed action retire` flag: `{}`", tokens[i]),
        }
        i += 1;
    }
    let confirm = confirm.context("`/sealed action retire` requires --confirm")?;
    if *action_id != confirm {
        bail!("`/sealed action retire` confirmation must exactly match the action id");
    }
    Ok(SealedActionCommand::Retire {
        action_id: action_id.to_string(),
        confirm,
    })
}

fn parse_scope(raw: &str) -> Result<SealedScopeKind> {
    match raw {
        "session" => Ok(SealedScopeKind::Session),
        "project" => Ok(SealedScopeKind::Project),
        "global" => Ok(SealedScopeKind::Global),
        _ => bail!("scope must be `session`, `project`, or `global`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_list() {
        let cmd = parse_sealed_command(&[]).unwrap();
        assert_eq!(
            cmd,
            SealedCommand::List {
                scope: None,
                project: None
            }
        );
    }

    #[test]
    fn list_with_scope_filter() {
        let cmd = parse_sealed_command(&["list", "--scope", "project"]).unwrap();
        assert_eq!(
            cmd,
            SealedCommand::List {
                scope: Some(SealedScopeKind::Project),
                project: None
            }
        );
    }

    #[test]
    fn list_with_project_filter() {
        let cmd = parse_sealed_command(&["list", "--project", "my-proj"]).unwrap();
        assert_eq!(
            cmd,
            SealedCommand::List {
                scope: None,
                project: Some("my-proj".to_string())
            }
        );
    }

    #[test]
    fn create_parses() {
        let cmd = parse_sealed_command(&[
            "create",
            "deploy_token",
            "--scope",
            "project",
            "--description",
            "Deploy token",
        ])
        .unwrap();
        match cmd {
            SealedCommand::Create {
                name,
                scope,
                description,
            } => {
                assert_eq!(name.as_str(), "deploy_token");
                assert_eq!(scope, SealedScopeKind::Project);
                assert_eq!(description.as_str(), "Deploy token");
            }
            _ => panic!("expected Create"),
        }
    }

    #[test]
    fn create_requires_scope() {
        assert!(parse_sealed_command(&["create", "token", "--description", "desc"]).is_err());
    }

    #[test]
    fn create_requires_description() {
        assert!(parse_sealed_command(&["create", "token", "--scope", "session"]).is_err());
    }

    #[test]
    fn create_rejects_unknown_scope() {
        assert!(
            parse_sealed_command(&[
                "create",
                "token",
                "--scope",
                "universe",
                "--description",
                "desc",
            ])
            .is_err()
        );
    }

    #[test]
    fn edit_parses() {
        let id = SealedRecordId::generate();
        let cmd =
            parse_sealed_command(&["edit", &id.to_string(), "--description", "New desc"]).unwrap();
        match cmd {
            SealedCommand::Edit {
                record_id,
                description,
            } => {
                assert_eq!(record_id, id);
                assert_eq!(description.as_str(), "New desc");
            }
            _ => panic!("expected Edit"),
        }
    }

    #[test]
    fn replace_parses() {
        let id = SealedRecordId::generate();
        let cmd = parse_sealed_command(&["replace", &id.to_string()]).unwrap();
        match cmd {
            SealedCommand::Replace { record_id } => assert_eq!(record_id, id),
            _ => panic!("expected Replace"),
        }
    }

    #[test]
    fn rotate_parses() {
        let id = SealedRecordId::generate();
        let cmd = parse_sealed_command(&["rotate", &id.to_string()]).unwrap();
        match cmd {
            SealedCommand::Rotate { record_id } => assert_eq!(record_id, id),
            _ => panic!("expected Rotate"),
        }
    }

    #[test]
    fn delete_requires_exact_confirm() {
        let id = SealedRecordId::generate();
        let cmd = parse_sealed_command(&["delete", &id.to_string(), "--confirm", &id.to_string()])
            .unwrap();
        match cmd {
            SealedCommand::Delete { record_id, confirm } => {
                assert_eq!(record_id, id);
                assert_eq!(confirm, id);
            }
            _ => panic!("expected Delete"),
        }
    }

    #[test]
    fn delete_rejects_mismatched_confirm() {
        let id1 = SealedRecordId::generate();
        let id2 = SealedRecordId::generate();
        assert!(
            parse_sealed_command(&["delete", &id1.to_string(), "--confirm", &id2.to_string()])
                .is_err()
        );
    }

    #[test]
    fn delete_rejects_missing_confirm() {
        let id = SealedRecordId::generate();
        assert!(parse_sealed_command(&["delete", &id.to_string()]).is_err());
    }

    #[test]
    fn recover_parses() {
        let id = SealedRecordId::generate();
        let cmd = parse_sealed_command(&["recover", &id.to_string()]).unwrap();
        match cmd {
            SealedCommand::Recover { record_id } => assert_eq!(record_id, id),
            _ => panic!("expected Recover"),
        }
    }

    #[test]
    fn action_list_parses() {
        let cmd = parse_sealed_command(&["action", "list"]).unwrap();
        assert_eq!(cmd, SealedCommand::Action(SealedActionCommand::List));
    }

    #[test]
    fn action_create_parses() {
        let cmd = parse_sealed_command(&[
            "action",
            "create",
            "https.deploy.notify",
            "--project",
            "my-proj",
            "--description",
            "Notify",
            "--origin-id",
            "0",
            "--projection-id",
            "http_status_and_ok",
        ])
        .unwrap();
        match cmd {
            SealedCommand::Action(SealedActionCommand::Create {
                kind_id,
                project_id,
                description,
                origin_id,
                projection_id,
            }) => {
                assert_eq!(kind_id, "https.deploy.notify");
                assert_eq!(project_id, "my-proj");
                assert_eq!(description.as_str(), "Notify");
                assert_eq!(origin_id, "0");
                assert_eq!(projection_id, "http_status_and_ok");
            }
            _ => panic!("expected Action Create"),
        }
    }

    #[test]
    fn action_create_requires_all_flags() {
        assert!(
            parse_sealed_command(&[
                "action",
                "create",
                "kind",
                "--project",
                "p",
                "--description",
                "d",
                "--origin-id",
                "0",
            ])
            .is_err()
        );
    }

    #[test]
    fn action_revise_description_parses() {
        let cmd = parse_sealed_command(&["action", "revise", "act-1", "--description", "New desc"])
            .unwrap();
        match cmd {
            SealedCommand::Action(SealedActionCommand::ReviseDescription {
                action_id,
                description,
            }) => {
                assert_eq!(action_id, "act-1");
                assert_eq!(description.as_str(), "New desc");
            }
            _ => panic!("expected ReviseDescription"),
        }
    }

    #[test]
    fn action_revise_enabled_parses() {
        let cmd =
            parse_sealed_command(&["action", "revise", "act-1", "--enabled", "true"]).unwrap();
        match cmd {
            SealedCommand::Action(SealedActionCommand::ReviseEnabled { action_id, enabled }) => {
                assert_eq!(action_id, "act-1");
                assert!(enabled);
            }
            _ => panic!("expected ReviseEnabled"),
        }
    }

    #[test]
    fn action_revise_rejects_both_flags() {
        assert!(
            parse_sealed_command(&[
                "action",
                "revise",
                "act-1",
                "--description",
                "d",
                "--enabled",
                "true",
            ])
            .is_err()
        );
    }

    #[test]
    fn action_retire_requires_exact_confirm() {
        let cmd =
            parse_sealed_command(&["action", "retire", "act-1", "--confirm", "act-1"]).unwrap();
        match cmd {
            SealedCommand::Action(SealedActionCommand::Retire { action_id, confirm }) => {
                assert_eq!(action_id, "act-1");
                assert_eq!(confirm, "act-1");
            }
            _ => panic!("expected Retire"),
        }
    }

    #[test]
    fn action_retire_rejects_mismatched_confirm() {
        assert!(
            parse_sealed_command(&["action", "retire", "act-1", "--confirm", "act-2"]).is_err()
        );
    }

    #[test]
    fn unknown_subcommand_rejects() {
        assert!(parse_sealed_command(&["frobnicate"]).is_err());
    }

    #[test]
    fn unknown_flag_rejects() {
        let id = SealedRecordId::generate();
        assert!(parse_sealed_command(&["rotate", &id.to_string(), "--bogus", "value"]).is_err());
    }
}
