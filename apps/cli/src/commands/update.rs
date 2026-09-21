//! `cockpit update` / `cockpit self-update` — one manual update authority.

use anyhow::{Context, Result, bail};
use cockpit_config::config::update_channel::UpdateChannel;
use cockpit_core::updater::{
    ManualUpdateOutcome, UpdateCheckResult, UpdateStatusSnapshot, Updater,
    effective_update_channel, installed_updater,
};

use crate::cli::UpdateArgs;

pub async fn run(args: UpdateArgs) -> Result<()> {
    let configured = effective_update_channel().context("invalid update channel configuration")?;
    let channel = if let Some(raw) = args.channel.as_deref() {
        UpdateChannel::resolve_effective(
            UpdateChannel::from_label(raw).context("invalid --channel value")?,
        )?
    } else {
        configured
    };

    if args.status {
        print_status(installed_updater().status(channel));
        return Ok(());
    }

    if args.version.is_some() {
        let outcome = installed_updater()
            .apply_manual(channel, args.version.as_deref())
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        print_outcome(outcome);
        return Ok(());
    }

    if channel == UpdateChannel::Off {
        if args.check {
            println!("updates: off");
        }
        return Ok(());
    }

    if !args.check {
        let outcome = installed_updater()
            .apply_manual(channel, None)
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        print_outcome(outcome);
        return Ok(());
    }

    match installed_updater().check(channel).await {
        UpdateCheckResult::Off => {
            println!("updates: off");
            Ok(())
        }
        UpdateCheckResult::Available { version } => {
            println!("update available: {version}");
            Ok(())
        }
        UpdateCheckResult::Current => {
            println!("cockpit is up to date");
            Ok(())
        }
        UpdateCheckResult::Failed(reason) => bail!("{reason}"),
    }
}

fn print_outcome(outcome: ManualUpdateOutcome) {
    match outcome {
        ManualUpdateOutcome::Updated { version } => println!("updated cockpit to {version}"),
        ManualUpdateOutcome::Homebrew { command } => println!("{command}"),
    }
}

fn print_status(snapshot: UpdateStatusSnapshot) {
    match snapshot {
        UpdateStatusSnapshot::Off => println!("updates: off"),
        UpdateStatusSnapshot::Ready { channel } => {
            println!("updates: ready ({})", channel.label());
        }
        UpdateStatusSnapshot::Unavailable { channel, reason } => {
            println!("updates: unavailable ({})", channel.label());
            println!("reason: {reason}");
        }
    }
}
