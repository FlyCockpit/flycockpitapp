//! `cockpit update` — sole manual update authority (disabled until activation).

use anyhow::{Context, Result, bail};
use cockpit_config::config::update_channel::UpdateChannel;
use cockpit_core::updater::{
    UpdateCheckResult, UpdateStatusSnapshot, Updater, effective_update_channel, installed_updater,
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
        installed_updater()
            .apply_manual(channel, args.version.as_deref())
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        return Ok(());
    }

    if channel == UpdateChannel::Off {
        if args.check {
            println!("updates: off");
        }
        return Ok(());
    }

    if !args.check {
        installed_updater()
            .apply_manual(channel, None)
            .await
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        return Ok(());
    }

    match installed_updater().check(channel).await {
        UpdateCheckResult::Off => {
            println!("updates: off");
            Ok(())
        }
        UpdateCheckResult::Disabled(reason) => bail!("{reason}"),
    }
}

fn print_status(snapshot: UpdateStatusSnapshot) {
    match snapshot {
        UpdateStatusSnapshot::Off => println!("updates: off"),
        UpdateStatusSnapshot::Disabled { channel, reason } => {
            println!("updates: disabled ({})", channel.label());
            println!("reason: {reason}");
            println!("hint: run `cockpit doctor` after production updater activation");
        }
    }
}
