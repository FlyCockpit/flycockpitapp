use anyhow::{Context, Result};

pub fn open(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut command = std::process::Command::new("open");
        command.arg(url);
        command
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut command = std::process::Command::new("cmd");
        command.args(["/C", "start", "", url]);
        command
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(url);
        command
    };
    cmd.spawn().context("launching browser")?;
    Ok(())
}
