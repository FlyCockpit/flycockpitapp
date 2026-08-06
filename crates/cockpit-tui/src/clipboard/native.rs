//! Native clipboard adapter (arboard on macOS/Windows; Linux always skipped).

use super::types::{PlatformKind, SafeErrorKind, SessionContext, SkipReason};

pub trait NativeClipboard: Send {
    fn set_plain(&mut self, text: &str) -> Result<(), SafeErrorKind>;
    fn set_rich(&mut self, plain: &str, html: &str) -> Result<(), SafeErrorKind>;
}

/// Production arboard-backed native clipboard.
///
/// Linux copy must never call `arboard::Clipboard::new` — the public API
/// cannot consume a held authenticated Wayland stream.
#[derive(Debug, Default)]
pub struct ArboardNative;

impl NativeClipboard for ArboardNative {
    fn set_plain(&mut self, text: &str) -> Result<(), SafeErrorKind> {
        #[cfg(target_os = "linux")]
        {
            let _ = text;
            Err(SafeErrorKind::Unsupported)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut cb =
                arboard::Clipboard::new().map_err(|_| SafeErrorKind::BackendUnavailable)?;
            cb.set_text(text.to_string())
                .map_err(|_| SafeErrorKind::WriteFailed)
        }
    }

    fn set_rich(&mut self, plain: &str, html: &str) -> Result<(), SafeErrorKind> {
        #[cfg(target_os = "linux")]
        {
            let _ = (plain, html);
            Err(SafeErrorKind::Unsupported)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut cb =
                arboard::Clipboard::new().map_err(|_| SafeErrorKind::BackendUnavailable)?;
            cb.set_html(html.to_string(), Some(plain.to_string()))
                .map_err(|_| SafeErrorKind::WriteFailed)
        }
    }
}

/// Deterministic native eligibility (no spawn).
pub fn native_eligibility(ctx: &SessionContext) -> Result<(), SkipReason> {
    if ctx.untrusted_remote {
        return Err(SkipReason::UntrustedRemote);
    }
    if ctx.ssh {
        return Err(SkipReason::SshSession);
    }
    if ctx.wsl_or_container {
        return Err(SkipReason::WslOrContainer);
    }
    if ctx.host_bridge {
        return Err(SkipReason::HostBridge);
    }
    if !ctx.same_host_local_desktop {
        return Err(SkipReason::NotSameHostLocalDesktop);
    }
    match ctx.platform {
        PlatformKind::Linux => {
            // arboard/wl-clipboard-rs cannot consume a held authenticated
            // stream; X11 reopen is also unsupported. Always skip.
            Err(SkipReason::LinuxNativeCannotConsumeHeldStream)
        }
        PlatformKind::MacOs | PlatformKind::Windows => Ok(()),
        PlatformKind::Other => Err(SkipReason::UnsupportedBackend),
    }
}

#[allow(dead_code)]
pub fn native_can_confirm_rich(ctx: &SessionContext) -> bool {
    native_eligibility(ctx).is_ok()
        && matches!(ctx.platform, PlatformKind::MacOs | PlatformKind::Windows)
}

/// Recording native adapter for tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct RecordingNative {
    pub plains: Vec<String>,
    pub rich: Vec<(String, String)>,
    pub fail_plain: Option<SafeErrorKind>,
    pub fail_rich: Option<SafeErrorKind>,
}

#[cfg(test)]
impl NativeClipboard for RecordingNative {
    fn set_plain(&mut self, text: &str) -> Result<(), SafeErrorKind> {
        if let Some(err) = self.fail_plain {
            return Err(err);
        }
        self.plains.push(text.to_string());
        Ok(())
    }

    fn set_rich(&mut self, plain: &str, html: &str) -> Result<(), SafeErrorKind> {
        if let Some(err) = self.fail_rich {
            return Err(err);
        }
        self.rich.push((plain.to_string(), html.to_string()));
        Ok(())
    }
}
