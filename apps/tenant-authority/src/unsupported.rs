//! Platform-support boundary.
//!
//! Non-Unix workspace builds retain every codec, validator, pure state-machine
//! test and bootstrap parser, but the service binary exits before opening a
//! listener with typed [`crate::UnsupportedPlatform`]. This module is the
//! home for any non-Unix-only shims needed to keep the workspace MSRV and
//! Windows CI target compiling.

pub use crate::UnsupportedPlatform;

/// Returns the typed unsupported-platform error a non-Unix service binary
/// exits with before opening a listener.
pub fn unsupported_platform() -> UnsupportedPlatform {
    UnsupportedPlatform
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_platform_is_typed() {
        let err = unsupported_platform();
        assert_eq!(
            err.to_string(),
            "unsupported platform: tenant-authority service requires a Unix peer-credential/admin-socket adapter"
        );
    }
}
