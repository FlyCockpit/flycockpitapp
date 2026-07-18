use std::sync::OnceLock;

static USER_AGENT: OnceLock<String> = OnceLock::new();

pub fn user_agent() -> &'static str {
    USER_AGENT
        .get_or_init(|| {
            format!(
                "cockpit/{} ({} {})",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        })
        .as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_shape_and_memoization_are_stable() {
        let first = user_agent();
        let second = user_agent();

        assert!(std::ptr::eq(first.as_ptr(), second.as_ptr()));
        assert!(first.starts_with("cockpit/"), "{first}");
        assert!(first.contains(" ("), "{first}");
        assert!(first.ends_with(')'), "{first}");
        let (product, platform) = first.split_once(" (").expect("platform comment");
        let version = product
            .strip_prefix("cockpit/")
            .expect("product/version prefix");
        let mut parts = version.split('.');
        for part in [parts.next(), parts.next(), parts.next()] {
            let part = part.expect("major/minor/patch component");
            assert!(
                !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()),
                "{first}"
            );
        }
        let platform = platform.trim_end_matches(')');
        let platform_parts: Vec<_> = platform.split(' ').collect();
        assert_eq!(platform_parts.len(), 2, "{first}");
        assert!(
            platform_parts.iter().all(|part| !part.is_empty()),
            "{first}"
        );
    }

    #[test]
    fn user_agent_contains_compile_time_version_os_and_arch() {
        let value = user_agent();

        assert!(value.contains(env!("CARGO_PKG_VERSION")), "{value}");
        assert!(value.contains(std::env::consts::OS), "{value}");
        assert!(value.contains(std::env::consts::ARCH), "{value}");
    }
}
