//! Host platform detection and platform recipe tables.

use std::collections::BTreeMap;

use super::schema::{HostPlatform, RemedyKind};

/// Detect the host platform for remedy selection.
///
/// Malformed or missing `/etc/os-release` becomes [`HostPlatform::GenericLinux`]
/// on Linux hosts (never panics).
pub fn detect_host_platform() -> HostPlatform {
    detect_host_platform_from(std::env::consts::OS, read_os_release().as_deref())
}

/// Pure platform detection for tests.
pub fn detect_host_platform_from(os: &str, os_release: Option<&str>) -> HostPlatform {
    match os {
        "macos" | "darwin" => HostPlatform::MacOs,
        "windows" => HostPlatform::Windows,
        "linux" => classify_linux(os_release),
        "freebsd" | "openbsd" | "netbsd" | "dragonfly" | "solaris" | "illumos" | "aix" => {
            HostPlatform::OtherUnix
        }
        _ => HostPlatform::Unsupported,
    }
}

fn classify_linux(os_release: Option<&str>) -> HostPlatform {
    let Some(text) = os_release else {
        return HostPlatform::GenericLinux;
    };
    let mut id = None;
    let mut id_like = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ID=") {
            id = Some(unquote(rest));
        } else if let Some(rest) = line.strip_prefix("ID_LIKE=") {
            id_like = Some(unquote(rest));
        }
    }
    let Some(id) = id else {
        // Malformed os-release without ID → generic Linux.
        return HostPlatform::GenericLinux;
    };
    if matches_debian_family(&id, id_like.as_deref()) {
        return HostPlatform::DebianUbuntu;
    }
    if matches_fedora_family(&id, id_like.as_deref()) {
        return HostPlatform::FedoraRhel;
    }
    if matches_arch_family(&id, id_like.as_deref()) {
        return HostPlatform::Arch;
    }
    HostPlatform::GenericLinux
}

fn matches_debian_family(id: &str, id_like: Option<&str>) -> bool {
    matches!(
        id,
        "debian" | "ubuntu" | "linuxmint" | "pop" | "raspbian" | "elementary"
    ) || id_like.is_some_and(|v| {
        v.split_whitespace()
            .any(|t| matches!(t, "debian" | "ubuntu"))
    })
}

fn matches_fedora_family(id: &str, id_like: Option<&str>) -> bool {
    matches!(
        id,
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "ol" | "amzn"
    ) || id_like.is_some_and(|v| {
        v.split_whitespace()
            .any(|t| matches!(t, "fedora" | "rhel" | "centos"))
    })
}

fn matches_arch_family(id: &str, id_like: Option<&str>) -> bool {
    matches!(id, "arch" | "manjaro" | "endeavouros" | "artix")
        || id_like.is_some_and(|v| v.split_whitespace().any(|t| t == "arch"))
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].to_string()
    } else {
        // Malformed quotes (e.g. ID=" or ID=') stay as raw text; classify_linux
        // then falls through to GenericLinux when ID is not a known distro.
        value.to_string()
    }
}

fn read_os_release() -> Option<String> {
    std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .ok()
}

/// Build a multi-platform remedy table for a common package name.
///
/// Recipes never execute package managers; they are display-only strings.
pub fn package_remedy_table(
    package_debian: &str,
    package_fedora: &str,
    package_arch: &str,
    package_brew: &str,
    package_winget: Option<&str>,
) -> BTreeMap<HostPlatform, String> {
    let mut recipes = BTreeMap::new();
    recipes.insert(
        HostPlatform::DebianUbuntu,
        format!("sudo apt-get install {package_debian}"),
    );
    recipes.insert(
        HostPlatform::FedoraRhel,
        format!("sudo dnf install {package_fedora}"),
    );
    recipes.insert(HostPlatform::Arch, format!("sudo pacman -S {package_arch}"));
    recipes.insert(
        HostPlatform::GenericLinux,
        format!("install {package_debian} with your distribution package manager"),
    );
    recipes.insert(HostPlatform::MacOs, format!("brew install {package_brew}"));
    recipes.insert(
        HostPlatform::OtherUnix,
        format!("install {package_debian} with your system package manager"),
    );
    if let Some(winget) = package_winget {
        recipes.insert(HostPlatform::Windows, format!("winget install {winget}"));
    } else {
        recipes.insert(
            HostPlatform::Windows,
            format!("Install `{package_debian}` and ensure it is on PATH."),
        );
    }
    recipes.insert(
        HostPlatform::Unsupported,
        format!("Install `{package_debian}` and ensure it is on PATH."),
    );
    recipes
}

/// Known catalog remedy for common binaries used by tools today.
pub fn common_platform_remedy(binary: &str) -> RemedyKind {
    match binary {
        "rg" | "ripgrep" => RemedyKind::platform_recipes(
            "Install ripgrep or use `search`/`grep` tools instead.",
            package_remedy_table(
                "ripgrep",
                "ripgrep",
                "ripgrep",
                "ripgrep",
                Some("BurntSushi.ripgrep.MSVC"),
            ),
        ),
        "fd" => RemedyKind::platform_recipes(
            "Install fd-find or use `code` with kind `tree`, or use `glob`, instead.",
            package_remedy_table("fd-find", "fd-find", "fd", "fd", Some("sharkdp.fd")),
        ),
        "gsed" => {
            let mut recipes = package_remedy_table("sed", "sed", "sed", "gnu-sed", None);
            recipes.insert(HostPlatform::MacOs, "brew install gnu-sed".into());
            recipes.insert(
                HostPlatform::DebianUbuntu,
                "GNU sed is the system sed on Debian/Ubuntu.".into(),
            );
            RemedyKind::platform_recipes(
                "Install GNU sed if macOS-compatible sed behavior is required.",
                recipes,
            )
        }
        "jq" => RemedyKind::platform_recipes(
            "Install jq, or use Cockpit's bundled `cockpit jq` applet in host sessions.",
            package_remedy_table("jq", "jq", "jq", "jq", Some("jqlang.jq")),
        ),
        "curl" => RemedyKind::platform_recipes(
            "Install curl or use another configured fetch provider.",
            package_remedy_table("curl", "curl", "curl", "curl", Some("cURL.cURL")),
        ),
        "python" | "python3" => RemedyKind::platform_recipes(
            "Install Python 3 and ensure it is on PATH.",
            package_remedy_table(
                "python3",
                "python3",
                "python",
                "python",
                Some("Python.Python.3.12"),
            ),
        ),
        "node" | "nodejs" | "npm" => RemedyKind::platform_recipes(
            "Install Node.js/npm and ensure it is on PATH.",
            package_remedy_table(
                "nodejs npm",
                "nodejs npm",
                "nodejs npm",
                "node",
                Some("OpenJS.NodeJS.LTS"),
            ),
        ),
        "docker" => RemedyKind::platform_recipes(
            "Install Docker or Podman to use container sandbox mode.",
            package_remedy_table(
                "docker.io",
                "docker",
                "docker",
                "docker",
                Some("Docker.DockerDesktop"),
            ),
        ),
        "podman" => RemedyKind::platform_recipes(
            "Install Podman or Docker to use container sandbox mode.",
            package_remedy_table(
                "podman",
                "podman",
                "podman",
                "podman",
                Some("RedHat.Podman"),
            ),
        ),
        other => RemedyKind::prose(format!("Install `{other}` and ensure it is on PATH.")),
    }
}

/// Config-only remedy for an arbitrary configured command (never package mapping).
pub fn configured_command_remedy(command: &str, exact_path: Option<&str>) -> RemedyKind {
    let message = if let Some(path) = exact_path {
        format!(
            "Configured command `{command}` at `{path}` is not a spawnable executable. Check the path and permissions in settings."
        )
    } else {
        format!(
            "Configured command `{command}` is not on PATH as a spawnable executable. Set an absolute path in settings or install it onto PATH."
        )
    };
    RemedyKind::config_guidance(message)
}
