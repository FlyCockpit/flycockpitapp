#!/bin/sh
# Read-only, best-effort post-install guidance. Never install or invoke remedies.
uname_s=${COCKPIT_INSTALLER_TEST_UNAME:-$(uname -s 2>/dev/null)}
if [ "$uname_s" != Linux ]; then
    exit 0
fi
if command -v bwrap >/dev/null 2>&1; then
    exit 0
fi

family=unknown
os_release=${COCKPIT_INSTALLER_TEST_OS_RELEASE:-/etc/os-release}
if [ -r "$os_release" ]; then
    # Values are data only; do not source the host-controlled file.
    os_like=$(sed -n 's/^ID_LIKE="\{0,1\}\([^"]*\).*/\1/p; s/^ID="\{0,1\}\([^"]*\).*/\1/p' "$os_release" 2>/dev/null | tr '\n' ' ')
    case " $os_like " in
        *" debian "*|*" ubuntu "*) family=debian ;;
        *" fedora "*|*" rhel "*|*" centos "*) family=fedora ;;
        *" arch "*) family=arch ;;
    esac
fi

printf '%s\n' 'Warning: Bubblewrap (bwrap) is not available; Cockpit installed successfully, but Linux shell sandboxing is weaker.' >&2
case "$family" in
    debian) printf '%s\n' 'Install the bubblewrap package with your Debian/Ubuntu package tools, then verify with: bwrap --version' >&2 ;;
    fedora) printf '%s\n' 'Install the bubblewrap package with your Fedora/RHEL package tools, then verify with: bwrap --version' >&2 ;;
    arch) printf '%s\n' 'Install the bubblewrap package with your Arch package tools, then verify with: bwrap --version' >&2 ;;
    *) printf '%s\n' 'See https://github.com/containers/bubblewrap and verify with: bwrap --version' >&2 ;;
esac
exit 0
