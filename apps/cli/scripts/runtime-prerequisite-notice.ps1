# Read-only, best-effort post-install guidance. Never install or invoke remedies.
if (-not $IsLinux) { exit 0 }
if (Get-Command bwrap -ErrorAction SilentlyContinue) { exit 0 }

$family = "unknown"
if (Test-Path -LiteralPath "/etc/os-release" -PathType Leaf) {
    $osRelease = Get-Content -LiteralPath "/etc/os-release" -ErrorAction SilentlyContinue
    $identity = ($osRelease | Where-Object { $_ -match '^(ID|ID_LIKE)=' }) -join ' '
    if ($identity -match '(debian|ubuntu)') { $family = "debian" }
    elseif ($identity -match '(fedora|rhel|centos)') { $family = "fedora" }
    elseif ($identity -match 'arch') { $family = "arch" }
}

[Console]::Error.WriteLine("Warning: Bubblewrap (bwrap) is not available; Cockpit installed successfully, but Linux shell sandboxing is weaker.")
switch ($family) {
    "debian" { [Console]::Error.WriteLine("Install the bubblewrap package with your Debian/Ubuntu package tools, then verify with: bwrap --version") }
    "fedora" { [Console]::Error.WriteLine("Install the bubblewrap package with your Fedora/RHEL package tools, then verify with: bwrap --version") }
    "arch" { [Console]::Error.WriteLine("Install the bubblewrap package with your Arch package tools, then verify with: bwrap --version") }
    default { [Console]::Error.WriteLine("See https://github.com/containers/bubblewrap and verify with: bwrap --version") }
}
exit 0
