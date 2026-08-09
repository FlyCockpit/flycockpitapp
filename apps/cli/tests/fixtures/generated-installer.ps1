$ErrorActionPreference = "Stop"
$archive = $env:COCKPIT_FIXTURE_ARCHIVE
$expected = $env:COCKPIT_FIXTURE_SHA256
$destination = $env:COCKPIT_FIXTURE_DEST
$stageRoot = $env:COCKPIT_FIXTURE_STAGE_ROOT
if (-not $archive -or -not $expected -or -not $destination -or -not $stageRoot) { throw "missing fixture injection" }
$arch = if ($env:COCKPIT_FIXTURE_ARCH) { $env:COCKPIT_FIXTURE_ARCH } else { [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant() }
if ($arch -notin @("x64", "amd64", "x86_64", "arm64", "aarch64")) { throw "unsupported architecture: $arch" }
$stage = Join-Path $stageRoot ("cockpit-installer-" + [Guid]::NewGuid().ToString("N"))
try {
  $unpack = Join-Path $stage "unpack"
  New-Item -ItemType Directory -Path $unpack -Force | Out-Null
  $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected.ToLowerInvariant()) { throw "checksum verification failed" }
  try { tar -xzf $archive -C $unpack } catch { throw "archive extraction failed" }
  if ($LASTEXITCODE -ne 0) { throw "archive extraction failed" }
  $bins = @(Get-ChildItem -LiteralPath $unpack -Recurse -File | Where-Object { $_.Name -in @("cockpit", "cockpit.exe") })
  if ($bins.Count -ne 1) { throw "archive must contain exactly one executable cockpit" }
  New-Item -ItemType Directory -Path $destination -Force | Out-Null
  $installed = Join-Path $destination "cockpit.exe"
  if (Test-Path -LiteralPath $installed) { throw "destination already exists" }
  $staged = Join-Path $stage "cockpit.exe"
  Copy-Item -LiteralPath $bins[0].FullName -Destination $staged
  Move-Item -LiteralPath $staged -Destination $installed
  $notice = Get-ChildItem -LiteralPath $unpack -Recurse -File -Filter runtime-prerequisite-notice.ps1 | Select-Object -First 1
  if ($notice) { & $notice.FullName }
} finally {
  Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
