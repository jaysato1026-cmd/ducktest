param(
    [Parameter(Mandatory=$true)][string]$Package,
    [switch]$WhatIf,
    [switch]$AllowDowngrade,
    [string]$InstallDirectory
)
$ErrorActionPreference = 'Stop'
$packageRoot = (Resolve-Path -LiteralPath $Package).Path
$sourceExe = Join-Path $packageRoot 'PHPtoSHELL.exe'
$manifest = Join-Path $packageRoot 'release-manifest.json'
if (-not (Test-Path -LiteralPath $sourceExe) -or -not (Test-Path -LiteralPath $manifest)) { throw 'Package must contain PHPtoSHELL.exe and release-manifest.json.' }
$packageManifest = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
if ($packageManifest.product -ne 'PHPtoSHELL' -or -not $packageManifest.files.'PHPtoSHELL.exe') { throw 'Invalid product manifest.' }
foreach ($entry in $packageManifest.files.psobject.Properties) {
    if ($entry.Name -ne [IO.Path]::GetFileName($entry.Name) -or $entry.Name.Contains(':')) { throw 'Manifest paths must be plain filenames.' }
    if ([string]$entry.Value -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid SHA256 manifest entry.' }
    $candidate = Join-Path $packageRoot $entry.Name
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "Missing package file: $($entry.Name)" }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($hash.ComputeHash([IO.File]::ReadAllBytes($candidate)))).Replace('-', '') }
    finally { $hash.Dispose() }
    if ($actual -ne [string]$entry.Value) { throw "Package hash mismatch: $($entry.Name)" }
}
$installRoot = if ($InstallDirectory) { [IO.Path]::GetFullPath($InstallDirectory) } else { Join-Path $env:LOCALAPPDATA 'PHPtoSHELL' }
if ($installRoot.TrimEnd('\') -eq [IO.Path]::GetPathRoot($installRoot).TrimEnd('\')) { throw 'Drive root cannot be an installation directory.' }
if ([string]::Equals($packageRoot.TrimEnd('\'), $installRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { throw 'Package and installation directories must be different.' }
$targetExe = Join-Path $installRoot 'PHPtoSHELL.exe'
$newVersion = [version]((Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).version)
$currentVersion = [version]'0.0.0'
if (Test-Path -LiteralPath $targetExe) {
    $installedManifest = Join-Path $installRoot 'release-manifest.json'
    if (-not (Test-Path -LiteralPath $installedManifest)) { throw 'Installed version is unknown; review the legacy installation before updating.' }
    $currentVersion = [version]((Get-Content -LiteralPath $installedManifest -Raw | ConvertFrom-Json).version)
}
if (-not $AllowDowngrade -and $newVersion -lt $currentVersion) { throw "Refusing downgrade $currentVersion -> $newVersion. Use -AllowDowngrade after review." }
$backup = Join-Path $installRoot ('recovery-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N'))
Write-Output "Planned update: $currentVersion -> $newVersion"
Write-Output "Target: $targetExe"
Write-Output "Recovery copy: $backup"
if ($WhatIf) { Write-Output 'WHATIF: no files changed.'; exit 0 }
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
New-Item -ItemType Directory -Force -Path $backup | Out-Null
foreach ($name in @('PHPtoSHELL.exe','release-manifest.json','policy.json','events.jsonl')) {
    $target = Join-Path $installRoot $name
    if (Test-Path -LiteralPath $target) { Copy-Item -LiteralPath $target -Destination (Join-Path $backup $name) -Force }
}
$temporary = Join-Path $installRoot 'PHPtoSHELL.exe.new'
$executableReplaced = $false
try {
    Copy-Item -LiteralPath $sourceExe -Destination $temporary -Force
    Move-Item -LiteralPath $temporary -Destination $targetExe -Force
    $executableReplaced = $true
    Copy-Item -LiteralPath $manifest -Destination (Join-Path $installRoot 'release-manifest.json') -Force
} catch {
    $updateFailure = $_
    if ($executableReplaced) {
        try {
            foreach ($name in @('PHPtoSHELL.exe','release-manifest.json')) {
                $previous = Join-Path $backup $name
                if (Test-Path -LiteralPath $previous -PathType Leaf) {
                    $restored = Join-Path $installRoot $name
                    Copy-Item -LiteralPath $previous -Destination $restored -Force
                    $checker = [Security.Cryptography.SHA256]::Create()
                    try {
                        $beforeHash = [Convert]::ToBase64String($checker.ComputeHash([IO.File]::ReadAllBytes($previous)))
                        $afterHash = [Convert]::ToBase64String($checker.ComputeHash([IO.File]::ReadAllBytes($restored)))
                    } finally { $checker.Dispose() }
                    if ($beforeHash -ne $afterHash) { throw "Recovery content mismatch: $name" }
                }
            }
        } catch {
            throw "Update and recovery failed. Preserve recovery folder: $backup. $($_.Exception.Message)"
        }
    }
    throw "Update failed. Recovery folder: $backup. $($updateFailure.Exception.Message)"
}
Write-Output "Updated. Existing policy and events were preserved. Recovery copy: $backup"
