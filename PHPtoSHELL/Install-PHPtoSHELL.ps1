param([switch]$Uninstall)
$ErrorActionPreference = 'Stop'
$installRoot = Join-Path $env:LOCALAPPDATA 'PHPtoSHELL'
$exe = Join-Path $installRoot 'PHPtoSHELL.exe'
$shortcut = Join-Path ([Environment]::GetFolderPath('Desktop')) 'PHPtoSHELL.lnk'
if ($Uninstall) {
    if (Test-Path -LiteralPath $shortcut) { Remove-Item -LiteralPath $shortcut -Force }
    if (Test-Path -LiteralPath $exe) { Remove-Item -LiteralPath $exe -Force }
    Write-Host 'PHPtoSHELL executable and shortcut removed. Policy and event logs remain in the app data folder.'
    exit 0
}
$source = Join-Path $PSScriptRoot 'PHPtoSHELL.exe'
if (-not (Test-Path -LiteralPath $source)) { throw 'PHPtoSHELL.exe was not found beside this installer.' }
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
Copy-Item -LiteralPath $source -Destination $exe -Force
$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($shortcut)
$link.TargetPath = $exe
$link.WorkingDirectory = $installRoot
$link.Description = 'PHPtoSHELL Blue Team defense console'
$link.Save()
Write-Host "PHPtoSHELL installed to $installRoot."
Write-Host 'Windows Firewall changes still require administrator approval inside the app.'
