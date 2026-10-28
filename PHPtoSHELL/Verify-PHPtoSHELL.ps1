param(
    [Parameter(Mandatory=$true)][string]$Path,
    [string]$ExpectedPublisher
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $Path).Path
$manifestPath = Join-Path $root 'release-manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath)) { throw 'release-manifest.json not found.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.product -ne 'PHPtoSHELL' -or -not $manifest.files.'PHPtoSHELL.exe' -or
    [string]$manifest.version -notmatch '^\d{4}\.\d{1,2}\.\d{1,2}$') { throw 'Invalid product, version or executable manifest entry.' }
$results = @()
foreach ($property in $manifest.files.psobject.Properties) {
    if ($property.Name -ne [IO.Path]::GetFileName($property.Name) -or $property.Name.Contains(':')) { throw 'Manifest paths must be plain filenames.' }
    if ([string]$property.Value -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid SHA256 manifest entry.' }
    $file = Join-Path $root $property.Name
    if (-not (Test-Path -LiteralPath $file)) { $results += [pscustomobject]@{File=$property.Name;State='MISSING'}; continue }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($file))).Replace('-', '')).ToLowerInvariant() }
    finally { $sha.Dispose() }
    $expected = ([string]$property.Value).ToLowerInvariant()
    $results += [pscustomobject]@{File=$property.Name;State=($(if ($actual -eq $expected) {'HASH-OK'} else {'HASH-MISMATCH'}));Sha256=$actual}
}
$exe = Join-Path $root 'PHPtoSHELL.exe'
$signature = $null
if (Test-Path -LiteralPath $exe) {
    try {
        Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
        $signature = Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop
    } catch {
        $signature = [pscustomobject]@{Status='NotAvailable';SignerCertificate=$null}
    }
}
$signatureState = if ($null -eq $signature) { 'MISSING' } elseif ($signature.Status -eq 'Valid') { 'SIGNED' } elseif ($signature.Status -eq 'NotSigned') { 'UNSIGNED-TEST' } elseif ($signature.Status -eq 'NotAvailable') { 'UNKNOWN' } else { 'INVALID' }
if ($ExpectedPublisher -and $signatureState -eq 'SIGNED' -and $signature.SignerCertificate.Subject -notlike "*$ExpectedPublisher*") { $signatureState = 'INVALID-PUBLISHER' }
[pscustomobject]@{
    Product=$manifest.product; Version=$manifest.version; HashResults=$results
    SignatureState=$signatureState
    Signer=if ($signature) { $signature.SignerCertificate.Subject } else { '' }
    OverallState=if (($results.State -contains 'MISSING') -or ($results.State -contains 'HASH-MISMATCH') -or $signatureState -in @('INVALID-PUBLISHER','INVALID','MISSING')) {'INVALID'} elseif ($signatureState -eq 'SIGNED') {'SIGNED'} elseif ($signatureState -eq 'UNKNOWN') {'UNKNOWN'} else {'UNSIGNED-TEST'}
} | ConvertTo-Json -Depth 5
