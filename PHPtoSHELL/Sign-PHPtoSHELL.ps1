param(
    [Parameter(Mandatory=$true)][string]$CertificateThumbprint,
    [Parameter(Mandatory=$true)][string]$SignToolPath,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)
$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot 'PHPtoSHELL.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw 'PHPtoSHELL.exe not found beside this script.' }
if (-not (Test-Path -LiteralPath $SignToolPath)) { throw 'signtool.exe not found. Install Windows SDK or provide its full path.' }
$cert = Get-ChildItem Cert:\CurrentUser\My\$CertificateThumbprint -ErrorAction SilentlyContinue
if (-not $cert -or -not $cert.HasPrivateKey) { throw 'The certificate thumbprint was not found or has no private key.' }
if ($cert.NotBefore -gt (Get-Date) -or $cert.NotAfter -le (Get-Date)) { throw 'The signing certificate is outside its validity period.' }
if (-not @($cert.EnhancedKeyUsageList | Where-Object { $_.ObjectId.Value -eq '1.3.6.1.5.5.7.3.3' }).Count) { throw 'A certificate with Code Signing usage is required.' }
& $SignToolPath sign /fd SHA256 /sha1 ($cert.Thumbprint) /tr $TimestampUrl /td SHA256 $exe
if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit code $LASTEXITCODE." }
& $SignToolPath verify /pa /all $exe
if ($LASTEXITCODE -ne 0) { throw 'Signature verification failed.' }
Write-Host 'PHPtoSHELL signed and verified successfully.'
