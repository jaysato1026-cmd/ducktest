[rtk] /!\ No hook installed — run `rtk init -g` for automatic token savings
#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Audit','Apply','Rollback','Commit')][string]$Mode = 'Audit',
    [string]$PlanPath,
    [string]$ApprovedPlanSha256,
    [string]$JournalPath,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'audit'),
    [ValidateRange(1,60)][int]$Samples = 3,
    [ValidateRange(1,60)][int]$IntervalSeconds = 10,
    [switch]$BusinessChecksPassed,
    [switch]$Automatic
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-InNetwork([string]$Address, [string]$Network) {
    $ip = [Net.IPAddress]::Parse(($Address -split '%')[0])
    if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
    $parts = $Network.Split('/')
    $net = [Net.IPAddress]::Parse($parts[0])
    if ($ip.AddressFamily -ne $net.AddressFamily) { return $false }
    $a = $ip.GetAddressBytes(); $b = $net.GetAddressBytes()
    $bits = if ($parts.Length -eq 2) { [int]$parts[1] } else { $a.Length * 8 }
    if ($bits -lt 0 -or $bits -gt $a.Length * 8) { throw 'Invalid prefix' }
    for ($i=0; $i -lt $a.Length; $i++) {
        $take = [Math]::Min(8, [Math]::Max(0, $bits - $i * 8))
        $mask = if ($take -eq 0) { 0 } else { (255 -shl (8-$take)) -band 255 }
        if (($a[$i] -band $mask) -ne ($b[$i] -band $mask)) { return $false }
    }
    return $true
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run Apply/Rollback/Commit from an elevated PowerShell session.'
    }
}

function Write-Json($Value, [string]$Path) {
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath ($Path+'.tmp') -Encoding UTF8
    Move-Item -LiteralPath ($Path+'.tmp') -Destination $Path -Force
}

function Get-Sha256([string]$Path) {
    $stream=[IO.File]::OpenRead((Resolve-Path -LiteralPath $Path).Path)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function Assert-ReadyPlan($Plan) {
    if ($Plan.version -ne 1 -or $Plan.port -ne 8080 -or $Plan.ready -isnot [bool] -or $Plan.ready -ne $true) {
        throw 'Not an approved version 1 / TCP 8080 plan. Preview cannot be applied.'
    }
    if ($Plan.target_computer -cne $env:COMPUTERNAME) { throw 'Target computer mismatch.' }
    if (@($Plan.allowed).Count -eq 0 -or @($Plan.blocked).Count -eq 0) { throw 'Empty plan.' }
    foreach ($block in $Plan.blocked) {
        if ($block -notmatch '^[0-9a-fA-F:.]+/\d+$') { throw 'Invalid blocked CIDR.' }
        foreach ($allow in $Plan.allowed) {
            if ((Test-InNetwork ($block.Split('/')[0]) $allow) -or
                (Test-InNetwork ($allow.Split('/')[0]) $block)) {
                throw 'A block overlaps an allowed source.'
            }
        }
    }
    $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if ($profiles.Count -eq 0) { throw 'No effective firewall profiles available.' }
    foreach ($profile in $profiles) {
        if ([string]$profile.Enabled -ne 'True' -or
            [string]$profile.AllowLocalFirewallRules -eq 'False' -or
            @($profile.DisabledInterfaceAliases | Where-Object { $_ -and $_ -ne 'NotConfigured' }).Count -gt 0) {
            throw 'Firewall disabled, local rule merge denied, or interface exclusions present.'
        }
    }
    foreach ($c in @(Get-NetTCPConnection -State Established | Where-Object LocalPort -eq 8080)) {
        $covered = $false
        foreach ($allow in $Plan.allowed) { if (Test-InNetwork $c.RemoteAddress $allow) { $covered=$true; break } }
        if (!$covered) { throw ('Unapproved live 8080 source: '+$c.RemoteAddress) }
    }
}

function Read-Journal([string]$Path) {
    $j = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($j.id -notmatch '^[a-f0-9]{32}$' -or $j.computer -cne $env:COMPUTERNAME -or
        $j.group -cne ('IngressGuard-'+$j.id) -or $j.task -cne ('IngressGuard-'+$j.id)) {
        throw 'Journal identity mismatch.'
    }
    foreach ($name in $j.rules) {
        if ($name -notmatch ('^IG-'+$j.id+'-\d+$')) { throw 'Journal contains foreign rules.' }
    }
    return $j
}

function Remove-OwnedRules($Journal) {
    foreach ($name in $Journal.rules) {
        $r = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
        foreach ($rule in $r) {
            if ($rule.Name -cne $name -or $rule.Group -cne $Journal.group) { throw 'Foreign rule collision.' }
            $rule | Remove-NetFirewallRule
        }
    }
}

if ($Mode -eq 'Audit') {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $ports = @(21,135,139,445,3306,5800,5900,7070,8005,8009,8080,9267,14147)
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowLocalFirewallRules,DisabledInterfaceAliases)
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True | ForEach-Object {
        $r=$_
        [pscustomobject]@{Name=$r.Name;DisplayName=$r.DisplayName;Action=[string]$r.Action;Profile=[string]$r.Profile;
            PolicyStoreSource=$r.PolicyStoreSource;
            Ports=@($r | Get-NetFirewallPortFilter | Select-Object Protocol,LocalPort,RemotePort);
            Addresses=@($r | Get-NetFirewallAddressFilter | Select-Object LocalAddress,RemoteAddress);
            Program=@($r | Get-NetFirewallApplicationFilter | Select-Object Program);
            Service=@($r | Get-NetFirewallServiceFilter | Select-Object Service)}
    })
    $snapshots = @()
    for ($n=0; $n -lt $Samples; $n++) {
        $tcp = @(Get-NetTCPConnection | Where-Object { $_.LocalPort -in $ports -or $_.RemotePort -in $ports })
        $pids = @($tcp | Select-Object -ExpandProperty OwningProcess -Unique)
        $processes = @(Get-CimInstance Win32_Process | Where-Object ProcessId -in $pids | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath)
        $snapshots += [pscustomobject]@{utc=(Get-Date).ToUniversalTime().ToString('o');
            tcp=@($tcp | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess); processes=$processes}
        if ($n+1 -lt $Samples) { Start-Sleep -Seconds $IntervalSeconds }
    }
    $report = [ordered]@{computer=$env:COMPUTERNAME;utc=$stamp;profiles=$profiles;inboundRules=$rules;snapshots=$snapshots;
        limitations='Sampling is not a complete dependency inventory. No packet payloads, command lines, passwords or cookies collected. Contains network addresses and paths; keep private.'}
    $out = Join-Path $OutputDirectory ('audit-'+$stamp+'.json')
    Write-Json $report $out
    Write-Output ('Audit saved: '+$out)
    return
}

Assert-Administrator
$lock=New-Object Threading.Mutex($false,'Global\IngressGuard-Deployment')
$acquired=$false
try { $acquired=$lock.WaitOne(30000) }
catch [Threading.AbandonedMutexException] { $acquired=$true }
if (!$acquired) { $lock.Dispose(); throw 'Another deployment operation is running.' }
try {
if ($Mode -eq 'Rollback' -or $Mode -eq 'Commit') {
    if (!$JournalPath) { throw 'JournalPath is required.' }
    $j = Read-Journal $JournalPath
    if ($Mode -eq 'Commit') {
        if (!$BusinessChecksPassed) { throw 'Verify login, player update, publishing, schedule and maintenance first.' }
        if ($j.status -ne 'pending' -or [datetime]::UtcNow -ge [datetime]$j.expiresUtc) { throw 'Rollback window expired or journal not pending.' }
        foreach ($name in $j.rules) {
            $r = Get-NetFirewallRule -PolicyStore PersistentStore -Name $name
            if ($r.Group -cne $j.group -or [string]$r.Enabled -ne 'True') { throw 'Rule verification failed.' }
        }
        $j.status='committed'; Write-Json $j $JournalPath
        Unregister-ScheduledTask -TaskName $j.task -Confirm:$false
        Write-Output 'Committed after operator business verification. Manual rollback remains available.'
    } else {
        # A scheduled rollback after successful Commit is harmless.
        if ($Automatic -and $j.status -ne 'pending') { return }
        Remove-OwnedRules $j
        $j.status='rolled-back'; Write-Json $j $JournalPath
        Unregister-ScheduledTask -TaskName $j.task -Confirm:$false -ErrorAction SilentlyContinue
        Write-Output 'Removed only journal-owned ingress rules.'
    }
    return
}

if (!$PlanPath -or $ApprovedPlanSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'PlanPath and reviewed SHA256 are required.' }
if ((Get-Sha256 $PlanPath) -ine $ApprovedPlanSha256) { throw 'Reviewed plan hash mismatch.' }
$plan = Get-Content -LiteralPath $PlanPath -Raw | ConvertFrom-Json
Assert-ReadyPlan $plan
if (@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Group -like 'IngressGuard-*' -or $_.Group -eq 'IngressGuardWatch' }).Count) {
    throw 'An existing IngressGuard deployment exists. Inspect or roll it back first.'
}
$id=[guid]::NewGuid().ToString('N')
$base=Join-Path $env:ProgramData 'IngressGuard'
New-Item -Path $base -ItemType Directory -Force | Out-Null
if ((Get-Item -LiteralPath $base).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'State root must not be a link.' }
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $identity=New-Object Security.Principal.SecurityIdentifier($sid)
    $access=New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($access)
}
Set-Acl -LiteralPath $base -AclObject $acl
$state=Join-Path $base $id
New-Item -Path $state -ItemType Directory | Out-Null
Set-Acl -LiteralPath $state -AclObject $acl
$copy=Join-Path $state 'Guard.ps1'; Copy-Item -LiteralPath $PSCommandPath -Destination $copy
$journalFile=Join-Path $state 'journal.json'
$batches=@()
$v4=@($plan.blocked | Where-Object { $_ -notmatch ':' })
$v6=@($plan.blocked | Where-Object { $_ -match ':' })
if($v4.Count){$batches += ,$v4}; if($v6.Count){$batches += ,$v6}
$names=@(); for($i=0;$i -lt $batches.Count;$i++) { $names += 'IG-'+$id+'-'+$i }
$j=[pscustomobject]@{id=$id;computer=$env:COMPUTERNAME;group=('IngressGuard-'+$id);task=('IngressGuard-'+$id);
    rules=$names;status='pending';expiresUtc=[datetime]::UtcNow.AddMinutes(10).ToString('o');planSha256=$ApprovedPlanSha256}
Write-Json $j $journalFile
$engine=Join-Path $PSHOME 'powershell.exe'
$arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$copy+'" -Mode Rollback -Automatic -JournalPath "'+$journalFile+'"'
$action=New-ScheduledTaskAction -Execute $engine -Argument $arguments
$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10)
$settings=New-ScheduledTaskSettingsSet -StartWhenAvailable
Register-ScheduledTask -TaskName $j.task -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest | Out-Null
try {
    for($i=0;$i -lt $names.Count;$i++) {
        New-NetFirewallRule -PolicyStore PersistentStore -Name $names[$i] -DisplayName $names[$i] -Group $j.group `
            -Direction Inbound -Action Block -Enabled True -Profile Any -Protocol TCP -LocalPort 8080 `
            -RemoteAddress $batches[$i] | Out-Null
    }
    foreach ($name in $names) {
        $active=Get-NetFirewallRule -PolicyStore ActiveStore -Name $name
        if ([string]$active.Enabled -ne 'True' -or [string]$active.Action -ne 'Block') { throw 'Rule not effective.' }
    }
    Write-Output ('Pending for 10 minutes; automatic rollback unless Commit follows business checks. Journal: '+$journalFile)
} catch {
    $original=$_
    Remove-OwnedRules $j
    $j.status='rolled-back'; Write-Json $j $journalFile
    Unregister-ScheduledTask -TaskName $j.task -Confirm:$false -ErrorAction SilentlyContinue
    throw $original
}
} finally {
    $lock.ReleaseMutex(); $lock.Dispose()
}

