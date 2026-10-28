[rtk] /!\ No hook installed — run `rtk init -g` for automatic token savings
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Check','Poll','Block','Unblock','Blocks')][string]$Operation,
    [string]$Address,
    [Parameter(Mandatory=$true)][string]$PolicyPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Normalize-IP([string]$Value) {
    $ip=[Net.IPAddress]::Parse(($Value -split '%')[0])
    if($ip.IsIPv4MappedToIPv6){$ip=$ip.MapToIPv4()}
    return $ip
}
function In-Network([Net.IPAddress]$IP,[string]$CIDR) {
    $parts=$CIDR.Split('/');$net=Normalize-IP $parts[0]
    if($IP.AddressFamily -ne $net.AddressFamily){return $false}
    $a=$IP.GetAddressBytes();$b=$net.GetAddressBytes()
    $bits=if($parts.Length -eq 2){[int]$parts[1]}else{$a.Length*8}
    if($bits -lt 0 -or $bits -gt $a.Length*8){throw 'Invalid prefix'}
    for($i=0;$i -lt $a.Length;$i++){
        $take=[Math]::Min(8,[Math]::Max(0,$bits-$i*8))
        $mask=if($take -eq 0){0}else{(255 -shl (8-$take)) -band 255}
        if(($a[$i] -band $mask) -ne ($b[$i] -band $mask)){return $false}
    };return $true
}
function Require-Administrator {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($identity)
    if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run Watch in elevated console'}
}
function Check-Firewall {
    Require-Administrator
    $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if(!$profiles.Count){throw 'No effective profiles'}
    foreach($p in $profiles){
        if([string]$p.Enabled -ne 'True' -or [string]$p.AllowLocalFirewallRules -eq 'False' -or
           @($p.DisabledInterfaceAliases | Where-Object {$_ -and $_ -ne 'NotConfigured'}).Count){throw 'Firewall not ready: disabled, merge denied, or interface excluded'}
    }
    $all=@(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound)
    foreach($r in $all){
        $bypass=$r.PSObject.Properties['OverrideBlockRules']
        if($bypass -and [string]$bypass.Value -eq 'True'){throw 'Authenticated bypass rule requires review'}
        if($r.Group -like 'IngressGuard-*'){throw 'Blanket ingress deployment conflicts with grace-period Watch'}
    }
}
function Get-Owned([string]$Name){
    $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name $Name -ErrorAction SilentlyContinue)
    foreach($r in $rules){if($r.Name -cne $Name -or $r.Group -cne 'IngressGuardWatch'){throw 'Foreign rule collision'}}
    return $rules
}
$policy=Get-Content -LiteralPath $PolicyPath -Raw | ConvertFrom-Json
if($policy.version -ne 1 -or $policy.port -ne 8080 -or @($policy.allowed_sources).Count -eq 0){throw 'Invalid watch policy'}
if($Operation -eq 'Poll'){
    $rows=@(Get-NetTCPConnection -State Established | Where-Object LocalPort -eq 8080 | Select-Object RemoteAddress,LocalAddress,OwningProcess)
    ConvertTo-Json -InputObject $rows -Compress;return
}
if($Operation -eq 'Check'){Check-Firewall;Write-Output '{"ready":true}';return}
if($Operation -eq 'Blocks'){
    $rows=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object Group -eq 'IngressGuardWatch' | ForEach-Object {
        [pscustomobject]@{Name=$_.Name;Enabled=[string]$_.Enabled;Addresses=@($_ | Get-NetFirewallAddressFilter | Select-Object -ExpandProperty RemoteAddress)}
    })
    ConvertTo-Json -InputObject $rows -Compress;return
}
$ip=Normalize-IP $Address
$hex=([BitConverter]::ToString($ip.GetAddressBytes())).Replace('-','')
$name='IGWatch-v1-'+$hex
if($Operation -eq 'Unblock'){
    Require-Administrator
    foreach($r in @(Get-Owned $name)){$r | Remove-NetFirewallRule}
    Write-Output '{"unblocked":true}';return
}
foreach($net in @($policy.allowed_sources)+@('127.0.0.0/8','::1/128')){
    if(In-Network $ip $net){throw 'Refusing to block a provisional allowlisted source or loopback'}
}
Check-Firewall
$existing=@(Get-Owned $name)
if($existing.Count){
    $active=Get-NetFirewallRule -PolicyStore ActiveStore -Name $name
    if([string]$active.Enabled -ne 'True' -or [string]$active.Action -ne 'Block'){throw 'Existing source block is not effective'}
    Write-Output '{"blocked":true,"tcp_close_proven":false}';return
}
if(@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object Group -eq 'IngressGuardWatch').Count -ge 64){throw '64 source-rule limit reached; operator review required'}
try{
    New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $name -Group 'IngressGuardWatch' `
        -Direction Inbound -Action Block -Enabled True -Profile Any -Protocol TCP -LocalPort 8080 -RemoteAddress $ip.ToString() | Out-Null
    $effective=Get-NetFirewallRule -PolicyStore ActiveStore -Name $name
    if([string]$effective.Enabled -ne 'True' -or [string]$effective.Action -ne 'Block'){throw 'Source rule not effective'}
    Write-Output '{"blocked":true,"tcp_close_proven":false}'
}catch{
    $original=$_
    foreach($r in @(Get-Owned $name)){$r | Remove-NetFirewallRule}
    throw $original
}

