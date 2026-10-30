<#
.SYNOPSIS
    Weekly health check of a hardened Windows workstation.

.DESCRIPTION
    Read-only. Verifies:
      [1] Defender real-time protection and the kit's ASR rules
      [2] Administrators group membership (and that your dedicated admin is present)
      [3] Risky services (Print Spooler, Remote Registry)
      [4] Notable listening ports, flagging self-hosted service ports you name
      [5] Windows Firewall profiles
      [6] BitLocker on the OS drive
      [7] Registry baseline (SMB signing, LLMNR, WDigest, AutoRun, UAC, RDP) and SMBv1

    Works from a standard account; some checks (Defender preferences, BitLocker) report
    "unavailable" without elevation. Exit code is the number of issues found, so it can be
    used from Task Scheduler or a monitoring agent.

.PARAMETER ExpectedAdmin
    Name of your dedicated administrator account. If set, its absence from Administrators
    is reported as an issue.

.PARAMETER ServicePort
    Ports of self-hosted services (dashboards, APIs) to call out if listening. Default 3000.

.PARAMETER LogDirectory
    If set, a transcript is written there as WindowsHardeningCheck_<date>.log.

.EXAMPLE
    .\Test-WindowsHardening.ps1 -ExpectedAdmin <USERNAME>

.EXAMPLE
    .\Test-WindowsHardening.ps1 -ExpectedAdmin <USERNAME> -ServicePort 3000, 9090 -LogDirectory "$env:ProgramData\WindowsHardeningKit\Logs"

.NOTES
    Author : Steven Drew
    License: MIT
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ExpectedAdmin,
    [int[]]$ServicePort = @(3000),
    [string]$LogDirectory
)

Import-Module (Join-Path $PSScriptRoot 'HardeningCommon.psm1') -Force

$script:Issues = New-Object System.Collections.Generic.List[string]

function Write-Check {
    param([string]$Label, [string]$Value, [ValidateSet('Ok', 'Warn', 'Bad', 'Info')][string]$Kind = 'Info', [string]$Issue)
    $color = @{ Ok = 'Green'; Warn = 'Yellow'; Bad = 'Red'; Info = 'White' }[$Kind]
    Write-Host ("    {0,-28}: {1}" -f $Label, $Value) -ForegroundColor $color
    if ($Issue) { $script:Issues.Add($Issue) }
}

if ($LogDirectory) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    Start-Transcript -Path (Join-Path $LogDirectory ("WindowsHardeningCheck_{0}.log" -f (Get-Date -Format 'yyyyMMdd'))) -Append | Out-Null
}

$bar = '=' * 64
Write-Host $bar -ForegroundColor Cyan
Write-Host ("   WINDOWS HARDENING CHECK - {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm')) -ForegroundColor Cyan
Write-Host $bar -ForegroundColor Cyan

# [1] Defender
Write-Host "`n[1] Microsoft Defender" -ForegroundColor Cyan
try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    if ($status.RealTimeProtectionEnabled) { Write-Check 'Real-time protection' 'Enabled' 'Ok' }
    else { Write-Check 'Real-time protection' 'DISABLED' 'Bad' 'Defender real-time protection is off' }
    Write-Check 'Signature age (days)' $status.AntivirusSignatureAge $(if ($status.AntivirusSignatureAge -le 3) { 'Ok' } else { 'Warn' })
}
catch { Write-Check 'Defender status' 'Unavailable' 'Warn' }

try {
    $mp = Get-MpPreference -ErrorAction Stop
    $ids = @($mp.AttackSurfaceReductionRules_Ids)
    $actions = @($mp.AttackSurfaceReductionRules_Actions)
    $missing = 0; $audit = 0
    foreach ($id in $AsrRules.Keys) {
        $i = [array]::IndexOf($ids, $id)
        if ($i -lt 0 -or $actions[$i] -eq 0) { $missing++ }
        elseif ($actions[$i] -eq 2) { $audit++ }
    }
    $kind = if ($missing) { 'Warn' } else { 'Ok' }
    $issue = if ($missing) { "$missing baseline ASR rule(s) not configured" } else { $null }
    Write-Check 'Baseline ASR rules' ("{0} of {1} set ({2} in audit mode)" -f ($AsrRules.Count - $missing), $AsrRules.Count, $audit) $kind $issue
}
catch { Write-Check 'ASR rules' 'Unavailable (run elevated)' 'Warn' }

# [2] Administrators
Write-Host "`n[2] Administrators group" -ForegroundColor Cyan
try {
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    Write-Check 'Members' $admins.Count $(if ($admins.Count -le 2) { 'Ok' } else { 'Warn' })
    foreach ($a in $admins) { Write-Host "      - $($a.Name)" }
    if ($ExpectedAdmin) {
        if ($admins | Where-Object { ($_.Name -split '\\')[-1] -eq $ExpectedAdmin }) { Write-Check 'Dedicated admin' 'Present' 'Ok' }
        else { Write-Check 'Dedicated admin' 'NOT FOUND' 'Warn' 'Dedicated admin account missing from Administrators' }
    }
    $me = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Check 'Current session elevated' $isAdmin $(if ($isAdmin) { 'Info' } else { 'Ok' })
}
catch { Write-Check 'Administrators' 'Unavailable' 'Warn' }

# [3] Services
Write-Host "`n[3] Risky services" -ForegroundColor Cyan
foreach ($name in 'Spooler', 'RemoteRegistry') {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Check $name 'Not present' 'Ok'; continue }
    if ($svc.StartType -eq 'Disabled') { Write-Check $name 'Disabled' 'Ok' }
    elseif ($svc.Status -eq 'Running') { Write-Check $name "Running ($($svc.StartType))" 'Warn' "$name is running" }
    else { Write-Check $name "Stopped ($($svc.StartType))" 'Warn' }
}

# [4] Listening ports
Write-Host "`n[4] Listening ports (notable)" -ForegroundColor Cyan
$notable = @(135, 139, 445, 3389, 5985, 5986) + $ServicePort
$listen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $notable -contains $_.LocalPort } |
    Sort-Object LocalPort -Unique
foreach ($p in $listen) {
    $proc = (Get-Process -Id $p.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    $bind = $p.LocalAddress
    if ($ServicePort -contains $p.LocalPort) {
        $public = $bind -in @('0.0.0.0', '::')
        Write-Check "TCP $($p.LocalPort) ($proc)" "$bind - self-hosted service, confirm firewall scope" $(if ($public) { 'Warn' } else { 'Ok' })
    }
    elseif ($p.LocalPort -eq 3389) { Write-Check "TCP 3389 ($proc)" 'Remote Desktop listening' 'Warn' 'Remote Desktop is listening' }
    else { Write-Check "TCP $($p.LocalPort) ($proc)" $bind 'Info' }
}

# [5] Firewall
Write-Host "`n[5] Windows Firewall" -ForegroundColor Cyan
foreach ($fw in Get-NetFirewallProfile) {
    if ($fw.Enabled -eq 'True' -or $fw.Enabled -eq $true) {
        Write-Check "$($fw.Name) profile" "Enabled, inbound $($fw.DefaultInboundAction)" 'Ok'
    }
    else { Write-Check "$($fw.Name) profile" 'DISABLED' 'Bad' "Firewall $($fw.Name) profile disabled" }
}

# [6] BitLocker
Write-Host "`n[6] BitLocker" -ForegroundColor Cyan
try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($bl.VolumeStatus -eq 'FullyEncrypted' -and $bl.ProtectionStatus -eq 'On') { Write-Check $env:SystemDrive 'Fully encrypted, protection on' 'Ok' }
    else { Write-Check $env:SystemDrive "$($bl.VolumeStatus) / protection $($bl.ProtectionStatus)" 'Warn' 'BitLocker not fully protecting the OS drive' }
}
catch { Write-Check 'BitLocker' 'Unavailable (run elevated)' 'Warn' }

# [7] Registry baseline
Write-Host "`n[7] Registry baseline" -ForegroundColor Cyan
foreach ($s in $RegistrySettings | Where-Object { $_.Section -ne 'Privacy' }) {
    $cur = Get-RegistryValueState -Path $s.Path -Name $s.Name
    if ($cur.Exists -and $cur.Value -eq $s.Value) { Write-Check $s.Description 'OK' 'Ok' }
    else {
        $shown = if ($cur.Exists) { $cur.Value } else { 'not set' }
        Write-Check $s.Description "Expected $($s.Value), found $shown" 'Warn' "Not applied: $($s.Description)"
    }
}
try {
    if ((Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol) { Write-Check 'SMBv1 server' 'ENABLED' 'Bad' 'SMBv1 is enabled' }
    else { Write-Check 'SMBv1 server' 'Disabled' 'Ok' }
}
catch { Write-Check 'SMBv1 server' 'Unavailable (run elevated)' 'Warn' }

# Summary
Write-Host "`n$bar" -ForegroundColor Cyan
if ($script:Issues.Count -eq 0) {
    Write-Host '   STATUS: No issues found.' -ForegroundColor Green
}
else {
    Write-Host "   ISSUES FOUND: $($script:Issues.Count)" -ForegroundColor Red
    $script:Issues | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
}
Write-Host $bar -ForegroundColor Cyan

if ($LogDirectory) { Stop-Transcript | Out-Null }
exit $script:Issues.Count
