<#
.SYNOPSIS
    Restores the settings changed by Invoke-WindowsHardening.ps1 from its state snapshot.

.DESCRIPTION
    Reads a state_<timestamp>.json file written by Invoke-WindowsHardening.ps1 and puts each
    value back exactly as it was:

      * Registry values are reset to their previous data, or removed if they did not exist.
      * Services get their previous startup type (and are started if they were running).
      * SMBv1 server protocol is re-enabled only if it was enabled before.
      * Firewall profiles get their previous enabled / default inbound / logging settings.
      * Defender preferences and ASR rules return to their previous values; ASR rules the kit
        added are removed.
      * Lockout policy returns to its previous values.
      * Firewall rules the kit created are removed.
      * The built-in Administrator is re-enabled only if it was enabled before.

    This is a targeted rollback, not a "reset to defaults". It never turns on anything that was
    off before hardening, which is what makes it safer than generic revert scripts that
    re-enable SMBv1 or reset the whole firewall.

.PARAMETER StateFile
    Path to the snapshot. Defaults to the newest one in the state directory.

.EXAMPLE
    .\Undo-WindowsHardening.ps1 -WhatIf

.EXAMPLE
    .\Undo-WindowsHardening.ps1 -StateFile "$env:ProgramData\WindowsHardeningKit\State\state_20260101_120000.json"

.NOTES
    Author : Steven Drew
    License: MIT
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$StateFile,
    [string]$StateDirectory = (Join-Path $env:ProgramData 'WindowsHardeningKit\State')
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HardeningCommon.psm1') -Force

if (-not $StateFile) {
    $latest = Get-ChildItem -Path $StateDirectory -Filter 'state_*.json' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $latest) { throw "No state file found in $StateDirectory." }
    $StateFile = $latest.FullName
}
Write-Host "Restoring from $StateFile" -ForegroundColor Cyan
$state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json

function Test-HasValue {
    param($Object, [string]$Name)
    return ($null -ne $Object -and $Object.PSObject.Properties[$Name] -and $null -ne $Object.$Name)
}

# Registry
foreach ($r in @($state.Registry)) {
    if ($null -eq $r) { continue }
    $target = "$($r.Path)\$($r.Name)"
    if ($r.Exists) {
        if ($PSCmdlet.ShouldProcess($target, "Restore value $($r.Value)")) {
            if (-not (Test-Path -LiteralPath $r.Path)) { New-Item -Path $r.Path -Force | Out-Null }
            Set-ItemProperty -LiteralPath $r.Path -Name $r.Name -Value $r.Value
        }
    }
    else {
        $current = Get-RegistryValueState -Path $r.Path -Name $r.Name
        if ($current.Exists -and $PSCmdlet.ShouldProcess($target, 'Remove (did not exist before)')) {
            Remove-ItemProperty -LiteralPath $r.Path -Name $r.Name
        }
    }
}

# Services
foreach ($s in @($state.Services)) {
    if ($null -eq $s) { continue }
    if ($PSCmdlet.ShouldProcess($s.Name, "StartupType $($s.StartType)")) {
        Set-Service -Name $s.Name -StartupType $s.StartType
        if ($s.Status -eq 'Running') { Start-Service -Name $s.Name -ErrorAction SilentlyContinue }
    }
}

# SMBv1
if ((Test-HasValue $state 'Smb1Server') -and $state.Smb1Server) {
    if ($PSCmdlet.ShouldProcess('SMB server', 'Re-enable SMBv1 (it was enabled before hardening)')) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
    }
}

# Firewall profiles
foreach ($f in @($state.Firewall)) {
    if ($null -eq $f) { continue }
    if ($PSCmdlet.ShouldProcess("Firewall profile $($f.Name)", 'Restore previous settings')) {
        Set-NetFirewallProfile -Name $f.Name -Enabled $f.Enabled -DefaultInboundAction $f.DefaultInboundAction -LogBlocked $f.LogBlocked -LogMaxSizeKilobytes $f.LogMaxSizeKilobytes
    }
}

# Firewall rules created by the kit
foreach ($name in @($state.FirewallRulesCreated)) {
    if (-not $name) { continue }
    if ($PSCmdlet.ShouldProcess($name, 'Remove firewall rule')) {
        Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
}

# Defender
if (Test-HasValue $state 'Defender') {
    $d = $state.Defender
    if ($PSCmdlet.ShouldProcess('Microsoft Defender', 'Restore previous preferences')) {
        Set-MpPreference -DisableRealtimeMonitoring ([bool]$d.DisableRealtimeMonitoring) -MAPSReporting $d.MAPSReporting -SubmitSamplesConsent $d.SubmitSamplesConsent -PUAProtection $d.PUAProtection
    }
    $prevIds = @($d.AsrIds | Where-Object { $_ })
    $prevActions = @($d.AsrActions)
    $kitIds = @($AsrRules.Keys)
    $added = @($kitIds | Where-Object { $prevIds -notcontains $_ })
    if ($added.Count -gt 0 -and $PSCmdlet.ShouldProcess("$($added.Count) ASR rules", 'Remove (added by the kit)')) {
        Remove-MpPreference -AttackSurfaceReductionRules_Ids $added
    }
    for ($i = 0; $i -lt $prevIds.Count; $i++) {
        if ($kitIds -contains $prevIds[$i] -and $i -lt $prevActions.Count) {
            if ($PSCmdlet.ShouldProcess($prevIds[$i], "Restore ASR action $($prevActions[$i])")) {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $prevIds[$i] -AttackSurfaceReductionRules_Actions $prevActions[$i]
            }
        }
    }
}

# Lockout policy
if (Test-HasValue $state 'AccountPolicy') {
    $p = $state.AccountPolicy
    $threshold = if ($p.LockoutThreshold -match '^\d+$') { $p.LockoutThreshold } else { '0' }
    if ($PSCmdlet.ShouldProcess('Local account policy', "Lockout threshold $threshold")) {
        & net.exe accounts "/lockoutthreshold:$threshold" | Out-Null
        if ($threshold -ne '0' -and $p.LockoutDuration -match '^\d+$' -and $p.LockoutWindow -match '^\d+$') {
            & net.exe accounts "/lockoutduration:$($p.LockoutDuration)" "/lockoutwindow:$($p.LockoutWindow)" | Out-Null
        }
    }
}

# Built-in Administrator
if ((Test-HasValue $state 'BuiltinAdministratorEnabled') -and $state.BuiltinAdministratorEnabled) {
    $builtin = Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-*-500' } | Select-Object -First 1
    if ($builtin -and -not $builtin.Enabled -and $PSCmdlet.ShouldProcess($builtin.Name, 'Re-enable (was enabled before)')) {
        Enable-LocalUser -SID $builtin.SID
    }
}

Write-Host 'Rollback complete. Reboot to finish restoring SMB, LLMNR and WDigest behaviour.' -ForegroundColor Green
