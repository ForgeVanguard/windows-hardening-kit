<#
.SYNOPSIS
    Applies a practical security baseline to a standalone Windows 10/11 workstation and
    records the previous state so every change can be rolled back.

.DESCRIPTION
    Sections (all on by default, skip any with -Skip):

      Defender    Real-time protection, cloud protection (MAPS Advanced), safe sample
                  submission, PUA blocking, and 10 Attack Surface Reduction rules.
      Network     SMBv1 server protocol off, SMB signing required (client + server), LLMNR off.
      Credential  WDigest plaintext credentials off; UAC on with secure-desktop consent prompt.
      Autorun     AutoRun/AutoPlay disabled on all drive types.
      Firewall    All profiles enabled, inbound default block, logging of dropped packets.
      Services    Remote Registry disabled.
      Spooler     Print Spooler disabled (skip on machines that print).
      Rdp         Inbound Remote Desktop disabled (skip on machines you RDP into).
      Privacy     Diagnostic data limited to Required; Edge optional diagnostics off.
      Lockout     Account lockout: 5 attempts, 15-minute duration and window.

    Optional:
      -ManagementPort / -ManagementSubnet
                  Allow a self-hosted service port (for example a dashboard on 3000) only from
                  a management subnet, and warn about other rules that open it more widely.
      -DisableBuiltinAdministrator
                  Disable the built-in Administrator account (only if another admin exists).

    Reported, not changed: BitLocker status of the OS volume and Administrators group
    membership. Use a dedicated admin account and a standard daily account.

    Before changing anything the script writes a JSON snapshot of every value it is about to
    touch to <StateDirectory>\state_<timestamp>.json. Undo-WindowsHardening.ps1 restores from
    that file.

.PARAMETER Skip
    Section names to leave untouched.

.PARAMETER AsrMode
    Enabled (block) or AuditMode. Default AuditMode on first run is a sensible way to see
    what would be blocked; switch to Enabled once the event log is quiet.

.PARAMETER StateDirectory
    Where pre-change snapshots are written.

.EXAMPLE
    .\Invoke-WindowsHardening.ps1 -WhatIf

.EXAMPLE
    .\Invoke-WindowsHardening.ps1 -AsrMode AuditMode -Skip Spooler

.EXAMPLE
    .\Invoke-WindowsHardening.ps1 -AsrMode Enabled -ManagementPort 3000 -ManagementSubnet 192.0.2.0/24

.NOTES
    Author : Steven Drew
    License: MIT
    Intended for standalone or lab machines. On Intune/GPO-managed devices, apply settings
    through the management platform instead; local changes may be overwritten.
    Some changes (SMB signing, LLMNR, WDigest) take full effect after a reboot.
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Defender', 'Network', 'Credential', 'Autorun', 'Firewall', 'Services', 'Spooler', 'Rdp', 'Privacy', 'Lockout')]
    [string[]]$Skip = @(),

    [ValidateSet('Enabled', 'AuditMode')]
    [string]$AsrMode = 'AuditMode',

    [ValidateRange(1, 65535)]
    [int]$ManagementPort,

    [string[]]$ManagementSubnet,

    [switch]$DisableBuiltinAdministrator,

    [string]$StateDirectory = (Join-Path $env:ProgramData 'WindowsHardeningKit\State')
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HardeningCommon.psm1') -Force

$script:Changes = New-Object System.Collections.Generic.List[object]

function Write-Step {
    param([string]$Message, [ValidateSet('Info', 'Ok', 'Warn', 'Skip')][string]$Kind = 'Info')
    $color = @{ Info = 'Cyan'; Ok = 'Green'; Warn = 'Yellow'; Skip = 'DarkGray' }[$Kind]
    Write-Host ("[{0}] {1}" -f $Kind.ToUpperInvariant(), $Message) -ForegroundColor $color
}

function Test-Section {
    param([string]$Name)
    return ($Skip -notcontains $Name)
}

function Add-Change {
    param([string]$Section, [string]$Item, [string]$Result)
    $script:Changes.Add([pscustomobject]@{ Section = $Section; Item = $Item; Result = $Result })
}

# -----------------------------------------------------------------------------
# 1. Snapshot current state
# -----------------------------------------------------------------------------
Write-Step 'Capturing current state...'

$builtinAdmin = Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-*-500' } | Select-Object -First 1

$state = [ordered]@{
    CreatedUtc   = (Get-Date).ToUniversalTime().ToString('o')
    ComputerName = $env:COMPUTERNAME
    Skip         = $Skip
    Registry     = @($RegistrySettings | Where-Object { Test-Section $_.Section } |
                    ForEach-Object { Get-RegistryValueState -Path $_.Path -Name $_.Name })
    Services     = @($ServiceSettings | Where-Object { Test-Section $_.Section } | ForEach-Object {
                        $svc = Get-Service -Name $_.Name -ErrorAction SilentlyContinue
                        if ($svc) { [pscustomobject]@{ Name = $svc.Name; StartType = [string]$svc.StartType; Status = [string]$svc.Status } }
                    })
    Smb1Server   = $null
    Firewall     = @()
    Defender     = $null
    AccountPolicy = $null
    FirewallRulesCreated = @()
    BuiltinAdministratorEnabled = $(if ($builtinAdmin) { [bool]$builtinAdmin.Enabled } else { $null })
}

if (Test-Section 'Network') {
    $state.Smb1Server = [bool](Get-SmbServerConfiguration).EnableSMB1Protocol
}
if (Test-Section 'Firewall') {
    $state.Firewall = @(Get-NetFirewallProfile | ForEach-Object {
        [pscustomobject]@{
            Name                 = $_.Name
            Enabled              = [string]$_.Enabled
            DefaultInboundAction = [string]$_.DefaultInboundAction
            LogBlocked           = [string]$_.LogBlocked
            LogMaxSizeKilobytes  = $_.LogMaxSizeKilobytes
        }
    })
}
if (Test-Section 'Defender') {
    $mp = Get-MpPreference
    $state.Defender = [pscustomobject]@{
        DisableRealtimeMonitoring = $mp.DisableRealtimeMonitoring
        MAPSReporting             = $mp.MAPSReporting
        SubmitSamplesConsent      = $mp.SubmitSamplesConsent
        PUAProtection             = $mp.PUAProtection
        AsrIds                    = @($mp.AttackSurfaceReductionRules_Ids)
        AsrActions                = @($mp.AttackSurfaceReductionRules_Actions)
    }
}
if (Test-Section 'Lockout') {
    $state.AccountPolicy = Get-AccountPolicy
}

$stateFile = $null
if ($PSCmdlet.ShouldProcess($StateDirectory, 'Write pre-change state snapshot')) {
    New-Item -Path $StateDirectory -ItemType Directory -Force | Out-Null
    $stateFile = Join-Path $StateDirectory ("state_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $state | ConvertTo-Json -Depth 6 | Set-Content -Path $stateFile -Encoding UTF8
    Write-Step "State saved: $stateFile" 'Ok'
}

# -----------------------------------------------------------------------------
# 2. Apply
# -----------------------------------------------------------------------------

# Defender
if (Test-Section 'Defender') {
    Write-Step 'Defender'
    if ($PSCmdlet.ShouldProcess('Microsoft Defender', 'Enable real-time, cloud, PUA protection')) {
        Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -PUAProtection Enabled
        Add-Change 'Defender' 'Real-time / MAPS Advanced / safe samples / PUA' 'Applied'
    }
    # Add-MpPreference appends; Set-MpPreference in a loop would replace the list each time.
    $ids = @($AsrRules.Keys)
    if ($PSCmdlet.ShouldProcess("$($ids.Count) ASR rules", "Set to $AsrMode")) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions (@($AsrMode) * $ids.Count)
        Add-Change 'Defender' "ASR rules x$($ids.Count)" $AsrMode
    }
}

# Registry-based sections
foreach ($setting in $RegistrySettings) {
    if (-not (Test-Section $setting.Section)) { continue }
    $target = "$($setting.Path)\$($setting.Name)"
    if ($PSCmdlet.ShouldProcess($target, "Set $($setting.Value) ($($setting.Description))")) {
        if (-not (Test-Path -LiteralPath $setting.Path)) {
            New-Item -Path $setting.Path -Force | Out-Null
        }
        New-ItemProperty -LiteralPath $setting.Path -Name $setting.Name -Value $setting.Value -PropertyType $setting.Type -Force | Out-Null
        Add-Change $setting.Section $setting.Description 'Applied'
    }
}

# SMBv1
if (Test-Section 'Network') {
    if ($state.Smb1Server -and $PSCmdlet.ShouldProcess('SMB server', 'Disable SMBv1 protocol')) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Add-Change 'Network' 'SMBv1 server protocol' 'Disabled'
    }
    elseif (-not $state.Smb1Server) {
        Add-Change 'Network' 'SMBv1 server protocol' 'Already disabled'
    }
}

# Firewall
if (Test-Section 'Firewall') {
    if ($PSCmdlet.ShouldProcess('All firewall profiles', 'Enable, default-block inbound, log dropped packets')) {
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -LogBlocked True -LogMaxSizeKilobytes 16384
        Add-Change 'Firewall' 'Profiles enabled + logging' 'Applied'
    }
}

# Services
foreach ($svcSetting in $ServiceSettings) {
    if (-not (Test-Section $svcSetting.Section)) { continue }
    $svc = Get-Service -Name $svcSetting.Name -ErrorAction SilentlyContinue
    if (-not $svc) { Add-Change $svcSetting.Section $svcSetting.Name 'Not present'; continue }
    if ($PSCmdlet.ShouldProcess($svcSetting.Name, "Stop and set StartupType $($svcSetting.StartType)")) {
        if ($svc.Status -eq 'Running') { Stop-Service -Name $svc.Name -Force }
        Set-Service -Name $svc.Name -StartupType $svcSetting.StartType
        Add-Change $svcSetting.Section $svcSetting.Name $svcSetting.StartType
    }
}

# Lockout policy
if (Test-Section 'Lockout') {
    if ($PSCmdlet.ShouldProcess('Local account policy', 'Lockout threshold 5, duration 15, window 15')) {
        & net.exe accounts /lockoutthreshold:5 | Out-Null
        & net.exe accounts /lockoutduration:15 /lockoutwindow:15 | Out-Null
        Add-Change 'Lockout' 'Threshold 5 / 15 min' 'Applied'
    }
}

# Management port restriction (optional)
if ($ManagementPort) {
    if (-not $ManagementSubnet) { throw '-ManagementSubnet is required with -ManagementPort.' }
    $allowName = $FirewallRulePrefix + "Allow TCP $ManagementPort from management"
    if ($PSCmdlet.ShouldProcess("TCP $ManagementPort", "Allow inbound only from $($ManagementSubnet -join ', ')")) {
        Get-NetFirewallRule -DisplayName $allowName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName $allowName -Direction Inbound -Protocol TCP -LocalPort $ManagementPort -RemoteAddress $ManagementSubnet -Action Allow | Out-Null
        Add-Change 'Firewall' "TCP $ManagementPort allowed from $($ManagementSubnet -join ', ')" 'Applied'

        # With inbound default = Block, this rule is the only way in, unless another allow rule
        # (often created by the application's installer) opens the port more widely.
        $wider = @(Get-NetFirewallPortFilter -Protocol TCP -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -eq [string]$ManagementPort } |
            Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and $_.DisplayName -ne $allowName })
        foreach ($r in $wider) {
            Write-Step "Another inbound allow rule also opens TCP ${ManagementPort}: '$($r.DisplayName)'. Review or disable it." 'Warn'
        }

        if ($stateFile) {
            $state.FirewallRulesCreated = @($allowName)
            $state | ConvertTo-Json -Depth 6 | Set-Content -Path $stateFile -Encoding UTF8
        }
    }
}

# Built-in Administrator (optional)
if ($DisableBuiltinAdministrator -and $builtinAdmin -and $builtinAdmin.Enabled) {
    $otherAdmins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -ne $builtinAdmin.SID.Value })
    if ($otherAdmins.Count -eq 0) {
        Write-Step 'No other administrator exists; leaving the built-in Administrator enabled.' 'Warn'
    }
    elseif ($PSCmdlet.ShouldProcess($builtinAdmin.Name, 'Disable built-in Administrator')) {
        Disable-LocalUser -SID $builtinAdmin.SID
        Add-Change 'Accounts' 'Built-in Administrator' 'Disabled'
    }
}

# -----------------------------------------------------------------------------
# 3. Report-only checks
# -----------------------------------------------------------------------------
try {
    $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $msg = "BitLocker $($env:SystemDrive) $($bl.VolumeStatus), protection $($bl.ProtectionStatus)"
    if ($bl.ProtectionStatus -eq 'On') { Write-Step $msg 'Ok' } else { Write-Step "$msg - enable it (Settings > Device encryption or manage-bde)." 'Warn' }
}
catch {
    Write-Step 'BitLocker status unavailable on this edition.' 'Warn'
}

$admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue)
Write-Step ("Administrators group: {0} member(s). Use a dedicated admin account and a standard daily account." -f $admins.Count) 'Info'

# -----------------------------------------------------------------------------
# 4. Summary
# -----------------------------------------------------------------------------
Write-Host ''
$script:Changes | Format-Table -AutoSize | Out-Host
if ($stateFile) {
    Write-Step "Undo with: .\Undo-WindowsHardening.ps1 -StateFile '$stateFile'" 'Info'
}
Write-Step 'Reboot to complete SMB, LLMNR and WDigest changes. Then run Test-WindowsHardening.ps1.' 'Info'
