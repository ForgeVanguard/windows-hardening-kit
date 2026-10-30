# Shared definitions for Invoke-WindowsHardening.ps1, Undo-WindowsHardening.ps1 and
# Test-WindowsHardening.ps1. Author: Steven Drew. License: MIT.

Set-StrictMode -Version Latest

# Attack Surface Reduction rules applied by the kit.
$script:AsrRules = [ordered]@{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
}

# Registry settings: Section, Path, Name, Value, Type, Description.
$script:RegistrySettings = @(
    @{ Section = 'Network';   Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient';                  Name = 'EnableMulticast';            Value = 0;   Type = 'DWord'; Description = 'Disable LLMNR' }
    @{ Section = 'Network';   Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters';     Name = 'RequireSecuritySignature';   Value = 1;   Type = 'DWord'; Description = 'Require SMB signing (client)' }
    @{ Section = 'Network';   Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';         Name = 'RequireSecuritySignature';   Value = 1;   Type = 'DWord'; Description = 'Require SMB signing (server)' }
    @{ Section = 'Credential';Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest';        Name = 'UseLogonCredential';         Value = 0;   Type = 'DWord'; Description = 'No WDigest plaintext credentials in LSASS' }
    @{ Section = 'Credential';Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';         Name = 'EnableLUA';                  Value = 1;   Type = 'DWord'; Description = 'UAC enabled' }
    @{ Section = 'Credential';Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';         Name = 'ConsentPromptBehaviorAdmin'; Value = 2;   Type = 'DWord'; Description = 'UAC: prompt for consent on the secure desktop' }
    @{ Section = 'Credential';Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';         Name = 'PromptOnSecureDesktop';      Value = 1;   Type = 'DWord'; Description = 'UAC: secure desktop' }
    @{ Section = 'Autorun';   Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer';       Name = 'NoDriveTypeAutoRun';         Value = 255; Type = 'DWord'; Description = 'Disable AutoRun on all drives' }
    @{ Section = 'Autorun';   Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer';       Name = 'NoAutorun';                  Value = 1;   Type = 'DWord'; Description = 'Disable AutoPlay/AutoRun' }
    @{ Section = 'Rdp';       Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server';                  Name = 'fDenyTSConnections';         Value = 1;   Type = 'DWord'; Description = 'Disable inbound Remote Desktop' }
    @{ Section = 'Privacy';   Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';                Name = 'AllowTelemetry';             Value = 1;   Type = 'DWord'; Description = 'Diagnostic data: required only' }
    @{ Section = 'Privacy';   Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection';                Name = 'AllowDeviceNameInTelemetry'; Value = 0;   Type = 'DWord'; Description = 'No device name in diagnostic data' }
    @{ Section = 'Privacy';   Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';                                  Name = 'DiagnosticData';             Value = 0;   Type = 'DWord'; Description = 'Edge: no optional diagnostic data' }
    @{ Section = 'Privacy';   Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';                                  Name = 'PersonalizationReportingEnabled'; Value = 0; Type = 'DWord'; Description = 'Edge: no personalization reporting' }
    @{ Section = 'Privacy';   Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';                                  Name = 'HideFirstRunExperience';     Value = 1;   Type = 'DWord'; Description = 'Edge: skip first-run experience' }
)

# Services: Section, Name, StartType.
$script:ServiceSettings = @(
    @{ Section = 'Services'; Name = 'RemoteRegistry'; StartType = 'Disabled' }
    @{ Section = 'Spooler';  Name = 'Spooler';        StartType = 'Disabled' }
)

$script:FirewallRulePrefix = 'WindowsHardeningKit - '

function Get-RegistryValueState {
    param([string]$Path, [string]$Name)
    $exists = $false
    $value  = $null
    if (Test-Path -LiteralPath $Path) {
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($item -and $item.PSObject.Properties[$Name]) {
            $exists = $true
            $value  = $item.$Name
        }
    }
    [pscustomobject]@{ Path = $Path; Name = $Name; Exists = $exists; Value = $value }
}

function Get-AccountPolicy {
    # Parses `net accounts` into a hashtable of the lockout values the kit changes.
    $policy = @{}
    $lines = & net.exe accounts 2>$null
    foreach ($line in $lines) {
        if ($line -match '^Lockout threshold:\s+(.+)$')                   { $policy.LockoutThreshold = $Matches[1].Trim() }
        elseif ($line -match '^Lockout duration \(minutes\):\s+(.+)$')    { $policy.LockoutDuration  = $Matches[1].Trim() }
        elseif ($line -match '^Lockout observation window \(minutes\):\s+(.+)$') { $policy.LockoutWindow = $Matches[1].Trim() }
    }
    return $policy
}

Export-ModuleMember -Function Get-RegistryValueState, Get-AccountPolicy -Variable AsrRules, RegistrySettings, ServiceSettings, FirewallRulePrefix
