# Remediation Script for 1431-ntt-mgmt-2
$logPath = "$PSScriptRoot\remediation_log_20250428_015903.log"
function Write-Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp`t$message"
    Add-Content -Path $logPath -Value $entry
}

Write-Host "`nControl ID 1134: Status of logon banner title setting (Legal Notice)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1134: Status of logon banner title setting (Legal Notice)"
    try {
        # Set the logon banner title (Legal Notice) in the registry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -Value "Legal Notice"
        $cmdOutput = "Executed remediation: Set logon banner title to 'Legal Notice'"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1134: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1134"
}

Write-Host "`nControl ID 8231: Configure Network Security: Configure encryption types allowed for Kerberos"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8231: Configure Network Security: Configure encryption types allowed for Kerberos"
    try {
        # Configure allowed encryption types for Kerberos (AES256, AES128, RC4)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 0x80000003
        $cmdOutput = "Executed remediation: Configured AES256, AES128, and RC4 encryption types for Kerberos"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8231: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8231"
}

Write-Host "`nControl ID 1527: Status of the Windows Firewall: Log Successful Connections (Domain) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1527: Status of the Windows Firewall: Log Successful Connections (Domain) setting"
    try {
        # Enable logging of successful connections for the Domain profile
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" -Name "LogSuccessfulConnections" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set LogSuccessfulConnections to 1 under DomainProfile successfully."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1527: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1527"
}

Write-Host "`nControl ID 2181: Current list of Groups and User Accounts granted the Access this computer from the network right"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2181: Current list of Groups and User Accounts granted the Access this computer from the network right"
    try {
        # Set "Access this computer from the network" user rights
        $policySetting = "*SeNetworkLogonRight*"
        $authorizedAccounts = @("Administrators", "Authenticated Users") # <-- Adjust these accounts/groups as needed for your environment
        
        # Convert accounts to a comma-separated string
        $accountList = $authorizedAccounts -join ","

        # Apply the security setting
        secedit /export /cfg C:\Windows\Temp\secedit_export.inf
        (Get-Content C:\Windows\Temp\secedit_export.inf) -replace "($policySetting\s*=).*", "`$1 $accountList" | Set-Content C:\Windows\Temp\secedit_update.inf
        secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secedit_update.inf /areas USER_RIGHTS

        Remove-Item C:\Windows\Temp\secedit_export.inf, C:\Windows\Temp\secedit_update.inf -Force

        $cmdOutput = "Updated Access this computer from the network right successfully to: $accountList"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2181: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2181"
}

Write-Host "`nControl ID 8425: Status of Do not display the password reveal button"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8425: Status of Do not display the password reveal button"
    try {
        # Disable the password reveal button
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set DisablePasswordReveal to 1 under HKLM:\Software\Policies\Microsoft\Windows\CredUI"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8425: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8425"
}

Write-Host "`nControl ID 1149: Status of the Microsoft network client: Digitally sign communications (always) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1149: Status of the Microsoft network client: Digitally sign communications (always) setting"
    try {
        # Set Microsoft network client to always digitally sign communications
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set RequireSecuritySignature to 1 under HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1149: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1149"
}

Write-Host "`nControl ID 3949: Status of the Windows Firewall: Inbound connections (Domain) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3949: Status of the Windows Firewall: Inbound connections (Domain) setting"
    try {
        # Set Windows Firewall inbound connections to block by default for Domain profile
        Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block
        $cmdOutput = "Set DefaultInboundAction to Block for Domain firewall profile."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3949: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3949"
}

Write-Host "`nControl ID 8188: Status of the Boot-Start Driver Initialization Policy setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8188: Status of the Boot-Start Driver Initialization Policy setting"
    try {
        # Set Boot-Start Driver Initialization Policy to Good and Unknown drivers blocked
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set DriverLoadPolicy to 1 under HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8188: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8188"
}

Write-Host "`nControl ID 7501: Status of the Registry policy processing option: Process even if the Group Policy objects have not changed setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 7501: Status of the Registry policy processing option: Process even if the Group Policy objects have not changed setting"
    try {
        # Enable "Process even if the Group Policy objects have not changed"
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableRsop" -PropertyType DWord -Value 0 -Force | Out-Null
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ProcessEvenIfGPOUnchanged" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set ProcessEvenIfGPOUnchanged to 1 and DisableRsop to 0 under HKLM:\Software\Policies\Microsoft\Windows\System"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 7501: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 7501"
}

Write-Host "`nControl ID 23206: Status of the Allow Diagnostic Data setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 23206: Status of the Allow Diagnostic Data setting"
    try {
        # Set Diagnostic Data level to 0 (Required) or 1 (Basic), per CIS recommendations
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Set AllowTelemetry to 0 under HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 23206: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 23206"
}

Write-Host "`nControl ID 14413: Status of the Configure detection for potentially unwanted applications setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 14413: Status of the Configure detection for potentially unwanted applications setting"
    try {
        # Enable PUA (Potentially Unwanted Application) Protection
        Set-MpPreference -PUAProtection Enabled
        $cmdOutput = "Enabled detection for potentially unwanted applications (PUAProtection)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 14413: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 14413"
}

Write-Host "`nControl ID 2342: Status of the Account Lockout Threshold setting (invalid login attempts)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2342: Status of the Account Lockout Threshold setting (invalid login attempts)"
    try {
        # Set Account Lockout Threshold
        # Example: Lock account after 5 invalid attempts (CIS typically recommends 5 or fewer)
        net accounts /lockoutthreshold:5
        
        $cmdOutput = "Set Account Lockout Threshold to 5 invalid login attempts."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2342: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2342"
}

Write-Host "`nControl ID 27617: Status of the Configure security policy processing: Process even if the Group Policy objects have not changed setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 27617: Status of the Configure security policy processing: Process even if the Group Policy objects have not changed setting"
    try {
        # Ensure security policies are processed even if GPOs haven't changed
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ProcessEvenIfGPOUnchanged" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set ProcessEvenIfGPOUnchanged to 1 under HKLM:\Software\Policies\Microsoft\Windows\System"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 27617: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 27617"
}

Write-Host "`nControl ID 26138: Status of password (PasswordComplexity) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 26138: Status of password (PasswordComplexity) setting"
    try {
        # Enable Password Complexity requirement
        secedit /export /cfg C:\Windows\Temp\secedit_export.inf
        (Get-Content C:\Windows\Temp\secedit_export.inf) -replace "(PasswordComplexity\s*=).*", "`$1 1" | Set-Content C:\Windows\Temp\secedit_update.inf
        secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secedit_update.inf /areas SECURITYPOLICY
        Remove-Item C:\Windows\Temp\secedit_export.inf, C:\Windows\Temp\secedit_update.inf -Force

        $cmdOutput = "Set PasswordComplexity to enabled (value 1) via secedit."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 26138: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 26138"
}

Write-Host "`nControl ID 7504: Status of the System: Maximum log size setting (in KB)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 7504: Status of the System: Maximum log size setting (in KB)"
    try {
        # Set System event log maximum size (example: 32768 KB = 32 MB, commonly recommended)
        wevtutil sl System /ms:32768

        $cmdOutput = "Set System event log maximum size to 32 MB (32768 KB)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 7504: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 7504"
}

Write-Host "`nControl ID 10098: Status of the Allow Input Personalization setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10098: Status of the Allow Input Personalization setting"
    try {
        # Disable Input Personalization
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -PropertyType DWord -Value 0 -Force | Out-Null

        $cmdOutput = "Disabled Input Personalization by setting AllowInputPersonalization to 0, and restricted text/ink collection."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10098: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10098"
}

Write-Host "`nControl ID 2341: Status of the Account Lockout Duration setting (invalid login attempts)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2341: Status of the Account Lockout Duration setting (invalid login attempts)"
    try {
        # Set Account Lockout Duration (example: 15 minutes)
        net accounts /lockoutduration:15

        $cmdOutput = "Set Account Lockout Duration to 15 minutes."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2341: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2341"
}

Write-Host "`nControl ID 8176: Status of the Do not enumerate connected users on domain-joined computers setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8176: Status of the Do not enumerate connected users on domain-joined computers setting"
    try {
        # Set DoNotEnumerateConnectedUsers to 1 (enabled)
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontEnumerateConnectedUsers" -PropertyType DWord -Value 1 -Force | Out-Null

        $cmdOutput = "Set DontEnumerateConnectedUsers to 1 under HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8176: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8176"
}

Write-Host "`nControl ID 4504: Status of the audit setting MPSSVC Rule-Level Policy Change (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4504: Status of the audit setting MPSSVC Rule-Level Policy Change (advanced audit setting"
    try {
        # Enable auditing for MPSSVC Rule-Level Policy Change
        AuditPol /Set /Subcategory:"MPSSVC Rule-Level Policy Change" /Success:Enable /Failure:Enable

        $cmdOutput = "Enabled auditing for MPSSVC Rule-Level Policy Change (success and failure)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4504: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4504"
}

Write-Host "`nControl ID 7503: Status of the Security: Maximum log size setting (in KB)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 7503: Status of the Security: Maximum log size setting (in KB)"
    try {
        # Set Security event log maximum size (example: 196608 KB = 192 MB)
        wevtutil sl Security /ms:196608

        $cmdOutput = "Set Security event log maximum size to 192 MB (196608 KB)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 7503: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 7503"
}

Write-Host "`nControl ID 4471: Status of the audit setting Security System Extension (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4471: Status of the audit setting Security System Extension (advanced audit setting)"
    try {
        # Enable auditing for Security System Extension
        AuditPol /Set /Subcategory:"Security System Extension" /Success:Enable /Failure:Enable

        $cmdOutput = "Enabled auditing for Security System Extension (success and failure)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4471: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4471"
}

Write-Host "`nControl ID 4119: Status of the Allow indexing of encrypted files setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4119: Status of the Allow indexing of encrypted files setting"
    try {
        # Disable indexing of encrypted files
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -PropertyType DWord -Value 0 -Force | Out-Null

        $cmdOutput = "Disabled AllowIndexingEncryptedStoresOrItems (set to 0) under HKLM:\Software\Policies\Microsoft\Windows\Windows Search."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4119: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4119"
}

Write-Host "`nControl ID 2196: Current list of Groups and User Accounts granted the Deny Access to this computer from the network right"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2196: Current list of Groups and User Accounts granted the Deny Access to this computer from the network right"
    try {
        # Assign "Deny access to this computer from the network" right
        $policySetting = "*SeDenyNetworkLogonRight*"
        $deniedAccounts = @("Guests", "Local account")  # <-- Adjust based on your CIS baseline or organization standards

        # Convert accounts to a comma-separated string
        $accountList = $deniedAccounts -join ","

        # Apply the setting
        secedit /export /cfg C:\Windows\Temp\secedit_export.inf
        (Get-Content C:\Windows\Temp\secedit_export.inf) -replace "($policySetting\s*=).*", "`$1 $accountList" | Set-Content C:\Windows\Temp\secedit_update.inf
        secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secedit_update.inf /areas USER_RIGHTS
        Remove-Item C:\Windows\Temp\secedit_export.inf, C:\Windows\Temp\secedit_update.inf -Force

        $cmdOutput = "Updated 'Deny access to this computer from the network' to: $accountList"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2196: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2196"
}

Write-Host "`nControl ID 10593: Status of the Hardened UNC Paths setting for Sysvol"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10593: Status of the Hardened UNC Paths setting for Sysvol"
    try {
        # Enforce hardened UNC paths for SYSVOL and NETLOGON
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\SYSVOL" -PropertyType String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\NETLOGON" -PropertyType String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force | Out-Null

        $cmdOutput = "Set Hardened UNC Paths for SYSVOL and NETLOGON with mutual authentication and integrity required."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10593: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10593"
}

Write-Host "`nControl ID 12013: Status of the Remote host allows delegation of non-exportable credentials (AllowProtectedCreds) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 12013: Status of the Remote host allows delegation of non-exportable credentials (AllowProtectedCreds) setting"
    try {
        # Allow delegation of non-exportable credentials (Protected Users Group protection)
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "AllowProtectedCreds" -PropertyType DWord -Value 1 -Force | Out-Null

        $cmdOutput = "Enabled AllowProtectedCreds (set to 1) under HKLM:\System\CurrentControlSet\Control\Lsa"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 12013: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 12013"
}

Write-Host "`nControl ID 4520: Status of the audit setting Detailed File Share (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4520: Status of the audit setting Detailed File Share (advanced audit setting)"
    try {
        # Enable auditing for Detailed File Share access
        AuditPol /Set /Subcategory:"Detailed File Share" /Success:Enable /Failure:Enable

        $cmdOutput = "Enabled auditing for Detailed File Share (success and failure)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4520: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4520"
}

Write-Host "`nControl ID 1196: Status of the MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1196: Status of the MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires setting"
    try {
        # Set ScreenSaverGracePeriod to 5 seconds (CIS recommends 5 or fewer)
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "ScreenSaverGracePeriod" -PropertyType String -Value "5" -Force | Out-Null

        $cmdOutput = "Set ScreenSaverGracePeriod to 5 seconds."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1196: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1196"
}

Write-Host "`nControl ID 8399: Status of the Configure Turn off app notifications on the lock screen"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8399: Status of the Configure Turn off app notifications on the lock screen"
    try {
        # Disable notifications on the lock screen
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -PropertyType DWord -Value 1 -Force | Out-Null

        $cmdOutput = "Disabled app notifications on the lock screen."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8399: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8399"
}

Write-Host "`nControl ID 25358: Windows - Status of NetBIOS name resolution"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25358: Windows - Status of NetBIOS name resolution"
    try {
        # Disable NetBIOS over TCP/IP
        Get-WmiObject -Query "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True" | ForEach-Object {
            $_.SetTcpipNetbios(2) | Out-Null
        }

        $cmdOutput = "Disabled NetBIOS over TCP/IP for all active network adapters."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25358: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25358"
}

Write-Host "`nControl ID 25360: Status of the Use authentication for outgoing RPC over named pipes connections setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25360: Status of the Use authentication for outgoing RPC over named pipes connections setting"
    try {
        # Require authentication for outbound RPC over named pipes
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*" -PropertyType String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force | Out-Null

        $cmdOutput = "Enabled authentication for outbound RPC over named pipes by setting HardenedPaths for \\*"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25360: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25360"
}

Write-Host "`nControl ID 13925: Status of Block Win32 API calls from Office macro ASR rule (92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13925: Status of Block Win32 API calls from Office macro ASR rule"
    try {
        # Enable ASR rule to block Win32 API calls from Office macros
        Add-MpPreference -AttackSurfaceReductionRules_Ids "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" -AttackSurfaceReductionRules_Actions Enabled

        $cmdOutput = "Enabled ASR rule: Block Win32 API calls from Office macro (92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13925: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13925"
}

Write-Host "`nControl ID 10006: Status of the Disallow Autoplay for non-volume devices setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10006: Status of the Disallow Autoplay for non-volume devices setting"
    try {
        # Disallow Autoplay for non-volume devices
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoplayfornonVolume" -PropertyType DWord -Value 1 -Force | Out-Null

        $cmdOutput = "Set NoAutoplayfornonVolume to 1 (Autoplay disabled for non-volume devices)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10006: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10006"
}

Write-Host "`nControl ID 10431: Status of the Require use of specific security layer for remote (RDP) connections setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10431: Status of the Require use of specific security layer for remote (RDP) connections setting"
    try {
        # Enforce use of SSL (TLS 1.0 or higher) for RDP security layer
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -PropertyType DWord -Value 2 -Force | Out-Null

        $cmdOutput = "Set RDP SecurityLayer to 2 (SSL)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10431: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10431"
}

Write-Host "`nControl ID 10081: Status of the Require domain users to elevate when setting a networks location setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10081: Status of the Require domain users to elevate when setting a networks location setting"
    try {
        # Require elevation to change network location (domain-joined systems)
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocation" -PropertyType DWord -Value 1 -Force | Out-Null

        $cmdOutput = "Set NC_StdDomainUserSetLocation to 1 (requires elevation for network location changes)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10081: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10081"
}

Write-Host "`nControl ID 11034: Configure Prevent Device Metadata Retrieval from Internet Windows Group Policy"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 11034: Configure Prevent Device Metadata Retrieval from Internet Windows Group Policy"
    try {
        # Disable metadata retrieval from the Internet
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -PropertyType DWord -Value 1 -Force | Out-Null

        $cmdOutput = "Set PreventDeviceMetadataFromNetwork to 1 (disables Internet retrieval of metadata)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 11034: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 11034"
}

Write-Host "`nControl ID 3778: Status of the contents of the login banner (Windows/Unix/Linux)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3778: Status of the contents of the login banner (Windows/Unix/Linux)"
    try {
        # Set the legal banner message and caption
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -PropertyType String -Value "WARNING" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -PropertyType String -Value "This system is for authorized use only. Unauthorized access is prohibited and may be subject to disciplinary action and criminal prosecution." -Force | Out-Null

        $cmdOutput = "Set login banner caption and text for LegalNotice."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3778: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3778"
}

Write-Host "`nControl ID 9440: Status of the Include command line in process creation events setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9440: Status of the Include command line in process creation events setting"
    try {
        # Enable command line logging in process creation events
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -PropertyType DWord -Value 1 -Force | Out-Null

        $cmdOutput = "Enabled inclusion of command line in process creation events."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9440: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9440"
}

Write-Host "`nControl ID 13968: Status of Manage preview builds: Set the behavior of receiving preview builds setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13968: Status of Manage preview builds: Set the behavior of receiving preview builds setting"
    try {
        # Block preview builds from being received or installed
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -PropertyType DWord -Value 0 -Force | Out-Null

        $cmdOutput = "Disabled receiving of preview builds (EnableConfigFlighting set to 0)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13968: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13968"
}

Write-Host "`nControl ID 25340: Status of the Manage processing of Queue-specific files setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25340: Status of the Manage processing of Queue-specific files setting"
    try {
        # Disable processing of queue-specific files
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint" -PropertyType DWord -Value 2 -Force | Out-Null

        $cmdOutput = "Disabled processing of Queue-specific files (RegisterSpoolerRemoteRpcEndPoint set to 2)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25340: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25340"
}

Write-Host "`nControl ID 10106: Status of Toggle user control over Insider builds"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10106: Status of Toggle user control over Insider builds"
    try {
        # Disable user control over Insider builds
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -PropertyType DWord -Value 0 -Force | Out-Null

        $cmdOutput = "Disabled user control over receiving Insider builds (AllowBuildPreview set to 0)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10106: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10106"
}

Write-Host "`nControl ID 9003: Status of the Lock screen camera setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9003: Status of the Lock screen camera setting"
    try {
        # Disable camera access on the lock screen
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -PropertyType DWord -Value 1 -Force | Out-Null

        $cmdOutput = "Disabled camera access on the lock screen (NoLockScreenCamera set to 1)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9003: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9003"
}

Write-Host "`nControl ID 11281: Status of the SMB v1 protocol for LanManServer services on Windows"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 11281: Status of the SMB v1 protocol for LanManServer services on Windows"
    try {
        # Disable SMBv1
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

        # Also disable the SMB 1.0 feature (if installed)
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart

        $cmdOutput = "Disabled SMBv1 protocol for LanManServer and removed feature if present."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 11281: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 11281"
}

Write-Host "`nControl ID 2343: Status of the Reset Account Lockout Counter After setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2343: Status of the Reset Account Lockout Counter After setting"
    try {
        # Set reset account lockout counter time (in minutes)
        # Example: 15 minutes (CIS benchmark typically recommends this)
        net accounts /lockoutwindow:15

        $cmdOutput = "Set Account Lockout Counter Reset After to 15 minutes."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2343: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2343"
}

Write-Host "`nControl ID 4139: Status of the Do not use temporary folders per session Group Policy setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4139: Status of the Do not use temporary folders per session Group Policy setting"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "UseTempFolders" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Executed remediation step for Control ID 4139"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4139: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4139"
}

Write-Host "`nControl ID 2199: Current list of Groups and User Accounts granted the Deny log on locally right"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2199: Current list of Groups and User Accounts granted the Deny log on locally right"
    try {
        # Replace this with a specific secedit assignment for SeDenyInteractiveLogonRight
        $deniedAccounts = @("Guests")
        $accountList = $deniedAccounts -join ","
        secedit /export /cfg C:\Windows\Temp\secedit_export.inf
        (Get-Content C:\Windows\Temp\secedit_export.inf) -replace "(SeDenyInteractiveLogonRight\s*=).*", "`$1 $accountList" | Set-Content C:\Windows\Temp\secedit_update.inf
        secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secedit_update.inf /areas USER_RIGHTS
        Remove-Item C:\Windows\Temp\secedit_export.inf, C:\Windows\Temp\secedit_update.inf -Force
        $cmdOutput = "Executed remediation step for Control ID 2199"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2199: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2199"
}

Write-Host "`nControl ID 2391: Current list of Groups and User Accounts granted the Allow log on locally (SeInteractiveLogonRight) right"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2391: Current list of Groups and User Accounts granted the Allow log on locally (SeInteractiveLogonRight) right"
    try {
        # Replace this with a specific secedit assignment for SeInteractiveLogonRight
        $allowedAccounts = @("Administrators", "Users")
        $accountList = $allowedAccounts -join ","
        secedit /export /cfg C:\Windows\Temp\secedit_export.inf
        (Get-Content C:\Windows\Temp\secedit_export.inf) -replace "(SeInteractiveLogonRight\s*=).*", "`$1 $accountList" | Set-Content C:\Windows\Temp\secedit_update.inf
        secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secedit_update.inf /areas USER_RIGHTS
        Remove-Item C:\Windows\Temp\secedit_export.inf, C:\Windows\Temp\secedit_update.inf -Force
        $cmdOutput = "Executed remediation step for Control ID 2391"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2391: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2391"
}

Write-Host "`nControl ID 5265: Status of the Network security: Allow LocalSystem NULL session fallback setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 5265: Status of the Network security: Allow LocalSystem NULL session fallback setting"
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AllowNullSessionFallback" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Executed remediation step for Control ID 5265"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 5265: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 5265"
}

Write-Host "`nControl ID 23129: Status of the Disable OneSettings Downloads setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 23129: Status of the Disable OneSettings Downloads setting"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Executed remediation step for Control ID 23129"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 23129: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 23129"
}

Write-Host "`nControl ID 12015: Status of the Block all consumer Microsoft account user authentication (DisableUserAuth) Group Policy setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 12015: Status of the Block all consumer Microsoft account user authentication (DisableUserAuth) Group Policy setting"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Executed remediation step for Control ID 12015"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 12015: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 12015"
}

Write-Host "`nControl ID 8141: Status of the Security Options Accounts: Block Microsoft accounts setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8141: Status of the Security Options Accounts: Block Microsoft accounts setting"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -PropertyType DWord -Value 3 -Force | Out-Null
        $cmdOutput = "Executed remediation step for Control ID 8141"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8141: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8141"
}

Write-Host "`nControl ID 10592: Status of the Hardened UNC Paths setting for Netlogon"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10592: Status of the Hardened UNC Paths setting for Netlogon"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\NETLOGON" -PropertyType String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force | Out-Null
        $cmdOutput = "Executed remediation step for Control ID 10592"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10592: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10592"
}

Write-Host "`nControl ID 14883: Status of Office communication application from creating child processes (26190899-1602-49e8-8b27-eb1d0a1ce869)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 14883: Status of Office communication application from creating child processes (26190899-1602-49e8-8b27-eb1d0a1ce869)"
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids "26190899-1602-49e8-8b27-eb1d0a1ce869" -AttackSurfaceReductionRules_Actions Enabled
        $cmdOutput = "Executed remediation step for Control ID 14883"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 14883: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 14883"
}

Write-Host "`nControl ID 13927: Status of Block JavaScript or VBScript from launching downloaded executable content ASR rule (D3E037E1-3EB8-44C8-A917-57927947596D)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13927: Status of Block JavaScript or VBScript from launching downloaded executable content ASR rule (D3E037E1-3EB8-44C8-A917-57927947596D)"
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids "D3E037E1-3EB8-44C8-A917-57927947596D" -AttackSurfaceReductionRules_Actions Enabled
        $cmdOutput = "Executed remediation step for Control ID 13927"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13927: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13927"
}

Write-Host "`nControl ID 8255: Status of the audit setting Removable Storage (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8255: Status of the audit setting Removable Storage (advanced audit setting)"
    try {
        AuditPol /Set /Subcategory:"Removable Storage" /Success:Enable /Failure:Enable
        $cmdOutput = "Enabled success and failure auditing for Removable Storage."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8255: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8255"
}

Write-Host "`nControl ID 11193: Status of the Continue experiences on this device setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 11193: Status of the Continue experiences on this device setting"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableCdp" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Disabled cross-device experience features (EnableCdp set to 0)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 11193: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 11193"
}

Write-Host "`nControl ID 9305: Status of the Notify antivirus programs when opening attachments configuration [For Windows user]"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9305: Status of the Notify antivirus programs when opening attachments configuration [For Windows user]"
    try {
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -PropertyType DWord -Value 3 -Force | Out-Null
        $cmdOutput = "Enabled attachment scan notification to antivirus (ScanWithAntiVirus set to 3)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9305: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9305"
}

Write-Host "`nControl ID 9388: Status of the Turn off picture password sign-in setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9388: Status of the Turn off picture password sign-in setting"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "BlockPicturePassword" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Disabled picture password sign-in (BlockPicturePassword set to 1)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9388: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9388"
}

Write-Host "`nControl ID 1195: Status of the MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from the WINS servers setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1195: Status of the MSS: (NoNameReleaseOnDemand)..."
    try {
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters" -Name "NoNameReleaseOnDemand" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set NoNameReleaseOnDemand to 1 (ignores NetBIOS name release requests unless from WINS)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1195: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1195"
}

Write-Host "`nControl ID 10404: Status of the Require user authentication for remote connections by using Network Level Authentication setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10404: Require user authentication for remote connections by using NLA"
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Enabled NLA for RDP (UserAuthentication set to 1)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10404: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10404"
}

Write-Host "`nControl ID 9830: Status of the Prevent users from sharing files within their profile setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9830: Status of the Prevent users from sharing files within their profile setting"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInplaceSharing" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set NoInplaceSharing to 1 to prevent users from sharing files within their profile."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9830: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9830"
}

Write-Host "`nControl ID 25348: Status of the Configure RPC connection settings: Protocol to use for outgoing RPC connections setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25348: Configure RPC connection settings"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "ForceRpcSecurity" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set ForceRpcSecurity to 1 to enforce secure protocol for outgoing RPC connections."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25348: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25348"
}

Write-Host "`nControl ID 25357: Status of Block abuse of exploited vulnerable signed drivers ASR rule (56a863a9-875e-4185-98a7-b882c64b5ce5)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25357: Block abuse of exploited vulnerable signed drivers ASR rule"
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids "56a863a9-875e-4185-98a7-b882c64b5ce5" -AttackSurfaceReductionRules_Actions Enabled
        $cmdOutput = "Enabled ASR rule to block abuse of vulnerable signed drivers."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25357: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25357"
}

Write-Host "`nControl ID 1377: Status of the Interactive Logon: Require Domain Controller authentication to unlock workstation setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1377: Require DC authentication to unlock workstation"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ForceUnlockLogon" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set ForceUnlockLogon to 1 to require DC authentication when unlocking."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1377: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1377"
}


Write-Host "`nControl ID 4473: Status of the audit setting IPsec Driver (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4473: Audit setting IPsec Driver"
    try {
        AuditPol /Set /Subcategory:"IPsec Driver" /Success:Enable /Failure:Enable
        $cmdOutput = "Enabled auditing for IPsec Driver (success and failure)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4473: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4473"
}

Write-Host "`nControl ID 7805: Status of Windows Automatic Updates (WSUS) setting ( NoAutoUpdate )"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 7805: WSUS setting NoAutoUpdate"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Set NoAutoUpdate to 0 to ensure automatic updates are enabled."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 7805: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 7805"
}

Write-Host "`nControl ID 2608: Status of the Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2608: Force subcategory settings override"
    try {
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set SCENoApplyLegacyAuditPolicy to 1 to enforce subcategory audit settings."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2608: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2608"
}

Write-Host "`nControl ID 2605: Status of the User Account Control: Behavior of the elevation prompt for standard users setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2605: UAC elevation prompt behavior for standard users"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Set ConsentPromptBehaviorUser to 0 (automatically deny elevation requests for standard users)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2605: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2605"
}

Write-Host "`nControl ID 4497: Status of the audit setting Process Creation (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4497: Audit setting Process Creation"
    try {
        AuditPol /Set /Subcategory:"Process Creation" /Success:Enable /Failure:Enable
        $cmdOutput = "Enabled success and failure auditing for Process Creation."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4497: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4497"
}

Write-Host "`nControl ID 3899: Status of the Solicited Remote Assistance policy setting (Terminal Services)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3899: Solicited Remote Assistance policy"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Disabled Solicited Remote Assistance (fAllowToGetHelp set to 0)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3899: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3899"
}

Write-Host "`nControl ID 10151: Status of the audit setting Audit PNP Activity (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10151: Audit PNP Activity"
    try {
        AuditPol /Set /Subcategory:"Plug and Play Events" /Success:Enable /Failure:Enable
        $cmdOutput = "Enabled auditing for Plug and Play device events (success and failure)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10151: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10151"
}

Write-Host "`nControl ID 23130: Status of the Enable OneSettings Auditing setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 23130: Enable OneSettings Auditing"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "EnableOneSettingsAuditing" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Enabled OneSettings auditing (EnableOneSettingsAuditing set to 1)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 23130: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 23130"
}

Write-Host "`nControl ID 2587: Status of the User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2587: UAC elevation prompt behavior for administrators"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -PropertyType DWord -Value 2 -Force | Out-Null
        $cmdOutput = "Set ConsentPromptBehaviorAdmin to 2 (prompt for credentials on the secure desktop)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2587: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2587"
}

Write-Host "`nControl ID 1525: Status of the Windows Firewall: Log file path and name (Domain) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1525: Firewall log path (Domain)"
    try {
        Set-NetFirewallProfile -Profile Domain -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
        $cmdOutput = "Set Windows Firewall log file path (Domain) to pfirewall.log."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1525: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1525"
}

Write-Host "`nControl ID 17242: Status of the Require pin for pairing Enabled First Time OR Always setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 17242: Require PIN for device pairing"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Enabled PIN requirement for Bluetooth device pairing (RequirePinForPairing set to 1)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 17242: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 17242"
}

Write-Host "`nControl ID 8273: Status of the Turn off Data Execution Prevention for Explorer setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8273: Disable DEP for Explorer"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Ensured DEP is enabled for Explorer (NoDataExecutionPrevention set to 0)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8273: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8273"
}

Write-Host "`nControl ID 3951: Status of the Windows Firewall: Firewall state (Private) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3951: Firewall state (Private)"
    try {
        Set-NetFirewallProfile -Profile Private -Enabled True
        $cmdOutput = "Enabled Windows Firewall for the Private profile."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3951: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3951"
}

Write-Host "`nControl ID 26140: Status of post-authentication actions (PostAuthenticationResetDelay) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 26140: PostAuthenticationResetDelay"
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PostAuthenticationResetDelay" -PropertyType DWord -Value 30 -Force | Out-Null
        $cmdOutput = "Set PostAuthenticationResetDelay to 30 seconds."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 26140: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 26140"
}

Write-Host "`nControl ID 1524: Status of the Windows Firewall: Log dropped packets (Domain) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1524: Log dropped packets (Domain)"
    try {
        Set-NetFirewallProfile -Profile Domain -LogDroppedPackets Enabled
        $cmdOutput = "Enabled logging of dropped packets on the Domain firewall profile."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1524: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1524"
}

Write-Host "`nControl ID 9404: Status of the Prevent the usage of OneDrive for file storage (Skydrive) group policy setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9404: Prevent OneDrive usage"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Disabled OneDrive file storage integration (DisableFileSync set to 1)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9404: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9404"
}

Write-Host "`nControl ID 5264: Status of the Microsoft network server: Server SPN target name validation level setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 5264: Server SPN target name validation level"
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMBServerNameHardeningLevel" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set SMBServerNameHardeningLevel to 1 to enable SPN target name validation."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 5264: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 5264"
}

Write-Host "`nControl ID 13922: Status of Attack Surface Reduction group policy"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13922: Enable ASR group policy enforcement"
    try {
        Set-MpPreference -EnableControlledFolderAccess Enabled
        $cmdOutput = "Enabled Attack Surface Reduction policies via Controlled Folder Access."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13922: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13922"
}

Write-Host "`nControl ID 3952: Status of the Windows Firewall: Firewall state (Domain) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3952: Firewall state (Domain)"
    try {
        Set-NetFirewallProfile -Profile Domain -Enabled True
        $cmdOutput = "Enabled Windows Firewall for the Domain profile."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3952: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3952"
}

Write-Host "`nControl ID 8160: Status of the Windows Firewall: Log File Size (Private) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8160: Firewall log file size (Private)"
    try {
        Set-NetFirewallProfile -Profile Private -LogMaxSizeKilobytes 16384
        $cmdOutput = "Set Private profile firewall log file size to 16384 KB (16 MB)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8160: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8160"
}

Write-Host "`nControl ID 11192: Status of the Turn off multicast name resolution setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 11192: Turn off multicast name resolution"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Disabled multicast name resolution (EnableMulticast set to 0)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 11192: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 11192"
}

Write-Host "`nControl ID 8274: Status of the Configure Windows Defender SmartScreen setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8274: Configure Windows Defender SmartScreen"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Enabled SmartScreen (EnableSmartScreen set to 1)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8274: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8274"
}

Write-Host "`nControl ID 8145: Status of the Security Options Interactive logon: Machine inactivity limit setting (seconds)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8145: Interactive logon inactivity timeout"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -PropertyType DWord -Value 900 -Force | Out-Null
        $cmdOutput = "Set machine inactivity limit to 900 seconds (15 minutes)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8145: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8145"
}

Write-Host "`nControl ID 26139: Status of Post-authentication actions (PostAuthenticationActions) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 26139: PostAuthenticationActions"
    try {
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "PostAuthenticationActions" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set PostAuthenticationActions to 1 to enable lock on reset actions."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 26139: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 26139"
}

Write-Host "`nControl ID 9014: Status of the Setup: Maximum Log Size (KB) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9014: Setup log max size"
    try {
        wevtutil sl Setup /ms:32768
        $cmdOutput = "Set Setup log maximum size to 32768 KB (32 MB)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9014: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9014"
}

Write-Host "`nControl ID 8367: Status of the name of the Built-in Administrator account"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8367: Rename built-in Administrator account"
    try {
        Rename-LocalUser -Name "Administrator" -NewName "spgadmin"
        $cmdOutput = "Renamed built-in Administrator account 'spgadmin' "
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8367: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8367"
}

Write-Host "`nControl ID 9009: Status of the Allow Microsoft accounts to be optional setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9009: Allow Microsoft accounts to be optional"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set MSAOptional to 1 to allow Microsoft accounts to be optional."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9009: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9009"
}

Write-Host "`nControl ID 3922: Status of the Turn off downloading of print drivers over HTTP setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3922: Turn off HTTP print driver downloads"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Disabled downloading of print drivers over HTTP (DisableWebPnPDownload set to 1)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3922: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3922"
}

Write-Host "`nControl ID 1381: Status of the Microsoft network server: Digitally Sign Communications (if Client agrees) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1381: Digitally sign communications (if client agrees)"
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set EnableSecuritySignature to 1 (sign if client agrees)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1381: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1381"
}

Write-Host "`nControl ID 8233: Status Network Security:Restrict NTLM: Audit Incoming NTLM Traffic setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8233: Audit Incoming NTLM Traffic"
    try {
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -PropertyType DWord -Value 2 -Force | Out-Null
        $cmdOutput = "Set AuditReceivingNTLMTraffic to 2 (audit all incoming NTLM traffic)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8233: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8233"
}

Write-Host "`nControl ID 8168: Status of the Windows Firewall: Log File Size (Public) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8168: Firewall log size (Public)"
    try {
        Set-NetFirewallProfile -Profile Public -LogMaxSizeKilobytes 16384
        $cmdOutput = "Set firewall log file size for Public profile to 16384 KB (16 MB)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8168: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8168"
}

Write-Host "`nControl ID 1169: Status of the MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1169: AutoAdminLogon setting"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -PropertyType String -Value "0" -Force | Out-Null
        $cmdOutput = "Disabled automatic logon (AutoAdminLogon set to 0)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1169: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1169"
}

Write-Host "`nControl ID 13343: Status of the Configure Windows Defender SmartScreen - Pick one of the following setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13343: Configure Windows Defender SmartScreen"
    try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -PropertyType String -Value "Warn" -Force | Out-Null
        $cmdOutput = "Enabled SmartScreen with 'Warn' level (EnableSmartScreen = 1, ShellSmartScreenLevel = 'Warn')."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13343: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13343"
}

Write-Host "`nControl ID 2197: Current list of Groups and User Accounts granted the Deny logon as a batch job right"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2197: Deny logon as a batch job"
    try {
        ntrights -u "Guests" +r SeDenyBatchLogonRight
        $cmdOutput = "Assigned 'Deny logon as a batch job' right to Guests (SeDenyBatchLogonRight)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2197: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2197"
}

Write-Host "`nControl ID 19070: Status of the Point and Print Restrictions: When installing drivers for a new connection setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 19070: Point and Print Restrictions"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Configured Point and Print: driver installs require elevation (NoWarningNoElevationOnInstall set to 0)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 19070: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 19070"
}

Write-Host "`nControl ID 3920: Status of the Turn off Internet download for Web publishing and online ordering wizards setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3920: Disable Internet downloads for publishing/ordering wizards"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Disabled Internet download for Web publishing/ordering wizards (NoWebServices set to 1)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3920: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3920"
}

Write-Host "`nControl ID 9453: Status of Scan removable drives (Windows Defender) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9453: Scan removable drives"
    try {
        Set-MpPreference -DisableRemovableDriveScanning $false
        $cmdOutput = "Enabled scanning of removable drives (DisableRemovableDriveScanning = false)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9453: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9453"
}

Write-Host "`nControl ID 8162: Status of the Windows Firewall: Log Successful Connections (Private) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8162: Log successful connections (Private)"
    try {
        Set-NetFirewallProfile -Profile Private -LogSuccessfulConnections Enabled
        $cmdOutput = "Enabled logging of successful connections for the Private firewall profile."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8162: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8162"
}

Write-Host "`nControl ID 4482: Status of the audit setting Other Logon/Logoff Events (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4482: Other Logon/Logoff Events"
    try {
        AuditPol /Set /Subcategory:"Other Logon/Logoff Events" /Success:Enable /Failure:Enable
        $cmdOutput = "Enabled auditing for Other Logon/Logoff Events (success and failure)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4482: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4482"
}

Write-Host "`nControl ID 4490: Status of the audit setting File Share (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4490: File Share auditing"
    try {
        AuditPol /Set /Subcategory:"File Share" /Success:Enable /Failure:Enable
        $cmdOutput = "Enabled auditing for File Share events (success and failure)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4490: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4490"
}

Write-Host "`nControl ID 1190: Status of the Interactive Logon: Do Not Display Last User Name setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1190: Do Not Display Last User Name"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set DontDisplayLastUserName to 1 (do not display last signed-in user)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1190: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1190"
}

Write-Host "`nControl ID 1172: Status of the MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1172: Disable IP Source Routing"
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -PropertyType DWord -Value 2 -Force | Out-Null
        $cmdOutput = "Set DisableIPSourceRouting to 2 (highest protection)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1172: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1172"
}

Write-Host "`nControl ID 11194: Status of the Block user from showing account details on sign-in setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 11194: Block showing account details on sign-in"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Blocked display of account details on sign-in screen."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 11194: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 11194"
}

Write-Host "`nControl ID 10348: Status of the Do not show feedback notifications setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10348: Disable feedback notifications"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set DoNotShowFeedbackNotifications to 1 to disable feedback prompts."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10348: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10348"
}

Write-Host "`nControl ID 13344: Status of the Prevent users from modifying settings setting for Windows Defender Exploit Protection"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13344: Prevent users from modifying Exploit Protection settings"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\ExploitGuard\ExploitProtection" -Name "ExploitProtection_Settings" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set ExploitProtection_Settings to 1 to prevent users from modifying Exploit Protection settings."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13344: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13344"
}

Write-Host "`nControl ID 1378: Status of the Interactive Logon: Smart Card Removal Behavior setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1378: Smart Card Removal Behavior"
    try {
        secedit /export /cfg C:\Windows\Temp\secpol.cfg
        (Get-Content C:\Windows\Temp\secpol.cfg).replace("ScRemoveOption = 0", "ScRemoveOption = 1") | Set-Content C:\Windows\Temp\secpol.cfg
        secedit /configure /db secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY
        Remove-Item C:\Windows\Temp\secpol.cfg
        $cmdOutput = "Set Smart Card Removal Behavior to lock the workstation (ScRemoveOption = 1)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1378: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1378"
}

Write-Host "`nControl ID 10377: Status of the Use enhanced anti-spoofing when available setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10377: Use enhanced anti-spoofing"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Enabled enhanced anti-spoofing for facial recognition."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10377: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10377"
}

Write-Host "`nControl ID 23138: Status of the Turn off Spotlight collection on Desktop setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 23138: Turn off Spotlight collection on Desktop"
    try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSpotlightCollectionOnDesktop" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Disabled Windows Spotlight collection on the desktop background."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 23138: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 23138"
}

Write-Host "`nControl ID 2400: Current list of Groups and User Accounts granted the Shut down the system (SeShutdownPrivilege) right"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2400: Shut down the system"
    try {
        ntrights -u "Users" +r SeShutdownPrivilege
        $cmdOutput = "Granted 'Shut down the system' right to Users (SeShutdownPrivilege). Modify account/group as needed."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2400: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2400"
}

Write-Host "`nControl ID 25338: Status of the Configure Redirection Guard setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25338: Configure Redirection Guard"
    try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Enabled Redirection Guard with VBS and secure platform enforcement."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25338: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25338"
}

Write-Host "`nControl ID 2186: Current list of Groups and User Accounts granted the Back up files and directories right"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2186: Back up files and directories right"
    try {
        ntrights -u "Administrators" +r SeBackupPrivilege
        $cmdOutput = "Granted 'Back up files and directories' right to Administrators (SeBackupPrivilege)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2186: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2186"
}

Write-Host "`nControl ID 2586: Status of the User Account Control: Admin Approval Mode for the Built-in Administrator account setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2586: Admin Approval Mode for Built-in Administrator"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Enabled Admin Approval Mode for Built-in Administrator (FilterAdministratorToken = 1)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2586: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2586"
}

Write-Host "`nControl ID 10370: Status of the Enable insecure guest logons setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10370: Disable insecure guest logons"
    try {
        New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Disabled insecure guest logons (AllowInsecureGuestAuth = 0)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10370: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10370"
}

Write-Host "`nControl ID 3875: Status of the Do not allow drive redirection setting (Terminal Services)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3875: Disable drive redirection in RDP"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Disabled drive redirection (fDisableCdm = 1)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3875: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3875"
}

Write-Host "`nControl ID 2399: Current list of Groups and User Accounts granted the Restore files and directories (SeRestorePrivilege) right"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2399: Restore files and directories right"
    try {
        ntrights -u "Administrators" +r SeRestorePrivilege
        $cmdOutput = "Granted 'Restore files and directories' right to Administrators (SeRestorePrivilege)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2399: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2399"
}

Write-Host "`nControl ID 27616: Status of the Configure security policy processing: Do not apply during periodic background processing setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 27616: Do not apply during periodic background processing"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}\0" -Name "NoBackgroundPolicy" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Set NoBackgroundPolicy to 0 to allow policy processing during background refresh."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 27616: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 27616"
}

Write-Host "`nControl ID 26147: Status of Configure password backup directory setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 26147: Configure password backup directory"
    try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "PasswordBackupDirectory" -PropertyType String -Value "None" -Force | Out-Null
        $cmdOutput = "Set PasswordBackupDirectory to 'None' to disable cloud password backup."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 26147: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 26147"
}

Write-Host "`nControl ID 9024: Status of the Apply UAC restrictions to local accounts on network logons settings"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9024: Apply UAC restrictions on network logons"
    try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Enforced UAC restrictions on local accounts for remote access (LocalAccountTokenFilterPolicy = 0)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9024: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9024"
}

Write-Host "`nControl ID 4741: Status of the MSS: (DisableIPSourceRoutingIPv6) IP source routing protection level (IPv6)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4741: Disable IPv6 IP source routing"
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -PropertyType DWord -Value 2 -Force | Out-Null
        $cmdOutput = "Set DisableIPSourceRouting (IPv6) to 2 to fully disable source routing."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4741: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4741"
}

Write-Host "`nControl ID 4493: Status of the audit setting Other Object Access Events (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4493: Other Object Access Events"
    try {
        AuditPol /Set /Subcategory:"Other Object Access Events" /Success:Enable /Failure:Enable
        $cmdOutput = "Enabled auditing for Other Object Access Events (success and failure)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4493: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4493"
}

Write-Host "`nControl ID 26149: Status of password (PasswordAgeDays) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 26149: Maximum password age"
    try {
        net accounts /maxpwage:90
        $cmdOutput = "Set maximum password age to 90 days."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 26149: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 26149"
}

Write-Host "`nControl ID 3932: Status of the Windows Firewall: Inbound connections (Public) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3932: Inbound firewall (Public) setting"
    try {
        Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
        $cmdOutput = "Set Windows Firewall (Public) to block inbound connections by default."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3932: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3932"
}

Write-Host "`nControl ID 26137: Status of Password (PasswordLength) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 26137: Password minimum length"
    try {
        net accounts /minpwlen:14
        $cmdOutput = "Set minimum password length to 14 characters."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 26137: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 26137"
}

Write-Host "`nControl ID 8161: Status of the Windows Firewall: Log file path and name (Private) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8161: Firewall log file path (Private)"
    try {
        Set-NetFirewallProfile -Profile Private -LogFileName "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
        $cmdOutput = "Set firewall log file path for Private profile to pfirewall.log."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8161: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8161"
}

Write-Host "`nControl ID 3960: Status of the Windows Firewall: Apply local firewall rules (Public) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3960: Apply local firewall rules (Public)"
    try {
        Set-NetFirewallProfile -Profile Public -AllowLocalRules False
        $cmdOutput = "Disabled local firewall rules for Public profile."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3960: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3960"
}

Write-Host "`nControl ID 8165: Status of the Windows Firewall: Log dropped packets (Public) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8165: Log dropped packets (Public)"
    try {
        Set-NetFirewallProfile -Profile Public -LogDroppedPackets Enabled
        $cmdOutput = "Enabled logging of dropped packets for Public firewall profile."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8165: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8165"
}

Write-Host "`nControl ID 3965: Status of the Windows Firewall: Display a notification (Public) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3965: Display notification (Public)"
    try {
        Set-NetFirewallProfile -Profile Public -NotifyOnListen True
        $cmdOutput = "Enabled notifications for listening apps on Public firewall profile."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3965: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3965"
}

Write-Host "`nControl ID 25359: Status of the Authentication protocol to use for incoming RPC connections setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25359: Authentication protocol for incoming RPC"
    try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "ForceAuthnLevel" -PropertyType DWord -Value 5 -Force | Out-Null
        $cmdOutput = "Set authentication protocol level to 'PktPrivacy' (5) for incoming RPC connections."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25359: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25359"
}

Write-Host "`nControl ID 25350: Status of the Allow Custom SSPs and APs to be loaded into LSASS setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25350: Disable loading of custom SSPs and APs into LSASS"
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages" -PropertyType MultiString -Value "kerberos","msv1_0","wdigest","tspkg","pku2u","schannel" -Force | Out-Null
        $cmdOutput = "Ensured only default SSPs/APs are configured under Security Packages."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25350: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25350"
}

Write-Host "`nControl ID 4506: Status of the audit setting Other Policy Change Events (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4506: Enable auditing of Other Policy Change Events"
    try {
        AuditPol /Set /Subcategory:"Other Policy Change Events" /Success:Enable /Failure:Enable
        $cmdOutput = "Enabled audit for Other Policy Change Events (success and failure)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4506: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4506"
}

Write-Host "`nControl ID 3891: Status of the Always prompt for password upon connection setting (Terminal Services)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3891: Require password prompt on RDP connection"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Configured Terminal Services to always prompt for password upon connection."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3891: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3891"
}

Write-Host "`nControl ID 14415: Status of the Encryption Oracle Remediation group policy"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 14415: Configure Encryption Oracle Remediation"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name "AllowEncryptionOracle" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Set AllowEncryptionOracle to 0 (Force updated clients only)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 14415: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 14415"
}

Write-Host "`nControl ID 25356: Status of the Enable MPR notifications for the system setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25356: Disable MPR notifications"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "EnableMPRNotifications" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Disabled MPR (Multiple Provider Router) notifications (EnableMPRNotifications = 0)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25356: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25356"
}

Write-Host "`nControl ID 9537: Status of Windows Defender - Turn on e-mail scanning setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9537: Enable Defender email scanning"
    try {
        Set-MpPreference -DisableEmailScanning $false
        $cmdOutput = "Enabled e-mail scanning in Windows Defender (DisableEmailScanning = False)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9537: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9537"
}

Write-Host "`nControl ID 1153: Status of the Network Access: Do not allow Anonymous Enumeration of SAM Accounts and Shares setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1153: Disable anonymous SAM/Shares enumeration"
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set RestrictAnonymous = 1 (disallow anonymous enumeration)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1153: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1153"
}

Write-Host "`nControl ID 3897: Status of Enumerate administrator accounts on elevation setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3897: Disable enumerating admin accounts on elevation"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Disabled enumeration of admin accounts on elevation prompt."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3897: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3897"
}

Write-Host "`nControl ID 8243: Configure Network Security:Restrict NTLM: Outgoing NTLM traffic to remote servers"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8243: Restrict outgoing NTLM"
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -PropertyType DWord -Value 2 -Force | Out-Null
        $cmdOutput = "Restricted outgoing NTLM traffic to remote servers (Block all = 2)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8243: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8243"
}

Write-Host "`nControl ID 8366: Status of the name of the Built-in Guest account"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8366: Rename Guest account"
    try {
        Rename-LocalUser -Name "Guest" -NewName "DisabledGuest"  # or another name per your policy
        $cmdOutput = "Renamed built-in Guest account to 'DisabledGuest'."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8366: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8366"
}

Write-Host "`nControl ID 3948: Status of the Windows Firewall: Inbound connections (Private) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3948: Block inbound connections (Private)"
    try {
        Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block
        $cmdOutput = "Set Private profile to block all inbound connections."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3948: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3948"
}

Write-Host "`nControl ID 11203: Status of the Do not suggest third-party content in Windows spotlight setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 11203: Disable third-party content in Spotlight"
    try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Disabled third-party suggestions in Windows Spotlight."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 11203: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 11203"
}

Write-Host "`nControl ID 2616: Status of the Prohibit installation and configuration of Network Bridge on the DNS domain network setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2616"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Prohibited installation/configuration of Network Bridge on DNS domain network."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2616: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2616"
}

Write-Host "`nControl ID 13923: Block Office applications from injecting code into other processes ASR rule"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13923"
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" -AttackSurfaceReductionRules_Actions Enabled
        $cmdOutput = "Enabled ASR rule to block Office applications from injecting code (ID: 75668C1F...)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13923: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13923"
}

Write-Host "`nControl ID 1183: Status of the Disable Autorun for all drives setting for the HKLM key"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1183"
    try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 255 -Force | Out-Null
        $cmdOutput = "Disabled Autorun for all drives (HKLM)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1183: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1183"
}

Write-Host "`nControl ID 13932: Block Office applications from creating executable content ASR rule"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13932"
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids "3B576869-A4EC-4529-8536-B80A7769E899" -AttackSurfaceReductionRules_Actions Enabled
        $cmdOutput = "Enabled ASR rule to block Office apps from creating executables (ID: 3B576869...)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13932: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13932"
}

Write-Host "`nControl ID 22305: Enable file hash computation feature"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 22305"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableFileHashComputation" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Enabled file hash computation feature."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 22305: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 22305"
}

Write-Host "`nControl ID 25361: Status of the Protocols to allow for incoming RPC connections setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25361"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set RPC RestrictRemoteClients to allow authenticated RPC traffic only."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25361: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25361"
}

Write-Host "`nControl ID 2607: Status of the Prohibit use of Internet Connection Sharing on your DNS domain network setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2607"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Disabled Internet Connection Sharing UI on DNS domain network."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2607: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2607"
}

Write-Host "`nControl ID 1389: Status of the Network Security: Minimum session security for NTLM SSP based (including secure RPC) clients setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1389"
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -PropertyType DWord -Value 537395200 -Force | Out-Null
        $cmdOutput = "Set minimum session security for NTLM SSP clients (Require NTLMv2, 128-bit encryption, and signing)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1389: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1389"
}

Write-Host "`nControl ID 25902: Status of Enable App Installer Hash Override setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25902"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppInstaller" -Name "EnableHashOverride" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Disabled App Installer hash override."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25902: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25902"
}

Write-Host "`nControl ID 2621: Status of the Turn off heap termination on corruption setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2621"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Name "DisableHeapTerminationOnCorruption" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Ensured heap termination on corruption is enabled."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2621: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2621"
}

Write-Host "`nControl ID 4133: Status of the Require secure RPC communication setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4133"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name "ForceSecureRpcAuthentication" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Enabled secure RPC communication."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4133: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4133"
}

Write-Host "`nControl ID 1071: Status of the Minimum Password Length setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1071"
    try {
        secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
        (Get-Content "$env:TEMP\secpol.cfg").replace("MinimumPasswordLength = 0", "MinimumPasswordLength = 14") | Set-Content "$env:TEMP\secpol.cfg"
        secedit /configure /db "$env:TEMP\secedit.sdb" /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY | Out-Null
        Remove-Item "$env:TEMP\secpol.cfg","$env:TEMP\secedit.sdb" -Force
        $cmdOutput = "Set minimum password length to 14 characters."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1071: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1071"
}

Write-Host "`nControl ID 10353: Status of the Turn off Microsoft consumer experiences setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10353"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Turned off Microsoft consumer experiences."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10353: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10353"
}

Write-Host "`nControl ID 10007: Status of the default behavior for AutoRun"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10007"
    try {
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Set default behavior for AutoRun to disabled."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10007: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10007"
}

Write-Host "`nControl ID 2198: Current list of Groups and User Accounts granted the Deny logon as a service right"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2198"
    try {
        ntrights -u "Guests" -m \\localhost +r SeDenyServiceLogonRight
        $cmdOutput = "Applied 'Deny logon as a service' to Guests group."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2198: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2198"
}

Write-Host "`nControl ID 4517: Status of the audit setting Credential Validation (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4517"
    try {
        AuditPol /set /subcategory:"Credential Validation" /success:enable /failure:enable
        $cmdOutput = "Enabled auditing for Credential Validation (success and failure)."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4517: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4517"
}

Write-Host "`nControl ID 9008: Status of the Do not display network selection UI setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9008"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -PropertyType DWord -Value 1 -Force | Out-Null
        $cmdOutput = "Disabled network selection UI on logon screen."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9008: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9008"
}

Write-Host "`nControl ID 4140: Status of the Do not delete temp folder upon exit setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4140"
    try {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DeleteTempDirsOnExit" -PropertyType DWord -Value 0 -Force | Out-Null
        $cmdOutput = "Configured system to retain temp folders on exit."
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4140: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4140"
}

Write-Host "`nControl ID 14884: Status of Block Adobe Reader from creating child processes ASR rule (7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 14884"
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -AttackSurfaceReductionRules_Actions Enabled
        $cmdOutput = "ASR rule 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c enabled for Adobe Reader child process blocking"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 14884: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 14884"
}

Write-Host "`nControl ID 22344: Status of the DoH Policy setting."
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 22344"
    try {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "DoHPolicy" -Value 0 -Type DWord
        $cmdOutput = "Disabled DNS over HTTPS (DoH) via Group Policy"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 22344: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 22344"
}

Write-Host "`nControl ID 25901: Status of Enable App Installer Experimental Features setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25901"
    try {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableExperimentalFeatures" -Value 0 -Type DWord
        $cmdOutput = "Disabled App Installer Experimental Features"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25901: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25901"
}

Write-Host "`nControl ID 1526: Status of the Windows Firewall: Log File Size (Domain) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1526"
    try {
        Set-NetFirewallProfile -Profile Domain -LogFileSizeKilobytes 16384
        $cmdOutput = "Set Domain Firewall Log File Size to 16384 KB"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1526: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1526"
}

Write-Host "`nControl ID 13931: Status of Prevent users and apps from accessing dangerous websites setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13931"
    try {
        Set-MpPreference -EnableNetworkProtection Enabled
        $cmdOutput = "Enabled Windows Defender Network Protection (blocks dangerous websites)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13931: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13931"
}

Write-Host "`nControl ID 2200: Current list of Groups and User Accounts granted the Deny logon through terminal (Remote Desktop) service right"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2200"
    try {
        ntrights -u "Guests" +r SeDenyRemoteInteractiveLogonRight
        $cmdOutput = "Applied Deny logon through Remote Desktop Services to Guests"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2200: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2200"
}

Write-Host "`nControl ID 1463: Status of the MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1463"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Name "WarningLevel" -Value 90 -Type DWord
        $cmdOutput = "Set security log warning level to 90%"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1463: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1463"
}

Write-Host "`nControl ID 13930: Status of Block credential stealing from the Windows local security authority subsystem (lsass.exe) ASR rule (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13930"
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -AttackSurfaceReductionRules_Actions Enabled
        $cmdOutput = "Enabled ASR rule to block LSASS credential theft"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13930: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13930"
}

Write-Host "`nControl ID 14414: Status of the Enumeration policy for external devices incompatible with Kernel DMA Protection setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 14414"
    try {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection" -Name "DeviceEnumerationPolicy" -Value 0 -Type DWord
        $cmdOutput = "Set DeviceEnumerationPolicy to 0 (block incompatible devices)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 14414: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 14414"
}

Write-Host "`nControl ID 10087: Status of the Enable Windows NTP Client setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10087"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" -Name "Enabled" -Value 1 -Type DWord
        $cmdOutput = "Enabled Windows NTP Client"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10087: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10087"
}

Write-Host "`nControl ID 8163: Status of the Windows Firewall: Log dropped packets (Private) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8163"
    try {
        Set-NetFirewallProfile -Profile Private -LogDroppedPackets Enabled
        $cmdOutput = "Enabled logging of dropped packets on Private Firewall Profile"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8163: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8163"
}

Write-Host "`nControl ID 5266: Status of the Network security: Allow Local System to use computer identity for NTLM setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 5266"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AllowSystemToUseComputerIdentity" -Value 1 -Type DWord
        $cmdOutput = "Enabled Local System use of computer identity for NTLM"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 5266: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 5266"
}

Write-Host "`nControl ID 1387: Status of the Network Security: LAN Manager Authentication Level setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1387"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord
        $cmdOutput = "Set LAN Manager Authentication Level to 'Send NTLMv2 response only. Refuse LM and NTLM'"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1387: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1387"
}

Write-Host "`nControl ID 4503: Status of the audit setting Authorization Policy Change (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4503"
    try {
        AuditPol /Set /SubCategory:"Authorization Policy Change" /Success:Enable /Failure:Enable
        $cmdOutput = "Enabled auditing for Authorization Policy Change (Success and Failure)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4503: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4503"
}

Write-Host "`nControl ID 17241: Configure Minimize the number of simultaneous connections to the Internet or a Windows Domain Prevent Wi-Fi when on Ethernet."
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 17241"
    try {
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value 3 -Type DWord
        $cmdOutput = "Set to prevent Wi-Fi connections when Ethernet is connected (MinimizeConnections = 3)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 17241: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 17241"
}

Write-Host "`nControl ID 1072: Status of the Minimum Password Age setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1072"
    try {
        net accounts /minpwage:1
        $cmdOutput = "Set minimum password age to 1 day"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1072: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1072"
}

Write-Host "`nControl ID 13928: Status of Block executable content from email client and webmail ASR rule (BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13928"
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" -AttackSurfaceReductionRules_Actions Enabled
        $cmdOutput = "Enabled ASR rule to block executable content from email client and webmail"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13928: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13928"
}

Write-Host "`nControl ID 23132: Status of the Limit Diagnostic Log Collection setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 23132"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1 -Type DWord
        $cmdOutput = "Set LimitDiagnosticLogCollection to 1 (Enabled)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 23132: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 23132"
}

Write-Host "`nControl ID 1513: Status of the RPC Endpoint Mapper Client Authentication setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1513"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -Type DWord
        $cmdOutput = "Enabled RPC Endpoint Mapper Client Authentication"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1513: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1513"
}

Write-Host "`nControl ID 25903: Status of Enable App Installer ms-appinstaller protocol setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25903"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableMSAppInstallerProtocol" -Value 0 -Type DWord
        $cmdOutput = "Disabled App Installer ms-appinstaller protocol (EnableMSAppInstallerProtocol = 0)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25903: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25903"
}

Write-Host "`nControl ID 2635: Status of the Set Client Connection Encryption Level setting (Terminal Services)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2635"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value 3 -Type DWord
        $cmdOutput = "Set Client Connection Encryption Level to High (MinEncryptionLevel = 3)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2635: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2635"
}

Write-Host "`nControl ID 13926: Status of Block execution of potentially obfuscated scripts ASR rule (5BEB7EFE-FD9A-4556-801D-275E5FFC04CC)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13926"
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids "5beb7efe-fd9a-4556-801d-275e5ffc04cc" -AttackSurfaceReductionRules_Actions Enabled
        $cmdOutput = "Enabled ASR rule to block execution of potentially obfuscated scripts"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13926: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13926"
}

Write-Host "`nControl ID 1189: Status of the Microsoft network server: Digitally sign communication (always) setting (SMB)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1189"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
        $cmdOutput = "Enforced SMB signing: Digitally sign communication (always) = Enabled"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1189: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1189"
}

Write-Host "`nControl ID 3962: Status of the Windows Firewall: Display a notification (Domain) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3962"
    try {
        Set-NetFirewallProfile -Profile Domain -NotifyOnListen True
        $cmdOutput = "Enabled firewall notifications on the Domain profile"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3962: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3962"
}

Write-Host "`nControl ID 19071: Status of the Point and Print Restrictions: When updating drivers for an existing connection setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 19071"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnUpdate" -Value 0 -Type DWord
        $cmdOutput = "Set NoWarningNoElevationOnUpdate = 0 (Elevation prompt required when updating drivers)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 19071: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 19071"
}

Write-Host "`nControl ID 3966: Status of the Windows Firewall: Apply local connection security rules (Public) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3966"
    try {
        Set-NetFirewallProfile -Profile Public -AllowLocalIPsecRules False
        $cmdOutput = "Disabled application of local connection security rules on Public profile"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3966: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3966"
}

Write-Host "`nControl ID 8251: Status of the Disallow WinRM from storing RunAs credentials setting (WinRM service)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8251"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -Value 1 -Type DWord
        $cmdOutput = "Disabled storing of RunAs credentials by WinRM (DisableRunAs = 1)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8251: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8251"
}

Write-Host "`nControl ID 3876: Status of the Do not allow passwords to be saved setting (Terminal Services)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3876"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Value 1 -Type DWord
        $cmdOutput = "Disallowed saving of passwords in RDP sessions (DisablePasswordSaving = 1)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3876: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3876"
}

Write-Host "`nControl ID 4511: Status of the audit setting Application Group Management (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4511"
    try {
        AuditPol /set /subcategory:"Application Group Management" /success:enable /failure:enable
        $cmdOutput = "Enabled auditing for Application Group Management (success and failure)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4511: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4511"
}

Write-Host "`nControl ID 26148: Status of Do not allow password expiration time longer than required by policy setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 26148"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PwdExpiryWarning" -Value 1 -Type DWord
        $cmdOutput = "Restricted password expiration time beyond domain policy limits (PwdExpiryWarning = 1)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 26148: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 26148"
}

Write-Host "`nControl ID 25900: Status of Enable App Installer setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25900"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableAppInstaller" -Value 0 -Type DWord
        $cmdOutput = "Disabled App Installer (EnableAppInstaller = 0)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25900: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25900"
}

Write-Host "`nControl ID 13924: Status of Block all Office applications from creating child processes ASR rule (D4F940AB-401B-4EFC-AADC-AD5F3C50688A)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13924"
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" -AttackSurfaceReductionRules_Actions Enabled
        $cmdOutput = "Enabled ASR rule to block all Office apps from creating child processes"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13924: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13924"
}

Write-Host "`nControl ID 9842: Status of the Turn off toast notifications on the lock screen setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9842"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord
        $cmdOutput = "Disabled toast notifications on the lock screen"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9842: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9842"
}

Write-Host "`nControl ID 11211: Status of the Configure Windows spotlight on Lock Screen setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 11211"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "ConfigureWindowsSpotlight" -Value 2 -Type DWord
        $cmdOutput = "Disabled Windows Spotlight on Lock Screen (ConfigureWindowsSpotlight = 2)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 11211: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 11211"
}

Write-Host "`nControl ID 4494: Status of the audit setting Sensitive Privilege Use (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4494: Status of the audit setting Sensitive Privilege Use (advanced audit setting)"
    try {
        AuditPol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
        $cmdOutput = "Enabled auditing for Sensitive Privilege Use (Success and Failure)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4494: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4494"
}

Write-Host "`nControl ID 7502: Status of the Application: Maximum log size setting (in KB)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 7502: Status of the Application: Maximum log size setting (in KB)"
    try {
        wevtutil sl Application /ms:32768
        $cmdOutput = "Set Application log maximum size to 32768 KB"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 7502: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 7502"
}

Write-Host "`nControl ID 1318: Status of the Enforce password history setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1318: Status of the Enforce password history setting"
    try {
        secedit /export /cfg C:\Temp\secpol.cfg
        (Get-Content C:\Temp\secpol.cfg).replace("PasswordHistorySize = 0", "PasswordHistorySize = 24") | Set-Content C:\Temp\secpol.cfg
        secedit /configure /db secedit.sdb /cfg C:\Temp\secpol.cfg /areas SECURITYPOLICY
        Remove-Item C:\Temp\secpol.cfg
        $cmdOutput = "Set Enforce password history to 24 passwords remembered"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1318: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1318"
}

Write-Host "`nControl ID 8248: Status of the Disallow Digest authentication setting (WinRM client)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8248: Status of the Disallow Digest authentication setting (WinRM client)"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value 0 -Type DWord
        $cmdOutput = "Disabled Digest authentication for WinRM client"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8248: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8248"
}

Write-Host "`nControl ID 19057: Status of the Relax minimum password length limits setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 19057: Status of the Relax minimum password length limits setting"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ScEnableRelaxationOnMinimumPasswordLength" -Value 0 -Type DWord
        $cmdOutput = "Disabled relaxed minimum password length enforcement"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 19057: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 19057"
}

Write-Host "`nControl ID 11195: Status of the NetBIOS node type setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 11195: Status of the NetBIOS node type setting"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord
        $cmdOutput = "Set NetBIOS NodeType to 2 (P-node only)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 11195: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 11195"
}

Write-Host "`nControl ID 25362: Status of the Configure RPC over TCP port setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 25362: Status of the Configure RPC over TCP port setting"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc\Internet" -Name "Ports" -Value "5000-5100" -Type MultiString
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc\Internet" -Name "PortsInternetAvailable" -Value "Y"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc\Internet" -Name "UseInternetPorts" -Value 1 -Type DWord
        $cmdOutput = "Configured RPC to use ports 5000-5100 over TCP"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 25362: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 25362"
}

Write-Host "`nControl ID 3950: Status of the Windows Firewall: Firewall state (Public) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3950: Status of the Windows Firewall: Firewall state (Public) setting"
    try {
        Set-NetFirewallProfile -Profile Public -Enabled True
        $cmdOutput = "Enabled Windows Firewall for Public profile"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3950: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3950"
}

Write-Host "`nControl ID 8167: Status of the Windows Firewall: Log Successful Connections (Public) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8167: Status of the Windows Firewall: Log Successful Connections (Public) setting"
    try {
        Set-NetFirewallProfile -Profile Public -LogSuccessfulConnections Enabled
        $cmdOutput = "Enabled logging of successful connections on the Public firewall profile"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8167: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8167"
}

Write-Host "`nControl ID 11198: Status of the Allow Windows Ink Workspace setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 11198: Status of the Allow Windows Ink Workspace setting"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0 -Type DWord
        $cmdOutput = "Disabled Windows Ink Workspace"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 11198: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 11198"
}

Write-Host "`nControl ID 21377: Status of Block persistence through WMI event subscription ASR rule (e6db77e5-3df2-4cf1-b95a-636979351e5b)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 21377: Status of Block persistence through WMI event subscription ASR rule"
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids "e6db77e5-3df2-4cf1-b95a-636979351e5b" -AttackSurfaceReductionRules_Actions Enabled
        $cmdOutput = "Enabled ASR rule to block persistence through WMI event subscription"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 21377: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 21377"
}

Write-Host "`nControl ID 1390: Status of the Network Security: Minimum session security for NTLM SSP based (including secure RPC) servers setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1390: NTLM SSP minimum session security for servers"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value 537395200 -Type DWord
        $cmdOutput = "Configured NTLM SSP server minimum session security to require NTLMv2, 128-bit encryption, and message integrity"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1390: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1390"
}

Write-Host "`nControl ID 3964: Status of the Windows Firewall: Display a notification (Private) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 3964: Status of the Windows Firewall: Display a notification (Private) setting"
    try {
        Set-NetFirewallProfile -Profile Private -NotifyOnListen True
        $cmdOutput = "Enabled display of firewall notifications on Private profile"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 3964: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 3964"
}

Write-Host "`nControl ID 10968: Network access: Restrict clients allowed to make remote calls to SAM"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10968: Restrict clients allowed to make remote calls to SAM"
    try {
        $sddl = "O:BAG:BAD:(A;;RC;;;BA)"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSAM" -Value $sddl
        $cmdOutput = "Restricted SAM remote calls to Administrators only"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10968: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10968"
}

Write-Host "`nControl ID 9004: Status of the Lock screen slide show setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9004: Status of the Lock screen slide show setting"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow" -Value 1 -Type DWord
        $cmdOutput = "Disabled lock screen slideshow"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9004: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9004"
}

Write-Host "`nControl ID 2612: Status of the Turn off downloading of enclosures setting (Internet Explorer)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 2612: Status of the Turn off downloading of enclosures setting (Internet Explorer)"
    try {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Value 1 -Type DWord
        $cmdOutput = "Disabled downloading of enclosures in Internet Explorer"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 2612: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 2612"
}

Write-Host "`nControl ID 9025: Status of the WDigest Authentication setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 9025: WDigest Authentication setting"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord
        $cmdOutput = "Disabled WDigest storing plaintext credentials in memory"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 9025: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 9025"
}

Write-Host "`nControl ID 4507: Status of the audit setting Account Management: User Account Management (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4507: User Account Management audit setting"
    try {
        AuditPol /Set /SubCategory:"User Account Management" /Success:Enable /Failure:Enable
        $cmdOutput = "Enabled auditing for User Account Management (Success and Failure)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4507: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4507"
}

Write-Host "`nControl ID 4477: Status of the audit setting Account Lockout (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 4477: Account Lockout audit setting"
    try {
        AuditPol /Set /SubCategory:"Account Lockout" /Success:Enable /Failure:Enable
        $cmdOutput = "Enabled auditing for Account Lockout (Success and Failure)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 4477: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 4477"
}

Write-Host "`nControl ID 1193: Status of the MSS: Allow ICMP redirects to override OSPF generated routes (EnableICMPRedirect) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1193: MSS - Disable ICMP Redirects"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord
        $cmdOutput = "Disabled ICMP redirects from overriding OSPF routes"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1193: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1193"
}

Write-Host "`nControl ID 23131: Status of the Limit Dump Collection setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 23131: Limit Dump Collection"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DisableDumpCollection" -Value 1 -Type DWord
        $cmdOutput = "Limited dump collection to reduce sensitive data exposure"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 23131: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 23131"
}

Write-Host "`nControl ID 10152: Status of the audit setting Audit Group Membership (advanced audit setting)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 10152: Audit Group Membership"
    try {
        AuditPol /Set /SubCategory:"Group Membership" /Success:Enable /Failure:Enable
        $cmdOutput = "Enabled auditing for Group Membership (Success and Failure)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 10152: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 10152"
}

Write-Host "`nControl ID 26144: Status of enable password encryption setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 26144: Enable password encryption"
    try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Type DWord
        $cmdOutput = "Enforced encrypted password use for network authentication"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 26144: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 26144"
}

Write-Host "`nControl ID 11212: Status of the Select when Feature Updates are received - DeferFeatureUpdatesPeriodInDays setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 11212: Feature Updates Deferment"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value 30 -Type DWord
        $cmdOutput = "Configured Windows to defer feature updates for 30 days"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 11212: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 11212"
}

Write-Host "`nControl ID 5267: Status of the Network security: Allow PKU2U authentication requests to this computer to use online identities setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 5267: PKU2U authentication requests setting"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" -Name "AllowOnlineID" -Value 0 -Type DWord
        $cmdOutput = "Disabled PKU2U authentication using online identities"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 5267: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 5267"
}

Write-Host "`nControl ID 13929: Status of Block untrusted and unsigned processes that run from USB ASR rule (b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4)"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 13929: USB ASR rule"
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
        $cmdOutput = "Enabled ASR rule to block untrusted/unsigned USB processes"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 13929: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 13929"
}

Write-Host "`nControl ID 23128: Status of the Turn off cloud consumer account state content setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 23128: Disable cloud consumer account state content"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 1 -Type DWord
        $cmdOutput = "Disabled cloud consumer account state content"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 23128: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 23128"
}

Write-Host "`nControl ID 8166: Status of the Windows Firewall: Log file path and name (Public) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 8166: Set Windows Firewall log file path (Public)"
    try {
        Set-NetFirewallProfile -Profile Public -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log'
        $cmdOutput = "Set Public Firewall log file path to pfirewall.log"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 8166: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 8166"
}

Write-Host "`nControl ID 1458: Status of the MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended) setting"
$confirm = Read-Host "Apply this remediation? (y/n)"
if ($confirm -eq "y") {
    Write-Log "User approved remediation for Control ID 1458: Safe DLL search mode"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1 -Type DWord
        $cmdOutput = "Enabled Safe DLL search mode (MSS setting)"
        Write-Host $cmdOutput
        Write-Log $cmdOutput
    } catch {
        Write-Log "ERROR applying remediation for Control ID 1458: $_"
    }
} else {
    Write-Log "User skipped remediation for Control ID 1458"
}
