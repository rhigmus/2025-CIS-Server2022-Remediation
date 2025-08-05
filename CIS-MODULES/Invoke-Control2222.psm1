function Invoke-Control2222 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.2.22: Current list of Groups and User Accounts granted the Deny Access to this computer from the network right"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.2.22"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.2.22: Current list of Groups and User Accounts granted the Deny Access to this computer from the network right"
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
            Write-Log "ERROR applying remediation for Control ID 2.2.22: $_"
}
}
