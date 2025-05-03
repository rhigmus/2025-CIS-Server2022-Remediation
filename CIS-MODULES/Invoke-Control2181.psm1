function Invoke-Control2181 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2181: Current list of Groups and User Accounts granted the Access this computer from the network right"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2181"
            return
        }
    }
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
