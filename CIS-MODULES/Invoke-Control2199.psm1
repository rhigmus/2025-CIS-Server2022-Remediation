function Invoke-Control2199 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2199: Current list of Groups and User Accounts granted the Deny log on locally right"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2199"
            return
        }
    }
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
}
