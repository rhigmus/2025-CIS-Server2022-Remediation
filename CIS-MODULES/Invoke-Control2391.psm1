function Invoke-Control2391 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2391: Current list of Groups and User Accounts granted the Allow log on locally (SeInteractiveLogonRight) right"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2391"
            return
        }
    }
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
}
