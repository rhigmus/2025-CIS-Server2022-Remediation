function Invoke-Control1751 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 17.5.1: Status of the audit setting Account Lockout (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 17.5.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 17.5.1: Account Lockout audit setting"
        try {
            AuditPol /Set /SubCategory:"Account Lockout" /Success:Enable /Failure:Enable
            $cmdOutput = "Enabled auditing for Account Lockout (Success and Failure)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 17.5.1: $_"
}
}
