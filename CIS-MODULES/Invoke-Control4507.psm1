function Invoke-Control4507 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 4507: Status of the audit setting Account Management: User Account Management (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 4507"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 4507: User Account Management audit setting"
        try {
            AuditPol /Set /SubCategory:"User Account Management" /Success:Enable /Failure:Enable
            $cmdOutput = "Enabled auditing for User Account Management (Success and Failure)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 4507: $_"
}
}
