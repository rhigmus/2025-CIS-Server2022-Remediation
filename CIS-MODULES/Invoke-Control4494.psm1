function Invoke-Control4494 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 4494: Status of the audit setting Sensitive Privilege Use (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 4494"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 4494: Status of the audit setting Sensitive Privilege Use (advanced audit setting)"
        try {
            AuditPol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
            $cmdOutput = "Enabled auditing for Sensitive Privilege Use (Success and Failure)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 4494: $_"
}
