function Invoke-Control4517 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 4517: Status of the audit setting Credential Validation (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 4517"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 4517"
        try {
            AuditPol /set /subcategory:"Credential Validation" /success:enable /failure:enable
            $cmdOutput = "Enabled auditing for Credential Validation (success and failure)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 4517: $_"
}
