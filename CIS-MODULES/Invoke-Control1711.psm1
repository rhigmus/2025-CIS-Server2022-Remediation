function Invoke-Control1711 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 17.1.1: Status of the audit setting Credential Validation (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 17.1.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 17.1.1"
        try {
            AuditPol /set /subcategory:"Credential Validation" /success:enable /failure:enable
            $cmdOutput = "Enabled auditing for Credential Validation (success and failure)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 17.1.1: $_"
}
}
