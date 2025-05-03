function Invoke-Control4511 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 4511: Status of the audit setting Application Group Management (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 4511"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 4511"
        try {
            AuditPol /set /subcategory:"Application Group Management" /success:enable /failure:enable
            $cmdOutput = "Enabled auditing for Application Group Management (success and failure)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 4511: $_"
}
