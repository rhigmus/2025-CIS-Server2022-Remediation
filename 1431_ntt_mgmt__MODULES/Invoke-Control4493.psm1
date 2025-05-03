function Invoke-Control4493 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 4493: Status of the audit setting Other Object Access Events (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 4493"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 4493: Other Object Access Events"
        try {
            AuditPol /Set /Subcategory:"Other Object Access Events" /Success:Enable /Failure:Enable
            $cmdOutput = "Enabled auditing for Other Object Access Events (success and failure)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 4493: $_"
}
