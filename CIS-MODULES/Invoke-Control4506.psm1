function Invoke-Control4506 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 4506: Status of the audit setting Other Policy Change Events (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 4506"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 4506: Enable auditing of Other Policy Change Events"
        try {
            AuditPol /Set /Subcategory:"Other Policy Change Events" /Success:Enable /Failure:Enable
            $cmdOutput = "Enabled audit for Other Policy Change Events (success and failure)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 4506: $_"
}
