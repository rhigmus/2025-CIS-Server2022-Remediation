function Invoke-Control4503 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 4503: Status of the audit setting Authorization Policy Change (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 4503"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 4503"
        try {
            AuditPol /Set /SubCategory:"Authorization Policy Change" /Success:Enable /Failure:Enable
            $cmdOutput = "Enabled auditing for Authorization Policy Change (Success and Failure)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 4503: $_"
}
