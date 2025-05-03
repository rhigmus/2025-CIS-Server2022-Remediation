function Invoke-Control4490 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 4490: Status of the audit setting File Share (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 4490"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 4490: File Share auditing"
        try {
            AuditPol /Set /Subcategory:"File Share" /Success:Enable /Failure:Enable
            $cmdOutput = "Enabled auditing for File Share events (success and failure)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 4490: $_"
}
