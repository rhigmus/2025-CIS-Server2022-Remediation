function Invoke-Control4520 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 4520: Status of the audit setting Detailed File Share (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 4520"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 4520: Status of the audit setting Detailed File Share (advanced audit setting)"
        try {
            # Enable auditing for Detailed File Share access
            AuditPol /Set /Subcategory:"Detailed File Share" /Success:Enable /Failure:Enable
    
            $cmdOutput = "Enabled auditing for Detailed File Share (success and failure)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 4520: $_"
}
