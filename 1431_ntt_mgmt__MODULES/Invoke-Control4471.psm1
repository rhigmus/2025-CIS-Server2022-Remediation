function Invoke-Control4471 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 4471: Status of the audit setting Security System Extension (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 4471"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 4471: Status of the audit setting Security System Extension (advanced audit setting)"
        try {
            # Enable auditing for Security System Extension
            AuditPol /Set /Subcategory:"Security System Extension" /Success:Enable /Failure:Enable
    
            $cmdOutput = "Enabled auditing for Security System Extension (success and failure)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 4471: $_"
}
