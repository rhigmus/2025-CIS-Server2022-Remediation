function Invoke-Control1774 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 17.7.4: Status of the audit setting MPSSVC Rule-Level Policy Change (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 17.7.4"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 17.7.4: Status of the audit setting MPSSVC Rule-Level Policy Change (advanced audit setting"
        try {
            # Enable auditing for MPSSVC Rule-Level Policy Change
            AuditPol /Set /Subcategory:"MPSSVC Rule-Level Policy Change" /Success:Enable /Failure:Enable
    
            $cmdOutput = "Enabled auditing for MPSSVC Rule-Level Policy Change (success and failure)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 17.7.4: $_"
}
}
