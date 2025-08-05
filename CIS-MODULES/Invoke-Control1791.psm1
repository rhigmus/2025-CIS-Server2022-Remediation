function Invoke-Control1791 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 17.9.1: Status of the audit setting IPsec Driver (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 17.9.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 17.9.1: Audit setting IPsec Driver"
        try {
            AuditPol /Set /Subcategory:"IPsec Driver" /Success:Enable /Failure:Enable
            $cmdOutput = "Enabled auditing for IPsec Driver (success and failure)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 17.9.1: $_"
}
}
