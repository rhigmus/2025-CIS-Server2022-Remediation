function Invoke-Control10151 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10151: Status of the audit setting Audit PNP Activity (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10151"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10151: Audit PNP Activity"
        try {
            AuditPol /Set /Subcategory:"Plug and Play Events" /Success:Enable /Failure:Enable
            $cmdOutput = "Enabled auditing for Plug and Play device events (success and failure)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10151: $_"
}
}
