function Invoke-Control1755 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 17.5.5: Status of the audit setting Other Logon/Logoff Events (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 17.5.5"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 17.5.5: Other Logon/Logoff Events"
        try {
            AuditPol /Set /Subcategory:"Other Logon/Logoff Events" /Success:Enable /Failure:Enable
            $cmdOutput = "Enabled auditing for Other Logon/Logoff Events (success and failure)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 17.5.5: $_"
}
}
