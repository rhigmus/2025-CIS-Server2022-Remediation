function Invoke-Control1732 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 17.3.2: Status of the audit setting Process Creation (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 17.3.2"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 17.3.2: Audit setting Process Creation"
        try {
            AuditPol /Set /Subcategory:"Process Creation" /Success:Enable /Failure:Enable
            $cmdOutput = "Enabled success and failure auditing for Process Creation."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 17.3.2: $_"
}
}
