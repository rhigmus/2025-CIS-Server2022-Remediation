function Invoke-Control8255 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8255: Status of the audit setting Removable Storage (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8255"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8255: Status of the audit setting Removable Storage (advanced audit setting)"
        try {
            AuditPol /Set /Subcategory:"Removable Storage" /Success:Enable /Failure:Enable
            $cmdOutput = "Enabled success and failure auditing for Removable Storage."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8255: $_"
}
}
