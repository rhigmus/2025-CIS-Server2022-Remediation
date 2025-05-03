function Invoke-Control10152 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10152: Status of the audit setting Audit Group Membership (advanced audit setting)"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10152"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10152: Audit Group Membership"
        try {
            AuditPol /Set /SubCategory:"Group Membership" /Success:Enable /Failure:Enable
            $cmdOutput = "Enabled auditing for Group Membership (Success and Failure)"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10152: $_"
}
