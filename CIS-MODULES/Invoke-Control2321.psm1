function Invoke-Control2321 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 2.3.2.1: Status of the Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 2.3.2.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 2.3.2.1: Force subcategory settings override"
        try {
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -PropertyType DWord -Value 1 -Force | Out-Null
            $cmdOutput = "Set SCENoApplyLegacyAuditPolicy to 1 to enforce subcategory audit settings."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 2.3.2.1: $_"
}
}
