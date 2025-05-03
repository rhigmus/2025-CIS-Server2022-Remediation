function Invoke-Control10968 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 10968: Network access: Restrict clients allowed to make remote calls to SAM"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 10968"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 10968: Restrict clients allowed to make remote calls to SAM"
        try {
            $sddl = "O:BAG:BAD:(A;;RC;;;BA)"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSAM" -Value $sddl
            $cmdOutput = "Restricted SAM remote calls to Administrators only"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 10968: $_"
}
