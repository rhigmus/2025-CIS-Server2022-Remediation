function Invoke-Control3950 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 3950: Status of the Windows Firewall: Firewall state (Public) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 3950"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 3950: Status of the Windows Firewall: Firewall state (Public) setting"
        try {
            Set-NetFirewallProfile -Profile Public -Enabled True
            $cmdOutput = "Enabled Windows Firewall for Public profile"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 3950: $_"
}
