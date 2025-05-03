function Invoke-Control3951 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 3951: Status of the Windows Firewall: Firewall state (Private) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 3951"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 3951: Firewall state (Private)"
        try {
            Set-NetFirewallProfile -Profile Private -Enabled True
            $cmdOutput = "Enabled Windows Firewall for the Private profile."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 3951: $_"
}
