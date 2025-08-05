function Invoke-Control921 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9.2.1: Status of the Windows Firewall: Firewall state (Private) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9.2.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9.2.1: Firewall state (Private)"
        try {
            Set-NetFirewallProfile -Profile Private -Enabled True
            $cmdOutput = "Enabled Windows Firewall for the Private profile."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9.2.1: $_"
}
}
