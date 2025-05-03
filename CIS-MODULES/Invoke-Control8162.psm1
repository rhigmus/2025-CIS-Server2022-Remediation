function Invoke-Control8162 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8162: Status of the Windows Firewall: Log Successful Connections (Private) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8162"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8162: Log successful connections (Private)"
        try {
            Set-NetFirewallProfile -Profile Private -LogSuccessfulConnections Enabled
            $cmdOutput = "Enabled logging of successful connections for the Private firewall profile."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8162: $_"
}
