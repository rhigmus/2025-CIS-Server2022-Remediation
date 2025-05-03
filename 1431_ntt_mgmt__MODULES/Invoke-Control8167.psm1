function Invoke-Control8167 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8167: Status of the Windows Firewall: Log Successful Connections (Public) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8167"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8167: Status of the Windows Firewall: Log Successful Connections (Public) setting"
        try {
            Set-NetFirewallProfile -Profile Public -LogSuccessfulConnections Enabled
            $cmdOutput = "Enabled logging of successful connections on the Public firewall profile"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8167: $_"
}
