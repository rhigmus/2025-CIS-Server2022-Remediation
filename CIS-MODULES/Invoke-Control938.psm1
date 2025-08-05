function Invoke-Control938 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9.3.8: Status of the Windows Firewall: Log dropped packets (Public) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9.3.8"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9.3.8: Log dropped packets (Public)"
        try {
            Set-NetFirewallProfile -Profile Public -LogDroppedPackets Enabled
            $cmdOutput = "Enabled logging of dropped packets for Public firewall profile."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9.3.8: $_"
}
}
