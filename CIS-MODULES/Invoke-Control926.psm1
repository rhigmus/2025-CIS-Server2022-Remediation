function Invoke-Control926 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9.2.6: Status of the Windows Firewall: Log dropped packets (Private) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9.2.6"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9.2.6"
        try {
            Set-NetFirewallProfile -Profile Private -LogDroppedPackets Enabled
            $cmdOutput = "Enabled logging of dropped packets on Private Firewall Profile"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9.2.6: $_"
}
}
