function Invoke-Control1524 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1524: Status of the Windows Firewall: Log dropped packets (Domain) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1524"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1524: Log dropped packets (Domain)"
        try {
            Set-NetFirewallProfile -Profile Domain -LogDroppedPackets Enabled
            $cmdOutput = "Enabled logging of dropped packets on the Domain firewall profile."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1524: $_"
}
}
