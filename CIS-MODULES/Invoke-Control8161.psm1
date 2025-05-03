function Invoke-Control8161 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8161: Status of the Windows Firewall: Log file path and name (Private) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8161"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8161: Firewall log file path (Private)"
        try {
            Set-NetFirewallProfile -Profile Private -LogFileName "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
            $cmdOutput = "Set firewall log file path for Private profile to pfirewall.log."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8161: $_"
}
