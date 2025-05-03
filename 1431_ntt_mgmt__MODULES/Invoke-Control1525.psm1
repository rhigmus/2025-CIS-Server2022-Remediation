function Invoke-Control1525 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1525: Status of the Windows Firewall: Log file path and name (Domain) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1525"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1525: Firewall log path (Domain)"
        try {
            Set-NetFirewallProfile -Profile Domain -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
            $cmdOutput = "Set Windows Firewall log file path (Domain) to pfirewall.log."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1525: $_"
}
