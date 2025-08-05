function Invoke-Control925 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9.2.5: Status of the Windows Firewall: Log file path and name (Private) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9.2.5"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9.2.5: Firewall log file path (Private)"
        try {
            Set-NetFirewallProfile -Profile Private -LogFileName "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
            $cmdOutput = "Set firewall log file path for Private profile to pfirewall.log."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9.2.5: $_"
}
}
