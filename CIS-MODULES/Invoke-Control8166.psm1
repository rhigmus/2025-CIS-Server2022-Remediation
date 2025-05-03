function Invoke-Control8166 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 8166: Status of the Windows Firewall: Log file path and name (Public) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 8166"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 8166: Set Windows Firewall log file path (Public)"
        try {
            Set-NetFirewallProfile -Profile Public -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log'
            $cmdOutput = "Set Public Firewall log file path to pfirewall.log"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 8166: $_"
}
