function Invoke-Control936 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9.3.6: Status of the Windows Firewall: Log file path and name (Public) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9.3.6"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9.3.6: Set Windows Firewall log file path (Public)"
        try {
            Set-NetFirewallProfile -Profile Public -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\publicfw.log'
            $cmdOutput = "Set Public Firewall log file path to publicfw.log"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9.3.6: $_"
}
}
