function Invoke-Control914 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9.1.4: Status of the Windows Firewall: Log file path and name (Domain) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9.1.4"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9.1.4: Firewall log path (Domain)"
        try {
            Set-NetFirewallProfile -Profile Domain -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\domainfw.log"
            $cmdOutput = "Set Windows Firewall log file path (Domain) to domainfw.log."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9.1.4: $_"
}
}
