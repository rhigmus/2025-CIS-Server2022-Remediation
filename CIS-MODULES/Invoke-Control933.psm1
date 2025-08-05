function Invoke-Control933 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9.3.3: Status of the Windows Firewall: Display a notification (Public) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9.3.3"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9.3.3: Display notification (Public)"
        try {
            Set-NetFirewallProfile -Profile Public -NotifyOnListen True
            $cmdOutput = "Enabled notifications for listening apps on Public firewall profile."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9.3.3: $_"
}
}
