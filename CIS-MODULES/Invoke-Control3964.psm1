function Invoke-Control3964 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 3964: Status of the Windows Firewall: Display a notification (Private) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 3964"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 3964: Status of the Windows Firewall: Display a notification (Private) setting"
        try {
            Set-NetFirewallProfile -Profile Private -NotifyOnListen True
            $cmdOutput = "Enabled display of firewall notifications on Private profile"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 3964: $_"
}
