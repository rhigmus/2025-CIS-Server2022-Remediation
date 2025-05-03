function Invoke-Control3962 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 3962: Status of the Windows Firewall: Display a notification (Domain) setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 3962"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 3962"
        try {
            Set-NetFirewallProfile -Profile Domain -NotifyOnListen True
            $cmdOutput = "Enabled firewall notifications on the Domain profile"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 3962: $_"
}
