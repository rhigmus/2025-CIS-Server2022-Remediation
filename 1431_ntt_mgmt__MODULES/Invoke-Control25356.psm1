function Invoke-Control25356 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 25356: Status of the Enable MPR notifications for the system setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 25356"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 25356: Disable MPR notifications"
        try {
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections" -Name "EnableMPRNotifications" -PropertyType DWord -Value 0 -Force | Out-Null
            $cmdOutput = "Disabled MPR (Multiple Provider Router) notifications (EnableMPRNotifications = 0)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 25356: $_"
}
