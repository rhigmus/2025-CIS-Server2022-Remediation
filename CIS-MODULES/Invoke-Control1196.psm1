function Invoke-Control1196 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 1196: Status of the MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 1196"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 1196: Status of the MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires setting"
        try {
            # Set ScreenSaverGracePeriod to 5 seconds (CIS recommends 5 or fewer)
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "ScreenSaverGracePeriod" -PropertyType String -Value "5" -Force | Out-Null
    
            $cmdOutput = "Set ScreenSaverGracePeriod to 5 seconds."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 1196: $_"
}
