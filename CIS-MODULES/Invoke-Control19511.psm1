function Invoke-Control19511 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 19.5.1.1: Status of the Turn off toast notifications on the lock screen setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 19.5.1.1"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 19.5.1.1"
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord
            $cmdOutput = "Disabled toast notifications on the lock screen"
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 19.5.1.1: $_"
}
}
