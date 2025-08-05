function Invoke-Control189285 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 18.9.28.5: Status of the Configure Turn off app notifications on the lock screen"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 18.9.28.5"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 18.9.28.5: Status of the Configure Turn off app notifications on the lock screen"
        try {
            # Disable notifications on the lock screen
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -PropertyType DWord -Value 1 -Force | Out-Null
    
            $cmdOutput = "Disabled app notifications on the lock screen."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 18.9.28.5: $_"
}
}
