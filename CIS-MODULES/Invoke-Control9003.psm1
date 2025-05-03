function Invoke-Control9003 {
    param([bool]$Apply = $false)

    Write-Host "`nControl ID 9003: Status of the Lock screen camera setting"
    if (-not $Apply) {
        $confirm = Read-Host "Apply this remediation? (y/n)"
        if ($confirm -ne "y") {
            Write-Log "User skipped remediation for Control ID 9003"
            return
        }
    }
        Write-Log "User approved remediation for Control ID 9003: Status of the Lock screen camera setting"
        try {
            # Disable camera access on the lock screen
            New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -PropertyType DWord -Value 1 -Force | Out-Null
    
            $cmdOutput = "Disabled camera access on the lock screen (NoLockScreenCamera set to 1)."
            Write-Host $cmdOutput
            Write-Log $cmdOutput
        } catch {
            Write-Log "ERROR applying remediation for Control ID 9003: $_"
}
